#include "core/debugger.h"
#include "core/disasm.h"
#include "core/os.h"
#include "core/util.h"
#include <algorithm>
#include <map>

#if defined(_WIN32) && (defined(_M_X64) || defined(__x86_64__))
#define CEASTA_WIN_DEBUGGER 1
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#include <windows.h>
#include <tlhelp32.h>
#endif

#ifdef CEASTA_WIN_DEBUGGER

namespace {

const DWORD status_wx86_breakpoint = 0x4000001F;  // int3 in a 32 bit process under wow64
const DWORD status_wx86_single_step = 0x4000001E;
const DWORD trap_flag = 0x100;

std::string win_error(DWORD e)
{
    wchar_t* buf = nullptr;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, e, 0, (LPWSTR)&buf, 0, nullptr);
    std::string s = buf ? util::trim(os::narrow(buf)) : std::string();
    if (buf)
        LocalFree(buf);
    return util::fmt("%s (error %lu)", s.empty() ? "unknown error" : s.c_str(), (unsigned long)e);
}

const char* exception_name(DWORD code)
{
    switch (code) {
    case EXCEPTION_ACCESS_VIOLATION: return "access violation";
    case EXCEPTION_ILLEGAL_INSTRUCTION: return "illegal instruction";
    case EXCEPTION_PRIV_INSTRUCTION: return "privileged instruction";
    case EXCEPTION_INT_DIVIDE_BY_ZERO: return "integer divide by zero";
    case EXCEPTION_INT_OVERFLOW: return "integer overflow";
    case EXCEPTION_STACK_OVERFLOW: return "stack overflow";
    case EXCEPTION_IN_PAGE_ERROR: return "in page error";
    case EXCEPTION_DATATYPE_MISALIGNMENT: return "misaligned data";
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED: return "array bounds exceeded";
    case EXCEPTION_FLT_DIVIDE_BY_ZERO: return "float divide by zero";
    case EXCEPTION_NONCONTINUABLE_EXCEPTION: return "noncontinuable exception";
    case 0xC0000409: return "stack buffer overrun / fast fail";
    case 0xE06D7363: return "c++ exception";
    case 0x406D1388: return "thread name";
    case DBG_CONTROL_C: return "ctrl+c";
    default: return "exception";
    }
}

std::string base_name(const std::string& p)
{
    size_t s = p.find_last_of("/\\");
    return s == std::string::npos ? p : p.substr(s + 1);
}

std::string file_path(HANDLE f)
{
    if (!f)
        return std::string();
    std::wstring buf(32768, L'\0');
    DWORD n = GetFinalPathNameByHandleW(f, &buf[0], (DWORD)buf.size(), FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (n == 0 || n >= buf.size())
        return std::string();
    buf.resize(n);
    if (buf.compare(0, 8, L"\\\\?\\UNC\\") == 0)
        buf = L"\\\\" + buf.substr(8);
    else if (buf.compare(0, 4, L"\\\\?\\") == 0)
        buf = buf.substr(4);
    return os::narrow(buf);
}

// register state of one thread. 32 bit targets under wow64 use the wow64 context
struct thread_ctx {
    bool wow = false;
    CONTEXT n;       // DECLSPEC_ALIGN(16) in the sdk, fine on the stack
    WOW64_CONTEXT w;
    uint64_t pc() const { return wow ? w.Eip : n.Rip; }
    uint64_t sp() const { return wow ? w.Esp : n.Rsp; }
    void set_pc(uint64_t v)
    {
        if (wow)
            w.Eip = (DWORD)v;
        else
            n.Rip = v;
    }
    DWORD& eflags() { return wow ? w.EFlags : n.EFlags; }
};

}

struct debugger::impl {
    debugger& owner;
    explicit impl(debugger& o) : owner(o) {}

    enum class step { none, into, resume };

    dbg_state state = dbg_state::none;
    HANDLE process = nullptr;       // from the create process event, the system closes it
    HANDLE own_process = nullptr;   // from CreateProcess / OpenProcess, we close these
    HANDLE own_thread = nullptr;
    DWORD pid = 0;
    DWORD cur_tid = 0;
    DWORD main_tid = 0;
    DWORD event_tid = 0;
    std::map<DWORD, HANDLE> threads;
    bool wow64 = false;
    bool attached = false;
    bool killing = false;
    bool pause_requested = false;
    bool have_event = false;        // a stop is waiting for ContinueDebugEvent
    DWORD cont_status = DBG_CONTINUE;
    bool seen_loader_bp = false;
    bool seen_wow_bp = false;
    uint64_t image_base = 0;
    uint64_t entry = 0;
    std::map<uint64_t, uint8_t> bps; // user breakpoints, address -> original byte
    uint64_t temp_bp = 0;            // entry point / step over / run to cursor
    uint8_t temp_orig = 0;
    bool temp_active = false;
    std::string temp_reason;
    uint64_t reinsert = 0;           // breakpoint to put back after the current single step
    step stepping = step::none;
    int exit_code = 0;
    std::string reason;
    std::vector<dbg_module> modules;

    void log(const std::string& s) const
    {
        if (owner.on_log)
            owner.on_log(s);
    }

    HANDLE thread_handle(DWORD tid) const
    {
        auto it = threads.find(tid);
        return it == threads.end() ? nullptr : it->second;
    }

    bool load_ctx(HANDLE th, thread_ctx& c) const
    {
        memset(&c, 0, sizeof(c));
        c.wow = wow64;
        if (!th)
            return false;
        if (wow64) {
            c.w.ContextFlags = WOW64_CONTEXT_FULL;
            return Wow64GetThreadContext(th, &c.w) != 0;
        }
        c.n.ContextFlags = CONTEXT_FULL;
        return GetThreadContext(th, &c.n) != 0;
    }

    bool store_ctx(HANDLE th, thread_ctx& c)
    {
        if (c.wow)
            return Wow64SetThreadContext(th, &c.w) != 0;
        return SetThreadContext(th, &c.n) != 0;
    }

    // ---- debug registers: dr0-dr3 hold the watched addresses, dr7 switches them on and says
    // what to watch, dr6 tells which one fired. every thread has its own set

    bool set_dregs(HANDLE th, const std::vector<debugger::watch>& w)
    {
        if (!th)
            return false;
        uint64_t dr7 = debugger::watch_dr7(w);
        if (wow64) {
            WOW64_CONTEXT c;
            memset(&c, 0, sizeof(c));
            c.ContextFlags = WOW64_CONTEXT_DEBUG_REGISTERS;
            if (!Wow64GetThreadContext(th, &c))
                return false;
            DWORD* dr[4] = {&c.Dr0, &c.Dr1, &c.Dr2, &c.Dr3};
            for (size_t i = 0; i < 4; i++)
                *dr[i] = i < w.size() ? (DWORD)w[i].addr : 0;
            c.Dr6 = 0;
            c.Dr7 = (DWORD)dr7;
            return Wow64SetThreadContext(th, &c) != 0;
        }
        CONTEXT c;
        memset(&c, 0, sizeof(c));
        c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (!GetThreadContext(th, &c))
            return false;
        DWORD64* dr[4] = {&c.Dr0, &c.Dr1, &c.Dr2, &c.Dr3};
        for (size_t i = 0; i < 4; i++)
            *dr[i] = i < w.size() ? w[i].addr : 0;
        c.Dr6 = 0;
        c.Dr7 = dr7;
        return SetThreadContext(th, &c) != 0;
    }

    // which watches fired on this thread (dr6 bits 0-3), cleared for the next time
    int take_dr6(HANDLE th)
    {
        if (!th)
            return 0;
        if (wow64) {
            WOW64_CONTEXT c;
            memset(&c, 0, sizeof(c));
            c.ContextFlags = WOW64_CONTEXT_DEBUG_REGISTERS;
            if (!Wow64GetThreadContext(th, &c))
                return 0;
            int fired = (int)(c.Dr6 & 0xF);
            if (fired) {
                c.Dr6 = 0;
                Wow64SetThreadContext(th, &c);
            }
            return fired;
        }
        CONTEXT c;
        memset(&c, 0, sizeof(c));
        c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (!GetThreadContext(th, &c))
            return 0;
        int fired = (int)(c.Dr6 & 0xF);
        if (fired) {
            c.Dr6 = 0;
            SetThreadContext(th, &c);
        }
        return fired;
    }

    size_t raw_read(uint64_t a, void* out, size_t n) const
    {
        if (!process || n == 0)
            return 0;
        SIZE_T got = 0;
        if (ReadProcessMemory(process, (LPCVOID)(uintptr_t)a, out, n, &got))
            return (size_t)got;
        // the range crosses an unreadable page, read what we can page by page
        size_t done = 0;
        while (done < n) {
            size_t chunk = std::min<size_t>(n - done, 0x1000 - (size_t)((a + done) & 0xfff));
            got = 0;
            if (!ReadProcessMemory(process, (LPCVOID)(uintptr_t)(a + done), (char*)out + done, chunk, &got) || got == 0)
                break;
            done += (size_t)got;
            if (got < chunk)
                break;
        }
        return done;
    }

    bool raw_write(uint64_t a, const void* in, size_t n)
    {
        if (!process)
            return false;
        DWORD old = 0;
        bool reprotected = VirtualProtectEx(process, (LPVOID)(uintptr_t)a, n, PAGE_EXECUTE_READWRITE, &old) != 0;
        SIZE_T put = 0;
        BOOL ok = WriteProcessMemory(process, (LPVOID)(uintptr_t)a, in, n, &put);
        if (reprotected) {
            DWORD tmp;
            VirtualProtectEx(process, (LPVOID)(uintptr_t)a, n, old, &tmp);
        }
        FlushInstructionCache(process, (LPCVOID)(uintptr_t)a, n);
        return ok && put == n;
    }

    bool write_cc(uint64_t a)
    {
        uint8_t cc = 0xCC;
        return raw_write(a, &cc, 1);
    }

    bool armed(uint64_t a) const { return bps.count(a) || (temp_active && temp_bp == a); }

    bool set_temp(uint64_t a, const std::string& why)
    {
        remove_temp();
        auto it = bps.find(a);
        if (it != bps.end()) {
            temp_orig = it->second; // a user breakpoint already put the int3 there
        } else {
            uint8_t b;
            if (raw_read(a, &b, 1) != 1 || !write_cc(a))
                return false;
            temp_orig = b;
        }
        temp_bp = a;
        temp_active = true;
        temp_reason = why;
        return true;
    }

    void remove_temp()
    {
        if (!temp_active)
            return;
        if (!bps.count(temp_bp))
            raw_write(temp_bp, &temp_orig, 1);
        temp_active = false;
    }

    uint64_t image_size(uint64_t base) const
    {
        uint32_t lfanew = 0, size = 0;
        if (raw_read(base + 0x3c, &lfanew, 4) != 4 || lfanew > 0x1000)
            return 0;
        raw_read(base + lfanew + 24 + 56, &size, 4);
        return size;
    }

    void cleanup()
    {
        if (own_thread)
            CloseHandle(own_thread);
        if (own_process)
            CloseHandle(own_process);
        own_thread = own_process = nullptr;
        process = nullptr;
        threads.clear();
        bps.clear();
        modules.clear();
        temp_active = false;
        reinsert = 0;
        stepping = step::none;
        have_event = false;
        owner.watch_list_.clear(); // runtime addresses of this process
        owner.watch_pid_ = 0;
        state = dbg_state::none;
        pid = cur_tid = main_tid = event_tid = 0;
        seen_loader_bp = seen_wow_bp = false;
        attached = killing = pause_requested = false;
        image_base = entry = 0;
    }

    void reset_for_new()
    {
        cleanup();
        exit_code = 0;
        reason.clear();
        wow64 = false;
    }

    // returns true when the debuggee should stay stopped
    bool on_exception(const DEBUG_EVENT& ev, DWORD& status)
    {
        const EXCEPTION_RECORD& er = ev.u.Exception.ExceptionRecord;
        DWORD code = er.ExceptionCode;
        uint64_t addr = (uint64_t)(uintptr_t)er.ExceptionAddress;
        bool first = ev.u.Exception.dwFirstChance != 0;
        HANDLE th = thread_handle(ev.dwThreadId);
        status = DBG_CONTINUE;

        if (code == EXCEPTION_BREAKPOINT || code == status_wx86_breakpoint) {
            if (armed(addr)) {
                // put the pc back onto the int3 we placed
                thread_ctx c;
                if (load_ctx(th, c)) {
                    c.set_pc(addr);
                    store_ctx(th, c);
                }
                bool user = bps.count(addr) != 0;
                std::string why = user ? std::string("breakpoint") : temp_reason;
                if (temp_active && temp_bp == addr)
                    remove_temp();
                stepping = step::none;
                reason = why;
                return true;
            }
            if (code == EXCEPTION_BREAKPOINT && !seen_loader_bp) {
                seen_loader_bp = true;
                if (attached) {
                    reason = "attached";
                    return true;
                }
                return false; // the loader's breakpoint, keep going to the entry point
            }
            if (code == status_wx86_breakpoint && !seen_wow_bp) {
                seen_wow_bp = true;
                return false; // wow64's own loader breakpoint
            }
            reason = pause_requested ? std::string("paused") : "int3 in the program at " + util::hex(addr);
            pause_requested = false;
            return true;
        }

        if (code == EXCEPTION_SINGLE_STEP || code == status_wx86_single_step) {
            if (reinsert) {
                if (bps.count(reinsert))
                    write_cc(reinsert);
                reinsert = 0;
            }
            // a watch fired: the instruction just before the pc wrote (or read) the memory
            std::vector<debugger::watch> w = owner.active_watches();
            int fired = w.empty() ? 0 : take_dr6(th);
            for (size_t i = 0; i < w.size(); i++)
                if (fired & (1 << i)) {
                    stepping = step::none;
                    reason = debugger::watch_text(w[i]);
                    return true;
                }
            if (stepping == step::into) {
                stepping = step::none;
                reason = "step";
                return true;
            }
            if (stepping == step::resume) {
                stepping = step::none;
                return false; // breakpoint is armed again, keep running
            }
            // a single step nobody asked for, with a watch set: that watch (dr6 came back empty)
            if (w.size() == 1)
                reason = debugger::watch_text(w[0]);
            else if (!w.empty())
                reason = "watchpoint at " + util::hex(addr);
            else
                reason = "single step at " + util::hex(addr);
            return true;
        }

        // other exceptions: the program gets the first chance, we stop when it would crash
        status = DBG_EXCEPTION_NOT_HANDLED;
        if (first) {
            if (code != 0x406D1388)
                log(util::fmt("first chance exception %08lX (%s) at %s", (unsigned long)code, exception_name(code), util::hex(addr).c_str()));
            return false;
        }
        reason = util::fmt("unhandled exception %08lX (%s) at %s", (unsigned long)code, exception_name(code), util::hex(addr).c_str());
        return true;
    }

    void handle(const DEBUG_EVENT& ev)
    {
        DWORD status = DBG_CONTINUE;
        bool stop = false;
        switch (ev.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT: {
            const CREATE_PROCESS_DEBUG_INFO& ci = ev.u.CreateProcessInfo;
            process = ci.hProcess;
            threads[ev.dwThreadId] = ci.hThread;
            main_tid = cur_tid = ev.dwThreadId;
            image_base = (uint64_t)(uintptr_t)ci.lpBaseOfImage;
            entry = (uint64_t)(uintptr_t)ci.lpStartAddress;
            BOOL w = FALSE;
            IsWow64Process(process, &w);
            wow64 = w != FALSE;
            std::string path = file_path(ci.hFile);
            if (ci.hFile)
                CloseHandle(ci.hFile);
            modules.push_back({base_name(path), path, image_base, image_size(image_base)});
            log(util::fmt("process %lu started, %s, image base %s", (unsigned long)ev.dwProcessId,
                wow64 ? "32 bit" : "64 bit", util::hex(image_base).c_str()));
            if (owner.on_created)
                owner.on_created();
            if (owner.break_on_entry && entry && !attached && !killing)
                set_temp(entry, "entry point");
            break;
        }
        case CREATE_THREAD_DEBUG_EVENT: {
            threads[ev.dwThreadId] = ev.u.CreateThread.hThread;
            std::vector<debugger::watch> w = owner.active_watches(); // a new thread starts unwatched
            if (!w.empty())
                set_dregs(ev.u.CreateThread.hThread, w);
            break;
        }
        case EXIT_THREAD_DEBUG_EVENT:
            threads.erase(ev.dwThreadId);
            if (cur_tid == ev.dwThreadId)
                cur_tid = threads.count(main_tid) ? main_tid : (threads.empty() ? 0 : threads.begin()->first);
            break;
        case LOAD_DLL_DEBUG_EVENT: {
            const LOAD_DLL_DEBUG_INFO& li = ev.u.LoadDll;
            std::string path = file_path(li.hFile);
            if (li.hFile)
                CloseHandle(li.hFile);
            uint64_t base = (uint64_t)(uintptr_t)li.lpBaseOfDll;
            modules.push_back({base_name(path), path, base, image_size(base)});
            break;
        }
        case UNLOAD_DLL_DEBUG_EVENT: {
            uint64_t base = (uint64_t)(uintptr_t)ev.u.UnloadDll.lpBaseOfDll;
            modules.erase(std::remove_if(modules.begin(), modules.end(),
                [&](const dbg_module& m) { return m.base == base; }), modules.end());
            break;
        }
        case OUTPUT_DEBUG_STRING_EVENT: {
            const OUTPUT_DEBUG_STRING_INFO& o = ev.u.DebugString;
            size_t n = std::min<size_t>(o.nDebugStringLength, 4096);
            uint64_t a = (uint64_t)(uintptr_t)o.lpDebugStringData;
            std::string s;
            if (o.fUnicode) {
                std::wstring ws(n, L'\0');
                size_t got = raw_read(a, &ws[0], n * 2) / 2;
                ws.resize(got);
                s = os::narrow(ws);
            } else {
                s.assign(n, '\0');
                s.resize(raw_read(a, &s[0], n));
            }
            while (!s.empty() && (s.back() == '\0' || s.back() == '\n' || s.back() == '\r'))
                s.pop_back();
            if (!s.empty())
                log("debug string: " + s);
            break;
        }
        case RIP_EVENT:
            log(util::fmt("rip error %lu", (unsigned long)ev.u.RipInfo.dwError));
            break;
        case EXIT_PROCESS_DEBUG_EVENT: {
            exit_code = (int)ev.u.ExitProcess.dwExitCode;
            ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
            log(util::fmt("process exited with code %d (0x%X)", exit_code, (unsigned)exit_code));
            cleanup();
            if (owner.on_exit)
                owner.on_exit(exit_code);
            return;
        }
        case EXCEPTION_DEBUG_EVENT:
            stop = on_exception(ev, status);
            break;
        default:
            break;
        }
        if (stop && !killing) {
            have_event = true;
            cont_status = status;
            event_tid = cur_tid = ev.dwThreadId;
            state = dbg_state::stopped;
            if (owner.on_stop)
                owner.on_stop();
        } else {
            ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, killing ? DBG_CONTINUE : status);
        }
    }

    bool resume(step mode, std::string& err)
    {
        if (state != dbg_state::stopped || !have_event) {
            err = "the process isn't stopped";
            return false;
        }
        HANDLE th = thread_handle(cur_tid);
        thread_ctx c;
        bool have_ctx = load_ctx(th, c);
        bool need_step = mode == step::into;
        if (have_ctx) {
            uint64_t pc = c.pc();
            if (temp_active && temp_bp == pc)
                remove_temp();
            auto it = bps.find(pc);
            if (it != bps.end()) {
                // step off our int3 with the original byte, then put it back
                raw_write(pc, &it->second, 1);
                reinsert = pc;
                need_step = true;
            }
        }
        if (need_step) {
            if (!have_ctx) {
                err = "can't read the thread context";
                return false;
            }
            c.eflags() |= trap_flag;
            store_ctx(th, c);
            stepping = mode == step::into ? step::into : step::resume;
        } else {
            stepping = step::none;
        }
        have_event = false;
        state = dbg_state::running;
        reason.clear();
        if (!ContinueDebugEvent(pid, event_tid, cont_status)) {
            err = "ContinueDebugEvent failed: " + win_error(GetLastError());
            return false;
        }
        return true;
    }
};

debugger::debugger() : d(new impl(*this)) {}

debugger::~debugger()
{
    if (d->state != dbg_state::none) {
        if (d->attached)
            detach();
        else
            kill();
    }
}

bool debugger::supported() { return true; }

bool debugger::start(const std::string& exe, const std::string& args, const std::string& cwd, std::string& err)
{
    if (d->state != dbg_state::none) {
        err = "a process is already being debugged";
        return false;
    }
    bin_arch arch;
    if (loader::peek_arch(exe, arch) && arch == bin_arch::arm64) {
        err = "the debugger runs x86 and x64 programs; this one is arm64";
        return false;
    }
    std::wstring wexe = os::widen(exe);
    std::wstring cmd = L"\"" + wexe + L"\"";
    if (!args.empty())
        cmd += L" " + os::widen(args);
    std::vector<wchar_t> cmdbuf(cmd.begin(), cmd.end());
    cmdbuf.push_back(0);
    std::string dir = cwd;
    if (dir.empty()) {
        size_t slash = exe.find_last_of("/\\");
        if (slash != std::string::npos)
            dir = exe.substr(0, slash);
    }
    std::wstring wdir = os::widen(dir);

    STARTUPINFOW si;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi;
    memset(&pi, 0, sizeof(pi));
    if (!CreateProcessW(wexe.c_str(), cmdbuf.data(), nullptr, nullptr, FALSE, DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
            nullptr, wdir.empty() ? nullptr : wdir.c_str(), &si, &pi)) {
        err = "can't start " + exe + ": " + win_error(GetLastError());
        return false;
    }
    d->reset_for_new();
    d->own_process = pi.hProcess;
    d->own_thread = pi.hThread;
    d->pid = pi.dwProcessId;
    d->main_tid = d->cur_tid = pi.dwThreadId;
    d->state = dbg_state::running;
    DebugSetProcessKillOnExit(TRUE);
    return true;
}

bool debugger::attach(uint32_t pid, std::string& err)
{
    if (d->state != dbg_state::none) {
        err = "a process is already being debugged";
        return false;
    }
    if (!DebugActiveProcess(pid)) {
        err = util::fmt("can't attach to %u: ", pid) + win_error(GetLastError());
        return false;
    }
    d->reset_for_new();
    d->pid = pid;
    d->attached = true;
    d->own_process = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pid);
    d->state = dbg_state::running;
    // closing ceasta must not take down a process we only attached to
    DebugSetProcessKillOnExit(FALSE);
    return true;
}

void debugger::detach()
{
    if (d->state == dbg_state::none)
        return;
    for (const auto& b : d->bps)
        d->raw_write(b.first, &b.second, 1);
    if (d->temp_active && !d->bps.count(d->temp_bp))
        d->raw_write(d->temp_bp, &d->temp_orig, 1);
    d->temp_active = false;
    if (d->have_event && !active_watches().empty())
        for (const auto& t : d->threads)
            d->set_dregs(t.second, {}); // no watch left behind to trip over
    if (d->have_event) {
        // clear a pending trap flag so the program doesn't trip over it
        thread_ctx c;
        HANDLE th = d->thread_handle(d->cur_tid);
        if (d->load_ctx(th, c) && (c.eflags() & trap_flag)) {
            c.eflags() &= ~trap_flag;
            d->store_ctx(th, c);
        }
        ContinueDebugEvent(d->pid, d->event_tid, d->cont_status);
        d->have_event = false;
    }
    DebugActiveProcessStop(d->pid);
    d->log("detached");
    d->cleanup();
}

void debugger::kill()
{
    if (d->state == dbg_state::none)
        return;
    d->killing = true;
    HANDLE h = d->own_process ? d->own_process : d->process;
    if (h)
        TerminateProcess(h, 1);
    if (d->have_event) {
        ContinueDebugEvent(d->pid, d->event_tid, DBG_CONTINUE);
        d->have_event = false;
    }
    d->state = dbg_state::running;
    uint64_t until = os::now_ms() + 5000;
    while (d->state != dbg_state::none && os::now_ms() < until)
        poll(100);
    if (d->state != dbg_state::none) {
        DebugActiveProcessStop(d->pid);
        d->cleanup();
    }
}

void debugger::poll(uint32_t timeout_ms)
{
    // handle a burst of events at once, so a hundred dll loads don't take a hundred frames
    for (int i = 0; i < 256 && d->state == dbg_state::running; i++) {
        DEBUG_EVENT ev;
        if (!WaitForDebugEvent(&ev, i == 0 ? timeout_ms : 0))
            break;
        d->handle(ev);
    }
}

dbg_state debugger::state() const { return d->state; }

bool debugger::raw_cont(std::string& err) { return d->resume(impl::step::none, err); }
bool debugger::raw_step_into(std::string& err) { return d->resume(impl::step::into, err); }

bool debugger::raw_step_over(std::string& err)
{
    if (d->state != dbg_state::stopped) {
        err = "the process isn't stopped";
        return false;
    }
    uint64_t p = pc();
    uint8_t buf[16];
    size_t n = read(p, buf, sizeof(buf));
    disassembler dis;
    insn in;
    if (n && dis.open(is64() ? bin_arch::x64 : bin_arch::x86) && dis.decode(buf, n, p, in) && in.kind == flow::call) {
        if (!d->set_temp(in.next(), "step over")) {
            err = "can't set a breakpoint after the call";
            return false;
        }
        return d->resume(impl::step::none, err);
    }
    return raw_step_into(err);
}

bool debugger::raw_run_to(uint64_t addr, std::string& err)
{
    if (d->state != dbg_state::stopped) {
        err = "the process isn't stopped";
        return false;
    }
    if (!d->set_temp(addr, "run to cursor")) {
        err = "can't write a breakpoint at " + util::hex(addr);
        return false;
    }
    return d->resume(impl::step::none, err);
}

bool debugger::pause(std::string& err)
{
    if (d->state != dbg_state::running || !d->process) {
        err = "the process isn't running";
        return false;
    }
    d->pause_requested = true;
    if (!DebugBreakProcess(d->process)) {
        d->pause_requested = false;
        err = "DebugBreakProcess failed: " + win_error(GetLastError());
        return false;
    }
    return true;
}

bool debugger::add_bp(uint64_t addr, std::string& err)
{
    if (!d->process) {
        err = "no process";
        return false;
    }
    if (d->bps.count(addr))
        return true;
    if (d->temp_active && d->temp_bp == addr) {
        d->bps[addr] = d->temp_orig;
        return true;
    }
    uint8_t orig;
    if (d->raw_read(addr, &orig, 1) != 1 || !d->write_cc(addr)) {
        err = "can't write a breakpoint at " + util::hex(addr);
        return false;
    }
    d->bps[addr] = orig;
    return true;
}

bool debugger::del_bp(uint64_t addr)
{
    auto it = d->bps.find(addr);
    if (it == d->bps.end())
        return false;
    uint8_t orig = it->second;
    d->bps.erase(it);
    if (d->reinsert == addr)
        d->reinsert = 0;
    if (d->temp_active && d->temp_bp == addr)
        d->temp_orig = orig; // the temp breakpoint still needs its int3
    else
        d->raw_write(addr, &orig, 1);
    return true;
}

bool debugger::has_bp(uint64_t addr) const { return d->bps.count(addr) != 0; }

std::vector<uint64_t> debugger::bps() const
{
    std::vector<uint64_t> out;
    for (const auto& b : d->bps)
        out.push_back(b.first);
    return out;
}

uint64_t debugger::pc() const
{
    thread_ctx c;
    return d->state == dbg_state::stopped && d->load_ctx(d->thread_handle(d->cur_tid), c) ? c.pc() : 0;
}

uint64_t debugger::sp() const
{
    thread_ctx c;
    return d->state == dbg_state::stopped && d->load_ctx(d->thread_handle(d->cur_tid), c) ? c.sp() : 0;
}

std::vector<reg_value> debugger::registers() const
{
    std::vector<reg_value> out;
    thread_ctx c;
    if (d->state != dbg_state::stopped || !d->load_ctx(d->thread_handle(d->cur_tid), c))
        return out;
    if (c.wow) {
        const WOW64_CONTEXT& w = c.w;
        out = {{"eax", w.Eax}, {"ebx", w.Ebx}, {"ecx", w.Ecx}, {"edx", w.Edx}, {"esi", w.Esi}, {"edi", w.Edi},
            {"ebp", w.Ebp}, {"esp", w.Esp}, {"eip", w.Eip}, {"eflags", w.EFlags}};
    } else {
        const CONTEXT& n = c.n;
        out = {{"rax", n.Rax}, {"rbx", n.Rbx}, {"rcx", n.Rcx}, {"rdx", n.Rdx}, {"rsi", n.Rsi}, {"rdi", n.Rdi},
            {"rbp", n.Rbp}, {"rsp", n.Rsp}, {"r8", n.R8}, {"r9", n.R9}, {"r10", n.R10}, {"r11", n.R11},
            {"r12", n.R12}, {"r13", n.R13}, {"r14", n.R14}, {"r15", n.R15}, {"rip", n.Rip}, {"eflags", n.EFlags}};
    }
    return out;
}

bool debugger::set_register(const std::string& name, uint64_t v, std::string& err)
{
    HANDLE th = d->thread_handle(d->cur_tid);
    thread_ctx c;
    if (d->state != dbg_state::stopped || !d->load_ctx(th, c)) {
        err = "the process isn't stopped";
        return false;
    }
    std::string r = util::lower(name);
    if (c.wow) {
        WOW64_CONTEXT& w = c.w;
        DWORD* f = r == "eax" ? &w.Eax : r == "ebx" ? &w.Ebx : r == "ecx" ? &w.Ecx : r == "edx" ? &w.Edx :
                   r == "esi" ? &w.Esi : r == "edi" ? &w.Edi : r == "ebp" ? &w.Ebp : r == "esp" ? &w.Esp :
                   r == "eip" ? &w.Eip : r == "eflags" ? &w.EFlags : nullptr;
        if (!f) {
            err = "unknown register " + name;
            return false;
        }
        *f = (DWORD)v;
    } else {
        CONTEXT& n = c.n;
        if (r == "eflags") {
            n.EFlags = (DWORD)v;
        } else {
            DWORD64* f = r == "rax" ? &n.Rax : r == "rbx" ? &n.Rbx : r == "rcx" ? &n.Rcx : r == "rdx" ? &n.Rdx :
                         r == "rsi" ? &n.Rsi : r == "rdi" ? &n.Rdi : r == "rbp" ? &n.Rbp : r == "rsp" ? &n.Rsp :
                         r == "r8" ? &n.R8 : r == "r9" ? &n.R9 : r == "r10" ? &n.R10 : r == "r11" ? &n.R11 :
                         r == "r12" ? &n.R12 : r == "r13" ? &n.R13 : r == "r14" ? &n.R14 : r == "r15" ? &n.R15 :
                         r == "rip" ? &n.Rip : nullptr;
            if (!f) {
                err = "unknown register " + name;
                return false;
            }
            *f = v;
        }
    }
    if (!d->store_ctx(th, c)) {
        err = "SetThreadContext failed: " + win_error(GetLastError());
        return false;
    }
    return true;
}

size_t debugger::read(uint64_t addr, void* out, size_t n) const
{
    size_t got = d->raw_read(addr, out, n);
    uint8_t* p = (uint8_t*)out;
    for (auto it = d->bps.lower_bound(addr); it != d->bps.end() && it->first < addr + got; ++it)
        p[it->first - addr] = it->second;
    if (d->temp_active && d->temp_bp >= addr && d->temp_bp < addr + got && !d->bps.count(d->temp_bp))
        p[d->temp_bp - addr] = d->temp_orig;
    return got;
}

bool debugger::write(uint64_t addr, const void* in, size_t n, std::string& err)
{
    if (!d->process) {
        err = "no process";
        return false;
    }
    // keep our int3s in place, remember the new bytes as the originals instead
    std::vector<uint8_t> buf((const uint8_t*)in, (const uint8_t*)in + n);
    for (size_t i = 0; i < n; i++) {
        uint64_t a = addr + i;
        auto it = d->bps.find(a);
        if (it != d->bps.end()) {
            it->second = buf[i];
            buf[i] = 0xCC;
        } else if (d->temp_active && d->temp_bp == a) {
            d->temp_orig = buf[i];
            buf[i] = 0xCC;
        }
    }
    if (!d->raw_write(addr, buf.data(), n)) {
        err = "can't write memory at " + util::hex(addr);
        return false;
    }
    return true;
}

// every thread is frozen while the program is stopped, so they all get the list now
bool debugger::apply_watches(std::string& err)
{
    if (d->state != dbg_state::stopped || !d->have_event) {
        err = "stop the program first";
        return false;
    }
    std::vector<watch> w = active_watches();
    bool any = false;
    DWORD last = 0;
    for (const auto& t : d->threads) {
        if (d->set_dregs(t.second, w))
            any = true;
        else
            last = GetLastError();
    }
    if (!any) {
        err = "can't set the debug registers: " + win_error(last);
        return false;
    }
    return true;
}

bool debugger::raw_call(uint64_t, const std::vector<uint64_t>&, uint64_t&, std::string& err)
{
    // TODO: drive a synchronous call through the win32 debug loop, like the linux backend does
    err = "calling a function in the target isn't available on windows yet";
    return false;
}

bool debugger::is64() const { return !d->wow64; }
uint64_t debugger::image_base() const { return d->image_base; }
uint32_t debugger::pid() const { return d->pid; }
uint32_t debugger::tid() const { return d->cur_tid; }
int debugger::exit_code() const { return d->exit_code; }
std::string debugger::stop_reason() const { return d->reason; }
std::vector<dbg_module> debugger::modules() const { return d->modules; }

std::vector<dbg_thread> debugger::threads() const
{
    std::vector<dbg_thread> out;
    for (const auto& t : d->threads) {
        thread_ctx c;
        out.push_back({t.first, d->state == dbg_state::stopped && d->load_ctx(t.second, c) ? c.pc() : 0});
    }
    return out;
}

// VirtualQueryEx over the address space: committed memory, named by the module it belongs to
// or the thread whose stack it is
std::vector<dbg_region> debugger::regions() const
{
    std::vector<dbg_region> out;
    if (!d->process)
        return out;
    std::vector<std::pair<uint64_t, DWORD>> stacks; // a thread's sp, its id
    if (d->state == dbg_state::stopped)
        for (const auto& t : d->threads) {
            thread_ctx c;
            if (d->load_ctx(t.second, c))
                stacks.push_back({c.sp(), t.first});
        }
    uint64_t a = 0, top = d->wow64 ? 0x100000000ull : 0x800000000000ull;
    while (a < top) {
        MEMORY_BASIC_INFORMATION mi;
        if (VirtualQueryEx(d->process, (LPCVOID)(uintptr_t)a, &mi, sizeof(mi)) != sizeof(mi))
            break;
        uint64_t base = (uint64_t)(uintptr_t)mi.BaseAddress, size = (uint64_t)mi.RegionSize;
        if (size == 0)
            break;
        if (mi.State == MEM_COMMIT) {
            DWORD p = mi.Protect & 0xFF;
            dbg_region r;
            r.base = base;
            r.size = size;
            r.perms = p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY ? "rwx"
                    : p == PAGE_EXECUTE_READ ? "r-x"
                    : p == PAGE_EXECUTE ? "--x"
                    : p == PAGE_READWRITE || p == PAGE_WRITECOPY ? "rw-"
                    : p == PAGE_READONLY ? "r--" : "---";
            if (mi.Type == MEM_IMAGE) {
                for (const dbg_module& m : d->modules)
                    if (base >= m.base && base < m.base + (m.size ? m.size : 1))
                        r.what = m.path.empty() ? m.name : m.path;
            } else {
                for (const auto& st : stacks)
                    if (st.first >= base && st.first < base + size)
                        r.what = util::fmt("[stack, thread %lu]", (unsigned long)st.second);
                if (r.what.empty() && mi.Type == MEM_MAPPED)
                    r.what = "[mapped]";
            }
            out.push_back(r);
        }
        if (base + size <= a)
            break;
        a = base + size;
    }
    return out;
}

bool debugger::select_thread(uint32_t tid)
{
    if (!d->threads.count(tid))
        return false;
    d->cur_tid = tid;
    return true;
}

std::vector<process_info> list_processes()
{
    std::vector<process_info> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return out;
    PROCESSENTRY32W pe;
    memset(&pe, 0, sizeof(pe));
    pe.dwSize = sizeof(pe);
    for (BOOL ok = Process32FirstW(snap, &pe); ok; ok = Process32NextW(snap, &pe))
        out.push_back({pe.th32ProcessID, os::narrow(pe.szExeFile)});
    CloseHandle(snap);
    std::sort(out.begin(), out.end(), [](const process_info& a, const process_info& b) {
        return util::lower(a.name) < util::lower(b.name);
    });
    return out;
}

#elif !defined(CEASTA_LINUX_DEBUGGER)

// no debugger on this platform, every call reports that

struct debugger::impl {};

debugger::debugger() : d(new impl()) {}
debugger::~debugger() = default;
bool debugger::supported() { return false; }

static const char* unsupported = "debugging is only available in the windows x64 build";

bool debugger::start(const std::string&, const std::string&, const std::string&, std::string& err)
{
    err = unsupported;
    return false;
}
bool debugger::attach(uint32_t, std::string& err)
{
    err = unsupported;
    return false;
}
void debugger::detach() {}
void debugger::kill() {}
void debugger::poll(uint32_t) {}
dbg_state debugger::state() const { return dbg_state::none; }
bool debugger::raw_cont(std::string& err)
{
    err = unsupported;
    return false;
}
bool debugger::raw_step_into(std::string& err)
{
    err = unsupported;
    return false;
}
bool debugger::raw_step_over(std::string& err)
{
    err = unsupported;
    return false;
}
bool debugger::raw_run_to(uint64_t, std::string& err)
{
    err = unsupported;
    return false;
}
bool debugger::pause(std::string& err)
{
    err = unsupported;
    return false;
}
bool debugger::add_bp(uint64_t, std::string& err)
{
    err = unsupported;
    return false;
}
bool debugger::del_bp(uint64_t) { return false; }
bool debugger::has_bp(uint64_t) const { return false; }
std::vector<uint64_t> debugger::bps() const { return {}; }
uint64_t debugger::pc() const { return 0; }
uint64_t debugger::sp() const { return 0; }
std::vector<reg_value> debugger::registers() const { return {}; }
bool debugger::set_register(const std::string&, uint64_t, std::string& err)
{
    err = unsupported;
    return false;
}
size_t debugger::read(uint64_t, void*, size_t) const { return 0; }
bool debugger::write(uint64_t, const void*, size_t, std::string& err)
{
    err = unsupported;
    return false;
}
bool debugger::raw_call(uint64_t, const std::vector<uint64_t>&, uint64_t&, std::string& err)
{
    err = unsupported;
    return false;
}
bool debugger::apply_watches(std::string& err)
{
    err = unsupported;
    return false;
}
bool debugger::is64() const { return true; }
uint64_t debugger::image_base() const { return 0; }
uint32_t debugger::pid() const { return 0; }
uint32_t debugger::tid() const { return 0; }
int debugger::exit_code() const { return 0; }
std::string debugger::stop_reason() const { return std::string(); }
std::vector<dbg_module> debugger::modules() const { return {}; }
std::vector<dbg_region> debugger::regions() const { return {}; }
std::vector<dbg_thread> debugger::threads() const { return {}; }
bool debugger::select_thread(uint32_t) { return false; }
std::vector<process_info> list_processes() { return {}; }

#endif
