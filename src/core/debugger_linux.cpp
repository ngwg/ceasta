#include "core/debugger.h"

#ifdef CEASTA_LINUX_DEBUGGER

#include "core/disasm.h"
#include "core/os.h"
#include "core/util.h"

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <vector>

#include <dirent.h>
#include <elf.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

// a user-mode debugger built on ptrace, the same facility gdb and lldb use.
// it mirrors the windows backend: everything runs on the calling thread, so the
// app / cli calls poll() to pick up stops. all addresses are runtime addresses.
//
// scope: 64-bit and 32-bit x86 tracees, breakpoints, single step, step over,
// run to, pause, registers, memory (int3 bytes hidden), modules from
// /proc/<pid>/maps, watchpoints in the debug registers. threads are tracked so
// control isn't lost; breakpoints and stepping act on the thread that reported
// the stop.

namespace {

const uint64_t trap_flag = 0x100;

std::string errno_str(int e) { return util::fmt("%s (errno %d)", strerror(e), e); }

// /proc files report size 0, so read them with a plain loop, not stat + read
std::string slurp(const std::string& path)
{
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0)
        return std::string();
    std::string out;
    char buf[8192];
    for (;;) {
        ssize_t r = ::read(fd, buf, sizeof(buf));
        if (r <= 0)
            break;
        out.append(buf, (size_t)r);
    }
    close(fd);
    return out;
}

std::string base_name(const std::string& p)
{
    size_t s = p.find_last_of('/');
    return s == std::string::npos ? p : p.substr(s + 1);
}

// the i386 register block (PTRACE_GETREGSET / NT_PRSTATUS on a 32-bit tracee)
struct regs32 {
    uint32_t ebx, ecx, edx, esi, edi, ebp, eax, xds, xes, xfs, xgs;
    uint32_t orig_eax, eip, xcs, eflags, esp, xss;
};

struct thread_ctx {
    bool m32 = false;
    user_regs_struct r64{};
    regs32 r32{};
    uint64_t pc() const { return m32 ? r32.eip : r64.rip; }
    uint64_t sp() const { return m32 ? r32.esp : r64.rsp; }
    void set_pc(uint64_t v)
    {
        if (m32)
            r32.eip = (uint32_t)v;
        else
            r64.rip = v;
    }
    uint64_t flags() const { return m32 ? r32.eflags : r64.eflags; }
    void set_flags(uint64_t v)
    {
        if (m32)
            r32.eflags = (uint32_t)v;
        else
            r64.eflags = v;
    }
};

} // namespace

struct debugger::impl {
    debugger& owner;
    explicit impl(debugger& o) : owner(o) {}

    enum class step { none, into, resume };

    dbg_state state = dbg_state::none;
    pid_t pid = 0;                 // thread group id (the process)
    pid_t cur_tid = 0;            // the stopped thread we present
    std::map<pid_t, bool> threads; // tid -> running
    int mem_fd = -1;
    bool m32 = false;
    bool attached = false;
    bool killing = false;
    bool at_exec = false;         // consumed the initial exec stop yet
    bool pause_requested = false;
    int pending_signal = 0;       // signal to deliver on the next resume
    uint64_t image_base = 0;
    uint64_t entry = 0;
    std::map<uint64_t, uint8_t> bps; // address -> original byte
    uint64_t temp_bp = 0;
    uint8_t temp_orig = 0;
    bool temp_active = false;
    std::string temp_reason;
    uint64_t reinsert = 0;
    step stepping = step::none;
    pid_t step_tid = 0;           // the thread being stepped
    pid_t orphan_step = 0;        // a thread whose step we stopped waiting for (another stopped first)
    std::set<pid_t> swallow;      // threads with a SIGSTOP of ours (or their first one) to drop
    uint64_t watch_gen = 0;       // bumps with every change to the watch list
    std::map<pid_t, uint64_t> dr_gen; // the watch list each thread's debug registers hold
    int exit_code = 0;
    std::string reason;
    std::vector<dbg_module> modules;
    uint64_t stop_seq = 0, maps_seq = 0; // libraries load after exec: reread the maps after a stop

    void log(const std::string& s) const
    {
        if (owner.on_log)
            owner.on_log(s);
    }

    void open_mem()
    {
        if (mem_fd >= 0)
            close(mem_fd);
        mem_fd = open(("/proc/" + std::to_string(pid) + "/mem").c_str(), O_RDWR | O_CLOEXEC);
    }

    size_t raw_read(uint64_t a, void* out, size_t n) const
    {
        if (mem_fd < 0 || n == 0)
            return 0;
        size_t done = 0;
        while (done < n) {
            ssize_t r = pread(mem_fd, (char*)out + done, n - done, (off_t)(a + done));
            if (r <= 0)
                break;
            done += (size_t)r;
        }
        return done;
    }

    // ptrace poke works through read-only code pages (the tracer is allowed to)
    bool raw_write(uint64_t a, const void* in, size_t n)
    {
        if (!pid || n == 0)
            return false;
        const uint8_t* src = (const uint8_t*)in;
        for (size_t i = 0; i < n;) {
            uint64_t word_addr = (a + i) & ~(uint64_t)(sizeof(long) - 1);
            errno = 0;
            long word = ptrace(PTRACE_PEEKDATA, cur_tid_or_pid(), (void*)(uintptr_t)word_addr, nullptr);
            if (word == -1 && errno)
                return false;
            uint8_t bytes[sizeof(long)];
            memcpy(bytes, &word, sizeof(long));
            size_t off = (size_t)((a + i) - word_addr);
            for (; off < sizeof(long) && i < n; off++, i++)
                bytes[off] = src[i];
            memcpy(&word, bytes, sizeof(long));
            if (ptrace(PTRACE_POKEDATA, cur_tid_or_pid(), (void*)(uintptr_t)word_addr, (void*)word) < 0)
                return false;
        }
        return true;
    }

    pid_t cur_tid_or_pid() const { return cur_tid ? cur_tid : pid; }

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
            temp_orig = it->second;
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

    bool get_ctx(pid_t tid, thread_ctx& c) const
    {
        c = thread_ctx();
        c.m32 = m32;
        iovec iov;
        if (m32) {
            iov.iov_base = &c.r32;
            iov.iov_len = sizeof(c.r32);
        } else {
            iov.iov_base = &c.r64;
            iov.iov_len = sizeof(c.r64);
        }
        return ptrace(PTRACE_GETREGSET, tid, (void*)NT_PRSTATUS, &iov) == 0;
    }

    bool set_ctx(pid_t tid, thread_ctx& c)
    {
        iovec iov;
        if (c.m32) {
            iov.iov_base = &c.r32;
            iov.iov_len = sizeof(c.r32);
        } else {
            iov.iov_base = &c.r64;
            iov.iov_len = sizeof(c.r64);
        }
        return ptrace(PTRACE_SETREGSET, tid, (void*)NT_PRSTATUS, &iov) == 0;
    }

    // ---- debug registers: dr0-dr3 hold the watched addresses, dr7 switches them on and says
    // what to watch, dr6 tells which one fired. the kernel keeps a set per thread and only
    // changes it while the thread is stopped

    static void* dr_offset(int i)
    {
        return (void*)(offsetof(struct user, u_debugreg) + (size_t)i * sizeof(((struct user*)nullptr)->u_debugreg[0]));
    }

    bool poke_dr(pid_t tid, int i, uint64_t v)
    {
        return ptrace(PTRACE_POKEUSER, tid, dr_offset(i), (void*)(uintptr_t)v) == 0;
    }

    // off first, then the addresses, then on: the kernel checks each address against the
    // length dr7 gives it
    bool write_dregs(pid_t tid, const std::vector<debugger::watch>& w, std::string& err)
    {
        if (!poke_dr(tid, 7, 0)) {
            err = "can't write the debug registers: " + errno_str(errno);
            return false;
        }
        for (size_t i = 0; i < w.size() && i < 4; i++)
            if (!poke_dr(tid, (int)i, w[i].addr)) {
                err = "the cpu won't watch " + util::hex(w[i].addr) + ": " + errno_str(errno);
                return false;
            }
        if (!w.empty() && !poke_dr(tid, 7, debugger::watch_dr7(w))) {
            err = "can't switch the watch on: " + errno_str(errno);
            return false;
        }
        return true;
    }

    // a thread's debug registers catch up with the watch list before it runs again
    void sync_dregs(pid_t tid)
    {
        if (!watch_gen)
            return;
        auto it = dr_gen.find(tid);
        if (it != dr_gen.end() && it->second == watch_gen)
            return;
        std::string err;
        if (write_dregs(tid, owner.active_watches(), err))
            dr_gen[tid] = watch_gen;
    }

    // which watches fired on this thread (dr6 bits 0-3); cleared, so an int3 later isn't
    // taken for one
    int take_dr6(pid_t tid)
    {
        errno = 0;
        long v = ptrace(PTRACE_PEEKUSER, tid, dr_offset(6), nullptr);
        if (v == -1 && errno)
            return 0;
        int fired = (int)(v & 0xF);
        if (fired)
            poke_dr(tid, 6, 0);
        return fired;
    }

    // resumes a thread that stopped for our own bookkeeping (its first stop, a clone, a
    // signal handed on), keeping a step on it going and the rest of the state as it is
    bool run_on(pid_t tid, int sig)
    {
        sync_dregs(tid);
        threads[tid] = true;
        bool stepping_it = stepping != step::none && tid == step_tid;
        return ptrace(stepping_it ? PTRACE_SINGLESTEP : PTRACE_CONT, tid, nullptr, (void*)(intptr_t)sig) == 0;
    }

    // detect a 32-bit tracee from the size the kernel fills in for NT_PRSTATUS
    void detect_bits(pid_t tid)
    {
        user_regs_struct buf{};
        iovec iov{&buf, sizeof(buf)};
        if (ptrace(PTRACE_GETREGSET, tid, (void*)NT_PRSTATUS, &iov) == 0)
            m32 = iov.iov_len <= sizeof(regs32);
    }

    uint64_t read_auxv_entry() const
    {
        std::string path = "/proc/" + std::to_string(pid) + "/auxv";
        int fd = open(path.c_str(), O_RDONLY);
        if (fd < 0)
            return 0;
        uint64_t result = 0;
        if (m32) {
            uint32_t pair[2];
            while (::read(fd, pair, sizeof(pair)) == (ssize_t)sizeof(pair) && pair[0])
                if (pair[0] == AT_ENTRY) { result = pair[1]; break; }
        } else {
            uint64_t pair[2];
            while (::read(fd, pair, sizeof(pair)) == (ssize_t)sizeof(pair) && pair[0])
                if (pair[0] == AT_ENTRY) { result = pair[1]; break; }
        }
        close(fd);
        return result;
    }

    void scan_maps()
    {
        modules.clear();
        std::string exe;
        {
            char buf[4096];
            ssize_t n = readlink(("/proc/" + std::to_string(pid) + "/exe").c_str(), buf, sizeof(buf) - 1);
            if (n > 0) exe.assign(buf, (size_t)n);
        }
        std::string maps = slurp("/proc/" + std::to_string(pid) + "/maps");
        if (maps.empty())
            return;
        std::map<std::string, std::pair<uint64_t, uint64_t>> ranges; // path -> [lo, hi)
        for (const std::string& line : util::split(maps, "\n")) {
            if (line.empty())
                continue;
            uint64_t lo = 0, hi = 0;
            size_t dash = line.find('-');
            if (dash == std::string::npos)
                continue;
            lo = strtoull(line.c_str(), nullptr, 16);
            hi = strtoull(line.c_str() + dash + 1, nullptr, 16);
            size_t path_at = line.find('/');
            if (path_at == std::string::npos)
                continue;
            std::string path = util::trim(line.substr(path_at));
            auto& r = ranges[path];
            if (r.second == 0 || lo < r.first)
                r.first = lo;
            if (hi > r.second)
                r.second = hi;
        }
        if (!exe.empty() && ranges.count(exe))
            image_base = ranges[exe].first;
        for (const auto& kv : ranges)
            modules.push_back({base_name(kv.first), kv.first, kv.second.first, kv.second.second - kv.second.first});
        std::sort(modules.begin(), modules.end(),
            [&](const dbg_module& a, const dbg_module& b) { return a.path == exe && b.path != exe ? true
                                                                 : b.path == exe ? false : a.base < b.base; });
    }

    void report(const std::string& why, pid_t tid)
    {
        if (stepping != step::none && step_tid && step_tid != tid)
            orphan_step = step_tid; // its step still ends with a trap: drop that one
        cur_tid = tid;
        state = dbg_state::stopped;
        reason = why;
        stepping = step::none;
        step_tid = 0;
        stop_seq++;
        if (owner.on_stop)
            owner.on_stop();
    }

    // the program is mapped (after execve): read its layout, arm the entry bp.
    // returns false when it decided to keep running (entry bp set), true to stop now.
    bool after_exec(pid_t tid)
    {
        at_exec = true;
        detect_bits(tid);
        open_mem();
        scan_maps();
        entry = read_auxv_entry();
        if (owner.on_created)
            owner.on_created();
        if (owner.break_on_entry && entry && !killing && set_temp(entry, "entry point")) {
            pending_signal = 0;
            do_cont(tid, step::none);
            return false;
        }
        report("entry", tid);
        return true;
    }

    // a thread stopped with SIGTRAP: figure out why
    void on_trap(pid_t tid, int event, bool orphan)
    {
        if (event == PTRACE_EVENT_EXEC) {
            after_exec(tid);
            return;
        }
        thread_ctx c;
        bool have = get_ctx(tid, c);
        uint64_t pc = have ? c.pc() : 0;
        bool mine = stepping != step::none && tid == step_tid;

        if (reinsert) {
            if (bps.count(reinsert))
                write_cc(reinsert);
            reinsert = 0;
        }
        // a watch fired: the instruction just before the pc wrote (or read) the memory
        if (watch_gen) {
            int fired = take_dr6(tid);
            std::vector<debugger::watch> w = owner.active_watches();
            for (size_t i = 0; i < w.size(); i++)
                if (fired & (1 << i)) {
                    report(debugger::watch_text(w[i]), tid);
                    return;
                }
        }
        if (mine && stepping == step::into) {
            report("step", tid);
            return;
        }
        if (mine && stepping == step::resume) {
            do_cont(tid, step::none);
            return;
        }

        uint64_t bp_at = pc ? pc - 1 : 0; // int3 already advanced rip past 0xCC
        if (have && armed(bp_at)) {
            c.set_pc(bp_at);
            set_ctx(tid, c);
            bool user = bps.count(bp_at) != 0;
            std::string why = user ? std::string("breakpoint") : temp_reason;
            if (temp_active && temp_bp == bp_at)
                remove_temp();
            report(why, tid);
            return;
        }
        if (orphan) {
            run_on(tid, 0); // the end of a step we stopped waiting for
            return;
        }
        if (pause_requested) {
            pause_requested = false;
            report("paused", tid);
            return;
        }
        report(pc ? "int3 in the program at " + util::hex(bp_at) : "trap", tid);
    }

    void on_signal(pid_t tid, int sig)
    {
        if (sig == SIGSTOP && pause_requested) {
            pause_requested = false;
            report("paused", tid);
            return;
        }
        // ctrl+c in the terminal: stop there and swallow it (gdb does the same),
        // so continuing doesn't kill the program
        if (sig == SIGINT) {
            pause_requested = false;
            pending_signal = 0;
            report("interrupted (ctrl+c)", tid);
            return;
        }
        // fatal signals: stop and show where. others: hand back to the program.
        bool fatal = sig == SIGSEGV || sig == SIGILL || sig == SIGFPE || sig == SIGBUS ||
                     sig == SIGABRT || sig == SIGSYS || sig == SIGTRAP;
        if (fatal) {
            thread_ctx c;
            uint64_t pc = get_ctx(tid, c) ? c.pc() : 0;
            report(util::fmt("signal %d (%s) at %s", sig, strsignal(sig), util::hex(pc).c_str()), tid);
            pending_signal = sig; // left pending; continuing re-delivers it
        } else {
            run_on(tid, sig);
        }
    }

    void handle_status(pid_t tid, int status)
    {
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            threads.erase(tid);
            swallow.erase(tid);
            dr_gen.erase(tid);
            if (tid == pid) {
                exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
                log(util::fmt("process exited with code %d (0x%X)", exit_code, (unsigned)exit_code));
                int code = exit_code;
                cleanup();
                if (owner.on_exit)
                    owner.on_exit(code);
            }
            return;
        }
        if (!WIFSTOPPED(status))
            return;
        int sig = WSTOPSIG(status);
        int event = status >> 16;
        bool known = threads.count(tid) != 0;
        threads[tid] = false;
        cur_tid = tid;
        if (killing) {
            do_cont(tid, step::none);
            return;
        }
        bool orphan = tid == orphan_step;
        if (orphan)
            orphan_step = 0;
        if (event == PTRACE_EVENT_CLONE || event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK) {
            unsigned long newtid = 0;
            ptrace(PTRACE_GETEVENTMSG, tid, nullptr, &newtid);
            // a new thread starts with a SIGSTOP, unless it already reported that one
            if (newtid && !threads.count((pid_t)newtid)) {
                threads[(pid_t)newtid] = true;
                swallow.insert((pid_t)newtid);
            }
            run_on(tid, 0);
            return;
        }
        // a SIGSTOP we caused: a new thread's first stop, or one that let us update the debug
        // registers. the thread picks those up and runs on
        if (event == 0 && sig == SIGSTOP && (swallow.erase(tid) || !known)) {
            run_on(tid, 0);
            return;
        }
        if (sig == SIGTRAP || event != 0) {
            on_trap(tid, event, orphan);
            return;
        }
        on_signal(tid, sig);
    }

    bool do_cont(pid_t tid, step mode)
    {
        int sig = pending_signal;
        pending_signal = 0;
        sync_dregs(tid);
        __ptrace_request req = mode == step::into || mode == step::resume ? PTRACE_SINGLESTEP : PTRACE_CONT;
        stepping = mode;
        step_tid = mode == step::none ? 0 : tid;
        threads[tid] = true;
        state = dbg_state::running;
        if (ptrace(req, tid, nullptr, (void*)(intptr_t)sig) < 0)
            return false;
        return true;
    }

    bool resume(step mode, std::string& err)
    {
        if (state != dbg_state::stopped) {
            err = "the process isn't stopped";
            return false;
        }
        pid_t tid = cur_tid;
        thread_ctx c;
        bool have = get_ctx(tid, c);
        step m = mode;
        if (have) {
            uint64_t pc = c.pc();
            if (temp_active && temp_bp == pc)
                remove_temp();
            auto it = bps.find(pc);
            if (it != bps.end()) {
                raw_write(pc, &it->second, 1); // step off our int3, then put it back
                reinsert = pc;
                m = mode == step::into ? step::into : step::resume;
            }
        }
        reason.clear();
        if (!do_cont(tid, m)) {
            err = "ptrace continue failed: " + errno_str(errno);
            return false;
        }
        return true;
    }

    void cleanup()
    {
        if (mem_fd >= 0)
            close(mem_fd);
        mem_fd = -1;
        threads.clear();
        bps.clear();
        modules.clear();
        temp_active = false;
        reinsert = 0;
        stepping = step::none;
        step_tid = orphan_step = 0;
        swallow.clear();
        dr_gen.clear();
        watch_gen = 0;
        owner.watch_list_.clear(); // runtime addresses of this process
        owner.watch_pid_ = 0;
        state = dbg_state::none;
        pid = cur_tid = 0;
        at_exec = attached = killing = pause_requested = false;
        pending_signal = 0;
        image_base = entry = 0;
    }

    void reset_for_new()
    {
        cleanup();
        exit_code = 0;
        reason.clear();
        m32 = false;
    }
};

// ---- public surface ----

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
    std::vector<std::string> argv{exe};
    for (const std::string& a : util::split(args, " "))
        if (!a.empty())
            argv.push_back(a);

    // everything the child needs is prepared before fork: another thread may hold a lock
    std::vector<char*> cargv;
    for (auto& s : argv)
        cargv.push_back(const_cast<char*>(s.c_str()));
    cargv.push_back(nullptr);
    long max_fd = sysconf(_SC_OPEN_MAX);
    if (max_fd < 0 || max_fd > 65536)
        max_fd = 65536;

    pid_t child = fork();
    if (child < 0) {
        err = "fork failed: " + errno_str(errno);
        return false;
    }
    if (child == 0) {
        // the program gets stdin / stdout / stderr, not ceasta's other files and sockets (an
        // inherited socket of the ai server would keep its connections open)
#ifdef SYS_close_range
        if (syscall(SYS_close_range, 3u, ~0u, 0u) != 0)
#endif
            for (long fd = 3; fd < max_fd; fd++)
                close((int)fd);
        ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
        if (!cwd.empty() && chdir(cwd.c_str()) != 0)
            _exit(127);
        execv(exe.c_str(), cargv.data());
        _exit(127); // execv failed
    }

    int status = 0;
    if (waitpid(child, &status, 0) < 0 || !WIFSTOPPED(status)) {
        err = "the target did not start under the debugger";
        return false;
    }
    d->reset_for_new();
    d->pid = child;
    d->cur_tid = child;
    d->threads[child] = false;
    long opts = PTRACE_O_EXITKILL | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC;
    ptrace(PTRACE_SETOPTIONS, child, nullptr, (void*)opts);
    d->state = dbg_state::running;
    // this first stop is the post-execve SIGTRAP: the program is already mapped,
    // so set it up here (a later PTRACE_EVENT_EXEC would be too late for our bp)
    d->after_exec(child);
    return true;
}

bool debugger::attach(uint32_t pid, std::string& err)
{
    if (d->state != dbg_state::none) {
        err = "a process is already being debugged";
        return false;
    }
    if (ptrace(PTRACE_ATTACH, (pid_t)pid, nullptr, nullptr) < 0) {
        err = util::fmt("can't attach to %u: ", pid) + errno_str(errno);
        return false;
    }
    int status = 0;
    waitpid((pid_t)pid, &status, 0);
    d->reset_for_new();
    d->pid = (pid_t)pid;
    d->cur_tid = (pid_t)pid;
    d->threads[(pid_t)pid] = false;
    d->attached = true;
    d->at_exec = true;
    long opts = PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC;
    ptrace(PTRACE_SETOPTIONS, (pid_t)pid, nullptr, (void*)opts);
    d->detect_bits((pid_t)pid);
    d->open_mem();
    d->scan_maps();
    d->entry = d->read_auxv_entry();
    d->state = dbg_state::stopped;
    d->reason = "attached";
    if (on_created)
        on_created();
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
    for (const auto& t : d->threads) {
        if (d->watch_gen && !t.second)
            d->poke_dr(t.first, 7, 0); // no watch left behind to trip over
        ptrace(PTRACE_DETACH, t.first, nullptr, nullptr);
    }
    d->log("detached");
    d->cleanup();
}

void debugger::kill()
{
    if (d->state == dbg_state::none)
        return;
    d->killing = true;
    pid_t p = d->pid;
    ::kill(p, SIGKILL);
    uint64_t until = os::now_ms() + 3000;
    while (d->state != dbg_state::none && os::now_ms() < until)
        poll(100);
    if (d->state != dbg_state::none)
        d->cleanup();
}

void debugger::poll(uint32_t timeout_ms)
{
    uint64_t deadline = os::now_ms() + timeout_ms;
    for (int i = 0; i < 512 && d->state == dbg_state::running; i++) {
        int status = 0;
        pid_t t = waitpid(-1, &status, __WALL | WNOHANG);
        if (t == 0) {
            if (os::now_ms() >= deadline)
                break;
            struct timespec ts{0, 2 * 1000 * 1000};
            nanosleep(&ts, nullptr);
            i--;
            continue;
        }
        if (t < 0)
            break;
        d->handle_status(t, status);
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
    if (d->state != dbg_state::running) {
        err = "the process isn't running";
        return false;
    }
    d->pause_requested = true;
    if (::kill(d->pid, SIGSTOP) != 0) {
        d->pause_requested = false;
        err = "can't signal the process: " + errno_str(errno);
        return false;
    }
    return true;
}

bool debugger::add_bp(uint64_t addr, std::string& err)
{
    if (!d->pid) {
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
        d->temp_orig = orig;
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
    return d->state == dbg_state::stopped && d->get_ctx(d->cur_tid, c) ? c.pc() : 0;
}

uint64_t debugger::sp() const
{
    thread_ctx c;
    return d->state == dbg_state::stopped && d->get_ctx(d->cur_tid, c) ? c.sp() : 0;
}

std::vector<reg_value> debugger::registers() const
{
    std::vector<reg_value> out;
    thread_ctx c;
    if (d->state != dbg_state::stopped || !d->get_ctx(d->cur_tid, c))
        return out;
    if (c.m32) {
        const regs32& r = c.r32;
        out = {{"eax", r.eax}, {"ebx", r.ebx}, {"ecx", r.ecx}, {"edx", r.edx}, {"esi", r.esi}, {"edi", r.edi},
            {"ebp", r.ebp}, {"esp", r.esp}, {"eip", r.eip}, {"eflags", r.eflags}};
    } else {
        const user_regs_struct& r = c.r64;
        out = {{"rax", r.rax}, {"rbx", r.rbx}, {"rcx", r.rcx}, {"rdx", r.rdx}, {"rsi", r.rsi}, {"rdi", r.rdi},
            {"rbp", r.rbp}, {"rsp", r.rsp}, {"r8", r.r8}, {"r9", r.r9}, {"r10", r.r10}, {"r11", r.r11},
            {"r12", r.r12}, {"r13", r.r13}, {"r14", r.r14}, {"r15", r.r15}, {"rip", r.rip}, {"eflags", r.eflags}};
    }
    return out;
}

bool debugger::set_register(const std::string& name, uint64_t v, std::string& err)
{
    thread_ctx c;
    if (d->state != dbg_state::stopped || !d->get_ctx(d->cur_tid, c)) {
        err = "the process isn't stopped";
        return false;
    }
    std::string r = util::lower(name);
    if (c.m32) {
        regs32& g = c.r32;
        uint32_t* f = r == "eax" ? &g.eax : r == "ebx" ? &g.ebx : r == "ecx" ? &g.ecx : r == "edx" ? &g.edx :
                      r == "esi" ? &g.esi : r == "edi" ? &g.edi : r == "ebp" ? &g.ebp : r == "esp" ? &g.esp :
                      r == "eip" ? &g.eip : r == "eflags" ? &g.eflags : nullptr;
        if (!f) { err = "unknown register " + name; return false; }
        *f = (uint32_t)v;
    } else {
        user_regs_struct& g = c.r64;
        unsigned long long* f = r == "rax" ? &g.rax : r == "rbx" ? &g.rbx : r == "rcx" ? &g.rcx : r == "rdx" ? &g.rdx :
                      r == "rsi" ? &g.rsi : r == "rdi" ? &g.rdi : r == "rbp" ? &g.rbp : r == "rsp" ? &g.rsp :
                      r == "r8" ? &g.r8 : r == "r9" ? &g.r9 : r == "r10" ? &g.r10 : r == "r11" ? &g.r11 :
                      r == "r12" ? &g.r12 : r == "r13" ? &g.r13 : r == "r14" ? &g.r14 : r == "r15" ? &g.r15 :
                      r == "rip" ? &g.rip : r == "eflags" ? &g.eflags : nullptr;
        if (!f) { err = "unknown register " + name; return false; }
        *f = v;
    }
    if (!d->set_ctx(d->cur_tid, c)) {
        err = "can't set registers: " + errno_str(errno);
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
    if (!d->pid) {
        err = "no process";
        return false;
    }
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

bool debugger::raw_call(uint64_t func, const std::vector<uint64_t>& args, uint64_t& result, std::string& err)
{
    if (d->state != dbg_state::stopped) {
        err = "the process isn't stopped";
        return false;
    }
    if (d->m32) {
        err = "calling a function is 64-bit only for now";
        return false;
    }
    thread_ctx saved;
    if (!d->get_ctx(d->cur_tid, saved)) {
        err = "can't read the registers";
        return false;
    }
    // a place to trap when the call returns: the entry point is mapped and executable. we only
    // trap on it, never run it, so reusing it is fine.
    uint64_t trap = d->entry ? d->entry : func;
    if (trap == func)
        trap = func + 1;

    // run the callee against clean code: lift our int3s (and the entry temp) for the call
    for (const auto& b : d->bps)
        d->raw_write(b.first, &b.second, 1);
    bool had_temp = d->temp_active;
    if (had_temp)
        d->raw_write(d->temp_bp, &d->temp_orig, 1);
    uint8_t trap_orig = 0;
    if (d->raw_read(trap, &trap_orig, 1) != 1) {
        err = "can't read the return trap address";
        for (const auto& b : d->bps)
            d->write_cc(b.first);
        return false;
    }

    // no watch stops inside the call either
    std::vector<watch> watched = active_watches();
    if (!watched.empty())
        d->poke_dr(d->cur_tid, 7, 0);

    thread_ctx c = saved;
    for (size_t i = 0; i < args.size() && i < 6; i++) {
        switch (i) {
        case 0: c.r64.rdi = args[i]; break;
        case 1: c.r64.rsi = args[i]; break;
        case 2: c.r64.rdx = args[i]; break;
        case 3: c.r64.rcx = args[i]; break;
        case 4: c.r64.r8 = args[i]; break;
        case 5: c.r64.r9 = args[i]; break;
        }
    }
    size_t stack_args = args.size() > 6 ? args.size() - 6 : 0;
    uint64_t sp = saved.sp() - 256;                 // clear the red zone
    sp = (sp - (8 + stack_args * 8)) & ~15ULL;      // 16-align the block base
    if (sp % 16 == 0)
        sp -= 8;                                    // so rsp % 16 == 8 at the callee's entry
    d->raw_write(sp, &trap, 8);
    for (size_t i = 0; i < stack_args; i++)
        d->raw_write(sp + 8 + i * 8, &args[6 + i], 8);
    c.r64.rsp = sp;
    c.set_pc(func);

    uint8_t cc = 0xCC;
    d->raw_write(trap, &cc, 1);
    bool ok = false;
    std::string why;
    if (!d->set_ctx(d->cur_tid, c)) {
        why = "can't set the registers";
    } else {
        for (int i = 0; i < 2000000; i++) {
            if (ptrace(PTRACE_CONT, d->cur_tid, nullptr, nullptr) != 0) {
                why = "continue failed: " + errno_str(errno);
                break;
            }
            int status = 0;
            if (waitpid(d->cur_tid, &status, __WALL) < 0) {
                why = "wait failed";
                break;
            }
            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                d->state = dbg_state::none;
                why = "the program exited during the call";
                break;
            }
            if (!WIFSTOPPED(status))
                continue;
            int sig = WSTOPSIG(status);
            if (sig == SIGTRAP) {
                thread_ctx cc2;
                d->get_ctx(d->cur_tid, cc2);
                uint64_t pc = cc2.pc();
                if (pc == trap || pc == trap + 1) {
                    result = cc2.r64.rax;
                    ok = true;
                    break;
                }
                why = "hit a breakpoint at " + util::hex(pc ? pc - 1 : 0) + " inside the call";
                break;
            }
            why = util::fmt("the called function got signal %d", sig);
            break;
        }
    }

    // put everything back: the trap byte, our breakpoints, the saved registers
    if (d->state != dbg_state::none) {
        d->raw_write(trap, &trap_orig, 1);
        for (const auto& b : d->bps)
            d->write_cc(b.first);
        if (had_temp)
            d->write_cc(d->temp_bp);
        d->set_ctx(d->cur_tid, saved);
        std::string ignore;
        if (!watched.empty())
            d->write_dregs(d->cur_tid, watched, ignore);
    }
    if (!ok) {
        err = why.empty() ? "the call didn't return" : why;
        return false;
    }
    return true;
}

// the stopped threads get the list now; the running ones stop for a moment (the kernel only
// changes a stopped thread's registers) and pick it up before they run on
bool debugger::apply_watches(std::string& err)
{
    if (d->state != dbg_state::stopped) {
        err = "stop the program first";
        return false;
    }
    std::vector<watch> w = active_watches();
    if (!d->write_dregs(d->cur_tid, w, err))
        return false;
    d->watch_gen++;
    d->dr_gen[d->cur_tid] = d->watch_gen;
    for (const auto& t : d->threads) {
        if (t.first == d->cur_tid)
            continue;
        std::string ignore;
        if (!t.second) {
            if (d->write_dregs(t.first, w, ignore))
                d->dr_gen[t.first] = d->watch_gen;
        } else if (!d->swallow.count(t.first) && syscall(SYS_tgkill, d->pid, t.first, SIGSTOP) == 0) {
            d->swallow.insert(t.first);
        }
    }
    return true;
}

bool debugger::is64() const { return !d->m32; }
uint64_t debugger::image_base() const { return d->image_base; }
uint32_t debugger::pid() const { return (uint32_t)d->pid; }
uint32_t debugger::tid() const { return (uint32_t)d->cur_tid; }
int debugger::exit_code() const { return d->exit_code; }
std::string debugger::stop_reason() const { return d->reason; }
std::vector<dbg_module> debugger::modules() const
{
    if (d->state == dbg_state::stopped && d->maps_seq != d->stop_seq) {
        d->scan_maps();
        d->maps_seq = d->stop_seq;
    }
    return d->modules;
}

// /proc/<pid>/maps: "lo-hi perms offset dev inode path"
std::vector<dbg_region> debugger::regions() const
{
    std::vector<dbg_region> out;
    if (!d->pid)
        return out;
    for (const std::string& line : util::split(slurp("/proc/" + std::to_string(d->pid) + "/maps"), "\n")) {
        size_t dash = line.find('-'), sp1 = line.find(' ');
        if (dash == std::string::npos || sp1 == std::string::npos || sp1 < dash)
            continue;
        dbg_region r;
        r.base = strtoull(line.c_str(), nullptr, 16);
        uint64_t hi = strtoull(line.c_str() + dash + 1, nullptr, 16);
        if (hi <= r.base)
            continue;
        r.size = hi - r.base;
        r.perms = line.substr(sp1 + 1, 3);
        // the path is the sixth field, and may contain spaces
        size_t at = sp1;
        for (int field = 0; field < 4 && at != std::string::npos; field++)
            at = line.find_first_not_of(' ', line.find(' ', at + 1));
        if (at != std::string::npos && at < line.size())
            r.what = util::trim(line.substr(at));
        out.push_back(r);
    }
    return out;
}

std::vector<dbg_thread> debugger::threads() const
{
    std::vector<dbg_thread> out;
    for (const auto& t : d->threads) {
        thread_ctx c;
        out.push_back({(uint32_t)t.first, d->state == dbg_state::stopped && d->get_ctx(t.first, c) ? c.pc() : 0});
    }
    return out;
}

bool debugger::select_thread(uint32_t tid)
{
    if (!d->threads.count((pid_t)tid))
        return false;
    d->cur_tid = (pid_t)tid;
    return true;
}

std::vector<process_info> list_processes()
{
    std::vector<process_info> out;
    DIR* dir = opendir("/proc");
    if (!dir)
        return out;
    for (dirent* e = readdir(dir); e; e = readdir(dir)) {
        char* end = nullptr;
        long p = strtol(e->d_name, &end, 10);
        if (!end || *end || p <= 0)
            continue;
        std::string name = util::trim(slurp(util::fmt("/proc/%ld/comm", p)));
        if (name.empty())
            continue;
        out.push_back({(uint32_t)p, name});
    }
    closedir(dir);
    std::sort(out.begin(), out.end(),
        [](const process_info& a, const process_info& b) { return util::lower(a.name) < util::lower(b.name); });
    return out;
}

#endif // CEASTA_LINUX_DEBUGGER
