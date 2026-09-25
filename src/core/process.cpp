#include "core/process.h"
#include "core/os.h"
#include "core/util.h"
#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <system_error>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#ifdef __linux__
#include <sys/syscall.h>
#endif
#include <unistd.h>
#endif

namespace fs = std::filesystem;

namespace os {

namespace {

void append_capped(std::string& dst, const char* p, size_t n, size_t cap)
{
    if (dst.size() < cap)
        dst.append(p, std::min(n, cap - dst.size()));
}

bool is_program_file(const fs::path& p)
{
    std::error_code ec;
    if (!fs::is_regular_file(p, ec))
        return false;
#ifdef _WIN32
    return true;
#else
    return access(p.c_str(), X_OK) == 0;
#endif
}

} // namespace

#ifdef _WIN32

namespace {

// one argument the way CommandLineToArgvW (and the c runtime) will split it back out
std::wstring quote_arg(const std::wstring& a)
{
    if (!a.empty() && a.find_first_of(L" \t\n\v\"") == std::wstring::npos)
        return a;
    std::wstring o = L"\"";
    for (size_t i = 0;; i++) {
        size_t slashes = 0;
        while (i < a.size() && a[i] == L'\\') {
            slashes++;
            i++;
        }
        if (i == a.size()) {
            o.append(slashes * 2, L'\\'); // they come before the closing quote
            break;
        }
        if (a[i] == L'"') {
            o.append(slashes * 2 + 1, L'\\');
            o.push_back(L'"');
        } else {
            o.append(slashes, L'\\');
            o.push_back(a[i]);
        }
    }
    o.push_back(L'"');
    return o;
}

// reads what's waiting in a pipe without blocking. false once the pipe is gone
bool drain(HANDLE h, std::string& dst, size_t cap)
{
    for (;;) {
        DWORD avail = 0;
        if (!PeekNamedPipe(h, nullptr, 0, nullptr, &avail, nullptr))
            return false;
        if (avail == 0)
            return true;
        char buf[65536];
        DWORD got = 0;
        if (!ReadFile(h, buf, std::min<DWORD>(avail, sizeof(buf)), &got, nullptr) || got == 0)
            return false;
        append_capped(dst, buf, got, cap);
    }
}

} // namespace

process_result run_process(const std::vector<std::string>& argv, uint32_t timeout_ms, const std::atomic<bool>* cancel,
    size_t max_output)
{
    process_result r;
    if (argv.empty()) {
        r.error = "nothing to run";
        return r;
    }
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    HANDLE out_r = nullptr, out_w = nullptr, err_r = nullptr, err_w = nullptr;
    if (!CreatePipe(&out_r, &out_w, &sa, 0) || !CreatePipe(&err_r, &err_w, &sa, 0)) {
        r.error = "couldn't make a pipe";
        for (HANDLE h : {out_r, out_w, err_r, err_w})
            if (h)
                CloseHandle(h);
        return r;
    }
    SetHandleInformation(out_r, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(err_r, HANDLE_FLAG_INHERIT, 0);
    HANDLE nul = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, nullptr);
    if (nul == INVALID_HANDLE_VALUE)
        nul = nullptr;

    // the program gets exactly these handles, none of ceasta's others
    STARTUPINFOEXW si{};
    si.StartupInfo.cb = sizeof(si);
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput = nul;
    si.StartupInfo.hStdOutput = out_w;
    si.StartupInfo.hStdError = err_w;
    std::vector<HANDLE> inherit;
    if (nul)
        inherit.push_back(nul);
    inherit.push_back(out_w);
    inherit.push_back(err_w);
    SIZE_T attr_size = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attr_size);
    std::vector<char> attr(attr_size);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)attr.data();
    bool list_ok = InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attr_size) &&
                   UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherit.data(),
                       inherit.size() * sizeof(HANDLE), nullptr, nullptr);

    std::wstring cmd;
    for (size_t i = 0; i < argv.size(); i++) {
        if (i)
            cmd += L" ";
        cmd += quote_arg(widen(argv[i]));
    }
    std::vector<wchar_t> cmdbuf(cmd.begin(), cmd.end());
    cmdbuf.push_back(0);
    PROCESS_INFORMATION pi{};
    BOOL ok = list_ok && CreateProcessW(widen(argv[0]).c_str(), cmdbuf.data(), nullptr, nullptr, TRUE,
                             CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr, &si.StartupInfo, &pi);
    DWORD start_error = GetLastError();
    DeleteProcThreadAttributeList(si.lpAttributeList);
    CloseHandle(out_w);
    CloseHandle(err_w);
    if (nul)
        CloseHandle(nul);
    if (!ok) {
        r.error = util::fmt("couldn't start %s (windows error %lu)", argv[0].c_str(), (unsigned long)start_error);
        CloseHandle(out_r);
        CloseHandle(err_r);
        return r;
    }
    r.started = true;
    CloseHandle(pi.hThread);

    uint64_t deadline = now_ms() + timeout_ms;
    for (;;) {
        drain(out_r, r.out, max_output);
        drain(err_r, r.err, max_output);
        if (WaitForSingleObject(pi.hProcess, 20) == WAIT_OBJECT_0)
            break;
        bool stop = false;
        if (cancel && cancel->load())
            stop = r.cancelled = true;
        else if (now_ms() >= deadline)
            stop = r.timed_out = true;
        if (stop) {
            TerminateProcess(pi.hProcess, 1);
            WaitForSingleObject(pi.hProcess, 5000);
            break;
        }
    }
    // what it wrote just before it ended
    drain(out_r, r.out, max_output);
    drain(err_r, r.err, max_output);
    DWORD code = 0;
    if (GetExitCodeProcess(pi.hProcess, &code))
        r.exit_code = (int)code;
    CloseHandle(pi.hProcess);
    CloseHandle(out_r);
    CloseHandle(err_r);
    return r;
}

std::string find_program(const std::string& name)
{
    if (name.empty())
        return std::string();
    fs::path p = fs::path(widen(name));
    if (name.find_first_of("/\\:") != std::string::npos) {
        if (is_program_file(p))
            return name;
        if (!p.has_extension() && is_program_file(fs::path(widen(name + ".exe"))))
            return name + ".exe";
        return std::string();
    }
    const wchar_t* path = _wgetenv(L"PATH");
    if (!path)
        return std::string();
    std::wstring all = path;
    size_t start = 0;
    while (start <= all.size()) {
        size_t end = all.find(L';', start);
        if (end == std::wstring::npos)
            end = all.size();
        std::wstring dir = all.substr(start, end - start);
        if (!dir.empty()) {
            for (const std::string& n : {name, name + ".exe"}) {
                fs::path c = fs::path(dir) / fs::path(widen(n));
                if (is_program_file(c))
                    return narrow(c.wstring());
            }
        }
        start = end + 1;
    }
    return std::string();
}

#else

namespace {

// a pipe whose ends other programs ceasta starts don't get
bool cloexec_pipe(int p[2])
{
#ifdef __linux__
    return pipe2(p, O_CLOEXEC) == 0;
#else
    if (pipe(p) != 0)
        return false;
    fcntl(p[0], F_SETFD, FD_CLOEXEC);
    fcntl(p[1], F_SETFD, FD_CLOEXEC);
    return true;
#endif
}

} // namespace

process_result run_process(const std::vector<std::string>& argv, uint32_t timeout_ms, const std::atomic<bool>* cancel,
    size_t max_output)
{
    process_result r;
    if (argv.empty()) {
        r.error = "nothing to run";
        return r;
    }
    int out_p[2], err_p[2];
    if (!cloexec_pipe(out_p)) {
        r.error = std::string("couldn't make a pipe: ") + strerror(errno);
        return r;
    }
    if (!cloexec_pipe(err_p)) {
        r.error = std::string("couldn't make a pipe: ") + strerror(errno);
        close(out_p[0]);
        close(out_p[1]);
        return r;
    }
    // everything the child uses is ready before fork: another thread may hold a lock
    std::vector<char*> cargv;
    for (const std::string& a : argv)
        cargv.push_back(const_cast<char*>(a.c_str()));
    cargv.push_back(nullptr);
    long max_fd = sysconf(_SC_OPEN_MAX);
    if (max_fd < 0 || max_fd > 65536)
        max_fd = 65536;

    pid_t pid = fork();
    if (pid == 0) {
        int nul = open("/dev/null", O_RDONLY);
        if (nul >= 0)
            dup2(nul, 0);
        dup2(out_p[1], 1);
        dup2(err_p[1], 2);
#if defined(__linux__) && defined(SYS_close_range)
        if (syscall(SYS_close_range, 3u, ~0u, 0u) != 0)
#endif
            for (long fd = 3; fd < max_fd; fd++)
                close((int)fd);
        execv(cargv[0], cargv.data());
        _exit(127);
    }
    close(out_p[1]);
    close(err_p[1]);
    if (pid < 0) {
        r.error = std::string("fork failed: ") + strerror(errno);
        close(out_p[0]);
        close(err_p[0]);
        return r;
    }
    r.started = true;

    uint64_t deadline = now_ms() + timeout_ms;
    pollfd fds[2] = {{out_p[0], POLLIN, 0}, {err_p[0], POLLIN, 0}};
    int status = 0;
    bool exited = false;
    char buf[65536];
    for (;;) {
        if (cancel && cancel->load()) {
            r.cancelled = true;
            break;
        }
        uint64_t now = now_ms();
        if (now >= deadline) {
            r.timed_out = true;
            break;
        }
        if (fds[0].fd < 0 && fds[1].fd < 0) {
            // both pipes are closed: wait for the exit itself
            pid_t w = waitpid(pid, &status, WNOHANG);
            if (w == pid || (w < 0 && errno == ECHILD)) {
                // ECHILD: someone else collected it (the linux debugger waits for any child)
                exited = true;
                break;
            }
            usleep(10000);
            continue;
        }
        int n = poll(fds, 2, (int)std::min<uint64_t>(deadline - now, 100));
        if (n < 0 && errno != EINTR)
            break;
        for (pollfd& f : fds) {
            if (f.fd < 0 || !(f.revents & (POLLIN | POLLHUP | POLLERR)))
                continue;
            ssize_t got = read(f.fd, buf, sizeof(buf));
            if (got > 0) {
                append_capped(&f == &fds[0] ? r.out : r.err, buf, (size_t)got, max_output);
            } else if (got == 0 || (errno != EINTR && errno != EAGAIN)) {
                close(f.fd);
                f.fd = -1;
            }
        }
    }
    for (pollfd& f : fds)
        if (f.fd >= 0)
            close(f.fd);
    if (!exited) {
        if (r.cancelled || r.timed_out || waitpid(pid, &status, WNOHANG) != pid) {
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
        }
    }
    if (WIFEXITED(status))
        r.exit_code = WEXITSTATUS(status);
    if (r.exit_code == 127 && r.out.empty() && r.err.empty()) {
        r.started = false;
        r.error = "couldn't run " + argv[0];
    }
    return r;
}

std::string find_program(const std::string& name)
{
    if (name.empty())
        return std::string();
    if (name.find('/') != std::string::npos)
        return is_program_file(fs::path(name)) ? name : std::string();
    const char* path = getenv("PATH");
    if (!path)
        return std::string();
    for (const std::string& dir : util::split(path, ":")) {
        if (dir.empty())
            continue;
        fs::path c = fs::path(dir) / name;
        if (is_program_file(c))
            return c.string();
    }
    return std::string();
}

#endif

}
