#include "core/os.h"
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <system_error>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shellapi.h>
#else
#include <unistd.h>
#endif

namespace fs = std::filesystem;

namespace os {

static const uint64_t max_file_size = 1024ull << 20;

#ifdef _WIN32
std::wstring widen(const std::string& s)
{
    if (s.empty())
        return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring out((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &out[0], n);
    return out;
}

std::string narrow(const std::wstring& s)
{
    if (s.empty())
        return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0, nullptr, nullptr);
    std::string out((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), &out[0], n, nullptr, nullptr);
    return out;
}

static fs::path to_path(const std::string& s) { return fs::path(widen(s)); }
static std::string from_path(const fs::path& p) { return narrow(p.wstring()); }
#else
static fs::path to_path(const std::string& s) { return fs::path(s); }
static std::string from_path(const fs::path& p) { return p.string(); }
#endif

bool read_file(const std::string& path, std::vector<uint8_t>& out, std::string& err)
{
    std::error_code ec;
    fs::path p = to_path(path);
    if (fs::is_directory(p, ec)) {
        err = "is a directory: " + path;
        return false;
    }
    std::ifstream f(p, std::ios::binary);
    if (!f) {
        err = "can't open " + path;
        return false;
    }
    f.seekg(0, std::ios::end);
    std::streamoff size = f.tellg();
    if (size < 0) {
        err = "can't read " + path;
        return false;
    }
    if ((uint64_t)size > max_file_size) {
        err = "file is too large (over 1 GiB): " + path;
        return false;
    }
    f.seekg(0, std::ios::beg);
    out.assign((size_t)size, 0);
    if (size > 0 && !f.read((char*)out.data(), size)) {
        err = "read failed: " + path;
        return false;
    }
    return true;
}

bool write_file(const std::string& path, const std::string& data, std::string& err)
{
    fs::path p = to_path(path);
    fs::path tmp = p;
    tmp += ".tmp";
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f) {
            err = "can't write " + path;
            return false;
        }
        f.write(data.data(), (std::streamsize)data.size());
        if (!f) {
            err = "write failed: " + path;
            return false;
        }
    }
    std::error_code ec;
    fs::rename(tmp, p, ec);
    if (ec) {
        // rename over an existing file can fail on some systems, fall back to remove + rename
        fs::remove(p, ec);
        ec.clear();
        fs::rename(tmp, p, ec);
        if (ec) {
            err = "can't replace " + path + ": " + ec.message();
            return false;
        }
    }
    return true;
}

bool exists(const std::string& path)
{
    std::error_code ec;
    return fs::exists(to_path(path), ec);
}

bool make_dirs(const std::string& path)
{
    std::error_code ec;
    fs::create_directories(to_path(path), ec);
    return fs::is_directory(to_path(path), ec);
}

std::vector<std::string> list_files(const std::string& dir, const std::string& ext)
{
    std::vector<std::string> out;
    std::error_code ec;
    fs::path d = to_path(dir);
    if (!fs::is_directory(d, ec))
        return out;
    for (fs::directory_iterator it(d, ec), end; !ec && it != end; it.increment(ec)) {
        if (!it->is_regular_file(ec))
            continue;
        std::string name = from_path(it->path().filename());
        if (name.size() >= ext.size() && name.compare(name.size() - ext.size(), ext.size(), ext) == 0)
            out.push_back(from_path(it->path()));
    }
    std::sort(out.begin(), out.end());
    return out;
}

std::string join(const std::string& a, const std::string& b)
{
    if (a.empty())
        return b;
    char last = a.back();
    if (last == '/' || last == '\\')
        return a + b;
#ifdef _WIN32
    return a + "\\" + b;
#else
    return a + "/" + b;
#endif
}

std::string exe_dir()
{
#ifdef _WIN32
    std::wstring buf(32768, L'\0');
    DWORD n = GetModuleFileNameW(nullptr, &buf[0], (DWORD)buf.size());
    if (n == 0 || n >= buf.size())
        return ".";
    buf.resize(n);
    return from_path(fs::path(buf).parent_path());
#else
    std::error_code ec;
    fs::path p = fs::read_symlink("/proc/self/exe", ec);
    if (ec)
        return ".";
    return from_path(p.parent_path());
#endif
}

std::string user_dir()
{
    std::string dir;
#ifdef _WIN32
    std::wstring appdata(32768, L'\0');
    DWORD n = GetEnvironmentVariableW(L"APPDATA", &appdata[0], (DWORD)appdata.size());
    if (n > 0 && n < appdata.size())
        dir = join(narrow(appdata.substr(0, n)), "ceasta");
#else
    const char* xdg = getenv("XDG_CONFIG_HOME");
    const char* home = getenv("HOME");
    if (xdg && *xdg)
        dir = join(xdg, "ceasta");
    else if (home && *home)
        dir = join(join(home, ".config"), "ceasta");
#endif
    if (dir.empty())
        dir = join(exe_dir(), "userdata");
    make_dirs(dir);
    return dir;
}

uint64_t now_ms()
{
    using namespace std::chrono;
    return (uint64_t)duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

void open_in_shell(const std::string& path)
{
#ifdef _WIN32
    ShellExecuteW(nullptr, L"open", widen(path).c_str(), nullptr, nullptr, SW_SHOWNORMAL);
#else
    (void)path;
#endif
}

}
