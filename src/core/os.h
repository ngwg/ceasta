#pragma once
#include <cstdint>
#include <string>
#include <vector>

// file system + platform bits. all paths are utf-8.

namespace os {

bool read_file(const std::string& path, std::vector<uint8_t>& out, std::string& err);
// the first n bytes (fewer when the file is shorter). false when it can't be opened
bool read_head(const std::string& path, size_t n, std::vector<uint8_t>& out);
// writes to a temp file first then renames, so a crash can't leave half a file
bool write_file(const std::string& path, const std::string& data, std::string& err);
bool exists(const std::string& path);
// lets the owner run the file (a program written out of a database); no-op on windows
void make_executable(const std::string& path);
bool make_dirs(const std::string& path);
// files in dir ending with ext (like ".lua"), sorted by name, full paths
std::vector<std::string> list_files(const std::string& dir, const std::string& ext);
std::string join(const std::string& a, const std::string& b);

std::string exe_dir();
// per user data dir (%APPDATA%\ceasta, ~/.config/ceasta), created on first use
std::string user_dir();

uint64_t now_ms();
void sleep_ms(uint32_t ms);
// opens a folder or file with the system shell. no-op where unsupported
void open_in_shell(const std::string& path);

#ifdef _WIN32
std::wstring widen(const std::string& s);
std::string narrow(const std::wstring& s);
#endif

}
