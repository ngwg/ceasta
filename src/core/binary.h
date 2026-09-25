#pragma once
#include <cstdint>
#include <string>
#include <vector>

// one loaded file, format independent. pe/elf/raw loaders fill this in.

enum class bin_format { none, pe, elf, raw };
enum class bin_arch { x86, x64 };

constexpr uint32_t perm_r = 1;
constexpr uint32_t perm_w = 2;
constexpr uint32_t perm_x = 4;

struct segment {
    std::string name;
    uint64_t start = 0;
    uint64_t end = 0;           // exclusive
    uint32_t perms = 0;
    uint64_t file_off = 0;      // where the initialized bytes live in the file
    uint64_t file_size = 0;     // initialized bytes, the rest reads as zero
    std::vector<uint8_t> data;  // end - start bytes

    uint64_t size() const { return end - start; }
    bool contains(uint64_t a) const { return a >= start && a < end; }
    bool exec() const { return (perms & perm_x) != 0; }
};

struct import_entry {
    std::string lib;
    std::string name;   // "#12" for ordinal only imports
    uint64_t slot = 0;  // iat / got slot the code reads the address from
    bool delay = false; // a pe delay-load import
};

struct export_entry {
    std::string name;
    uint32_t ordinal = 0;
    uint64_t addr = 0;     // 0 when forwarded
    std::string forward;   // "dll.func" for forwarded exports
};

struct symbol_entry {
    std::string name;
    uint64_t addr = 0;
    uint64_t size = 0;
    bool func = false;
};

struct binary {
    std::string path;
    std::string name;
    bin_format format = bin_format::none;
    bin_arch arch = bin_arch::x64;
    uint64_t base = 0;
    uint64_t entry = 0;
    bool has_entry = false;
    std::string kind;                     // "exe (gui)", "dll", "elf pie", ...
    std::vector<std::string> notes;       // loader warnings / info for the output log
    std::vector<std::string> libs;        // needed libraries (elf DT_NEEDED, pe import dlls)
    std::vector<segment> segments;        // sorted by start
    std::vector<import_entry> imports;
    std::vector<export_entry> exports;
    std::vector<symbol_entry> symbols;
    std::vector<uint64_t> func_hints;     // extra function starts (pdata, tls callbacks, init arrays)
    std::vector<uint64_t> ptr_locs;       // addresses holding absolute pointers (from relocations)
    std::vector<uint8_t> file;            // raw file bytes

    int ptr_size() const { return arch == bin_arch::x64 ? 8 : 4; }
    bool is64() const { return arch == bin_arch::x64; }
    const segment* seg_at(uint64_t a) const;
    bool is_code(uint64_t a) const;
    bool is_mapped(uint64_t a) const { return seg_at(a) != nullptr; }
    uint64_t min_addr() const;
    uint64_t max_addr() const;

    // reads up to n bytes, stops at unmapped memory. returns bytes read
    size_t read(uint64_t a, void* out, size_t n) const;
    bool read_u8(uint64_t a, uint8_t& v) const { return read(a, &v, 1) == 1; }
    bool read_u16(uint64_t a, uint16_t& v) const;
    bool read_u32(uint64_t a, uint32_t& v) const;
    bool read_u64(uint64_t a, uint64_t& v) const;
    bool read_ptr(uint64_t a, uint64_t& v) const;
    // nul terminated ascii at a, capped at max_len
    std::string read_cstr(uint64_t a, size_t max_len = 256) const;
    // overwrites mapped bytes (the loaders apply relocations with it)
    bool patch(uint64_t a, const void* src, size_t n);

    // sort segments, fill data for each from the file
    void finish_segments();
};

const char* format_name(bin_format f);
const char* arch_name(bin_arch a);

namespace loader {

// detects pe / elf, anything else loads as a raw blob (x64, base 0)
bool open(const std::string& path, binary& out, std::string& err);
bool from_bytes(std::vector<uint8_t> bytes, const std::string& path, binary& out, std::string& err);
void raw(std::vector<uint8_t> bytes, const std::string& path, uint64_t base, bin_arch arch, binary& out);

// format parsers, work on out.file (set by the caller)
bool pe(binary& out, std::string& err);
bool elf(binary& out, std::string& err);

}
