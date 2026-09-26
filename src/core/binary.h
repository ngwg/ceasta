#pragma once
#include <cstdint>
#include <string>
#include <vector>

// one loaded file, format independent. pe/elf/mach-o/raw loaders fill this in.

enum class bin_format { none, pe, elf, raw, macho };
enum class bin_arch { x86, x64, arm64 };

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
    // exception landing pads (c++, rust): code only the unwinder jumps to. (function, pad): the
    // pad is part of that function, not one of its own
    std::vector<std::pair<uint64_t, uint64_t>> landing_pads;
    // the file lists every function start (mach-o LC_FUNCTION_STARTS): code found any other way
    // (a switch case nobody resolved, a pointer into the middle) is part of the function around it
    bool starts_complete = false;
    std::vector<uint8_t> file;            // raw file bytes
    // a universal (fat) mach-o file: the architectures in it, and where the loaded one is in file
    std::vector<bin_arch> slices;
    uint64_t slice_off = 0;
    uint64_t slice_size = 0;              // 0: not a slice, the whole file

    int ptr_size() const { return arch == bin_arch::x86 ? 4 : 8; }
    bool is64() const { return arch != bin_arch::x86; }
    // x86 or x64: what the decompiler, the debugger and the signatures understand
    bool is_x86() const { return arch != bin_arch::arm64; }
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
// "x86", "x64", "arm64" (and the usual other spellings)
bool parse_arch(const std::string& s, bin_arch& out);

namespace loader {

struct options {
    // which part of a universal mach-o file to load. unset: x86_64 when it has one (the
    // decompiler reads it), else arm64
    bool has_slice = false;
    bin_arch slice = bin_arch::x64;
};

// detects pe / elf / mach-o, anything else loads as a raw blob (x64, base 0)
bool open(const std::string& path, binary& out, std::string& err, const options& o = options());
bool from_bytes(std::vector<uint8_t> bytes, const std::string& path, binary& out, std::string& err,
    const options& o = options());
void raw(std::vector<uint8_t> bytes, const std::string& path, uint64_t base, bin_arch arch, binary& out);

// the machine a pe / elf / mach-o file is built for, read from its header without loading it
bool peek_arch(const std::string& path, bin_arch& out);

// format parsers, work on out.file (set by the caller)
bool pe(binary& out, std::string& err);
bool elf(binary& out, std::string& err);
bool macho(binary& out, std::string& err, const options& o);
// a mach-o file, thin or universal (by its first bytes)
bool is_macho(const std::vector<uint8_t>& head);
bool macho_arch(const std::vector<uint8_t>& head, bin_arch& out);

// a value in dwarf pointer encoding enc at p, which moves past it: absolute, uleb / sleb, 2 / 4 / 8
// bytes, pc relative. false for the encodings it doesn't know (data / text relative, indirect)
bool read_dwarf_ptr(const binary& b, uint64_t& p, uint8_t enc, uint64_t& out);
// one function's lsda (its exception table: the calls that can throw and where the unwinder goes
// for each): the landing pads go into b.landing_pads. func is the start the pads are offsets from
void read_lsda(binary& b, uint64_t func, uint64_t lsda);
// a go program: every function's name from its pclntab (stripped ones keep it), as symbols
void read_go_functions(binary& b);

}
