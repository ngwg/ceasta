#include "core/binary.h"
#include "core/util.h"
#include <algorithm>
#include <cstdlib>

// pe32 / pe32+ loader. every field read is bounds checked, the file is untrusted.

namespace {

struct pe_section {
    std::string name;
    uint32_t va = 0;
    uint32_t vsize = 0;
    uint32_t raw_size = 0;
    uint32_t raw_ptr = 0;
    uint32_t flags = 0;
};

const size_t max_imports = 200000;

std::string clean_name(const char* p, size_t n)
{
    std::string s;
    for (size_t i = 0; i < n && p[i]; i++) {
        unsigned char c = (unsigned char)p[i];
        s += (c >= 32 && c < 127) ? (char)c : '?';
    }
    return s;
}

void add_lib(binary& b, const std::string& lib)
{
    if (std::find(b.libs.begin(), b.libs.end(), lib) == b.libs.end())
        b.libs.push_back(lib);
}

// reads one thunk array (import name table) and pairs it with the iat slots
void read_thunks(binary& b, const std::string& dll, uint64_t names_va, uint64_t iat_va)
{
    int ps = b.ptr_size();
    uint64_t ord_flag = b.is64() ? 0x8000000000000000ull : 0x80000000ull;
    for (uint32_t j = 0; j < 65536 && b.imports.size() < max_imports; j++) {
        uint64_t v;
        if (!b.read_ptr(names_va + (uint64_t)j * ps, v) || v == 0)
            break;
        import_entry e;
        e.lib = dll;
        e.slot = iat_va + (uint64_t)j * ps;
        if (v & ord_flag) {
            e.name = util::fmt("#%u", (unsigned)(v & 0xffff));
        } else {
            e.name = b.read_cstr(b.base + (v & 0x7fffffff) + 2, 512);
            if (e.name.empty())
                e.name = util::fmt("?%llx", (unsigned long long)v);
        }
        b.imports.push_back(e);
    }
}

void parse_imports(binary& b, uint32_t rva)
{
    for (uint32_t i = 0; i < 4096; i++) {
        uint8_t d[20];
        if (b.read(b.base + rva + (uint64_t)i * 20, d, 20) != 20)
            break;
        uint32_t oft = util::rd32(d), name_rva = util::rd32(d + 12), ft = util::rd32(d + 16);
        if (oft == 0 && name_rva == 0 && ft == 0)
            break;
        if (ft == 0)
            continue;
        std::string dll = b.read_cstr(b.base + name_rva, 256);
        if (dll.empty())
            dll = "?";
        add_lib(b, dll);
        read_thunks(b, dll, b.base + (oft ? oft : ft), b.base + ft);
    }
}

void parse_delay_imports(binary& b, uint32_t rva)
{
    for (uint32_t i = 0; i < 4096; i++) {
        uint8_t d[32];
        if (b.read(b.base + rva + (uint64_t)i * 32, d, 32) != 32)
            break;
        uint32_t attrs = util::rd32(d), name = util::rd32(d + 4), iat = util::rd32(d + 12), names = util::rd32(d + 16);
        if (name == 0)
            break;
        // old style descriptors hold vas instead of rvas
        uint64_t adj = (attrs & 1) ? b.base : 0;
        std::string dll = b.read_cstr(adj + name, 256);
        if (dll.empty() || iat == 0 || names == 0)
            continue;
        add_lib(b, dll);
        size_t first = b.imports.size();
        read_thunks(b, dll, adj + names, adj + iat);
        for (size_t k = first; k < b.imports.size(); k++)
            b.imports[k].delay = true;
    }
}

void parse_exports(binary& b, uint32_t rva, uint32_t size)
{
    uint8_t d[40];
    if (b.read(b.base + rva, d, 40) != 40)
        return;
    uint32_t ord_base = util::rd32(d + 16);
    uint32_t nfuncs = std::min<uint32_t>(util::rd32(d + 20), 1u << 20);
    uint32_t nnames = std::min<uint32_t>(util::rd32(d + 24), 1u << 20);
    uint32_t funcs = util::rd32(d + 28), names = util::rd32(d + 32), ords = util::rd32(d + 36);

    std::vector<std::string> by_index(nfuncs);
    for (uint32_t j = 0; j < nnames; j++) {
        uint16_t idx;
        uint32_t name_rva;
        if (!b.read_u16(b.base + ords + (uint64_t)j * 2, idx) || !b.read_u32(b.base + names + (uint64_t)j * 4, name_rva))
            break;
        if (idx < nfuncs && by_index[idx].empty())
            by_index[idx] = b.read_cstr(b.base + name_rva, 512);
    }
    for (uint32_t i = 0; i < nfuncs; i++) {
        uint32_t f;
        if (!b.read_u32(b.base + funcs + (uint64_t)i * 4, f))
            break;
        if (f == 0)
            continue;
        export_entry e;
        e.ordinal = ord_base + i;
        e.name = by_index[i].empty() ? util::fmt("ord_%u", e.ordinal) : by_index[i];
        if (f >= rva && f < (uint64_t)rva + size)
            e.forward = b.read_cstr(b.base + f, 512);
        else
            e.addr = b.base + f;
        b.exports.push_back(e);
    }
}

// x64 .pdata, gives exact function starts. chained entries are function fragments, skip them
void parse_pdata(binary& b, uint32_t rva, uint32_t size)
{
    uint32_t n = std::min<uint32_t>(size / 12, 1u << 20);
    for (uint32_t i = 0; i < n; i++) {
        uint8_t e[12];
        if (b.read(b.base + rva + (uint64_t)i * 12, e, 12) != 12)
            break;
        uint32_t begin = util::rd32(e), end = util::rd32(e + 4), unwind = util::rd32(e + 8);
        if (begin == 0 || end <= begin || (unwind & 1))
            continue;
        uint8_t ver_flags;
        if (!b.read_u8(b.base + unwind, ver_flags) || ((ver_flags >> 3) & 0x4))
            continue;
        b.func_hints.push_back(b.base + begin);
    }
}

// arm64 .pdata: 8 byte entries, the start and either packed unwind data or where the .xdata is.
// fragments of a function (split off by the compiler, no prolog of their own) are skipped
void parse_pdata_arm64(binary& b, uint32_t rva, uint32_t size)
{
    uint32_t n = std::min<uint32_t>(size / 8, 1u << 20);
    for (uint32_t i = 0; i < n; i++) {
        uint32_t begin, unwind;
        if (!b.read_u32(b.base + rva + (uint64_t)i * 8, begin) || !b.read_u32(b.base + rva + (uint64_t)i * 8 + 4, unwind))
            break;
        if (begin == 0 || (begin & 3))
            continue;
        uint32_t flag = unwind & 3;
        if (flag == 2 || flag == 3)
            continue; // packed, no prolog: a fragment
        if (flag == 0) {
            // .xdata header, then epilog scopes, then the unwind codes. a fragment's codes start with end_c
            uint32_t h;
            if (!b.read_u32(b.base + unwind, h))
                continue;
            uint32_t epilogs = (h >> 22) & 31, words = h >> 27;
            uint64_t p = b.base + unwind + 4;
            if (epilogs == 0 && words == 0) {
                uint32_t h2;
                if (!b.read_u32(p, h2))
                    continue;
                epilogs = h2 & 0xffff;
                p += 4;
            }
            if (!(h & (1u << 21)))
                p += (uint64_t)epilogs * 4; // e set: the one epilog is described in the header
            uint8_t first = 0;
            if (b.read_u8(p, first) && first == 0xe5)
                continue;
        }
        b.func_hints.push_back(b.base + begin);
    }
}

void parse_tls(binary& b, uint32_t rva)
{
    uint64_t list = 0;
    if (b.is64()) {
        if (!b.read_u64(b.base + rva + 24, list))
            return;
    } else {
        uint32_t v;
        if (!b.read_u32(b.base + rva + 12, v))
            return;
        list = v;
    }
    for (int k = 0; list && k < 64; k++) {
        uint64_t cb;
        if (!b.read_ptr(list + (uint64_t)k * b.ptr_size(), cb) || cb == 0)
            break;
        if (!b.is_code(cb))
            continue;
        b.func_hints.push_back(cb);
        b.symbols.push_back({util::fmt("tls_callback_%d", k), cb, 0, true});
    }
}

// base relocations, every absolute pointer in the image has one
void parse_relocs(binary& b, uint32_t rva, uint32_t size)
{
    uint64_t pos = b.base + rva, end = pos + size;
    while (pos + 8 <= end && b.ptr_locs.size() < (4u << 20)) {
        uint32_t page, block;
        if (!b.read_u32(pos, page) || !b.read_u32(pos + 4, block) || block < 8)
            break;
        uint32_t n = (block - 8) / 2;
        for (uint32_t i = 0; i < n; i++) {
            uint16_t e;
            if (!b.read_u16(pos + 8 + (uint64_t)i * 2, e))
                break;
            int type = e >> 12;
            if ((type == 10 && b.is64()) || (type == 3 && !b.is64()))
                b.ptr_locs.push_back(b.base + page + (e & 0xfff));
        }
        pos += block;
    }
}

// coff symbol table, mingw and clang builds often keep it
void parse_coff_symbols(binary& b, const util::byte_reader& r, uint32_t ptr, uint32_t count, const std::vector<pe_section>& secs)
{
    if (ptr == 0 || count == 0 || ptr >= b.file.size())
        return;
    uint64_t max_count = (b.file.size() - ptr) / 18;
    count = (uint32_t)std::min<uint64_t>(count, max_count);
    uint64_t strtab = (uint64_t)ptr + (uint64_t)count * 18;
    uint32_t strtab_size = r.u32(strtab);
    for (uint32_t i = 0; i < count; i++) {
        uint64_t rec = (uint64_t)ptr + (uint64_t)i * 18;
        const uint8_t* p = &b.file[(size_t)rec];
        int16_t sect = (int16_t)util::rd16(p + 12);
        uint16_t type = util::rd16(p + 14);
        uint8_t cls = p[16], naux = p[17];
        std::string name;
        if (util::rd32(p) == 0) {
            uint32_t off = util::rd32(p + 4);
            if (off >= 4 && off < strtab_size && r.ok(strtab + off, 1)) {
                uint64_t max_n = std::min<uint64_t>(strtab_size - off, b.file.size() - (strtab + off));
                name = clean_name((const char*)&b.file[(size_t)(strtab + off)], (size_t)std::min<uint64_t>(max_n, 512));
            }
        } else {
            name = clean_name((const char*)p, 8);
        }
        i += naux;
        if ((cls != 2 && cls != 3) || sect <= 0 || sect > (int)secs.size())
            continue;
        if (name.empty() || name[0] == '.' || name.find("@feat") != std::string::npos)
            continue;
        uint64_t addr = b.base + secs[(size_t)sect - 1].va + util::rd32(p + 8);
        bool func = ((type >> 4) & 0x3) == 2;
        b.symbols.push_back({name, addr, 0, func});
        if (func && b.is_code(addr))
            b.func_hints.push_back(addr);
    }
}

}

namespace loader {

bool pe(binary& b, std::string& err)
{
    util::byte_reader r{b.file};
    uint32_t lfanew = r.u32(0x3c);
    uint64_t coff = (uint64_t)lfanew + 4;
    if (!r.ok(coff, 20)) {
        err = "truncated pe header";
        return false;
    }
    uint16_t machine = r.u16(coff);
    uint16_t nsec = r.u16(coff + 2);
    uint32_t sym_ptr = r.u32(coff + 8), sym_count = r.u32(coff + 12);
    uint16_t opt_size = r.u16(coff + 16);
    uint16_t chars = r.u16(coff + 18);
    uint64_t opt = coff + 20;

    if (machine == 0x14c)
        b.arch = bin_arch::x86;
    else if (machine == 0x8664)
        b.arch = bin_arch::x64;
    else if (machine == 0xaa64)
        b.arch = bin_arch::arm64;
    else {
        err = util::fmt("unsupported pe machine 0x%x (x86, x64 and arm64 are supported)", machine);
        return false;
    }
    if (!r.ok(opt, 2) || opt_size < 2) {
        err = "missing pe optional header";
        return false;
    }
    uint16_t magic = r.u16(opt);
    bool pe64 = magic == 0x20b;
    if (magic != 0x10b && magic != 0x20b) {
        err = util::fmt("bad optional header magic 0x%x", magic);
        return false;
    }
    if (pe64 != b.is64())
        b.notes.push_back("optional header type doesn't match the machine field");
    if (b.arch == bin_arch::arm64 && !pe64) {
        err = "arm64 pe file with a 32 bit optional header";
        return false;
    }
    // the optional header type decides pointer sizes in the tables
    if (b.arch != bin_arch::arm64)
        b.arch = pe64 ? bin_arch::x64 : bin_arch::x86;

    uint32_t min_opt = pe64 ? 112 : 96;
    if (opt_size < min_opt || !r.ok(opt, min_opt)) {
        err = "truncated pe optional header";
        return false;
    }
    uint32_t aep = r.u32(opt + 16);
    b.base = pe64 ? r.u64(opt + 24) : r.u32(opt + 28);
    uint32_t hdr_size = r.u32(opt + 60);
    uint16_t subsystem = r.u16(opt + 68);
    uint32_t ndirs = std::min<uint32_t>(r.u32(opt + (pe64 ? 108 : 92)), 16);
    uint64_t dirs = opt + (pe64 ? 112 : 96);
    ndirs = (uint32_t)std::min<uint64_t>(ndirs, (opt_size - (dirs - opt)) / 8);
    auto dir = [&](uint32_t i, uint32_t& rva, uint32_t& size) {
        rva = size = 0;
        if (i >= ndirs || !r.ok(dirs + i * 8, 8))
            return false;
        rva = r.u32(dirs + i * 8);
        size = r.u32(dirs + i * 8 + 4);
        return rva != 0;
    };

    // section table
    uint64_t sec_off = opt + opt_size;
    std::vector<pe_section> secs;
    if (nsec > 1024) {
        b.notes.push_back(util::fmt("%u sections declared, only the first 1024 are used", nsec));
        nsec = 1024;
    }
    uint64_t strtab = (uint64_t)sym_ptr + (uint64_t)sym_count * 18;
    for (uint32_t i = 0; i < nsec; i++) {
        uint64_t s = sec_off + (uint64_t)i * 40;
        if (!r.ok(s, 40)) {
            b.notes.push_back("section table is truncated");
            break;
        }
        pe_section ps;
        ps.name = clean_name((const char*)&b.file[(size_t)s], 8);
        // long names ("/4") point into the coff string table
        if (ps.name.size() > 1 && ps.name[0] == '/' && sym_ptr) {
            uint64_t off = strtoull(ps.name.c_str() + 1, nullptr, 10);
            if (r.ok(strtab + off, 1))
                ps.name = clean_name((const char*)&b.file[(size_t)(strtab + off)], (size_t)std::min<uint64_t>(64, b.file.size() - (strtab + off)));
        }
        ps.vsize = r.u32(s + 8);
        ps.va = r.u32(s + 12);
        ps.raw_size = r.u32(s + 16);
        ps.raw_ptr = r.u32(s + 20);
        ps.flags = r.u32(s + 36);
        secs.push_back(ps);
    }

    // header as its own read only segment, like the loader maps it
    {
        segment h;
        h.name = "header";
        uint64_t n = hdr_size ? hdr_size : 0x400;
        n = std::min<uint64_t>(n, std::max<uint64_t>(b.file.size(), 1));
        n = std::min<uint64_t>(n, 0x10000);
        h.start = b.base;
        h.end = b.base + n;
        h.perms = perm_r;
        h.file_off = 0;
        h.file_size = n;
        if (h.end > h.start)
            b.segments.push_back(h);
    }
    for (const pe_section& ps : secs) {
        uint64_t size = ps.vsize ? ps.vsize : ps.raw_size;
        if (size == 0)
            continue;
        segment s;
        s.name = ps.name.empty() ? "noname" : ps.name;
        s.start = b.base + ps.va;
        s.end = s.start + size;
        if (s.start < b.base || s.end < s.start) {
            b.notes.push_back("section " + s.name + " has an address that wraps around, skipped");
            continue;
        }
        if (ps.flags & 0x40000000)
            s.perms |= perm_r;
        if (ps.flags & 0x80000000)
            s.perms |= perm_w;
        if (ps.flags & (0x20000000 | 0x20))
            s.perms |= perm_x | perm_r;
        if (s.perms == 0)
            s.perms = perm_r;
        s.file_off = ps.raw_ptr;
        s.file_size = ps.raw_ptr ? ps.raw_size : 0;
        b.segments.push_back(s);
    }
    b.finish_segments();

    uint32_t rva, size;
    if (dir(1, rva, size))
        parse_imports(b, rva);
    if (dir(13, rva, size))
        parse_delay_imports(b, rva);
    if (dir(0, rva, size))
        parse_exports(b, rva, size);
    if (b.arch == bin_arch::arm64 && dir(3, rva, size))
        parse_pdata_arm64(b, rva, size);
    else if (b.is64() && dir(3, rva, size))
        parse_pdata(b, rva, size);
    if (dir(9, rva, size))
        parse_tls(b, rva);
    if (dir(5, rva, size))
        parse_relocs(b, rva, size);
    parse_coff_symbols(b, r, sym_ptr, sym_count, secs);
    for (const export_entry& e : b.exports)
        if (e.addr && b.is_code(e.addr))
            b.func_hints.push_back(e.addr);

    if (aep) {
        b.entry = b.base + aep;
        b.has_entry = true;
        b.func_hints.push_back(b.entry);
    }

    b.format = bin_format::pe;
    if (chars & 0x2000)
        b.kind = "dll";
    else if (subsystem == 2)
        b.kind = "exe (gui)";
    else if (subsystem == 3)
        b.kind = "exe (console)";
    else if (subsystem == 1)
        b.kind = "native / driver";
    else if (subsystem >= 10 && subsystem <= 13)
        b.kind = "efi";
    else
        b.kind = "exe";
    if (dir(14, rva, size)) {
        b.kind += " .net";
        b.notes.push_back(".net assembly: only the native stub is machine code, the il isn't disassembled");
    }
    return true;
}

}
