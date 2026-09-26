#include "core/binary.h"
#include "core/util.h"
#include <algorithm>
#include <cstring>
#include <unordered_map>
#include <unordered_set>

// mach-o loader (macos, ios): 64-bit x86_64 and arm64 (arm64e too), a thin file or one slice
// of a universal one. bounds checked, the file is untrusted.
//
// names lose the underscore mach-o puts in front of every c name (_printf is printf, __Z... is
// _Z...), so they read and match (prototypes, what doesn't return) like on the other formats.

namespace {

enum : uint32_t {
    mh_magic = 0xfeedface,
    mh_cigam = 0xcefaedfe,
    mh_magic_64 = 0xfeedfacf,
    mh_cigam_64 = 0xcffaedfe,
    fat_magic = 0xcafebabe,
    fat_magic_64 = 0xcafebabf,

    cpu_x86 = 7,
    cpu_x86_64 = 0x01000007,
    cpu_arm = 12,
    cpu_arm64 = 0x0100000c,
    cpu_arm64_32 = 0x0200000c,
    cpu_ppc = 18,
    cpu_ppc64 = 0x01000012,
    cpu_sub_arm64e = 2,

    lc_req_dyld = 0x80000000,
    lc_symtab = 0x2,
    lc_unixthread = 0x5,
    lc_dysymtab = 0xb,
    lc_load_dylib = 0xc,
    lc_id_dylib = 0xd,
    lc_load_weak_dylib = 0x18 | lc_req_dyld,
    lc_segment_64 = 0x19,
    lc_reexport_dylib = 0x1f | lc_req_dyld,
    lc_lazy_load_dylib = 0x20,
    lc_dyld_info = 0x22,
    lc_dyld_info_only = 0x22 | lc_req_dyld,
    lc_load_upward_dylib = 0x23 | lc_req_dyld,
    lc_function_starts = 0x26,
    lc_main = 0x28 | lc_req_dyld,
    lc_encryption_info_64 = 0x2c,
    lc_dyld_exports_trie = 0x33 | lc_req_dyld,
    lc_dyld_chained_fixups = 0x34 | lc_req_dyld,

    // section types (the low byte of flags) and attributes
    s_zerofill = 0x1,
    s_non_lazy_symbol_pointers = 0x6,
    s_lazy_symbol_pointers = 0x7,
    s_symbol_stubs = 0x8,
    s_mod_init_func_pointers = 0x9,
    s_gb_zerofill = 0xc,
    s_thread_local_zerofill = 0x12,
    s_init_func_offsets = 0x16,
    s_attr_pure_instructions = 0x80000000,
    s_attr_some_instructions = 0x400,

    indirect_symbol_local = 0x80000000,
    indirect_symbol_abs = 0x40000000,
};

// reads from one slice of the file: offsets are from the slice's mach header
struct span {
    const uint8_t* p = nullptr;
    uint64_t n = 0;
    bool ok(uint64_t off, uint64_t len) const { return off <= n && len <= n - off; }
    uint8_t u8(uint64_t off) const { return ok(off, 1) ? p[off] : 0; }
    uint16_t u16(uint64_t off) const { return ok(off, 2) ? util::rd16(p + off) : 0; }
    uint32_t u32(uint64_t off) const { return ok(off, 4) ? util::rd32(p + off) : 0; }
    uint64_t u64(uint64_t off) const { return ok(off, 8) ? util::rd64(p + off) : 0; }
    std::string cstr(uint64_t off, size_t max_len = 1024) const
    {
        std::string s;
        while (ok(off, 1) && s.size() < max_len && p[off])
            s += (char)p[off++];
        return s;
    }
    // a string field of fixed size (segment and section names, 16 bytes)
    std::string fixed(uint64_t off, size_t len) const
    {
        std::string s;
        for (size_t i = 0; i < len && ok(off + i, 1) && p[off + i]; i++)
            s += (char)p[off + i];
        return s;
    }
};

uint32_t be32(const uint8_t* p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }
uint64_t be64(const uint8_t* p) { return (uint64_t)be32(p) << 32 | be32(p + 4); }

struct mseg {
    std::string name;
    uint64_t vmaddr = 0, vmsize = 0, fileoff = 0, filesize = 0;
    uint32_t initprot = 0, nsects = 0;
};

struct msect {
    std::string seg, name;
    uint64_t addr = 0, size = 0;
    uint32_t offset = 0, flags = 0, reserved1 = 0, reserved2 = 0;
    uint32_t type() const { return flags & 0xff; }
    bool code() const { return (flags & (s_attr_pure_instructions | s_attr_some_instructions)) != 0; }
};

struct nlist {
    std::string name;
    uint8_t type = 0, sect = 0;
    uint16_t desc = 0;
    uint64_t value = 0;
};

struct linkedit {
    uint32_t off = 0, size = 0;
    bool present() const { return size != 0; }
};

struct ctx {
    ctx(binary& b_, span s_) : b(b_), s(s_) {}
    binary& b;
    span s;
    uint64_t slice_off = 0;       // where s starts in b.file
    uint32_t filetype = 0;
    std::vector<mseg> segs;       // every LC_SEGMENT_64, in order (bind opcodes count them)
    std::vector<msect> sects;     // every section, in order (nlist n_sect is 1 + an index here)
    std::vector<std::string> dylibs; // install names by ordinal - 1
    linkedit symtab_syms, symtab_strs;
    uint32_t nsyms = 0;
    uint32_t indirect_off = 0, nindirect = 0;
    linkedit rebase, bind, weak_bind, lazy_bind, export_info, exports_trie, chained, function_starts;
    uint64_t entry_off = 0;
    bool has_main = false;
    uint64_t thread_pc = 0;
    bool has_thread = false;
    uint64_t header_addr = 0;     // where the mach header is loaded: offsets in the dyld info are from here
    std::unordered_map<uint64_t, uint32_t> import_at; // slot -> index in b.imports

    // the unix name of a symbol: without the underscore every c name starts with
    static std::string clean(const std::string& n) { return n.size() > 1 && n[0] == '_' ? n.substr(1) : n; }

    // a dylib's short name for the imports list: libSystem.B.dylib, Foundation
    std::string lib_name(int64_t ordinal) const
    {
        if (ordinal < 1 || (uint64_t)ordinal > dylibs.size())
            return std::string();
        const std::string& p = dylibs[(size_t)ordinal - 1];
        size_t slash = p.find_last_of('/');
        return slash == std::string::npos ? p : p.substr(slash + 1);
    }

    bool read_nlist(uint32_t i, nlist& out) const
    {
        uint64_t off = symtab_syms.off + (uint64_t)i * 16;
        if (i >= nsyms || !s.ok(off, 16))
            return false;
        uint32_t strx = s.u32(off);
        out.type = s.u8(off + 4);
        out.sect = s.u8(off + 5);
        out.desc = s.u16(off + 6);
        out.value = s.u64(off + 8);
        out.name = strx < symtab_strs.size ? s.cstr((uint64_t)symtab_strs.off + strx,
                                                  std::min<uint64_t>(symtab_strs.size - strx, 1024))
                                           : std::string();
        return true;
    }

    // a segment's address from its index in the load commands (the dyld info counts them)
    bool seg_addr(uint64_t segi, uint64_t off, uint64_t& out) const
    {
        if (segi >= segs.size() || off > segs[segi].vmsize)
            return false;
        out = segs[segi].vmaddr + off;
        return true;
    }

    void add_import(uint64_t slot, const std::string& raw_name, int64_t ordinal)
    {
        if (raw_name.empty() || !b.is_mapped(slot))
            return;
        if (import_at.count(slot))
            return;
        import_at.emplace(slot, (uint32_t)b.imports.size());
        b.imports.push_back({lib_name(ordinal), clean(raw_name), slot});
    }
};

uint64_t uleb(const span& s, uint64_t& p, uint64_t end, bool& ok)
{
    uint64_t v = 0;
    for (int shift = 0;; shift += 7) {
        if (p >= end || shift >= 64) {
            ok = false;
            return v;
        }
        uint8_t c = s.u8(p++);
        v |= (uint64_t)(c & 0x7f) << shift;
        if (!(c & 0x80))
            return v;
    }
}

int64_t sleb(const span& s, uint64_t& p, uint64_t end, bool& ok)
{
    int64_t v = 0;
    int shift = 0;
    uint8_t c = 0;
    do {
        if (p >= end || shift >= 64) {
            ok = false;
            return v;
        }
        c = s.u8(p++);
        v |= (int64_t)(c & 0x7f) << shift;
        shift += 7;
    } while (c & 0x80);
    if (shift < 64 && (c & 0x40))
        v |= -((int64_t)1 << shift);
    return v;
}

// ---- load commands ----

bool read_commands(ctx& c, uint32_t ncmds, uint32_t sizeofcmds, std::string& err)
{
    const span& s = c.s;
    uint64_t off = 32, end = 32 + (uint64_t)sizeofcmds;
    if (!s.ok(32, sizeofcmds)) {
        err = "mach-o load commands run past the end of the file";
        return false;
    }
    for (uint32_t i = 0; i < std::min<uint32_t>(ncmds, 65536) && off + 8 <= end; i++) {
        uint32_t cmd = s.u32(off), size = s.u32(off + 4);
        if (size < 8 || off + size > end) {
            c.b.notes.push_back("a mach-o load command is broken, the rest are skipped");
            break;
        }
        auto le = [&](uint64_t o) { return linkedit{s.u32(off + o), s.u32(off + o + 4)}; };
        switch (cmd) {
        case lc_segment_64: {
            if (size < 72)
                break;
            mseg g;
            g.name = s.fixed(off + 8, 16);
            g.vmaddr = s.u64(off + 24);
            g.vmsize = s.u64(off + 32);
            g.fileoff = s.u64(off + 40);
            g.filesize = s.u64(off + 48);
            g.initprot = s.u32(off + 60);
            g.nsects = s.u32(off + 64);
            uint64_t so = off + 72;
            for (uint32_t k = 0; k < g.nsects && so + 80 <= off + size; k++, so += 80) {
                msect x;
                x.name = s.fixed(so, 16);
                x.seg = s.fixed(so + 16, 16);
                x.addr = s.u64(so + 32);
                x.size = s.u64(so + 40);
                x.offset = s.u32(so + 48);
                x.flags = s.u32(so + 64);
                x.reserved1 = s.u32(so + 68);
                x.reserved2 = s.u32(so + 72);
                c.sects.push_back(x);
            }
            c.segs.push_back(g);
            break;
        }
        case lc_symtab:
            if (size >= 24) {
                c.symtab_syms = {s.u32(off + 8), 0};
                c.nsyms = std::min<uint32_t>(s.u32(off + 12), 4u << 20);
                c.symtab_syms.size = c.nsyms * 16;
                c.symtab_strs = le(16);
            }
            break;
        case lc_dysymtab:
            if (size >= 80) {
                c.indirect_off = s.u32(off + 56);
                c.nindirect = std::min<uint32_t>(s.u32(off + 60), 4u << 20);
            }
            break;
        case lc_load_dylib: case lc_load_weak_dylib: case lc_reexport_dylib: case lc_lazy_load_dylib:
        case lc_load_upward_dylib: {
            uint32_t name_off = s.u32(off + 8);
            c.dylibs.push_back(name_off < size ? s.cstr(off + name_off, size - name_off) : std::string("?"));
            break;
        }
        case lc_dyld_info: case lc_dyld_info_only:
            if (size >= 48) {
                c.rebase = le(8);
                c.bind = le(16);
                c.weak_bind = le(24);
                c.lazy_bind = le(32);
                c.export_info = le(40);
            }
            break;
        case lc_dyld_exports_trie: c.exports_trie = le(8); break;
        case lc_dyld_chained_fixups: c.chained = le(8); break;
        case lc_function_starts: c.function_starts = le(8); break;
        case lc_main:
            if (size >= 24) {
                c.entry_off = s.u64(off + 8);
                c.has_main = true;
            }
            break;
        case lc_unixthread: {
            // flavor, count, then the registers: rip is the 17th on x86_64, pc the 33rd on arm64
            uint32_t flavor = s.u32(off + 8);
            if (flavor == 4 && size >= 16 + 17 * 8)
                c.thread_pc = s.u64(off + 16 + 16 * 8), c.has_thread = true;
            else if (flavor == 6 && size >= 16 + 33 * 8)
                c.thread_pc = s.u64(off + 16 + 32 * 8), c.has_thread = true;
            break;
        }
        case lc_encryption_info_64:
            if (size >= 20 && s.u32(off + 16) != 0)
                c.b.notes.push_back(util::fmt("the code is encrypted (an app store app, cryptid %u): what's in "
                                              "0x%x bytes from file offset 0x%x can't be read until it's decrypted",
                    s.u32(off + 16), s.u32(off + 12), s.u32(off + 8)));
            break;
        default:
            break;
        }
        off += size;
    }
    return true;
}

// sections become the segments ceasta shows (__text, __stubs, __cstring, __got, ...)
void map_sections(ctx& c)
{
    binary& b = c.b;
    for (const mseg& g : c.segs) {
        if (g.initprot == 0 || g.vmsize == 0 || g.name == "__LINKEDIT")
            continue; // __PAGEZERO, the linker's tables
        uint32_t perms = ((g.initprot & 1) ? perm_r : 0) | ((g.initprot & 2) ? perm_w : 0) | ((g.initprot & 4) ? perm_x : 0);
        bool any = false;
        for (const msect& x : c.sects) {
            if (x.seg != g.name || x.size == 0 || x.addr < g.vmaddr || x.addr - g.vmaddr >= g.vmsize)
                continue;
            uint32_t t = x.type();
            segment seg;
            seg.name = x.name;
            seg.start = x.addr;
            seg.end = x.addr + x.size;
            if (seg.end < seg.start)
                continue;
            // only sections of instructions are code: __TEXT also holds __cstring, __const, the
            // unwind tables, which are data
            seg.perms = (perms & ~perm_x) | (x.code() ? perm_x : 0);
            bool zero = t == s_zerofill || t == s_gb_zerofill || t == s_thread_local_zerofill;
            seg.file_off = c.slice_off + x.offset;
            seg.file_size = zero || x.offset == 0 ? 0 : x.size;
            b.segments.push_back(seg);
            any = true;
        }
        if (!any && c.filetype != 1) {
            // a segment without sections: map all of it
            segment seg;
            seg.name = g.name;
            seg.start = g.vmaddr;
            seg.end = g.vmaddr + g.vmsize;
            if (seg.end < seg.start)
                continue;
            seg.perms = perms;
            seg.file_off = c.slice_off + g.fileoff;
            seg.file_size = std::min(g.filesize, g.vmsize);
            b.segments.push_back(seg);
        }
    }
    if (c.filetype == 1) {
        // an object file: one unnamed segment, its sections laid out by the assembler
        for (const msect& x : c.sects) {
            if (x.size == 0)
                continue;
            segment seg;
            seg.name = x.name;
            seg.start = x.addr;
            seg.end = x.addr + x.size;
            if (seg.end < seg.start)
                continue;
            seg.perms = perm_r | (x.code() ? perm_x : perm_w);
            uint32_t t = x.type();
            seg.file_off = c.slice_off + x.offset;
            seg.file_size = (t == s_zerofill || t == s_gb_zerofill || t == s_thread_local_zerofill) ? 0 : x.size;
            b.segments.push_back(seg);
        }
    }
}

// ---- symbols ----

void read_symbols(ctx& c)
{
    binary& b = c.b;
    if (!c.nsyms || !c.s.ok(c.symtab_syms.off, (uint64_t)c.nsyms * 16))
        return;
    for (uint32_t i = 0; i < c.nsyms; i++) {
        nlist n;
        if (!c.read_nlist(i, n))
            break;
        if (n.type & 0xe0)
            continue; // debugger (stab) entries
        uint8_t kind = n.type & 0x0e;
        if (kind != 0x0e || n.sect == 0 || n.sect > c.sects.size() || n.name.empty())
            continue; // only ones defined in a section
        if (!b.is_mapped(n.value))
            continue;
        const msect& x = c.sects[n.sect - 1];
        // assembler temporaries (ltmp0, l_.str, Lfunc_end0) aren't names anyone gave
        if (n.name[0] == 'l' || n.name[0] == 'L')
            if (n.name.compare(0, 4, "ltmp") == 0 || n.name.compare(0, 2, "l_") == 0 || n.name.compare(0, 2, "L_") == 0 ||
                n.name.compare(0, 5, "Lfunc") == 0)
                continue;
        bool func = x.code() && x.type() != s_symbol_stubs;
        std::string name = ctx::clean(n.name);
        b.symbols.push_back({name, n.value, 0, func});
        if (func)
            b.func_hints.push_back(n.value);
        bool ext = (n.type & 0x01) && !(n.type & 0x10);
        if (ext && !c.exports_trie.present() && !c.export_info.present())
            b.exports.push_back({name, 0, n.value, std::string()});
    }
}

// ---- dyld info: rebase and bind opcodes ----

void run_rebase(ctx& c, const linkedit& info)
{
    const span& s = c.s;
    binary& b = c.b;
    if (!info.present() || !s.ok(info.off, info.size))
        return;
    uint64_t p = info.off, end = (uint64_t)info.off + info.size;
    uint64_t segi = 0, off = 0;
    bool ok = true;
    auto one = [&]() {
        uint64_t a;
        if (c.seg_addr(segi, off, a) && b.ptr_locs.size() < (4u << 20))
            b.ptr_locs.push_back(a);
        off += 8;
    };
    while (p < end && ok) {
        uint8_t op = s.u8(p++), imm = op & 0x0f;
        switch (op & 0xf0) {
        case 0x00: return; // done
        case 0x10: break;   // type
        case 0x20: segi = imm; off = uleb(s, p, end, ok); break;
        case 0x30: off += uleb(s, p, end, ok); break;
        case 0x40: off += (uint64_t)imm * 8; break;
        case 0x50: for (uint32_t i = 0; i < imm; i++) one(); break;
        case 0x60: {
            uint64_t n = uleb(s, p, end, ok);
            for (uint64_t i = 0; i < n && i < (1u << 24); i++)
                one();
            break;
        }
        case 0x70: one(); off += uleb(s, p, end, ok); break;
        case 0x80: {
            uint64_t n = uleb(s, p, end, ok), skip = uleb(s, p, end, ok);
            for (uint64_t i = 0; i < n && i < (1u << 24); i++) {
                one();
                off += skip;
            }
            break;
        }
        default: return;
        }
    }
}

// bind, weak bind and lazy bind share the opcodes. a lazy stream is many small ones, each
// ending with done, so it keeps going after one
void run_bind(ctx& c, const linkedit& info, bool lazy)
{
    const span& s = c.s;
    if (!info.present() || !s.ok(info.off, info.size))
        return;
    uint64_t p = info.off, end = (uint64_t)info.off + info.size;
    uint64_t segi = 0, off = 0;
    int64_t ordinal = 0;
    std::string sym;
    bool ok = true;
    auto one = [&]() {
        uint64_t a;
        if (c.seg_addr(segi, off, a))
            c.add_import(a, sym, ordinal);
        off += 8;
    };
    while (p < end && ok) {
        uint8_t op = s.u8(p++), imm = op & 0x0f;
        switch (op & 0xf0) {
        case 0x00:
            if (!lazy)
                return;
            break;
        case 0x10: ordinal = imm; break;
        case 0x20: ordinal = (int64_t)uleb(s, p, end, ok); break;
        case 0x30: ordinal = imm ? (int64_t)(int8_t)(0xf0 | imm) : 0; break;
        case 0x40: {
            sym = s.cstr(p, std::min<uint64_t>(end - p, 4096));
            p += sym.size() + 1;
            break;
        }
        case 0x50: break;                           // type
        case 0x60: sleb(s, p, end, ok); break;      // addend
        case 0x70: segi = imm; off = uleb(s, p, end, ok); break;
        case 0x80: off += uleb(s, p, end, ok); break;
        case 0x90: one(); break;
        case 0xa0: one(); off += uleb(s, p, end, ok); break;
        case 0xb0: one(); off += (uint64_t)imm * 8; break;
        case 0xc0: {
            uint64_t n = uleb(s, p, end, ok), skip = uleb(s, p, end, ok);
            for (uint64_t i = 0; i < n && i < (1u << 24); i++) {
                one();
                off += skip;
            }
            break;
        }
        case 0xd0: // threaded binds (early arm64e): the chains aren't followed
            c.b.notes.push_back("threaded binds (early arm64e) aren't read: some imports have no names");
            return;
        default: return;
        }
    }
}

// ---- chained fixups (macos 12 and later, every arm64e file) ----

void run_chained(ctx& c)
{
    const span& s = c.s;
    binary& b = c.b;
    const linkedit& info = c.chained;
    if (!info.present() || !s.ok(info.off, info.size) || info.size < 28)
        return;
    uint64_t h = info.off, hend = (uint64_t)info.off + info.size;
    uint32_t starts_off = s.u32(h + 4), imports_off = s.u32(h + 8), symbols_off = s.u32(h + 12);
    uint32_t imports_count = std::min<uint32_t>(s.u32(h + 16), 1u << 20);
    uint32_t imports_format = s.u32(h + 20), symbols_format = s.u32(h + 24);
    if (symbols_format != 0) {
        b.notes.push_back("chained fixups with compressed names aren't read: imports have no names");
        imports_count = 0;
    }

    struct cimport {
        std::string name;
        int64_t ordinal = 0;
    };
    std::vector<cimport> imports;
    imports.reserve(imports_count);
    uint32_t isize = imports_format == 1 ? 4 : imports_format == 2 ? 8 : imports_format == 3 ? 16 : 0;
    for (uint32_t i = 0; i < imports_count && isize; i++) {
        uint64_t e = h + imports_off + (uint64_t)i * isize;
        if (e + isize > hend)
            break;
        cimport im;
        uint64_t name_off;
        if (imports_format == 3) {
            uint64_t v = s.u64(e);
            uint16_t ord = (uint16_t)(v & 0xffff);
            im.ordinal = ord >= 0xfff0 ? (int64_t)(int16_t)ord : ord;
            name_off = v >> 32;
        } else {
            uint32_t v = s.u32(e);
            uint8_t ord = (uint8_t)(v & 0xff);
            im.ordinal = ord >= 0xf0 ? (int64_t)(int8_t)ord : ord;
            name_off = v >> 9;
        }
        uint64_t np = h + symbols_off + name_off;
        if (np < hend)
            im.name = s.cstr(np, std::min<uint64_t>(hend - np, 4096));
        imports.push_back(im);
    }

    uint64_t si = h + starts_off;
    uint32_t seg_count = s.u32(si);
    size_t fixups = 0, unknown = 0;
    for (uint32_t g = 0; g < seg_count && g < c.segs.size() && si + 4 + (g + 1) * 4ull <= hend; g++) {
        uint32_t so = s.u32(si + 4 + g * 4ull);
        if (!so)
            continue;
        uint64_t ss = si + so;
        if (ss + 22 > hend)
            continue;
        uint16_t page_size = s.u16(ss + 4), format = s.u16(ss + 6);
        uint64_t seg_offset = s.u64(ss + 8);
        uint16_t page_count = s.u16(ss + 20);
        uint64_t stride = format == 2 || format == 6 ? 4 : 8;
        bool arm64e = format == 1 || format == 9 || format == 12;
        if (!(format == 2 || format == 6 || arm64e)) {
            unknown++;
            continue;
        }
        // segment_offset is from the start of the image (the mach header), not the segment
        for (uint32_t pg = 0; pg < page_count && ss + 22 + (pg + 1) * 2ull <= hend; pg++) {
            uint16_t start = s.u16(ss + 22 + pg * 2ull);
            if (start == 0xffff)
                continue;
            uint64_t a = c.header_addr + seg_offset + (uint64_t)pg * page_size + (start & 0x7fff);
            for (int guard = 0; guard < 65536; guard++) {
                uint64_t v;
                if (!b.read_u64(a, v))
                    break;
                uint64_t next;
                bool bind;
                uint64_t target = 0;
                int64_t addend = 0;
                uint32_t ordinal = 0;
                if (arm64e) {
                    bool auth = (v >> 63) & 1;
                    bind = (v >> 62) & 1;
                    next = (v >> 51) & 0x7ff;
                    if (bind) {
                        ordinal = format == 12 ? (uint32_t)(v & 0xffffff) : (uint32_t)(v & 0xffff);
                        if (!auth) {
                            addend = (int64_t)((v >> 32) & 0x7ffff);
                            if (addend & 0x40000)
                                addend |= ~(int64_t)0x7ffff;
                        }
                    } else if (auth) {
                        target = c.header_addr + (v & 0xffffffff); // offset from the mach header
                    } else {
                        uint64_t t = v & 0x7ffffffffffull, high8 = (v >> 43) & 0xff;
                        target = (format == 1 ? t : c.header_addr + t) | high8 << 56;
                    }
                } else {
                    bind = (v >> 63) & 1;
                    next = (v >> 51) & 0xfff;
                    if (bind) {
                        ordinal = (uint32_t)(v & 0xffffff);
                        addend = (int64_t)((v >> 24) & 0xff);
                    } else {
                        uint64_t t = v & 0xfffffffffull, high8 = (v >> 36) & 0xff;
                        target = (format == 2 ? t : c.header_addr + t) | high8 << 56;
                    }
                }
                (void)addend;
                uint64_t w = 0;
                if (bind) {
                    if (ordinal < imports.size())
                        c.add_import(a, imports[ordinal].name, imports[ordinal].ordinal);
                } else {
                    w = target;
                    if (b.ptr_locs.size() < (4u << 20))
                        b.ptr_locs.push_back(a);
                }
                // the pointer as it is once loaded (an import's slot reads as 0)
                b.patch(a, &w, 8);
                fixups++;
                if (!next)
                    break;
                a += next * stride;
            }
        }
    }
    if (unknown)
        b.notes.push_back("some chained fixups use a pointer format that isn't read (kernel or firmware)");
    (void)fixups;
}

// ---- the indirect symbol table: stubs and pointer sections by symbol ----

void read_indirect(ctx& c)
{
    binary& b = c.b;
    const span& s = c.s;
    if (!c.nindirect || !s.ok(c.indirect_off, (uint64_t)c.nindirect * 4))
        return;
    auto sym_of = [&](uint32_t idx, nlist& n) {
        if (idx >= c.nindirect)
            return false;
        uint32_t si = s.u32(c.indirect_off + (uint64_t)idx * 4);
        if (si & (indirect_symbol_local | indirect_symbol_abs))
            return false;
        return c.read_nlist(si, n) && !n.name.empty();
    };
    for (const msect& x : c.sects) {
        uint32_t t = x.type();
        if (t == s_non_lazy_symbol_pointers || t == s_lazy_symbol_pointers) {
            uint64_t n = std::min<uint64_t>(x.size / 8, 1u << 20);
            for (uint64_t i = 0; i < n; i++) {
                nlist sym;
                // undefined ones are imports; a pointer to something defined here isn't
                if (sym_of(x.reserved1 + (uint32_t)i, sym) && (sym.type & 0x0e) == 0)
                    c.add_import(x.addr + i * 8, sym.name, (sym.desc >> 8) & 0xff);
            }
        } else if (t == s_symbol_stubs && x.reserved2) {
            // every stub starts a tiny function (a jump through its slot): the analysis names it
            uint64_t n = std::min<uint64_t>(x.size / x.reserved2, 1u << 20);
            for (uint64_t i = 0; i < n; i++)
                b.func_hints.push_back(x.addr + i * x.reserved2);
        }
    }
}

// ---- exports ----

void read_export_trie(ctx& c, const linkedit& info)
{
    const span& s = c.s;
    binary& b = c.b;
    if (!info.present() || !s.ok(info.off, info.size))
        return;
    uint64_t start = info.off, end = (uint64_t)info.off + info.size;
    struct item {
        uint64_t node;
        std::string prefix;
    };
    std::vector<item> stack{{start, std::string()}};
    std::unordered_set<uint64_t> seen;
    while (!stack.empty() && b.exports.size() < (1u << 20)) {
        item it = std::move(stack.back());
        stack.pop_back();
        if (it.node >= end || !seen.insert(it.node).second)
            continue;
        uint64_t p = it.node;
        bool ok = true;
        uint64_t term = uleb(s, p, end, ok);
        if (!ok)
            continue;
        uint64_t children = p + term;
        if (term) {
            uint64_t flags = uleb(s, p, end, ok);
            export_entry e;
            e.name = ctx::clean(it.prefix);
            if (flags & 0x08) {
                // a re-export: another library's symbol under this name
                uint64_t ord = uleb(s, p, end, ok);
                std::string other = s.cstr(p, std::min<uint64_t>(end - p, 1024));
                e.forward = c.lib_name((int64_t)ord) + "." + ctx::clean(other.empty() ? it.prefix : other);
            } else {
                uint64_t v = uleb(s, p, end, ok);
                e.addr = (flags & 3) == 2 ? v : c.header_addr + v; // absolute, or from the header
                if (flags & 0x10) {
                    // stub and resolver: the address is a stub, the resolver picks the function
                    uint64_t resolver = c.header_addr + uleb(s, p, end, ok);
                    if (ok && b.is_code(resolver))
                        b.func_hints.push_back(resolver);
                }
            }
            if (ok) {
                if (e.addr && b.is_code(e.addr))
                    b.func_hints.push_back(e.addr);
                b.exports.push_back(e);
            }
        }
        if (children >= end)
            continue;
        p = children;
        uint8_t n = s.u8(p++);
        for (uint8_t i = 0; i < n && p < end; i++) {
            std::string edge = s.cstr(p, std::min<uint64_t>(end - p, 4096));
            p += edge.size() + 1;
            bool ok2 = true;
            uint64_t child = uleb(s, p, end, ok2);
            if (!ok2 || it.prefix.size() + edge.size() > 4096)
                break;
            stack.push_back({start + child, it.prefix + edge});
        }
    }
}

// ---- function starts, initializers ----

void read_function_starts(ctx& c)
{
    const span& s = c.s;
    binary& b = c.b;
    const linkedit& info = c.function_starts;
    if (!info.present() || !s.ok(info.off, info.size))
        return;
    // uleb deltas, the first from the start of __TEXT
    uint64_t p = info.off, end = (uint64_t)info.off + info.size, a = c.header_addr;
    for (const mseg& g : c.segs)
        if (g.name == "__TEXT") {
            a = g.vmaddr;
            break;
        }
    bool ok = true;
    size_t n = 0;
    while (p < end && ok && n < (4u << 20)) {
        uint64_t d = uleb(s, p, end, ok);
        if (!ok || d == 0)
            break;
        a += d;
        if (b.is_code(a)) {
            b.func_hints.push_back(a);
            n++;
        }
    }
    b.starts_complete = n > 0;
}

void read_initializers(ctx& c)
{
    binary& b = c.b;
    for (const msect& x : c.sects) {
        uint32_t t = x.type();
        if (t == s_mod_init_func_pointers) {
            for (uint64_t i = 0; i < std::min<uint64_t>(x.size / 8, 4096); i++) {
                uint64_t v;
                if (b.read_u64(x.addr + i * 8, v) && b.is_code(v))
                    b.func_hints.push_back(v);
            }
        } else if (t == s_init_func_offsets) {
            for (uint64_t i = 0; i < std::min<uint64_t>(x.size / 4, 4096); i++) {
                uint32_t v;
                if (b.read_u32(x.addr + i * 4, v) && b.is_code(c.header_addr + v))
                    b.func_hints.push_back(c.header_addr + v);
            }
        }
    }
}

// ---- exception landing pads: __unwind_info's lsda index, then each lsda's call sites ----

void read_landing_pads(ctx& c)
{
    binary& b = c.b;
    const msect* ui = nullptr;
    for (const msect& x : c.sects)
        if (x.name == "__unwind_info" && x.seg == "__TEXT")
            ui = &x;
    uint32_t version, index_off, index_count;
    if (!ui || !b.read_u32(ui->addr, version) || version != 1 || !b.read_u32(ui->addr + 20, index_off) ||
        !b.read_u32(ui->addr + 24, index_count) || index_count < 2)
        return;
    // the lsda index is one array, from the first index entry's start to the last (a sentinel)'s
    uint32_t lsda_first, lsda_end;
    if (!b.read_u32(ui->addr + index_off + 8, lsda_first) ||
        !b.read_u32(ui->addr + index_off + (uint64_t)(index_count - 1) * 12 + 8, lsda_end) || lsda_end < lsda_first)
        return;
    uint64_t n = std::min<uint64_t>((lsda_end - lsda_first) / 8, 1u << 20);
    for (uint64_t i = 0; i < n; i++) {
        uint32_t func_off, lsda_off;
        uint64_t e = ui->addr + lsda_first + i * 8;
        if (!b.read_u32(e, func_off) || !b.read_u32(e + 4, lsda_off))
            break;
        uint64_t func = c.header_addr + func_off;
        if (b.is_code(func))
            loader::read_lsda(b, func, c.header_addr + lsda_off);
    }
    std::sort(b.landing_pads.begin(), b.landing_pads.end());
    b.landing_pads.erase(std::unique(b.landing_pads.begin(), b.landing_pads.end()), b.landing_pads.end());
}

// a file offset in the slice as an address (LC_MAIN gives the entry point as one)
bool file_to_addr(const ctx& c, uint64_t off, uint64_t& out)
{
    for (const mseg& g : c.segs)
        if (g.filesize && off >= g.fileoff && off - g.fileoff < g.filesize) {
            out = g.vmaddr + (off - g.fileoff);
            return true;
        }
    return false;
}

const char* cpu_name(uint32_t cpu, uint32_t sub)
{
    switch (cpu) {
    case cpu_x86_64: return "x86_64";
    case cpu_arm64: return (sub & 0xffffff) == cpu_sub_arm64e ? "arm64e" : "arm64";
    case cpu_x86: return "i386";
    case cpu_arm: return "arm";
    case cpu_arm64_32: return "arm64_32";
    case cpu_ppc: return "ppc";
    case cpu_ppc64: return "ppc64";
    default: return "unknown";
    }
}

bool cpu_arch(uint32_t cpu, bin_arch& out)
{
    if (cpu == cpu_x86_64)
        out = bin_arch::x64;
    else if (cpu == cpu_arm64)
        out = bin_arch::arm64;
    else
        return false;
    return true;
}

struct fat_slice {
    uint32_t cpu = 0, sub = 0;
    uint64_t off = 0, size = 0;
};

// the slices of a universal file, or none when it isn't one (0xcafebabe is also a java class)
std::vector<fat_slice> fat_slices(const std::vector<uint8_t>& f)
{
    std::vector<fat_slice> out;
    if (f.size() < 8)
        return out;
    uint32_t magic = be32(f.data()), n = be32(f.data() + 4);
    if ((magic != fat_magic && magic != fat_magic_64) || n == 0 || n > 30)
        return out;
    bool w = magic == fat_magic_64;
    uint64_t es = w ? 32 : 20;
    for (uint32_t i = 0; i < n; i++) {
        uint64_t e = 8 + i * es;
        if (e + es > f.size())
            return {};
        const uint8_t* p = f.data() + e;
        fat_slice sl;
        sl.cpu = be32(p);
        sl.sub = be32(p + 4);
        sl.off = w ? be64(p + 8) : be32(p + 8);
        sl.size = w ? be64(p + 16) : be32(p + 12);
        if (sl.off >= f.size() || sl.size > f.size() - sl.off)
            return {};
        out.push_back(sl);
    }
    return out;
}

}

namespace loader {

bool is_macho(const std::vector<uint8_t>& f)
{
    if (f.size() < 32)
        return false;
    uint32_t m = util::rd32(f.data());
    return m == mh_magic_64 || m == mh_magic || m == mh_cigam || m == mh_cigam_64 || !fat_slices(f).empty();
}

bool macho_arch(const std::vector<uint8_t>& head, bin_arch& out)
{
    if (head.size() >= 8 && util::rd32(head.data()) == mh_magic_64)
        return cpu_arch(util::rd32(head.data() + 4), out);
    if (head.size() >= 8 && (be32(head.data()) == fat_magic || be32(head.data()) == fat_magic_64)) {
        // the slice ceasta opens by default: x86_64 when there is one
        uint32_t n = be32(head.data() + 4);
        bool w = be32(head.data()) == fat_magic_64;
        bool any = false;
        for (uint32_t i = 0; i < n && i < 30 && 8 + (i + 1) * (w ? 32u : 20u) <= head.size(); i++) {
            bin_arch a;
            if (cpu_arch(be32(head.data() + 8 + i * (w ? 32 : 20)), a)) {
                if (!any || a == bin_arch::x64)
                    out = a;
                any = true;
            }
        }
        return any;
    }
    return false;
}

bool macho(binary& b, std::string& err, const options& o)
{
    // a universal file: pick the slice
    uint64_t slice_off = 0, slice_size = b.file.size();
    std::vector<fat_slice> fat = fat_slices(b.file);
    if (!fat.empty()) {
        std::string all;
        int pick = -1;
        for (size_t i = 0; i < fat.size(); i++) {
            all += std::string(all.empty() ? "" : ", ") + cpu_name(fat[i].cpu, fat[i].sub);
            bin_arch a;
            if (!cpu_arch(fat[i].cpu, a))
                continue;
            b.slices.push_back(a);
            if (o.has_slice ? a == o.slice && pick < 0 : (pick < 0 || (a == bin_arch::x64 && b.slices[0] != bin_arch::x64)))
                pick = (int)i;
        }
        if (pick < 0) {
            err = o.has_slice ? util::fmt("this universal file has no %s part (it has %s)", arch_name(o.slice), all.c_str())
                              : "this universal file has no x86_64 or arm64 part (it has " + all + ")";
            return false;
        }
        slice_off = fat[(size_t)pick].off;
        slice_size = fat[(size_t)pick].size;
        b.notes.push_back(util::fmt("universal file (%s): showing %s", all.c_str(), cpu_name(fat[(size_t)pick].cpu, fat[(size_t)pick].sub)));
    }
    b.slice_off = slice_off;
    b.slice_size = fat.empty() ? 0 : slice_size;

    ctx c(b, span{b.file.data() + slice_off, slice_size});
    c.slice_off = slice_off;
    const span& s = c.s;
    uint32_t magic = s.u32(0);
    if (magic == mh_magic || magic == mh_cigam) {
        err = "32-bit mach-o files aren't supported (x86_64 and arm64 ones are)";
        return false;
    }
    if (magic == mh_cigam_64) {
        err = "big endian (powerpc) mach-o files aren't supported";
        return false;
    }
    if (magic != mh_magic_64 || !s.ok(0, 32)) {
        err = "not a mach-o file";
        return false;
    }
    uint32_t cpu = s.u32(4), sub = s.u32(8);
    c.filetype = s.u32(12);
    uint32_t ncmds = s.u32(16), sizeofcmds = s.u32(20), flags = s.u32(24);
    if (!cpu_arch(cpu, b.arch)) {
        err = util::fmt("unsupported mach-o cpu %s (x86_64 and arm64 are supported)", cpu_name(cpu, sub));
        return false;
    }
    if (!read_commands(c, ncmds, sizeofcmds, err))
        return false;
    if (cpu == cpu_arm64 && (sub & 0xffffff) == cpu_sub_arm64e)
        b.notes.push_back("arm64e: pointers carry authentication codes (pac), ceasta shows them without");

    map_sections(c);
    if (b.segments.empty()) {
        err = "mach-o file has no sections to load";
        return false;
    }
    b.finish_segments();
    if (b.segments.empty()) {
        err = "mach-o file has no sections to load";
        return false;
    }

    // the image base: where the mach header is (the __TEXT segment, file offset 0)
    c.header_addr = b.segments.front().start;
    for (const mseg& g : c.segs)
        if (g.fileoff == 0 && g.filesize && g.initprot) {
            c.header_addr = g.vmaddr;
            break;
        }
    b.base = c.header_addr;
    b.libs = c.dylibs;

    read_symbols(c);
    run_chained(c);
    run_rebase(c, c.rebase);
    run_bind(c, c.bind, false);
    run_bind(c, c.weak_bind, false);
    run_bind(c, c.lazy_bind, true);
    read_indirect(c);
    read_export_trie(c, c.exports_trie.present() ? c.exports_trie : c.export_info);
    read_function_starts(c);
    read_initializers(c);
    read_landing_pads(c);

    std::sort(b.imports.begin(), b.imports.end(), [](const import_entry& x, const import_entry& y) { return x.slot < y.slot; });
    auto by_addr_name = [](const auto& x, const auto& y) { return x.addr != y.addr ? x.addr < y.addr : x.name < y.name; };
    auto same = [](const auto& x, const auto& y) { return x.addr == y.addr && x.name == y.name; };
    std::sort(b.symbols.begin(), b.symbols.end(), by_addr_name);
    b.symbols.erase(std::unique(b.symbols.begin(), b.symbols.end(), same), b.symbols.end());
    std::sort(b.exports.begin(), b.exports.end(), by_addr_name);
    b.exports.erase(std::unique(b.exports.begin(), b.exports.end(), same), b.exports.end());

    uint64_t entry = 0;
    if (c.has_main && file_to_addr(c, c.entry_off, entry)) {
    } else if (c.has_thread) {
        entry = c.thread_pc;
    }
    if (entry && b.is_mapped(entry)) {
        b.entry = entry;
        b.has_entry = true;
        b.func_hints.push_back(entry);
    }

    b.format = bin_format::macho;
    switch (c.filetype) {
    case 1: b.kind = "mach-o object"; break;
    case 2: b.kind = "mach-o exec"; break;
    case 6: b.kind = "mach-o dylib"; break;
    case 7: b.kind = "mach-o dyld"; break;
    case 8: b.kind = "mach-o bundle"; break;
    case 0xb: b.kind = "mach-o kext"; break;
    default: b.kind = util::fmt("mach-o (type %u)", c.filetype); break;
    }
    if (c.filetype == 2 && !(flags & 0x200000))
        b.kind += " (not pie)";
    if (c.filetype == 1)
        b.notes.push_back("an object file: its relocations aren't applied, calls to other files show as 0");
    return true;
}

}
