#include "core/binary.h"
#include "core/util.h"
#include <algorithm>
#include <cstring>
#include <unordered_map>

// elf32 / elf64 little endian loader (x86, x64, arm64). bounds checked, the file is untrusted.

namespace {

enum : uint32_t {
    sht_symtab = 2,
    sht_rela = 4,
    sht_dynamic = 6,
    sht_nobits = 8,
    sht_rel = 9,
    sht_dynsym = 11,
    sht_init_array = 14,
    sht_fini_array = 15,
    sht_preinit_array = 16,
};

enum : uint64_t {
    shf_write = 1,
    shf_alloc = 2,
    shf_exec = 4,
    shf_tls = 0x400,
};

struct shdr {
    std::string name;
    uint32_t name_off = 0, type = 0, link = 0, info = 0;
    uint64_t flags = 0, addr = 0, offset = 0, size = 0, entsize = 0, align = 0;
};

struct phdr {
    uint32_t type = 0, flags = 0;
    uint64_t offset = 0, vaddr = 0, filesz = 0, memsz = 0;
};

struct elf_sym {
    std::string name;
    uint64_t value = 0, size = 0;
    uint16_t shndx = 0;
    uint8_t type = 0, bind = 0;
};

struct ctx {
    binary& b;
    util::byte_reader r;
    bool is64;
    std::vector<shdr> secs;
    std::vector<uint64_t> sec_addr; // load address per section (differs for .o files)

    bool sec_ok(uint32_t i) const { return i < secs.size(); }

    // reads symbol i of a symbol table section
    bool sym(const shdr& tab, uint64_t i, elf_sym& out) const
    {
        uint64_t es = is64 ? 24 : 16;
        uint64_t off = tab.offset + i * es;
        if (!r.ok(off, es) || !sec_ok(tab.link))
            return false;
        uint32_t name;
        if (is64) {
            name = r.u32(off);
            uint8_t info = r.u8(off + 4);
            out.type = info & 0xf;
            out.bind = info >> 4;
            out.shndx = r.u16(off + 6);
            out.value = r.u64(off + 8);
            out.size = r.u64(off + 16);
        } else {
            name = r.u32(off);
            out.value = r.u32(off + 4);
            out.size = r.u32(off + 8);
            uint8_t info = r.u8(off + 12);
            out.type = info & 0xf;
            out.bind = info >> 4;
            out.shndx = r.u16(off + 14);
        }
        const shdr& strtab = secs[tab.link];
        out.name = name < strtab.size ? r.cstr(strtab.offset + name, std::min<uint64_t>(strtab.size - name, 512)) : std::string();
        return true;
    }
};

void read_symbols(ctx& c, bool et_rel)
{
    binary& b = c.b;
    for (const shdr& tab : c.secs) {
        if (tab.type != sht_symtab && tab.type != sht_dynsym)
            continue;
        uint64_t es = c.is64 ? 24 : 16;
        uint64_t count = std::min<uint64_t>(tab.size / es, 1u << 20);
        for (uint64_t i = 1; i < count; i++) {
            elf_sym s;
            if (!c.sym(tab, i, s))
                break;
            // skip undefined (imports), section and file symbols, special indexes
            if (s.shndx == 0 || s.shndx >= 0xff00 || s.type == 3 || s.type == 4 || s.name.empty())
                continue;
            // arm mapping symbols ($x code starts here, $d data, $x.12, ...) aren't names
            if (s.name[0] == '$' && s.name.size() >= 2 && strchr("xdat", s.name[1]) &&
                (s.name.size() == 2 || s.name[2] == '.' || s.name[2] == '_'))
                continue;
            uint64_t addr = s.value;
            if (et_rel) {
                if (!c.sec_ok(s.shndx))
                    continue;
                addr += c.sec_addr[s.shndx];
            }
            if (!b.is_mapped(addr))
                continue;
            bool func = s.type == 2 || s.type == 10;
            b.symbols.push_back({s.name, addr, s.size, func});
            if (func && b.is_code(addr))
                b.func_hints.push_back(addr);
            if (tab.type == sht_dynsym && (s.bind == 1 || s.bind == 2))
                b.exports.push_back({s.name, 0, addr, std::string()});
        }
    }
    auto by_addr_name = [](const auto& x, const auto& y) { return x.addr != y.addr ? x.addr < y.addr : x.name < y.name; };
    auto same = [](const auto& x, const auto& y) { return x.addr == y.addr && x.name == y.name; };
    std::sort(b.symbols.begin(), b.symbols.end(), by_addr_name);
    b.symbols.erase(std::unique(b.symbols.begin(), b.symbols.end(), same), b.symbols.end());
    std::sort(b.exports.begin(), b.exports.end(), by_addr_name);
    b.exports.erase(std::unique(b.exports.begin(), b.exports.end(), same), b.exports.end());
}

// jump_slot / glob_dat relocs against undefined symbols are the imports.
// relative relocs into init/fini arrays point at constructors.
void read_relocs(ctx& c)
{
    binary& b = c.b;
    for (const shdr& rs : c.secs) {
        if ((rs.type != sht_rela && rs.type != sht_rel) || !c.sec_ok(rs.link))
            continue;
        const shdr& symtab = c.secs[rs.link];
        if (symtab.type != sht_dynsym && symtab.type != sht_symtab)
            continue;
        bool rela = rs.type == sht_rela;
        uint64_t es = c.is64 ? (rela ? 24 : 16) : (rela ? 12 : 8);
        // glob_dat, jump_slot and relative: 6, 7, 8 on x86 and x64, 1025, 1026, 1027 on arm64
        uint32_t t0 = b.arch == bin_arch::arm64 ? 1025 : 6;
        uint64_t count = std::min<uint64_t>(rs.size / es, 1u << 20);
        for (uint64_t i = 0; i < count; i++) {
            uint64_t off = rs.offset + i * es;
            if (!c.r.ok(off, es))
                break;
            uint64_t where, info;
            int64_t addend = 0;
            uint32_t type;
            uint64_t symi;
            if (c.is64) {
                where = c.r.u64(off);
                info = c.r.u64(off + 8);
                if (rela)
                    addend = (int64_t)c.r.u64(off + 16);
                type = (uint32_t)(info & 0xffffffff);
                symi = info >> 32;
            } else {
                where = c.r.u32(off);
                info = c.r.u32(off + 4);
                if (rela)
                    addend = (int32_t)c.r.u32(off + 8);
                type = (uint32_t)(info & 0xff);
                symi = info >> 8;
            }
            if ((type == t0 || type == t0 + 1) && symi != 0) {
                elf_sym s;
                if (c.sym(symtab, symi, s) && s.shndx == 0 && !s.name.empty())
                    b.imports.push_back({std::string(), s.name, where});
            } else if (type == t0 + 2) {
                // R_*_RELATIVE: we load at the link address, so the pointer is just the addend.
                // lld leaves zeros in rela targets, write the value so data reads right
                uint64_t target = (uint64_t)addend;
                if (!rela) {
                    b.read_ptr(where, target);
                } else if (c.is64) {
                    b.patch(where, &target, 8);
                } else {
                    uint32_t t32 = (uint32_t)target;
                    b.patch(where, &t32, 4);
                }
                if (b.ptr_locs.size() < (4u << 20))
                    b.ptr_locs.push_back(where);
                for (const shdr& a : c.secs)
                    if ((a.type == sht_init_array || a.type == sht_fini_array || a.type == sht_preinit_array) &&
                        where >= a.addr && where < a.addr + a.size && b.is_code(target))
                        b.func_hints.push_back(target);
            }
        }
    }
    std::sort(b.imports.begin(), b.imports.end(), [](const import_entry& x, const import_entry& y) { return x.slot < y.slot; });
    b.imports.erase(std::unique(b.imports.begin(), b.imports.end(),
        [](const import_entry& x, const import_entry& y) { return x.slot == y.slot; }), b.imports.end());
}

void read_needed(ctx& c)
{
    for (const shdr& d : c.secs) {
        if (d.type != sht_dynamic || !c.sec_ok(d.link))
            continue;
        const shdr& strtab = c.secs[d.link];
        uint64_t es = c.is64 ? 16 : 8;
        uint64_t count = std::min<uint64_t>(d.size / es, 4096);
        for (uint64_t i = 0; i < count; i++) {
            uint64_t off = d.offset + i * es;
            uint64_t tag = c.is64 ? c.r.u64(off) : c.r.u32(off);
            uint64_t val = c.is64 ? c.r.u64(off + 8) : c.r.u32(off + 4);
            if (tag == 0)
                break;
            if (tag == 1 && val < strtab.size)
                c.b.libs.push_back(c.r.cstr(strtab.offset + val, 256));
        }
    }
}

bool uleb(const binary& b, uint64_t& p, uint64_t end, uint64_t& out)
{
    out = 0;
    for (int shift = 0; p < end && shift < 64; shift += 7) {
        uint8_t v;
        if (!b.read_u8(p++, v))
            return false;
        out |= (uint64_t)(v & 0x7f) << shift;
        if (!(v & 0x80))
            return true;
    }
    return false;
}

// bytes a value in dwarf pointer encoding enc takes (0 when unknown / variable)
unsigned enc_size(uint8_t enc, int ptr)
{
    switch (enc & 0x0f) {
    case 0x00: return (unsigned)ptr;
    case 0x02: case 0x0a: return 2;
    case 0x03: case 0x0b: return 4;
    case 0x04: case 0x0c: return 8;
    default: return 0;
    }
}

// what an fde's cie says about it
struct cie_info {
    uint8_t fde_enc = 0xff;  // how its pc range is written, 0xff: unknown
    uint8_t lsda_enc = 0xff; // how its lsda pointer is written, 0xff: it has none
    bool z = false;          // it has augmentation data
};

// a function's unwind info starts from the state right after a call. gcc's split off cold
// parts (foo.cold) are entered with the caller's frame already set up, so their first rules
// (before the first advance) move the cfa or save registers: those aren't function starts.
// lsda is set to the fde's exception table, 0 when it has none
bool fde_is_fragment(const binary& b, uint64_t fde, std::unordered_map<uint64_t, cie_info>& cies, uint64_t& lsda)
{
    lsda = 0;
    uint32_t len, cie_ptr;
    if (!b.read_u32(fde, len) || len == 0 || len == 0xffffffff || !b.read_u32(fde + 4, cie_ptr) || !cie_ptr)
        return false;
    uint64_t end = fde + 4 + len, cie = fde + 4 - cie_ptr;
    auto it = cies.find(cie);
    if (it == cies.end()) {
        // the cie: version, augmentation, alignments, return register, then augmentation data
        cie_info info;
        uint32_t clen, id;
        uint8_t ver;
        if (b.read_u32(cie, clen) && clen && clen != 0xffffffff && b.read_u32(cie + 4, id) && id == 0 &&
            b.read_u8(cie + 8, ver)) {
            uint64_t cend = cie + 4 + clen, p = cie + 9, v;
            std::string aug = b.read_cstr(p, 16);
            p += aug.size() + 1;
            bool ok = aug.find("eh") == std::string::npos && uleb(b, p, cend, v) && uleb(b, p, cend, v);
            if (ok && ver == 1)
                p++;
            else if (ok)
                ok = uleb(b, p, cend, v);
            if (ok && !aug.empty() && aug[0] == 'z' && uleb(b, p, cend, v)) {
                info.z = true;
                for (size_t i = 1; i < aug.size() && p < cend; i++) {
                    uint8_t e = 0;
                    if (aug[i] == 'R') {
                        b.read_u8(p++, e);
                        info.fde_enc = e;
                    } else if (aug[i] == 'P') {
                        b.read_u8(p++, e);
                        p += enc_size(e, b.ptr_size());
                    } else if (aug[i] == 'L') {
                        b.read_u8(p++, e);
                        info.lsda_enc = e;
                    } else if (aug[i] != 'S' && aug[i] != 'B' && aug[i] != 'G') {
                        break;
                    }
                }
            }
            if (!ok)
                info.fde_enc = 0xff;
        }
        it = cies.emplace(cie, info).first;
    }
    const cie_info& ci = it->second;
    unsigned sz = ci.fde_enc == 0xff ? 0 : enc_size(ci.fde_enc, b.ptr_size());
    if (!sz)
        return false;
    uint64_t p = fde + 8 + 2 * (uint64_t)sz, v;
    if (ci.z) {
        if (!uleb(b, p, end, v))
            return false;
        // the augmentation data is the lsda pointer, when the cie says there is one
        uint64_t q = p;
        if (ci.lsda_enc != 0xff && v && !loader::read_dwarf_ptr(b, q, ci.lsda_enc, lsda))
            lsda = 0;
        p += v;
    }
    for (int n = 0; p < end && n < 64; n++) {
        uint8_t op;
        if (!b.read_u8(p++, op))
            return false;
        uint8_t hi = op & 0xc0;
        if (hi == 0x40)
            return false; // advance_loc: the rules that follow are for later instructions
        if (hi == 0x80)
            return true;  // offset: a register is already saved
        if (hi == 0xc0)
            continue;     // restore
        switch (op) {
        case 0x00: case 0x0a: case 0x0b: // nop, remember / restore state
            break;
        case 0x02: case 0x03: case 0x04: // advance_loc1 / 2 / 4
            return false;
        case 0x06: case 0x07: case 0x08: case 0x2e: // restore_extended, undefined, same_value, gnu_args_size
            if (!uleb(b, p, end, v))
                return false;
            break;
        case 0x05: case 0x09: case 0x0c: case 0x0d: case 0x0e: case 0x0f: case 0x10: case 0x11: case 0x12:
        case 0x13: case 0x14: case 0x15: case 0x16: case 0x2d:
            return true; // the cfa or a register's rule changes before anything ran
        default:
            return false;
        }
    }
    return false;
}

// .eh_frame_hdr: a sorted table with the start of every function that has unwind info. gcc and
// clang write one for nearly every function, stripped or not
void read_eh_frame_hdr(ctx& c)
{
    binary& b = c.b;
    for (size_t i = 0; i < c.secs.size(); i++) {
        const shdr& s = c.secs[i];
        if (s.name != ".eh_frame_hdr" || !c.sec_addr[i] || s.size < 12)
            continue;
        uint64_t hdr = c.sec_addr[i], end = hdr + s.size, p = hdr + 4;
        uint8_t h[4];
        if (b.read(hdr, h, 4) != 4 || h[0] != 1)
            return;
        // one value in dwarf pointer encoding enc: 2 / 4 / 8 bytes, absolute, pc or data relative
        auto get = [&](uint8_t enc, uint64_t& out) {
            uint64_t at = p, v = 0;
            if (enc == 0xff || (enc & 0x80))
                return false;
            switch (enc & 0x0f) {
            case 0x00: if (!b.read_ptr(p, v)) return false; p += (uint64_t)b.ptr_size(); break;
            case 0x02: case 0x0a: { uint16_t x; if (!b.read_u16(p, x)) return false; v = (enc & 8) ? (uint64_t)(int64_t)(int16_t)x : x; p += 2; break; }
            case 0x03: case 0x0b: { uint32_t x; if (!b.read_u32(p, x)) return false; v = (enc & 8) ? (uint64_t)(int64_t)(int32_t)x : x; p += 4; break; }
            case 0x04: case 0x0c: if (!b.read_u64(p, v)) return false; p += 8; break;
            default: return false;
            }
            if ((enc & 0x70) == 0x10)
                v += at;
            else if ((enc & 0x70) == 0x30)
                v += hdr;
            else if (enc & 0x70)
                return false;
            out = c.is64 ? v : v & 0xffffffffull;
            return true;
        };
        uint64_t eh_frame = 0, count = 0;
        if (!get(h[1], eh_frame) || !get(h[2], count))
            return;
        count = std::min<uint64_t>(count, 1u << 20);
        std::unordered_map<uint64_t, cie_info> cies;
        for (uint64_t k = 0; k < count && p < end; k++) {
            uint64_t start = 0, fde = 0, lsda = 0;
            if (!get(h[3], start) || !get(h[3], fde))
                break;
            if (!b.is_code(start))
                continue;
            if (!fde_is_fragment(b, fde, cies, lsda))
                b.func_hints.push_back(start);
            // c++ and rust landing pads: code only the unwinder jumps to
            if (lsda)
                loader::read_lsda(b, start, lsda);
        }
        std::sort(b.landing_pads.begin(), b.landing_pads.end());
        b.landing_pads.erase(std::unique(b.landing_pads.begin(), b.landing_pads.end()), b.landing_pads.end());
        return;
    }
}

void read_init_arrays(ctx& c)
{
    binary& b = c.b;
    for (const shdr& a : c.secs) {
        if (a.type != sht_init_array && a.type != sht_fini_array && a.type != sht_preinit_array)
            continue;
        uint64_t n = std::min<uint64_t>(a.size / b.ptr_size(), 4096);
        for (uint64_t i = 0; i < n; i++) {
            uint64_t v;
            if (b.read_ptr(a.addr + i * b.ptr_size(), v) && v && b.is_code(v))
                b.func_hints.push_back(v);
        }
    }
}

}

namespace loader {

bool elf(binary& b, std::string& err)
{
    util::byte_reader r{b.file};
    uint8_t cls = r.u8(4), data = r.u8(5);
    if (data != 1) {
        err = "big endian elf files aren't supported";
        return false;
    }
    if (cls != 1 && cls != 2) {
        err = "bad elf class";
        return false;
    }
    bool is64 = cls == 2;
    uint16_t type = r.u16(16), machine = r.u16(18);
    if (machine == 62)
        b.arch = bin_arch::x64;
    else if (machine == 3)
        b.arch = bin_arch::x86;
    else if (machine == 183 && is64)
        b.arch = bin_arch::arm64;
    else {
        err = util::fmt("unsupported elf machine %u (x86, x64 and arm64 are supported)", machine);
        return false;
    }

    uint64_t entry, phoff, shoff;
    uint32_t phentsize, phnum, shentsize, shnum, shstrndx;
    if (is64) {
        if (!r.ok(0, 64)) {
            err = "truncated elf header";
            return false;
        }
        entry = r.u64(24);
        phoff = r.u64(32);
        shoff = r.u64(40);
        phentsize = r.u16(54);
        phnum = r.u16(56);
        shentsize = r.u16(58);
        shnum = r.u16(60);
        shstrndx = r.u16(62);
    } else {
        if (!r.ok(0, 52)) {
            err = "truncated elf header";
            return false;
        }
        entry = r.u32(24);
        phoff = r.u32(28);
        shoff = r.u32(32);
        phentsize = r.u16(42);
        phnum = r.u16(44);
        shentsize = r.u16(46);
        shnum = r.u16(48);
        shstrndx = r.u16(50);
    }

    ctx c{b, r, is64, {}, {}};
    uint32_t sh_min = is64 ? 64 : 40, ph_min = is64 ? 56 : 32;

    auto read_shdr = [&](uint64_t off, shdr& s) {
        s.name_off = r.u32(off);
        s.type = r.u32(off + 4);
        if (is64) {
            s.flags = r.u64(off + 8);
            s.addr = r.u64(off + 16);
            s.offset = r.u64(off + 24);
            s.size = r.u64(off + 32);
            s.link = r.u32(off + 40);
            s.info = r.u32(off + 44);
            s.align = r.u64(off + 48);
            s.entsize = r.u64(off + 56);
        } else {
            s.flags = r.u32(off + 8);
            s.addr = r.u32(off + 12);
            s.offset = r.u32(off + 16);
            s.size = r.u32(off + 20);
            s.link = r.u32(off + 24);
            s.info = r.u32(off + 28);
            s.align = r.u32(off + 32);
            s.entsize = r.u32(off + 36);
        }
    };

    if (shoff && shentsize >= sh_min && r.ok(shoff, sh_min)) {
        // extended numbering keeps the real counts in section 0
        shdr zero;
        read_shdr(shoff, zero);
        if (shnum == 0)
            shnum = (uint32_t)std::min<uint64_t>(zero.size, 100000);
        if (shstrndx == 0xffff)
            shstrndx = zero.link;
        if (phnum == 0xffff)
            phnum = zero.info;
        for (uint32_t i = 0; i < std::min<uint32_t>(shnum, 100000); i++) {
            uint64_t off = shoff + (uint64_t)i * shentsize;
            if (!r.ok(off, sh_min)) {
                b.notes.push_back("section header table is truncated");
                break;
            }
            shdr s;
            read_shdr(off, s);
            c.secs.push_back(s);
        }
        if (shstrndx < c.secs.size()) {
            const shdr& names = c.secs[shstrndx];
            for (shdr& s : c.secs)
                if (s.name_off < names.size)
                    s.name = r.cstr(names.offset + s.name_off, std::min<uint64_t>(names.size - s.name_off, 64));
        }
    }

    std::vector<phdr> phs;
    if (phoff && phentsize >= ph_min) {
        for (uint32_t i = 0; i < std::min<uint32_t>(phnum, 65535); i++) {
            uint64_t off = phoff + (uint64_t)i * phentsize;
            if (!r.ok(off, ph_min))
                break;
            phdr p;
            p.type = r.u32(off);
            if (is64) {
                p.flags = r.u32(off + 4);
                p.offset = r.u64(off + 8);
                p.vaddr = r.u64(off + 16);
                p.filesz = r.u64(off + 32);
                p.memsz = r.u64(off + 40);
            } else {
                p.offset = r.u32(off + 4);
                p.vaddr = r.u32(off + 8);
                p.filesz = r.u32(off + 16);
                p.memsz = r.u32(off + 20);
                p.flags = r.u32(off + 24);
            }
            phs.push_back(p);
        }
    }

    bool et_rel = type == 1;
    c.sec_addr.assign(c.secs.size(), 0);
    uint64_t next = 0x10000;
    bool any_alloc = false;
    for (size_t i = 0; i < c.secs.size(); i++) {
        const shdr& s = c.secs[i];
        if (!(s.flags & shf_alloc) || s.size == 0)
            continue;
        if ((s.flags & shf_tls) && s.type == sht_nobits)
            continue; // .tbss takes no address space
        uint64_t addr = s.addr;
        if (et_rel) {
            // object files have every section at 0, lay them out one after another
            uint64_t align = std::min<uint64_t>(std::max<uint64_t>(s.align, 1), 0x1000);
            next = (next + align - 1) / align * align;
            addr = next;
            next += s.size;
        }
        c.sec_addr[i] = addr;
        segment seg;
        seg.name = s.name.empty() ? util::fmt("sec%zu", i) : s.name;
        seg.start = addr;
        seg.end = addr + s.size;
        if (seg.end < seg.start)
            continue;
        seg.perms = perm_r | ((s.flags & shf_write) ? perm_w : 0) | ((s.flags & shf_exec) ? perm_x : 0);
        seg.file_off = s.offset;
        seg.file_size = s.type == sht_nobits ? 0 : s.size;
        b.segments.push_back(seg);
        any_alloc = true;
    }
    if (!any_alloc) {
        int n = 0;
        for (const phdr& p : phs) {
            if (p.type != 1 || p.memsz == 0)
                continue;
            segment seg;
            seg.name = util::fmt("load%d", n++);
            seg.start = p.vaddr;
            seg.end = p.vaddr + p.memsz;
            if (seg.end < seg.start)
                continue;
            seg.perms = ((p.flags & 4) ? perm_r : 0) | ((p.flags & 2) ? perm_w : 0) | ((p.flags & 1) ? perm_x : 0);
            seg.file_off = p.offset;
            seg.file_size = p.filesz;
            b.segments.push_back(seg);
        }
    }
    if (b.segments.empty()) {
        err = "elf file has no loadable segments";
        return false;
    }
    b.finish_segments();
    if (b.segments.empty()) {
        err = "elf file has no loadable segments";
        return false;
    }

    b.base = b.segments.front().start;
    for (const phdr& p : phs)
        if (p.type == 1) {
            b.base = std::min(b.base, p.vaddr);
        }

    read_symbols(c, et_rel);
    read_relocs(c);
    read_needed(c);
    read_init_arrays(c);
    read_eh_frame_hdr(c);

    if (entry && !et_rel && b.is_mapped(entry)) {
        b.entry = entry;
        b.has_entry = true;
        b.func_hints.push_back(entry);
    }

    bool interp = false;
    for (const phdr& p : phs)
        interp |= p.type == 3;
    b.format = bin_format::elf;
    if (type == 1)
        b.kind = "elf object";
    else if (type == 2)
        b.kind = "elf exec";
    else if (type == 3)
        b.kind = interp ? "elf pie" : "elf shared object";
    else if (type == 4)
        b.kind = "elf core";
    else
        b.kind = "elf";
    return true;
}

}
