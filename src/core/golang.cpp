#include "core/binary.h"
#include "core/util.h"
#include <algorithm>
#include <unordered_set>

// go programs carry a table of every function (the pclntab: the runtime's stack traces need it)
// with its name, stripped (-ldflags="-s -w") or not, on every os. four layouts:
//
//   go 1.2 - 1.15    magic fffffffb   entries (pc, offset), names counted from the table's start
//   go 1.16 - 1.17   magic fffffffa   a header with where the name table and the entries are
//   go 1.18 - 1.19   magic fffffff0   the header also has the text start; entries are 32-bit
//   go 1.20 and on   magic fffffff1   offsets from it
//
// each entry points at the function's _func record, which repeats its start (checked, so data
// that merely looks like a header can't name anything) and has the name's offset

namespace {

bool magic_ok(uint32_t m)
{
    return m == 0xfffffffb || m == 0xfffffffa || m == 0xfffffff0 || m == 0xfffffff1;
}

// a header at h: its magic, two zero bytes, the instruction size (1 x86, 4 arm) and the pointer size
bool header_at(const binary& b, uint64_t h)
{
    uint8_t x[8];
    return b.read(h, x, 8) == 8 && magic_ok(util::rd32(x)) && x[4] == 0 && x[5] == 0 &&
           (x[6] == 1 || x[6] == 2 || x[6] == 4) && x[7] == b.ptr_size();
}

bool printable(const std::string& s)
{
    if (s.empty())
        return false;
    for (char c : s)
        if ((unsigned char)c < 0x20 || c == 0x7f)
            return false;
    return true;
}

struct go_func {
    uint64_t entry;
    std::string name;
    uint32_t deferreturn; // where the runtime resumes it after a recovered panic, 0: none
};

// the functions of the table at h, sorted by address. false when it doesn't hold together
bool parse(const binary& b, uint64_t h, std::vector<go_func>& out)
{
    uint32_t magic = 0;
    uint64_t ps = (uint64_t)b.ptr_size(), nfunc = 0;
    if (!b.read_u32(h, magic) || !b.read_ptr(h + 8, nfunc) || nfunc == 0 || nfunc > (4u << 20))
        return false;
    uint64_t names, ftab, text = 0, esz;
    bool rel = false; // entries are 32-bit offsets from the text start
    if (magic == 0xfffffffb) {
        names = h;
        ftab = h + 8 + ps;
        esz = 2 * ps;
    } else {
        uint64_t k = magic == 0xfffffffa ? 0 : 1, nameoff, pclnoff;
        if ((k && (!b.read_ptr(h + 8 + 2 * ps, text) || !b.is_code(text))) ||
            !b.read_ptr(h + 8 + (2 + k) * ps, nameoff) || !b.read_ptr(h + 8 + (6 + k) * ps, pclnoff))
            return false;
        names = h + nameoff;
        ftab = h + pclnoff;
        rel = k != 0;
        esz = rel ? 8 : 2 * ps;
    }
    // _func records are counted from the table start (1.2 - 1.15) or the entries' start
    uint64_t base = magic == 0xfffffffb ? h : ftab;
    out.clear();
    out.reserve((size_t)nfunc);
    uint64_t prev = 0, bad = 0;
    for (uint64_t i = 0; i < nfunc; i++) {
        uint64_t e = ftab + i * esz, entry = 0, fo = 0, again = 0;
        uint32_t nameoff = 0;
        if (rel) {
            uint32_t a, f, a2;
            if (!b.read_u32(e, a) || !b.read_u32(e + 4, f) || !b.read_u32(base + f, a2))
                return false;
            entry = text + a;
            fo = f;
            again = text + a2;
        } else if (!b.read_ptr(e, entry) || !b.read_ptr(e + ps, fo) || !b.read_ptr(base + fo, again)) {
            return false;
        }
        std::string name;
        if (b.read_u32(base + fo + (rel ? 4 : ps), nameoff) && (int32_t)nameoff >= 0)
            name = b.read_cstr(names + nameoff, 1024);
        // then args and deferreturn (go 1.16 on; older ones had other fields there)
        uint32_t dr = 0;
        if (magic == 0xfffffffb || !b.read_u32(base + fo + (rel ? 12 : ps + 8), dr))
            dr = 0;
        if (again != entry || entry < prev || !b.is_code(entry) || !printable(name)) {
            if (++bad > 16 + nfunc / 32)
                return false;
            continue;
        }
        prev = entry;
        // go 1.17 and older join closure names with a middle dot (json.wrap·1): json.wrap.1,
        // the way go's tools print them now
        for (size_t k; (k = name.find("\xc2\xb7")) != std::string::npos;)
            name.replace(k, 2, ".");
        out.push_back({entry, name, dr});
    }
    return !out.empty();
}

} // namespace

namespace loader {

void read_go_functions(binary& b)
{
    std::vector<go_func> fns;
    bool found = false;
    // the table's own section: .gopclntab, .data.rel.ro.gopclntab (pie), __gopclntab (mach-o)
    for (const segment& s : b.segments) {
        const std::string& n = s.name;
        if (n.size() >= 9 && n.compare(n.size() - 9, 9, "gopclntab") == 0 && header_at(b, s.start) && parse(b, s.start, fns)) {
            found = true;
            break;
        }
    }
    // windows files (and elf ones without sections) have it in their read-only data: look for it
    for (size_t si = 0; !found && si < b.segments.size(); si++) {
        const segment& s = b.segments[si];
        if (s.exec() && b.format != bin_format::macho)
            continue;
        const std::vector<uint8_t>& d = s.data;
        for (size_t off = (size_t)((4 - (s.start & 3)) & 3); off + 16 <= d.size(); off += 4) {
            if (d[off + 1] != 0xff || d[off + 2] != 0xff || d[off + 3] != 0xff || !magic_ok(util::rd32(&d[off])) ||
                !header_at(b, s.start + off) || !parse(b, s.start + off, fns))
                continue;
            found = true;
            break;
        }
    }
    if (!found)
        return;
    std::unordered_set<uint64_t> named;
    for (const symbol_entry& sy : b.symbols)
        if (sy.func)
            named.insert(sy.addr);
    bool cgo = false;
    for (size_t i = 0; i < fns.size(); i++) {
        uint64_t a = fns[i].entry, end = i + 1 < fns.size() ? fns[i + 1].entry : 0;
        const std::string& n = fns[i].name;
        cgo = cgo || n.compare(0, 12, "runtime/cgo.") == 0 || n.compare(0, 5, "_cgo_") == 0;
        b.func_hints.push_back(a);
        // the deferreturn call: only the runtime jumps there, like to a landing pad
        uint64_t dr = a + fns[i].deferreturn;
        if (fns[i].deferreturn && (!end || dr < end) && b.is_code(dr))
            b.landing_pads.push_back({a, dr});
        if (named.insert(a).second)
            b.symbols.push_back({n, a, end ? end - a : 0, true});
    }
    std::sort(b.landing_pads.begin(), b.landing_pads.end());
    b.landing_pads.erase(std::unique(b.landing_pads.begin(), b.landing_pads.end()), b.landing_pads.end());
    // every go function is in the table, so code found some other way belongs to the one
    // around it. not with cgo: its c functions aren't in it
    if (!cgo)
        b.starts_complete = true;
    b.notes.push_back(util::fmt("go program: %zu function names from its pclntab", fns.size()));
}

} // namespace loader
