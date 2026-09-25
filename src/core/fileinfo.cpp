#include "core/fileinfo.h"
#include "core/util.h"
#include <algorithm>
#include <cmath>
#include <cstring>
#include <functional>
#include <map>

// ------------------------------------------------------------------ hashes and entropy

double entropy(const uint8_t* p, size_t n)
{
    if (!n)
        return 0;
    size_t count[256] = {};
    for (size_t i = 0; i < n; i++)
        count[p[i]]++;
    double e = 0;
    for (size_t c : count)
        if (c) {
            double q = (double)c / (double)n;
            e -= q * std::log2(q);
        }
    return e;
}

namespace {

std::string to_hex(const uint8_t* d, size_t n)
{
    static const char* digits = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < n; i++) {
        s += digits[d[i] >> 4];
        s += digits[d[i] & 15];
    }
    return s;
}

inline uint32_t rol(uint32_t x, int c) { return (x << c) | (x >> (32 - c)); }
inline uint32_t ror(uint32_t x, int c) { return (x >> c) | (x << (32 - c)); }

// the message and its padding, 64 bytes at a time: padding goes in a tail buffer so the file
// isn't copied. big_endian_len: sha-2 stores the bit length big endian, md5 little endian
template <class F>
void blocks(const uint8_t* msg, size_t len, bool big_endian_len, F&& f)
{
    size_t full = len / 64 * 64;
    for (size_t i = 0; i < full; i += 64)
        f(msg + i);
    uint8_t tail[128] = {};
    size_t rest = len - full;
    if (rest)
        memcpy(tail, msg + full, rest);
    tail[rest] = 0x80;
    size_t tlen = rest + 1 + 8 <= 64 ? 64 : 128;
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++)
        tail[tlen - 8 + i] = (uint8_t)(big_endian_len ? bits >> (56 - 8 * i) : bits >> (8 * i));
    f(tail);
    if (tlen == 128)
        f(tail + 64);
}

} // namespace

std::string md5_hex(const void* data, size_t n)
{
    static uint32_t K[64];
    static const int S[64] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9,
        14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};
    static bool init = false;
    if (!init) { // floor(abs(sin(i + 1)) * 2^32)
        for (int i = 0; i < 64; i++)
            K[i] = (uint32_t)(std::fabs(std::sin((double)i + 1.0)) * 4294967296.0);
        init = true;
    }
    uint32_t h[4] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};
    blocks((const uint8_t*)data, n, false, [&](const uint8_t* b) {
        uint32_t m[16];
        for (int i = 0; i < 16; i++)
            m[i] = (uint32_t)b[i * 4] | (uint32_t)b[i * 4 + 1] << 8 | (uint32_t)b[i * 4 + 2] << 16 | (uint32_t)b[i * 4 + 3] << 24;
        uint32_t a = h[0], bb = h[1], c = h[2], d = h[3];
        for (int i = 0; i < 64; i++) {
            uint32_t f;
            int g;
            if (i < 16) {
                f = (bb & c) | (~bb & d);
                g = i;
            } else if (i < 32) {
                f = (d & bb) | (~d & c);
                g = (5 * i + 1) % 16;
            } else if (i < 48) {
                f = bb ^ c ^ d;
                g = (3 * i + 5) % 16;
            } else {
                f = c ^ (bb | ~d);
                g = (7 * i) % 16;
            }
            uint32_t t = d;
            d = c;
            c = bb;
            bb = bb + rol(a + f + K[i] + m[g], S[i]);
            a = t;
        }
        h[0] += a;
        h[1] += bb;
        h[2] += c;
        h[3] += d;
    });
    uint8_t out[16];
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            out[i * 4 + j] = (uint8_t)(h[i] >> (8 * j));
    return to_hex(out, 16);
}

std::string sha256_hex(const void* data, size_t n)
{
    static const uint32_t K[64] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
        0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
        0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85,
        0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c,
        0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
    uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    blocks((const uint8_t*)data, n, true, [&](const uint8_t* b) {
        uint32_t w[64];
        for (int i = 0; i < 16; i++)
            w[i] = (uint32_t)b[i * 4] << 24 | (uint32_t)b[i * 4 + 1] << 16 | (uint32_t)b[i * 4 + 2] << 8 | b[i * 4 + 3];
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = h[0], bb = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 64; i++) {
            uint32_t t1 = hh + (ror(e, 6) ^ ror(e, 11) ^ ror(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
            uint32_t t2 = (ror(a, 2) ^ ror(a, 13) ^ ror(a, 22)) + ((a & bb) ^ (a & c) ^ (bb & c));
            hh = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = bb;
            bb = a;
            a = t1 + t2;
        }
        h[0] += a;
        h[1] += bb;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += hh;
    });
    uint8_t out[32];
    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 4; j++)
            out[i * 4 + j] = (uint8_t)(h[i] >> (24 - 8 * j));
    return to_hex(out, 32);
}

// ------------------------------------------------------------------ helpers

namespace {

// a unix time as a utc date (days to y-m-d as in howard hinnant's civil_from_days)
std::string when(uint32_t t)
{
    if (!t)
        return "0";
    int64_t days = (int64_t)t / 86400, secs = (int64_t)t % 86400;
    int64_t z = days + 719468, era = z / 146097, doe = z - era * 146097;
    int64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    int64_t y = yoe + era * 400, doy = doe - (365 * yoe + yoe / 4 - yoe / 100), mp = (5 * doy + 2) / 153;
    int64_t d = doy - (153 * mp + 2) / 5 + 1, m = mp < 10 ? mp + 3 : mp - 9;
    y += m <= 2;
    // before 1995 or after 2040: a hash (reproducible builds) or a faked date
    bool odd = y < 1995 || y > 2040;
    return util::fmt("%04lld-%02lld-%02lld %02lld:%02lld:%02lld UTC  (%08X)%s", (long long)y, (long long)m, (long long)d,
        (long long)(secs / 3600), (long long)(secs / 60 % 60), (long long)(secs % 60), t, odd ? ", probably not a real date" : "");
}

std::string kib(uint64_t n)
{
    if (n < 10240)
        return util::fmt("%llu bytes", (unsigned long long)n);
    if (n < 10ull * 1024 * 1024)
        return util::fmt("%.1f KB", (double)n / 1024.0);
    return util::fmt("%.1f MB", (double)n / (1024.0 * 1024.0));
}

// what some bytes are, from their first bytes
std::string sniff(const uint8_t* p, size_t n)
{
    auto starts = [&](const char* sig, size_t len) { return n >= len && memcmp(p, sig, len) == 0; };
    if (starts("MZ", 2))
        return "a windows program (MZ)";
    if (starts("\x7f" "ELF", 4))
        return "an elf program";
    if (starts("PK\x03\x04", 4))
        return "a zip archive";
    if (starts("\x89PNG", 4))
        return "a png image";
    if (starts("GIF8", 4))
        return "a gif image";
    if (starts("\xff\xd8\xff", 3))
        return "a jpeg image";
    if (starts("BM", 2) && n > 14)
        return "a bmp image";
    if (starts("%PDF", 4))
        return "a pdf";
    if (starts("7z\xbc\xaf", 4))
        return "a 7-zip archive";
    if (starts("Rar!", 4))
        return "a rar archive";
    if (starts("\x1f\x8b", 2))
        return "gzip data";
    if (starts("MSCF", 4))
        return "a cab archive";
    if (starts("<?xml", 5) || starts("\xef\xbb\xbf<?xml", 8))
        return "xml";
    return std::string();
}

// section names packers and protectors leave behind
std::string packer_of_section(const std::string& n)
{
    static const std::pair<const char*, const char*> known[] = {{"UPX0", "UPX"}, {"UPX1", "UPX"}, {"UPX2", "UPX"},
        {".aspack", "ASPack"}, {".adata", "ASPack"}, {".petite", "Petite"}, {"MPRESS1", "MPRESS"}, {"MPRESS2", "MPRESS"},
        {".MPRESS1", "MPRESS"}, {".themida", "Themida"}, {".winlice", "WinLicense"}, {".vmp0", "VMProtect"},
        {".vmp1", "VMProtect"}, {".vmp2", "VMProtect"}, {".enigma1", "Enigma Protector"}, {".enigma2", "Enigma Protector"},
        {"PEC2", "PECompact"}, {"PEC2TO", "PECompact"}, {"pec1", "PECompact"}, {".nsp0", "NsPack"}, {".nsp1", "NsPack"},
        {"nsp0", "NsPack"}, {".perplex", "Perplex"}, {".yP", "Y0da Protector"}, {".packed", "a packer"},
        {".RLPack", "RLPack"}, {"kkrunchy", "kkrunchy"}, {".MaskPE", "MaskPE"}, {"FSG!", "FSG"}, {".ccg", "CCG"},
        {".boom", "The Boomerang"}, {"ExeS", "EXE Stealth"}, {".spack", "Simple Pack"}, {".ASPack", "ASPack"}};
    for (const auto& k : known)
        if (n == k.first)
            return k.second;
    return std::string();
}

bool has_bytes(const std::vector<uint8_t>& f, size_t from, size_t to, const char* s, size_t len)
{
    to = std::min(to, f.size());
    for (size_t i = from; i + len <= to; i++)
        if (memcmp(&f[i], s, len) == 0)
            return true;
    return false;
}

std::string utf16(const std::vector<uint8_t>& f, uint64_t off, size_t max_chars, size_t* used = nullptr)
{
    std::string s;
    size_t i = 0;
    for (; i < max_chars && off + i * 2 + 1 < f.size(); i++) {
        uint16_t c = (uint16_t)(f[(size_t)(off + i * 2)] | f[(size_t)(off + i * 2 + 1)] << 8);
        if (!c)
            break;
        s += c < 0x80 ? (char)c : '?';
    }
    if (used)
        *used = i;
    return s;
}

// ------------------------------------------------------------------ pe

struct pe_sec {
    std::string name;
    uint32_t va, vsize, raw_ptr, raw_size, flags;
};

struct pe_ctx {
    const binary& b;
    util::byte_reader r;
    std::vector<pe_sec> secs;
    uint64_t rva_to_off(uint32_t rva) const
    {
        for (const pe_sec& s : secs)
            if (rva >= s.va && rva < s.va + std::max(s.vsize, s.raw_size) && rva - s.va < s.raw_size)
                return (uint64_t)s.raw_ptr + (rva - s.va);
        return rva < 0x1000 && rva < b.file.size() ? rva : ~0ull; // the headers
    }
};

void pe_version(pe_ctx& c, uint64_t off, uint64_t size, file_info& out)
{
    // VS_VERSIONINFO: nodes of {wLength, wValueLength, wType, key (utf-16, nul), pad to 4, value, pad,
    // children}; StringFileInfo -> StringTable -> String {key, value}
    const std::vector<uint8_t>& f = c.b.file;
    uint64_t end = std::min<uint64_t>(off + size, f.size());
    int guard = 0;
    std::function<void(uint64_t, uint64_t, int)> walk = [&](uint64_t at, uint64_t stop, int depth) {
        while (at + 6 < stop && guard++ < 2000 && depth < 6) {
            uint16_t len = c.r.u16(at), vlen = c.r.u16(at + 2), type = c.r.u16(at + 4);
            if (len < 6 || at + len > stop)
                return;
            size_t used = 0;
            std::string key = utf16(f, at + 6, 64, &used);
            uint64_t v = (at + 6 + (used + 1) * 2 + 3) & ~3ull;
            if (depth == 3 && type == 1 && vlen) { // a String: the value is utf-16
                std::string val = util::trim(utf16(f, v, std::min<size_t>(vlen, 512)));
                if (!val.empty())
                    out.version.push_back({key, val});
            }
            uint64_t kids = depth == 0 ? (v + vlen + 3) & ~3ull // the fixed file info, then children
                          : depth == 3 ? at + len
                          : (v + (type == 1 ? vlen * 2u : vlen) + 3) & ~3ull;
            if (depth == 0 || key == "StringFileInfo" || depth == 2)
                walk(kids, at + len, depth + 1);
            at = (at + len + 3) & ~3ull;
        }
    };
    walk(off, end, 0);
}

const char* res_type_name(uint32_t id)
{
    switch (id) {
    case 1: return "CURSOR";
    case 2: return "BITMAP";
    case 3: return "ICON";
    case 4: return "MENU";
    case 5: return "DIALOG";
    case 6: return "STRING";
    case 7: return "FONTDIR";
    case 8: return "FONT";
    case 9: return "ACCELERATOR";
    case 10: return "RCDATA";
    case 11: return "MESSAGETABLE";
    case 12: return "GROUP_CURSOR";
    case 14: return "GROUP_ICON";
    case 16: return "VERSION";
    case 17: return "DLGINCLUDE";
    case 19: return "PLUGPLAY";
    case 20: return "VXD";
    case 21: return "ANICURSOR";
    case 22: return "ANIICON";
    case 23: return "HTML";
    case 24: return "MANIFEST";
    default: return nullptr;
    }
}

void pe_resources(pe_ctx& c, uint32_t rva, file_info& out)
{
    uint64_t root = c.rva_to_off(rva);
    if (root == ~0ull)
        return;
    const std::vector<uint8_t>& f = c.b.file;
    auto entry_name = [&](uint32_t v) -> std::string {
        if (v & 0x80000000u) {
            uint64_t at = root + (v & 0x7fffffffu);
            uint16_t n = c.r.u16(at);
            return utf16(f, at + 2, std::min<uint16_t>(n, 128));
        }
        return std::to_string(v);
    };
    size_t count = 0;
    auto dir = [&](uint64_t at, auto&& self, int level, std::string type, std::string name, uint32_t type_id) -> void {
        if (!c.r.ok(at, 16) || level > 2 || count > 5000)
            return;
        uint32_t n = (uint32_t)c.r.u16(at + 12) + c.r.u16(at + 14);
        for (uint32_t i = 0; i < n && i < 4096 && count <= 5000; i++) {
            uint64_t e = at + 16 + (uint64_t)i * 8;
            uint32_t nm = c.r.u32(e), off = c.r.u32(e + 4);
            std::string label = entry_name(nm);
            std::string t = type, na = name;
            uint32_t tid = type_id;
            if (level == 0) {
                tid = nm & 0x80000000u ? 0 : nm;
                const char* known = tid ? res_type_name(tid) : nullptr;
                t = known ? known : label;
            } else if (level == 1) {
                na = label;
            }
            if (off & 0x80000000u) {
                self(root + (off & 0x7fffffffu), self, level + 1, t, na, tid);
                continue;
            }
            // a data entry: rva, size
            uint64_t de = root + off;
            uint32_t drva = c.r.u32(de), dsize = c.r.u32(de + 4);
            file_info::resource res;
            res.type = t;
            res.name = na;
            res.lang = level == 2 ? (nm & 0xffff) : 0;
            res.size = dsize;
            uint64_t fo = c.rva_to_off(drva);
            res.file_off = fo == ~0ull ? 0 : fo;
            if (fo != ~0ull && c.r.ok(fo, 1)) {
                size_t len = (size_t)std::min<uint64_t>(dsize, f.size() - fo);
                res.entropy = entropy(&f[(size_t)fo], len);
                res.note = sniff(&f[(size_t)fo], len);
                if (tid == 16)
                    pe_version(c, fo, dsize, out);
                if (tid == 24) { // the manifest: which privileges it asks for
                    std::string xml((const char*)&f[(size_t)fo], std::min<size_t>(len, 8192));
                    size_t lv = xml.find("level=");
                    if (lv != std::string::npos) {
                        size_t q = xml.find_first_of("\"'", lv), q2 = q == std::string::npos ? q : xml.find(xml[q], q + 1);
                        if (q2 != std::string::npos)
                            res.note = "runs as " + xml.substr(q + 1, q2 - q - 1);
                    }
                }
            }
            out.resources.push_back(res);
            count++;
        }
    };
    dir(root, dir, 0, std::string(), std::string(), 0);
}

void inspect_pe(const binary& b, file_info& out)
{
    pe_ctx c{b, util::byte_reader{b.file}, {}};
    util::byte_reader& r = c.r;
    uint32_t lfanew = r.u32(0x3c);
    uint64_t coff = (uint64_t)lfanew + 4;
    if (!r.ok(coff, 20))
        return;
    uint16_t machine = r.u16(coff), nsec = r.u16(coff + 2), opt_size = r.u16(coff + 16), chars = r.u16(coff + 18);
    uint32_t stamp = r.u32(coff + 4);
    uint64_t opt = coff + 20;
    bool pe64 = r.u16(opt) == 0x20b;
    uint32_t aep = r.u32(opt + 16);
    uint16_t sub = r.u16(opt + 68), dllc = r.u16(opt + 70);
    uint64_t dirs = opt + (pe64 ? 112 : 96);
    uint32_t ndirs = std::min<uint32_t>(r.u32(opt + (pe64 ? 108 : 92)), 16);
    auto dir = [&](uint32_t i, uint32_t& rva, uint32_t& size) {
        rva = size = 0;
        if (i >= ndirs)
            return false;
        rva = r.u32(dirs + i * 8);
        size = r.u32(dirs + i * 8 + 4);
        return rva != 0 && size != 0;
    };
    uint64_t sec_off = opt + opt_size;
    for (uint16_t i = 0; i < nsec && i < 96; i++) {
        uint64_t s = sec_off + (uint64_t)i * 40;
        if (!r.ok(s, 40))
            break;
        pe_sec ps;
        char nm[9] = {};
        memcpy(nm, &b.file[(size_t)s], 8);
        for (char& ch : nm)
            if (ch && (ch < 32 || ch > 126))
                ch = '?';
        ps.name = nm;
        ps.vsize = r.u32(s + 8);
        ps.va = r.u32(s + 12);
        ps.raw_size = r.u32(s + 16);
        ps.raw_ptr = r.u32(s + 20);
        ps.flags = r.u32(s + 36);
        c.secs.push_back(ps);
    }

    const char* mach = machine == 0x8664 ? "x86-64" : machine == 0x14c ? "x86 (i386)" : machine == 0xaa64 ? "arm64" : "other";
    out.header.push_back({"format", std::string(pe64 ? "PE32+" : "PE32") + ((chars & 0x2000) ? " dll" : " exe")});
    out.header.push_back({"machine", util::fmt("%s (0x%04X)", mach, machine)});
    const char* subs = sub == 2 ? "windows gui" : sub == 3 ? "console" : sub == 1 ? "native (a driver)" : sub == 10 ? "efi application"
                     : sub == 11 ? "efi boot service driver" : sub == 12 ? "efi runtime driver" : sub == 9 ? "windows ce" : "other";
    out.header.push_back({"subsystem", util::fmt("%s (%u)", subs, sub)});
    out.header.push_back({"built", when(stamp)});
    out.header.push_back({"linker", util::fmt("%u.%u", r.u8(opt + 2), r.u8(opt + 3))});
    out.header.push_back({"image base", util::fmt("0x%llX", (unsigned long long)b.base)});
    out.header.push_back({"entry point", util::fmt("0x%llX (rva 0x%X)", (unsigned long long)(b.base + aep), aep)});
    out.header.push_back({"image size", kib(r.u32(opt + 56))});
    std::string sec;
    auto flag = [&](bool on, const char* yes, const char* no) {
        sec += (sec.empty() ? "" : ", ") + std::string(on ? yes : no);
    };
    flag(dllc & 0x40, "aslr", "no aslr");
    if (pe64 && (dllc & 0x40))
        flag(dllc & 0x20, "high entropy aslr", "32-bit aslr");
    flag(dllc & 0x100, "dep", "no dep");
    flag(dllc & 0x4000, "control flow guard", "no cfg");
    if (dllc & 0x400)
        flag(true, "no seh", "");
    uint32_t sig_off, sig_size;
    bool signed_pe = dir(4, sig_off, sig_size);
    flag(signed_pe, "signed (authenticode, not checked)", "not signed");
    out.header.push_back({"security", sec});
    uint32_t cs = r.u32(opt + 64);
    out.header.push_back({"checksum", cs ? util::fmt("0x%08X", cs) : std::string("0 (not set)")});

    // the debug directory: the pdb path the linker wrote
    uint32_t drva, dsize;
    if (dir(6, drva, dsize)) {
        uint64_t d = c.rva_to_off(drva);
        for (uint32_t i = 0; d != ~0ull && i < dsize / 28 && i < 16; i++) {
            uint64_t e = d + (uint64_t)i * 28;
            if (r.u32(e + 12) != 2) // codeview
                continue;
            uint64_t cv = r.u32(e + 24);
            if (r.ok(cv, 24) && r.u32(cv) == 0x53445352) { // "RSDS"
                std::string pdb = r.cstr(cv + 24, 260);
                if (!pdb.empty())
                    out.header.push_back({"pdb", pdb});
            }
        }
    }
    // tls callbacks run before the entry point: debuggers miss them, malware likes them
    uint32_t trva, tsize;
    if (dir(9, trva, tsize)) {
        uint64_t t = c.rva_to_off(trva);
        uint64_t cb_va = t == ~0ull ? 0 : pe64 ? r.u64(t + 24) : r.u32(t + 12);
        int n = 0;
        uint64_t v = 0;
        while (cb_va && n < 64 && b.read_ptr(cb_va + (uint64_t)n * b.ptr_size(), v) && v)
            n++;
        if (n) {
            out.header.push_back({"tls callbacks", std::to_string(n)});
            out.warnings.push_back(util::fmt("%d tls callback%s: code that runs before the entry point", n, n == 1 ? "" : "s"));
        }
    }
    uint32_t crva, csize;
    if (dir(14, crva, csize)) {
        out.header.push_back({"runtime", ".net (clr)"});
        out.warnings.push_back("a .net assembly: its code is IL for the .net runtime, not x86 - ceasta shows the native stub. "
                               "a .net decompiler (dnSpy, ILSpy) reads the rest");
    }
    if (has_bytes(b.file, 0x40, std::min<size_t>(lfanew, 0x400), "Rich", 4))
        out.header.push_back({"rich header", "yes: built with microsoft's tools"});

    // sections
    uint64_t data_end = 0;
    std::string packer;
    for (const pe_sec& s : c.secs) {
        file_info::section fs;
        fs.name = s.name;
        fs.addr = b.base + s.va;
        fs.size = s.vsize;
        fs.file_off = s.raw_ptr;
        fs.file_size = s.raw_size;
        fs.perms = std::string((s.flags & 0x40000000u) ? "r" : "-") + ((s.flags & 0x80000000u) ? "w" : "-") +
                   ((s.flags & 0x20000000u) ? "x" : "-");
        if (s.raw_size && r.ok(s.raw_ptr, 1))
            fs.entropy = entropy(&b.file[s.raw_ptr], (size_t)std::min<uint64_t>(s.raw_size, b.file.size() - s.raw_ptr));
        out.sections.push_back(fs);
        data_end = std::max<uint64_t>(data_end, (uint64_t)s.raw_ptr + s.raw_size);
        if (packer.empty())
            packer = packer_of_section(s.name);
    }
    if (packer.empty() && has_bytes(b.file, 0, std::min<size_t>(b.file.size(), 0x1000), "UPX!", 4))
        packer = "UPX";
    if (!packer.empty())
        out.warnings.push_back("packed with " + packer + ": the real code is compressed or encrypted and unpacks itself "
                               "when it runs." + (packer == "UPX" ? " upx -d unpacks it;" : "") +
                               " or run it in the debugger to the original entry point and read it there");
    // the entry point's section
    for (const pe_sec& s : c.secs)
        if (aep >= s.va && aep < s.va + std::max(s.vsize, s.raw_size)) {
            bool first_code = false;
            for (const pe_sec& t : c.secs)
                if (t.flags & 0x20000000u) {
                    first_code = &t == &s;
                    break;
                }
            static const char* const usual[] = {".text", ".itext", "CODE", ".code", "INIT", ".init", "text"};
            bool normal = false;
            for (const char* u : usual)
                normal = normal || s.name == u;
            if (s.flags & 0x80000000u)
                out.warnings.push_back("the entry point is in " + s.name + ", which is writable: code that changes itself (a packer)");
            else if (!first_code && !normal && packer.empty())
                out.warnings.push_back("the entry point is in " + s.name + ", not the first code section: often a packer's stub");
        }
    for (const file_info::section& s : out.sections)
        if (s.entropy > 7.2 && s.file_size > 4096 && packer.empty() && s.name != ".rsrc") { // resources: checked one by one
            out.warnings.push_back(util::fmt("%s has an entropy of %.2f: compressed or encrypted data", s.name.c_str(), s.entropy));
            break;
        }
    // an overlay: data past the last section (not the signature, not a coff symbol table) -
    // installers and droppers keep payloads there
    uint32_t sym_ptr = r.u32(coff + 8), nsyms = r.u32(coff + 12);
    if (sym_ptr && sym_ptr >= data_end && r.ok(sym_ptr, (uint64_t)nsyms * 18 + 4)) {
        uint64_t strtab = (uint64_t)sym_ptr + (uint64_t)nsyms * 18;
        data_end = strtab + r.u32(strtab);
    }
    uint64_t end = b.file.size();
    if (signed_pe && sig_off >= data_end && (uint64_t)sig_off + sig_size <= b.file.size())
        end = sig_off;
    bool zeros = true; // padding to the file alignment isn't an overlay
    for (uint64_t i = data_end; zeros && i < end && i < b.file.size(); i++)
        zeros = b.file[(size_t)i] == 0;
    if (data_end && end > data_end + 16 && !zeros) {
        std::string what = sniff(&b.file[(size_t)data_end], (size_t)(end - data_end));
        out.warnings.push_back(util::fmt("an overlay: %s after the last section (at file offset 0x%llX)%s", kib(end - data_end).c_str(),
            (unsigned long long)data_end, what.empty() ? "" : (", " + what).c_str()));
    }
    // few imports but LoadLibrary / GetProcAddress: the rest are looked up at runtime
    bool loads = false;
    for (const import_entry& e : b.imports)
        loads = loads || e.name.find("GetProcAddress") != std::string::npos || e.name.find("LdrGetProcedureAddress") != std::string::npos;
    if (b.imports.size() <= 12 && loads)
        out.warnings.push_back(util::fmt("only %zu imports, among them GetProcAddress: the program looks up the rest while it runs",
            b.imports.size()));

    uint32_t rrva, rsize;
    if (dir(2, rrva, rsize))
        pe_resources(c, rrva, out);
    for (const file_info::resource& res : out.resources) {
        if (res.note.find("program") != std::string::npos)
            out.warnings.push_back("resource " + res.type + "/" + res.name + " holds " + res.note + ": an embedded payload?");
        else if (res.entropy > 7.5 && res.size > 4096 && res.type != "ICON" && res.type != "BITMAP" && res.note.find("image") == std::string::npos &&
                 res.note.find("archive") == std::string::npos && res.note.find("gzip") == std::string::npos)
            out.warnings.push_back(util::fmt("resource %s/%s (%s) looks encrypted or compressed (entropy %.2f)", res.type.c_str(),
                res.name.c_str(), kib(res.size).c_str(), res.entropy));
    }

    // imphash: md5 of the imports, "lib.func" lower case, the way pefile makes it
    std::string imp;
    for (const import_entry& e : b.imports) {
        if (e.delay)
            continue; // like pefile: the import directory only
        std::string lib = util::lower(e.lib);
        for (const char* ext : {".dll", ".sys", ".ocx"}) {
            size_t n = strlen(ext);
            if (lib.size() > n && lib.compare(lib.size() - n, n, ext) == 0)
                lib = lib.substr(0, lib.size() - n);
        }
        std::string fn = e.name.size() > 1 && e.name[0] == '#' ? "ord" + e.name.substr(1) : util::lower(e.name);
        imp += (imp.empty() ? "" : ",") + lib + "." + fn;
    }
    if (!imp.empty())
        out.imphash = md5_hex(imp.data(), imp.size());
}

// ------------------------------------------------------------------ elf

void inspect_elf(const binary& b, file_info& out)
{
    util::byte_reader r{b.file};
    bool e64 = r.u8(4) == 2;
    if (r.u8(5) != 1) {
        out.header.push_back({"format", "big endian elf (not read)"});
        return;
    }
    uint16_t type = r.u16(16), machine = r.u16(18);
    uint64_t entry = e64 ? r.u64(24) : r.u32(24);
    uint64_t phoff = e64 ? r.u64(32) : r.u32(28), shoff = e64 ? r.u64(40) : r.u32(32);
    uint16_t phentsize = r.u16(e64 ? 54 : 42), phnum = r.u16(e64 ? 56 : 44);
    uint16_t shentsize = r.u16(e64 ? 58 : 46), shnum = r.u16(e64 ? 60 : 48), shstrndx = r.u16(e64 ? 62 : 50);
    const char* osabi = r.u8(7) == 0 ? "system v" : r.u8(7) == 3 ? "linux" : r.u8(7) == 9 ? "freebsd" : r.u8(7) == 6 ? "solaris" : "other";
    const char* mach = machine == 62 ? "x86-64" : machine == 3 ? "x86 (i386)" : machine == 183 ? "arm64" : machine == 40 ? "arm" : "other";
    bool interp = false, stack_x = false, relro = false, now = false;
    std::string interp_path;
    // program headers
    for (uint16_t i = 0; i < phnum && i < 256; i++) {
        uint64_t p = phoff + (uint64_t)i * phentsize;
        if (!r.ok(p, e64 ? 56 : 32))
            break;
        uint32_t pt = r.u32(p);
        uint32_t flags = e64 ? r.u32(p + 4) : r.u32(p + 24);
        uint64_t off = e64 ? r.u64(p + 8) : r.u32(p + 4);
        if (pt == 3) { // PT_INTERP
            interp = true;
            interp_path = r.cstr(off, 256);
        } else if (pt == 0x6474e551) { // PT_GNU_STACK
            stack_x = (flags & 1) != 0;
        } else if (pt == 0x6474e552) { // PT_GNU_RELRO
            relro = true;
        } else if (pt == 2) { // PT_DYNAMIC: bind now?
            uint64_t sz = e64 ? r.u64(p + 32) : r.u32(p + 16);
            size_t ent = e64 ? 16 : 8;
            for (uint64_t d = off; d + ent <= off + sz && d + ent <= b.file.size(); d += ent) {
                int64_t tag = e64 ? (int64_t)r.u64(d) : (int32_t)r.u32(d);
                uint64_t val = e64 ? r.u64(d + 8) : r.u32(d + 4);
                if (tag == 0)
                    break;
                if (tag == 24 || (tag == 30 && (val & 8)) || (tag == 0x6ffffffb && (val & 1)))
                    now = true; // DT_BIND_NOW, DF_BIND_NOW, DF_1_NOW
            }
        }
    }
    out.header.push_back({"format", std::string(e64 ? "ELF64" : "ELF32") + (type == 3 ? (interp ? " pie executable" : " shared library")
                                   : type == 2 ? " executable" : type == 1 ? " object file" : type == 4 ? " core dump" : "")});
    out.header.push_back({"machine", util::fmt("%s (%u)", mach, machine)});
    out.header.push_back({"os abi", osabi});
    out.header.push_back({"entry point", util::fmt("0x%llX", (unsigned long long)entry)});
    if (!interp_path.empty())
        out.header.push_back({"interpreter", interp_path});
    if (!b.libs.empty()) {
        std::string libs;
        for (const std::string& l : b.libs)
            libs += (libs.empty() ? "" : ", ") + l;
        out.header.push_back({"needs", libs});
    }
    bool canary = false, fortify = false;
    for (const import_entry& e : b.imports) {
        canary = canary || e.name == "__stack_chk_fail";
        fortify = fortify || (e.name.size() > 6 && e.name.compare(0, 2, "__") == 0 && e.name.compare(e.name.size() - 4, 4, "_chk") == 0);
    }
    std::string sec;
    auto flag = [&](bool on, const char* yes, const char* no) { sec += (sec.empty() ? "" : ", ") + std::string(on ? yes : no); };
    flag(type == 3 && interp, "pie", "no pie");
    flag(!stack_x, "nx stack", "executable stack");
    flag(relro, now ? "full relro" : "partial relro", "no relro");
    flag(canary, "stack canary", "no canary");
    if (fortify)
        flag(true, "fortify", "");
    out.header.push_back({"security", sec});
    if (stack_x)
        out.warnings.push_back("the stack is executable (PT_GNU_STACK allows it): old toolchains, or code that runs on the stack");

    // section headers: names, entropy, a few that say how it was built
    uint64_t shstr = 0;
    if (shstrndx < shnum && r.ok(shoff + (uint64_t)shstrndx * shentsize, e64 ? 64 : 40))
        shstr = e64 ? r.u64(shoff + (uint64_t)shstrndx * shentsize + 24) : r.u32(shoff + (uint64_t)shstrndx * shentsize + 16);
    bool symtab = false;
    for (uint16_t i = 0; i < shnum && i < 1024; i++) {
        uint64_t sh = shoff + (uint64_t)i * shentsize;
        if (!r.ok(sh, e64 ? 64 : 40))
            break;
        uint32_t nm = r.u32(sh), stype = r.u32(sh + 4);
        uint64_t flags = e64 ? r.u64(sh + 8) : r.u32(sh + 8);
        uint64_t addr = e64 ? r.u64(sh + 16) : r.u32(sh + 12);
        uint64_t off = e64 ? r.u64(sh + 24) : r.u32(sh + 16);
        uint64_t size = e64 ? r.u64(sh + 32) : r.u32(sh + 20);
        std::string name = shstr ? r.cstr(shstr + nm, 64) : std::string();
        if (stype == 2)
            symtab = true;
        if (name == ".comment" && r.ok(off, 1)) {
            std::string cm;
            for (uint64_t at = off; at < off + size && at < b.file.size();) {
                std::string one = r.cstr(at, 200);
                if (!one.empty() && cm.find(one) == std::string::npos)
                    cm += (cm.empty() ? "" : "; ") + one;
                at += one.size() + 1;
            }
            if (!cm.empty())
                out.header.push_back({"compiler", cm});
        }
        if (name == ".note.gnu.build-id" && r.ok(off + 16, 1)) {
            uint32_t descsz = r.u32(off + 4);
            if (r.ok(off + 16, descsz) && descsz <= 64)
                out.header.push_back({"build id", to_hex(&b.file[(size_t)off + 16], descsz)});
        }
        if (name == ".gopclntab" || name == ".go.buildinfo" || name == ".note.go.buildid")
            out.header.push_back({"language", "go (a go runtime is built in: most functions are the runtime's)"});
        if (!(flags & 2) || name.empty()) // SHF_ALLOC: loaded
            continue;
        file_info::section fs;
        fs.name = name;
        fs.addr = addr;
        fs.size = size;
        fs.file_off = stype == 8 ? 0 : off; // NOBITS (.bss) has no bytes
        fs.file_size = stype == 8 ? 0 : size;
        fs.perms = std::string("r") + ((flags & 1) ? "w" : "-") + ((flags & 4) ? "x" : "-");
        if (fs.file_size && r.ok(off, 1))
            fs.entropy = entropy(&b.file[(size_t)off], (size_t)std::min<uint64_t>(size, b.file.size() - off));
        out.sections.push_back(fs);
    }
    out.header.push_back({"symbols", symtab ? "yes (not stripped)" : "stripped"});
    std::string packer;
    if (has_bytes(b.file, 0, std::min<size_t>(b.file.size(), 0x1000), "UPX!", 4))
        packer = "UPX";
    if (!packer.empty())
        out.warnings.push_back("packed with " + packer + ": the real code is compressed and unpacks itself when it runs. upx -d unpacks it");
    else if (!shnum)
        out.warnings.push_back("no section headers: stripped hard, or packed");
    for (const file_info::section& s : out.sections)
        if (s.entropy > 7.2 && s.file_size > 4096 && packer.empty()) {
            out.warnings.push_back(util::fmt("%s has an entropy of %.2f: compressed or encrypted data", s.name.c_str(), s.entropy));
            break;
        }
}

} // namespace

file_info inspect(const binary& b)
{
    file_info out;
    if (!b.file.empty()) {
        out.md5 = md5_hex(b.file.data(), b.file.size());
        out.sha256 = sha256_hex(b.file.data(), b.file.size());
        out.entropy = entropy(b.file.data(), b.file.size());
    }
    out.header.push_back({"file", b.path});
    out.header.push_back({"size", kib(b.file.size())});
    if (b.format == bin_format::pe)
        inspect_pe(b, out);
    else if (b.format == bin_format::elf)
        inspect_elf(b, out);
    else
        out.header.push_back({"format", util::fmt("raw %s code at 0x%llX", arch_name(b.arch), (unsigned long long)b.base)});
    if (out.entropy > 7.5 && b.file.size() > 16384)
        out.warnings.push_back(util::fmt("the whole file has an entropy of %.2f: most of it is compressed or encrypted", out.entropy));
    return out;
}
