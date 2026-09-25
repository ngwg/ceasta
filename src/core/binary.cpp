#include "core/binary.h"
#include "core/os.h"
#include "core/util.h"
#include <algorithm>

// caps so a broken header can't make us allocate gigabytes
static const uint64_t max_seg_size = 256ull << 20;
static const uint64_t max_total_size = 1024ull << 20;

const char* format_name(bin_format f)
{
    switch (f) {
    case bin_format::pe: return "pe";
    case bin_format::elf: return "elf";
    case bin_format::raw: return "raw";
    default: return "none";
    }
}

const char* arch_name(bin_arch a)
{
    switch (a) {
    case bin_arch::x86: return "x86";
    case bin_arch::arm64: return "arm64";
    default: return "x64";
    }
}

bool parse_arch(const std::string& s, bin_arch& out)
{
    if (s == "x86" || s == "x32" || s == "i386" || s == "32")
        out = bin_arch::x86;
    else if (s == "x64" || s == "x86_64" || s == "amd64" || s == "64")
        out = bin_arch::x64;
    else if (s == "arm64" || s == "aarch64")
        out = bin_arch::arm64;
    else
        return false;
    return true;
}

const segment* binary::seg_at(uint64_t a) const
{
    // segments are sorted and don't overlap after finish_segments
    auto it = std::upper_bound(segments.begin(), segments.end(), a,
        [](uint64_t v, const segment& s) { return v < s.start; });
    if (it == segments.begin())
        return nullptr;
    --it;
    return it->contains(a) ? &*it : nullptr;
}

bool binary::is_code(uint64_t a) const
{
    const segment* s = seg_at(a);
    return s && s->exec();
}

uint64_t binary::min_addr() const
{
    return segments.empty() ? 0 : segments.front().start;
}

uint64_t binary::max_addr() const
{
    return segments.empty() ? 0 : segments.back().end;
}

size_t binary::read(uint64_t a, void* out, size_t n) const
{
    uint8_t* dst = (uint8_t*)out;
    size_t done = 0;
    while (done < n) {
        const segment* s = seg_at(a + done);
        if (!s)
            break;
        uint64_t off = a + done - s->start;
        size_t chunk = (size_t)std::min<uint64_t>(n - done, s->size() - off);
        memcpy(dst + done, s->data.data() + off, chunk);
        done += chunk;
    }
    return done;
}

bool binary::read_u16(uint64_t a, uint16_t& v) const
{
    uint8_t b[2];
    if (read(a, b, 2) != 2)
        return false;
    v = util::rd16(b);
    return true;
}

bool binary::read_u32(uint64_t a, uint32_t& v) const
{
    uint8_t b[4];
    if (read(a, b, 4) != 4)
        return false;
    v = util::rd32(b);
    return true;
}

bool binary::read_u64(uint64_t a, uint64_t& v) const
{
    uint8_t b[8];
    if (read(a, b, 8) != 8)
        return false;
    v = util::rd64(b);
    return true;
}

bool binary::read_ptr(uint64_t a, uint64_t& v) const
{
    if (is64())
        return read_u64(a, v);
    uint32_t x;
    if (!read_u32(a, x))
        return false;
    v = x;
    return true;
}

bool binary::patch(uint64_t a, const void* src, size_t n)
{
    const segment* s = seg_at(a);
    if (!s || n > s->end - a)
        return false;
    memcpy(const_cast<segment*>(s)->data.data() + (a - s->start), src, n);
    return true;
}

std::string binary::read_cstr(uint64_t a, size_t max_len) const
{
    std::string out;
    for (size_t i = 0; i < max_len; i++) {
        uint8_t c;
        if (!read_u8(a + i, c) || c == 0)
            break;
        out += (char)c;
    }
    return out;
}

void binary::finish_segments()
{
    std::stable_sort(segments.begin(), segments.end(),
        [](const segment& x, const segment& y) { return x.start < y.start; });

    std::vector<segment> out;
    uint64_t total = 0;
    for (segment& s : segments) {
        if (s.end <= s.start)
            continue;
        // trim overlap with the previous segment
        if (!out.empty() && s.start < out.back().end) {
            uint64_t cut = out.back().end - s.start;
            if (cut >= s.size()) {
                notes.push_back(util::fmt("segment %s overlaps %s, skipped", s.name.c_str(), out.back().name.c_str()));
                continue;
            }
            notes.push_back(util::fmt("segment %s overlaps %s, trimmed", s.name.c_str(), out.back().name.c_str()));
            s.start += cut;
            s.file_off += cut;
            s.file_size = s.file_size > cut ? s.file_size - cut : 0;
        }
        if (s.size() > max_seg_size) {
            notes.push_back(util::fmt("segment %s is huge (0x%llx bytes), truncated", s.name.c_str(), (unsigned long long)s.size()));
            s.end = s.start + max_seg_size;
        }
        if (total + s.size() > max_total_size) {
            notes.push_back(util::fmt("mapped size limit reached, segment %s and later are skipped", s.name.c_str()));
            break;
        }
        total += s.size();

        s.data.assign((size_t)s.size(), 0);
        uint64_t n = std::min(s.file_size, s.size());
        if (s.file_off < file.size()) {
            n = std::min<uint64_t>(n, file.size() - s.file_off);
            if (n)
                memcpy(s.data.data(), file.data() + s.file_off, (size_t)n);
        }
        out.push_back(std::move(s));
    }
    segments = std::move(out);
}

namespace loader {

static std::string base_name(const std::string& path)
{
    size_t p = path.find_last_of("/\\");
    return p == std::string::npos ? path : path.substr(p + 1);
}

void raw(std::vector<uint8_t> bytes, const std::string& path, uint64_t base, bin_arch arch, binary& out)
{
    out = binary();
    if (base + bytes.size() + 1 < base)
        base = 0; // would wrap around
    out.path = path;
    out.name = base_name(path);
    out.format = bin_format::raw;
    out.arch = arch;
    out.base = base;
    out.kind = "raw blob";
    out.file = std::move(bytes);
    segment s;
    s.name = "raw";
    s.start = base;
    s.end = base + std::max<uint64_t>(out.file.size(), 1);
    s.perms = perm_r | perm_w | perm_x;
    s.file_off = 0;
    s.file_size = out.file.size();
    out.segments.push_back(s);
    out.finish_segments();
    out.entry = base;
    out.has_entry = !out.file.empty();
    if (out.has_entry)
        out.func_hints.push_back(base);
}

bool from_bytes(std::vector<uint8_t> bytes, const std::string& path, binary& out, std::string& err)
{
    const uint8_t* p = bytes.data();
    size_t n = bytes.size();
    bool is_pe = false;
    if (n >= 0x40 && p[0] == 'M' && p[1] == 'Z') {
        uint32_t lfanew = util::rd32(p + 0x3c);
        is_pe = (uint64_t)lfanew + 4 <= n && memcmp(p + lfanew, "PE\0\0", 4) == 0;
    }
    bool is_elf = n >= 16 && memcmp(p, "\x7f" "ELF", 4) == 0;

    if (!is_pe && !is_elf) {
        raw(std::move(bytes), path, 0, bin_arch::x64, out);
        out.notes.push_back("unknown file format, loaded as raw x64 code at 0");
        return true;
    }

    out = binary();
    out.path = path;
    out.name = base_name(path);
    out.file = std::move(bytes);
    // the parsers map segments themselves (finish_segments) before reading tables
    bool ok = is_pe ? pe(out, err) : elf(out, err);
    if (!ok)
        return false;
    if (out.segments.empty()) {
        err = "file has no loadable sections";
        return false;
    }
    return true;
}

bool peek_arch(const std::string& path, bin_arch& out)
{
    std::vector<uint8_t> head;
    if (!os::read_head(path, 4096, head))
        return false;
    const uint8_t* h = head.data();
    size_t n = head.size();
    if (n >= 20 && memcmp(h, "\x7f" "ELF", 4) == 0) {
        uint16_t m = (uint16_t)(h[18] | h[19] << 8);
        if (m != 3 && m != 62 && m != 183)
            return false;
        out = m == 3 ? bin_arch::x86 : m == 62 ? bin_arch::x64 : bin_arch::arm64;
        return true;
    }
    if (n >= 0x40 && h[0] == 'M' && h[1] == 'Z') {
        uint32_t lfanew = util::rd32(h + 0x3c);
        if ((uint64_t)lfanew + 6 > n || memcmp(h + lfanew, "PE\0\0", 4) != 0)
            return false;
        uint16_t m = (uint16_t)(h[lfanew + 4] | h[lfanew + 5] << 8);
        if (m != 0x14c && m != 0x8664 && m != 0xaa64)
            return false;
        out = m == 0x14c ? bin_arch::x86 : m == 0x8664 ? bin_arch::x64 : bin_arch::arm64;
        return true;
    }
    return false;
}

bool open(const std::string& path, binary& out, std::string& err)
{
    std::vector<uint8_t> bytes;
    if (!os::read_file(path, bytes, err))
        return false;
    return from_bytes(std::move(bytes), path, out, err);
}

}
