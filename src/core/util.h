#pragma once
#include <array>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

// small shared helpers, header only

namespace util {

inline std::string fmt(const char* f, ...)
{
    char buf[1024];
    va_list args;
    va_start(args, f);
    int n = vsnprintf(buf, sizeof(buf), f, args);
    va_end(args);
    if (n < 0)
        return std::string();
    if (n < (int)sizeof(buf))
        return std::string(buf, (size_t)n);
    std::string out((size_t)n, '\0');
    va_start(args, f);
    vsnprintf(&out[0], (size_t)n + 1, f, args);
    va_end(args);
    return out;
}

// uppercase / lowercase hex without prefix or padding
inline std::string hex(uint64_t v) { return fmt("%llX", (unsigned long long)v); }
inline std::string hex_lower(uint64_t v) { return fmt("%llx", (unsigned long long)v); }

inline std::string lower(std::string s)
{
    for (char& c : s)
        if (c >= 'A' && c <= 'Z')
            c = (char)(c - 'A' + 'a');
    return s;
}

inline std::string trim(const std::string& s)
{
    size_t a = 0, b = s.size();
    while (a < b && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n'))
        a++;
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r' || s[b - 1] == '\n'))
        b--;
    return s.substr(a, b - a);
}

// case insensitive substring test, empty needle always matches
inline bool icontains(const std::string& hay, const std::string& needle)
{
    if (needle.empty())
        return true;
    return lower(hay).find(lower(needle)) != std::string::npos;
}

inline int hex_digit(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

// parses "401000", "0x401000", "401000h". no sign, no spaces inside
inline bool parse_hex(const std::string& in, uint64_t& out)
{
    std::string s = trim(in);
    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        s = s.substr(2);
    else if (s.size() > 1 && (s.back() == 'h' || s.back() == 'H'))
        s.pop_back();
    if (s.empty() || s.size() > 16)
        return false;
    uint64_t v = 0;
    for (char c : s) {
        int d = hex_digit(c);
        if (d < 0)
            return false;
        v = (v << 4) | (uint64_t)d;
    }
    out = v;
    return true;
}

// splits on any char in seps, drops empty parts
inline std::vector<std::string> split(const std::string& s, const char* seps)
{
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (strchr(seps, c)) {
            if (!cur.empty())
                out.push_back(cur);
            cur.clear();
        } else {
            cur += c;
        }
    }
    if (!cur.empty())
        out.push_back(cur);
    return out;
}

// escapes a string for display in a listing comment ("a\nb" -> a\nb)
inline std::string escape(const std::string& s, size_t max_len = 0)
{
    std::string out;
    for (size_t i = 0; i < s.size(); i++) {
        if (max_len && out.size() >= max_len) {
            out += "...";
            break;
        }
        unsigned char c = (unsigned char)s[i];
        if (c == '\n')
            out += "\\n";
        else if (c == '\r')
            out += "\\r";
        else if (c == '\t')
            out += "\\t";
        else if (c == '"')
            out += "\\\"";
        else if (c == '\\')
            out += "\\\\";
        else if (c < 32 || c == 127)
            out += fmt("\\x%02x", c);
        else
            out += (char)c;
    }
    return out;
}

inline uint32_t crc32(const uint8_t* data, size_t n)
{
    // function local static init is thread safe (loader runs on a worker thread)
    static const std::array<uint32_t, 256> table = [] {
        std::array<uint32_t, 256> t{};
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t c = i;
            for (int k = 0; k < 8; k++)
                c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            t[i] = c;
        }
        return t;
    }();
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++)
        crc = table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFu;
}

// little endian reads from a buffer, caller checks bounds
inline uint16_t rd16(const uint8_t* p) { return (uint16_t)(p[0] | (p[1] << 8)); }
inline uint32_t rd32(const uint8_t* p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
inline uint64_t rd64(const uint8_t* p) { return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32); }

// bounds checked little endian reads from a file buffer, out of range reads give 0
struct byte_reader {
    const std::vector<uint8_t>& f;
    bool ok(uint64_t off, uint64_t n) const { return off <= f.size() && n <= f.size() - off; }
    uint8_t u8(uint64_t off) const { return ok(off, 1) ? f[(size_t)off] : 0; }
    uint16_t u16(uint64_t off) const { return ok(off, 2) ? rd16(&f[(size_t)off]) : 0; }
    uint32_t u32(uint64_t off) const { return ok(off, 4) ? rd32(&f[(size_t)off]) : 0; }
    uint64_t u64(uint64_t off) const { return ok(off, 8) ? rd64(&f[(size_t)off]) : 0; }
    // nul terminated string at off, stops at the end of the buffer
    std::string cstr(uint64_t off, size_t max_len = 512) const
    {
        std::string s;
        while (ok(off, 1) && s.size() < max_len && f[(size_t)off])
            s += (char)f[(size_t)off++];
        return s;
    }
};

// base64 (standard alphabet, with padding), for the program copy inside a .ceasta database
inline std::string base64_encode(const uint8_t* data, size_t n)
{
    static const char* digits = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve((n + 2) / 3 * 4);
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = (uint32_t)data[i] << 16;
        if (i + 1 < n)
            v |= (uint32_t)data[i + 1] << 8;
        if (i + 2 < n)
            v |= data[i + 2];
        out += digits[(v >> 18) & 63];
        out += digits[(v >> 12) & 63];
        out += i + 1 < n ? digits[(v >> 6) & 63] : '=';
        out += i + 2 < n ? digits[v & 63] : '=';
    }
    return out;
}

// appends the decoded bytes; skips anything that isn't a base64 digit (line breaks). false on
// a stray character in the middle of the data
inline bool base64_decode(const std::string& in, std::vector<uint8_t>& out)
{
    uint32_t v = 0;
    int bits = 0;
    for (char c : in) {
        int d;
        if (c >= 'A' && c <= 'Z')
            d = c - 'A';
        else if (c >= 'a' && c <= 'z')
            d = c - 'a' + 26;
        else if (c >= '0' && c <= '9')
            d = c - '0' + 52;
        else if (c == '+')
            d = 62;
        else if (c == '/')
            d = 63;
        else if (c == '=' || c == '\n' || c == '\r' || c == ' ')
            continue;
        else
            return false;
        v = (v << 6) | (uint32_t)d;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back((uint8_t)(v >> bits));
        }
    }
    return true;
}

}
