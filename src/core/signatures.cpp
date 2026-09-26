#include "core/signatures.h"

#include "core/analysis.h"
#include "core/database.h"
#include "core/demangle.h"
#include "core/disasm.h"
#include "core/util.h"

#include <cctype>
#include <cstdlib>
#include <unordered_map>

namespace {

// the same "real symbol, not an auto label" test the diff uses
bool real_name(const std::string& n)
{
    if (n.empty() || n.compare(0, 4, "sub_") == 0 || n.compare(0, 4, "loc_") == 0)
        return false;
    for (char c : n)
        if (!std::isxdigit((unsigned char)c))
            return true; // has a non-hex char, so it's a real name
    return false;         // all hex: an address label
}

// a fingerprint of a function's bytes with relative branch displacements wildcarded, so the
// same code in another build (where those relative offsets differ) still matches. returns 0
// when the function can't be fingerprinted (too small / undecodable).
uint64_t fingerprint(database& db, uint64_t start, uint64_t end, uint32_t& length_out)
{
    if (end <= start || end - start > 0x8000)
        return 0;
    uint32_t len = (uint32_t)(end - start);
    std::vector<uint8_t> bytes(len);
    if (db.bin.read(start, bytes.data(), len) != len)
        return 0;
    std::vector<uint8_t> mask(len, 1); // 1 = a fixed byte, 0 = wildcard

    disassembler dis;
    if (!dis.open(db.bin.arch))
        return 0;
    uint64_t a = start;
    int guard = 0;
    while (a < end && guard++ < 100000) {
        insn in;
        if (!dis.decode(db.bin, a, in) || in.size == 0)
            break;
        db.an.resolve(in);
        // arm64 keeps branch offsets and addresses (adrp, adr, the page offset after an adrp)
        // inside the 4 byte word: wildcard all of it
        if (in.arm && (in.has_target || in.has_page || in.has_mem)) {
            size_t off = (size_t)(a - start);
            for (size_t k = 0; k < 4 && off + k < len; k++)
                mask[off + k] = 0;
        }
        // wildcard the displacement of a direct relative branch (its value is an inter-function
        // offset that changes between builds)
        else if (in.is_branch() && !in.indirect && in.has_target) {
            size_t off = (size_t)(a - start);
            if (in.size >= 5) { // rel32: the last 4 bytes
                for (int k = 0; k < 4; k++)
                    if (off + in.size - 1 - (size_t)k < len)
                        mask[off + in.size - 1 - (size_t)k] = 0;
            } else if (in.size == 2) { // rel8: the last byte
                if (off + 1 < len)
                    mask[off + 1] = 0;
            }
        }
        a += in.size;
    }

    uint64_t h = 14695981039346656037ULL;
    auto fold = [&](uint8_t b) { h ^= b; h *= 1099511628211ULL; };
    for (uint32_t i = 0; i < len; i++) {
        fold(mask[i]);
        fold(mask[i] ? bytes[i] : 0);
    }
    length_out = len;
    return h;
}

} // namespace

std::vector<signature> make_signatures(database& db)
{
    std::vector<signature> out;
    for (const function& f : db.an.funcs) {
        if (f.thunk)
            continue;
        std::string name = db.name_at(f.start);
        if (!real_name(name))
            continue;
        // a demangled name keeps its mangled spelling: one word, and it demangles again where
        // the signature names a function
        std::string raw = db.raw_name_at(f.start);
        signature s;
        s.name = raw.empty() ? name : raw;
        s.hash = fingerprint(db, f.start, f.end, s.length);
        if (s.hash && s.length >= 8) // skip tiny stubs, they collide
            out.push_back(std::move(s));
    }
    return out;
}

std::string signatures_to_text(const std::vector<signature>& sigs)
{
    std::string s = "ceasta-sig 1\n";
    for (const signature& sig : sigs)
        s += util::fmt("%016llx %u %s\n", (unsigned long long)sig.hash, sig.length, sig.name.c_str());
    return s;
}

std::vector<signature> signatures_from_text(const std::string& text)
{
    std::vector<signature> out;
    size_t pos = 0;
    bool first = true;
    while (pos < text.size()) {
        size_t nl = text.find('\n', pos);
        std::string line = text.substr(pos, nl == std::string::npos ? std::string::npos : nl - pos);
        pos = nl == std::string::npos ? text.size() : nl + 1;
        if (first) {
            first = false;
            if (line.compare(0, 10, "ceasta-sig") == 0)
                continue;
        }
        if (line.empty())
            continue;
        size_t sp1 = line.find(' ');
        size_t sp2 = sp1 == std::string::npos ? std::string::npos : line.find(' ', sp1 + 1);
        if (sp1 == std::string::npos || sp2 == std::string::npos)
            continue;
        signature s;
        s.hash = strtoull(line.substr(0, sp1).c_str(), nullptr, 16);
        s.length = (uint32_t)strtoul(line.substr(sp1 + 1, sp2 - sp1 - 1).c_str(), nullptr, 10);
        s.name = line.substr(sp2 + 1);
        if (s.hash && !s.name.empty())
            out.push_back(std::move(s));
    }
    return out;
}

std::vector<sig_match> match_signatures(database& db, const std::vector<signature>& sigs, bool apply)
{
    // index the signatures by (hash, length); drop any key that maps to more than one name, so
    // an ambiguous fingerprint never names a function
    struct entry {
        std::string name;
        bool unique = true;
    };
    std::unordered_map<uint64_t, entry> by_key;
    auto key = [](uint64_t hash, uint32_t len) { return hash ^ ((uint64_t)len << 1); };
    for (const signature& s : sigs) {
        auto it = by_key.find(key(s.hash, s.length));
        if (it == by_key.end())
            by_key[key(s.hash, s.length)] = {s.name, true};
        else if (it->second.name != s.name)
            it->second.unique = false;
    }

    std::vector<sig_match> matched;
    for (const function& f : db.an.funcs) {
        if (f.thunk)
            continue;
        std::string cur = db.name_at(f.start);
        if (real_name(cur)) // already has a real name
            continue;
        uint32_t len = 0;
        uint64_t h = fingerprint(db, f.start, f.end, len);
        if (!h || len < 8)
            continue;
        auto it = by_key.find(key(h, len));
        if (it == by_key.end() || !it->second.unique)
            continue;
        demangle::result d = demangle::run(it->second.name);
        matched.push_back({f.start, d.ok ? d.display : it->second.name});
        if (apply) {
            std::string err;
            db.set_name(f.start, it->second.name, err);
        }
    }
    return matched;
}
