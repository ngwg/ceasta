#include "core/diff.h"

#include "core/analysis.h"
#include "core/database.h"
#include "core/disasm.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <unordered_map>

namespace {

// a position-independent fingerprint of one function: a hash of its instruction stream (opcode
// + register operands, but not the immediate / address values that move between builds), plus a
// sorted list of instruction ids for a similarity estimate.
struct fingerprint {
    uint64_t addr = 0;
    uint64_t hash = 14695981039346656037ULL; // fnv-1a
    std::vector<uint16_t> ids;               // per instruction, for the changed-similarity score
    uint32_t insns = 0;

    void fold(uint64_t v)
    {
        for (int i = 0; i < 8; i++) {
            hash ^= (v >> (i * 8)) & 0xFF;
            hash *= 1099511628211ULL;
        }
    }
};

fingerprint fingerprint_of(database& db, const function& f)
{
    fingerprint fp;
    fp.addr = f.start;
    disassembler dis;
    if (!dis.open(db.bin.is64() ? bin_arch::x64 : bin_arch::x86))
        return fp;
    uint64_t a = f.start;
    int guard = 0;
    while (a < f.end && guard++ < 100000) {
        insn in;
        if (!dis.decode(db.bin, a, in) || in.size == 0)
            break;
        // opcode and register shape, not the operand values that move between builds. an
        // immediate that isn't an address is a real constant (a magic number, a struct size),
        // so fold it in - that catches a changed constant. addresses and branch targets are
        // skipped so aslr / relocation doesn't make everything look different.
        fp.fold(in.id);
        fp.fold(((uint64_t)in.reg0 << 16) | in.reg1);
        fp.fold((in.has_imm ? 1u : 0u) | (in.has_mem_op ? 2u : 0u) | ((unsigned)in.kind << 4));
        if (in.has_imm && !db.bin.is_mapped(in.imm))
            fp.fold(in.imm);
        fp.ids.push_back((uint16_t)in.id);
        fp.insns++;
        a += in.size;
    }
    std::sort(fp.ids.begin(), fp.ids.end());
    return fp;
}

// order-insensitive similarity of two instruction-id multisets: 2*common / (|a| + |b|)
double similarity(const std::vector<uint16_t>& a, const std::vector<uint16_t>& b)
{
    if (a.empty() && b.empty())
        return 1.0;
    size_t i = 0, j = 0, common = 0;
    while (i < a.size() && j < b.size()) {
        if (a[i] == b[j]) {
            common++;
            i++;
            j++;
        } else if (a[i] < b[j]) {
            i++;
        } else {
            j++;
        }
    }
    return 2.0 * (double)common / (double)(a.size() + b.size());
}

// a name worth matching by: a real symbol, not an auto sub_/loc_/address label
bool real_name(const std::string& n)
{
    if (n.empty())
        return false;
    if (n.compare(0, 4, "sub_") == 0 || n.compare(0, 4, "loc_") == 0)
        return false;
    // a bare hex address label
    bool hex = true;
    for (char c : n)
        if (!std::isxdigit((unsigned char)c))
            hex = false;
    return !hex;
}

} // namespace

diff_result diff_databases(database& a, database& b)
{
    diff_result r;
    r.funcs_a = a.an.funcs.size();
    r.funcs_b = b.an.funcs.size();

    std::vector<fingerprint> fa, fb;
    fa.reserve(a.an.funcs.size());
    fb.reserve(b.an.funcs.size());
    for (const function& f : a.an.funcs)
        fa.push_back(fingerprint_of(a, f));
    for (const function& f : b.an.funcs)
        fb.push_back(fingerprint_of(b, f));

    std::vector<char> used_a(fa.size(), 0), used_b(fb.size(), 0);

    // 1) match by name
    std::unordered_map<std::string, size_t> name_b;
    for (size_t j = 0; j < fb.size(); j++) {
        std::string n = b.name_at(fb[j].addr);
        if (real_name(n))
            name_b.emplace(n, j);
    }
    for (size_t i = 0; i < fa.size(); i++) {
        std::string n = a.name_at(fa[i].addr);
        if (!real_name(n))
            continue;
        auto it = name_b.find(n);
        if (it == name_b.end() || used_b[it->second])
            continue;
        size_t j = it->second;
        used_a[i] = used_b[j] = 1;
        diff_pair p;
        p.a = fa[i].addr;
        p.b = fb[j].addr;
        p.name = n;
        p.by_name = true;
        if (fa[i].hash == fb[j].hash) {
            p.similarity = 1.0;
            r.identical.push_back(p);
        } else {
            p.similarity = similarity(fa[i].ids, fb[j].ids);
            r.changed.push_back(p);
        }
    }

    // 2) match the rest by content hash (greedy, unique hashes first)
    std::unordered_map<uint64_t, std::vector<size_t>> hash_b;
    for (size_t j = 0; j < fb.size(); j++)
        if (!used_b[j])
            hash_b[fb[j].hash].push_back(j);
    for (size_t i = 0; i < fa.size(); i++) {
        if (used_a[i])
            continue;
        auto it = hash_b.find(fa[i].hash);
        if (it == hash_b.end())
            continue;
        size_t j = SIZE_MAX;
        for (size_t cand : it->second)
            if (!used_b[cand]) {
                j = cand;
                break;
            }
        if (j == SIZE_MAX)
            continue;
        used_a[i] = used_b[j] = 1;
        diff_pair p;
        p.a = fa[i].addr;
        p.b = fb[j].addr;
        p.name = a.name_at(fa[i].addr);
        if (p.name.empty())
            p.name = a.location(fa[i].addr);
        p.similarity = 1.0;
        r.identical.push_back(p);
    }

    // 3) whatever is left is added / removed
    for (size_t i = 0; i < fa.size(); i++)
        if (!used_a[i])
            r.removed.push_back(fa[i].addr);
    for (size_t j = 0; j < fb.size(); j++)
        if (!used_b[j])
            r.added.push_back(fb[j].addr);

    auto by_sim = [](const diff_pair& x, const diff_pair& y) { return x.similarity < y.similarity; };
    std::sort(r.changed.begin(), r.changed.end(), by_sim);
    return r;
}
