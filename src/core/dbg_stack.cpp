#include "core/dbg_stack.h"
#include "core/debugger.h"
#include "core/disasm.h"
#include <algorithm>
#include <cstring>

namespace {

struct walker {
    debugger& d;
    std::vector<dbg_region> exec; // the executable regions, by address
    disassembler dis;

    explicit walker(debugger& dbg) : d(dbg)
    {
        for (const dbg_region& r : d.regions())
            if (r.perms.size() == 3 && r.perms[2] == 'x')
                exec.push_back(r);
        dis.open(d.is64() ? bin_arch::x64 : bin_arch::x86);
    }

    bool executable(uint64_t a) const
    {
        auto it = std::upper_bound(exec.begin(), exec.end(), a, [](uint64_t v, const dbg_region& r) { return v < r.base; });
        if (it == exec.begin())
            return false;
        --it;
        return a >= it->base && a - it->base < it->size;
    }

    // the call instruction that ends right where ret points: where it is, and where it goes
    // when that's written in it
    bool call_before(uint64_t ret, uint64_t& at, bool& direct, uint64_t& target)
    {
        if (ret < 8 || !executable(ret - 1))
            return false;
        uint8_t buf[8];
        if (d.read(ret - 8, buf, sizeof(buf)) != sizeof(buf))
            return false;
        // e8 rel32, ff 15 [rip+x], ff d0 (call rax), 41 ff d0, ff 54 24 08, ff 94 24 x...
        static const int lens[] = {5, 6, 2, 3, 7, 4};
        for (int len : lens) {
            insn in;
            if (dis.decode(buf + 8 - len, (size_t)len, ret - (uint64_t)len, in) && in.size == len && in.kind == flow::call) {
                at = ret - (uint64_t)len;
                direct = in.has_target && !in.indirect;
                target = in.target;
                return true;
            }
        }
        return false;
    }

    // a direct call to a jump (a plt stub, an import thunk) lands where the jump goes
    uint64_t through_thunk(uint64_t target)
    {
        uint8_t buf[16];
        size_t n = d.read(target, buf, sizeof(buf));
        insn in;
        if (n && dis.decode(buf, n, target, in) && in.kind == flow::jump && in.has_target && !in.indirect)
            return in.target;
        return target;
    }
};

} // namespace

std::vector<stack_frame> dbg_call_stack(debugger& d, int max_frames, const std::function<uint64_t(uint64_t)>& func_start)
{
    std::vector<stack_frame> out;
    if (d.state() != dbg_state::stopped || max_frames < 1)
        return out;
    out.push_back({d.pc(), 0, 0});
    walker w(d);
    if (!w.dis.ok())
        return out;

    // the stack from sp up to the end of its region (at most 1 MB of it)
    uint64_t sp = d.sp();
    uint64_t end = sp + (1u << 20);
    for (const dbg_region& r : d.regions())
        if (sp >= r.base && sp - r.base < r.size)
            end = std::min(end, r.base + r.size);
    size_t ptr = d.is64() ? 8 : 4;
    std::vector<uint8_t> mem(end > sp ? (size_t)(end - sp) : 0);
    mem.resize(d.read(sp, mem.data(), mem.size()));
    auto func_of = [&](uint64_t a) { return func_start ? func_start(a) : 0; };

    // every value on the stack that could be a return address
    struct cand {
        uint64_t ret, slot, at, target; // target: where the call goes (through a thunk), 0 unknown
        uint64_t func;                  // the function ret is in, 0 unknown
    };
    std::vector<cand> c;
    c.push_back({out[0].pc, 0, 0, 0, func_of(out[0].pc)}); // frame 0
    for (size_t i = 0; i + ptr <= mem.size() && c.size() < 513; i += ptr) {
        uint64_t ret = 0, at = 0, target = 0;
        memcpy(&ret, mem.data() + i, ptr);
        bool direct = false;
        if (!w.call_before(ret, at, direct, target))
            continue;
        uint64_t t = direct ? w.through_thunk(target) : 0;
        c.push_back({ret, sp + i, at, t, func_of(ret)});
    }

    // the most believable chain: a call that goes to the function above it counts for it, one
    // that goes somewhere else counts against it (a leftover in a local, or a tail call), and
    // every value left out costs a little. frame 0 is always in
    const int verified = 2, mismatch = -3, skipped = -1;
    auto edge = [&](size_t i, size_t j) {
        const cand& a = c[i];
        const cand& b = c[j];
        if (!a.func || !b.target || !func_of(b.target))
            return 0; // can't tell
        return b.target == a.func ? verified : mismatch;
    };
    size_t n = c.size();
    std::vector<long> best(n, 0);
    std::vector<size_t> prev(n, 0);
    for (size_t j = 1; j < n; j++) {
        best[j] = -1000000;
        for (size_t i = 0; i < j; i++) {
            long v = best[i] + edge(i, j) + skipped * (long)(j - i - 1);
            if (v > best[j]) {
                best[j] = v;
                prev[j] = i;
            }
        }
    }
    size_t last = 0;
    long top = 0;
    for (size_t j = 1; j < n; j++) {
        long v = best[j] + skipped * (long)(n - 1 - j);
        if (v > top || last == 0) {
            top = v;
            last = j;
        }
    }
    if (n == 1)
        return out;
    std::vector<size_t> chain;
    for (size_t j = last; j != 0; j = prev[j])
        chain.push_back(j);
    for (size_t k = chain.size(); k-- > 0 && (int)out.size() < max_frames;)
        out.push_back({c[chain[k]].ret, c[chain[k]].slot, c[chain[k]].at});
    return out;
}
