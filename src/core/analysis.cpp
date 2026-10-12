#include "core/analysis.h"
#include "core/disasm.h"
#include "core/util.h"
#include <algorithm>
#include <map>
#include <set>

// ---- lookups ----

int analysis::seg_index(uint64_t a) const
{
    auto it = std::upper_bound(seg_start.begin(), seg_start.end(), a);
    if (it == seg_start.begin())
        return -1;
    size_t i = (size_t)(it - seg_start.begin()) - 1;
    if (a - seg_start[i] >= flags[i].size())
        return -1;
    return (int)i;
}

uint8_t analysis::flags_at(uint64_t a) const
{
    int i = seg_index(a);
    return i < 0 ? 0 : flags[(size_t)i][(size_t)(a - seg_start[(size_t)i])];
}

void analysis::add_flags(uint64_t a, uint8_t f)
{
    int i = seg_index(a);
    if (i >= 0)
        flags[(size_t)i][(size_t)(a - seg_start[(size_t)i])] |= f;
}

void analysis::clear_flags(uint64_t a, uint8_t f)
{
    int i = seg_index(a);
    if (i >= 0)
        flags[(size_t)i][(size_t)(a - seg_start[(size_t)i])] &= (uint8_t)~f;
}

static bool is_tail_only(uint8_t f)
{
    return (f & fl_tail) && !(f & (fl_code | fl_str | fl_data));
}

uint32_t analysis::item_size(uint64_t a) const
{
    int i = seg_index(a);
    if (i < 0)
        return 1;
    const std::vector<uint8_t>& f = flags[(size_t)i];
    size_t off = (size_t)(a - seg_start[(size_t)i]);
    size_t n = 1;
    while (off + n < f.size() && is_tail_only(f[off + n]) && n < 0x10000)
        n++;
    return (uint32_t)n;
}

uint64_t analysis::item_head(uint64_t a) const
{
    uint64_t h = a;
    for (int k = 0; k < 0x10000 && is_tail_only(flags_at(h)) && h > 0; k++)
        h--;
    return is_tail_only(flags_at(h)) ? a : h;
}

const function* analysis::func_at(uint64_t start) const
{
    auto it = std::lower_bound(funcs.begin(), funcs.end(), start,
        [](const function& f, uint64_t v) { return f.start < v; });
    return (it != funcs.end() && it->start == start) ? &*it : nullptr;
}

const function* analysis::func_containing(uint64_t a) const
{
    auto it = std::upper_bound(funcs.begin(), funcs.end(), a,
        [](uint64_t v, const function& f) { return v < f.start; });
    // a function with a chunk after another one can still contain a, look back a bit
    for (int k = 0; k < 32 && it != funcs.begin(); k++) {
        --it;
        if (a >= it->start && a < it->end)
            return &*it;
    }
    return nullptr;
}

std::pair<const xref*, const xref*> analysis::refs_to(uint64_t a) const
{
    auto r = std::equal_range(xto.begin(), xto.end(), xref{0, a, xref_type::jump},
        [](const xref& x, const xref& y) { return x.to < y.to; });
    return {xto.data() + (r.first - xto.begin()), xto.data() + (r.second - xto.begin())};
}

std::pair<const xref*, const xref*> analysis::refs_from(uint64_t a) const
{
    auto r = std::equal_range(xfrom.begin(), xfrom.end(), xref{a, 0, xref_type::jump},
        [](const xref& x, const xref& y) { return x.from < y.from; });
    return {xfrom.data() + (r.first - xfrom.begin()), xfrom.data() + (r.second - xfrom.begin())};
}

const string_item* analysis::string_at(uint64_t a) const
{
    auto it = std::lower_bound(strings.begin(), strings.end(), a,
        [](const string_item& s, uint64_t v) { return s.addr < v; });
    return (it != strings.end() && it->addr == a) ? &*it : nullptr;
}

void analysis::resolve(insn& in) const
{
    if (!in.arm)
        return;
    auto it = pc_refs.find(in.addr);
    if (it == pc_refs.end())
        return;
    in.has_mem = true;
    in.mem = it->second;
    in.is_lea = !in.has_mem_op && !in.is_branch(); // add x0, x0, #off: an address, not an access
}

int cfg::block_of(uint64_t a) const
{
    for (size_t i = 0; i < blocks.size(); i++)
        if (a >= blocks[i].start && a < blocks[i].end)
            return (int)i;
    return -1;
}

bool is_noreturn_name(const std::string& name)
{
    static const char* const names[] = {
        "exit", "_exit", "_Exit", "abort", "quick_exit", "ExitProcess", "ExitThread",
        "FreeLibraryAndExitThread", "FatalExit", "FatalAppExitA", "FatalAppExitW",
        "RtlExitUserProcess", "RtlExitUserThread", "__stack_chk_fail", "__stack_chk_fail_local",
        "__assert_fail", "__assert_rtn", "_assert", "_wassert", "__fortify_fail", "__chk_fail",
        "__libc_fatal", "longjmp", "_longjmp", "siglongjmp", "__longjmp_chk", "pthread_exit",
        "err", "errx", "verr", "verrx", "__cxa_throw", "__cxa_rethrow", "__cxa_bad_cast",
        "__cxa_bad_typeid", "__cxa_throw_bad_array_new_length", "_Unwind_Resume",
        "_CxxThrowException", "__std_terminate", "terminate", "_ZSt9terminatev",
        "__report_gsfailure", "_invalid_parameter_noinfo_noreturn", "_invoke_watson",
        "_ZSt17__throw_bad_allocv", "_ZSt20__throw_length_errorPKc", "_ZSt19__throw_logic_errorPKc",
        "_ZSt20__throw_out_of_rangePKc", "_ZSt24__throw_out_of_range_fmtPKcz",
        "_ZSt25__throw_bad_function_callv",
    };
    for (const char* n : names)
        if (name == n)
            return true;
    return false;
}

// ---- the analysis pass ----

namespace {

bool is_print(uint8_t c)
{
    return (c >= 0x20 && c < 0x7f) || c == '\t' || c == '\n' || c == '\r';
}

struct worker {
    const binary& b;
    analysis& an;
    analysis_progress* prog;
    disassembler dis;
    std::unordered_set<uint64_t> func_starts;
    // starts that only come from heuristics (pointer scans, prologues, gap sweep). a switch
    // that jumps there proves it's a case label, so these get demoted again
    std::unordered_set<uint64_t> weak_starts;
    // code heuristics found in a file that lists every function start: it joins the function
    // it's in rather than starting one
    std::vector<uint64_t> orphans;
    std::vector<uint64_t> work;
    std::vector<uint64_t> deferred;               // code pointers seen in operands
    std::vector<xref> xrefs;
    std::unordered_map<uint64_t, uint8_t> data_cand;
    std::unordered_map<uint64_t, std::string> sym_names;
    std::unordered_map<uint64_t, int> thunk_cache;
    const segment* got = nullptr;                 // .got.plt for 32 bit pic plt stubs
    uint64_t mask = 0;
    bool imm_refs = false;
    bool cancelled = false;
    bool arm = false;                             // arm64: 4 byte instructions, the a64_ state below
    bool mips = false;                            // mips32: 4 byte instructions, delay slots

    // arm64: what registers hold while walking code. kind 1: an address (adrp, adr, add),
    // kind 2: the value loaded from the address v (a pointer slot, like a got entry)
    struct a64_val {
        uint8_t reg = 0;
        uint8_t kind = 0;
        uint64_t v = 0;
        uint64_t from = 0; // the adrp that started it, 0 if none
    };
    using a64_regs = std::vector<a64_val>;
    struct a64_state {
        a64_regs regs;
        int breg = -1;        // a register the code checked is below bcount (a switch index),
        int breg2 = -1;       // and a copy of it
        uint32_t bcount = 0;
        int creg = -1;        // "cmp creg, #cimm" whose flags are still live
        uint64_t cimm = 0;
        bool empty() const { return regs.empty() && breg < 0 && breg2 < 0 && creg < 0; }
    };
    std::unordered_map<uint64_t, a64_state> a64_pending; // the state a branch target starts with

    // mips: what the general registers hold while walking code. kind 1: a constant or address
    // (lui, addiu, ori, a got entry known from the file), kind 2: loaded from the slot at v
    // (a got entry that's an import). $gp keeps its value across calls in o32 code
    struct mips_state {
        uint32_t v[32] = {};
        uint8_t k[32] = {};
        int creg = -1;     // a "slti creg, idx, cimm" bound (a switch index) still live
        uint32_t cimm = 0;
        uint8_t clob = 0;  // 1: a call's clobbers pend; 2: its delay slot has run
        bool empty() const
        {
            if (creg >= 0)
                return false;
            for (int i = 0; i < 32; i++)
                if (k[i])
                    return false;
            return true;
        }
    };
    std::unordered_map<uint64_t, mips_state> mips_pending;
    uint32_t gp_value = 0; // the $gp constant a pic elf sets up at its entry
    bool gp_known = false;

    worker(const binary& bin, analysis& out, analysis_progress* p) : b(bin), an(out), prog(p) {}

    bool stop_requested()
    {
        if (prog && prog->cancel.load())
            cancelled = true;
        return cancelled;
    }

    void progress(int pct)
    {
        if (prog)
            prog->percent.store(pct);
    }

    bool code_at(uint64_t a) const { return b.is_code(a); }

    bool range_free(uint64_t a, uint32_t n) const
    {
        for (uint32_t k = 0; k < n; k++)
            if (!an.mapped(a + k) || (an.flags_at(a + k) & (fl_code | fl_tail | fl_str | fl_data)))
                return false;
        return true;
    }

    void mark_item(uint64_t a, uint32_t n, uint8_t head)
    {
        an.add_flags(a, head);
        for (uint32_t k = 1; k < n; k++)
            an.add_flags(a + k, fl_tail);
    }

    void add_xref(uint64_t from, uint64_t to, xref_type t) { xrefs.push_back({from, to, t}); }

    void add_func(uint64_t a, bool weak = false)
    {
        if (!code_at(a) || ((arm || mips) && (a & 3)))
            return;
        if (weak && b.starts_complete && !func_starts.count(a)) {
            if (!(an.flags_at(a) & fl_code)) {
                push_code(a);
                orphans.push_back(a);
            }
            return;
        }
        if (func_starts.insert(a).second) {
            work.push_back(a);
            if (weak)
                weak_starts.insert(a);
        } else if (!weak) {
            weak_starts.erase(a); // a real call confirms it
        }
    }

    void push_code(uint64_t a)
    {
        if (code_at(a) && !((arm || mips) && (a & 3)))
            work.push_back(a);
    }

    // ---- arm64 register tracking ----

    static const a64_val* a64_get(const a64_regs& st, int r)
    {
        for (const a64_val& v : st)
            if (v.reg == r)
                return &v;
        return nullptr;
    }

    static void a64_kill(a64_regs& st, int r)
    {
        for (size_t i = 0; i < st.size(); i++)
            if (st[i].reg == r) {
                st[i] = st.back();
                st.pop_back();
                return;
            }
    }

    // a register loaded from a got slot that isn't an import: the slot holds a pointer we know
    bool got_value(uint64_t slot, uint64_t& v) const
    {
        const segment* s = b.seg_at(slot);
        bool got = s && (s->name.compare(0, 4, ".got") == 0 || s->name == "__got" || s->name == "__auth_got");
        // a raw dump has no section names: with $gp recovered, any word reachable as a signed
        // 16 bit gp offset — the form every "lw x, off($gp)" the code emits takes
        if (!got && b.format == bin_format::raw && gp_known) {
            uint32_t d = (uint32_t)(slot - gp_value);
            got = d >= (uint32_t)0xffff8000 || d < 0x8000;
        }
        return got && !an.slot_import.count(slot) && b.read_ptr(slot, v) && v && b.is_mapped(v);
    }

    // runs one instruction over the register state. what it uses (an add of a known page, a load
    // or store at a known place, a branch through a loaded slot) goes in pc_refs and in `in`
    void a64_step(a64_state& state, insn& in)
    {
        a64_regs& st = state.regs;
        uint64_t use = 0, from = 0;
        bool used = false;
        const a64_val* src = nullptr;
        if (ins::a64_add_imm(in)) {
            src = a64_get(st, regs::a64_num(in.reg1));
            if (src && src->kind == 1) {
                use = src->v + in.imm;
                used = true;
            }
        } else if (in.has_mem_op && !in.mem_index) {
            src = a64_get(st, regs::a64_num(in.mem_base));
            if (src && src->kind == 1) {
                use = src->v + (uint64_t)in.mem_disp;
                used = true;
            }
        } else if (in.indirect && in.is_branch()) {
            src = a64_get(st, regs::a64_num(in.reg0));
            if (src && src->kind == 2) {
                use = src->v;
                used = true;
            }
        }
        if (used) {
            from = src->from;
            an.pc_refs[in.addr] = use;
            if (from)
                an.page_refs.emplace(from, use);
            in.has_mem = true;
            in.mem = use;
            in.is_lea = !in.has_mem_op && !in.is_branch();
        }

        // what it leaves behind
        int dst = regs::a64_num(in.reg0);
        a64_val nv;
        bool keep = false;
        if (in.has_page) {
            nv = {(uint8_t)dst, 1, in.page, in.addr};
            keep = true;
        } else if (in.has_mem && in.is_lea) { // adr, or the add just resolved
            nv = {(uint8_t)dst, 1, in.mem, from};
            keep = true;
        } else if (in.has_mem && !in.mem_write && !in.is_branch() && in.mem_size == 8 && in.nwr >= 1 &&
                   in.wr[0] == dst) { // ldr xd, [known]: a pointer slot
            uint64_t v;
            if (got_value(in.mem, v))
                nv = {(uint8_t)dst, 1, v, 0};
            else
                nv = {(uint8_t)dst, 2, in.mem, from};
            keep = true;
        } else if (ins::a64_mov_reg(in)) {
            const a64_val* s = a64_get(st, regs::a64_num(in.reg1));
            if (s) {
                nv = *s;
                nv.reg = (uint8_t)dst;
                keep = true;
            }
        }
        if (in.kind == flow::call) {
            for (int r = 0; r <= 18; r++)
                a64_kill(st, r); // the callee may change x0..x18
            state.breg = state.breg2 = state.creg = -1;
        }
        // mov w8, w0 after the range check on w0: w8 is in range too
        int moved = ins::a64_mov_reg(in) ? regs::a64_num(in.reg1) : -1;
        int copy = moved >= 0 && (moved == state.breg || moved == state.breg2) ? dst : -1;
        for (uint8_t i = 0; i < in.nwr; i++) {
            a64_kill(st, in.wr[i]);
            if (in.wr[i] == state.breg)
                state.breg = -1;
            if (in.wr[i] == state.breg2)
                state.breg2 = -1;
            if (in.wr[i] == state.creg)
                state.creg = -1;
        }
        if (keep && dst >= 0 && dst <= 30)
            st.push_back(nv);
        if (copy >= 0) {
            if (state.breg < 0)
                state.breg = copy;
            else
                state.breg2 = copy;
        }
        if (in.sets_flags)
            state.creg = -1;
        if (ins::a64_cmp_imm(in)) {
            state.creg = regs::a64_num(in.reg0);
            state.cimm = in.imm;
        }
    }

    // the state a branch target starts with, when it's reached first from here
    void a64_hand_over(uint64_t target, const a64_state& st)
    {
        if (!st.empty() && !func_starts.count(target) && !(an.flags_at(target) & fl_code))
            a64_pending.emplace(target, st);
    }

    // ---- mips register tracking ----

    // a register read: $zero reads as the known constant 0
    static bool mips_get(const mips_state& st, int r, uint8_t& kind, uint32_t& v)
    {
        if (r == 0) {
            kind = 1;
            v = 0;
            return true;
        }
        if (r > 0 && st.k[r]) {
            kind = st.k[r];
            v = st.v[r];
            return true;
        }
        return false;
    }

    // runs one instruction over the register state. loads and stores at a known base, and
    // branches through a known register, resolve to addresses (pc_refs, in.has_mem / target)
    void mips_step(mips_state& st, insn& in)
    {
        int rd = regs::mips_num(in.reg0);
        // the call was two steps ago (its delay slot ran with pre-call state): its
        // caller-saved clobbers land here, before whatever this instruction does
        if (st.clob == 2) {
            static const int scratch[] = {2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 24, 25};
            for (int r : scratch) {
                st.k[r] = 0;
                if (st.creg == r)
                    st.creg = -1;
            }
        }
        if (st.clob)
            st.clob++;

        // read every source before anything kills it: an addiu usually writes its own source
        uint8_t kd = 0, k1 = 0, k2 = 0, kb = 0;
        uint32_t vd = 0, v1 = 0, v2 = 0, vb = 0;
        mips_get(st, rd, kd, vd);
        mips_get(st, regs::mips_num(in.reg1), k1, v1);
        mips_get(st, regs::mips_num(in.reg2), k2, v2);
        mips_get(st, regs::mips_num(in.mem_base), kb, vb);

        // memory at a known base: lw t9, got16(gp) resolves to its slot
        if (in.has_mem_op && kb == 1) {
            uint32_t use = vb + (int32_t)in.mem_disp;
            an.pc_refs[in.addr] = use;
            in.has_mem = true;
            in.mem = use;
        }
        // an indirect branch or call through a register we know: jr t9 / jalr t9
        if (in.indirect && in.is_branch() && kd) {
            an.pc_refs[in.addr] = vd;
            if (kd == 1 && !in.has_mem_op) {
                in.has_target = true;
                in.target = vd; // jr to a lui / addiu computed address
            } else if (kd == 2) {
                in.has_mem = true;
                in.mem = vd; // the got slot: imports resolve through it
            }
        }

        // kill what it writes, then remember what we can track
        for (uint8_t i = 0; i < in.nwr; i++) {
            if (in.wr[i] > 0)
                st.k[in.wr[i]] = 0;
            if (in.wr[i] == st.creg)
                st.creg = -1;
        }

        bool addr_formed = false; // an add / ori / move resolved a register to a known address
        if (ins::mips_lui(in)) {
            if (rd > 0) {
                st.k[rd] = 1;
                st.v[rd] = (uint32_t)in.imm; // decode stored it shifted left 16
            }
        } else if (ins::mips_addiu(in) && rd > 0 && k1 == 1) {
            st.k[rd] = 1;
            st.v[rd] = v1 + (uint32_t)(int32_t)in.imm;
            addr_formed = true;
        } else if (ins::mips_ori(in) && rd > 0 && k1 == 1) {
            st.k[rd] = 1;
            st.v[rd] = v1 | (uint32_t)in.imm;
            addr_formed = true;
        } else if (ins::mips_xori(in) && rd > 0 && k1 == 1) {
            st.k[rd] = 1;
            st.v[rd] = v1 ^ (uint32_t)in.imm;
            addr_formed = true;
        } else if (ins::mips_andi(in) && rd > 0 && k1 == 1) {
            st.k[rd] = 1;
            st.v[rd] = v1 & (uint32_t)in.imm;
        } else if ((ins::mips_addu(in) || ins::mips_subu(in)) && rd > 0 && k1 == 1 && k2 == 1) {
            st.k[rd] = 1;
            st.v[rd] = ins::mips_subu(in) ? v1 - v2 : v1 + v2;
            addr_formed = true;
        } else if (ins::mips_move(in) && rd > 0) {
            st.k[rd] = k1;
            st.v[rd] = v1;
            if (k1 == 1)
                addr_formed = true;
        } else if (ins::mips_lw(in) && rd > 0 && in.has_mem) {
            uint64_t ptr;
            if (got_value(in.mem, ptr)) {
                st.k[rd] = 1; // a pointer the file already knows
                st.v[rd] = (uint32_t)ptr;
            } else {
                st.k[rd] = 2; // loaded from the slot at mem (an import, usually)
                st.v[rd] = (uint32_t)in.mem;
            }
        } else if (ins::mips_slti(in)) {
            st.creg = regs::mips_num(in.reg1);
            st.cimm = (uint32_t)in.imm;
        }
        // a pair (lui %hi / addiu %lo) just computed an address: surface it like an lea
        if (addr_formed && rd > 0 && st.k[rd] == 1 && !in.has_mem) {
            an.pc_refs[in.addr] = st.v[rd];
            in.has_mem = true;
            in.mem = st.v[rd];
            in.is_lea = true;
        }
        if (in.kind == flow::call) {
            // caller saved: v0 v1, a0..a3, t0..t7, t8 t9 — but the delay slot runs first,
            // so the clobbers wait two steps. $gp and the s registers survive
            st.k[31] = 1; // ra
            st.v[31] = (uint32_t)(in.addr + 8); // delay slots: the return address is addr + 8
            st.clob = 1;
        }
        // o32: $gp is a program constant (the code reloads it from the frame after calls,
        // which only restores the same value) — whatever ran, it stays known
        if (gp_known) {
            st.k[28] = 1;
            st.v[28] = gp_value;
        }
    }

    void mips_hand_over(uint64_t target, const mips_state& st)
    {
        if (!st.empty() && !func_starts.count(target) && !(an.flags_at(target) & fl_code))
            mips_pending.emplace(target, st);
    }

    // an arm64 stub that jumps through an import slot: adrp x16, page; ldr x17, [x16, #off];
    // add x16, x16, #off; br x17 (plt), or adrp x16 / ldr x16 / br x16 (windows). the slot, or 0
    uint64_t a64_stub_slot(uint64_t a)
    {
        a64_state st;
        for (int i = 0; i < 6; i++, a += 4) {
            insn in;
            if (!dis.decode(b, a, in))
                return 0;
            if (ins::is_endbr(in) || ins::is_nop(in))
                continue;
            if (!in.has_page && !ins::a64_add_imm(in) && !ins::a64_mov_reg(in) &&
                !(in.has_mem_op && !in.mem_write && !in.mem_index) && !(in.indirect && in.kind == flow::jump))
                return 0;
            a64_step(st, in);
            if (in.kind == flow::jump)
                return in.has_mem ? in.mem : 0;
        }
        return 0;
    }

    // absolute address of a memory operand, including "jmp [ebx+x]" in 32 bit pic plt stubs
    bool mem_addr(const insn& in, uint64_t& out) const
    {
        if (in.has_mem) {
            out = in.mem;
            return true;
        }
        if (got && in.has_mem_op && regs::same_reg(in.mem_base, regs::ebx()) && in.mem_index == 0) {
            const segment* s = b.seg_at(in.addr);
            if (s && s->name.compare(0, 4, ".plt") == 0) {
                out = (got->start + (uint64_t)in.mem_disp) & 0xffffffffull;
                return true;
            }
        }
        return false;
    }

    // mips pic plt stub: lui gp, hi / lw t9, slot(gp) / addiu gp, gp, lo / jr t9 (or a t7
    // variant). the got slot it jumps through, or 0
    uint64_t mips_stub_slot(uint64_t a)
    {
        mips_state st;
        if (gp_known) {
            st.k[28] = 1;
            st.v[28] = gp_value;
        }
        for (int i = 0; i < 8; i++, a += 4) {
            insn in;
            if (!dis.decode(b, a, in) || !in.mips)
                return 0;
            bool tail = in.indirect && in.kind == flow::jump;
            mips_step(st, in);
            if (tail)
                return in.has_mem ? in.mem : 0;
            if (in.is_branch() || in.kind == flow::stop)
                return 0; // a real branch: not a stub tail
        }
        return 0;
    }

    int import_of_slot(uint64_t slot) const
    {
        auto it = an.slot_import.find(slot);
        return it == an.slot_import.end() ? -1 : (int)it->second;
    }

    // import that the code at a jumps straight to (jmp [slot], maybe after endbr), or -1
    int thunk_import_at(uint64_t a)
    {
        auto it = thunk_cache.find(a);
        if (it != thunk_cache.end())
            return it->second;
        int r = -1;
        insn in;
        if (arm) {
            uint64_t slot = a64_stub_slot(a);
            if (slot)
                r = import_of_slot(slot);
        } else if (mips) {
            uint64_t slot = mips_stub_slot(a);
            if (slot)
                r = import_of_slot(slot);
        } else if (dis.decode(b, a, in)) {
            if (ins::is_endbr(in)) {
                uint64_t n = in.next();
                if (!dis.decode(b, n, in))
                    in = insn();
            }
            uint64_t m;
            if (in.kind == flow::jump && in.indirect && mem_addr(in, m))
                r = import_of_slot(m);
        }
        thunk_cache[a] = r;
        return r;
    }

    std::string callee_name(const insn& in)
    {
        uint64_t m;
        if (in.indirect) {
            if (mem_addr(in, m)) {
                int i = import_of_slot(m);
                if (i >= 0)
                    return b.imports[(size_t)i].name;
            }
            return std::string();
        }
        if (!in.has_target)
            return std::string();
        int ti = thunk_import_at(in.target);
        if (ti >= 0)
            return b.imports[(size_t)ti].name;
        auto it = sym_names.find(in.target);
        return it == sym_names.end() ? std::string() : it->second;
    }

    void note_data(uint64_t a, uint8_t size)
    {
        if (!code_at(a))
            data_cand.emplace(a, size);
    }

    // "call $+5; pop reg" is how 32 bit code reads eip, not a call to a function. mips's
    // "bal to the delay slot or the next line" does the same with ra
    static bool get_pc_call(const insn& in)
    {
        if (in.kind != flow::call || !in.has_target)
            return false;
        if (in.mips)
            return in.target == in.next() || in.target == in.next() + 4;
        return in.target == in.next();
    }

    void refs(const insn& in)
    {
        if (in.has_target)
            add_xref(in.addr, in.target, in.kind == flow::call && !get_pc_call(in) ? xref_type::call : xref_type::jump);
        uint64_t m;
        if (mem_addr(in, m) && b.is_mapped(m)) {
            if (in.is_lea) {
                add_xref(in.addr, m, xref_type::offset);
                if (code_at(m))
                    deferred.push_back(m);
            } else {
                add_xref(in.addr, m, in.mem_write ? xref_type::write : xref_type::read);
                note_data(m, in.mem_size);
            }
        }
        if (imm_refs && in.has_imm && in.imm >= 0x10000 && b.is_mapped(in.imm)) {
            add_xref(in.addr, in.imm, xref_type::offset);
            if (code_at(in.imm) && (ins::is_push(in) || ins::is_move(in)))
                deferred.push_back(in.imm);
        }
    }

    // switch tables: jmp [idx*ps + table], or the lea/movsxd/add/jmp reg forms
    void resolve_table(const insn* hist, int nh, const insn& j)
    {
        int ps = b.ptr_size();
        uint64_t table = 0, basev = 0;
        uint32_t es = 0;
        int mode = 0; // 1 absolute pointers, 2 signed offsets from base, 3 unsigned offsets from base
        unsigned idx = 0;
        int load_pos = nh;

        if (j.has_mem_op && j.mem_base == 0 && j.mem_index != 0 && j.mem_scale == ps) {
            table = (uint64_t)j.mem_disp & mask;
            es = (uint32_t)ps;
            mode = 1;
            idx = j.mem_index;
        } else if (!j.has_mem_op && j.reg0 != 0) {
            unsigned r = j.reg0, breg = 0;
            int add_pos = -1;
            for (int i = nh - 1; i >= 0 && i >= nh - 6; i--)
                if (ins::is_add(hist[i]) && regs::same_reg(hist[i].reg0, r) && hist[i].reg1) {
                    add_pos = i;
                    breg = hist[i].reg1;
                    break;
                }
            if (add_pos < 0)
                return;
            int lp = -1;
            for (int i = add_pos - 1; i >= 0 && i >= add_pos - 6; i--) {
                const insn& h = hist[i];
                if (ins::is_move(h) && regs::same_reg(h.reg0, r) && h.has_mem_op && h.mem_scale == 4 &&
                    h.mem_index != 0 && regs::same_reg(h.mem_base, breg)) {
                    lp = i;
                    break;
                }
            }
            if (lp < 0)
                return;
            bool found = false;
            for (int i = add_pos - 1; i >= 0; i--) {
                const insn& h = hist[i];
                if (h.is_lea && regs::same_reg(h.reg0, breg) && h.has_mem && h.mem_rip) {
                    basev = h.mem;
                    found = true;
                    break;
                }
            }
            // i386 pic code keeps the got address in ebx (the abi guarantees it)
            if (!found && got && regs::same_reg(breg, regs::ebx())) {
                basev = got->start;
                found = true;
            }
            if (!found)
                return;
            const insn& ld = hist[lp];
            table = basev + (uint64_t)ld.mem_disp;
            es = 4;
            idx = ld.mem_index;
            load_pos = lp;
            mode = ins::is_movsxd(ld) ? 2 : 3;
        } else {
            return;
        }

        // case count from "cmp idx, n / ja default", following register copies back
        uint32_t count = 0;
        bool bounded = false;
        unsigned cur = idx;
        for (int i = load_pos - 1; i >= 0 && i >= load_pos - 10; i--) {
            const insn& h = hist[i];
            if (ins::is_cmp(h) && regs::same_reg(h.reg0, cur) && h.has_imm) {
                if (i + 1 < nh && (ins::is_ja(hist[i + 1]) || ins::is_jae(hist[i + 1]))) {
                    uint64_t n = h.imm + (ins::is_ja(hist[i + 1]) ? 1 : 0);
                    if (n > 0 && n <= 4096) {
                        count = (uint32_t)n;
                        bounded = true;
                    }
                }
                break;
            }
            if (ins::is_move(h) && regs::same_reg(h.reg0, cur) && h.reg1)
                cur = h.reg1;
        }

        const segment* js = b.seg_at(j.addr);
        uint32_t limit = bounded ? count : 512;
        std::vector<uint64_t> targets;
        uint32_t n = 0;
        for (; n < limit; n++) {
            uint64_t ea = table + (uint64_t)n * es;
            if (!bounded && n > 0 && (an.flags_at(ea) & (fl_code | fl_str)))
                break;
            uint64_t e;
            if (es == 8) {
                if (!b.read_u64(ea, e))
                    break;
            } else {
                uint32_t v;
                if (!b.read_u32(ea, v))
                    break;
                e = v;
            }
            uint64_t t;
            if (mode == 1)
                t = e & mask;
            else if (mode == 2)
                t = (basev + (uint64_t)(int64_t)(int32_t)(uint32_t)e) & mask;
            else
                t = (basev + e) & mask;
            if (!js || !js->contains(t))
                break;
            uint8_t tf = an.flags_at(t);
            if (is_tail_only(tf) || (tf & (fl_str | fl_data)))
                break;
            uint64_t dist = t > j.addr ? t - j.addr : j.addr - t;
            if (!bounded && dist > 0x100000)
                break;
            targets.push_back(t);
        }
        if (targets.empty())
            return;

        for (uint32_t k = 0; k < n; k++) {
            uint64_t ea = table + (uint64_t)k * es;
            if (range_free(ea, es)) {
                mark_item(ea, es, fl_data);
                an.data_sizes[ea] = (uint8_t)es;
            }
        }
        std::vector<uint64_t> cases = targets;
        std::sort(targets.begin(), targets.end());
        targets.erase(std::unique(targets.begin(), targets.end()), targets.end());
        add_xref(j.addr, table, xref_type::read);
        for (uint64_t t : targets) {
            add_xref(j.addr, t, xref_type::jump);
            push_code(t);
            if (weak_starts.erase(t))
                func_starts.erase(t);
        }
        jump_table jt;
        jt.jmp = j.addr;
        jt.table = table;
        jt.entry_size = es;
        jt.entries = n;
        jt.targets = std::move(targets);
        jt.cases = std::move(cases);
        jt.index_reg = idx;
        an.tables[j.addr] = std::move(jt);
    }

    // arm64: the instruction in hist[0..pos) that last wrote general register r, or -1
    static int a64_def(const insn* hist, int pos, int r)
    {
        for (int i = pos - 1; i >= 0; i--)
            for (uint8_t k = 0; k < hist[i].nwr; k++)
                if (hist[i].wr[k] == r)
                    return i;
        return -1;
    }

    // arm64: the address register r holds just before hist[pos], from an adrp / adr / add / mov there
    static bool a64_value(const insn* hist, int pos, int r, uint64_t& out, int depth = 0)
    {
        int d = a64_def(hist, pos, r);
        if (d < 0 || depth > 3)
            return false;
        const insn& h = hist[d];
        if (h.has_page) {
            out = h.page;
            return true;
        }
        if (h.has_mem && h.is_lea) {
            out = h.mem;
            return true;
        }
        if (ins::a64_mov_reg(h))
            return a64_value(hist, d, regs::a64_num(h.reg1), out, depth + 1);
        return false;
    }

    // what the register walk knew before a hist entry: the address in its memory base, first and
    // second source register (bits 1, 2, 4 of k), for values set before the window
    struct a64_seen {
        uint8_t k = 0;
        uint64_t v[3] = {};
    };

    static a64_seen a64_snapshot(const a64_state& st, const insn& in)
    {
        a64_seen r;
        unsigned regs3[3] = {in.mem_base, in.reg1, in.reg2};
        for (int i = 0; i < 3; i++) {
            const a64_val* v = regs3[i] ? a64_get(st.regs, regs::a64_num(regs3[i])) : nullptr;
            if (v && v->kind == 1) {
                r.k |= (uint8_t)(1 << i);
                r.v[i] = v->v;
            }
        }
        return r;
    }

    // arm64 switch: br xt, where xt = base + (extend(table[idx]) << k). gcc, clang and msvc all
    // load a small offset from a table and add it to a base label (or to the table itself)
    void resolve_table_a64(const insn* hist, const int* hbreg, const int* hbreg2, const uint32_t* hbcount,
        const a64_seen* hseen, int nh, const insn& j)
    {
        // the address register r holds before hist[pos]: from the window, else from the walk
        auto value_at = [&](int pos, int slot, int r, uint64_t& out) {
            if (a64_value(hist, pos, r, out))
                return true;
            if (a64_def(hist, pos, r) < 0 && (hseen[pos].k & (1 << slot))) {
                out = hseen[pos].v[slot];
                return true;
            }
            return false;
        };
        int ap = a64_def(hist, nh, regs::a64_num(j.reg0));
        if (ap < 0 || !ins::a64_add_reg(hist[ap]))
            return;
        const insn& add = hist[ap];
        int ra = regs::a64_num(add.reg1), rb = regs::a64_num(add.reg2);
        for (int pick = 0; pick < 2; pick++) {
            int re = pick == 0 ? rb : ra, rbase = pick == 0 ? ra : rb;
            int lp = a64_def(hist, ap, re);
            if (lp < 0)
                continue;
            const insn& ld = hist[lp];
            if (!ld.has_mem_op || !ld.mem_index || ld.mem_write || !ld.mem_size || ld.mem_size > 4 || ld.has_mem)
                continue;
            if (pick == 1 && add.ext != a64_none)
                continue; // the shifted register has to be the entry
            uint64_t table, base;
            if (!value_at(lp, 0, regs::a64_num(ld.mem_base), table))
                continue;
            if (rbase == regs::a64_num(ld.mem_base) && a64_def(hist, ap, rbase) < lp)
                base = table; // offsets from the table itself
            else if (!value_at(ap, pick == 0 ? 1 : 2, rbase, base))
                continue;

            // case count: the range check ("cmp idx, #n / b.hi default") the walk came through
            int idx = regs::a64_num(ld.mem_index);
            uint32_t count = hbreg[lp] == idx || hbreg2[lp] == idx ? hbcount[lp] : 0;
            if (!count || count > 4096)
                return; // without a bound any byte looks like a target

            uint32_t es = ld.mem_size;
            const segment* js = b.seg_at(j.addr);
            std::vector<uint64_t> targets;
            uint32_t n = 0;
            for (; n < count; n++) {
                uint8_t raw[4] = {};
                if (b.read(table + (uint64_t)n * es, raw, es) != es)
                    break;
                uint64_t u = 0;
                for (uint32_t k = 0; k < es; k++)
                    u |= (uint64_t)raw[k] << (8 * k);
                int64_t e = (int64_t)u;
                if (ld.mem_signed && es < 8 && (u >> (es * 8 - 1)) & 1)
                    e = (int64_t)(u | (~0ull << (es * 8)));
                if (pick == 0) {
                    switch (add.ext) {
                    case a64_uxtb: e = (int64_t)(uint8_t)e; break;
                    case a64_uxth: e = (int64_t)(uint16_t)e; break;
                    case a64_uxtw: e = (int64_t)(uint32_t)e; break;
                    case a64_sxtb: e = (int8_t)e; break;
                    case a64_sxth: e = (int16_t)e; break;
                    case a64_sxtw: e = (int32_t)e; break;
                    default: break;
                    }
                    e = (int64_t)((uint64_t)e << (add.shift & 63));
                }
                uint64_t t = base + (uint64_t)e;
                if (!js || !js->contains(t) || (t & 3))
                    break;
                uint8_t tf = an.flags_at(t);
                if (is_tail_only(tf) || (tf & (fl_str | fl_data)))
                    break;
                targets.push_back(t);
            }
            if (n != count || targets.empty())
                return;
            for (uint32_t k = 0; k < n; k++) {
                uint64_t ea = table + (uint64_t)k * es;
                if (range_free(ea, es)) {
                    mark_item(ea, es, fl_data);
                    an.data_sizes[ea] = (uint8_t)es;
                }
            }
            std::vector<uint64_t> cases = targets;
            std::sort(targets.begin(), targets.end());
            targets.erase(std::unique(targets.begin(), targets.end()), targets.end());
            add_xref(j.addr, table, xref_type::read);
            for (uint64_t t : targets) {
                add_xref(j.addr, t, xref_type::jump);
                push_code(t);
                if (weak_starts.erase(t))
                    func_starts.erase(t);
            }
            jump_table jt;
            jt.jmp = j.addr;
            jt.table = table;
            jt.entry_size = es;
            jt.entries = n;
            jt.targets = std::move(targets);
            jt.cases = std::move(cases);
            jt.index_reg = ld.mem_index;
            an.tables[j.addr] = std::move(jt);
            return;
        }
    }

    // mips: what the register walk knew before a hist entry
    struct mips_seen {
        uint8_t k = 0;        // bits 1, 2, 4: mem_base, reg1, reg2 known
        uint32_t v[3] = {};
        int creg = -1;        // the switch bound still live at that point
        uint32_t cimm = 0;
    };

    static mips_seen mips_snapshot(const mips_state& st, const insn& in)
    {
        mips_seen r;
        r.creg = st.creg;
        r.cimm = st.cimm;
        unsigned regs3[3] = {in.mem_base, in.reg1, in.reg2};
        for (int i = 0; i < 3; i++) {
            uint8_t kind;
            uint32_t v;
            if (mips_get(st, regs::mips_num(regs3[i]), kind, v) && kind == 1) {
                r.k |= (uint8_t)(1 << i);
                r.v[i] = v;
            }
        }
        return r;
    }

    // mips: the instruction in hist[0..pos) that last wrote general register r, or -1
    static int mips_def(const insn* hist, int pos, int r)
    {
        if (r <= 0)
            return -1;
        for (int i = pos - 1; i >= 0; i--)
            for (uint8_t k = 0; k < hist[i].nwr; k++)
                if (hist[i].wr[k] == r)
                    return i;
        return -1;
    }

    // mips switch: jr t, where t is loaded from base + idx * 4 and base is a known address
    // (lui %hi / addiu %lo pairs, a got page, gp). the entries are absolute targets, or offsets
    // a trailing addu adds to a known base
    void resolve_table_mips(const insn* hist, const mips_seen* hseen, int nh, const insn& j)
    {
        int jd = regs::mips_num(j.reg0);
        if (jd <= 0)
            return;
        int lp = mips_def(hist, nh, jd);
        if (lp < 0 || !ins::mips_lw(hist[lp]))
            return;
        const insn& ld = hist[lp];
        if (!ld.has_mem_op || ld.mem_write)
            return;

        // the lw's base register: a known constant means absolute entries only with no index —
        // a switch needs the addu of a known base with the shifted index
        int lb = regs::mips_num(ld.mem_base);
        int bp = mips_def(hist, lp, lb);
        if (bp < 0)
            return;
        const insn& ad = hist[bp];
        if (!ins::mips_addu(ad))
            return;
        int ra = regs::mips_num(ad.reg1), rb = regs::mips_num(ad.reg2);
        for (int pick = 0; pick < 2; pick++) {
            int rbase = pick == 0 ? ra : rb, rsh = pick == 0 ? rb : ra;
            if (!(hseen[bp].k & (pick == 0 ? 2 : 4)))
                continue; // the base side has to be known
            uint64_t basev = pick == 0 ? hseen[bp].v[1] : hseen[bp].v[2];
            int sp = mips_def(hist, bp, rsh);
            if (sp < 0)
                continue;
            const insn& sh = hist[sp];
            uint32_t es = 0;
            int idx = -1;
            if (ins::mips_sll(sh) && regs::mips_num(sh.reg1) > 0) {
                idx = regs::mips_num(sh.reg1);
                es = 1u << (sh.imm & 31);
            } else if (ins::mips_sllv(sh) && regs::mips_num(sh.reg1) > 0) {
                idx = regs::mips_num(sh.reg1);
                es = 4;
            }
            if (idx <= 0 || es < 1 || es > 4)
                continue;
            uint64_t table = basev + (uint64_t)ld.mem_disp;

            // case count: the slti bound on the index still live when the table was loaded
            uint32_t count = hseen[lp].creg == idx ? hseen[lp].cimm
                           : hseen[sp].creg == idx ? hseen[sp].cimm
                           : hseen[bp].creg == idx ? hseen[bp].cimm
                                                   : 0;
            if (!count || count > 4096)
                return; // without a bound any byte looks like a target

            // entries relative to a base? an addu after the lw that feeds the jr
            uint64_t relbase = 0;
            bool relative = false;
            int fp = -1;
            for (int i = lp + 1; i < nh; i++)
                if (hist[i].nwr >= 1 && hist[i].wr[0] == jd) {
                    fp = i;
                    break;
                }
            if (fp > 0 && ins::mips_addu(hist[fp])) {
                const insn& fin = hist[fp];
                for (int pick2 = 0; pick2 < 2; pick2++) {
                    int rq = regs::mips_num(pick2 == 0 ? fin.reg1 : fin.reg2);
                    int slot = rq == regs::mips_num(fin.reg1) ? 1 : rq == regs::mips_num(fin.reg2) ? 2 : 0;
                    if (slot && (hseen[fp].k & (1 << slot))) {
                        relbase = hseen[fp].v[slot];
                        relative = true;
                    }
                }
            }

            const segment* js = b.seg_at(j.addr);
            std::vector<uint64_t> targets;
            uint32_t n = 0;
            for (; n < count; n++) {
                uint32_t e = 0;
                uint8_t raw[4];
                if (b.read(table + (uint64_t)n * es, raw, es) != es)
                    break;
                for (uint32_t k = 0; k < es; k++)
                    e |= (uint32_t)raw[k] << (8 * k);
                uint64_t t = relative ? (uint32_t)(relbase + (uint32_t)(int32_t)e) : e;
                if (!js || !js->contains(t) || (t & 3))
                    break;
                uint8_t tf = an.flags_at(t);
                if (is_tail_only(tf) || (tf & (fl_str | fl_data)))
                    break;
                targets.push_back(t);
            }
            if (n != count || targets.empty())
                return;
            for (uint32_t k = 0; k < n; k++) {
                uint64_t ea = table + (uint64_t)k * es;
                if (range_free(ea, es)) {
                    mark_item(ea, es, fl_data);
                    an.data_sizes[ea] = (uint8_t)es;
                }
            }
            std::vector<uint64_t> cases = targets;
            std::sort(targets.begin(), targets.end());
            targets.erase(std::unique(targets.begin(), targets.end()), targets.end());
            add_xref(j.addr, table, xref_type::read);
            for (uint64_t t : targets) {
                add_xref(j.addr, t, xref_type::jump);
                push_code(t);
                if (weak_starts.erase(t))
                    func_starts.erase(t);
            }
            jump_table jt;
            jt.jmp = j.addr;
            jt.table = table;
            jt.entry_size = es;
            jt.entries = n;
            jt.targets = std::move(targets);
            jt.cases = std::move(cases);
            jt.index_reg = (unsigned)idx;
            an.tables[j.addr] = std::move(jt);
            return;
        }
    }

    // linear walk from a, following fall through. branch targets go on the work list
    void explore(uint64_t a)
    {
        const int hist_max = 12;
        insn hist[hist_max];
        int hbreg[hist_max];        // arm64: the range checked registers before each one
        int hbreg2[hist_max];
        uint32_t hbcount[hist_max];
        a64_seen hseen[hist_max];   // arm64: addresses its registers held
        int nh = 0;
        a64_state st;
        mips_state mst;
        mips_seen hm[hist_max];
        if (arm) {
            auto p = a64_pending.find(a);
            if (p != a64_pending.end()) {
                if (!func_starts.count(a))
                    st = std::move(p->second);
                a64_pending.erase(p);
            }
        }
        if (mips) {
            auto p = mips_pending.find(a);
            if (p != mips_pending.end()) {
                if (!func_starts.count(a))
                    mst = std::move(p->second);
                mips_pending.erase(p);
            } else if (gp_known) {
                mst.k[28] = 1; // pic: $gp is the same constant in every function
                mst.v[28] = gp_value;
            }
        }
        uint64_t first = a;
        for (;;) {
            if (!code_at(a) || (an.flags_at(a) & (fl_code | fl_tail | fl_str | fl_data)))
                return;
            insn in;
            if (!dis.decode(b, a, in) || !code_at(a + in.size - 1))
                return;
            for (uint32_t k = 1; k < in.size; k++)
                if ((an.flags_at(a + k) & (fl_code | fl_tail | fl_str | fl_data)) ||
                    (func_starts.count(a + k) && !weak_starts.count(a + k)))
                    return; // would overlap something we already know, or a function yet to explore
            mark_item(a, in.size, fl_code);
            an.insn_count++;
            if (arm && a != first) {
                if (func_starts.count(a)) {
                    st = a64_state(); // ran into the next function
                } else if (!a64_pending.empty()) {
                    // a branch target this walk reached first: a range check made on the branch's
                    // side still counts (the path falling in here is often a call that doesn't return)
                    auto p = a64_pending.find(a);
                    if (p != a64_pending.end()) {
                        if (st.breg < 0 && st.breg2 < 0 && p->second.breg >= 0) {
                            st.breg = p->second.breg;
                            st.breg2 = p->second.breg2;
                            st.bcount = p->second.bcount;
                        }
                        a64_pending.erase(p);
                    }
                }
            }
            if (mips && a != first) {
                if (func_starts.count(a)) {
                    mst = mips_state(); // ran into the next function
                    if (gp_known) {
                        mst.k[28] = 1;
                        mst.v[28] = gp_value;
                    }
                } else {
                    auto p = mips_pending.find(a);
                    if (p != mips_pending.end()) {
                        if (mst.empty())
                            mst = p->second;
                        mips_pending.erase(p);
                    }
                }
            }
            int pre_breg = st.breg, pre_breg2 = st.breg2;
            uint32_t pre_bcount = st.bcount;
            a64_seen pre_seen;
            mips_seen pre_m;
            if (arm) {
                pre_seen = a64_snapshot(st, in);
                a64_step(st, in);
            }
            if (mips) {
                pre_m = mips_snapshot(mst, in);
                mips_step(mst, in);
            }
            refs(in);

            bool stop = false;
            switch (in.kind) {
            case flow::jump:
                if (in.has_target) {
                    if (arm)
                        a64_hand_over(in.target, st);
                    if (mips)
                        mips_hand_over(in.target, mst);
                    if (thunk_import_at(in.target) >= 0)
                        add_func(in.target); // a tail call to an import stub
                    else
                        push_code(in.target);
                } else if (mips && in.has_mem) {
                    // a jr through a got slot with no import behind it: in a raw dump the
                    // file's own pointer is the tail target (an elf resolves it as an import)
                    uint64_t ptr;
                    if (got_value(in.mem, ptr) && b.is_mapped(ptr))
                        push_code(ptr);
                } else if (arm) {
                    resolve_table_a64(hist, hbreg, hbreg2, hbcount, hseen, nh, in);
                    auto t = an.tables.find(in.addr);
                    if (t != an.tables.end())
                        for (uint64_t x : t->second.targets)
                            a64_hand_over(x, st);
                } else if (mips) {
                    resolve_table_mips(hist, hm, nh, in);
                    auto t = an.tables.find(in.addr);
                    if (t != an.tables.end())
                        for (uint64_t x : t->second.targets)
                            mips_hand_over(x, mst);
                } else {
                    resolve_table(hist, nh, in);
                }
                stop = true;
                break;
            case flow::cond:
                if (in.has_target) {
                    if (arm) {
                        // a range check: below the bound on one side (the switch), default on the other
                        a64_state taken = st;
                        if ((ins::a64_bls(in) || ins::a64_blo(in)) && st.creg >= 0) {
                            taken.breg = st.creg;
                            taken.breg2 = -1;
                            taken.bcount = (uint32_t)std::min<uint64_t>(st.cimm + (ins::a64_bls(in) ? 1 : 0), 1u << 20);
                        }
                        a64_hand_over(in.target, taken);
                        if ((ins::a64_bhi(in) || ins::a64_bhs(in)) && st.creg >= 0) {
                            st.breg = st.creg;
                            st.breg2 = -1;
                            st.bcount = (uint32_t)std::min<uint64_t>(st.cimm + (ins::a64_bhi(in) ? 1 : 0), 1u << 20);
                        }
                    }
                    if (mips)
                        mips_hand_over(in.target, mst);
                    push_code(in.target);
                }
                break;
            case flow::call:
                if (in.has_target && !get_pc_call(in))
                    add_func(in.target);
                else if (mips && in.indirect) {
                    // pic call "lw t9, off(gp); jalr t9": mips_step records the slot in
                    // in.mem. in a raw dump that slot's file value is the only way to reach
                    // the callee — an elf would stop at the import boundary, this blob has none
                    uint64_t ptr;
                    if (in.has_mem && got_value(in.mem, ptr) && b.is_mapped(ptr))
                        add_func(ptr);
                }
                if (is_noreturn_name(callee_name(in))) {
                    an.noret_calls.insert(in.addr);
                    stop = true;
                }
                break;
            case flow::ret:
            case flow::stop:
                stop = true;
                break;
            default:
                break;
            }
            if (stop) {
                // mips: the instruction in a taken branch's delay slot runs before the branch
                // takes effect, so it's code this walk would otherwise never reach
                if (mips && (in.kind == flow::jump || in.kind == flow::ret || in.kind == flow::call))
                    mark_delay_slot(in.next());
                return;
            }
            if (nh == hist_max) {
                for (int i = 1; i < hist_max; i++) {
                    hist[i - 1] = hist[i];
                    hbreg[i - 1] = hbreg[i];
                    hbreg2[i - 1] = hbreg2[i];
                    hbcount[i - 1] = hbcount[i];
                    hseen[i - 1] = hseen[i];
                    hm[i - 1] = hm[i];
                }
                nh--;
            }
            hbreg[nh] = pre_breg;
            hbreg2[nh] = pre_breg2;
            hbcount[nh] = pre_bcount;
            hseen[nh] = pre_seen;
            hm[nh] = pre_m;
            hist[nh++] = in;
            a = in.next();
        }
    }

    // mips delay slot: decode and mark one instruction without following it
    void mark_delay_slot(uint64_t a)
    {
        if (!code_at(a) || (an.flags_at(a) & (fl_code | fl_tail | fl_str | fl_data)) || (a & 3))
            return;
        insn in;
        if (!dis.decode(b, a, in) || !code_at(a + in.size - 1))
            return;
        for (uint32_t k = 1; k < in.size; k++)
            if (an.flags_at(a + k) & (fl_code | fl_tail | fl_str | fl_data))
                return;
        mark_item(a, in.size, fl_code);
        an.insn_count++;
        refs(in);
    }

    void run_work()
    {
        size_t n = 0;
        while (!work.empty()) {
            if ((++n & 1023) == 0 && stop_requested())
                return;
            uint64_t a = work.back();
            work.pop_back();
            explore(a);
        }
    }

    // strong function start patterns. -1 is a wildcard byte
    bool prologue_at(const uint8_t* d, size_t avail, bool wide) const
    {
        static const int p64[][8] = {
            {0x55, 0x48, 0x89, 0xe5, -2},             // push rbp; mov rbp, rsp
            {0x55, 0x48, 0x8b, 0xec, -2},             // same, other encoding
            {0xf3, 0x0f, 0x1e, 0xfa, -2},             // endbr64
            {0x48, 0x89, 0x5c, 0x24, -1, -2},         // mov [rsp+x], rbx
            {0x48, 0x89, 0x4c, 0x24, 0x08, -2},       // mov [rsp+8], rcx
            {0x48, 0x89, 0x54, 0x24, 0x10, -2},       // mov [rsp+10h], rdx
            {0x4c, 0x89, 0x44, 0x24, 0x18, -2},       // mov [rsp+18h], r8
            {0x48, 0x83, 0xec, -1, -2},               // sub rsp, imm8
            {0x48, 0x81, 0xec, -1, -1, 0x00, 0x00, -2}, // sub rsp, imm32
            {0x40, 0x53, 0x48, 0x83, 0xec, -2},       // push rbx; sub rsp, x
        };
        static const int p32[][8] = {
            {0x55, 0x8b, 0xec, -2},                   // push ebp; mov ebp, esp
            {0x55, 0x89, 0xe5, -2},                   // same, gcc encoding
            {0x8b, 0xff, 0x55, 0x8b, 0xec, -2},       // mov edi, edi (hot patch) + frame
            {0xf3, 0x0f, 0x1e, 0xfb, -2},             // endbr32
        };
        auto match = [&](const int* p) {
            for (size_t i = 0; p[i] != -2; i++)
                if (i >= avail || (p[i] >= 0 && d[i] != (uint8_t)p[i]))
                    return false;
            return true;
        };
        if (wide) {
            for (const auto& p : p64)
                if (match(p))
                    return true;
        } else {
            for (const auto& p : p32)
                if (match(p))
                    return true;
        }
        return false;
    }

    bool prologue_at(uint64_t a) const
    {
        uint8_t buf[8];
        size_t n = b.read(a, buf, sizeof(buf));
        if (arm)
            return n >= 4 && !(a & 3) && ins::a64_prologue(util::rd32(buf));
        return n && prologue_at(buf, n, b.is64());
    }

    // unreached functions: a strong prologue right after padding / other code
    void scan_prologues()
    {
        for (size_t si = 0; si < b.segments.size(); si++) {
            const segment& s = b.segments[si];
            if (!s.exec())
                continue;
            const std::vector<uint8_t>& d = s.data;
            const std::vector<uint8_t>& fl = an.flags[si];
            if (arm) {
                for (size_t off = (size_t)((4 - (s.start & 3)) & 3); off + 4 <= d.size(); off += 4) {
                    if (fl[off] || !ins::a64_prologue(util::rd32(&d[off])))
                        continue;
                    if (off >= 4 && !fl[off - 4] && !ins::a64_gap_before(util::rd32(&d[off - 4])))
                        continue;
                    add_func(s.start + off, true);
                }
                continue;
            }
            if (mips) {
                for (size_t off = (size_t)((4 - (s.start & 3)) & 3); off + 4 <= d.size(); off += 4) {
                    if (fl[off] || !ins::mips_prologue(util::rd32(&d[off])))
                        continue;
                    if (off >= 4 && !fl[off - 4] && !ins::mips_gap_before(util::rd32(&d[off - 4])))
                        continue;
                    add_func(s.start + off, true);
                }
                continue;
            }
            for (size_t off = 0; off < d.size(); off++) {
                if (fl[off])
                    continue;
                if (off > 0 && !fl[off - 1]) {
                    uint8_t prev = d[off - 1];
                    if (prev != 0xcc && prev != 0x90 && prev != 0x00 && prev != 0xc3)
                        continue;
                }
                if (prologue_at(&d[off], d.size() - off, b.is64()))
                    add_func(s.start + off, true);
            }
        }
    }

    // relocations tell us exactly which data holds pointers: typed items, and
    // function starts when they point at code (vtables, callback and init tables)
    void scan_reloc_ptrs()
    {
        int ps = b.ptr_size();
        for (uint64_t loc : b.ptr_locs) {
            if (code_at(loc))
                continue;
            uint64_t v;
            if (!b.read_ptr(loc, v) || !v || !b.is_mapped(v))
                continue;
            if (range_free(loc, (uint32_t)ps)) {
                mark_item(loc, (uint32_t)ps, fl_data);
                an.data_sizes[loc] = (uint8_t)ps;
            }
            add_xref(loc, v, xref_type::offset);
            if (code_at(v))
                deferred.push_back(v);
        }
    }

    // no relocations (non pie elf, stripped pe): aligned pointers into code that land on a
    // known function or a strong prologue
    void scan_data_ptrs()
    {
        if (!b.ptr_locs.empty() || b.format == bin_format::raw)
            return;
        int ps = b.ptr_size();
        for (size_t si = 0; si < b.segments.size(); si++) {
            const segment& s = b.segments[si];
            if (s.exec() || s.file_size == 0)
                continue;
            uint64_t first = (s.start + ps - 1) / ps * ps;
            for (uint64_t loc = first; loc + ps <= s.start + std::min(s.file_size, s.size()); loc += ps) {
                uint64_t v;
                if (!b.read_ptr(loc, v) || !code_at(v))
                    continue;
                if (!func_starts.count(v) && !prologue_at(v))
                    continue;
                if (range_free(loc, (uint32_t)ps)) {
                    mark_item(loc, (uint32_t)ps, fl_data);
                    an.data_sizes[loc] = (uint8_t)ps;
                }
                add_xref(loc, v, xref_type::offset);
                deferred.push_back(v);
            }
        }
    }

    uint64_t skip_padding(uint64_t p, uint64_t lim)
    {
        if (arm || mips) {
            p = (p + 3) & ~3ull;
            uint32_t w;
            while (p + 4 <= lim && b.read_u32(p, w) &&
                   (w == 0 || (arm && w == 0xd503201f))) // zeros, nop (arm also: nop hint)
                p += 4;
            return std::min(p, lim);
        }
        while (p < lim) {
            uint8_t c;
            if (!b.read_u8(p, c))
                return lim;
            if (c == 0xcc || c == 0x90 || c == 0x00) {
                p++;
                continue;
            }
            insn in;
            if (dis.decode(b, p, in) && ins::is_nop(in) && p + in.size <= lim) {
                p += in.size;
                continue;
            }
            break;
        }
        return p;
    }

    // decodes linearly from a. real code decodes cleanly up to a ret / jmp, or for a good while
    bool plausible_code(uint64_t a, uint64_t lim)
    {
        insn in;
        int zero_ops = 0;
        for (int i = 0; i < 256; i++) {
            if (a >= lim || !dis.decode(b, a, in) || a + in.size > lim)
                return false;
            if (ins::is_suspicious(in) || in.kind == flow::stop)
                return false;
            if (!arm && !mips && in.size >= 2 && in.bytes[0] == 0 && in.bytes[1] == 0 && ++zero_ops >= 2)
                return false; // runs of "add [rax], al" are zeros, not code
            if (!arm && !mips && i == 0 && in.bytes[0] == 0)
                return false;
            if (in.kind == flow::ret || in.kind == flow::jump)
                return i >= 1;
            a = in.next();
        }
        return true;
    }

    // code nobody points at: after each piece of known code, skip padding and try again
    void sweep_gaps()
    {
        for (int pass = 0; pass < 64 && !cancelled; pass++) {
            bool found = false;
            for (size_t si = 0; si < b.segments.size(); si++) {
                const segment& s = b.segments[si];
                if (!s.exec())
                    continue;
                const std::vector<uint8_t>& fl = an.flags[si];
                size_t off = 0, size = fl.size();
                while (off < size) {
                    if (fl[off]) {
                        off++;
                        continue;
                    }
                    size_t run_end = off;
                    while (run_end < size && !fl[run_end])
                        run_end++;
                    bool after_code = off == 0 || ((fl[off - 1] & (fl_code | fl_tail)) && !(fl[off - 1] & (fl_str | fl_data)));
                    if (after_code) {
                        uint64_t lim = s.start + run_end;
                        uint64_t p = skip_padding(s.start + off, lim);
                        if (p < lim && plausible_code(p, lim)) {
                            add_func(p, true);
                            run_work();
                            found = true;
                        }
                    }
                    off = run_end;
                }
            }
            if (!found)
                break;
        }
    }

    // alignment padding between functions shows as nop / int3 instead of raw bytes
    void mark_padding()
    {
        for (size_t si = 0; si < b.segments.size(); si++) {
            const segment& s = b.segments[si];
            if (!s.exec())
                continue;
            std::vector<uint8_t>& fl = an.flags[si];
            size_t off = 0, size = fl.size();
            while (off < size) {
                if (fl[off]) {
                    off++;
                    continue;
                }
                size_t run_end = off;
                while (run_end < size && !fl[run_end])
                    run_end++;
                if (off > 0 && (fl[off - 1] & (fl_code | fl_tail))) {
                    uint64_t p = s.start + off, lim = s.start + run_end;
                    std::vector<std::pair<uint64_t, uint8_t>> pads;
                    insn in;
                    while (p < lim && dis.decode(b, p, in) && p + in.size <= lim &&
                           (ins::is_nop(in) || (!arm && in.size == 1 && in.bytes[0] == 0xcc))) {
                        pads.push_back({p, in.size});
                        p += in.size;
                    }
                    if (p == lim)
                        for (const auto& pd : pads)
                            mark_item(pd.first, pd.second, fl_code);
                }
                off = run_end;
            }
        }
    }

    void build_functions()
    {
        std::vector<uint64_t> starts(func_starts.begin(), func_starts.end());
        std::sort(starts.begin(), starts.end());
        std::sort(orphans.begin(), orphans.end());
        an.funcs.reserve(starts.size());
        size_t done = 0;
        for (size_t si = 0; si < starts.size(); si++) {
            uint64_t s = starts[si];
            if ((++done & 255) == 0) {
                if (stop_requested())
                    return;
                progress(60 + (int)(25 * done / starts.size()));
            }
            if (!(an.flags_at(s) & fl_code))
                continue;
            function f;
            f.start = s;
            f.end = s;
            std::vector<uint64_t> stack{s};
            // the function's landing pads, reached through the unwinder rather than a jump
            auto pads = std::equal_range(b.landing_pads.begin(), b.landing_pads.end(), std::make_pair(s, (uint64_t)0),
                [](const std::pair<uint64_t, uint64_t>& x, const std::pair<uint64_t, uint64_t>& y) { return x.first < y.first; });
            for (auto it = pads.first; it != pads.second; ++it)
                stack.push_back(it->second);
            // orphan code up to the next function, in the same section
            if (!orphans.empty()) {
                uint64_t next = si + 1 < starts.size() ? starts[si + 1] : ~0ull;
                const segment* seg = b.seg_at(s);
                for (auto it = std::lower_bound(orphans.begin(), orphans.end(), s); it != orphans.end() && *it < next; ++it)
                    if (b.seg_at(*it) == seg)
                        stack.push_back(*it);
            }
            std::unordered_set<uint64_t> seen;
            while (!stack.empty() && seen.size() < 200000) {
                uint64_t a = stack.back();
                stack.pop_back();
                for (;;) {
                    if (seen.count(a) || !(an.flags_at(a) & fl_code) || (a != s && func_starts.count(a)))
                        break;
                    insn in;
                    if (!dis.decode(b, a, in))
                        break;
                    seen.insert(a);
                    f.insns++;
                    f.end = std::max(f.end, in.next());
                    bool stop = false;
                    if (in.kind == flow::jump) {
                        if (in.has_target) {
                            stack.push_back(in.target);
                        } else {
                            auto t = an.tables.find(a);
                            if (t != an.tables.end())
                                for (uint64_t x : t->second.targets)
                                    stack.push_back(x);
                        }
                        stop = true;
                    } else if (in.kind == flow::cond) {
                        if (in.has_target)
                            stack.push_back(in.target);
                    } else if (in.kind == flow::call) {
                        stop = an.noret_calls.count(a) != 0;
                    } else if (in.kind == flow::ret || in.kind == flow::stop) {
                        stop = true;
                    }
                    if (stop)
                        break;
                    a = in.next();
                }
            }

            // thunk: the whole body is one jump (after an optional endbr)
            insn first;
            uint64_t fa = s;
            uint64_t slot = arm && f.insns <= 6 ? a64_stub_slot(s)
                          : mips && f.insns <= 6 ? mips_stub_slot(s)
                                                 : 0;
            if (slot && import_of_slot(slot) >= 0) {
                f.thunk = true;
                f.thunk_target = slot;
                an.thunk_import[s] = (uint32_t)import_of_slot(slot);
            } else if (dis.decode(b, fa, first) && ins::is_endbr(first)) {
                fa = first.next();
                if (!dis.decode(b, fa, first))
                    first = insn();
            }
            if (!slot && first.kind == flow::jump && f.insns <= 2) {
                uint64_t m;
                if (first.indirect && mem_addr(first, m)) {
                    int imp = import_of_slot(m);
                    if (imp >= 0) {
                        f.thunk = true;
                        f.thunk_target = m;
                        an.thunk_import[s] = (uint32_t)imp;
                    }
                } else if (first.has_target && first.target != s) {
                    f.thunk = true;
                    f.thunk_target = first.target;
                }
            }
            an.add_flags(s, fl_func);
            an.funcs.push_back(f);
        }
    }

    void scan_strings()
    {
        std::unordered_set<uint64_t> reffed;
        for (const xref& x : xrefs)
            reffed.insert(x.to);
        for (size_t si = 0; si < b.segments.size(); si++) {
            const segment& seg = b.segments[si];
            const std::vector<uint8_t>& d = seg.data;
            std::vector<uint8_t>& fl = an.flags[si];
            size_t i = 0;
            while (i < d.size() && an.strings.size() < 500000) {
                if (fl[i]) {
                    i++;
                    continue;
                }
                uint64_t a = seg.start + i;
                bool refd = reffed.count(a) != 0;
                // a raw dump has no sections, so "executable" says nothing: scan it like data
                if (seg.exec() && b.format != bin_format::raw && !refd) {
                    i++;
                    continue;
                }
                // utf-16le made of ascii characters
                size_t wl = 0;
                while (i + wl * 2 + 1 < d.size() && is_print(d[i + wl * 2]) && d[i + wl * 2 + 1] == 0 &&
                       !fl[i + wl * 2] && !fl[i + wl * 2 + 1])
                    wl++;
                size_t wend = i + wl * 2;
                if (wl >= (refd ? 3u : 5u) && wend + 1 < d.size() && d[wend] == 0 && d[wend + 1] == 0 && !fl[wend] && !fl[wend + 1]) {
                    string_item s;
                    s.addr = a;
                    s.len = (uint32_t)(wl * 2 + 2);
                    s.wide = true;
                    for (size_t k = 0; k < wl; k++)
                        s.text += (char)d[i + k * 2];
                    mark_item(a, s.len, fl_str);
                    an.strings.push_back(std::move(s));
                    i += wl * 2 + 2;
                    continue;
                }
                size_t n = 0;
                while (i + n < d.size() && is_print(d[i + n]) && !fl[i + n])
                    n++;
                if (n >= (refd ? 2u : 5u) && i + n < d.size() && d[i + n] == 0 && !fl[i + n]) {
                    string_item s;
                    s.addr = a;
                    s.len = (uint32_t)(n + 1);
                    s.text.assign((const char*)&d[i], n);
                    mark_item(a, s.len, fl_str);
                    an.strings.push_back(std::move(s));
                    i += n + 1;
                    continue;
                }
                i += std::max<size_t>(n, 1);
            }
        }
        std::sort(an.strings.begin(), an.strings.end(),
            [](const string_item& x, const string_item& y) { return x.addr < y.addr; });
    }

    void mark_data()
    {
        std::vector<std::pair<uint64_t, uint8_t>> cands(data_cand.begin(), data_cand.end());
        std::sort(cands.begin(), cands.end());
        for (const auto& c : cands) {
            uint8_t sz = c.second;
            if (sz != 1 && sz != 2 && sz != 4 && sz != 8 && sz != 16)
                continue;
            if (range_free(c.first, sz)) {
                mark_item(c.first, sz, fl_data);
                an.data_sizes[c.first] = sz;
            }
        }
    }

    bool run()
    {
        mask = b.is64() ? ~0ull : 0xffffffffull;
        arm = b.arch == bin_arch::arm64;
        mips = b.arch == bin_arch::mips;
        imm_refs = (b.format == bin_format::pe || b.format == bin_format::elf || b.format == bin_format::macho) &&
                   b.base >= 0x10000;
        // an architecture the listing can't decode yet: every decode fails and the passes
        // below just find no code — the file still opens as data and strings
        dis.open(b.arch);
        an = analysis();
        for (const segment& s : b.segments) {
            an.seg_start.push_back(s.start);
            an.flags.emplace_back((size_t)s.size(), (uint8_t)0);
            if (!b.is64() && (s.name == ".got.plt" || (!got && s.name == ".got")))
                got = &s;
        }

        int ps = b.ptr_size();
        if (mips && b.mips_gp) {
            // the loader answered (the raw blob ran the prologue vote): trust it
            gp_value = (uint32_t)b.mips_gp;
            gp_known = true;
        } else if (mips) {
            // no loader answer: read the lui / addiu pair at the entry, where the c runtime
            // sets $gp up
            mips_state st0;
            uint64_t a = b.entry;
            for (int i = 0; i < 64; i++, a += 4) {
                insn in;
                if (!dis.decode(b, a, in) || !in.mips || in.is_branch())
                    break;
                if (ins::mips_lui(in) && regs::mips_num(in.reg0) == 28 && in.has_imm) {
                    st0.k[28] = 1;
                    st0.v[28] = (uint32_t)in.imm;
                } else if (ins::mips_addiu(in) && regs::mips_num(in.reg0) == 28 &&
                           regs::mips_num(in.reg1) == 28 && in.has_imm && st0.k[28] == 1) {
                    gp_value = st0.v[28] + (uint32_t)(int32_t)in.imm;
                    gp_known = true;
                    break;
                } else if (in.nwr >= 1 && in.wr[0] == 28) {
                    break; // gp written by something we don't track
                }
            }
        }
        for (size_t i = 0; i < b.imports.size(); i++) {
            uint64_t slot = b.imports[i].slot;
            an.slot_import.emplace(slot, (uint32_t)i);
            if (range_free(slot, (uint32_t)ps)) {
                mark_item(slot, (uint32_t)ps, fl_data);
                an.data_sizes[slot] = (uint8_t)ps;
            }
        }
        if (mips && gp_known && b.format == bin_format::raw) {
            // no imports section: read the pointer table at $gp - 0x7ff0 ourselves, the same
            // addresses an "lw x, off(gp)" would touch. marking them data lets a jr through a
            // slot resolve to the function it points at. the window can hold null entries and
            // slots pointing past the dump (bss, ram), so skip rather than stop at the first
            uint32_t gp_base = gp_value - 0x7ff0;
            for (uint32_t off = 0; off < 0x10000; off += 4) {
                uint64_t slot = (gp_base + off) & mask;
                uint64_t ptr;
                if (!b.is_mapped(slot) || !b.read_ptr(slot, ptr) || !ptr || !b.is_mapped(ptr))
                    continue; // padding, or a slot the runtime linker would fill
                if (range_free(slot, (uint32_t)ps)) {
                    mark_item(slot, (uint32_t)ps, fl_data);
                    an.data_sizes[slot] = (uint8_t)ps;
                }
            }
        }
        for (const symbol_entry& s : b.symbols)
            if (s.func)
                sym_names.emplace(s.addr, s.name);
        for (const export_entry& e : b.exports)
            if (e.addr)
                sym_names.emplace(e.addr, e.name);

        progress(2);
        if (b.has_entry)
            add_func(b.entry);
        for (uint64_t h : b.func_hints)
            add_func(h);
        for (const export_entry& e : b.exports)
            if (e.addr)
                add_func(e.addr);
        // landing pads are code, but part of their function: no starts of their own
        for (const auto& lp : b.landing_pads)
            push_code(lp.second);
        run_work();
        if (cancelled)
            return false;
        progress(35);
        scan_reloc_ptrs();
        scan_data_ptrs();

        // code pointers (relocations, lea / push offset) to code nobody reached yet
        for (size_t i = 0; i < deferred.size(); i++) {
            uint64_t c = deferred[i];
            if (an.flags_at(c) == 0 && code_at(c)) {
                add_func(c, true);
                run_work();
                if (cancelled)
                    return false;
            }
        }
        progress(45);
        scan_prologues();
        run_work();
        if (cancelled)
            return false;
        progress(50);
        sweep_gaps();
        if (cancelled)
            return false;
        mark_padding();
        progress(60);

        build_functions();
        if (cancelled)
            return false;
        progress(85);
        scan_strings();
        mark_data();
        progress(92);

        std::sort(xrefs.begin(), xrefs.end(), [](const xref& x, const xref& y) {
            if (x.to != y.to)
                return x.to < y.to;
            if (x.from != y.from)
                return x.from < y.from;
            return x.type < y.type;
        });
        xrefs.erase(std::unique(xrefs.begin(), xrefs.end(), [](const xref& x, const xref& y) {
            return x.to == y.to && x.from == y.from && x.type == y.type;
        }), xrefs.end());
        an.xto = xrefs;
        an.xfrom = std::move(xrefs);
        std::stable_sort(an.xfrom.begin(), an.xfrom.end(), [](const xref& x, const xref& y) {
            return x.from != y.from ? x.from < y.from : x.to < y.to;
        });
        for (const xref& x : an.xto) {
            uint8_t f = an.flags_at(x.to);
            if (an.mapped(x.to) && !is_tail_only(f))
                an.add_flags(x.to, fl_label);
        }
        progress(100);
        return true;
    }
};

}

// ---- mips pic detection for raw blobs ----

// read one aligned mips32 word
static uint32_t mips_word(const std::vector<uint8_t>& d, size_t off)
{
    return (uint32_t)d[off] | ((uint32_t)d[off + 1] << 8) | ((uint32_t)d[off + 2] << 16) |
        ((uint32_t)d[off + 3] << 24);
}

// what a function start looks like for $gp purposes, one of:
// 0 unknown, 1 "bal +8; .word gp; lw $gp,($ra)" (self-relative literal pool: the word the
// bal's ra lands on holds the absolute gp value), 2 "lui $gp, hi" (classic, needs the %lo
// addiu which may be far away), 3 "lui $gp, hi; addiu $gp, $gp, lo" (a complete pair)
static int mips_prologue_kind(const std::vector<uint8_t>& d, size_t i, size_t words, uint32_t& hi)
{
    if (i + 4 > words)
        return 0;
    uint32_t w0 = mips_word(d, i * 4);
    if (w0 == 0x04110002) { // bal with a +8 branch offset: ra = the next instruction
        if (mips_word(d, i * 4 + 12) == 0x8ffc0000) { // lw $gp, 0($ra)
            hi = mips_word(d, i * 4 + 8); // the word ra points at IS the gp value
            return 1;
        }
        return 0;
    }
    if ((w0 & 0xffe00000) == 0x3c000000 && ((w0 >> 16) & 0x1f) == 28) { // lui $gp, imm
        hi = (uint32_t)(w0 & 0xffff) << 16;
        if (i + 2 <= words) {
            uint32_t w1 = mips_word(d, i * 4 + 4);
            if ((w1 & 0xffe00000) == 0x27000000 && ((w1 >> 16) & 0x1f) == 28 &&
                ((w1 >> 21) & 0x1f) == 28) // addiu $gp, $gp, lo
                return 3;
        }
        return 2;
    }
    return 0;
}

// how many words in [lo, lo + 0x10000) read as pointers into the image itself. a real
// gp-anchored table is dense with them; a wrong guess lands in code or padding
static int pointer_window_score(const std::vector<uint8_t>& d, uint64_t base, uint32_t lo)
{
    if (base > lo || lo - base + 0x10000 > d.size())
        return 0;
    size_t start = (size_t)(lo - base);
    int n = 0;
    for (uint32_t off = 0; off < 0x10000 && start + off + 4 <= d.size(); off += 4) {
        uint32_t w = mips_word(d, start + off);
        if (w >= (uint32_t)base && w - (uint32_t)base < d.size())
            n++;
    }
    return n;
}

mips_pic detect_mips_pic(const std::vector<uint8_t>& blob, uint64_t base)
{
    mips_pic r;
    if (blob.size() < 64)
        return r;
    std::map<uint32_t, int> votes1, votes2, votes3;
    size_t words = blob.size() / 4;
    for (size_t i = 0; i + 1 < words; i++) {
        uint32_t hi = 0;
        int k = mips_prologue_kind(blob, i, words, hi);
        if (k == 1)
            votes1[hi]++;
        else if (k == 2)
            votes2[hi]++;
        else if (k == 3)
            votes3[hi]++;
    }
    // a bal-stub vote is a four-word fingerprint (branch, pointer literal, gp load): one hit
    // settles it. a lui/addiu pair is exact too. a lone lui high is common in data, so it only
    // counts with several votes and a pointer-dense 64k window where the table would live
    for (const std::map<uint32_t, int>* vs : {&votes1, &votes3}) {
        for (const auto& v : *vs) {
            if (v.second) {
                r.found = true;
                r.gp = v.first;
                r.votes = v.second;
                return r;
            }
        }
    }
    uint32_t best = 0;
    int bestn = 0, bestscore = 0;
    for (const auto& v : votes2) {
        if (v.second < 3)
            continue;
        int score = pointer_window_score(blob, base, v.first);
        if (score > bestscore) {
            bestscore = score;
            bestn = v.second;
            best = v.first;
        }
    }
    if (bestscore >= 32) {
        r.found = true;
        r.gp = best; // the %lo part is filled in later, off the real loads
        r.votes = bestn;
    }
    return r;
}

bool analyze(const binary& b, analysis& out, analysis_progress* progress)
{
    worker w(b, out, progress);
    return w.run();
}

// ---- control flow graph ----

bool build_cfg(const binary& b, const analysis& a, uint64_t fs, cfg& out, size_t max_blocks)
{
    out = cfg();
    out.func = fs;
    disassembler dis;
    if (!dis.open(b.arch) || !(a.flags_at(fs) & fl_code))
        return false;

    struct item {
        uint8_t size = 0;
        flow kind = flow::normal;
        bool has_target = false;
        uint64_t target = 0;
        bool noret = false;
    };
    std::map<uint64_t, item> items;
    std::set<uint64_t> leaders{fs};
    std::vector<uint64_t> stack{fs};
    auto other_func = [&](uint64_t x) { return x != fs && (a.flags_at(x) & fl_func); };

    while (!stack.empty() && items.size() < 100000) {
        uint64_t p = stack.back();
        stack.pop_back();
        for (;;) {
            if (items.count(p) || !(a.flags_at(p) & fl_code) || other_func(p))
                break;
            insn in;
            if (!dis.decode(b, p, in))
                break;
            item it;
            it.size = in.size;
            it.kind = in.kind;
            it.has_target = in.has_target;
            it.target = in.target;
            it.noret = in.kind == flow::call && a.noret_calls.count(p);
            items[p] = it;
            bool stop = false;
            if (in.kind == flow::jump) {
                if (in.has_target) {
                    if (!other_func(in.target)) {
                        leaders.insert(in.target);
                        stack.push_back(in.target);
                    }
                } else {
                    auto t = a.tables.find(p);
                    if (t != a.tables.end())
                        for (uint64_t x : t->second.targets)
                            if (!other_func(x)) {
                                leaders.insert(x);
                                stack.push_back(x);
                            }
                }
                stop = true;
            } else if (in.kind == flow::cond) {
                if (in.has_target && !other_func(in.target)) {
                    leaders.insert(in.target);
                    stack.push_back(in.target);
                }
                leaders.insert(in.next());
            } else if (in.kind == flow::ret || in.kind == flow::stop || it.noret) {
                stop = true;
            }
            if (stop)
                break;
            p = in.next();
        }
    }
    if (items.empty())
        return false;

    // cut into blocks
    std::vector<cfg_block> blocks;
    uint64_t prev_next = 0;
    bool prev_ends = true;
    for (const auto& kv : items) {
        uint64_t addr = kv.first;
        const item& it = kv.second;
        if (blocks.empty() || prev_ends || leaders.count(addr) || prev_next != addr) {
            if (blocks.size() >= max_blocks) {
                out.truncated = true;
                break;
            }
            cfg_block nb;
            nb.start = addr;
            blocks.push_back(nb);
        }
        cfg_block& cur = blocks.back();
        cur.insns.push_back(addr);
        cur.end = addr + it.size;
        prev_next = addr + it.size;
        prev_ends = it.kind == flow::jump || it.kind == flow::cond || it.kind == flow::ret ||
                    it.kind == flow::stop || it.noret;
    }

    // entry block first
    for (size_t i = 0; i < blocks.size(); i++)
        if (blocks[i].start == fs) {
            std::swap(blocks[0], blocks[i]);
            break;
        }
    std::unordered_map<uint64_t, uint32_t> index;
    for (size_t i = 0; i < blocks.size(); i++)
        index[blocks[i].start] = (uint32_t)i;
    auto link = [&](cfg_block& from, uint64_t to, edge_kind k) {
        auto it = index.find(to);
        if (it != index.end())
            from.succ.push_back({it->second, k});
    };
    for (cfg_block& blk : blocks) {
        uint64_t last = blk.insns.back();
        const item& it = items[last];
        uint64_t next = last + it.size;
        if (it.kind == flow::cond) {
            if (it.has_target)
                link(blk, it.target, edge_kind::taken);
            link(blk, next, edge_kind::not_taken);
        } else if (it.kind == flow::jump) {
            if (it.has_target) {
                link(blk, it.target, edge_kind::jump);
            } else {
                auto t = a.tables.find(last);
                if (t != a.tables.end())
                    for (uint64_t x : t->second.targets)
                        link(blk, x, edge_kind::table);
            }
        } else if (it.kind != flow::ret && it.kind != flow::stop && !it.noret) {
            link(blk, next, edge_kind::next);
        }
    }
    out.blocks = std::move(blocks);
    return true;
}
