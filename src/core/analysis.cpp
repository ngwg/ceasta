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
        if (!code_at(a))
            return;
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
        if (code_at(a))
            work.push_back(a);
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
        if (dis.decode(b, a, in)) {
            if (ins::is_endbr(in.id)) {
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

    // "call $+5; pop reg" is how 32 bit code reads eip, not a call to a function
    static bool get_pc_call(const insn& in) { return in.kind == flow::call && in.has_target && in.target == in.next(); }

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
            if (code_at(in.imm) && (ins::is_push(in.id) || ins::is_move(in.id)))
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
                if (ins::is_add(hist[i].id) && regs::same_reg(hist[i].reg0, r) && hist[i].reg1) {
                    add_pos = i;
                    breg = hist[i].reg1;
                    break;
                }
            if (add_pos < 0)
                return;
            int lp = -1;
            for (int i = add_pos - 1; i >= 0 && i >= add_pos - 6; i--) {
                const insn& h = hist[i];
                if (ins::is_move(h.id) && regs::same_reg(h.reg0, r) && h.has_mem_op && h.mem_scale == 4 &&
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
            mode = ins::is_movsxd(ld.id) ? 2 : 3;
        } else {
            return;
        }

        // case count from "cmp idx, n / ja default", following register copies back
        uint32_t count = 0;
        bool bounded = false;
        unsigned cur = idx;
        for (int i = load_pos - 1; i >= 0 && i >= load_pos - 10; i--) {
            const insn& h = hist[i];
            if (ins::is_cmp(h.id) && regs::same_reg(h.reg0, cur) && h.has_imm) {
                if (i + 1 < nh && (ins::is_ja(hist[i + 1].id) || ins::is_jae(hist[i + 1].id))) {
                    uint64_t n = h.imm + (ins::is_ja(hist[i + 1].id) ? 1 : 0);
                    if (n > 0 && n <= 4096) {
                        count = (uint32_t)n;
                        bounded = true;
                    }
                }
                break;
            }
            if (ins::is_move(h.id) && regs::same_reg(h.reg0, cur) && h.reg1)
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

    // linear walk from a, following fall through. branch targets go on the work list
    void explore(uint64_t a)
    {
        const int hist_max = 12;
        insn hist[hist_max];
        int nh = 0;
        for (;;) {
            if (!code_at(a) || (an.flags_at(a) & (fl_code | fl_tail | fl_str | fl_data)))
                return;
            insn in;
            if (!dis.decode(b, a, in) || !code_at(a + in.size - 1))
                return;
            for (uint32_t k = 1; k < in.size; k++)
                if (an.flags_at(a + k) & (fl_code | fl_tail | fl_str | fl_data))
                    return; // would overlap something we already know
            mark_item(a, in.size, fl_code);
            an.insn_count++;
            refs(in);

            bool stop = false;
            switch (in.kind) {
            case flow::jump:
                if (in.has_target)
                    push_code(in.target);
                else
                    resolve_table(hist, nh, in);
                stop = true;
                break;
            case flow::cond:
                if (in.has_target)
                    push_code(in.target);
                break;
            case flow::call:
                if (in.has_target && !get_pc_call(in))
                    add_func(in.target);
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
            if (stop)
                return;
            if (nh == hist_max) {
                for (int i = 1; i < hist_max; i++)
                    hist[i - 1] = hist[i];
                nh--;
            }
            hist[nh++] = in;
            a = in.next();
        }
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
        while (p < lim) {
            uint8_t c;
            if (!b.read_u8(p, c))
                return lim;
            if (c == 0xcc || c == 0x90 || c == 0x00) {
                p++;
                continue;
            }
            insn in;
            if (dis.decode(b, p, in) && ins::is_nop(in.id) && p + in.size <= lim) {
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
            if (ins::is_suspicious(in.id) || in.kind == flow::stop)
                return false;
            if (in.size >= 2 && in.bytes[0] == 0 && in.bytes[1] == 0 && ++zero_ops >= 2)
                return false; // runs of "add [rax], al" are zeros, not code
            if (i == 0 && in.bytes[0] == 0)
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
                           (ins::is_nop(in.id) || (in.size == 1 && in.bytes[0] == 0xcc))) {
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
        an.funcs.reserve(starts.size());
        size_t done = 0;
        for (uint64_t s : starts) {
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
            if (dis.decode(b, fa, first) && ins::is_endbr(first.id)) {
                fa = first.next();
                if (!dis.decode(b, fa, first))
                    first = insn();
            }
            if (first.kind == flow::jump && f.insns <= 2) {
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
                if (seg.exec() && !refd) {
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
        imm_refs = (b.format == bin_format::pe || b.format == bin_format::elf) && b.base >= 0x10000;
        if (!dis.open(b.arch))
            return false;
        an = analysis();
        for (const segment& s : b.segments) {
            an.seg_start.push_back(s.start);
            an.flags.emplace_back((size_t)s.size(), (uint8_t)0);
            if (!b.is64() && (s.name == ".got.plt" || (!got && s.name == ".got")))
                got = &s;
        }

        int ps = b.ptr_size();
        for (size_t i = 0; i < b.imports.size(); i++) {
            uint64_t slot = b.imports[i].slot;
            an.slot_import.emplace(slot, (uint32_t)i);
            if (range_free(slot, (uint32_t)ps)) {
                mark_item(slot, (uint32_t)ps, fl_data);
                an.data_sizes[slot] = (uint8_t)ps;
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
