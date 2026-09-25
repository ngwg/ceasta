#include "core/decompiler.h"

#include "core/analysis.h"
#include "core/binary.h"
#include "core/database.h"
#include "core/util.h"

#include <capstone/capstone.h>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

namespace {

// ------------------------------------------------------------------ expressions

struct expr;
using ep = std::shared_ptr<expr>;

struct expr {
    enum class k { num, sym, reg, mem, un, bin, call, tern } kind = k::num;
    uint64_t num = 0;
    bool sgn = false;
    bool indirect = false; // call through a pointer: kids[0] is the target
    int width = 0;       // mem access width in bytes
    std::string text;    // sym/reg identifier, un/bin operator, call name
    uint64_t ref = 0;    // address a sym/call names, 0 = none
    std::vector<ep> kids;
};

ep e_num(uint64_t v, bool sgn = false)
{
    auto e = std::make_shared<expr>();
    e->kind = expr::k::num;
    e->num = v;
    e->sgn = sgn;
    return e;
}
ep e_sym(const std::string& s, uint64_t ref = 0)
{
    auto e = std::make_shared<expr>();
    e->kind = expr::k::sym;
    e->text = s;
    e->ref = ref;
    return e;
}
ep e_reg(const std::string& s)
{
    auto e = std::make_shared<expr>();
    e->kind = expr::k::reg;
    e->text = s;
    return e;
}
ep e_un(const std::string& op, ep a)
{
    auto e = std::make_shared<expr>();
    e->kind = expr::k::un;
    e->text = op;
    e->kids = {std::move(a)};
    return e;
}
ep e_bin(const std::string& op, ep a, ep b)
{
    auto e = std::make_shared<expr>();
    e->kind = expr::k::bin;
    e->text = op;
    e->kids = {std::move(a), std::move(b)};
    return e;
}
ep e_mem(ep addr, int width)
{
    auto e = std::make_shared<expr>();
    e->kind = expr::k::mem;
    e->width = width;
    e->kids = {std::move(addr)};
    return e;
}
ep e_tern(ep c, ep a, ep b)
{
    auto e = std::make_shared<expr>();
    e->kind = expr::k::tern;
    e->kids = {std::move(c), std::move(a), std::move(b)};
    return e;
}
// an instruction with no c operator, shown as a call: __rol(x, 5)
ep e_intr(const std::string& name, std::vector<ep> args)
{
    auto e = std::make_shared<expr>();
    e->kind = expr::k::call;
    e->text = name;
    e->kids = std::move(args);
    return e;
}

int node_count(const ep& e)
{
    if (!e)
        return 0;
    int n = 1;
    for (const auto& c : e->kids)
        n += node_count(c);
    return n;
}

int prec(const expr& e)
{
    if (e.kind == expr::k::tern)
        return 1;
    if (e.kind != expr::k::bin)
        return 100;
    const std::string& o = e.text;
    if (o == "*" || o == "/" || o == "%")
        return 12;
    if (o == "+" || o == "-")
        return 11;
    if (o == "<<" || o == ">>")
        return 10;
    if (o == "<" || o == ">" || o == "<=" || o == ">=")
        return 8;
    if (o == "==" || o == "!=")
        return 7;
    if (o == "&")
        return 6;
    if (o == "^")
        return 5;
    if (o == "|")
        return 4;
    if (o == "&&")
        return 3;
    if (o == "||")
        return 2;
    return 1;
}

std::string hex_num(uint64_t v, bool sgn)
{
    char buf[32];
    if (sgn) {
        int64_t s = (int64_t)v;
        if (s < 0 && s > -0x10000) {
            std::snprintf(buf, sizeof(buf), "-%lld", (long long)(-s));
            return buf;
        }
    }
    if (v < 10) {
        std::snprintf(buf, sizeof(buf), "%llu", (unsigned long long)v);
        return buf;
    }
    std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)v);
    return buf;
}

const char* mem_type(int width)
{
    switch (width) {
    case 1: return "char";
    case 2: return "short";
    case 4: return "int";
    case 8: return "long long";
    default: return "void*";
    }
}

std::string print(const ep& e, int parent_prec);

// logical negation, flipping comparisons instead of wrapping in !()
ep negate(const ep& e)
{
    if (e && e->kind == expr::k::bin) {
        static const std::map<std::string, std::string> flip = {
            {"==", "!="}, {"!=", "=="}, {"<", ">="}, {">=", "<"}, {">", "<="}, {"<=", ">"}};
        auto it = flip.find(e->text);
        if (it != flip.end())
            return e_bin(it->second, e->kids[0], e->kids[1]);
    }
    if (e && e->kind == expr::k::un && e->text == "!")
        return e->kids[0];
    return e_un("!", e ? e : e_num(0));
}

std::string print(const ep& e, int parent_prec = 0)
{
    if (!e)
        return "?";
    switch (e->kind) {
    case expr::k::num:
        return hex_num(e->num, e->sgn);
    case expr::k::sym:
    case expr::k::reg:
        return e->text;
    case expr::k::mem: {
        const ep& a = e->kids[0];
        if (a->kind == expr::k::un && a->text == "&")
            return print(a->kids[0], 100); // *(&sym) -> sym
        return std::string("*(") + mem_type(e->width) + "*)" + print(a, 100);
    }
    case expr::k::un:
        return e->text + print(e->kids[0], 90);
    case expr::k::bin: {
        int p = prec(*e);
        std::string s = print(e->kids[0], p) + " " + e->text + " " + print(e->kids[1], p + 1);
        return p < parent_prec ? "(" + s + ")" : s;
    }
    case expr::k::call: {
        size_t first = e->indirect && !e->kids.empty() ? 1 : 0;
        std::string s = first ? "(*" + print(e->kids[0], 90) + ")(" : e->text + "(";
        for (size_t i = first; i < e->kids.size(); i++) {
            if (i > first)
                s += ", ";
            s += print(e->kids[i], 0);
        }
        return s + ")";
    }
    case expr::k::tern: {
        std::string s = print(e->kids[0], 2) + " ? " + print(e->kids[1], 2) + " : " + print(e->kids[2], 1);
        return 1 < parent_prec ? "(" + s + ")" : s;
    }
    }
    return "?";
}

// does `text` contain `word` as a whole identifier?
bool mentions(const std::string& text, const std::string& word)
{
    auto ident = [](char c) { return std::isalnum((unsigned char)c) || c == '_'; };
    for (size_t at = text.find(word); at != std::string::npos; at = text.find(word, at + 1)) {
        bool left = at == 0 || !ident(text[at - 1]);
        bool right = at + word.size() >= text.size() || !ident(text[at + word.size()]);
        if (left && right)
            return true;
    }
    return false;
}

// does e read register `name`? the subtree `skip` is left out
bool refs_name(const ep& e, const std::string& name, const expr* skip)
{
    if (!e || e.get() == skip)
        return false;
    if (e->kind == expr::k::reg && e->text == name)
        return true;
    for (const ep& k : e->kids)
        if (refs_name(k, name, skip))
            return true;
    return false;
}

bool has_mem(const ep& e)
{
    if (!e)
        return false;
    if (e->kind == expr::k::mem)
        return true;
    for (const ep& k : e->kids)
        if (has_mem(k))
            return true;
    return false;
}

bool contains(const ep& e, const expr* node)
{
    if (!e)
        return false;
    if (e.get() == node)
        return true;
    for (const ep& k : e->kids)
        if (contains(k, node))
            return true;
    return false;
}

// copy-on-write rewrites. memo maps an old node to its new copy, so a subtree shared by
// several expressions stays shared (the same node) after the rewrite.
using rewrite_memo = std::unordered_map<const expr*, ep>;

template <class F>
ep rewrite_tree(const ep& e, F&& hit, rewrite_memo& memo)
{
    if (!e)
        return e;
    if (ep r = hit(e))
        return r;
    auto it = memo.find(e.get());
    if (it != memo.end())
        return it->second;
    ep out = e;
    for (size_t i = 0; i < e->kids.size(); i++) {
        ep k = rewrite_tree(e->kids[i], hit, memo);
        if (k != e->kids[i]) {
            if (out == e)
                out = std::make_shared<expr>(*e);
            out->kids[i] = k;
        }
    }
    memo[e.get()] = out;
    return out;
}

// replace one node (by identity) with `to`
ep replace_node(const ep& e, const expr* node, const ep& to, rewrite_memo& memo)
{
    return rewrite_tree(e, [&](const ep& x) { return x.get() == node ? to : ep(); }, memo);
}

// replace every read of register `name` with `to`
ep replace_reg(const ep& e, const std::string& name, const ep& to, rewrite_memo& memo)
{
    return rewrite_tree(e, [&](const ep& x) {
        return x->kind == expr::k::reg && x->text == name ? to : ep();
    }, memo);
}

// ------------------------------------------------------------------ registers

std::string reg_family(const char* raw)
{
    if (!raw)
        return "";
    std::string n = raw;
    for (char& c : n)
        c = (char)std::tolower((unsigned char)c);
    struct row {
        const char* fam;
        const char* names[6];
    };
    static const row table[] = {
        {"rax", {"rax", "eax", "ax", "al", "ah", nullptr}},
        {"rbx", {"rbx", "ebx", "bx", "bl", "bh", nullptr}},
        {"rcx", {"rcx", "ecx", "cx", "cl", "ch", nullptr}},
        {"rdx", {"rdx", "edx", "dx", "dl", "dh", nullptr}},
        {"rsi", {"rsi", "esi", "si", "sil", nullptr, nullptr}},
        {"rdi", {"rdi", "edi", "di", "dil", nullptr, nullptr}},
        {"rbp", {"rbp", "ebp", "bp", "bpl", nullptr, nullptr}},
        {"rsp", {"rsp", "esp", "sp", "spl", nullptr, nullptr}},
    };
    for (const auto& r : table)
        for (const char* nm : r.names)
            if (nm && n == nm)
                return r.fam;
    if (n.size() >= 2 && n[0] == 'r' && std::isdigit((unsigned char)n[1])) {
        std::string base = "r";
        size_t i = 1;
        while (i < n.size() && std::isdigit((unsigned char)n[i]))
            base += n[i++];
        int v = std::atoi(base.c_str() + 1);
        if (v >= 8 && v <= 15)
            return base;
    }
    return "";
}

std::string reg_display(const std::string& fam, bool is64)
{
    if (is64 || fam.empty())
        return fam;
    static const std::map<std::string, std::string> m = {
        {"rax", "eax"}, {"rbx", "ebx"}, {"rcx", "ecx"}, {"rdx", "edx"},
        {"rsi", "esi"}, {"rdi", "edi"}, {"rbp", "ebp"}, {"rsp", "esp"}};
    auto it = m.find(fam);
    return it == m.end() ? fam : it->second;
}

int reg_bit(const std::string& fam)
{
    static const std::map<std::string, int> m = {
        {"rax", 0}, {"rcx", 1}, {"rdx", 2}, {"rbx", 3}, {"rsp", 4}, {"rbp", 5},
        {"rsi", 6}, {"rdi", 7}, {"r8", 8}, {"r9", 9}, {"r10", 10}, {"r11", 11},
        {"r12", 12}, {"r13", 13}, {"r14", 14}, {"r15", 15}};
    auto it = m.find(fam);
    return it == m.end() ? -1 : it->second;
}

const char* arg_reg_at(int index, bool is64, bin_format fmt)
{
    static const char* win64[] = {"rcx", "rdx", "r8", "r9"};
    static const char* sysv[] = {"rdi", "rsi", "rdx", "rcx", "r8", "r9"};
    if (!is64)
        return nullptr;
    if (fmt == bin_format::pe)
        return index >= 0 && index < 4 ? win64[index] : nullptr;
    return index >= 0 && index < 6 ? sysv[index] : nullptr;
}

// register family for a reg_bit index
const char* fam_name(int b)
{
    static const char* names[16] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                                    "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15"};
    return b >= 0 && b < 16 ? names[b] : "";
}

int low_bit(uint32_t m)
{
    for (int b = 0; b < 32; b++)
        if (m & (1u << b))
            return b;
    return -1;
}

// the jcc that tests the same condition as a setcc / cmovcc, 0 if none
unsigned jcc_for(unsigned id, bool& is_set)
{
    is_set = true;
    switch (id) {
    case X86_INS_SETE: return X86_INS_JE;
    case X86_INS_SETNE: return X86_INS_JNE;
    case X86_INS_SETG: return X86_INS_JG;
    case X86_INS_SETGE: return X86_INS_JGE;
    case X86_INS_SETL: return X86_INS_JL;
    case X86_INS_SETLE: return X86_INS_JLE;
    case X86_INS_SETA: return X86_INS_JA;
    case X86_INS_SETAE: return X86_INS_JAE;
    case X86_INS_SETB: return X86_INS_JB;
    case X86_INS_SETBE: return X86_INS_JBE;
    case X86_INS_SETS: return X86_INS_JS;
    case X86_INS_SETNS: return X86_INS_JNS;
    default: break;
    }
    is_set = false;
    switch (id) {
    case X86_INS_CMOVE: return X86_INS_JE;
    case X86_INS_CMOVNE: return X86_INS_JNE;
    case X86_INS_CMOVG: return X86_INS_JG;
    case X86_INS_CMOVGE: return X86_INS_JGE;
    case X86_INS_CMOVL: return X86_INS_JL;
    case X86_INS_CMOVLE: return X86_INS_JLE;
    case X86_INS_CMOVA: return X86_INS_JA;
    case X86_INS_CMOVAE: return X86_INS_JAE;
    case X86_INS_CMOVB: return X86_INS_JB;
    case X86_INS_CMOVBE: return X86_INS_JBE;
    case X86_INS_CMOVS: return X86_INS_JS;
    case X86_INS_CMOVNS: return X86_INS_JNS;
    default: return 0;
    }
}

// ------------------------------------------------------------------ block ir

struct stmt {
    uint64_t addr = 0;
    std::string text;
};

enum class term_kind { fallthrough, ret, jump, cond, sw, indirect, noreturn };

struct block_ir {
    uint64_t start = 0, end = 0;
    std::vector<stmt> stmts;
    term_kind term = term_kind::fallthrough;
    ep cond;
    uint64_t taken = 0;
    uint64_t fall = 0;
    const jump_table* table = nullptr;
    uint32_t def = 0, use = 0, live_in = 0, live_out = 0;
};

struct flag_state {
    bool valid = false, is_cmp = false, is_test = false;
    ep a, b, res;
};

// what one instruction reads and writes: register families as reg_bit masks, and
// whether it tests or changes the status flags
struct insn_rw {
    uint32_t rd = 0, wr = 0;
    bool flags_rd = false, flags_wr = false;
    bool call = false, ret = false;
    bool tail = false;   // a jump out of the function (a tail call)
    uint64_t target = 0; // direct call / tail call target
    int proto_args = -1; // a call whose prototype says how many arguments it takes
};

// ------------------------------------------------------------------ lifter

class lifter {
public:
    lifter(database& db, csh cs) : db_(db), cs_(cs), is64_(db.bin.is64()) {}
    bool run(uint64_t func_start, std::vector<block_ir>& out, std::vector<std::string>& params,
             bool& returns_value);

    // the variables in the stack frame, by their offset from the stack pointer at the entry
    // (0 is the return address): local_1c below it, arg_0 above
    struct frame_slot {
        std::string name;
        int width = 0;
    };
    std::map<int64_t, frame_slot> frame;

private:
    database& db_;
    csh cs_;
    bool is64_;
    std::set<std::string> params_;

    // what a call to a function of this binary does with registers
    struct callee_info {
        int arity = -1;        // argument registers it reads, -1 when unknown
        uint32_t clobbers = 0; // scratch registers it may change
    };
    std::unordered_map<uint64_t, callee_info> callees_;

    // the stack pointer before each instruction as an offset from its value at the entry, when
    // it's known; rbp's, when rbp is the frame pointer
    std::unordered_map<uint64_t, int64_t> sp_at_;
    bool rbp_frame_ = false;
    int64_t rbp_off_ = 0;
    bool cur_sp_known_ = false; // the instruction being lifted
    int64_t cur_sp_ = 0;
    std::unordered_map<uint64_t, int> pops_; // callee -> bytes of arguments it takes off the stack
    void frame_pass(const cfg& g, int entry);
    int callee_pops(cs_insn* call);
    std::string frame_var(int64_t off, int width);
    bool slot_of(const x86_op_mem& m, int64_t& off) const;
    // what a call goes to by name, and the prototype that says what it takes (null: unknown)
    const prototype* call_proto(cs_insn* call, std::string* name = nullptr, uint64_t* ref = nullptr);
    int stack_args_of(cs_insn* call); // how many stack arguments a call takes, -1 unknown

    std::string disp(const std::string& fam) { return reg_display(fam, is64_); }
    uint32_t scratch() const;
    uint32_t access(cs_insn* in, uint32_t& wr);
    const function* local_fn(uint64_t target);
    const callee_info& callee_of(uint64_t target);
    int result_used(uint64_t func);
    ep reg_read(std::unordered_map<std::string, ep>& cur, const std::string& fam);
    ep sym_for(uint64_t a);
    ep mem_address(const x86_op_mem& m, std::unordered_map<std::string, ep>& cur, uint64_t rip, int width = 0);
    ep operand_expr(cs_insn* in, const cs_x86_op& op, std::unordered_map<std::string, ep>& cur);
    ep build_cond(const flag_state& fs, unsigned cc_id, bool& ok);
};

// registers a call may change: rax (the result) and the other scratch registers
uint32_t lifter::scratch() const
{
    uint32_t m = (1u << reg_bit("rax")) | (1u << reg_bit("rcx")) | (1u << reg_bit("rdx"));
    if (is64_) {
        for (const char* r : {"r8", "r9", "r10", "r11"})
            m |= 1u << reg_bit(r);
        if (db_.bin.format != bin_format::pe)
            m |= (1u << reg_bit("rsi")) | (1u << reg_bit("rdi"));
    }
    return m;
}

// register families an instruction reads (returned) and writes (wr), as reg_bit masks
uint32_t lifter::access(cs_insn* in, uint32_t& wr)
{
    uint32_t rd = 0;
    wr = 0;
    cs_regs r, w;
    uint8_t nr = 0, nw = 0;
    if (cs_regs_access(cs_, in, r, &nr, w, &nw) == CS_ERR_OK) {
        for (uint8_t i = 0; i < nr; i++) {
            int b = reg_bit(reg_family(cs_reg_name(cs_, r[i])));
            if (b >= 0)
                rd |= 1u << b;
        }
        for (uint8_t i = 0; i < nw; i++) {
            int b = reg_bit(reg_family(cs_reg_name(cs_, w[i])));
            if (b >= 0)
                wr |= 1u << b;
        }
    }
    // xor eax, eax / sub eax, eax only write
    const cs_x86& x = in->detail->x86;
    if ((in->id == X86_INS_XOR || in->id == X86_INS_SUB) && x.op_count >= 2 &&
        x.operands[0].type == X86_OP_REG && x.operands[1].type == X86_OP_REG &&
        x.operands[0].reg == x.operands[1].reg) {
        int b = reg_bit(reg_family(cs_reg_name(cs_, x.operands[0].reg)));
        if (b >= 0)
            rd &= ~(1u << b);
    }
    // push reg: a save (or a dummy push that aligns the stack), not a use of the value
    if (in->id == X86_INS_PUSH && x.op_count >= 1 && x.operands[0].type == X86_OP_REG) {
        int b = reg_bit(reg_family(cs_reg_name(cs_, x.operands[0].reg)));
        if (b >= 0 && b != reg_bit("rsp"))
            rd &= ~(1u << b);
    }
    if (in->id == X86_INS_CALL)
        wr |= scratch();
    return rd;
}

// the function of this binary a call lands in (through a thunk), or null
const function* lifter::local_fn(uint64_t target)
{
    const function* fn = db_.an.func_containing(target);
    if (!fn || fn->start != target)
        return nullptr;
    if (fn->thunk) {
        const function* to = fn->thunk_target ? db_.an.func_containing(fn->thunk_target) : nullptr;
        fn = to && to->start == fn->thunk_target && !to->thunk ? to : nullptr;
    }
    return fn;
}

// what a call to `target` reads and changes. for a function of this binary: the argument
// registers it reads, and the scratch registers it writes - compilers keep values in the
// others across such a call. anything else reads unknown arguments and changes all scratch.
const lifter::callee_info& lifter::callee_of(uint64_t target)
{
    auto hit = callees_.find(target);
    if (hit != callees_.end())
        return hit->second;
    callee_info& ci = callees_[target];
    uint32_t all = scratch();
    ci.clobbers = all;
    const function* fn = local_fn(target);
    cfg g;
    if (!fn || !build_cfg(db_.bin, db_.an, fn->start, g, 400))
        return ci;
    cs_insn* in = cs_malloc(cs_);
    if (!in)
        return ci;
    size_t nb = g.blocks.size();
    std::vector<uint32_t> use(nb, 0), def(nb, 0), live(nb, 0);
    int entry = 0;
    uint32_t w = 0;
    for (size_t bi = 0; bi < nb; bi++) {
        if (g.blocks[bi].start == fn->start)
            entry = (int)bi;
        for (uint64_t a : g.blocks[bi].insns) {
            uint8_t code[16];
            size_t n = db_.bin.read(a, code, sizeof(code));
            const uint8_t* p = code;
            size_t left = n;
            uint64_t addr = a;
            if (!cs_disasm_iter(cs_, &p, &left, &addr, in)) {
                w |= all;
                continue;
            }
            uint32_t wr = 0, rd = access(in, wr); // a call in there changes all scratch
            const cs_x86& x = in->detail->x86;
            if (in->id == X86_INS_JMP && !(x.op_count >= 1 && x.operands[0].type == X86_OP_IMM) &&
                !db_.an.tables.count(a))
                wr |= all; // an indirect jump could go anywhere
            use[bi] |= rd & ~def[bi];
            def[bi] |= wr;
            w |= wr;
        }
    }
    cs_free(in, 1);
    ci.clobbers = w & all;
    bool changed = true;
    int guard = 0;
    while (changed && guard++ < 20000) {
        changed = false;
        for (size_t bi = 0; bi < nb; bi++) {
            uint32_t o = 0;
            for (const cfg_edge& e : g.blocks[bi].succ)
                o |= live[e.to];
            uint32_t v = use[bi] | (o & ~def[bi]);
            if (v != live[bi]) {
                live[bi] = v;
                changed = true;
            }
        }
    }
    // variadic (system v): al holds the number of vector registers and every argument
    // register gets spilled, so the count says nothing
    if (!is64_ || (db_.bin.format != bin_format::pe && (live[entry] & 1u)))
        return ci;
    // the last argument register it reads sets the count (an unused first one still exists)
    ci.arity = 0;
    for (int i = 0; arg_reg_at(i, is64_, db_.bin.format); i++)
        if (live[entry] & (1u << reg_bit(arg_reg_at(i, is64_, db_.bin.format))))
            ci.arity = i + 1;
    return ci;
}

// do callers read rax after calling `func`? 1 yes, 0 no (every call site overwrites or
// drops it), -1 no call sites to look at
int lifter::result_used(uint64_t func)
{
    auto refs = db_.an.refs_to(func);
    const function* self = db_.an.func_containing(func);
    cs_insn* in = cs_malloc(cs_);
    if (!in)
        return -1;
    int sites = 0;
    bool used = false;
    for (const xref* x = refs.first; x != refs.second && !used; ++x) {
        if (x->type == xref_type::jump) {
            // a tail jump from another function hands the result on
            const function* from = db_.an.func_containing(x->from);
            if (from && from != self) {
                sites++;
                used = true;
            }
            continue;
        }
        if (x->type != xref_type::call)
            continue;
        sites++;
        uint64_t pc = x->from;
        bool first = true;
        for (int i = 0; i < 16; i++) {
            uint8_t code[16];
            size_t n = db_.bin.read(pc, code, sizeof(code));
            const uint8_t* p = code;
            size_t left = n;
            uint64_t addr = pc;
            if (!cs_disasm_iter(cs_, &p, &left, &addr, in)) {
                used = true; // can't tell
                break;
            }
            pc = addr;
            if (first) { // the call itself
                first = false;
                continue;
            }
            uint32_t wr = 0, rd = access(in, wr);
            if (rd & 1u) {
                used = true;
                break;
            }
            if (wr & 1u)
                break; // overwritten, or clobbered by the next call
            if (cs_insn_group(cs_, in, X86_GRP_JUMP) || cs_insn_group(cs_, in, X86_GRP_RET)) {
                used = true; // it leaves the block: assume it's used
                break;
            }
        }
    }
    cs_free(in, 1);
    if (!sites)
        return -1;
    return used ? 1 : 0;
}

ep lifter::reg_read(std::unordered_map<std::string, ep>& cur, const std::string& fam)
{
    auto it = cur.find(fam);
    if (it != cur.end() && it->second)
        return it->second;
    return e_reg(disp(fam));
}

// ---- the stack frame

bool lifter::slot_of(const x86_op_mem& m, int64_t& off) const
{
    if (m.index != X86_REG_INVALID || m.base == X86_REG_INVALID || m.segment != X86_REG_INVALID)
        return false;
    std::string fam = reg_family(cs_reg_name(cs_, m.base));
    if (fam == "rsp" && cur_sp_known_) {
        off = cur_sp_ + m.disp;
        return true;
    }
    if (fam == "rbp" && rbp_frame_) {
        off = rbp_off_ + m.disp;
        return true;
    }
    return false;
}

// local_1c for a slot 0x1c below the return address, arg_4 for one 4 above the first argument
std::string lifter::frame_var(int64_t off, int width)
{
    int64_t ptr = is64_ ? 8 : 4;
    char buf[48];
    if (off < 0)
        std::snprintf(buf, sizeof(buf), "local_%llx", (unsigned long long)(-off));
    else if (off >= ptr)
        std::snprintf(buf, sizeof(buf), "arg_%llx", (unsigned long long)(off - ptr));
    else
        return std::string(); // the return address itself
    frame_slot& s = frame[off];
    s.name = buf;
    s.width = std::max(s.width, width);
    return s.name;
}

const prototype* lifter::call_proto(cs_insn* in, std::string* name, uint64_t* ref)
{
    const cs_x86& x = in->detail->x86;
    if (x.op_count < 1)
        return nullptr;
    const cs_x86_op& op = x.operands[0];
    if (op.type == X86_OP_IMM) {
        uint64_t t = (uint64_t)op.imm;
        if (ref)
            *ref = t;
        if (name) {
            std::string n = db_.name_at(t);
            *name = n.empty() ? db_.location(t) : n;
        }
        return db_.callee_proto(t);
    }
    // call [slot]: through an import's slot (the iat or the got), which has the import's name
    if (op.type == X86_OP_MEM && op.mem.index == X86_REG_INVALID &&
        (op.mem.base == X86_REG_RIP || op.mem.base == X86_REG_INVALID)) {
        uint64_t slot = op.mem.base == X86_REG_RIP ? in->address + in->size + (uint64_t)op.mem.disp : (uint64_t)op.mem.disp;
        if (!is64_)
            slot &= 0xffffffffull;
        std::string n = db_.name_at(slot);
        if (!n.empty() && db_.an.slot_import.count(slot)) {
            if (ref)
                *ref = slot;
            if (name)
                *name = n;
            return known_prototype(n);
        }
    }
    return nullptr;
}

// what a 32-bit callee takes off the stack itself (stdcall: ret n)
int lifter::callee_pops(cs_insn* call)
{
    if (is64_)
        return 0;
    uint64_t ref = 0;
    const prototype* p = call_proto(call, nullptr, &ref);
    if (p)
        return p->stdcall ? 4 * (int)p->params.size() : 0;
    if (!ref)
        return 0;
    auto hit = pops_.find(ref);
    if (hit != pops_.end())
        return hit->second;
    int pops = 0;
    const function* fn = local_fn(ref);
    cs_insn* in = fn ? cs_malloc(cs_) : nullptr;
    for (uint64_t a = fn ? fn->start : 0; in && a < fn->end;) {
        uint32_t sz = db_.an.item_size(a);
        if (db_.an.flags_at(a) & fl_code) {
            uint8_t code[16];
            size_t n = db_.bin.read(a, code, sizeof(code));
            const uint8_t* p2 = code;
            size_t left = n;
            uint64_t addr = a;
            if (cs_disasm_iter(cs_, &p2, &left, &addr, in) && in->id == X86_INS_RET && in->detail->x86.op_count == 1 &&
                in->detail->x86.operands[0].type == X86_OP_IMM) {
                pops = (int)in->detail->x86.operands[0].imm;
                break;
            }
        }
        a += sz ? sz : 1;
    }
    if (in)
        cs_free(in, 1);
    pops_[ref] = pops;
    return pops;
}

// how many arguments a call takes on the stack: from its prototype, a stdcall callee's ret n,
// or the "add esp, n" after a cdecl call. -1 when that isn't known
int lifter::stack_args_of(cs_insn* call)
{
    int nregs = 0;
    while (arg_reg_at(nregs, is64_, db_.bin.format))
        nregs++;
    const prototype* p = call_proto(call);
    if (p && !p->variadic)
        return std::max(0, (int)p->params.size() - nregs);
    if (is64_)
        return -1;
    if (!p) {
        int pops = callee_pops(call);
        if (pops > 0)
            return pops / 4;
    }
    // add esp, n right after the call: the caller clears n bytes of arguments
    uint8_t code[16];
    uint64_t next = call->address + call->size;
    size_t n = db_.bin.read(next, code, sizeof(code));
    cs_insn* in = cs_malloc(cs_);
    int count = -1;
    const uint8_t* q = code;
    size_t left = n;
    uint64_t addr = next;
    if (in && cs_disasm_iter(cs_, &q, &left, &addr, in) && in->id == X86_INS_ADD && in->detail->x86.op_count == 2 &&
        in->detail->x86.operands[0].type == X86_OP_REG && in->detail->x86.operands[1].type == X86_OP_IMM &&
        reg_family(cs_reg_name(cs_, in->detail->x86.operands[0].reg)) == "rsp")
        count = (int)(in->detail->x86.operands[1].imm / 4);
    if (in)
        cs_free(in, 1);
    return count;
}

// where the stack pointer is before each instruction, and whether rbp is a frame pointer: a
// walk over the blocks from the entry. a block reached with two different offsets, an
// alloca or an "and rsp, -16" leave it unknown from there (rbp relative slots still work)
void lifter::frame_pass(const cfg& g, int entry)
{
    const int64_t unknown = INT64_MIN;
    const int64_t ptr = is64_ ? 8 : 4;
    size_t nb = g.blocks.size();
    sp_at_.clear();
    rbp_frame_ = false;
    bool rbp_bad = false;
    std::vector<int64_t> in(nb, unknown);
    std::vector<char> seen(nb, 0);
    std::vector<int> work;
    if (entry < 0 || (size_t)entry >= nb)
        return;
    in[(size_t)entry] = 0;
    seen[(size_t)entry] = 1;
    work.push_back(entry);
    cs_insn* insn = cs_malloc(cs_);
    if (!insn)
        return;
    auto fam_of = [&](const cs_x86_op& op) {
        return op.type == X86_OP_REG ? reg_family(cs_reg_name(cs_, op.reg)) : std::string();
    };
    auto set_frame = [&](int64_t at) {
        if (rbp_frame_ && rbp_off_ != at)
            rbp_bad = true;
        rbp_frame_ = true;
        rbp_off_ = at;
    };
    int guard = 0;
    while (!work.empty() && guard++ < 200000) {
        int b = work.back();
        work.pop_back();
        int64_t sp = in[(size_t)b];
        for (uint64_t a : g.blocks[(size_t)b].insns) {
            if (sp != unknown)
                sp_at_[a] = sp;
            else
                sp_at_.erase(a);
            uint8_t code[16];
            size_t n = db_.bin.read(a, code, sizeof(code));
            const uint8_t* p = code;
            size_t left = n;
            uint64_t addr = a;
            if (!cs_disasm_iter(cs_, &p, &left, &addr, insn)) {
                sp = unknown;
                continue;
            }
            const cs_x86& x = insn->detail->x86;
            std::string d0 = x.op_count >= 1 ? fam_of(x.operands[0]) : std::string();
            std::string d1 = x.op_count >= 2 ? fam_of(x.operands[1]) : std::string();
            int64_t size = x.op_count >= 1 && x.operands[0].size == 2 ? 2 : ptr;
            auto known = [&](int64_t v) { return sp == unknown ? unknown : v; };
            switch (insn->id) {
            case X86_INS_PUSH:
                sp = known(sp - size);
                break;
            case X86_INS_POP:
                sp = d0 == "rsp" ? unknown : known(sp + size);
                break;
            case X86_INS_PUSHFQ:
            case X86_INS_PUSHFD:
                sp = known(sp - ptr);
                break;
            case X86_INS_POPFQ:
            case X86_INS_POPFD:
                sp = known(sp + ptr);
                break;
            case X86_INS_PUSHAL:
                sp = known(sp - 32);
                break;
            case X86_INS_POPAL:
                sp = known(sp + 32);
                break;
            case X86_INS_SUB:
            case X86_INS_ADD:
                if (d0 == "rsp")
                    sp = x.operands[1].type == X86_OP_IMM
                        ? known(sp + (insn->id == X86_INS_ADD ? 1 : -1) * (int64_t)x.operands[1].imm) : unknown;
                break;
            case X86_INS_LEA: {
                const x86_op_mem& m = x.operands[1].mem;
                std::string base = m.base != X86_REG_INVALID ? reg_family(cs_reg_name(cs_, m.base)) : std::string();
                bool plain = m.index == X86_REG_INVALID;
                if (d0 == "rsp")
                    sp = plain && base == "rsp" ? known(sp + m.disp)
                       : plain && base == "rbp" && rbp_frame_ ? rbp_off_ + m.disp : unknown;
                else if (d0 == "rbp") {
                    if (plain && base == "rsp" && sp != unknown)
                        set_frame(sp + m.disp);
                    else
                        rbp_bad = true;
                }
                break;
            }
            case X86_INS_MOV:
                if (d0 == "rsp")
                    sp = d1 == "rbp" && rbp_frame_ ? rbp_off_ : unknown;
                else if (d0 == "rbp") {
                    if (d1 == "rsp" && sp != unknown)
                        set_frame(sp);
                    else
                        rbp_bad = true;
                }
                break;
            case X86_INS_LEAVE:
                sp = rbp_frame_ ? rbp_off_ + ptr : unknown;
                break;
            case X86_INS_ENTER:
                if (sp != unknown) {
                    sp -= ptr;
                    set_frame(sp);
                    sp -= (int64_t)x.operands[0].imm;
                }
                break;
            case X86_INS_CALL:
                sp = known(sp + callee_pops(insn));
                break;
            default: {
                // anything else that changes rsp (and rsp, -16 / mov rsp, rax) loses track; rbp
                // changed any other way isn't a frame pointer
                bool wr0 = x.op_count >= 1 && x.operands[0].type == X86_OP_REG && (x.operands[0].access & CS_AC_WRITE);
                if (wr0 && d0 == "rsp")
                    sp = unknown;
                if (wr0 && d0 == "rbp")
                    rbp_bad = true;
                if (insn->id == X86_INS_XCHG && (d0 == "rbp" || d1 == "rbp"))
                    rbp_bad = true;
                break;
            }
            }
        }
        for (const cfg_edge& e : g.blocks[(size_t)b].succ) {
            size_t t = e.to;
            if (!seen[t]) {
                seen[t] = 1;
                in[t] = sp;
                work.push_back((int)t);
            } else if (in[t] != sp && in[t] != unknown) {
                in[t] = unknown;
                work.push_back((int)t);
            }
        }
    }
    cs_free(insn, 1);
    if (rbp_bad)
        rbp_frame_ = false;
}

ep lifter::sym_for(uint64_t a)
{
    std::string n = db_.name_at(a);
    if (!n.empty())
        return e_sym(n, a);
    return e_num(a);
}

ep lifter::mem_address(const x86_op_mem& m, std::unordered_map<std::string, ep>& cur, uint64_t rip, int width)
{
    if (m.base == X86_REG_RIP) {
        uint64_t ea = rip + (uint64_t)m.disp;
        return e_un("&", sym_for(ea));
    }
    int64_t off = 0;
    if (slot_of(m, off)) { // a variable in the stack frame
        std::string nm = frame_var(off, width);
        if (!nm.empty())
            return e_un("&", e_sym(nm));
    }
    ep e;
    if (m.base != X86_REG_INVALID) {
        std::string fam = reg_family(cs_reg_name(cs_, m.base));
        e = fam.empty() ? e_reg(cs_reg_name(cs_, m.base)) : reg_read(cur, fam);
    }
    if (m.index != X86_REG_INVALID) {
        std::string fam = reg_family(cs_reg_name(cs_, m.index));
        ep idx = fam.empty() ? e_reg(cs_reg_name(cs_, m.index)) : reg_read(cur, fam);
        if (m.scale > 1)
            idx = e_bin("*", idx, e_num((uint64_t)m.scale));
        e = e ? e_bin("+", e, idx) : idx;
    }
    if (!e)
        return e_un("&", sym_for((uint64_t)m.disp));
    if (m.disp > 0)
        e = e_bin("+", e, e_num((uint64_t)m.disp));
    else if (m.disp < 0)
        e = e_bin("-", e, e_num((uint64_t)(-m.disp)));
    return e;
}

ep lifter::operand_expr(cs_insn* in, const cs_x86_op& op, std::unordered_map<std::string, ep>& cur)
{
    if (op.type == X86_OP_REG) {
        std::string fam = reg_family(cs_reg_name(cs_, op.reg));
        return fam.empty() ? e_reg(cs_reg_name(cs_, op.reg)) : reg_read(cur, fam);
    }
    if (op.type == X86_OP_IMM) {
        // an address of something in the file (a string, a global, a function): by name
        uint64_t v = (uint64_t)op.imm;
        if (!is64_)
            v &= 0xffffffffull;
        if (v >= 0x10000 && db_.bin.is_mapped(v) && (db_.an.flags_at(v) & (fl_str | fl_data | fl_label | fl_func)) &&
            !db_.name_at(v).empty())
            return e_un("&", sym_for(v));
        return e_num((uint64_t)op.imm, true);
    }
    if (op.type == X86_OP_MEM) {
        uint64_t rip = in->address + in->size;
        return e_mem(mem_address(op.mem, cur, rip, op.size), op.size);
    }
    return e_sym("?");
}

ep lifter::build_cond(const flag_state& fs, unsigned cc_id, bool& ok)
{
    ok = true;
    auto cmp = [&](const char* op) -> ep {
        if (fs.is_cmp && fs.a && fs.b)
            return e_bin(op, fs.a, fs.b);
        if (fs.is_test && fs.a && fs.b) {
            if (print(fs.a) == print(fs.b))
                return e_bin(op, fs.a, e_num(0));
            return e_bin(op, e_bin("&", fs.a, fs.b), e_num(0));
        }
        return e_bin(op, fs.res ? fs.res : e_sym("flags"), e_num(0));
    };
    auto uns = [&](const char* op) -> ep {
        if (fs.is_cmp && fs.a && fs.b)
            return e_bin(op, e_un("(unsigned)", fs.a), e_un("(unsigned)", fs.b));
        return cmp(op);
    };
    switch (cc_id) {
    case X86_INS_JE: return cmp("==");
    case X86_INS_JNE: return cmp("!=");
    case X86_INS_JG: return cmp(">");
    case X86_INS_JGE: return cmp(">=");
    case X86_INS_JL: return cmp("<");
    case X86_INS_JLE: return cmp("<=");
    case X86_INS_JA: return uns(">");
    case X86_INS_JAE: return uns(">=");
    case X86_INS_JB: return uns("<");
    case X86_INS_JBE: return uns("<=");
    case X86_INS_JS: return fs.res ? e_bin("<", fs.res, e_num(0)) : cmp("<");
    case X86_INS_JNS: return fs.res ? e_bin(">=", fs.res, e_num(0)) : cmp(">=");
    default:
        ok = false;
        return e_sym("cond");
    }
}

bool lifter::run(uint64_t func_start, std::vector<block_ir>& out, std::vector<std::string>& params,
                 bool& returns_value)
{
    cfg g;
    if (!build_cfg(db_.bin, db_.an, func_start, g, 800))
        return false;
    cs_insn* insn = cs_malloc(cs_);
    if (!insn)
        return false;

    size_t nb = g.blocks.size();
    out.clear();
    out.resize(nb);
    std::unordered_map<uint64_t, int> block_of;
    for (size_t i = 0; i < nb; i++)
        block_of[g.blocks[i].start] = (int)i;
    bin_format fmt = db_.bin.format;
    returns_value = false;
    bool call_sets_rax = false;
    int entry = block_of.count(func_start) ? block_of[func_start] : 0;

    auto bit = [](const std::string& fam) -> uint32_t {
        int b = reg_bit(fam);
        return b >= 0 ? (1u << b) : 0u;
    };
    // registers a call may change (rax carries the result), and the argument registers
    uint32_t scratch = this->scratch();
    std::vector<uint32_t> arg_bits;
    uint32_t arg_mask = 0;
    if (is64_) {
        for (int i = 0; arg_reg_at(i, is64_, fmt); i++) {
            arg_bits.push_back(bit(arg_reg_at(i, is64_, fmt)));
            arg_mask |= arg_bits.back();
        }
    }
    const uint64_t flag_tests = X86_EFLAGS_TEST_OF | X86_EFLAGS_TEST_SF | X86_EFLAGS_TEST_ZF |
                                X86_EFLAGS_TEST_PF | X86_EFLAGS_TEST_CF | X86_EFLAGS_TEST_AF;
    const uint64_t flag_writes =
        X86_EFLAGS_MODIFY_OF | X86_EFLAGS_MODIFY_SF | X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_MODIFY_PF |
        X86_EFLAGS_MODIFY_CF | X86_EFLAGS_MODIFY_AF | X86_EFLAGS_RESET_OF | X86_EFLAGS_RESET_SF |
        X86_EFLAGS_RESET_ZF | X86_EFLAGS_RESET_PF | X86_EFLAGS_RESET_CF | X86_EFLAGS_RESET_AF |
        X86_EFLAGS_SET_OF | X86_EFLAGS_SET_SF | X86_EFLAGS_SET_ZF | X86_EFLAGS_SET_PF |
        X86_EFLAGS_SET_CF | X86_EFLAGS_SET_AF | X86_EFLAGS_UNDEFINED_OF | X86_EFLAGS_UNDEFINED_SF |
        X86_EFLAGS_UNDEFINED_ZF | X86_EFLAGS_UNDEFINED_PF | X86_EFLAGS_UNDEFINED_CF |
        X86_EFLAGS_UNDEFINED_AF;

    auto same_regs = [&](const cs_x86& x) {
        return x.op_count >= 2 && x.operands[0].type == X86_OP_REG && x.operands[1].type == X86_OP_REG &&
               x.operands[0].reg == x.operands[1].reg;
    };

    frame_pass(g, entry);

    // stack arguments: pushes (32-bit) and stores to the outgoing area ([rsp + 0x20 + 8n] on
    // win64) that a call in the same block takes: they become that call's arguments instead of
    // statements of their own. an argument push reads its register
    std::vector<std::vector<char>> arg_mark(nb);
    std::vector<std::unordered_map<size_t, std::vector<int64_t>>> call_slots(nb); // call -> its argument slots
    for (size_t bi = 0; bi < nb; bi++) {
        const cfg_block& cb = g.blocks[bi];
        size_t ni = cb.insns.size();
        std::vector<char>& is_arg = arg_mark[bi];
        std::unordered_map<size_t, std::vector<int64_t>>& call_stack = call_slots[bi];
        is_arg.assign(ni, 0);
        {
            const int64_t ptr = is64_ ? 8 : 4;
            const bool pe = db_.bin.format == bin_format::pe;
            const int64_t base = is64_ && pe ? 0x20 : 0;
            std::vector<std::pair<size_t, int64_t>> cand; // since the last call: instruction, slot
            bool prologue = (int)bi == entry;
            for (size_t k = 0; k < ni; k++) {
                uint8_t code[16];
                size_t n = db_.bin.read(cb.insns[k], code, sizeof(code));
                const uint8_t* p = code;
                size_t left = n;
                uint64_t addr = cb.insns[k];
                if (!cs_disasm_iter(cs_, &p, &left, &addr, insn))
                    continue;
                const cs_x86& x = insn->detail->x86;
                auto spi = sp_at_.find(cb.insns[k]);
                bool spk = spi != sp_at_.end();
                int64_t sp = spk ? spi->second : 0;
                std::string d0 = x.op_count >= 1 && x.operands[0].type == X86_OP_REG
                    ? reg_family(cs_reg_name(cs_, x.operands[0].reg)) : std::string();
                std::string d1 = x.op_count >= 2 && x.operands[1].type == X86_OP_REG
                    ? reg_family(cs_reg_name(cs_, x.operands[1].reg)) : std::string();
                unsigned id = insn->id;
                bool setup = id == X86_INS_PUSH || id == X86_INS_ENDBR32 || id == X86_INS_ENDBR64 ||
                             (id == X86_INS_MOV && d0 == "rbp" && d1 == "rsp") ||
                             ((id == X86_INS_SUB || id == X86_INS_AND) && d0 == "rsp") || (id == X86_INS_LEA && d0 == "rbp");
                if (id == X86_INS_PUSH) {
                    // the registers a prologue saves aren't arguments
                    static const std::set<std::string> saved = {"rbp", "rbx", "rsi", "rdi", "r12", "r13", "r14", "r15"};
                    bool save = prologue && saved.count(d0);
                    if (!save && !is64_ && spk)
                        cand.push_back({k, sp - ptr});
                } else if (id == X86_INS_MOV && x.op_count == 2 && x.operands[0].type == X86_OP_MEM && spk &&
                           x.operands[0].mem.index == X86_REG_INVALID && x.operands[0].mem.base != X86_REG_INVALID &&
                           reg_family(cs_reg_name(cs_, x.operands[0].mem.base)) == "rsp") {
                    cand.push_back({k, sp + x.operands[0].mem.disp});
                } else if (id == X86_INS_CALL) {
                    int nargs = stack_args_of(insn);
                    if (spk && nargs < 0 && (!is64_ || pe)) {
                        // not known: the ones that line up from the call's stack pointer
                        nargs = 0;
                        for (bool more = true; more; nargs += more ? 1 : 0) {
                            more = false;
                            for (const auto& c : cand)
                                more = more || c.second == sp + base + ptr * nargs;
                        }
                    }
                    std::vector<int64_t> slots;
                    for (int i = 0; spk && i < nargs; i++) {
                        int64_t want = sp + base + ptr * i;
                        slots.push_back(want);
                        for (size_t c = cand.size(); c-- > 0;)
                            if (cand[c].second == want) {
                                is_arg[cand[c].first] = 1;
                                break;
                            }
                    }
                    if (!slots.empty())
                        call_stack[k] = slots;
                    cand.clear();
                }
                if (!setup)
                    prologue = false;
            }
        }
    }

    // pass 1: what each instruction reads and writes
    std::vector<std::vector<insn_rw>> rws(nb);
    for (size_t bi = 0; bi < nb; bi++) {
        const cfg_block& cb = g.blocks[bi];
        out[bi].start = cb.start;
        out[bi].end = cb.end;
        for (uint64_t a : cb.insns) {
            insn_rw r;
            uint8_t code[16];
            size_t n = db_.bin.read(a, code, sizeof(code));
            const uint8_t* p = code;
            size_t left = n;
            uint64_t addr = a;
            if (cs_disasm_iter(cs_, &p, &left, &addr, insn)) {
                r.rd = access(insn, r.wr);
                const cs_x86& x = insn->detail->x86;
                if (insn->id == X86_INS_PUSH && arg_mark[bi][rws[bi].size()] && x.op_count >= 1 && x.operands[0].type == X86_OP_REG) {
                    int b = reg_bit(reg_family(cs_reg_name(cs_, x.operands[0].reg)));
                    if (b >= 0)
                        r.rd |= 1u << b; // an argument: its value is used
                }
                if (insn->id == X86_INS_CALL) {
                    r.call = true;
                    r.flags_wr = true;
                    if (x.op_count >= 1 && x.operands[0].type == X86_OP_IMM) {
                        r.target = (uint64_t)x.operands[0].imm;
                        const callee_info& ci = callee_of(r.target);
                        r.wr = (r.wr & ~scratch) | ci.clobbers;
                        for (int i = 0; i < ci.arity && i < (int)arg_bits.size(); i++)
                            r.rd |= arg_bits[i]; // it reads its arguments
                    }
                    // a prototype says which argument registers it reads
                    const prototype* pr = call_proto(insn);
                    if (pr && !pr->variadic) {
                        r.proto_args = (int)pr->params.size();
                        for (int i = 0; i < r.proto_args && i < (int)arg_bits.size(); i++)
                            r.rd |= arg_bits[i];
                    }
                    if (r.wr & 1u)
                        call_sets_rax = true;
                } else if (insn->id == X86_INS_JMP && x.op_count >= 1 && x.operands[0].type == X86_OP_IMM &&
                           !block_of.count((uint64_t)x.operands[0].imm)) {
                    // a jump out of the function: a tail call, the callee's result is ours
                    r.tail = true;
                    r.target = (uint64_t)x.operands[0].imm;
                    const callee_info& ci = callee_of(r.target);
                    for (int i = 0; i < ci.arity && i < (int)arg_bits.size(); i++)
                        r.rd |= arg_bits[i];
                    if (ci.clobbers & 1u)
                        call_sets_rax = true;
                } else {
                    if (insn->id == X86_INS_JMP && x.op_count >= 1 && x.operands[0].type == X86_OP_MEM &&
                        !db_.an.tables.count(a))
                        r.tail = true; // jmp [ptr]: a tail call through a pointer
                    if (r.wr & 1u)
                        returns_value = true; // rax written somewhere -> assume it returns a value
                    if (!cs_insn_group(cs_, insn, X86_GRP_FPU)) {
                        uint64_t ef = insn->detail->x86.eflags;
                        r.flags_rd = (ef & flag_tests) != 0;
                        r.flags_wr = (ef & flag_writes) != 0;
                    }
                }
                r.ret = cs_insn_group(cs_, insn, X86_GRP_RET);
            }
            rws[bi].push_back(r);
        }
    }
    // callers settle whether there is a result: rax read after the call. without callers,
    // guess from rax being written
    int used = result_used(func_start);
    if (used >= 0)
        returns_value = used == 1 && (returns_value || call_sets_rax); // nothing sets rax: void
    // a ret reads the return value
    if (returns_value)
        for (auto& v : rws)
            if (!v.empty() && v.back().ret)
                v.back().rd |= 1u;

    std::vector<std::vector<int>> succ(nb), pred(nb);
    for (size_t bi = 0; bi < nb; bi++)
        for (const cfg_edge& e : g.blocks[bi].succ) {
            succ[bi].push_back((int)e.to);
            pred[e.to].push_back((int)bi);
        }
    auto liveness = [&]() {
        for (size_t bi = 0; bi < nb; bi++) {
            uint32_t def = 0, use = 0;
            for (const insn_rw& r : rws[bi]) {
                use |= r.rd & ~def;
                def |= r.wr;
            }
            out[bi].def = def;
            out[bi].use = use;
            out[bi].live_in = out[bi].live_out = 0;
        }
        bool changed = true;
        int guard = 0;
        while (changed && guard++ < 20000) {
            changed = false;
            for (size_t bi = 0; bi < nb; bi++) {
                uint32_t o = 0;
                for (int s : succ[bi])
                    o |= out[s].live_in;
                uint32_t in = out[bi].use | (o & ~out[bi].def);
                if (o != out[bi].live_out || in != out[bi].live_in) {
                    out[bi].live_out = o;
                    out[bi].live_in = in;
                    changed = true;
                }
            }
        }
    };
    liveness();

    // parameters: up to the last argument register read before being written (one that is
    // only passed along still counts as a parameter)
    int nparams = 0;
    for (int i = 0; arg_reg_at(i, is64_, fmt); i++)
        if (out[entry].live_in & bit(arg_reg_at(i, is64_, fmt)))
            nparams = i + 1;
    for (int i = 0; i < nparams; i++) {
        params_.insert(arg_reg_at(i, is64_, fmt));
        params.push_back(disp(arg_reg_at(i, is64_, fmt)));
    }

    // call arguments: the argument registers something set since the last call (a
    // parameter counts as set), as a prefix. calls read them, so the values survive until
    // the call even across a block boundary.
    std::vector<uint32_t> set_in(nb, 0);
    if (!arg_bits.empty()) {
        uint32_t param_bits = 0;
        for (const std::string& pr : params_)
            param_bits |= bit(pr);
        std::vector<uint32_t> set_out(nb, 0);
        auto walk = [&](size_t bi, uint32_t s, bool apply) {
            for (insn_rw& r : rws[bi]) {
                if (r.call || r.tail) {
                    // a known callee's arguments are already counted
                    bool known = (r.target && callee_of(r.target).arity >= 0) || r.proto_args >= 0;
                    for (size_t i = 0; apply && !known && i < arg_bits.size() && (s & arg_bits[i]); i++)
                        r.rd |= arg_bits[i];
                    if (r.call)
                        s &= ~r.wr;
                } else {
                    s |= r.wr & arg_mask;
                }
            }
            return s;
        };
        bool changed = true;
        int guard = 0;
        while (changed && guard++ < 20000) {
            changed = false;
            for (size_t bi = 0; bi < nb; bi++) {
                uint32_t in = (int)bi == entry ? param_bits : 0;
                for (int p : pred[bi])
                    in |= set_out[p];
                uint32_t o = walk(bi, in, false);
                if (in != set_in[bi] || o != set_out[bi]) {
                    set_in[bi] = in;
                    set_out[bi] = o;
                    changed = true;
                }
            }
        }
        for (size_t bi = 0; bi < nb; bi++)
            walk(bi, set_in[bi], true);
        liveness();
    }

    // pass 2: statements. a register's new value stays pending - an expression, not yet a
    // statement - until it has to be written out: a later block reads it, it grew big, a
    // call or store may change memory it reads, or its register is about to change while
    // another pending value still reads the old one. pending expressions always mean the
    // registers as the statements printed so far left them.
    int temps = 0;
    for (size_t bi = 0; bi < nb; bi++) {
        const cfg_block& cb = g.blocks[bi];
        block_ir& ir = out[bi];
        const std::vector<insn_rw>& rw = rws[bi];
        size_t ni = cb.insns.size();

        std::unordered_map<std::string, ep> cur;
        std::unordered_map<std::string, size_t> born; // instruction that set a pending value
        for (const std::string& pr : params_)
            cur[pr] = e_reg(disp(pr));
        flag_state fs;
        uint32_t argset = set_in[bi];

        // this block's stack arguments (see the pass before pass 1)
        std::vector<char>& is_arg = arg_mark[bi];
        std::unordered_map<size_t, std::vector<int64_t>>& call_stack = call_slots[bi];
        std::map<int64_t, std::pair<ep, uint64_t>> out_args; // frame offset -> value, where it was set

        // liveness after each instruction, and whether the flags are still to be tested
        std::vector<uint32_t> live_after(ni, 0);
        std::vector<char> flags_after(ni, 0);
        {
            uint32_t live = ir.live_out;
            bool fl = false;
            for (size_t k = ni; k-- > 0;) {
                live_after[k] = live;
                flags_after[k] = fl;
                live = (live & ~rw[k].wr) | rw[k].rd;
                if (rw[k].flags_rd)
                    fl = true;
                else if (rw[k].flags_wr)
                    fl = false;
            }
        }

        struct asg {
            std::string fam;
            ep val;
        };
        auto line = [&](uint64_t at, const std::string& s) { ir.stmts.push_back({at, s}); };
        auto pending = [&](const std::string& fam) {
            if (fam == "rsp")
                return false;
            auto it = cur.find(fam);
            if (it == cur.end() || !it->second)
                return false;
            return !(it->second->kind == expr::k::reg && it->second->text == disp(fam));
        };

        // write `todo` out as statements. the values are parallel - each is what it was before
        // any of them is assigned - and `readers` (expressions printed or kept after this) keep
        // their meaning. `spare` are dead values a reader may still contain: naming one can
        // break a conflict, a temp is the last resort. returns the registers assigned.
        auto emit_batch = [&](uint64_t at, std::vector<asg> todo, std::vector<ep*> readers,
                              std::vector<asg> spare) {
            std::vector<std::string> done;
            auto age = [&](const std::string& f) {
                auto it = born.find(f);
                return it == born.end() ? (size_t)0 : it->second;
            };
            std::stable_sort(todo.begin(), todo.end(),
                             [&](const asg& x, const asg& y) { return age(x.fam) < age(y.fam); });
            auto rewrite = [&](auto f) {
                std::vector<ep*> hs;
                for (asg& t : todo)
                    hs.push_back(&t.val);
                for (asg& s : spare)
                    hs.push_back(&s.val);
                for (ep* r : readers)
                    hs.push_back(r);
                std::vector<ep> keep; // old trees stay alive while the memo points into them
                for (ep* h : hs)
                    keep.push_back(*h);
                rewrite_memo memo;
                for (ep* h : hs)
                    *h = f(*h, memo);
            };
            // would assigning a's register change what another value reads?
            auto conflicts = [&](const asg& a) {
                std::string nm = disp(a.fam);
                for (const asg& t : todo)
                    if (&t != &a && refs_name(t.val, nm, a.val.get()))
                        return true;
                for (ep* r : readers)
                    if (refs_name(*r, nm, a.val.get()))
                        return true;
                return false;
            };
            auto commit = [&](asg a) {
                std::string nm = disp(a.fam);
                line(at, nm + " = " + print(a.val) + ";");
                done.push_back(a.fam);
                // dead values that read the old register can't be named any more
                spare.erase(std::remove_if(spare.begin(), spare.end(),
                                           [&](const asg& s) { return refs_name(s.val, nm, a.val.get()); }),
                            spare.end());
                ep named = e_reg(nm);
                const expr* node = a.val.get();
                rewrite([&](const ep& e, rewrite_memo& memo) { return replace_node(e, node, named, memo); });
            };
            while (!todo.empty()) {
                size_t pick = todo.size();
                for (size_t k = 0; k < todo.size() && pick == todo.size(); k++)
                    if (!conflicts(todo[k]))
                        pick = k;
                if (pick < todo.size()) {
                    asg a = todo[pick];
                    todo.erase(todo.begin() + (std::ptrdiff_t)pick);
                    commit(a);
                    continue;
                }
                size_t sp = spare.size();
                for (size_t k = 0; k < spare.size() && sp == spare.size(); k++) {
                    bool held = false;
                    for (const asg& t : todo)
                        held = held || contains(t.val, spare[k].val.get());
                    for (ep* r : readers)
                        held = held || contains(*r, spare[k].val.get());
                    if (held && !conflicts(spare[k]))
                        sp = k;
                }
                if (sp < spare.size()) {
                    asg a = spare[sp];
                    spare.erase(spare.begin() + (std::ptrdiff_t)sp);
                    commit(a);
                    continue;
                }
                // a cycle: keep the old value of the first register in a temp
                std::string nm = disp(todo[0].fam);
                std::string t = "tmp" + std::to_string(++temps);
                line(at, t + " = " + nm + ";");
                ep tv = e_reg(t);
                rewrite([&](const ep& e, rewrite_memo& memo) { return replace_reg(e, nm, tv, memo); });
            }
            return done;
        };

        // write out the pending values of `fams` at instruction k. live pending values that
        // read one of them, or a register in `clobber` (about to be changed by a statement the
        // caller prints next), are written out with them. `extra` are more readers.
        auto settle = [&](size_t k, const std::vector<std::string>& fams, const std::vector<std::string>& clobber,
                          std::vector<ep*> extra) {
            uint32_t live = live_after[k];
            std::set<std::string> in(fams.begin(), fams.end());
            std::vector<std::string> changing = clobber;
            changing.insert(changing.end(), fams.begin(), fams.end());
            for (bool grew = true; grew;) {
                grew = false;
                for (auto& kv : cur) {
                    if (in.count(kv.first) || !pending(kv.first) || !(live & bit(kv.first)))
                        continue;
                    for (const std::string& c : changing)
                        if (refs_name(kv.second, disp(c), nullptr)) {
                            in.insert(kv.first);
                            changing.push_back(kv.first);
                            grew = true;
                            break;
                        }
                }
            }
            std::vector<asg> todo, spare;
            std::vector<ep*> readers = std::move(extra);
            if (flags_after[k])
                for (ep* f : {&fs.a, &fs.b, &fs.res})
                    if (*f)
                        readers.push_back(f);
            for (auto& oa : out_args)
                readers.push_back(&oa.second.first);
            for (auto& kv : cur) {
                if (!pending(kv.first))
                    continue;
                if (in.count(kv.first))
                    todo.push_back({kv.first, kv.second});
                else if (live & bit(kv.first))
                    readers.push_back(&kv.second);
                else
                    spare.push_back({kv.first, kv.second});
            }
            if (todo.empty())
                return;
            std::vector<std::string> done = emit_batch(cb.insns[k], todo, readers, spare);
            for (const std::string& f : done) {
                cur[f] = e_reg(disp(f));
                born.erase(f);
            }
            // dead values that read a register that just changed are stale now
            for (auto it = cur.begin(); it != cur.end();) {
                bool stale = false;
                if (pending(it->first) && !(live & bit(it->first)))
                    for (const std::string& f : done)
                        stale = stale || refs_name(it->second, disp(f), nullptr);
                it = stale ? cur.erase(it) : std::next(it);
            }
        };

        // flags still to be tested must not read memory about to change (mem) or a register
        // about to change (clobber): those parts are computed into temps now
        auto pin_flags = [&](size_t k, const std::vector<std::string>& clobber, bool mem) {
            if (!flags_after[k])
                return;
            std::vector<std::pair<const expr*, ep>> made;
            for (ep* f : {&fs.a, &fs.b, &fs.res}) {
                if (!*f)
                    continue;
                bool bad = mem && has_mem(*f);
                for (const std::string& c : clobber)
                    bad = bad || refs_name(*f, disp(c), nullptr);
                if (!bad)
                    continue;
                ep t;
                for (auto& m : made)
                    if (m.first == f->get())
                        t = m.second;
                if (!t) {
                    std::string nm = "tmp" + std::to_string(++temps);
                    line(cb.insns[k], nm + " = " + print(*f) + ";");
                    t = e_reg(nm);
                    made.push_back({f->get(), t});
                }
                *f = t;
            }
        };

        // new register values at instruction k (all read before any is set)
        auto assign_all = [&](size_t k, const std::vector<asg>& vals) {
            std::vector<std::string> big;
            for (const asg& v : vals) {
                if (v.fam.empty() || !v.val)
                    continue;
                // the stack pointer, and rbp as a frame pointer, are always shown by name
                bool frame = v.fam == "rbp" && ((v.val->kind == expr::k::reg && v.val->text == disp("rsp")) || rbp_frame_);
                if (v.fam == "rsp" || frame) {
                    cur.erase(v.fam);
                    continue;
                }
                cur[v.fam] = v.val;
                born[v.fam] = k;
                if (node_count(v.val) > 6 && (live_after[k] & bit(v.fam)))
                    big.push_back(v.fam);
            }
            if (!big.empty())
                settle(k, big, {}, {});
        };
        auto assign = [&](size_t k, const std::string& fam, ep v) { assign_all(k, {{fam, std::move(v)}}); };

        // stack arguments no call took: stores to their slots after all
        auto flush_args = [&]() {
            std::map<int64_t, std::pair<ep, uint64_t>> left;
            left.swap(out_args);
            for (auto& kv : left) {
                std::string nm = frame_var(kv.first, is64_ ? 8 : 4);
                line(kv.second.second, (nm.empty() ? std::string("?") : nm) + " = " + print(kv.second.first) + ";");
            }
        };
        // a store or a call may change memory: pending values that read it go out first
        auto barrier = [&](size_t k, std::vector<ep*> extra) {
            flush_args();
            std::vector<std::string> fams;
            for (auto& kv : cur)
                if (pending(kv.first) && (live_after[k] & bit(kv.first)) && has_mem(kv.second))
                    fams.push_back(kv.first);
            settle(k, fams, {}, std::move(extra));
            pin_flags(k, {}, true);
            for (auto it = cur.begin(); it != cur.end();) {
                bool stale = pending(it->first) && !(live_after[k] & bit(it->first)) && has_mem(it->second);
                it = stale ? cur.erase(it) : std::next(it);
            }
        };
        auto store = [&](size_t k, ep dst, const std::string& op, ep src) {
            barrier(k, {&dst, &src});
            line(cb.insns[k], print(dst) + " " + op + " " + print(src) + ";");
            return dst;
        };

        // an instruction the lifter doesn't model: printed as is, after the registers it
        // reads hold their values and nothing pending reads a register it changes
        auto opaque = [&](size_t k, cs_insn* in) {
            flush_args();
            const insn_rw& r = rw[k];
            std::vector<std::string> reads, writes;
            for (int b = 0; b < 16; b++) {
                std::string fam = fam_name(b);
                if (fam == "rsp")
                    continue;
                if ((r.rd & (1u << b)) && pending(fam))
                    reads.push_back(fam);
                if (r.wr & (1u << b))
                    writes.push_back(fam);
            }
            for (const std::string& w : writes)
                if (!(r.rd & bit(w)))
                    cur.erase(w); // overwritten without being read
            bool writes_mem = false;
            const cs_x86& xx = in->detail->x86;
            for (uint8_t i = 0; i < xx.op_count; i++)
                if (xx.operands[i].type == X86_OP_MEM && (xx.operands[i].access & CS_AC_WRITE))
                    writes_mem = true;
            if (writes_mem)
                barrier(k, {});
            settle(k, reads, writes, {});
            pin_flags(k, writes, false);
            std::string text = std::string("__asm { ") + in->mnemonic;
            if (in->op_str[0])
                text += std::string(" ") + in->op_str;
            line(in->address, text + " }");
            for (const std::string& w : writes) {
                cur[w] = e_reg(disp(w));
                born.erase(w);
            }
            for (auto it = cur.begin(); it != cur.end();) {
                bool stale = false;
                if (pending(it->first))
                    for (const std::string& w : writes)
                        stale = stale || refs_name(it->second, disp(w), nullptr);
                it = stale ? cur.erase(it) : std::next(it);
            }
        };

        for (size_t k = 0; k < ni; k++) {
            uint64_t a = cb.insns[k];
            uint8_t code[16];
            size_t n = db_.bin.read(a, code, sizeof(code));
            const uint8_t* p = code;
            size_t left = n;
            uint64_t addr = a;
            if (!cs_disasm_iter(cs_, &p, &left, &addr, insn))
                continue;
            cs_x86& x = insn->detail->x86;
            unsigned id = insn->id;
            bool last = k + 1 == ni;
            auto spi = sp_at_.find(a);
            cur_sp_known_ = spi != sp_at_.end();
            cur_sp_ = cur_sp_known_ ? spi->second : 0;
            // flags this instruction replaces without reading are dead from here on
            if (rw[k].flags_wr && !rw[k].flags_rd)
                fs = {};
            bool fs_set = false;

            auto reg_of = [&](const cs_x86_op& op) {
                return op.type == X86_OP_REG ? reg_family(cs_reg_name(cs_, op.reg)) : std::string();
            };
            auto val = [&](const cs_x86_op& op) { return operand_expr(insn, op, cur); };
            auto result_flags = [&](ep r) {
                fs = {};
                fs.valid = true;
                fs.res = std::move(r);
                fs_set = true;
            };
            auto arith = [&](const char* op) {
                if (x.op_count < 1)
                    return;
                ep d = val(x.operands[0]);
                ep s = x.op_count >= 2 ? val(x.operands[1]) : e_num(1);
                if (x.operands[0].type == X86_OP_REG) {
                    ep r = e_bin(op, d, s);
                    result_flags(r);
                    assign(k, reg_of(x.operands[0]), r);
                } else if (x.operands[0].type == X86_OP_MEM) {
                    result_flags(store(k, d, std::string(op) + "=", s)); // the result is in memory now
                }
            };
            // one-operand mul / imul / div / idiv work on rdx:rax
            auto wide = [&](bool div) {
                ep v = reg_read(cur, "rax"), s = val(x.operands[0]);
                if (div)
                    assign_all(k, {{"rax", e_bin("/", v, s)}, {"rdx", e_bin("%", v, s)}});
                else
                    assign_all(k, {{"rax", e_bin("*", v, s)}, {"rdx", e_intr("__mulhi", {v, s})}});
            };

            switch (id) {
            case X86_INS_PUSH:
                if (is_arg[k] && x.op_count >= 1 && cur_sp_known_)
                    out_args[cur_sp_ - (is64_ ? 8 : 4)] = {val(x.operands[0]), a};
                break;
            case X86_INS_NOP:
            case X86_INS_ENDBR32:
            case X86_INS_ENDBR64:
            case X86_INS_POP:
            case X86_INS_LEAVE:
            case X86_INS_CDQE:
            case X86_INS_CWDE:
            case X86_INS_CBW:
                break;
            case X86_INS_MOV:
            case X86_INS_MOVZX:
            case X86_INS_MOVSX:
            case X86_INS_MOVSXD:
            case X86_INS_MOVABS:
                if (x.op_count >= 2) {
                    ep s = val(x.operands[1]);
                    int64_t off = 0;
                    if (x.operands[0].type == X86_OP_REG)
                        assign(k, reg_of(x.operands[0]), s);
                    else if (x.operands[0].type == X86_OP_MEM && is_arg[k] && slot_of(x.operands[0].mem, off))
                        out_args[off] = {s, a}; // a stack argument of the next call
                    else if (x.operands[0].type == X86_OP_MEM)
                        store(k, val(x.operands[0]), "=", s);
                }
                break;
            case X86_INS_LEA:
                if (x.op_count >= 2 && x.operands[1].type == X86_OP_MEM)
                    assign(k, reg_of(x.operands[0]),
                           mem_address(x.operands[1].mem, cur, insn->address + insn->size));
                break;
            case X86_INS_ADD: arith("+"); break;
            case X86_INS_AND: arith("&"); break;
            case X86_INS_OR: arith("|"); break;
            case X86_INS_SHL:
            case X86_INS_SAL: arith("<<"); break;
            case X86_INS_SHR:
            case X86_INS_SAR: arith(">>"); break;
            case X86_INS_SUB:
            case X86_INS_XOR:
                if (same_regs(x)) {
                    result_flags(e_num(0));
                    assign(k, reg_of(x.operands[0]), e_num(0));
                } else {
                    arith(id == X86_INS_SUB ? "-" : "^");
                }
                break;
            case X86_INS_IMUL:
                if (x.op_count == 3) {
                    ep r = e_bin("*", val(x.operands[1]), val(x.operands[2]));
                    result_flags(r);
                    assign(k, reg_of(x.operands[0]), r);
                } else if (x.op_count == 2) {
                    arith("*");
                } else if (x.op_count == 1) {
                    wide(false);
                }
                break;
            case X86_INS_MUL:
                if (x.op_count == 1)
                    wide(false);
                break;
            case X86_INS_DIV:
            case X86_INS_IDIV:
                if (x.op_count == 1)
                    wide(true);
                break;
            case X86_INS_INC:
            case X86_INS_DEC:
                if (x.op_count >= 1) {
                    const char* op = id == X86_INS_INC ? "+" : "-";
                    if (x.operands[0].type == X86_OP_REG) {
                        ep r = e_bin(op, val(x.operands[0]), e_num(1));
                        result_flags(r);
                        assign(k, reg_of(x.operands[0]), r);
                    } else if (x.operands[0].type == X86_OP_MEM) {
                        result_flags(store(k, val(x.operands[0]), std::string(op) + "=", e_num(1)));
                    }
                }
                break;
            case X86_INS_NEG:
            case X86_INS_NOT:
                if (x.op_count >= 1) {
                    const char* op = id == X86_INS_NEG ? "-" : "~";
                    ep d = val(x.operands[0]);
                    ep r = e_un(op, d);
                    if (x.operands[0].type == X86_OP_REG) {
                        if (id == X86_INS_NEG)
                            result_flags(r);
                        assign(k, reg_of(x.operands[0]), r);
                    } else if (x.operands[0].type == X86_OP_MEM) {
                        ep m = store(k, d, "=", r);
                        if (id == X86_INS_NEG)
                            result_flags(m);
                    }
                }
                break;
            case X86_INS_CMP:
            case X86_INS_TEST:
                if (x.op_count >= 2) {
                    fs = {};
                    fs.valid = true;
                    fs.is_cmp = id == X86_INS_CMP;
                    fs.is_test = id == X86_INS_TEST;
                    fs.a = val(x.operands[0]);
                    fs.b = val(x.operands[1]);
                    fs_set = true;
                }
                break;
            case X86_INS_CDQ:
            case X86_INS_CQO:
            case X86_INS_CWD:
                // the sign of rax into rdx, for a following idiv
                assign(k, "rdx", e_bin(">>", reg_read(cur, "rax"),
                                       e_num(id == X86_INS_CQO ? 63 : id == X86_INS_CDQ ? 31 : 15)));
                break;
            case X86_INS_XCHG: {
                std::string fa = x.op_count == 2 ? reg_of(x.operands[0]) : std::string();
                std::string fb = x.op_count == 2 ? reg_of(x.operands[1]) : std::string();
                if (!fa.empty() && !fb.empty()) {
                    if (fa != fb)
                        assign_all(k, {{fa, reg_read(cur, fb)}, {fb, reg_read(cur, fa)}});
                } else {
                    opaque(k, insn);
                }
                break;
            }
            case X86_INS_ROL:
            case X86_INS_ROR:
            case X86_INS_BSWAP:
                if (x.op_count >= 1 && x.operands[0].type == X86_OP_REG) {
                    std::vector<ep> args{val(x.operands[0])};
                    if (id != X86_INS_BSWAP)
                        args.push_back(x.op_count >= 2 ? val(x.operands[1]) : e_num(1));
                    const char* nm = id == X86_INS_ROL ? "__rol" : id == X86_INS_ROR ? "__ror" : "__bswap";
                    assign(k, reg_of(x.operands[0]), e_intr(nm, std::move(args)));
                } else {
                    opaque(k, insn);
                }
                break;
            case X86_INS_POPCNT:
            case X86_INS_LZCNT:
            case X86_INS_TZCNT:
            case X86_INS_BSF:
            case X86_INS_BSR:
                if (x.op_count >= 2 && x.operands[0].type == X86_OP_REG) {
                    std::string nm = std::string("__") + insn->mnemonic;
                    assign(k, reg_of(x.operands[0]), e_intr(nm, {val(x.operands[1])}));
                } else {
                    opaque(k, insn);
                }
                break;
            case X86_INS_CALL: {
                auto ce = std::make_shared<expr>();
                ce->kind = expr::k::call;
                std::string pname;
                uint64_t pref = 0;
                const prototype* pr = call_proto(insn, &pname, &pref);
                if (x.op_count >= 1 && x.operands[0].type == X86_OP_IMM) {
                    uint64_t target = (uint64_t)x.operands[0].imm;
                    std::string nm = db_.name_at(target);
                    ce->text = nm.empty() ? db_.location(target) : nm;
                    ce->ref = target;
                } else if (!pname.empty()) {
                    ce->text = pname; // call [CreateFileW]: the import, by name
                    ce->ref = pref;
                } else if (x.op_count >= 1) {
                    ce->indirect = true;
                    ce->kids.push_back(val(x.operands[0]));
                } else {
                    ce->text = "(*indirect)";
                }
                // arguments: what the prototype or a known callee reads, else what was set since
                // the last call; then the ones on the stack
                int known = pr && !pr->variadic ? (int)pr->params.size() : rw[k].target ? callee_of(rw[k].target).arity : -1;
                size_t in_regs = 0;
                for (size_t i = 0; i < arg_bits.size(); i++) {
                    if (known >= 0 ? (int)i >= known : !(argset & arg_bits[i]))
                        break;
                    ce->kids.push_back(reg_read(cur, fam_name(low_bit(arg_bits[i]))));
                    in_regs++;
                }
                auto stk = call_stack.find(k);
                if (stk != call_stack.end() && (!is64_ || in_regs == arg_bits.size()))
                    for (int64_t off : stk->second) {
                        auto oa = out_args.find(off);
                        if (oa != out_args.end()) {
                            ce->kids.push_back(oa->second.first);
                            out_args.erase(oa);
                        } else {
                            std::string nm = frame_var(off, is64_ ? 8 : 4);
                            ce->kids.push_back(nm.empty() ? e_sym("?") : e_mem(e_un("&", e_sym(nm)), is64_ ? 8 : 4));
                        }
                    }
                ep call = ce;
                barrier(k, {&call});
                uint32_t clob = rw[k].wr & scratch;
                if ((live_after[k] & 1u) && (clob & 1u)) {
                    // the result is used: "rax = f(...);"
                    cur["rax"] = call;
                    born["rax"] = k;
                    settle(k, {"rax"}, {}, {});
                } else {
                    line(a, print(call) + ";");
                    if (clob & 1u)
                        cur.erase("rax");
                }
                // the callee may change these scratch registers
                for (auto it = cur.begin(); it != cur.end();) {
                    bool gone = (bit(it->first) & clob) && it->first != "rax";
                    it = gone ? cur.erase(it) : std::next(it);
                }
                argset &= ~clob;
                fs = {};
                fs_set = true;
                break;
            }
            case X86_INS_RET:
            case X86_INS_RETF:
                break;
            default: {
                bool is_set = false;
                unsigned cc = jcc_for(id, is_set);
                if (cc) {
                    bool ok = false;
                    ep c = build_cond(fs, cc, ok);
                    if (ok && is_set && x.op_count >= 1 && x.operands[0].type == X86_OP_REG) {
                        assign(k, reg_of(x.operands[0]), c);
                        break;
                    }
                    if (ok && is_set && x.op_count >= 1 && x.operands[0].type == X86_OP_MEM) {
                        store(k, val(x.operands[0]), "=", c);
                        break;
                    }
                    if (ok && !is_set && x.op_count >= 2 && x.operands[0].type == X86_OP_REG) {
                        assign(k, reg_of(x.operands[0]), e_tern(c, val(x.operands[1]), val(x.operands[0])));
                        break;
                    }
                }
                if (cs_insn_group(cs_, insn, X86_GRP_JUMP) || cs_insn_group(cs_, insn, X86_GRP_RET))
                    break;
                if (rw[k].wr & ~bit("rsp")) {
                    opaque(k, insn);
                } else {
                    for (uint8_t i = 0; i < x.op_count; i++)
                        if (x.operands[i].type == X86_OP_MEM && (x.operands[i].access & CS_AC_WRITE)) {
                            barrier(k, {}); // e.g. an sse store: not shown, but memory changed
                            break;
                        }
                }
                break;
            }
            }
            if (rw[k].flags_wr && !fs_set)
                fs = {};
            if (!rw[k].call)
                argset |= rw[k].wr & arg_mask;

            if (last) {
                if (cs_insn_group(cs_, insn, X86_GRP_RET)) {
                    ir.term = term_kind::ret;
                    if (returns_value)
                        ir.cond = reg_read(cur, "rax");
                } else if (id == X86_INS_JMP) {
                    if (x.op_count >= 1 && x.operands[0].type == X86_OP_IMM &&
                        !block_of.count((uint64_t)x.operands[0].imm)) {
                        // a jump out of the function: a tail call
                        uint64_t t = (uint64_t)x.operands[0].imm;
                        auto ce = std::make_shared<expr>();
                        ce->kind = expr::k::call;
                        std::string nm = db_.name_at(t);
                        ce->text = nm.empty() ? db_.location(t) : nm;
                        ce->ref = t;
                        int known = callee_of(t).arity;
                        for (size_t i = 0; i < arg_bits.size(); i++) {
                            if (known >= 0 ? (int)i >= known : !(argset & arg_bits[i]))
                                break;
                            ce->kids.push_back(reg_read(cur, fam_name(low_bit(arg_bits[i]))));
                        }
                        ir.term = term_kind::indirect;
                        ir.cond = ce;
                    } else if (x.op_count >= 1 && x.operands[0].type == X86_OP_IMM) {
                        ir.term = term_kind::jump;
                        ir.fall = (uint64_t)x.operands[0].imm;
                    } else {
                        auto t = db_.an.tables.find(a);
                        if (t != db_.an.tables.end()) {
                            ir.term = term_kind::sw;
                            ir.table = &t->second;
                            std::string fam = t->second.index_reg
                                ? reg_family(cs_reg_name(cs_, t->second.index_reg)) : std::string();
                            if (!fam.empty())
                                ir.cond = reg_read(cur, fam);
                            else if (x.op_count >= 1)
                                ir.cond = val(x.operands[0]);
                        } else {
                            ir.term = term_kind::indirect;
                            if (x.op_count >= 1 && x.operands[0].type == X86_OP_MEM) {
                                // jmp [ptr] leaving the function: a tail call through a pointer
                                // (an import's slot: that import, by name)
                                auto ce = std::make_shared<expr>();
                                ce->kind = expr::k::call;
                                std::string pname;
                                uint64_t pref = 0;
                                const prototype* pr = call_proto(insn, &pname, &pref);
                                if (!pname.empty()) {
                                    ce->text = pname;
                                    ce->ref = pref;
                                } else {
                                    ce->indirect = true;
                                    ce->kids.push_back(val(x.operands[0]));
                                }
                                int known = pr && !pr->variadic ? (int)pr->params.size() : -1;
                                for (size_t i = 0; i < arg_bits.size(); i++) {
                                    if (known >= 0 ? (int)i >= known : !(argset & arg_bits[i]))
                                        break;
                                    ce->kids.push_back(reg_read(cur, fam_name(low_bit(arg_bits[i]))));
                                }
                                ir.cond = ce;
                            } else if (x.op_count >= 1) {
                                ir.cond = val(x.operands[0]); // the jump target
                            }
                        }
                    }
                } else if (cs_insn_group(cs_, insn, X86_GRP_JUMP)) {
                    bool ok = false;
                    ir.term = term_kind::cond;
                    ir.cond = build_cond(fs, id, ok);
                    if (x.op_count >= 1 && x.operands[0].type == X86_OP_IMM)
                        ir.taken = (uint64_t)x.operands[0].imm;
                    ir.fall = ir.end;
                } else if (id == X86_INS_CALL && db_.an.noret_calls.count(a)) {
                    ir.term = term_kind::noreturn;
                }
            }
        }
        if (ir.term == term_kind::fallthrough)
            ir.fall = ir.end;
        flush_args();

        // values a later block reads become statements at the end of this one
        {
            std::vector<asg> todo, spare;
            for (auto& kv : cur) {
                if (!pending(kv.first))
                    continue;
                if (ir.live_out & bit(kv.first))
                    todo.push_back({kv.first, kv.second});
                else
                    spare.push_back({kv.first, kv.second});
            }
            std::vector<ep*> readers;
            if (ir.cond)
                readers.push_back(&ir.cond);
            if (!todo.empty())
                emit_batch(ni ? cb.insns.back() : cb.start, todo, readers, spare);
        }
    }

    // switch variable: prefer the operand of the guarding "cmp idx, n / ja default"
    // in a predecessor block - that names the real index, not the table temp.
    for (block_ir& sw : out) {
        if (sw.term != term_kind::sw)
            continue;
        for (const block_ir& pb : out) {
            bool goes_to_sw = (pb.term == term_kind::cond && (pb.taken == sw.start || pb.fall == sw.start)) ||
                              ((pb.term == term_kind::jump || pb.term == term_kind::fallthrough) &&
                               pb.fall == sw.start);
            if (!goes_to_sw || pb.term != term_kind::cond || !pb.cond)
                continue;
            ep c = pb.cond;
            if (c->kind == expr::k::bin && !c->kids.empty()) {
                ep lhs = c->kids[0];
                if (lhs->kind == expr::k::un && lhs->text == "(unsigned)" && !lhs->kids.empty())
                    lhs = lhs->kids[0];
                sw.cond = lhs;
                break;
            }
        }
    }

    // a switch block computes the table jump's target: assignments that nothing after them
    // reads are that computation, not worth showing
    for (block_ir& sw : out) {
        if (sw.term != term_kind::sw)
            continue;
        std::string rest = sw.cond ? print(sw.cond) : std::string();
        for (size_t i = sw.stmts.size(); i-- > 0;) {
            const std::string& t = sw.stmts[i].text;
            size_t eq = t.find(" = ");
            std::string lhs = eq == std::string::npos ? std::string() : t.substr(0, eq);
            std::string fam = reg_family(lhs.c_str());
            if (!fam.empty() && disp(fam) == lhs && !(sw.live_out & (1u << reg_bit(fam))) &&
                !mentions(rest, lhs)) {
                sw.stmts.erase(sw.stmts.begin() + (std::ptrdiff_t)i);
                continue;
            }
            rest += " " + t;
        }
    }

    cs_free(insn, 1);
    return true;
}

// ------------------------------------------------------------------ structuring

struct loopctx {
    int header = -1;
    int follow = -1;
    int latch = -1;    // do-while: the block whose test closes the loop
    bool dowhile = false;
};

struct structurer {
    database& db;
    std::vector<block_ir>& blocks;
    bool returns_value;
    std::unordered_map<uint64_t, int> idx;
    std::vector<std::vector<int>> succ, pred;
    std::vector<int> rpo, order, idom, ipdom;
    std::vector<char> is_header;
    std::vector<int> loop_follow, header_of;
    std::map<int, std::set<int>> bodies; // loop header -> blocks in the loop
    std::vector<char> emitted;
    std::set<int> want_label;
    std::vector<decomp_line> out;

    structurer(database& d, std::vector<block_ir>& b, bool rv) : db(d), blocks(b), returns_value(rv) {}

    int at(uint64_t a) { auto it = idx.find(a); return it == idx.end() ? -1 : it->second; }
    std::string label_name(int b) { return "L_" + db.fmt_addr(blocks[b].start); }
    void line(int indent, const std::string& s, uint64_t addr = 0) { out.push_back({indent, s, addr}); }

    void build_graph();
    void compute_rpo(int entry);
    void compute_dom();
    void find_loops();
    bool dominates(int a, int b);
    bool repeat_return(int b, int indent, int stop, std::vector<loopctx>& loops);

    void emit_block_stmts(int b, int indent);
    void emit_term(int b, int indent, int stop, std::vector<loopctx>& loops);
    void emit(int b, int indent, int stop, std::vector<loopctx>& loops);
    void go(int target, int indent, int stop, std::vector<loopctx>& loops);
    std::vector<int> latches_of(int header);
    void run(int entry);
};

void structurer::build_graph()
{
    idx.clear();
    for (size_t i = 0; i < blocks.size(); i++)
        idx[blocks[i].start] = (int)i;
    size_t n = blocks.size();
    succ.assign(n, {});
    pred.assign(n, {});
    for (size_t i = 0; i < n; i++) {
        const block_ir& b = blocks[i];
        auto add = [&](uint64_t a) {
            int t = at(a);
            if (t >= 0) {
                succ[i].push_back(t);
                pred[t].push_back((int)i);
            }
        };
        switch (b.term) {
        case term_kind::ret:
        case term_kind::indirect:
        case term_kind::noreturn:
            break;
        case term_kind::jump:
            add(b.fall);
            break;
        case term_kind::cond:
            add(b.taken);
            add(b.fall);
            break;
        case term_kind::sw:
            if (b.table)
                for (uint64_t t : b.table->targets)
                    add(t);
            break;
        case term_kind::fallthrough:
            add(b.fall);
            break;
        }
    }
}

void structurer::compute_rpo(int entry)
{
    size_t n = blocks.size();
    order.assign(n, -1);
    rpo.clear();
    std::vector<char> vis(n, 0);
    std::vector<std::pair<int, size_t>> st;
    st.push_back({entry, 0});
    vis[entry] = 1;
    std::vector<int> post;
    while (!st.empty()) {
        auto& top = st.back();
        if (top.second < succ[top.first].size()) {
            int nx = succ[top.first][top.second++];
            if (!vis[nx]) {
                vis[nx] = 1;
                st.push_back({nx, 0});
            }
        } else {
            post.push_back(top.first);
            st.pop_back();
        }
    }
    for (auto it = post.rbegin(); it != post.rend(); ++it)
        rpo.push_back(*it);
    for (size_t i = 0; i < rpo.size(); i++)
        order[rpo[i]] = (int)i;
}

void structurer::compute_dom()
{
    size_t n = blocks.size();
    idom.assign(n, -1);
    if (rpo.empty())
        return;
    int entry = rpo[0];
    idom[entry] = entry;
    auto inter = [&](int a, int b) {
        while (a != b) {
            while (order[a] > order[b])
                a = idom[a];
            while (order[b] > order[a])
                b = idom[b];
        }
        return a;
    };
    bool changed = true;
    while (changed) {
        changed = false;
        for (int b : rpo) {
            if (b == entry)
                continue;
            int nd = -1;
            for (int p : pred[b]) {
                if (order[p] < 0 || idom[p] == -1)
                    continue;
                nd = nd == -1 ? p : inter(p, nd);
            }
            if (nd != -1 && idom[b] != nd) {
                idom[b] = nd;
                changed = true;
            }
        }
    }
}

bool structurer::dominates(int a, int b)
{
    int x = b;
    int guard = 0;
    while (x != -1 && guard++ < 100000) {
        if (x == a)
            return true;
        if (idom[x] == x)
            break;
        x = idom[x];
    }
    return false;
}

void structurer::find_loops()
{
    size_t n = blocks.size();
    is_header.assign(n, 0);
    loop_follow.assign(n, -1);
    header_of.assign(n, -1);
    for (size_t u = 0; u < n; u++)
        for (int v : succ[u])
            if (order[v] >= 0 && order[(int)u] >= 0 && dominates(v, (int)u)) {
                is_header[v] = 1;
                std::set<int> body;
                body.insert(v);
                std::vector<int> stack{(int)u};
                while (!stack.empty()) {
                    int x = stack.back();
                    stack.pop_back();
                    if (body.count(x))
                        continue;
                    body.insert(x);
                    for (int pr : pred[x])
                        if (!body.count(pr))
                            stack.push_back(pr);
                }
                for (int x : body)
                    if (header_of[x] == -1 || order[header_of[x]] < order[v])
                        header_of[x] = v;
                bodies[v].insert(body.begin(), body.end());
                int follow = -1;
                for (int s : succ[v])
                    if (!body.count(s))
                        follow = s;
                if (follow == -1)
                    for (int x : body)
                        for (int s : succ[x])
                            if (!body.count(s) && (follow == -1 || order[s] < order[follow]))
                                follow = s;
                if (loop_follow[v] == -1)
                    loop_follow[v] = follow;
            }
}

void structurer::emit_block_stmts(int b, int indent)
{
    for (const stmt& s : blocks[b].stmts)
        line(indent, s.text, s.addr);
}

// a small block that returns is repeated where it's needed again, instead of a goto
bool structurer::repeat_return(int b, int indent, int stop, std::vector<loopctx>& loops)
{
    const block_ir& ib = b < 0 ? blocks[0] : blocks[b];
    bool tail = ib.term == term_kind::indirect && ib.cond && ib.cond->kind == expr::k::call;
    if (b < 0 || (ib.term != term_kind::ret && !tail) || ib.stmts.size() > 2)
        return false;
    emit_block_stmts(b, indent);
    emit_term(b, indent, stop, loops);
    return true;
}

void structurer::go(int target, int indent, int stop, std::vector<loopctx>& loops)
{
    if (target < 0)
        return;
    if (!loops.empty()) {
        if (target == loops.back().follow) {
            line(indent, "break;");
            return;
        }
        if (target == loops.back().header) {
            if (loops.back().dowhile) {
                // continue would test the do-while condition first; this jump doesn't
                want_label.insert(target);
                line(indent, "goto " + label_name(target) + ";");
            } else {
                line(indent, "continue;");
            }
            return;
        }
    }
    if (target == stop)
        return;
    if (emitted[target]) {
        if (repeat_return(target, indent, stop, loops))
            return;
        want_label.insert(target);
        line(indent, "goto " + label_name(target) + ";");
        return;
    }
    emit(target, indent, stop, loops);
}

void structurer::emit_term(int b, int indent, int stop, std::vector<loopctx>& loops)
{
    block_ir& ib = blocks[b];
    switch (ib.term) {
    case term_kind::ret:
        if (returns_value && ib.cond)
            line(indent, "return " + print(ib.cond) + ";", ib.end ? ib.end - 1 : 0);
        else
            line(indent, "return;");
        break;
    case term_kind::indirect:
        if (ib.cond && ib.cond->kind == expr::k::call) {
            if (returns_value) {
                line(indent, "return " + print(ib.cond) + "; // tail call", ib.end ? ib.end - 1 : 0);
            } else {
                line(indent, print(ib.cond) + "; // tail call", ib.end ? ib.end - 1 : 0);
                line(indent, "return;");
            }
        } else if (ib.cond) {
            line(indent, "goto *" + print(ib.cond, 90) + "; // indirect jump", ib.end ? ib.end - 1 : 0);
        } else {
            line(indent, "return; // indirect jump");
        }
        break;
    case term_kind::noreturn:
        // the last statement was the noreturn call; nothing flows out
        break;
    case term_kind::jump:
        go(at(ib.fall), indent, stop, loops);
        break;
    case term_kind::fallthrough:
        go(at(ib.fall), indent, stop, loops);
        break;
    case term_kind::cond: {
        int t = at(ib.taken), f = at(ib.fall);
        std::string c = ib.cond ? print(ib.cond) : "cond";
        std::string not_c = ib.cond ? print(negate(ib.cond)) : "!(" + c + ")";
        // pick the merge point so the if body is single-entry
        int merge = ipdom.empty() ? -1 : ipdom[b];
        if (!loops.empty()) {
            auto lb = bodies.find(loops.back().header);
            if (lb != bodies.end()) {
                bool t_out = !lb->second.count(t), f_out = !lb->second.count(f);
                if (t_out != f_out) {
                    // one arm leaves the loop: "if (c) { break / return }", then the loop goes on
                    line(indent, "if (" + (t_out ? c : not_c) + ") {", ib.start);
                    go(t_out ? t : f, indent + 1, -1, loops);
                    line(indent, "}");
                    go(t_out ? f : t, indent, stop, loops);
                    break;
                }
                if (merge >= 0 && !lb->second.count(merge))
                    merge = -1; // the paths only meet outside the loop
            }
        }
        // both arms present
        bool t_is_merge = t == merge, f_is_merge = f == merge;
        if (t_is_merge && !f_is_merge) {
            // only the fall arm has a body: if (!cond) { fall }
            line(indent, "if (" + not_c + ") {", ib.start);
            go(f, indent + 1, merge, loops);
            line(indent, "}");
            go(merge, indent, stop, loops);
        } else if (f_is_merge && !t_is_merge) {
            line(indent, "if (" + c + ") {", ib.start);
            go(t, indent + 1, merge, loops);
            line(indent, "}");
            go(merge, indent, stop, loops);
        } else if (!t_is_merge && !f_is_merge && merge != -1) {
            line(indent, "if (" + c + ") {", ib.start);
            go(t, indent + 1, merge, loops);
            line(indent, "} else {");
            go(f, indent + 1, merge, loops);
            line(indent, "}");
            go(merge, indent, stop, loops);
        } else {
            // no clean merge: guard with a goto
            line(indent, "if (" + c + ") {", ib.start);
            go(t, indent + 1, stop, loops);
            line(indent, "}");
            go(f, indent, stop, loops);
        }
        break;
    }
    case term_kind::sw: {
        std::string v = ib.cond ? print(ib.cond) : "switch_var";
        line(indent, "switch (" + v + ") {", ib.start);
        int merge = ipdom.empty() ? -1 : ipdom[b];
        if (ib.table) {
            // group case indices by target, in case order
            std::map<uint64_t, std::vector<uint32_t>> by_target;
            for (uint32_t i = 0; i < ib.table->cases.size(); i++)
                by_target[ib.table->cases[i]].push_back(i);
            std::vector<std::pair<uint64_t, std::vector<uint32_t>>> groups(by_target.begin(), by_target.end());
            std::sort(groups.begin(), groups.end(),
                      [](const auto& x, const auto& y) { return x.second.front() < y.second.front(); });
            // inside the switch, "break" leaves the switch (to the merge), never a loop
            loopctx sc;
            sc.header = -2;
            sc.follow = merge;
            loops.push_back(sc);
            for (auto& g : groups) {
                for (uint32_t ci : g.second)
                    line(indent + 1, "case " + std::to_string(ci) + ":");
                int tb = at(g.first);
                if (tb < 0)
                    continue;
                if (tb == merge) {
                    line(indent + 2, "break;");
                } else if (!emitted[tb] && idom[tb] == b) {
                    // only this switch leads here: the case body goes inline
                    size_t before = out.size();
                    go(tb, indent + 2, merge, loops);
                    const std::string& lt = out.size() > before ? out.back().text : std::string();
                    bool left = lt.compare(0, 6, "return") == 0 || lt == "break;" || lt == "continue;" ||
                                lt.compare(0, 5, "goto ") == 0;
                    if (!left)
                        line(indent + 2, "break;");
                } else if (!(emitted[tb] && repeat_return(tb, indent + 2, merge, loops))) {
                    want_label.insert(tb);
                    line(indent + 2, "goto " + label_name(tb) + ";");
                }
            }
            loops.pop_back();
        }
        line(indent, "}");
        go(merge, indent, stop, loops);
        break;
    }
    }
}

std::vector<int> structurer::latches_of(int header)
{
    // predecessors of the header that the header dominates (back-edge sources)
    std::vector<int> out;
    for (int p : pred[header])
        if (order[p] >= 0 && dominates(header, p))
            out.push_back(p);
    return out;
}

void structurer::emit(int b, int indent, int stop, std::vector<loopctx>& loops)
{
    if (b < 0 || b == stop)
        return;

    // a do-while latch we are walking towards: emit its body, let the caller close the loop
    if (!loops.empty() && loops.back().dowhile && b == loops.back().latch && !emitted[b]) {
        emitted[b] = 1;
        if (want_label.count(b))
            line(indent, label_name(b) + ":", blocks[b].start);
        emit_block_stmts(b, indent);
        return;
    }

    if (emitted[b]) {
        if (repeat_return(b, indent, stop, loops))
            return;
        want_label.insert(b);
        line(indent, "goto " + label_name(b) + ";");
        return;
    }

    if (is_header[b] && (loops.empty() || loops.back().header != b)) {
        int follow = loop_follow[b];
        block_ir& hb = blocks[b];

        // pick a conditional latch that closes the loop (bottom-test do/while)
        int dw_latch = -1;
        for (int L : latches_of(b)) {
            block_ir& lb = blocks[L];
            if (lb.term == term_kind::cond) {
                int t = at(lb.taken), f = at(lb.fall);
                if (t == b || f == b) {
                    dw_latch = L;
                    follow = (t == b) ? f : t;
                    break;
                }
            }
        }
        bool top_test = hb.term == term_kind::cond && loop_follow[b] != -1 &&
            (at(hb.taken) == loop_follow[b] || at(hb.fall) == loop_follow[b]);

        if (dw_latch != -1) {
            // do { ... } while (cond);
            loopctx lc;
            lc.header = b;
            lc.follow = follow;
            lc.latch = dw_latch;
            lc.dowhile = true;
            block_ir& lb = blocks[dw_latch];
            std::string cond;
            if (at(lb.taken) == b)
                cond = lb.cond ? print(lb.cond) : "1";
            else
                cond = lb.cond ? print(negate(lb.cond)) : "0";
            line(indent, "do {", hb.start);
            loops.push_back(lc);
            emit(b, indent + 1, -1, loops);
            loops.pop_back();
            line(indent, "} while (" + cond + ");");
            go(follow, indent, stop, loops);
            return;
        }

        emitted[b] = 1;
        if (want_label.count(b))
            line(indent, label_name(b) + ":", hb.start);
        loopctx lc;
        lc.header = b;
        lc.follow = loop_follow[b];
        loops.push_back(lc);
        if (top_test) {
            int body_entry;
            ep stay; // the loop goes on while this holds
            if (at(hb.fall) == loop_follow[b]) {
                stay = hb.cond;
                body_entry = at(hb.taken);
            } else {
                stay = hb.cond ? negate(hb.cond) : nullptr;
                body_entry = at(hb.fall);
            }
            if (hb.stmts.empty()) {
                line(indent, "while (" + (stay ? print(stay) : std::string("1")) + ") {", hb.start);
            } else {
                // the header computes something before its test, on every pass
                line(indent, "while (1) {", hb.start);
                emit_block_stmts(b, indent + 1);
                line(indent + 1, "if (" + (stay ? print(negate(stay)) : std::string("0")) + ") {");
                line(indent + 2, "break;");
                line(indent + 1, "}");
            }
            go(body_entry, indent + 1, b, loops);
            line(indent, "}");
        } else {
            line(indent, "while (1) {", hb.start);
            emit_block_stmts(b, indent + 1);
            emit_term(b, indent + 1, b, loops);
            line(indent, "}");
        }
        loops.pop_back();
        go(loop_follow[b], indent, stop, loops);
        return;
    }

    emitted[b] = 1;
    if (want_label.count(b))
        line(indent, label_name(b) + ":", blocks[b].start);
    emit_block_stmts(b, indent);
    emit_term(b, indent, stop, loops);
}

void structurer::run(int entry)
{
    build_graph();
    compute_rpo(entry);
    compute_dom();
    // post-dominators: dominators of the reversed graph, rooted at a virtual
    // exit node (index n) that every exit block flows into. ipdom == n means
    // the paths only meet at the function exit, reported as -1.
    {
        int n = (int)blocks.size();
        int vexit = n;
        std::vector<std::vector<int>> rsucc(n + 1), rpred(n + 1);
        for (int i = 0; i < n; i++) {
            if (succ[i].empty()) {
                rsucc[vexit].push_back(i);
                rpred[i].push_back(vexit);
            }
            for (int s : succ[i]) {
                rsucc[s].push_back(i); // reversed edge s -> i
                rpred[i].push_back(s);
            }
        }
        std::vector<int> rorder(n + 1, -1), rrpo, post;
        std::vector<char> vis(n + 1, 0);
        std::vector<std::pair<int, size_t>> st{{vexit, 0}};
        vis[vexit] = 1;
        while (!st.empty()) {
            auto& top = st.back();
            if (top.second < rsucc[top.first].size()) {
                int nx = rsucc[top.first][top.second++];
                if (!vis[nx]) {
                    vis[nx] = 1;
                    st.push_back({nx, 0});
                }
            } else {
                post.push_back(top.first);
                st.pop_back();
            }
        }
        for (auto it = post.rbegin(); it != post.rend(); ++it)
            rrpo.push_back(*it);
        for (size_t i = 0; i < rrpo.size(); i++)
            rorder[rrpo[i]] = (int)i;
        std::vector<int> pd(n + 1, -1);
        pd[vexit] = vexit;
        auto inter = [&](int a, int b) {
            int guard = 0;
            while (a != b && guard++ < 1000000) {
                while (rorder[a] > rorder[b])
                    a = pd[a];
                while (rorder[b] > rorder[a])
                    b = pd[b];
            }
            return a;
        };
        bool changed = true;
        int rounds = 0;
        while (changed && rounds++ < 1000) {
            changed = false;
            for (int b : rrpo) {
                if (b == vexit)
                    continue;
                int nd = -1;
                for (int p : rpred[b]) {
                    if (rorder[p] < 0 || pd[p] == -1)
                        continue;
                    nd = nd == -1 ? p : inter(p, nd);
                }
                if (nd != -1 && pd[b] != nd) {
                    pd[b] = nd;
                    changed = true;
                }
            }
        }
        ipdom.assign(n, -1);
        for (int i = 0; i < n; i++)
            ipdom[i] = (pd[i] == vexit) ? -1 : pd[i];
    }
    find_loops();

    // a goto can go back to a block that is already written: a first pass finds every
    // label that's needed, the next one writes them
    std::set<int> labels;
    for (int pass = 0; pass < 4; pass++) {
        out.clear();
        emitted.assign(blocks.size(), 0);
        want_label = labels;
        std::vector<loopctx> loops;
        emit(entry, 0, -1, loops);
        // any block the walk missed (irreducible / unreachable) - append with a label
        for (int b : rpo)
            if (!emitted[b]) {
                want_label.insert(b);
                line(0, "");
                emit(b, 0, -1, loops);
            }
        if (want_label == labels)
            break;
        labels = want_label;
    }
}

// tidy up the emitted lines: drop empty then-branches and empty blocks
std::vector<decomp_line> cleanup(const std::vector<decomp_line>& in)
{
    std::vector<decomp_line> v;
    // which line opened the block at each indent, to tell loop bodies from if bodies
    std::vector<std::string> opener;
    auto is_if = [](const std::string& s) {
        return s.size() > 7 && s.compare(0, 4, "if (") == 0 && s.compare(s.size() - 3, 3, ") {") == 0;
    };
    for (size_t i = 0; i < in.size(); i++) {
        const decomp_line& l = in[i];
        if (opener.size() <= (size_t)l.indent)
            opener.resize((size_t)l.indent + 1);
        if (!l.text.empty() && l.text.back() == '{')
            opener[(size_t)l.indent] = l.text;
        if (l.text == "continue;" && l.indent > 0 && i + 1 < in.size() && in[i + 1].indent == l.indent - 1 &&
            in[i + 1].text == "}" && opener[(size_t)l.indent - 1].compare(0, 6, "while ") == 0)
            continue;
        if (l.text == "} else {" && i + 1 < in.size() && in[i + 1].indent == l.indent && in[i + 1].text == "}") {
            // empty else: just close the if
            decomp_line nl = l;
            nl.text = "}";
            v.push_back(nl);
            i++;
            continue;
        }
        if (is_if(l.text) && i + 1 < in.size()) {
            const decomp_line& nx = in[i + 1];
            std::string cond = l.text.substr(4, l.text.size() - 7);
            if (nx.indent == l.indent && nx.text == "} else {") {
                // empty then: invert to if (!(cond)) { <else body> }
                decomp_line nl = l;
                nl.text = "if (!(" + cond + ")) {";
                v.push_back(nl);
                i++; // skip the "} else {"
                continue;
            }
            if (nx.indent == l.indent && nx.text == "}") {
                // empty if with no else: drop both lines
                i++;
                continue;
            }
        }
        v.push_back(l);
    }
    return v;
}

// identifiers in a printed line renamed, except inside __asm { } and comments
std::string rename_tokens(const std::string& text, const std::map<std::string, std::string>& names)
{
    if (names.empty())
        return text;
    std::string out;
    size_t i = 0, n = text.size();
    auto ident = [](char c) { return std::isalnum((unsigned char)c) || c == '_'; };
    while (i < n) {
        if (text.compare(i, 2, "//") == 0) {
            out += text.substr(i);
            break;
        }
        if (text.compare(i, 7, "__asm {") == 0) {
            size_t e = text.find('}', i);
            e = e == std::string::npos ? n : e + 1;
            out += text.substr(i, e - i);
            i = e;
            continue;
        }
        if (ident(text[i])) {
            size_t j = i;
            while (j < n && ident(text[j]))
                j++;
            std::string w = text.substr(i, j - i);
            auto it = std::isdigit((unsigned char)w[0]) ? names.end() : names.find(w);
            out += it == names.end() ? w : it->second;
            i = j;
            continue;
        }
        out += text[i++];
    }
    return out;
}

bool is_reg_name(const std::string& w)
{
    return !reg_family(w.c_str()).empty() || (w.size() > 3 && w.compare(0, 3, "tmp") == 0 &&
           std::isdigit((unsigned char)w[3]));
}

} // namespace

// ------------------------------------------------------------------ public api

decompiled decompile(database& db, uint64_t func_start)
{
    decompiled r;
    r.func = func_start;
    const function* fn = db.an.func_containing(func_start);
    uint64_t start = fn ? fn->start : func_start;
    r.func = start;
    r.name = db.location(start);

    if (fn && fn->thunk) {
        r.ok = true;
        std::string tn = db.name_at(fn->thunk_target);
        if (tn.empty())
            tn = db.location(fn->thunk_target);
        r.lines.push_back({0, r.name + ": thunk to " + tn, start});
        return r;
    }

    if (!db.bin.is_x86()) {
        r.error = util::fmt("the decompiler reads x86 and x64 code; this is %s (the listing and graph work)",
            arch_name(db.bin.arch));
        return r;
    }
    csh cs = 0;
    if (cs_open(CS_ARCH_X86, db.bin.is64() ? CS_MODE_64 : CS_MODE_32, &cs) != CS_ERR_OK) {
        r.error = "capstone failed to open";
        return r;
    }
    cs_option(cs, CS_OPT_DETAIL, CS_OPT_ON);

    std::vector<block_ir> ir;
    std::vector<std::string> params;
    bool returns_value = false;
    lifter lf(db, cs);
    bool ok = lf.run(start, ir, params, returns_value);
    if (!ok || ir.empty()) {
        cs_close(&cs);
        r.error = "could not decode the function";
        return r;
    }

    structurer st(db, ir, returns_value);
    int entry = st.at(start);
    if (entry < 0)
        entry = 0;
    st.run(entry < 0 ? 0 : entry);

    // ---- the variables: parameters, the stack frame, registers used as variables. your names
    // and types (db.lvars) and your prototype (db.protos) go over the decompiler's own
    const bool is64 = db.bin.is64();
    const int64_t ptr = is64 ? 8 : 4;
    const std::map<std::string, database::lvar>* user = nullptr;
    auto uit = db.lvars.find(start);
    if (uit != db.lvars.end())
        user = &uit->second;
    auto pit = db.protos.find(start);
    const prototype* proto = pit == db.protos.end() ? nullptr : &pit->second;
    auto user_of = [&](const std::string& key) -> const database::lvar* {
        if (!user)
            return nullptr;
        auto it = user->find(key);
        return it == user->end() ? nullptr : &it->second;
    };
    // parameters: the argument registers, then stack slots above the return address (all of
    // them on 32-bit; on 64-bit the ones after the registers, past win64's home area)
    int nregs = 0;
    while (arg_reg_at(nregs, is64, db.bin.format))
        nregs++;
    std::vector<std::string> pkeys = params; // register display names
    int64_t stack_from = !is64 ? ptr : ptr + (db.bin.format == bin_format::pe ? 0x20 : 0);
    int64_t max_arg = -1;
    for (const auto& f : lf.frame)
        if (f.first >= stack_from && f.first < stack_from + 64 * ptr)
            max_arg = std::max(max_arg, f.first);
    bool stack_params = !is64 || (int)params.size() == nregs;
    int want = proto ? (int)proto->params.size() : -1;
    if (stack_params && max_arg >= 0 && want < 0)
        for (int64_t off = stack_from; off <= max_arg; off += ptr)
            pkeys.push_back(lf.frame.count(off) ? lf.frame[off].name : util::fmt("arg_%llx", (unsigned long long)(off - ptr)));
    if (want >= 0) { // the prototype says how many
        pkeys.resize(std::min<size_t>(pkeys.size(), (size_t)want));
        for (int i = (int)pkeys.size(); i < want; i++) {
            if (i < nregs)
                pkeys.push_back(reg_display(arg_reg_at(i, is64, db.bin.format), is64));
            else
                pkeys.push_back(util::fmt("arg_%llx", (unsigned long long)(stack_from - ptr + (i - (is64 ? nregs : 0)) * ptr)));
        }
    }
    std::set<std::string> is_param(pkeys.begin(), pkeys.end());
    std::map<std::string, std::string> names; // key -> the name shown, where they differ
    std::set<std::string> taken;
    auto add_var = [&](const std::string& key, bool param, bool stack, const std::string& def_type, int pindex) {
        decomp_var v;
        v.key = key;
        v.param = param;
        v.stack = stack;
        v.name = key;
        v.type = def_type;
        if (proto && pindex >= 0 && pindex < (int)proto->params.size()) {
            v.name = proto->params[(size_t)pindex].name;
            v.type = proto->params[(size_t)pindex].type;
        }
        if (const database::lvar* u = user_of(key)) {
            if (!u->name.empty())
                v.name = u->name;
            if (!u->type.empty())
                v.type = u->type;
        }
        if (v.name != key && taken.count(v.name))
            v.name = key; // a clash: keep the decompiler's name
        taken.insert(v.name);
        if (v.name != key)
            names[key] = v.name;
        r.vars.push_back(v);
    };
    for (size_t i = 0; i < pkeys.size(); i++) {
        bool stk = pkeys[i].compare(0, 4, "arg_") == 0;
        int64_t off = 0;
        for (const auto& f : lf.frame)
            if (f.second.name == pkeys[i])
                off = f.first;
        add_var(pkeys[i], true, stk, stk && off && lf.frame[off].width ? mem_type(lf.frame[off].width) : "int", (int)i);
    }
    // the frame's other slots: width tells the type; a slot only ever used by address (a
    // buffer) is an array up to the next slot
    std::vector<std::pair<int64_t, std::string>> decls; // offset, declaration key
    for (auto it = lf.frame.begin(); it != lf.frame.end(); ++it) {
        if (is_param.count(it->second.name))
            continue;
        std::string ty;
        if (it->second.width > 0) {
            ty = mem_type(it->second.width);
        } else {
            auto next = std::next(it);
            int64_t limit = next == lf.frame.end() || (it->first < 0 && next->first > 0) ? (it->first < 0 ? 0 : it->first)
                                                                                       : next->first;
            int64_t gap = limit - it->first;
            ty = gap > 0 && gap <= 0x10000 ? util::fmt("char[0x%llx]", (unsigned long long)gap) : "char[]";
        }
        add_var(it->second.name, false, true, ty, -1);
        decls.push_back({it->first, it->second.name});
    }
    // registers the body keeps values in
    std::vector<decomp_line> body = cleanup(st.out);
    std::set<std::string> regs, used;
    for (const decomp_line& l : body) {
        const std::string& t = l.text;
        size_t asm_at = t.find("__asm {");
        std::string scan = asm_at == std::string::npos ? t : t.substr(0, asm_at);
        for (size_t i = 0; i < scan.size();) {
            if (std::isalpha((unsigned char)scan[i]) || scan[i] == '_') {
                size_t j = i;
                while (j < scan.size() && (std::isalnum((unsigned char)scan[j]) || scan[j] == '_'))
                    j++;
                std::string w = scan.substr(i, j - i);
                used.insert(w);
                if (!is_param.count(w) && is_reg_name(w))
                    regs.insert(w);
                i = j;
            } else if (std::isdigit((unsigned char)scan[i])) {
                while (i < scan.size() && std::isalnum((unsigned char)scan[i]))
                    i++;
            } else {
                i++;
            }
        }
    }
    for (const std::string& rg : regs)
        add_var(rg, false, false, std::string(), -1);
    r.vars.erase(std::remove_if(r.vars.begin(), r.vars.end(),
                                [&](const decomp_var& v) { return !v.param && v.stack && !used.count(v.key); }),
                 r.vars.end());

    // signature: your prototype's return type, else what the lifter saw
    std::string ret = proto ? proto->ret : returns_value ? "int" : "void";
    std::string sig = ret + " " + r.name + "(";
    size_t np = 0;
    for (const decomp_var& v : r.vars) {
        if (!v.param)
            continue;
        if (np++)
            sig += ", ";
        size_t fp = v.type.find("(*)");
        sig += fp != std::string::npos ? v.type.substr(0, fp + 2) + v.name + v.type.substr(fp + 2) : v.type + " " + v.name;
    }
    if (proto && proto->variadic)
        sig += np ? ", ..." : "...";
    else if (!np)
        sig += "void";
    sig += ")";
    r.lines.push_back({0, sig, start});
    r.lines.push_back({0, "{", 0});
    // declarations: the stack variables, and registers you gave a type
    for (const auto& d : decls)
        for (const decomp_var& v : r.vars)
            if (v.key == d.second && !v.param && used.count(v.key)) {
                size_t br = v.type.find('[');
                std::string decl = br == std::string::npos ? v.type + " " + v.name + ";"
                                                           : v.type.substr(0, br) + " " + v.name + v.type.substr(br) + ";";
                r.lines.push_back({1, decl, 0});
            }
    for (const decomp_var& v : r.vars)
        if (!v.stack && !v.param && !v.type.empty())
            r.lines.push_back({1, v.type + " " + v.name + ";", 0});
    if (r.lines.size() > 2)
        r.lines.push_back({1, "", 0});
    for (auto& l : body) {
        decomp_line dl = l;
        dl.indent += 1;
        dl.text = rename_tokens(dl.text, names);
        r.lines.push_back(dl);
    }
    r.lines.push_back({0, "}", 0});
    r.ok = true;

    cs_close(&cs);
    return r;
}

std::string decompile_text(database& db, uint64_t func_start)
{
    decompiled d = decompile(db, func_start);
    if (!d.ok)
        return "// " + (d.error.empty() ? std::string("decompile failed") : d.error) + "\n";
    std::string s;
    for (const decomp_line& l : d.lines) {
        for (int i = 0; i < l.indent; i++)
            s += "    ";
        s += l.text;
        s += "\n";
    }
    return s;
}

std::string decompile_text_marked(database& db, uint64_t func_start, uint64_t here)
{
    decompiled d = decompile(db, func_start);
    if (!d.ok)
        return "// " + (d.error.empty() ? std::string("decompile failed") : d.error) + "\n";
    // the marked line is the one with the greatest addr not past `here` (each line carries the
    // address of the instruction it came from)
    size_t mark = d.lines.size();
    uint64_t best = 0;
    for (size_t i = 0; i < d.lines.size(); i++) {
        uint64_t a = d.lines[i].addr;
        if (a && a <= here && a >= best) {
            best = a;
            mark = i;
        }
    }
    std::string s;
    for (size_t i = 0; i < d.lines.size(); i++) {
        for (int j = 0; j < d.lines[i].indent; j++)
            s += "    ";
        s += d.lines[i].text;
        if (i == mark)
            s += "    // <= here (" + db.fmt_addr(here) + ")";
        s += "\n";
    }
    return s;
}
