#include "core/decompiler.h"

#include "core/analysis.h"
#include "core/binary.h"
#include "core/database.h"

#include <capstone/capstone.h>

#include <algorithm>
#include <cctype>
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
    enum class k { num, sym, reg, mem, un, bin, call } kind = k::num;
    uint64_t num = 0;
    bool sgn = false;
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
        std::string s = e->text + "(";
        for (size_t i = 0; i < e->kids.size(); i++) {
            if (i)
                s += ", ";
            s += print(e->kids[i], 0);
        }
        return s + ")";
    }
    }
    return "?";
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

// ------------------------------------------------------------------ lifter

class lifter {
public:
    lifter(database& db, csh cs) : db_(db), cs_(cs), is64_(db.bin.is64()) {}
    bool run(uint64_t func_start, std::vector<block_ir>& out, std::vector<std::string>& params,
             bool& returns_value);

private:
    database& db_;
    csh cs_;
    bool is64_;
    std::set<std::string> params_;

    std::string disp(const std::string& fam) { return reg_display(fam, is64_); }
    ep reg_read(std::unordered_map<std::string, ep>& cur, const std::string& fam);
    ep sym_for(uint64_t a);
    ep mem_address(const x86_op_mem& m, std::unordered_map<std::string, ep>& cur, uint64_t rip);
    ep operand_expr(cs_insn* in, const cs_x86_op& op, std::unordered_map<std::string, ep>& cur);
    ep build_cond(const flag_state& fs, unsigned cc_id, bool& ok);
};

ep lifter::reg_read(std::unordered_map<std::string, ep>& cur, const std::string& fam)
{
    auto it = cur.find(fam);
    if (it != cur.end() && it->second)
        return it->second;
    return e_reg(disp(fam));
}

ep lifter::sym_for(uint64_t a)
{
    std::string n = db_.name_at(a);
    if (!n.empty())
        return e_sym(n, a);
    return e_num(a);
}

ep lifter::mem_address(const x86_op_mem& m, std::unordered_map<std::string, ep>& cur, uint64_t rip)
{
    if (m.base == X86_REG_RIP) {
        uint64_t ea = rip + (uint64_t)m.disp;
        return e_un("&", sym_for(ea));
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
    if (op.type == X86_OP_IMM)
        return e_num((uint64_t)op.imm, true);
    if (op.type == X86_OP_MEM) {
        uint64_t rip = in->address + in->size;
        return e_mem(mem_address(op.mem, cur, rip), op.size);
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

    out.clear();
    out.resize(g.blocks.size());
    std::unordered_map<uint64_t, int> block_of;
    for (size_t i = 0; i < g.blocks.size(); i++)
        block_of[g.blocks[i].start] = (int)i;
    bin_format fmt = db_.bin.format;
    returns_value = false;

    // pass 1: def / use per block
    for (size_t bi = 0; bi < g.blocks.size(); bi++) {
        const cfg_block& cb = g.blocks[bi];
        block_ir& ir = out[bi];
        ir.start = cb.start;
        ir.end = cb.end;
        for (uint64_t a : cb.insns) {
            uint8_t code[16];
            size_t n = db_.bin.read(a, code, sizeof(code));
            const uint8_t* p = code;
            size_t left = n;
            uint64_t addr = a;
            if (!cs_disasm_iter(cs_, &p, &left, &addr, insn))
                continue;
            cs_regs rd, wr;
            uint8_t nrd = 0, nwr = 0;
            if (cs_regs_access(cs_, insn, rd, &nrd, wr, &nwr) == CS_ERR_OK) {
                for (uint8_t i = 0; i < nrd; i++) {
                    int b = reg_bit(reg_family(cs_reg_name(cs_, rd[i])));
                    if (b >= 0 && !(ir.def & (1u << b)))
                        ir.use |= (1u << b);
                }
                for (uint8_t i = 0; i < nwr; i++) {
                    int b = reg_bit(reg_family(cs_reg_name(cs_, wr[i])));
                    if (b >= 0)
                        ir.def |= (1u << b);
                }
            }
        }
        if (out[bi].def & 1u)
            returns_value = true; // rax written somewhere -> assume it returns a value
    }

    // liveness fixpoint
    std::vector<std::vector<int>> succ(g.blocks.size());
    for (size_t bi = 0; bi < g.blocks.size(); bi++)
        for (const cfg_edge& e : g.blocks[bi].succ)
            succ[bi].push_back((int)e.to);
    bool changed = true;
    int guard = 0;
    while (changed && guard++ < 20000) {
        changed = false;
        for (size_t bi = 0; bi < g.blocks.size(); bi++) {
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

    // parameters: arg regs live-in at entry (as a prefix)
    int entry = block_of.count(func_start) ? block_of[func_start] : 0;
    for (int i = 0;; i++) {
        const char* ar = arg_reg_at(i, is64_, fmt);
        if (!ar)
            break;
        int b = reg_bit(ar);
        if (b >= 0 && (out[entry].live_in & (1u << b))) {
            params_.insert(ar);
            params.push_back(disp(ar));
        } else {
            break;
        }
    }

    // pass 2: statements with block-local propagation
    for (size_t bi = 0; bi < g.blocks.size(); bi++) {
        const cfg_block& cb = g.blocks[bi];
        block_ir& ir = out[bi];
        std::unordered_map<std::string, ep> cur;
        for (const std::string& pr : params_)
            cur[pr] = e_reg(disp(pr));
        flag_state fs;

        auto line = [&](uint64_t at, const std::string& s) { ir.stmts.push_back({at, s}); };

        for (size_t ii = 0; ii < cb.insns.size(); ii++) {
            uint64_t a = cb.insns[ii];
            uint8_t code[16];
            size_t n = db_.bin.read(a, code, sizeof(code));
            const uint8_t* p = code;
            size_t left = n;
            uint64_t addr = a;
            if (!cs_disasm_iter(cs_, &p, &left, &addr, insn))
                continue;
            cs_x86& x = insn->detail->x86;
            unsigned id = insn->id;
            bool last = ii + 1 == cb.insns.size();

            auto set_reg = [&](const cs_x86_op& dst, ep val) {
                std::string fam = reg_family(cs_reg_name(cs_, dst.reg));
                if (fam.empty())
                    return;
                if (fam == "rsp" || fam == "rbp") {
                    cur[fam] = val;
                    return;
                }
                int b = reg_bit(fam);
                bool live = b >= 0 && (ir.live_out & (1u << b));
                // materialise a line when the value is big or leaves the block
                if (node_count(val) > 6 || (live && last)) {
                    line(a, disp(fam) + " = " + print(val) + ";");
                    cur[fam] = e_reg(disp(fam));
                } else {
                    cur[fam] = val;
                }
            };
            auto arith = [&](const char* op) {
                if (x.op_count < 2)
                    return;
                ep d = operand_expr(insn, x.operands[0], cur);
                ep s = operand_expr(insn, x.operands[1], cur);
                ep r = e_bin(op, d, s);
                fs = {};
                fs.valid = true;
                fs.res = r;
                if (x.operands[0].type == X86_OP_REG)
                    set_reg(x.operands[0], r);
                else if (x.operands[0].type == X86_OP_MEM)
                    line(a, print(d) + " " + op + "= " + print(s) + ";");
            };

            switch (id) {
            case X86_INS_NOP:
            case X86_INS_ENDBR32:
            case X86_INS_ENDBR64:
            case X86_INS_PUSH:
            case X86_INS_POP:
            case X86_INS_LEAVE:
                break;
            case X86_INS_MOV:
            case X86_INS_MOVZX:
            case X86_INS_MOVSX:
            case X86_INS_MOVSXD:
            case X86_INS_MOVABS:
                if (x.op_count >= 2) {
                    ep s = operand_expr(insn, x.operands[1], cur);
                    if (x.operands[0].type == X86_OP_REG)
                        set_reg(x.operands[0], s);
                    else if (x.operands[0].type == X86_OP_MEM)
                        line(a, print(operand_expr(insn, x.operands[0], cur)) + " = " + print(s) + ";");
                }
                break;
            case X86_INS_LEA:
                if (x.op_count >= 2 && x.operands[1].type == X86_OP_MEM) {
                    uint64_t rip = insn->address + insn->size;
                    set_reg(x.operands[0], mem_address(x.operands[1].mem, cur, rip));
                }
                break;
            case X86_INS_ADD: arith("+"); break;
            case X86_INS_SUB: arith("-"); break;
            case X86_INS_AND: arith("&"); break;
            case X86_INS_OR: arith("|"); break;
            case X86_INS_SHL:
            case X86_INS_SAL: arith("<<"); break;
            case X86_INS_SHR:
            case X86_INS_SAR: arith(">>"); break;
            case X86_INS_IMUL:
                if (x.op_count == 3)
                    set_reg(x.operands[0], e_bin("*", operand_expr(insn, x.operands[1], cur),
                                                 operand_expr(insn, x.operands[2], cur)));
                else if (x.op_count == 2)
                    arith("*");
                break;
            case X86_INS_XOR:
                if (x.op_count >= 2 && x.operands[0].type == X86_OP_REG &&
                    x.operands[1].type == X86_OP_REG && x.operands[0].reg == x.operands[1].reg) {
                    fs = {};
                    fs.valid = true;
                    fs.res = e_num(0);
                    set_reg(x.operands[0], e_num(0));
                } else {
                    arith("^");
                }
                break;
            case X86_INS_INC:
            case X86_INS_DEC:
                if (x.op_count >= 1 && x.operands[0].type == X86_OP_REG) {
                    ep r = e_bin(id == X86_INS_INC ? "+" : "-",
                                 operand_expr(insn, x.operands[0], cur), e_num(1));
                    fs = {};
                    fs.valid = true;
                    fs.res = r;
                    set_reg(x.operands[0], r);
                }
                break;
            case X86_INS_NEG:
                if (x.op_count >= 1 && x.operands[0].type == X86_OP_REG)
                    set_reg(x.operands[0], e_un("-", operand_expr(insn, x.operands[0], cur)));
                break;
            case X86_INS_NOT:
                if (x.op_count >= 1 && x.operands[0].type == X86_OP_REG)
                    set_reg(x.operands[0], e_un("~", operand_expr(insn, x.operands[0], cur)));
                break;
            case X86_INS_CMP:
                if (x.op_count >= 2) {
                    fs = {};
                    fs.valid = true;
                    fs.is_cmp = true;
                    fs.a = operand_expr(insn, x.operands[0], cur);
                    fs.b = operand_expr(insn, x.operands[1], cur);
                }
                break;
            case X86_INS_TEST:
                if (x.op_count >= 2) {
                    fs = {};
                    fs.valid = true;
                    fs.is_test = true;
                    fs.a = operand_expr(insn, x.operands[0], cur);
                    fs.b = operand_expr(insn, x.operands[1], cur);
                }
                break;
            case X86_INS_CALL: {
                uint64_t target = 0;
                if (x.op_count >= 1 && x.operands[0].type == X86_OP_IMM)
                    target = (uint64_t)x.operands[0].imm;
                auto ce = std::make_shared<expr>();
                ce->kind = expr::k::call;
                if (target) {
                    std::string nm = db_.name_at(target);
                    ce->text = nm.empty() ? db_.location(target) : nm;
                    ce->ref = target;
                } else if (x.op_count >= 1) {
                    ce->text = "(*" + print(operand_expr(insn, x.operands[0], cur)) + ")";
                } else {
                    ce->text = "(*indirect)";
                }
                if (is64_) {
                    for (int ai = 0;; ai++) {
                        const char* ar = arg_reg_at(ai, is64_, fmt);
                        if (!ar)
                            break;
                        auto it = cur.find(ar);
                        if (it == cur.end())
                            break;
                        ce->kids.push_back(it->second);
                    }
                }
                std::string rax = is64_ ? "rax" : "eax";
                bool used = (ir.live_out & 1u) != 0;
                if (used) {
                    line(a, rax + " = " + print(ce) + ";");
                    cur["rax"] = e_reg(rax);
                } else {
                    line(a, print(ce) + ";");
                    cur.erase("rax");
                }
                break;
            }
            case X86_INS_RET:
            case X86_INS_RETF:
                break;
            default:
                if (!cs_insn_group(cs_, insn, X86_GRP_JUMP) && !cs_insn_group(cs_, insn, X86_GRP_RET)) {
                    cs_regs rd, wr;
                    uint8_t nrd = 0, nwr = 0;
                    if (cs_regs_access(cs_, insn, rd, &nrd, wr, &nwr) == CS_ERR_OK)
                        for (uint8_t i = 0; i < nwr; i++) {
                            std::string fam = reg_family(cs_reg_name(cs_, wr[i]));
                            if (!fam.empty() && fam != "rsp" && fam != "rbp")
                                cur[fam] = e_reg(disp(fam));
                        }
                }
                break;
            }

            if (last) {
                if (cs_insn_group(cs_, insn, X86_GRP_RET)) {
                    ir.term = term_kind::ret;
                    if (returns_value) {
                        auto it = cur.find("rax");
                        ir.cond = it != cur.end() && it->second ? it->second : e_reg(is64_ ? "rax" : "eax");
                    }
                } else if (id == X86_INS_JMP) {
                    if (x.op_count >= 1 && x.operands[0].type == X86_OP_IMM) {
                        ir.term = term_kind::jump;
                        ir.fall = (uint64_t)x.operands[0].imm;
                    } else {
                        auto t = db_.an.tables.find(a);
                        if (t != db_.an.tables.end()) {
                            ir.term = term_kind::sw;
                            ir.table = &t->second;
                            std::string fam = t->second.index_reg
                                ? reg_family(cs_reg_name(cs_, t->second.index_reg)) : std::string();
                            if (!fam.empty()) {
                                auto it = cur.find(fam);
                                ir.cond = it != cur.end() && it->second ? it->second : e_reg(disp(fam));
                            } else if (x.op_count >= 1) {
                                ir.cond = operand_expr(insn, x.operands[0], cur);
                            }
                        } else {
                            ir.term = term_kind::indirect;
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
            line(indent, "continue;");
            return;
        }
    }
    if (target == stop)
        return;
    if (emitted[target]) {
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
        line(indent, "return; // indirect jump");
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
        // pick the merge point so the if body is single-entry
        int merge = ipdom.empty() ? -1 : ipdom[b];
        // both arms present
        bool t_is_merge = t == merge, f_is_merge = f == merge;
        if (t_is_merge && !f_is_merge) {
            // only the fall arm has a body: if (!cond) { fall }
            line(indent, "if (" + (ib.cond ? print(negate(ib.cond)) : "!(" + c + ")") + ") {", ib.start);
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
        if (ib.table) {
            // group case indices by target
            std::map<uint64_t, std::vector<uint32_t>> by_target;
            for (uint32_t i = 0; i < ib.table->cases.size(); i++)
                by_target[ib.table->cases[i]].push_back(i);
            for (auto& kv : by_target) {
                for (uint32_t ci : kv.second)
                    line(indent + 1, "case " + std::to_string(ci) + ":");
                int tb = at(kv.first);
                if (tb >= 0) {
                    want_label.insert(tb);
                    line(indent + 2, "goto " + label_name(tb) + ";");
                }
            }
        }
        line(indent, "}");
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
        loopctx lc;
        lc.header = b;
        lc.follow = loop_follow[b];
        loops.push_back(lc);
        if (top_test) {
            emit_block_stmts(b, indent);
            int body_entry;
            std::string cond;
            if (at(hb.fall) == loop_follow[b]) {
                cond = hb.cond ? print(hb.cond) : "1";
                body_entry = at(hb.taken);
            } else {
                cond = hb.cond ? print(negate(hb.cond)) : "0";
                body_entry = at(hb.fall);
            }
            line(indent, "while (" + cond + ") {", hb.start);
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
    emitted.assign(blocks.size(), 0);

    std::vector<loopctx> loops;
    emit(entry, 0, -1, loops);
    // any block the walk missed (irreducible / unreachable) - append with a label
    for (int b : rpo)
        if (!emitted[b]) {
            want_label.insert(b);
            line(0, "");
            emit(b, 0, -1, loops);
        }
}

// tidy up the emitted lines: drop empty then-branches and empty blocks
std::vector<decomp_line> cleanup(const std::vector<decomp_line>& in)
{
    std::vector<decomp_line> v;
    auto is_if = [](const std::string& s) {
        return s.size() > 7 && s.compare(0, 4, "if (") == 0 && s.compare(s.size() - 3, 3, ") {") == 0;
    };
    for (size_t i = 0; i < in.size(); i++) {
        const decomp_line& l = in[i];
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

    // signature
    std::string sig = (returns_value ? "int " : "void ") + r.name + "(";
    for (size_t i = 0; i < params.size(); i++) {
        if (i)
            sig += ", ";
        sig += "int " + params[i];
    }
    if (params.empty() && db.bin.is64())
        sig += "void";
    sig += ")";
    r.lines.push_back({0, sig, start});
    r.lines.push_back({0, "{", 0});
    for (auto& l : cleanup(st.out)) {
        decomp_line dl = l;
        dl.indent += 1;
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
