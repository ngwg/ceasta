#include "core/decompiler.h"

#include "core/analysis.h"
#include "core/binary.h"
#include "core/database.h"
#include "core/util.h"

#include <capstone/capstone.h>

#include <algorithm>
#include <array>
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

// the machine the function is for: x86 / x64, or arm64. the register helpers and the lifter
// follow it (decompile sets it)
thread_local bool g_arm = false;

// ------------------------------------------------------------------ expressions

struct expr;
using ep = std::shared_ptr<expr>;

struct expr {
    enum class k { num, sym, reg, mem, un, bin, call, tern } kind = k::num;
    uint64_t num = 0;
    bool sgn = false;
    bool indirect = false; // call through a pointer: kids[0] is the target
    bool fp = false;       // a floating point comparison: a nan makes it and its opposite false
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

// ------------------------------------------------------------------ your types in the printout
//
//   *(long long*)(rdi + 8)        rdi->next       (rdi a struct node*)
//   *(int*)(rsi + rcx * 4)        rsi[rcx]        (rsi an int*)
//   local_50                      pt.y            (local_58 a struct point, y at 8)

struct frame_struct {
    std::string key;     // local_58
    int64_t off = 0;     // its frame offset
    const ctype_def* def = nullptr;
};

struct type_view {
    const ctypes* lib = nullptr;
    const database* db = nullptr;
    int64_t ptr = 8;
    std::map<std::string, std::string> vars; // a variable (register, frame slot) -> its type
    std::vector<frame_struct> frame;         // struct variables of the frame
};

thread_local const type_view* g_types = nullptr;
// while learning: what each register is set to, "?" when the values' types differ or are unknown
thread_local std::map<std::string, std::string>* g_learn = nullptr;

// while making a struct from how a variable is used: every read or write through it
struct use_collector {
    std::string key;                      // the variable: rdi, local_20
    std::map<uint64_t, uint32_t> fields;  // offset -> the widest access there
    std::set<uint64_t> self;              // fields put back in the variable: a list's next
};
thread_local use_collector* g_uses = nullptr;

// the variable plus a constant: rdi + 0x18, or the frame slot holding it: *(&local_20) + 8
bool use_offset(const ep& a, int64_t& off)
{
    std::vector<std::pair<ep, int>> todo{{a, 1}};
    off = 0;
    bool base = false;
    while (!todo.empty()) {
        ep e = todo.back().first;
        int sign = todo.back().second;
        todo.pop_back();
        if (!e || todo.size() > 16)
            return false;
        if (e->kind == expr::k::num) {
            off += sign * (int64_t)e->num;
            continue;
        }
        if (e->kind == expr::k::bin && (e->text == "+" || e->text == "-")) {
            todo.push_back({e->kids[0], sign});
            todo.push_back({e->kids[1], e->text == "-" ? -sign : sign});
            continue;
        }
        bool is_var = ((e->kind == expr::k::reg || e->kind == expr::k::sym) && e->text == g_uses->key) ||
                      (e->kind == expr::k::mem && e->kids[0]->kind == expr::k::un && e->kids[0]->text == "&" &&
                       e->kids[0]->kids[0]->kind == expr::k::sym && e->kids[0]->kids[0]->text == g_uses->key);
        if (!is_var || sign < 0 || base)
            return false;
        base = true;
    }
    return base && off >= 0 && off <= 0x100000;
}

void note_use(const ep& a, int width)
{
    int64_t off;
    if (!g_uses || width <= 0 || width > 64 || !use_offset(a, off))
        return;
    uint32_t& w = g_uses->fields[(uint64_t)off];
    w = std::max(w, (uint32_t)width);
}

// the variable is set to v: when that's one of its own fields (p = p->next), the field points
// to another one of these
void note_self(const ep& v, int ptr)
{
    int64_t off;
    if (g_uses && v && v->kind == expr::k::mem && v->width == ptr && use_offset(v->kids[0], off))
        g_uses->self.insert((uint64_t)off);
}

// a frame slot's offset from its name: local_1c is -0x1c, arg_4 is 4 above the return address
// (arm64: 4 above the stack pointer at the entry)
bool slot_offset(const std::string& n, int64_t ptr, int64_t& off)
{
    const char* p = nullptr;
    int64_t base = 0, sign = 1;
    if (n.compare(0, 6, "local_") == 0) {
        p = n.c_str() + 6;
        sign = -1;
    } else if (n.compare(0, 4, "arg_") == 0) {
        p = n.c_str() + 4;
        base = g_arm ? 0 : ptr; // arm64: no return address on the stack
    } else {
        return false;
    }
    char* end = nullptr;
    unsigned long long v = strtoull(p, &end, 16);
    if (!end || *end || end == p)
        return false;
    off = base + sign * (int64_t)v;
    return true;
}

// the struct variable of the frame a slot is inside of (not its first byte), and where in it
const frame_struct* slot_inside(const std::string& n, int64_t& rel)
{
    int64_t off;
    if (!g_types || g_types->frame.empty() || !slot_offset(n, g_types->ptr, off))
        return nullptr;
    for (const frame_struct& f : g_types->frame)
        if (off > f.off && off < f.off + (int64_t)f.def->size) {
            rel = off - f.off;
            return &f;
        }
    return nullptr;
}

std::string type_of(const ep& e);

// e as coef * var for one variable
bool linear(const ep& e, ep& var, int64_t& coef, int depth)
{
    if (!e || depth > 8)
        return false;
    if (e->kind == expr::k::bin && (e->text == "*" || e->text == "<<")) {
        const ep& a = e->kids[0];
        const ep& b = e->kids[1];
        if (b->kind == expr::k::num || (e->text == "*" && a->kind == expr::k::num)) {
            uint64_t k = b->kind == expr::k::num ? b->num : a->num;
            if (e->text == "<<")
                k = k < 16 ? 1ull << k : 0;
            if (!k || k > 0x10000 || !linear(b->kind == expr::k::num ? a : b, var, coef, depth + 1))
                return false;
            coef *= (int64_t)k;
            return true;
        }
        return false;
    }
    if (e->kind == expr::k::bin && (e->text == "+" || e->text == "-")) {
        ep v1, v2;
        int64_t c1 = 0, c2 = 0;
        if (!linear(e->kids[0], v1, c1, depth + 1) || !linear(e->kids[1], v2, c2, depth + 1) || print(v1, 0) != print(v2, 0))
            return false;
        var = v1;
        coef = e->text == "+" ? c1 + c2 : c1 - c2;
        return true;
    }
    if (e->kind == expr::k::num || e->kind == expr::k::bin || e->kind == expr::k::tern)
        return false;
    var = e;
    coef = 1;
    return true;
}

// base + off + index * scale
struct addr_parts {
    ep base, index;
    int64_t off = 0;
    uint32_t scale = 0;
};

bool split_addr(const ep& a, addr_parts& p)
{
    std::vector<ep> terms;
    std::vector<std::pair<const ep, int>> todo{{a, 1}};
    while (!todo.empty()) {
        ep e = todo.back().first;
        int sign = todo.back().second;
        todo.pop_back();
        if (!e || todo.size() > 16)
            return false;
        if (e->kind == expr::k::num) {
            p.off += sign * (int64_t)e->num;
        } else if (e->kind == expr::k::bin && (e->text == "+" || e->text == "-")) {
            todo.push_back({e->kids[0], sign});
            todo.push_back({e->kids[1], e->text == "-" ? -sign : sign});
        } else if (sign < 0) {
            return false;
        } else {
            terms.push_back(e);
        }
    }
    // the base is the term with a pointer type (or the address of a struct variable of the
    // frame); the other one, if any, the index
    const ctypes& lib = *g_types->lib;
    for (const ep& t : terms) {
        if (p.base)
            break;
        if (t->kind == expr::k::un && t->text == "&" && t->kids[0]->kind == expr::k::sym) {
            auto v = g_types->vars.find(t->kids[0]->text);
            if (v != g_types->vars.end() && lib.aggregate(v->second))
                p.base = t;
        } else if (t->kind != expr::k::bin) {
            std::string ty = type_of(t);
            if (!ty.empty() && (lib.pointee(ty) || lib.scalar_pointee(ty)))
                p.base = t;
        }
    }
    // the rest is one variable times a constant, however the compiler spelled the product:
    // (i * 4 + i) * 8 is i * 40
    int64_t scale = 0;
    std::string ix;
    for (const ep& t : terms) {
        if (t == p.base)
            continue;
        ep v;
        int64_t c = 0;
        if (!linear(t, v, c, 0))
            return false;
        std::string pv = print(v, 0);
        if (p.index && pv != ix)
            return false;
        p.index = v;
        ix = pv;
        scale += c;
    }
    if (p.index) {
        if (scale < 1 || scale > 0x100000)
            return false;
        p.scale = (uint32_t)scale;
    }
    return p.base != nullptr;
}

// what a memory read of width bytes at a is through your types: base->path, var.path, p[i]
bool typed_read(const ep& a, int width, std::string& text, std::string& type)
{
    const ctypes& lib = *g_types->lib;
    // a frame variable, or a slot inside a struct one
    if (a->kind == expr::k::un && a->text == "&" && a->kids[0]->kind == expr::k::sym) {
        const std::string& n = a->kids[0]->text;
        int64_t rel = 0;
        std::string path;
        if (const frame_struct* f = slot_inside(n, rel)) {
            if (!lib.member_at(*f->def, (uint64_t)rel, width, path, type))
                return false;
            text = f->key + "." + path;
            return true;
        }
        auto v = g_types->vars.find(n);
        const ctype_def* d = v == g_types->vars.end() ? nullptr : lib.aggregate(v->second);
        if (d && (uint32_t)width != d->size && lib.member_at(*d, 0, width, path, type)) {
            text = n + "." + path;
            return true;
        }
        return false;
    }
    addr_parts p;
    if (!split_addr(a, p) || p.off < 0)
        return false;
    std::string bt = type_of(p.base), idx = p.index ? print(p.index, 0) : std::string();
    const ctype_def* s = bt.empty() ? nullptr : lib.pointee(bt);
    if (s) {
        std::string path;
        if (!lib.member_at(*s, (uint64_t)p.off, width, path, type, idx, p.scale))
            return false;
        text = print(p.base, 100) + "->" + path;
        return true;
    }
    // &local_58 + 8: a field of a struct variable of the frame
    if (p.base->kind == expr::k::un && p.base->text == "&" && p.base->kids[0]->kind == expr::k::sym) {
        const std::string& n = p.base->kids[0]->text;
        auto v = g_types->vars.find(n);
        const ctype_def* d = v == g_types->vars.end() ? nullptr : lib.aggregate(v->second);
        std::string path;
        if (!d || !lib.member_at(*d, (uint64_t)p.off, width, path, type, idx, p.scale))
            return false;
        text = n + "." + path;
        return true;
    }
    // a pointer to a scalar: p[i]
    uint32_t es = bt.empty() ? 0 : lib.scalar_pointee(bt);
    if (!es || (uint32_t)width != es || p.off % es || (p.index && p.scale != es))
        return false;
    std::string at = std::to_string(p.off / es);
    if (p.index)
        at = p.off ? idx + " + " + at : idx;
    text = !p.index && p.off == 0 ? "*" + print(p.base, 90) : print(p.base, 100) + "[" + at + "]";
    type = ctypes::normalize(bt);
    type = type.substr(0, type.rfind('*'));
    return true;
}

// the type of an expression as far as your types say, "" when they don't
std::string type_of(const ep& e)
{
    if (!g_types || !e)
        return std::string();
    if (e->kind == expr::k::reg || e->kind == expr::k::sym) {
        auto it = g_types->vars.find(e->text);
        return it == g_types->vars.end() ? std::string() : it->second;
    }
    if (e->kind == expr::k::call && !e->indirect && e->ref && g_types->db) {
        const prototype* p = g_types->db->callee_proto(e->ref);
        return p && p->ret != "void" && p->ret != "int" ? p->ret : std::string();
    }
    if (e->kind == expr::k::un && e->text == "&" && e->kids[0]->kind == expr::k::sym) {
        auto it = g_types->vars.find(e->kids[0]->text);
        return it == g_types->vars.end() ? std::string() : ctypes::normalize(it->second) + "*";
    }
    if (e->kind == expr::k::bin && (e->text == "+" || e->text == "-")) {
        // pointer arithmetic keeps the type; the address of a member is a pointer to it
        addr_parts p;
        if (!split_addr(e, p) || p.base->kind == expr::k::un)
            return std::string();
        std::string bt = type_of(p.base), path, type;
        const ctypes& lib = *g_types->lib;
        const ctype_def* s = lib.pointee(bt);
        if (s && s->size && p.off % s->size == 0 && (!p.index || p.scale == s->size))
            return bt;
        if (s && p.off >= 0 && lib.member_at(*s, (uint64_t)p.off, 0, path, type, p.index ? print(p.index, 0) : std::string(), p.scale)) {
            size_t br = type.find('[');
            return (br == std::string::npos ? type : type.substr(0, br)) + "*";
        }
        return lib.scalar_pointee(bt) ? bt : std::string();
    }
    if (e->kind == expr::k::mem) {
        const ep& a = e->kids[0];
        if (a->kind == expr::k::un && a->text == "&" && a->kids[0]->kind == expr::k::sym) {
            auto it = g_types->vars.find(a->kids[0]->text);
            if (it != g_types->vars.end() && !g_types->lib->aggregate(it->second))
                return it->second; // a frame variable's value
        }
        std::string text, type;
        if (typed_read(a, e->width, text, type))
            return type;
    }
    return std::string();
}

// base + off as an address through your types: &p->field, &p[2], &pt.y, (char*)p + 3
bool typed_address(const ep& e, std::string& text)
{
    addr_parts p;
    if (!split_addr(e, p))
        return false;
    const ctypes& lib = *g_types->lib;
    std::string path, type, idx = p.index ? print(p.index, 0) : std::string();
    if (p.base->kind == expr::k::un) { // &local_58 + 8
        const std::string& n = p.base->kids[0]->text;
        const ctype_def* d = lib.aggregate(g_types->vars.at(n));
        if (!d || p.off < 0 || !lib.member_at(*d, (uint64_t)p.off, 0, path, type, idx, p.scale))
            return false;
        text = "&" + n + "." + path;
        return true;
    }
    std::string bt = type_of(p.base);
    const ctype_def* s = lib.pointee(bt);
    uint32_t es = s ? 0 : lib.scalar_pointee(bt);
    if (!s && !es)
        return false;
    if (s && p.off >= 0 && lib.member_at(*s, (uint64_t)p.off, 0, path, type, idx, p.scale)) {
        // the start of an array member is the array: p->name, not &p->name[0]
        if (path.size() > 3 && path.compare(path.size() - 3, 3, "[0]") == 0)
            text = print(p.base, 100) + "->" + path.substr(0, path.size() - 3);
        else
            text = "&" + print(p.base, 100) + "->" + path;
        return true;
    }
    // pointer arithmetic counts in elements: p + 1 is the next one
    uint32_t step = s ? s->size : es;
    if (step && p.off % step == 0 && (!p.index || p.scale == step) && (p.index || p.off)) {
        int64_t k = p.off / (int64_t)step;
        std::string at = p.index ? idx : std::string();
        if (k)
            at += (at.empty() ? std::string() : k < 0 ? " - " : " + ") + (at.empty() && k < 0 ? "-" : "") +
                  std::to_string(k < 0 ? -k : k);
        text = print(p.base, 100) + (at[0] == '-' ? " - " + at.substr(1) : " + " + at);
        return true;
    }
    // no member starts there: count in bytes, the way the machine does
    text = "(char*)" + print(p.base, 100);
    if (p.index)
        text += " + " + print(p.index, 12) + (p.scale > 1 ? " * " + hex_num(p.scale, false) : std::string());
    if (p.off)
        text += (p.off < 0 ? " - " : " + ") + hex_num((uint64_t)(p.off < 0 ? -p.off : p.off), false);
    return true;
}

// logical negation, flipping comparisons instead of wrapping in !()
ep negate(const ep& e)
{
    if (e && e->fp)
        return e_un("!", e);
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
        if (g_uses)
            note_use(a, e->width);
        // "u": a byte or two read zero extended (arm64's ldrb / ldrh)
        bool zext = e->text == "u" && e->width < 4;
        std::string ty = zext ? std::string("unsigned ") + mem_type(e->width) : std::string(mem_type(e->width));
        if (g_types) {
            std::string text, type;
            if (typed_read(a, e->width, text, type))
                return text;
            // through a typed pointer, but not a whole member: *(char*)&p->flags, or counted in bytes
            std::string at;
            if (a->kind != expr::k::un && typed_address(a, at) && at.compare(0, 2, "&*") != 0)
                return "*(" + ty + "*)" + (at[0] == '(' ? "(" + at + ")" : at);
        }
        if (a->kind == expr::k::un && a->text == "&" && a->kids[0]->kind == expr::k::num) // no name there
            return "*(" + ty + "*)" + print(a->kids[0], 100);
        if (a->kind == expr::k::un && a->text == "&") // *(&sym) -> sym
            return zext ? "(" + ty + ")" + print(a->kids[0], 100) : print(a->kids[0], 100);
        return "*(" + ty + "*)" + print(a, 100);
    }
    case expr::k::un:
        if (g_types && e->text == "&" && e->kids[0]->kind == expr::k::sym) {
            int64_t rel = 0;
            std::string path, type;
            const frame_struct* f = slot_inside(e->kids[0]->text, rel);
            if (f && g_types->lib->member_at(*f->def, (uint64_t)rel, 0, path, type))
                return "&" + f->key + "." + path;
        }
        if (e->text == "&" && e->kids[0]->kind == expr::k::num) // an address without a name
            return print(e->kids[0], parent_prec);
        return e->text + print(e->kids[0], 90);
    case expr::k::bin: {
        if (g_types && (e->text == "+" || e->text == "-")) {
            std::string text;
            if (typed_address(e, text))
                return 100 < parent_prec && text[0] == '(' ? "(" + text + ")" : text;
        }
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
    if (e->kind == expr::k::call && (e->text.compare(0, 8, "__readfs") == 0 || e->text.compare(0, 8, "__readgs") == 0))
        return true; // thread data
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
    if (g_arm) {
        // x0 - x30 and their w halves (fp and lr are x29 and x30), and sp. the zero register
        // is a number, not a variable
        if (n == "fp")
            return "x29";
        if (n == "lr")
            return "x30";
        if (n == "sp" || n == "wsp")
            return "sp";
        if ((n.size() == 2 || n.size() == 3) && (n[0] == 'x' || n[0] == 'w') && std::isdigit((unsigned char)n[1]) &&
            (n.size() == 2 || std::isdigit((unsigned char)n[2])) && std::atoi(n.c_str() + 1) <= 30)
            return "x" + n.substr(1);
        return "";
    }
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
    if (g_arm || is64 || fam.empty())
        return fam;
    static const std::map<std::string, std::string> m = {
        {"rax", "eax"}, {"rbx", "ebx"}, {"rcx", "ecx"}, {"rdx", "edx"},
        {"rsi", "esi"}, {"rdi", "edi"}, {"rbp", "ebp"}, {"rsp", "esp"}};
    auto it = m.find(fam);
    return it == m.end() ? fam : it->second;
}

int reg_bit(const std::string& fam)
{
    if (g_arm) { // x0 - x30, sp 31
        if (fam == "sp")
            return 31;
        if (fam.size() >= 2 && fam[0] == 'x' && std::isdigit((unsigned char)fam[1]))
            return std::atoi(fam.c_str() + 1) <= 30 ? std::atoi(fam.c_str() + 1) : -1;
        return -1;
    }
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
    static const char* aapcs[] = {"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"};
    if (g_arm)
        return index >= 0 && index < 8 ? aapcs[index] : nullptr;
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
    static const char* arm[32] = {"x0",  "x1",  "x2",  "x3",  "x4",  "x5",  "x6",  "x7",  "x8",  "x9",  "x10",
                                  "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x19", "x20", "x21",
                                  "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29", "x30", "sp"};
    if (g_arm)
        return b >= 0 && b < 32 ? arm[b] : "";
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
    // arm64 ccmp: the flags are pre ? these : the constant nzcv
    ep pre;
    uint8_t nzcv = 0;
    bool fp = false;  // arm64 fcmp: a and b are floating point registers
    bool sum = false; // arm64 adds: res is a + b (the carry: it wrapped around)
    bool wide = false; // arm64: of x registers (unsigned is unsigned long long)
};

// what one instruction reads and writes: register families as reg_bit masks, and
// whether it tests or changes the status flags
struct insn_rw {
    uint32_t rd = 0, wr = 0;
    uint32_t rd_known = 0; // arm64: reads of an address known on every way in (not in rd)
    uint32_t vwr = 0;      // arm64: vector registers written (by number)
    int vzero = -1;        // arm64: the vector register it sets to zero
    bool flags_rd = false, flags_wr = false;
    bool call = false, ret = false;
    bool tail = false;   // a jump out of the function (a tail call)
    uint64_t target = 0; // direct call / tail call target
    int proto_args = -1; // a call whose prototype says how many arguments it takes
};

// ------------------------------------------------------------------ arm64 instructions

// the zero register reads as 0 and writes nowhere
bool arm_zr(csh cs, unsigned r)
{
    const char* n = cs_reg_name(cs, r);
    return n && (!strcmp(n, "xzr") || !strcmp(n, "wzr"));
}

// bytes in a register: w 4, x (and sp, fp, lr) 8, the vector views b h s d q
int arm_reg_size(csh cs, unsigned r)
{
    const char* n = cs_reg_name(cs, r);
    if (!n)
        return 8;
    switch (n[0]) {
    case 'w': return 4;
    case 'b': return 1;
    case 'h': return 2;
    case 's': return strcmp(n, "sp") ? 4 : 8;
    case 'q':
    case 'v':
    case 'z': return 16;
    default: return 8;
    }
}

bool arm_is_load(unsigned id)
{
    switch (id) {
    case ARM64_INS_LDR: case ARM64_INS_LDUR: case ARM64_INS_LDRB: case ARM64_INS_LDURB: case ARM64_INS_LDRH:
    case ARM64_INS_LDURH: case ARM64_INS_LDRSB: case ARM64_INS_LDURSB: case ARM64_INS_LDRSH: case ARM64_INS_LDURSH:
    case ARM64_INS_LDRSW: case ARM64_INS_LDURSW: case ARM64_INS_LDAR: case ARM64_INS_LDARB: case ARM64_INS_LDARH:
    case ARM64_INS_LDAPR: case ARM64_INS_LDAPRB: case ARM64_INS_LDAPRH: case ARM64_INS_LDAXR: case ARM64_INS_LDXR:
    case ARM64_INS_LDAXRB: case ARM64_INS_LDXRB: case ARM64_INS_LDAXRH: case ARM64_INS_LDXRH:
    case ARM64_INS_LDP: case ARM64_INS_LDPSW: case ARM64_INS_LDNP:
        return true;
    default:
        return false;
    }
}

bool arm_is_store(unsigned id)
{
    switch (id) {
    case ARM64_INS_STR: case ARM64_INS_STUR: case ARM64_INS_STRB: case ARM64_INS_STURB: case ARM64_INS_STRH:
    case ARM64_INS_STURH: case ARM64_INS_STLR: case ARM64_INS_STLRB: case ARM64_INS_STLRH: case ARM64_INS_STP:
    case ARM64_INS_STNP:
        return true;
    default:
        return false;
    }
}

// bytes one register of a load / store moves
int arm_mem_width(csh cs, cs_insn* in)
{
    switch (in->id) {
    case ARM64_INS_LDRB: case ARM64_INS_LDURB: case ARM64_INS_LDRSB: case ARM64_INS_LDURSB: case ARM64_INS_STRB:
    case ARM64_INS_STURB: case ARM64_INS_LDARB: case ARM64_INS_STLRB: case ARM64_INS_LDAPRB: case ARM64_INS_LDAXRB:
    case ARM64_INS_LDXRB:
        return 1;
    case ARM64_INS_LDRH: case ARM64_INS_LDURH: case ARM64_INS_LDRSH: case ARM64_INS_LDURSH: case ARM64_INS_STRH:
    case ARM64_INS_STURH: case ARM64_INS_LDARH: case ARM64_INS_STLRH: case ARM64_INS_LDAPRH: case ARM64_INS_LDAXRH:
    case ARM64_INS_LDXRH:
        return 2;
    case ARM64_INS_LDRSW: case ARM64_INS_LDURSW: case ARM64_INS_LDPSW:
        return 4;
    default: {
        const cs_arm64& x = in->detail->arm64;
        return x.op_count >= 1 && x.operands[0].type == ARM64_OP_REG ? arm_reg_size(cs, x.operands[0].reg) : 8;
    }
    }
}

// ldrb / ldrh: the byte or two zero extended
bool arm_zext_load(unsigned id)
{
    switch (id) {
    case ARM64_INS_LDRB: case ARM64_INS_LDURB: case ARM64_INS_LDARB: case ARM64_INS_LDAPRB: case ARM64_INS_LDAXRB:
    case ARM64_INS_LDXRB: case ARM64_INS_LDRH: case ARM64_INS_LDURH: case ARM64_INS_LDARH: case ARM64_INS_LDAPRH:
    case ARM64_INS_LDAXRH: case ARM64_INS_LDXRH:
        return true;
    default:
        return false;
    }
}

bool arm_is_call(unsigned id)
{
    return id == ARM64_INS_BL || id == ARM64_INS_BLR || id == ARM64_INS_BLRAA || id == ARM64_INS_BLRAAZ ||
           id == ARM64_INS_BLRAB || id == ARM64_INS_BLRABZ;
}

bool arm_is_ret(unsigned id) { return id == ARM64_INS_RET || id == ARM64_INS_RETAA || id == ARM64_INS_RETAB; }

bool arm_is_br(unsigned id)
{
    return id == ARM64_INS_BR || id == ARM64_INS_BRAA || id == ARM64_INS_BRAAZ || id == ARM64_INS_BRAB ||
           id == ARM64_INS_BRABZ;
}

// b.cond (not b, which capstone gives the same id)
bool arm_conditional(const cs_arm64& x)
{
    return x.cc != ARM64_CC_INVALID && x.cc != ARM64_CC_AL && x.cc != ARM64_CC_NV;
}

// floating point and vector instructions (an operand in one of those registers): the lifter
// shows them as they are
bool arm_vector(csh cs, cs_insn* in)
{
    const cs_arm64& x = in->detail->arm64;
    for (uint8_t i = 0; i < x.op_count; i++) {
        if (x.operands[i].type != ARM64_OP_REG)
            continue;
        const char* n = cs_reg_name(cs, x.operands[i].reg);
        if (n && n[0] != 'x' && n[0] != 'w' && strcmp(n, "sp") && strcmp(n, "fp") && strcmp(n, "lr"))
            return true;
    }
    return false;
}

// the number of a floating point / vector register (b0 h0 s0 d0 q0 v0 are one), else -1
int arm_vreg(const char* n)
{
    if (!n || !n[0] || !strchr("bhsdqvz", n[0]) || !isdigit((unsigned char)n[1]))
        return -1;
    return atoi(n + 1);
}

// the vector registers an instruction writes, and the one it sets to zero (movi v0.2d, #0;
// fmov d0, xzr; dup v0.4s, wzr), -1 when none
void arm_vec_effect(csh cs, cs_insn* in, uint32_t& wr, int& zero)
{
    wr = 0;
    zero = -1;
    const cs_arm64& x = in->detail->arm64;
    const char* mn = in->mnemonic;
    if (mn[0] == 's' && mn[1] == 't')
        return; // a store
    bool ld = mn[0] == 'l' && mn[1] == 'd'; // a load: every register before the address
    for (uint8_t i = 0; i < x.op_count && x.operands[i].type != ARM64_OP_MEM; i++) {
        int n = x.operands[i].type == ARM64_OP_REG ? arm_vreg(cs_reg_name(cs, x.operands[i].reg)) : -1;
        if (n >= 0)
            wr |= 1u << n;
        if (!ld)
            break;
    }
    if (!wr || (wr & (wr - 1)) || x.op_count != 2)
        return;
    const cs_arm64_op& s = x.operands[1];
    if ((in->id == ARM64_INS_MOVI && s.type == ARM64_OP_IMM && s.imm == 0) ||
        ((in->id == ARM64_INS_DUP || in->id == ARM64_INS_FMOV) && s.type == ARM64_OP_REG && arm_zr(cs, s.reg)))
        for (zero = 0; !(wr & (1u << zero)); zero++)
            ;
}

// instructions with nothing to show: hints, barriers, pointer authentication, prefetches
bool arm_nothing(unsigned id)
{
    switch (id) {
    case ARM64_INS_NOP: case ARM64_INS_HINT: case ARM64_INS_BTI: case ARM64_INS_DMB: case ARM64_INS_DSB:
    case ARM64_INS_ISB: case ARM64_INS_PRFM: case ARM64_INS_YIELD: case ARM64_INS_CSDB: case ARM64_INS_CLREX:
    case ARM64_INS_PACIASP: case ARM64_INS_PACIBSP: case ARM64_INS_AUTIASP: case ARM64_INS_AUTIBSP:
    case ARM64_INS_PACIAZ: case ARM64_INS_PACIBZ: case ARM64_INS_AUTIAZ: case ARM64_INS_AUTIBZ:
    case ARM64_INS_XPACLRI:
        return true;
    default:
        return false;
    }
}

// a + b with numbers worked out (adrp's page plus the low bits is an address)
ep fold(const ep& e)
{
    if (!e || e->kind != expr::k::bin || e->kids[0]->kind != expr::k::num || e->kids[1]->kind != expr::k::num)
        return e;
    uint64_t a = e->kids[0]->num, b = e->kids[1]->num;
    const std::string& o = e->text;
    if (o == "+")
        return e_num(a + b, true);
    if (o == "-")
        return e_num(a - b, true);
    if (o == "*")
        return e_num(a * b, true);
    if (o == "&")
        return e_num(a & b, true);
    if (o == "|")
        return e_num(a | b, true);
    if (o == "^")
        return e_num(a ^ b, true);
    if (o == "<<" && b < 64)
        return e_num(a << b, true);
    return e;
}

// does condition cc hold for the flags nzcv (n in bit 3 .. v in bit 0)?
bool nzcv_holds(uint8_t f, int cc)
{
    bool n = f & 8, z = f & 4, c = f & 2, v = f & 1;
    switch (cc) {
    case ARM64_CC_EQ: return z;
    case ARM64_CC_NE: return !z;
    case ARM64_CC_HS: return c;
    case ARM64_CC_LO: return !c;
    case ARM64_CC_MI: return n;
    case ARM64_CC_PL: return !n;
    case ARM64_CC_VS: return v;
    case ARM64_CC_VC: return !v;
    case ARM64_CC_HI: return c && !z;
    case ARM64_CC_LS: return !c || z;
    case ARM64_CC_GE: return n == v;
    case ARM64_CC_LT: return n != v;
    case ARM64_CC_GT: return !z && n == v;
    case ARM64_CC_LE: return z || n != v;
    default: return true;
    }
}


// ------------------------------------------------------------------ lifter

class lifter {
public:
    lifter(database& db, csh cs) : db_(db), cs_(cs), is64_(db.bin.is64()), arm_(db.bin.arch == bin_arch::arm64) {}
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
    bool arm_;
    // the stack pointer, the frame pointer and the register a result comes back in
    std::string sp_ = arm_ ? "sp" : "rsp", fp_ = arm_ ? "x29" : "rbp", ret_ = arm_ ? "x0" : "rax";
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
    std::string callee_text(uint64_t t);
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

    // arm64
    std::set<uint64_t> arm_skip_; // prologue saves, epilogue restores, the frame pointer's setup
    void frame_pass_arm(const cfg& g, int entry);
    void find_saves_arm(const cfg& g, int entry);
    void access_arm(cs_insn* in, uint32_t& rd, uint32_t& wr, bool& flags_rd, bool& flags_wr);
    bool slot_of_arm(const arm64_op_mem& m, int64_t& off) const;
    ep mem_address_arm(const cs_arm64_op& op, std::unordered_map<std::string, ep>& cur, int width);
    ep operand_arm(const cs_arm64_op& op, std::unordered_map<std::string, ep>& cur);
    ep addr_value(uint64_t v);
    ep place(uint64_t a);
    ep inside_item(uint64_t a);
    ep named_sum(const ep& e, bool access);
    ep build_cond_arm(const flag_state& fs, int cc, bool& ok);
};

// registers a call may change: rax (the result) and the other scratch registers
uint32_t lifter::scratch() const
{
    if (arm_)
        return 0x7ffffu; // x0 - x18 (x0 the result; x16 - x18 the linker's and the platform's)
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
    if (arm_) {
        bool frd = false, fwr = false;
        access_arm(in, rd, wr, frd, fwr);
        if (arm_is_call(in->id))
            wr |= scratch();
        return rd;
    }
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
            if (arm_ ? arm_is_br(in->id) && !db_.an.tables.count(a)
                     : in->id == X86_INS_JMP && !(x.op_count >= 1 && x.operands[0].type == X86_OP_IMM) &&
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
    if (!is64_ || (!arm_ && db_.bin.format != bin_format::pe && (live[entry] & 1u)))
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
            if (arm_ && arm_is_call(in->id)) {
                // arm64: x0 goes on to the next call as its first argument, unless it takes none
                const cs_arm64& x = in->detail->arm64;
                int ar = in->id == ARM64_INS_BL && x.op_count >= 1 && x.operands[0].type == ARM64_OP_IMM
                             ? callee_of((uint64_t)x.operands[0].imm).arity : -1;
                if (ar != 0)
                    rd |= 1u;
            }
            if (rd & 1u) {
                used = true;
                break;
            }
            if (wr & 1u)
                break; // overwritten, or clobbered by the next call
            bool leaves = arm_ ? in->id == ARM64_INS_B || in->id == ARM64_INS_CBZ || in->id == ARM64_INS_CBNZ ||
                                     in->id == ARM64_INS_TBZ || in->id == ARM64_INS_TBNZ || arm_is_br(in->id) || arm_is_ret(in->id)
                               : cs_insn_group(cs_, in, X86_GRP_JUMP) || cs_insn_group(cs_, in, X86_GRP_RET);
            if (leaves) {
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
    int64_t ptr = arm_ ? 0 : is64_ ? 8 : 4; // arm64 keeps the return address in x30
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

// how a call to t is written. an import's stub (the plt) as a call to the import, the way the
// source has it: memcmp(...), not j_memcmp(...)
std::string lifter::callee_text(uint64_t t)
{
    auto ti = db_.an.thunk_import.find(t);
    std::string n = ti != db_.an.thunk_import.end() && !db_.user_names.count(t)
        ? db_.call_name(db_.bin.imports[ti->second].slot) : db_.call_name(t);
    return n.empty() ? db_.location(t) : n;
}

const prototype* lifter::call_proto(cs_insn* in, std::string* name, uint64_t* ref)
{
    if (arm_) { // bl f; blr / br through a register are named from what the register holds
        const cs_arm64& a = in->detail->arm64;
        if ((in->id != ARM64_INS_BL && in->id != ARM64_INS_B) || a.op_count < 1 || a.operands[0].type != ARM64_OP_IMM)
            return nullptr;
        uint64_t t = (uint64_t)a.operands[0].imm;
        if (ref)
            *ref = t;
        if (name)
            *name = callee_text(t);
        return db_.callee_proto(t);
    }
    const cs_x86& x = in->detail->x86;
    if (x.op_count < 1)
        return nullptr;
    const cs_x86_op& op = x.operands[0];
    if (op.type == X86_OP_IMM) {
        uint64_t t = (uint64_t)op.imm;
        if (ref)
            *ref = t;
        if (name)
            *name = callee_text(t);
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
                *name = db_.call_name(slot);
            return known_prototype(n);
        }
        // call [got slot]: a function of this file, called the way rust and -fno-plt code do
        uint64_t via;
        if (got_target(db_.bin, db_.an, slot, via)) {
            if (ref)
                *ref = via;
            if (name) {
                std::string cn = db_.call_name(via);
                *name = cn.empty() ? db_.location(via) : cn;
            }
            return db_.callee_proto(via);
        }
    }
    return nullptr;
}

// what a 32-bit callee takes off the stack itself (stdcall: ret n)
int lifter::callee_pops(cs_insn* call)
{
    if (is64_ || arm_)
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

// a place in memory at a known address: &name, &item + k inside a string or data item with a
// name (a merged string's tail), else &number
ep lifter::place(uint64_t a)
{
    if (!db_.name_at(a).empty())
        return e_un("&", sym_for(a));
    ep in = inside_item(a);
    return in ? in : e_un("&", e_num(a, true));
}

ep lifter::inside_item(uint64_t a)
{
    if (!db_.bin.is_mapped(a))
        return nullptr;
    uint64_t h = db_.an.item_head(a);
    if (h >= a || !(db_.an.flags_at(h) & (fl_str | fl_data)) || db_.name_at(h).empty())
        return nullptr;
    return e_bin("+", e_un("&", sym_for(h)), e_num(a - h));
}

ep lifter::mem_address(const x86_op_mem& m, std::unordered_map<std::string, ep>& cur, uint64_t rip, int width)
{
    if (m.base == X86_REG_RIP)
        return place(rip + (uint64_t)m.disp);
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
        return place((uint64_t)m.disp);
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
        ep a = addr_value(v);
        return a->kind == expr::k::num ? e_num((uint64_t)op.imm, true) : a;
    }
    if (op.type == X86_OP_MEM) {
        uint64_t rip = in->address + in->size;
        if (op.mem.segment == X86_REG_FS || op.mem.segment == X86_REG_GS) {
            // thread data: fs:[0x28] is the stack canary on linux, gs:[0x60] the peb on windows
            x86_op_mem m = op.mem;
            m.segment = X86_REG_INVALID;
            ep at = m.base == X86_REG_INVALID && m.index == X86_REG_INVALID ? e_num((uint64_t)m.disp, true)
                                                                         : mem_address(m, cur, rip, op.size);
            const char* sz = op.size == 1 ? "byte" : op.size == 2 ? "word" : op.size == 4 ? "dword" : "qword";
            return e_intr(std::string(op.mem.segment == X86_REG_FS ? "__readfs" : "__readgs") + sz, {at});
        }
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

// ------------------------------------------------------------------ arm64 lifting

// registers read and written as reg_bit masks (x30, the link register, is left out: calls and
// returns use it, the code doesn't), and whether the flags are tested / set. capstone's own
// lists are off for aliases (cmp writes nothing, cbz doesn't test the flags)
void lifter::access_arm(cs_insn* in, uint32_t& rd, uint32_t& wr, bool& flags_rd, bool& flags_wr)
{
    rd = wr = 0;
    flags_rd = flags_wr = false;
    const cs_arm64& x = in->detail->arm64;
    unsigned id = in->id;
    auto bit = [&](unsigned r) -> uint32_t {
        int b = reg_bit(reg_family(cs_reg_name(cs_, r)));
        return b >= 0 && b != 30 ? 1u << b : 0u;
    };
    int mi = -1;
    for (int k = 0; k < x.op_count; k++)
        if (x.operands[k].type == ARM64_OP_MEM) {
            mi = k;
            if (x.operands[k].mem.base != ARM64_REG_INVALID)
                rd |= bit(x.operands[k].mem.base);
            if (x.operands[k].mem.index != ARM64_REG_INVALID)
                rd |= bit(x.operands[k].mem.index);
        }
    auto regs = [&](int from, int to) {
        uint32_t m = 0;
        for (int k = from; k < to && k < x.op_count; k++)
            if (x.operands[k].type == ARM64_OP_REG)
                m |= bit(x.operands[k].reg);
        return m;
    };
    switch (id) {
    case ARM64_INS_CMP:
    case ARM64_INS_CMN:
    case ARM64_INS_TST:
        rd |= regs(0, x.op_count);
        flags_wr = true;
        break;
    case ARM64_INS_CCMP:
    case ARM64_INS_CCMN:
        rd |= regs(0, x.op_count);
        flags_rd = flags_wr = true;
        break;
    case ARM64_INS_B:
        flags_rd = arm_conditional(x);
        break;
    case ARM64_INS_CBZ:
    case ARM64_INS_CBNZ:
    case ARM64_INS_TBZ:
    case ARM64_INS_TBNZ:
        rd |= regs(0, 1);
        break;
    case ARM64_INS_SVC: // a system call: the number in x8 (x16 on apple), arguments from x0, result in x0
        rd |= 0x3fu | (1u << (db_.bin.format == bin_format::macho ? 16 : 8));
        wr |= 1u;
        break;
    default:
        if (arm_is_call(id) || arm_is_br(id) || arm_is_ret(id)) {
            rd |= regs(0, 1);
        } else if (arm_is_store(id)) {
            rd |= regs(0, mi < 0 ? x.op_count : mi);
        } else if (arm_is_load(id)) {
            wr |= regs(0, mi < 0 ? x.op_count : mi);
        } else if (x.op_count >= 1 && x.operands[0].type == ARM64_OP_REG) {
            wr |= bit(x.operands[0].reg);
            rd |= regs(1, x.op_count);
            if (id == ARM64_INS_MOVK || id == ARM64_INS_BFI || id == ARM64_INS_BFXIL || id == ARM64_INS_BFM)
                rd |= bit(x.operands[0].reg); // they keep the rest of it
        }
        switch (id) {
        case ARM64_INS_CSEL: case ARM64_INS_CSET: case ARM64_INS_CSETM: case ARM64_INS_CSINC: case ARM64_INS_CSINV:
        case ARM64_INS_CSNEG: case ARM64_INS_CINC: case ARM64_INS_CINV: case ARM64_INS_CNEG: case ARM64_INS_ADC:
        case ARM64_INS_ADCS: case ARM64_INS_SBC: case ARM64_INS_SBCS: case ARM64_INS_NGC: case ARM64_INS_NGCS:
            flags_rd = true;
            break;
        default:
            break;
        }
        flags_wr = x.update_flags;
        break;
    }
    if (mi >= 0 && x.writeback && x.operands[mi].mem.base != ARM64_REG_INVALID)
        wr |= bit(x.operands[mi].mem.base);
}

// where sp is before each instruction, from the entry, and whether x29 is a frame pointer
// (mov x29, sp / add x29, sp, #16 after the prologue's stp x29, x30, [sp, #-32]!)
void lifter::frame_pass_arm(const cfg& g, int entry)
{
    const int64_t unknown = INT64_MIN;
    size_t nb = g.blocks.size();
    sp_at_.clear();
    rbp_frame_ = false;
    bool fp_bad = false;
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
    auto fam_of = [&](const cs_arm64_op& op) {
        return op.type == ARM64_OP_REG ? reg_family(cs_reg_name(cs_, op.reg)) : std::string();
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
            uint8_t code[4];
            const uint8_t* p = code;
            size_t left = db_.bin.read(a, code, sizeof(code));
            uint64_t addr = a;
            if (!cs_disasm_iter(cs_, &p, &left, &addr, insn)) {
                sp = unknown;
                continue;
            }
            const cs_arm64& x = insn->detail->arm64;
            unsigned id = insn->id;
            auto known = [&](int64_t v) { return sp == unknown ? unknown : v; };
            std::string d0 = x.op_count >= 1 ? fam_of(x.operands[0]) : std::string();
            std::string s1 = x.op_count >= 2 ? fam_of(x.operands[1]) : std::string();
            bool imm2 = x.op_count >= 3 && x.operands[2].type == ARM64_OP_IMM;
            int64_t k2 = imm2 ? x.operands[2].imm << (x.operands[2].shift.type == ARM64_SFT_LSL ? x.operands[2].shift.value : 0) : 0;
            // a load / store that moves its base register: [sp, #-32]! and [sp], #32
            for (int k = 0; k < x.op_count; k++) {
                const cs_arm64_op& op = x.operands[k];
                if (op.type != ARM64_OP_MEM || !x.writeback || reg_family(cs_reg_name(cs_, op.mem.base)) != "sp")
                    continue;
                if (x.post_index)
                    sp = k + 1 < x.op_count && x.operands[k + 1].type == ARM64_OP_IMM ? known(sp + x.operands[k + 1].imm) : unknown;
                else
                    sp = known(sp + op.mem.disp);
            }
            bool writes0 = x.op_count >= 1 && x.operands[0].type == ARM64_OP_REG && id != ARM64_INS_CMP &&
                           id != ARM64_INS_CMN && id != ARM64_INS_TST && id != ARM64_INS_CCMP && id != ARM64_INS_CCMN &&
                           !arm_is_store(id) && !arm_is_call(id) && !arm_is_br(id) && id != ARM64_INS_CBZ &&
                           id != ARM64_INS_CBNZ && id != ARM64_INS_TBZ && id != ARM64_INS_TBNZ;
            if (!writes0)
                continue;
            bool add = id == ARM64_INS_ADD, sub = id == ARM64_INS_SUB;
            if (d0 == "sp") {
                if ((add || sub) && s1 == "sp" && imm2)
                    sp = known(sp + (add ? k2 : -k2));
                else if ((add || sub) && s1 == "x29" && imm2 && rbp_frame_)
                    sp = rbp_off_ + (add ? k2 : -k2);
                else if (id == ARM64_INS_MOV && s1 == "x29" && rbp_frame_)
                    sp = rbp_off_;
                else
                    sp = unknown;
            } else if (d0 == "x29" || (arm_is_load(id) && x.op_count >= 2 && fam_of(x.operands[1]) == "x29")) {
                // mov x29, sp / add x29, sp, #k sets up the frame pointer; a load into it is the
                // epilogue putting the caller's back
                if (id == ARM64_INS_MOV && s1 == "sp" && sp != unknown) {
                    if (rbp_frame_ && rbp_off_ != sp)
                        fp_bad = true;
                    rbp_frame_ = true;
                    rbp_off_ = sp;
                } else if (add && s1 == "sp" && imm2 && sp != unknown) {
                    if (rbp_frame_ && rbp_off_ != sp + k2)
                        fp_bad = true;
                    rbp_frame_ = true;
                    rbp_off_ = sp + k2;
                } else if (!arm_is_load(id)) {
                    fp_bad = true;
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
    if (fp_bad)
        rbp_frame_ = false;
}

bool lifter::slot_of_arm(const arm64_op_mem& m, int64_t& off) const
{
    if (m.index != ARM64_REG_INVALID || m.base == ARM64_REG_INVALID)
        return false;
    std::string fam = reg_family(cs_reg_name(cs_, m.base));
    if (fam == "sp" && cur_sp_known_) {
        off = cur_sp_ + m.disp;
        return true;
    }
    if (fam == "x29" && rbp_frame_) {
        off = rbp_off_ + m.disp;
        return true;
    }
    return false;
}

// the registers the prologue saves (stp x29, x30, [sp, #-32]!, str x19, [sp, #16]) and the
// epilogue loads back, and the frame pointer's setup: bookkeeping, not statements. a save is a
// store of a callee-saved register nothing has changed yet on any way there (the prologue can
// be in a branch: shrink wrapping); the link register's store always is one
void lifter::find_saves_arm(const cfg& g, int entry)
{
    arm_skip_.clear();
    size_t nb = g.blocks.size();
    if (entry < 0 || (size_t)entry >= nb)
        return;
    cs_insn* insn = cs_malloc(cs_);
    if (!insn)
        return;
    auto decode = [&](uint64_t a) {
        uint8_t code[4];
        const uint8_t* p = code;
        size_t left = db_.bin.read(a, code, sizeof(code));
        uint64_t addr = a;
        return cs_disasm_iter(cs_, &p, &left, &addr, insn);
    };
    auto saved_reg = [&](unsigned r) {
        std::string n = cs_reg_name(cs_, r);
        if (n == "fp" || n == "lr")
            return true;
        int v = n.size() >= 2 && (n[0] == 'x' || n[0] == 'd') ? std::atoi(n.c_str() + 1) : -1;
        return n[0] == 'x' ? v >= 19 && v <= 28 : v >= 8 && v <= 15; // d8 - d15 keep their low halves
    };
    auto set_sp = [&](uint64_t a) {
        auto it = sp_at_.find(a);
        cur_sp_known_ = it != sp_at_.end();
        cur_sp_ = cur_sp_known_ ? it->second : 0;
    };
    // registers written in each block, and on some way into it
    std::vector<uint32_t> gen(nb, 0), in(nb, 0);
    for (size_t b = 0; b < nb; b++)
        for (uint64_t a : g.blocks[b].insns)
            if (decode(a)) {
                uint32_t rd = 0, wr = 0;
                bool frd = false, fwr = false;
                access_arm(insn, rd, wr, frd, fwr);
                if (arm_is_call(insn->id))
                    wr |= scratch();
                gen[b] |= wr;
            }
    for (bool changed = true; changed;) {
        changed = false;
        for (size_t b = 0; b < nb; b++)
            for (const cfg_edge& e : g.blocks[b].succ) {
                uint32_t v = in[e.to] | in[b] | gen[b];
                if (v != in[e.to]) {
                    in[e.to] = v;
                    changed = true;
                }
            }
    }
    std::map<int64_t, std::string> slots; // frame offset -> the register saved there
    for (size_t b = 0; b < nb; b++) {
        uint32_t written = in[b];
        for (uint64_t a : g.blocks[b].insns) {
            if (!decode(a))
                break;
            const cs_arm64& x = insn->detail->arm64;
            set_sp(a);
            if (insn->id == ARM64_INS_STP || insn->id == ARM64_INS_STR || insn->id == ARM64_INS_STUR) {
                int mi = x.op_count - 1;
                while (mi > 0 && x.operands[mi].type != ARM64_OP_MEM)
                    mi--;
                int64_t off = 0;
                bool save = mi >= 1 && x.operands[mi].type == ARM64_OP_MEM && slot_of_arm(x.operands[mi].mem, off);
                for (int k = 0; save && k < mi; k++) {
                    int bit = x.operands[k].type == ARM64_OP_REG ? reg_bit(reg_family(cs_reg_name(cs_, x.operands[k].reg))) : -1;
                    save = x.operands[k].type == ARM64_OP_REG && saved_reg(x.operands[k].reg) && !(bit >= 0 && (written & (1u << bit)));
                }
                if (save) {
                    int size = arm_reg_size(cs_, x.operands[0].reg);
                    for (int k = 0; k < mi; k++)
                        slots[off + k * size] = cs_reg_name(cs_, x.operands[k].reg);
                    arm_skip_.insert(a);
                    continue;
                }
            }
            // mov x29, sp / add x29, sp, #k: the frame pointer
            if ((insn->id == ARM64_INS_MOV || insn->id == ARM64_INS_ADD) && x.op_count >= 2 &&
                x.operands[0].type == ARM64_OP_REG && x.operands[1].type == ARM64_OP_REG &&
                reg_family(cs_reg_name(cs_, x.operands[0].reg)) == "x29" && reg_family(cs_reg_name(cs_, x.operands[1].reg)) == "sp" &&
                rbp_frame_) {
                arm_skip_.insert(a);
                continue;
            }
            uint32_t rd = 0, wr = 0;
            bool frd = false, fwr = false;
            access_arm(insn, rd, wr, frd, fwr);
            if (arm_is_call(insn->id))
                wr |= scratch();
            written |= wr;
        }
    }
    // the loads that put them back
    if (!slots.empty())
        for (const cfg_block& b : g.blocks)
            for (uint64_t a : b.insns) {
                if (!decode(a) || (insn->id != ARM64_INS_LDP && insn->id != ARM64_INS_LDR && insn->id != ARM64_INS_LDUR))
                    continue;
                const cs_arm64& x = insn->detail->arm64;
                set_sp(a);
                int mi = 1;
                while (mi < x.op_count && x.operands[mi].type != ARM64_OP_MEM)
                    mi++;
                int64_t off = 0;
                if (mi >= x.op_count || !slot_of_arm(x.operands[mi].mem, off))
                    continue;
                int size = arm_reg_size(cs_, x.operands[0].reg);
                bool restore = true;
                for (int k = 0; restore && k < mi; k++) {
                    auto s = slots.find(off + k * size);
                    restore = x.operands[k].type == ARM64_OP_REG && s != slots.end() && s->second == cs_reg_name(cs_, x.operands[k].reg);
                }
                if (restore)
                    arm_skip_.insert(a);
            }
    cs_free(insn, 1);
}

// a number, or &name when it's the address of something with a name (a string, a global)
ep lifter::addr_value(uint64_t v)
{
    if (v >= 0x10000 && db_.bin.is_mapped(v) && (db_.an.flags_at(v) & (fl_str | fl_data | fl_label | fl_func)) &&
        !db_.name_at(v).empty())
        return e_un("&", sym_for(v));
    ep in = v >= 0x10000 ? inside_item(v) : nullptr;
    uint8_t c = 1;
    if (in && (db_.an.flags_at(db_.an.item_head(v)) & fl_str) && db_.bin.read(v, &c, 1) == 1 && !c)
        return e_sym("\"\""); // a string's end: the empty string
    return in ? in : e_num(v, true);
}

// a sum worked out: a number that is an address with a name reads as &name, and &item + k as
// what's at that address when it has a name of its own (else as &item + k, in one sum).
// access: a place read or written (any name there will do)
ep lifter::named_sum(const ep& e, bool access)
{
    ep f = fold(e), base = f;
    uint64_t k = 0;
    while (base->kind == expr::k::bin && (base->text == "+" || base->text == "-") && base->kids[1]->kind == expr::k::num) {
        k = base->text == "+" ? k + base->kids[1]->num : k - base->kids[1]->num;
        base = base->kids[0];
    }
    bool item = base->kind == expr::k::un && base->text == "&" && base->kids[0]->kind == expr::k::sym && base->kids[0]->ref;
    if (base->kind != expr::k::num && !item)
        return f;
    uint64_t v = (item ? base->kids[0]->ref : base->num) + k;
    ep n = access ? place(v) : addr_value(v);
    if (n->kind != expr::k::num && !(n->kind == expr::k::un && n->kids[0]->kind == expr::k::num))
        return n;
    if (!item)
        return access ? e_un("&", e_num(v, true)) : e_num(v, true);
    if (!k)
        return base;
    return (int64_t)k < 0 ? e_bin("-", base, e_num(0 - k)) : e_bin("+", base, e_num(k));
}

ep lifter::mem_address_arm(const cs_arm64_op& op, std::unordered_map<std::string, ep>& cur, int width)
{
    const arm64_op_mem& m = op.mem;
    int64_t off = 0;
    if (slot_of_arm(m, off)) { // a variable in the stack frame
        std::string nm = frame_var(off, width);
        if (!nm.empty())
            return e_un("&", e_sym(nm));
    }
    ep e;
    if (m.base != ARM64_REG_INVALID) {
        std::string fam = reg_family(cs_reg_name(cs_, m.base));
        e = fam.empty() ? e_reg(cs_reg_name(cs_, m.base)) : reg_read(cur, fam);
    }
    if (m.index != ARM64_REG_INVALID) {
        std::string fam = reg_family(cs_reg_name(cs_, m.index));
        ep idx = arm_zr(cs_, m.index) ? e_num(0) : fam.empty() ? e_reg(cs_reg_name(cs_, m.index)) : reg_read(cur, fam);
        if (op.ext == ARM64_EXT_SXTW)
            idx = e_un("(int)", idx);
        else if (op.ext == ARM64_EXT_UXTW)
            idx = e_un("(unsigned int)", idx);
        if (op.shift.type == ARM64_SFT_LSL && op.shift.value)
            idx = e_bin("*", idx, e_num(1ull << op.shift.value));
        e = e ? e_bin("+", e, idx) : idx;
    }
    if (!e)
        e = e_num(0);
    if (m.disp > 0)
        e = e_bin("+", e, e_num((uint64_t)m.disp));
    else if (m.disp < 0)
        e = e_bin("-", e, e_num((uint64_t)(-(int64_t)m.disp)));
    return named_sum(e, true); // a global: adrp's page plus the offset
}

ep lifter::operand_arm(const cs_arm64_op& op, std::unordered_map<std::string, ep>& cur)
{
    ep v;
    if (op.type == ARM64_OP_REG) {
        if (arm_zr(cs_, op.reg))
            return e_num(0);
        std::string fam = reg_family(cs_reg_name(cs_, op.reg));
        v = fam.empty() ? e_reg(cs_reg_name(cs_, op.reg)) : reg_read(cur, fam);
        switch (op.ext) { // w2, sxtw: the low part, sign or zero extended
        case ARM64_EXT_SXTB: v = e_un("(char)", v); break;
        case ARM64_EXT_SXTH: v = e_un("(short)", v); break;
        case ARM64_EXT_SXTW: v = e_un("(int)", v); break;
        case ARM64_EXT_UXTB: v = e_un("(unsigned char)", v); break;
        case ARM64_EXT_UXTH: v = e_un("(unsigned short)", v); break;
        case ARM64_EXT_UXTW: v = e_un("(unsigned int)", v); break;
        default: break;
        }
    } else if (op.type == ARM64_OP_IMM || op.type == ARM64_OP_CIMM) {
        v = e_num((uint64_t)op.imm, true);
    } else if (op.type == ARM64_OP_MEM) {
        return e_mem(mem_address_arm(op, cur, 8), 8);
    } else {
        return e_sym("?");
    }
    if (op.shift.type != ARM64_SFT_INVALID && op.shift.value) {
        ep k = e_num(op.shift.value);
        switch (op.shift.type) {
        case ARM64_SFT_LSL: v = fold(e_bin("<<", v, k)); break;
        case ARM64_SFT_LSR: v = e_bin(">>", e_un(arm_reg_size(cs_, op.reg) == 4 ? "(unsigned)" : "(unsigned long long)", v), k); break;
        case ARM64_SFT_ASR: v = e_bin(">>", v, k); break;
        case ARM64_SFT_ROR: v = e_intr("__ror", {v, k}); break;
        default: break;
        }
    }
    return v;
}

// the condition cc on the flags a cmp / tst / flag-setting instruction left, and after a ccmp:
// pre ? cc(cmp) : cc(its constant)
ep lifter::build_cond_arm(const flag_state& fs, int cc, bool& ok)
{
    ok = true;
    if (cc == ARM64_CC_AL || cc == ARM64_CC_NV)
        return e_num(1);
    if (fs.pre) {
        flag_state inner = fs;
        inner.pre = nullptr;
        ep c = build_cond_arm(inner, cc, ok);
        return nzcv_holds(fs.nzcv, cc) ? e_bin("||", negate(fs.pre), c) : e_bin("&&", fs.pre, c);
    }
    if (fs.fp && fs.a && fs.b) {
        // after fcmp: lt, le, hi, hs and pl also hold when a value is a nan (so does ne)
        auto c = [&](const char* op) {
            ep e = e_bin(op, fs.a, fs.b);
            e->fp = true;
            return e;
        };
        switch (cc) {
        case ARM64_CC_EQ: return c("==");
        case ARM64_CC_NE: return c("!=");
        case ARM64_CC_MI:
        case ARM64_CC_LO: return c("<");
        case ARM64_CC_GT: return c(">");
        case ARM64_CC_GE: return c(">=");
        case ARM64_CC_LS: return c("<=");
        case ARM64_CC_LT: return e_un("!", c(">="));
        case ARM64_CC_LE: return e_un("!", c(">"));
        case ARM64_CC_HI: return e_un("!", c("<="));
        case ARM64_CC_HS:
        case ARM64_CC_PL: return e_un("!", c("<"));
        default:
            ok = false; // vs / vc: unordered or not
            return e_sym("cond");
        }
    }
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
    const char* u = fs.wide ? "(unsigned long long)" : "(unsigned)";
    auto uns = [&](const char* op) -> ep {
        if (fs.is_cmp && fs.a && fs.b)
            return e_bin(op, e_un(u, fs.a), e_un(u, fs.b));
        ok = false;
        return e_sym("cond");
    };
    // zero or not: the result when there is one (x = x - 1; if (x != 0)), else a == b
    auto zero = [&](const char* op) -> ep {
        if (fs.res)
            return e_bin(op, fs.res, e_num(0));
        return cmp(op);
    };
    // the sign of the result
    auto sign = [&](const char* op) -> ep {
        if (fs.res)
            return e_bin(op, fs.res, e_num(0));
        if (fs.is_cmp && fs.a && fs.b)
            return fs.b->kind == expr::k::num && fs.b->num == 0 ? e_bin(op, fs.a, e_num(0))
                                                              : e_bin(op, e_bin("-", fs.a, fs.b), e_num(0));
        return cmp(op);
    };
    if ((cc == ARM64_CC_VS || cc == ARM64_CC_VC) && fs.a && fs.b && (fs.sum || fs.is_cmp) && !fs.fp) {
        // signed overflow: of a + b (adds), a - b (subs, cmp)
        ep o = e_intr(fs.sum ? "__ofadd" : "__ofsub", {fs.a, fs.b});
        return cc == ARM64_CC_VS ? o : e_un("!", o);
    }
    if (fs.sum && fs.res && fs.a && (cc == ARM64_CC_HS || cc == ARM64_CC_LO)) // adds: the carry
        return e_bin(cc == ARM64_CC_HS ? "<" : ">=", e_un(u, fs.res), e_un(u, fs.a));
    bool test = fs.is_test || (!fs.is_cmp && fs.res); // ands / tst / adds: c and v say nothing useful
    switch (cc) {
    case ARM64_CC_EQ: return zero("==");
    case ARM64_CC_NE: return zero("!=");
    case ARM64_CC_MI: return sign("<");
    case ARM64_CC_PL: return sign(">=");
    case ARM64_CC_GT: return test ? sign(">") : cmp(">");
    case ARM64_CC_GE: return test ? sign(">=") : cmp(">=");
    case ARM64_CC_LT: return test ? sign("<") : cmp("<");
    case ARM64_CC_LE: return test ? sign("<=") : cmp("<=");
    case ARM64_CC_HI: return uns(">");
    case ARM64_CC_HS: return uns(">=");
    case ARM64_CC_LO: return uns("<");
    case ARM64_CC_LS: return uns("<=");
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

    if (arm_) {
        frame_pass_arm(g, entry);
        find_saves_arm(g, entry);
    } else {
        frame_pass(g, entry);
    }

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
        if (!arm_) {
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
            bool decoded = cs_disasm_iter(cs_, &p, &left, &addr, insn);
            if (decoded && arm_) {
                // arm64: saves / restores / the frame pointer's setup and hints do nothing here
                unsigned id = insn->id;
                const cs_arm64& ax = insn->detail->arm64;
                if (!arm_skip_.count(a) && !arm_nothing(id)) {
                    access_arm(insn, r.rd, r.wr, r.flags_rd, r.flags_wr);
                    arm_vec_effect(cs_, insn, r.vwr, r.vzero);
                    if (arm_is_call(id)) {
                        r.vwr = ~0u; // the callee may change them
                        r.call = true;
                        r.flags_wr = true;
                        r.wr |= scratch;
                        if (id == ARM64_INS_BL && ax.op_count >= 1 && ax.operands[0].type == ARM64_OP_IMM) {
                            r.target = (uint64_t)ax.operands[0].imm;
                            const callee_info& ci = callee_of(r.target);
                            r.wr = (r.wr & ~scratch) | ci.clobbers;
                            for (int i = 0; i < ci.arity && i < (int)arg_bits.size(); i++)
                                r.rd |= arg_bits[i];
                        }
                        const prototype* pr = call_proto(insn);
                        if (pr && !pr->variadic) {
                            r.proto_args = (int)pr->params.size();
                            for (int i = 0; i < r.proto_args && i < (int)arg_bits.size(); i++)
                                r.rd |= arg_bits[i];
                        }
                        if (r.wr & 1u)
                            call_sets_rax = true;
                    } else if (id == ARM64_INS_B && !arm_conditional(ax) && ax.op_count >= 1 &&
                               ax.operands[0].type == ARM64_OP_IMM && !block_of.count((uint64_t)ax.operands[0].imm)) {
                        r.tail = true; // b to another function: a tail call
                        r.target = (uint64_t)ax.operands[0].imm;
                        const callee_info& ci = callee_of(r.target);
                        for (int i = 0; i < ci.arity && i < (int)arg_bits.size(); i++)
                            r.rd |= arg_bits[i];
                        if (ci.clobbers & 1u)
                            call_sets_rax = true;
                    } else if (arm_is_br(id) && !db_.an.tables.count(a)) {
                        r.tail = true; // br x16: a tail call through a register
                    }
                    r.ret = arm_is_ret(id);
                }
            } else if (decoded) {
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
    if (arm_) {
        // x0 is the first argument too: a result is x0 set by something other than a call on
        // the way to a ret
        std::vector<int> last_x0(nb, 0); // the block's last write of x0: 0 none, 1 a call, 2 anything else
        std::vector<std::vector<int>> preds(nb);
        std::vector<char> seen(nb, 0);
        std::vector<int> work;
        for (size_t bi = 0; bi < nb; bi++) {
            for (size_t k = rws[bi].size(); k-- > 0;)
                if (rws[bi][k].wr & 1u) {
                    last_x0[bi] = rws[bi][k].call ? 1 : 2;
                    break;
                }
            for (const cfg_edge& e : g.blocks[bi].succ)
                preds[e.to].push_back((int)bi);
            if (!rws[bi].empty() && rws[bi].back().ret) {
                seen[bi] = 1;
                work.push_back((int)bi);
            }
        }
        while (!work.empty() && !returns_value) {
            int b = work.back();
            work.pop_back();
            if (last_x0[b] == 2)
                returns_value = true;
            else if (!last_x0[b])
                for (int q : preds[b])
                    if (!seen[q]) {
                        seen[q] = 1;
                        work.push_back(q);
                    }
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
    // arm64's are a0, a1, ...: x0 carries results too, so the argument is a variable of its own,
    // read where x0 still holds it
    std::map<std::string, std::string> arg_var;
    for (int i = 0; i < nparams; i++) {
        params_.insert(arg_reg_at(i, is64_, fmt));
        params.push_back(arm_ ? "a" + std::to_string(i) : disp(arg_reg_at(i, is64_, fmt)));
        arg_var[arg_reg_at(i, is64_, fmt)] = params.back();
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

    // arm64: an address made before a branch (adrp x1, page; b.eq ...; then add x0, x1, #off)
    // is a number where every way in agrees on it. reads of it there use the number, so the
    // page doesn't have to be a variable
    std::vector<uint32_t> known_in(nb, 0), known_pages(nb, 0); // pages: adrp's, not an address yet
    std::vector<std::array<uint64_t, 32>> known_val(nb);
    std::vector<uint32_t> intact_in(nb, 0); // arm64: parameters no way here has changed
    if (arm_) {
        uint32_t pmask = 0;
        for (const std::string& pr : params_)
            pmask |= bit(pr);
        std::vector<uint32_t> intact_out(nb, 0);
        std::vector<char> seen(nb, 0);
        for (bool changed = true; changed;) {
            changed = false;
            for (size_t bi = 0; bi < nb; bi++) {
                uint32_t in = (int)bi == entry ? pmask : ~0u;
                bool any = (int)bi == entry;
                for (int q : pred[bi])
                    if (seen[q]) {
                        in &= intact_out[q];
                        any = true;
                    }
                if (!any)
                    continue;
                uint32_t o = in;
                for (const insn_rw& r : rws[bi])
                    o &= ~r.wr;
                if (!seen[bi] || in != intact_in[bi] || o != intact_out[bi]) {
                    seen[bi] = 1;
                    intact_in[bi] = in;
                    intact_out[bi] = o;
                    changed = true;
                }
            }
        }
        // what each instruction does: kind 1 sets v (a page from adrp), 2 adds v to src, 3 copies src
        struct kstep {
            uint8_t kind = 0;
            bool page = false;
            int dst = -1, src = -1;
            uint64_t v = 0;
        };
        std::vector<std::vector<kstep>> ks(nb);
        for (size_t bi = 0; bi < nb; bi++)
            for (uint64_t a : g.blocks[bi].insns) {
                kstep st;
                uint8_t code[4];
                const uint8_t* p = code;
                size_t left = db_.bin.read(a, code, sizeof(code));
                uint64_t addr = a;
                if (cs_disasm_iter(cs_, &p, &left, &addr, insn) && !arm_skip_.count(a)) {
                    const cs_arm64& x = insn->detail->arm64;
                    auto reg = [&](int i) {
                        return i < x.op_count && x.operands[i].type == ARM64_OP_REG && arm_reg_size(cs_, x.operands[i].reg) == 8
                            ? reg_bit(reg_family(cs_reg_name(cs_, x.operands[i].reg))) : -1;
                    };
                    st.dst = reg(0);
                    if ((insn->id == ARM64_INS_ADRP || insn->id == ARM64_INS_ADR) && x.op_count >= 2) {
                        st.kind = 1;
                        st.page = insn->id == ARM64_INS_ADRP;
                        st.v = (uint64_t)x.operands[1].imm;
                    } else if (insn->id == ARM64_INS_ADD && x.op_count == 3 && x.operands[2].type == ARM64_OP_IMM) {
                        const cs_arm64_op& o = x.operands[2];
                        st.kind = 2;
                        st.src = reg(1);
                        st.v = (uint64_t)o.imm << (o.shift.type == ARM64_SFT_LSL ? o.shift.value : 0);
                    } else if (insn->id == ARM64_INS_MOV && x.op_count == 2) {
                        st.kind = 3;
                        st.src = reg(1);
                    }
                    if (st.dst < 0 || st.dst >= 31)
                        st.kind = 0; // only x0 - x30
                }
                ks[bi].push_back(st);
            }
        auto run_block = [&](size_t bi, uint32_t known, uint32_t& pages, std::array<uint64_t, 32>& val) {
            for (size_t k = 0; k < ks[bi].size(); k++) {
                const kstep& st = ks[bi][k];
                bool have = st.kind == 1 || (st.kind > 1 && st.src >= 0 && (known & (1u << st.src)));
                uint64_t v = st.kind == 1 ? st.v : have ? val[st.src] + (st.kind == 2 ? st.v : 0) : 0;
                bool page = st.kind == 1 ? st.page : st.kind == 3 && have && (pages & (1u << st.src));
                known &= ~rws[bi][k].wr;
                pages &= ~rws[bi][k].wr;
                if (have) {
                    known |= 1u << st.dst;
                    val[st.dst] = v;
                    if (page)
                        pages |= 1u << st.dst;
                }
            }
            return known;
        };
        std::vector<uint32_t> known_out(nb, 0), pages_out(nb, 0);
        std::vector<std::array<uint64_t, 32>> out_val(nb);
        std::vector<char> done(nb, 0);
        auto same = [](uint32_t m, const std::array<uint64_t, 32>& x, const std::array<uint64_t, 32>& y) {
            for (int r = 0; r < 32; r++)
                if ((m & (1u << r)) && x[r] != y[r])
                    return false;
            return true;
        };
        for (bool changed = true; changed;) {
            changed = false;
            for (size_t bi = 0; bi < nb; bi++) {
                uint32_t in = 0, pg = 0;
                std::array<uint64_t, 32> iv{};
                bool any = (int)bi == entry;
                for (int q : pred[bi]) {
                    if ((int)bi == entry || !done[q])
                        continue;
                    if (!any) {
                        in = known_out[q];
                        pg = pages_out[q];
                        iv = out_val[q];
                        any = true;
                        continue;
                    }
                    for (int r = 0; r < 32; r++)
                        if ((in & (1u << r)) && (!(known_out[q] & (1u << r)) || out_val[q][r] != iv[r]))
                            in &= ~(1u << r);
                    pg &= pages_out[q];
                }
                if (!any)
                    continue; // no way in worked out yet
                pg &= in;
                std::array<uint64_t, 32> ov = iv;
                uint32_t opg = pg;
                uint32_t o = run_block(bi, in, opg, ov);
                if (!done[bi] || in != known_in[bi] || pg != known_pages[bi] || o != known_out[bi] ||
                    opg != pages_out[bi] || !same(in, iv, known_val[bi]) || !same(o, ov, out_val[bi])) {
                    done[bi] = 1;
                    known_in[bi] = in;
                    known_pages[bi] = pg;
                    known_val[bi] = iv;
                    known_out[bi] = o;
                    pages_out[bi] = opg;
                    out_val[bi] = ov;
                    changed = true;
                }
            }
        }
        for (size_t bi = 0; bi < nb; bi++) {
            uint32_t still = known_in[bi] | intact_in[bi];
            for (insn_rw& r : rws[bi]) {
                r.rd_known = r.rd & still;
                r.rd &= ~still;
                still &= ~r.wr;
            }
        }
        liveness();
    }
    // arm64: vector registers that are zero on every way in (movi v0.2d, #0 before stores of it
    // that zero a struct: memset)
    std::vector<uint32_t> vzero_in(nb, 0);
    if (arm_) {
        std::vector<uint32_t> vzero_out(nb, 0);
        std::vector<char> done(nb, 0);
        for (bool changed = true; changed;) {
            changed = false;
            for (size_t bi = 0; bi < nb; bi++) {
                uint32_t in = 0;
                bool any = (int)bi == entry;
                for (int q : pred[bi])
                    if ((int)bi != entry && done[q]) {
                        in = any ? in & vzero_out[q] : vzero_out[q];
                        any = true;
                    }
                if (!any)
                    continue;
                uint32_t o = in;
                for (const insn_rw& r : rws[bi])
                    o = (o & ~r.vwr) | (r.vzero >= 0 ? 1u << r.vzero : 0u);
                if (!done[bi] || in != vzero_in[bi] || o != vzero_out[bi]) {
                    done[bi] = 1;
                    vzero_in[bi] = in;
                    vzero_out[bi] = o;
                    changed = true;
                }
            }
        }
    }

    // pass 2: statements. a register's new value stays pending - an expression, not yet a
    // statement - until it has to be written out: a later block reads it, it grew big, a
    // call or store may change memory it reads, or its register is about to change while
    // another pending value still reads the old one. pending expressions always mean the
    // registers as the statements printed so far left them.
    //
    // a block whose only way in is from one block, and that tests the flags before setting
    // them (cmp; b.lt ...; then b.ne in the next block), starts with the flags that block left:
    // it's done after that block
    std::vector<int> flags_from(nb, -1);
    std::vector<char> flags_out(nb, 0);
    for (size_t s = 0; s < nb; s++) {
        int from = pred[s].empty() || (int)s == entry ? -1 : pred[s][0];
        for (int p : pred[s])
            from = p == from ? from : -1;
        if (from < 0)
            continue;
        for (const insn_rw& r : rws[s]) {
            if (r.flags_rd) {
                flags_from[s] = from;
                flags_out[from] = 1;
            }
            if (r.flags_rd || r.flags_wr)
                break;
        }
    }
    std::vector<int> order;
    {
        std::vector<char> placed(nb, 0);
        for (size_t b = 0; b < nb; b++) {
            std::vector<int> chain;
            for (int c = (int)b; c >= 0 && !placed[c]; c = flags_from[c]) {
                placed[c] = 1;
                chain.push_back(c);
            }
            order.insert(order.end(), chain.rbegin(), chain.rend());
        }
    }
    std::vector<flag_state> fs_end(nb);

    int temps = 0;
    for (int bi : order) {
        const cfg_block& cb = g.blocks[bi];
        block_ir& ir = out[bi];
        const std::vector<insn_rw>& rw = rws[bi];
        size_t ni = cb.insns.size();

        std::unordered_map<std::string, ep> cur;
        std::unordered_map<std::string, size_t> born; // instruction that set a pending value
        for (const std::string& pr : params_)
            cur[pr] = e_reg(disp(pr));
        std::unordered_map<std::string, const expr*> known; // the known addresses it starts with
        for (int r = 0; r < 31; r++)
            if (known_in[bi] & (1u << r)) {
                uint64_t n = known_val[bi][r];
                ep v = known_pages[bi] & (1u << r) ? e_num(n, true) : addr_value(n);
                cur[fam_name(r)] = v;
                known[fam_name(r)] = v.get();
            }
        for (const auto& av : arg_var)
            if (intact_in[bi] & bit(av.first)) {
                ep v = e_reg(av.second); // x0 still holds the argument
                cur[av.first] = v;
                if (bi != entry) // the entry block is where x0 = a0 has to be written, if at all
                    known[av.first] = v.get();
            }
        flag_state fs;
        if (flags_from[bi] >= 0)
            fs = fs_end[flags_from[bi]];
        uint32_t vzero = vzero_in[bi]; // vector registers that are zero
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
            bool fl = flags_out[bi];
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
            if (fam == sp_)
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
                if (g_uses && nm == g_uses->key)
                    note_self(a.val, is64_ ? 8 : 4);
                if (g_learn) {
                    std::string t = type_of(a.val);
                    // p = p + 4 moves a pointer: it doesn't say what p is
                    bool moves = t.empty() && a.val->kind == expr::k::bin && (a.val->text == "+" || a.val->text == "-") &&
                                 a.val->kids[0]->kind == expr::k::reg && a.val->kids[0]->text == nm;
                    auto it = g_learn->find(nm);
                    if (moves)
                        ;
                    else if (it == g_learn->end())
                        (*g_learn)[nm] = t.empty() ? "?" : t;
                    else if (it->second != t)
                        it->second = "?";
                }
                done.push_back(a.fam);
                // dead values that read the old register can't be named any more
                spare.erase(std::remove_if(spare.begin(), spare.end(),
                                           [&](const asg& s) { return refs_name(s.val, nm, a.val.get()); }),
                            spare.end());
                // what reads the value reads the register from here on - unless it's a number or
                // a variable nothing assigns (a0): that reads better as it is
                if (a.val->kind == expr::k::num || (a.val->kind == expr::k::reg && reg_family(a.val->text.c_str()).empty()))
                    return;
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
                for (ep* f : {&fs.a, &fs.b, &fs.res, &fs.pre})
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
            for (ep* f : {&fs.a, &fs.b, &fs.res, &fs.pre}) {
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
                bool frame = v.fam == fp_ && ((v.val->kind == expr::k::reg && v.val->text == disp(sp_)) || rbp_frame_);
                if (v.fam == sp_ || frame) {
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
            if (dst->kind == expr::k::call && (dst->text.compare(0, 8, "__readfs") == 0 || dst->text.compare(0, 8, "__readgs") == 0)) {
                // thread data: __writefsdword(-0x10, v)
                ep v = op == "=" ? src : e_bin(op.substr(0, op.size() - 1), dst, src);
                line(cb.insns[k], "__write" + dst->text.substr(6) + "(" + print(dst->kids[0]) + ", " + print(v) + ");");
                return dst;
            }
            line(cb.insns[k], print(dst) + " " + op + " " + print(src) + ";");
            if (g_uses && op == "=" && dst->kind == expr::k::mem && dst->kids[0]->kind == expr::k::un &&
                dst->kids[0]->text == "&" && dst->kids[0]->kids[0]->kind == expr::k::sym &&
                dst->kids[0]->kids[0]->text == g_uses->key)
                note_self(src, is64_ ? 8 : 4);
            // a frame variable holds what's stored in it: local_20 = a makes it a's type
            if (g_learn && op == "=" && dst->kind == expr::k::mem && dst->kids[0]->kind == expr::k::un &&
                dst->kids[0]->text == "&" && dst->kids[0]->kids[0]->kind == expr::k::sym) {
                std::string nm = dst->kids[0]->kids[0]->text, t = type_of(src);
                int64_t off;
                if (slot_offset(nm, is64_ ? 8 : 4, off)) {
                    auto it = g_learn->find(nm);
                    if (it == g_learn->end())
                        (*g_learn)[nm] = t.empty() ? "?" : t;
                    else if (it->second != t)
                        it->second = "?";
                }
            }
            return dst;
        };

        // an instruction the lifter doesn't model: printed as is, after the registers it
        // reads hold their values and nothing pending reads a register it changes
        auto opaque = [&](size_t k, cs_insn* in) {
            flush_args();
            const insn_rw& r = rw[k];
            std::vector<std::string> reads, writes;
            uint32_t rd = r.rd | r.rd_known;
            for (int b = 0; b < (arm_ ? 32 : 16); b++) {
                std::string fam = fam_name(b);
                if (fam == sp_)
                    continue;
                if ((rd & (1u << b)) && pending(fam))
                    reads.push_back(fam);
                if (r.wr & (1u << b))
                    writes.push_back(fam);
            }
            for (const std::string& w : writes)
                if (!(rd & bit(w)))
                    cur.erase(w); // overwritten without being read
            bool writes_mem = false;
            if (arm_) { // a store, an atomic, anything else with a memory operand that isn't a load
                const cs_arm64& xa = in->detail->arm64;
                for (uint8_t i = 0; i < xa.op_count; i++)
                    if (xa.operands[i].type == ARM64_OP_MEM && !arm_is_load(in->id))
                        writes_mem = true;
            } else {
                const cs_x86& xx = in->detail->x86;
                for (uint8_t i = 0; i < xx.op_count; i++)
                    if (xx.operands[i].type == X86_OP_MEM && (xx.operands[i].access & CS_AC_WRITE))
                        writes_mem = true;
            }
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

            if (arm_) {
                const cs_arm64& ax = insn->detail->arm64;
                auto op = [&](int i) -> const cs_arm64_op& { return ax.operands[i]; };
                // operand i's register family ("" for the zero register and vector registers)
                auto fam = [&](int i) {
                    return i < ax.op_count && ax.operands[i].type == ARM64_OP_REG && !arm_zr(cs_, ax.operands[i].reg)
                        ? reg_family(cs_reg_name(cs_, ax.operands[i].reg)) : std::string();
                };
                auto v = [&](int i) { return i < ax.op_count ? operand_arm(ax.operands[i], cur) : e_num(0); };
                auto put = [&](ep r) {
                    std::string f = fam(0);
                    if (!f.empty() && f != sp_)
                        assign(k, f, std::move(r));
                };
                auto imm_of = [&](int i) -> int64_t {
                    const cs_arm64_op& o = ax.operands[i];
                    return o.imm << (o.shift.type == ARM64_SFT_LSL ? o.shift.value : 0);
                };
                // a number that's an address of something with a name reads as &name
                auto named = [&](ep e) { return named_sum(e, false); };
                // sp / x29 plus k: the address of a frame variable
                auto frame_addr = [&](const std::string& base, int64_t k2, ep& out) {
                    int64_t off = 0;
                    if (base == "sp" && cur_sp_known_)
                        off = cur_sp_ + k2;
                    else if (base == "x29" && rbp_frame_)
                        off = rbp_off_ + k2;
                    else
                        return false;
                    std::string nm = frame_var(off, 0);
                    if (nm.empty())
                        return false;
                    out = e_un("&", e_sym(nm));
                    return true;
                };
                auto neg = [&](ep e) { return e->kind == expr::k::num ? e_num(0 - e->num, true) : e_un("-", e); };
                bool wide = ax.op_count >= 1 && ax.operands[0].type == ARM64_OP_REG && arm_reg_size(cs_, ax.operands[0].reg) == 8;
                auto flags_cmp = [&](ep a2, ep b2, ep res) {
                    fs = {};
                    fs.valid = true;
                    fs.is_cmp = true;
                    fs.wide = wide;
                    fs.a = std::move(a2);
                    fs.b = std::move(b2);
                    fs.res = std::move(res);
                    fs_set = true;
                };
                auto cond = [&](bool& ok) { return build_cond_arm(fs, ax.cc, ok); };
                int mi = -1;
                for (int i = 0; i < ax.op_count && mi < 0; i++)
                    if (ax.operands[i].type == ARM64_OP_MEM)
                        mi = i;
                // bit fields: lsb and width in operands 2 and 3
                int64_t lsb = ax.op_count >= 4 ? op(2).imm : 0, width = ax.op_count >= 4 ? op(3).imm : 0;
                uint64_t fmask = width >= 64 ? ~0ull : (1ull << width) - 1;
                bool bits32 = ax.op_count >= 1 && ax.operands[0].type == ARM64_OP_REG && arm_reg_size(cs_, ax.operands[0].reg) == 4;

                if (arm_skip_.count(a) || arm_nothing(id)) {
                    // the prologue's saves, the epilogue's restores, the frame pointer, hints
                } else if ((id == ARM64_INS_FCMP || id == ARM64_INS_FCMPE) && ax.op_count >= 2) {
                    // floating point: the registers by name (what sets them is shown as it is)
                    auto fv = [&](int i) { return op(i).type == ARM64_OP_REG ? e_reg(cs_reg_name(cs_, op(i).reg)) : e_sym("0.0"); };
                    flags_cmp(fv(0), fv(1), nullptr);
                    fs.fp = true;
                } else if (arm_vector(cs_, insn)) {
                    // a compare's register changing: its flags can't be said with it any more
                    const char* mn = insn->mnemonic;
                    bool st = mn[0] == 's' && mn[1] == 't', ld = mn[0] == 'l' && mn[1] == 'd';
                    for (int i = 0; fs.fp && !st && i < ax.op_count && op(i).type == ARM64_OP_REG && (i == 0 || ld); i++) {
                        int n = arm_vreg(cs_reg_name(cs_, op(i).reg));
                        for (const ep& e : {fs.a, fs.b})
                            if (n >= 0 && e && e->kind == expr::k::reg && arm_vreg(e->text.c_str()) == n)
                                fs = {};
                    }
                    // stores of registers that are zero: a struct or an array cleared
                    bool zeros = arm_is_store(id) && mi >= 1;
                    for (int r2 = 0; zeros && r2 < mi; r2++) {
                        int n = op(r2).type == ARM64_OP_REG ? arm_vreg(cs_reg_name(cs_, op(r2).reg)) : -1;
                        zeros = n >= 0 && (vzero & (1u << n));
                    }
                    if (rw[k].vzero >= 0) {
                        line(a, "v" + std::to_string(rw[k].vzero) + " = 0;");
                    } else if (zeros) {
                        int w = arm_mem_width(cs_, insn);
                        if (w > 8) {
                            ep at = mem_address_arm(op(mi), cur, w);
                            barrier(k, {&at});
                            line(a, "memset(" + print(at) + ", 0, " + std::to_string(w * mi) + ");");
                        } else {
                            for (int r2 = 0; r2 < mi; r2++) {
                                cs_arm64_op m2 = op(mi);
                                m2.mem.disp += w * r2;
                                store(k, e_mem(mem_address_arm(m2, cur, w), w), "=", e_num(0));
                            }
                        }
                        std::string base = reg_family(cs_reg_name(cs_, op(mi).mem.base));
                        if (ax.writeback && base != sp_ && !base.empty()) {
                            int64_t step = ax.post_index ? (mi + 1 < ax.op_count && op(mi + 1).type == ARM64_OP_IMM ? op(mi + 1).imm : 0)
                                                         : op(mi).mem.disp;
                            assign(k, base, fold(e_bin("+", reg_read(cur, base), e_num((uint64_t)step, true))));
                        }
                    } else {
                        opaque(k, insn);
                    }
                } else switch (id) {
                case ARM64_INS_MOV:
                case ARM64_INS_MOVZ:
                case ARM64_INS_MOVN: {
                    ep out;
                    if (fam(1) == "sp" && frame_addr("sp", 0, out))
                        put(out); // mov x0, sp: the frame's address
                    else if (fam(0) != "x29" || !rbp_frame_)
                        put(named(v(1)));
                    break;
                }
                case ARM64_INS_MOVK: { // 16 bits of it: movk x0, #0x1234, lsl #16
                    unsigned sh = op(1).shift.type == ARM64_SFT_LSL ? op(1).shift.value : 0;
                    uint64_t mask = ~(0xffffull << sh), bits = ((uint64_t)op(1).imm & 0xffff) << sh;
                    if (bits32)
                        mask &= 0xffffffffull;
                    ep old = v(0);
                    put(named(old->kind == expr::k::num ? e_num((old->num & mask) | bits, true)
                                                        : e_bin("|", e_bin("&", old, e_num(mask)), e_num(bits))));
                    break;
                }
                case ARM64_INS_ADD:
                case ARM64_INS_SUB:
                case ARM64_INS_ADDS:
                case ARM64_INS_SUBS: {
                    bool plus = id == ARM64_INS_ADD || id == ARM64_INS_ADDS;
                    std::string d = fam(0), b = fam(1);
                    ep out;
                    if ((b == "sp" || (b == "x29" && rbp_frame_)) && ax.op_count >= 3 && op(2).type == ARM64_OP_IMM &&
                        frame_addr(b, plus ? imm_of(2) : -imm_of(2), out)) {
                        put(out); // add x0, sp, #16: a frame variable's address
                        break;
                    }
                    if (d == "sp" || (d == "x29" && rbp_frame_))
                        break; // the stack moving: the frame pass follows it
                    ep a2 = v(1), b2 = v(2);
                    ep r = named(e_bin(plus ? "+" : "-", a2, b2));
                    if (ax.update_flags) {
                        if (plus) {
                            result_flags(r);
                            fs.a = a2;
                            fs.b = b2;
                            fs.sum = true;
                            fs.wide = wide;
                        } else
                            flags_cmp(a2, b2, fam(0).empty() ? nullptr : r);
                    }
                    put(r);
                    break;
                }
                case ARM64_INS_CMP:
                    flags_cmp(v(0), v(1), nullptr);
                    break;
                case ARM64_INS_CMN: // cmn x0, #1 compares with -1
                    flags_cmp(v(0), neg(v(1)), nullptr);
                    break;
                case ARM64_INS_TST:
                    fs = {};
                    fs.valid = true;
                    fs.is_test = true;
                    fs.a = v(0);
                    fs.b = v(1);
                    fs_set = true;
                    break;
                case ARM64_INS_CCMP:
                case ARM64_INS_CCMN: { // cond ? cmp a, b : flags = #nzcv
                    bool ok = false;
                    ep pre = cond(ok);
                    ep a2 = v(0), b2 = id == ARM64_INS_CCMP ? v(1) : neg(v(1));
                    uint8_t nzcv = (uint8_t)(ax.op_count >= 3 ? op(2).imm : 0);
                    flags_cmp(a2, b2, nullptr);
                    if (ok) {
                        fs.pre = pre;
                        fs.nzcv = nzcv;
                    } else {
                        fs = {};
                    }
                    break;
                }
                case ARM64_INS_AND:
                case ARM64_INS_ANDS:
                case ARM64_INS_ORR:
                case ARM64_INS_EOR:
                case ARM64_INS_BIC:
                case ARM64_INS_BICS:
                case ARM64_INS_ORN:
                case ARM64_INS_EON: {
                    bool inv = id == ARM64_INS_BIC || id == ARM64_INS_BICS || id == ARM64_INS_ORN || id == ARM64_INS_EON;
                    const char* o = id == ARM64_INS_ORR || id == ARM64_INS_ORN ? "|" : id == ARM64_INS_EOR || id == ARM64_INS_EON ? "^" : "&";
                    ep a2 = v(1), b2 = v(2);
                    if (inv)
                        b2 = b2->kind == expr::k::num ? e_num(~b2->num, true) : e_un("~", b2);
                    ep r = named(e_bin(o, a2, b2));
                    if (ax.update_flags) {
                        fs = {};
                        fs.valid = true;
                        fs.is_test = true;
                        fs.a = a2;
                        fs.b = b2;
                        fs_set = true;
                    }
                    put(r);
                    break;
                }
                case ARM64_INS_MVN:
                    put(e_un("~", v(1)));
                    break;
                case ARM64_INS_NEG:
                case ARM64_INS_NEGS: {
                    ep r = neg(v(1));
                    if (id == ARM64_INS_NEGS)
                        flags_cmp(e_num(0), v(1), r);
                    put(r);
                    break;
                }
                case ARM64_INS_LSL: put(fold(e_bin("<<", v(1), v(2)))); break;
                case ARM64_INS_LSR: // a logical shift: of the unsigned value
                    put(e_bin(">>", e_un(bits32 ? "(unsigned)" : "(unsigned long long)", v(1)), v(2)));
                    break;
                case ARM64_INS_ASR: put(e_bin(">>", v(1), v(2))); break;
                case ARM64_INS_ROR: put(e_intr("__ror", {v(1), v(2)})); break;
                case ARM64_INS_MUL:
                case ARM64_INS_SMULL: put(e_bin("*", v(1), v(2))); break;
                case ARM64_INS_UMULL: // 32 x 32 bits unsigned, 64 out
                    put(e_bin("*", e_un("(unsigned long long)", e_un("(unsigned)", v(1))), e_un("(unsigned)", v(2))));
                    break;
                case ARM64_INS_MNEG: put(e_un("-", e_bin("*", v(1), v(2)))); break;
                case ARM64_INS_SMULH: put(e_intr("__mulhi", {v(1), v(2)})); break;
                case ARM64_INS_UMULH: put(e_intr("__umulhi", {v(1), v(2)})); break;
                case ARM64_INS_SDIV: put(e_bin("/", v(1), v(2))); break;
                case ARM64_INS_UDIV: { // of the unsigned values
                    const char* u = bits32 ? "(unsigned)" : "(unsigned long long)";
                    put(e_bin("/", e_un(u, v(1)), e_un(u, v(2))));
                    break;
                }
                case ARM64_INS_MADD:
                case ARM64_INS_SMADDL:
                case ARM64_INS_UMADDL: put(e_bin("+", v(3), e_bin("*", v(1), v(2)))); break;
                case ARM64_INS_MSUB:
                case ARM64_INS_SMSUBL:
                case ARM64_INS_UMSUBL: {
                    // a - (a / b) * b is a % b: how a remainder comes out of udiv / sdiv
                    ep q = v(1), m = v(2), a2 = v(3);
                    auto is_div = [&](const ep& d, const ep& by) {
                        return d->kind == expr::k::bin && d->text == "/" && print(d->kids[0]) == print(a2) && print(d->kids[1]) == print(by);
                    };
                    if (is_div(q, m))
                        put(e_bin("%", a2, m));
                    else if (is_div(m, q))
                        put(e_bin("%", a2, q));
                    else
                        put(e_bin("-", a2, e_bin("*", q, m)));
                    break;
                }
                case ARM64_INS_SXTB: put(e_un("(char)", v(1))); break;
                case ARM64_INS_SXTH: put(e_un("(short)", v(1))); break;
                case ARM64_INS_SXTW: put(e_un("(int)", v(1))); break;
                case ARM64_INS_UXTB: put(e_un("(unsigned char)", v(1))); break;
                case ARM64_INS_UXTH: put(e_un("(unsigned short)", v(1))); break;
                case ARM64_INS_UXTW: put(e_un("(unsigned int)", v(1))); break;
                case ARM64_INS_UBFX: // (x >> lsb) & mask
                    put(lsb ? e_bin("&", e_bin(">>", v(1), e_num(lsb)), e_num(fmask)) : e_bin("&", v(1), e_num(fmask)));
                    break;
                case ARM64_INS_UBFIZ: // (x & mask) << lsb
                    put(e_bin("<<", e_bin("&", v(1), e_num(fmask)), e_num(lsb)));
                    break;
                case ARM64_INS_SBFX:
                case ARM64_INS_SBFIZ: {
                    // a sign-extended field: (int)x << 2 is sbfiz x0, x1, #2, #32
                    const char* cast = width == 32 ? "(int)" : width == 16 ? "(short)" : width == 8 ? "(char)" : nullptr;
                    if (id == ARM64_INS_SBFX && cast && !lsb)
                        put(e_un(cast, v(1)));
                    else if (id == ARM64_INS_SBFIZ && cast)
                        put(lsb ? e_bin("<<", e_un(cast, v(1)), e_num(lsb)) : e_un(cast, v(1)));
                    else
                        put(e_intr(id == ARM64_INS_SBFX ? "__sbfx" : "__sbfiz", {v(1), e_num(lsb), e_num(width)}));
                    break;
                }
                case ARM64_INS_BFI: // d = (d & ~(mask << lsb)) | ((x & mask) << lsb)
                    put(e_bin("|", e_bin("&", v(0), e_num(~(fmask << lsb), true)),
                              e_bin("<<", e_bin("&", v(1), e_num(fmask)), e_num(lsb))));
                    break;
                case ARM64_INS_BFXIL: // d = (d & ~mask) | ((x >> lsb) & mask)
                    put(e_bin("|", e_bin("&", v(0), e_num(~fmask, true)),
                              e_bin("&", lsb ? e_bin(">>", v(1), e_num(lsb)) : v(1), e_num(fmask))));
                    break;
                case ARM64_INS_EXTR: // two registers shifted together; the same one twice rotates it
                    if (print(v(1)) == print(v(2)))
                        put(e_intr("__ror", {v(1), v(3)}));
                    else
                        put(e_intr("__extr", {v(1), v(2), v(3)}));
                    break;
                case ARM64_INS_CLZ: put(e_intr("__clz", {v(1)})); break;
                case ARM64_INS_CLS: put(e_intr("__cls", {v(1)})); break;
                case ARM64_INS_RBIT: put(e_intr("__rbit", {v(1)})); break;
                case ARM64_INS_REV: put(e_intr("__bswap", {v(1)})); break;
                case ARM64_INS_REV16: put(e_intr("__rev16", {v(1)})); break;
                case ARM64_INS_REV32: put(e_intr("__rev32", {v(1)})); break;
                case ARM64_INS_CSEL:
                case ARM64_INS_CSINC:
                case ARM64_INS_CSINV:
                case ARM64_INS_CSNEG:
                case ARM64_INS_CSET:
                case ARM64_INS_CSETM:
                case ARM64_INS_CINC:
                case ARM64_INS_CINV:
                case ARM64_INS_CNEG: {
                    bool ok = false;
                    ep c = cond(ok);
                    if (!ok) {
                        opaque(k, insn);
                        break;
                    }
                    auto inv = [&](ep e) { return e->kind == expr::k::num ? e_num(~e->num, true) : e_un("~", e); };
                    switch (id) {
                    case ARM64_INS_CSEL: put(e_tern(c, v(1), v(2))); break;
                    case ARM64_INS_CSINC: put(e_tern(c, v(1), fold(e_bin("+", v(2), e_num(1))))); break;
                    case ARM64_INS_CSINV: put(e_tern(c, v(1), inv(v(2)))); break;
                    case ARM64_INS_CSNEG: put(e_tern(c, v(1), neg(v(2)))); break;
                    case ARM64_INS_CSET: put(c); break;
                    case ARM64_INS_CSETM: put(e_tern(c, e_num((uint64_t)-1, true), e_num(0))); break;
                    case ARM64_INS_CINC: put(e_tern(c, fold(e_bin("+", v(1), e_num(1))), v(1))); break;
                    case ARM64_INS_CINV: put(e_tern(c, inv(v(1)), v(1))); break;
                    default: put(e_tern(c, neg(v(1)), v(1))); break;
                    }
                    break;
                }
                case ARM64_INS_ADR:
                    put(addr_value((uint64_t)op(1).imm));
                    break;
                case ARM64_INS_ADRP: // a page: the add or the access after it names what it reaches
                    put(e_num((uint64_t)op(1).imm, true));
                    break;
                case ARM64_INS_MRS: {
                    const char* comma = strchr(insn->op_str, ',');
                    put(e_intr("__mrs", {e_sym(comma ? util::trim(comma + 1) : std::string(insn->op_str))}));
                    break;
                }
                case ARM64_INS_SVC: { // a system call: its number, then the arguments set for it
                    std::vector<ep> args{reg_read(cur, db_.bin.format == bin_format::macho ? "x16" : "x8")};
                    for (int i = 0; i < 6; i++) {
                        bool more = false;
                        for (int j = i; j < 6; j++)
                            more = more || (argset & (1u << j));
                        if (!more)
                            break;
                        args.push_back(reg_read(cur, fam_name(i)));
                    }
                    ep sc = e_intr("__syscall", args);
                    barrier(k, {&sc});
                    if (live_after[k] & 1u) {
                        cur[ret_] = sc;
                        born[ret_] = k;
                        settle(k, {ret_}, {}, {});
                    } else {
                        line(a, print(sc) + ";");
                        cur.erase(ret_);
                    }
                    break;
                }
                case ARM64_INS_BRK:
                case ARM64_INS_UDF:
                case ARM64_INS_HLT:
                    barrier(k, {});
                    line(a, "__builtin_trap();");
                    break;
                case ARM64_INS_B:
                case ARM64_INS_CBZ:
                case ARM64_INS_CBNZ:
                case ARM64_INS_TBZ:
                case ARM64_INS_TBNZ:
                case ARM64_INS_RET:
                case ARM64_INS_RETAA:
                case ARM64_INS_RETAB:
                    break; // the block's end, below
                default:
                    if (arm_is_load(id) && mi >= 1) {
                        // ldr / ldp: each register from its place; a writeback moves the base
                        int w = arm_mem_width(cs_, insn);
                        std::vector<asg> vals;
                        for (int r2 = 0; r2 < mi; r2++) {
                            cs_arm64_op m2 = op(mi);
                            m2.mem.disp += w * r2;
                            ep at = mem_address_arm(m2, cur, w);
                            // a got slot of this file's own variable holds its address: &counter
                            uint64_t slot = at->kind == expr::k::un && at->text == "&" ? at->kids[0]->kind == expr::k::sym
                                ? at->kids[0]->ref : at->kids[0]->kind == expr::k::num ? at->kids[0]->num : 0 : 0;
                            uint64_t to = 0;
                            const segment* sg = slot ? db_.bin.seg_at(slot) : nullptr;
                            if (w == 8 && sg && (sg->name.compare(0, 4, ".got") == 0 || sg->name == "__got" || sg->name == "__auth_got") &&
                                !db_.an.slot_import.count(slot) && db_.bin.read_ptr(slot, to) && to && db_.bin.is_mapped(to))
                                vals.push_back({fam(r2), addr_value(to)});
                            else {
                                ep m = e_mem(at, w);
                                if (arm_zext_load(id))
                                    m->text = "u";
                                vals.push_back({fam(r2), m});
                            }
                        }
                        std::string base = reg_family(cs_reg_name(cs_, op(mi).mem.base));
                        if (ax.writeback && base != sp_ && !base.empty()) {
                            int64_t step = ax.post_index ? (mi + 1 < ax.op_count && op(mi + 1).type == ARM64_OP_IMM ? op(mi + 1).imm : 0)
                                                         : op(mi).mem.disp;
                            vals.push_back({base, fold(e_bin("+", reg_read(cur, base), e_num((uint64_t)step, true)))});
                        }
                        assign_all(k, vals);
                    } else if (arm_is_load(id) && ax.op_count >= 2 && op(1).type == ARM64_OP_IMM) {
                        // ldr x0, =value: from the literal pool
                        int w = arm_mem_width(cs_, insn);
                        put(e_mem(place((uint64_t)op(1).imm), w));
                    } else if (arm_is_store(id) && mi >= 1) {
                        int w = arm_mem_width(cs_, insn);
                        for (int r2 = 0; r2 < mi; r2++) {
                            cs_arm64_op m2 = op(mi);
                            m2.mem.disp += w * r2;
                            store(k, e_mem(mem_address_arm(m2, cur, w), w), "=", v(r2));
                        }
                        std::string base = reg_family(cs_reg_name(cs_, op(mi).mem.base));
                        if (ax.writeback && base != sp_ && !base.empty()) {
                            int64_t step = ax.post_index ? (mi + 1 < ax.op_count && op(mi + 1).type == ARM64_OP_IMM ? op(mi + 1).imm : 0)
                                                         : op(mi).mem.disp;
                            assign(k, base, fold(e_bin("+", reg_read(cur, base), e_num((uint64_t)step, true))));
                        }
                    } else if (arm_is_call(id)) {
                        auto ce = std::make_shared<expr>();
                        ce->kind = expr::k::call;
                        std::string pname;
                        uint64_t pref = 0;
                        const prototype* pr = call_proto(insn, &pname, &pref);
                        if (!pname.empty()) {
                            ce->text = pname;
                            ce->ref = pref;
                        } else {
                            // blr x16: an import's slot (or a got slot) it was loaded from names it
                            ep t = v(0);
                            uint64_t slot = t->kind == expr::k::mem && t->kids[0]->kind == expr::k::un && t->kids[0]->text == "&" &&
                                            t->kids[0]->kids[0]->kind == expr::k::sym ? t->kids[0]->kids[0]->ref : 0;
                            uint64_t via = 0;
                            if (slot && db_.an.slot_import.count(slot)) {
                                ce->text = db_.call_name(slot);
                                ce->ref = slot;
                                pr = known_prototype(db_.name_at(slot));
                            } else if (slot && got_target(db_.bin, db_.an, slot, via)) {
                                ce->text = callee_text(via);
                                ce->ref = via;
                                pr = db_.callee_proto(via);
                            } else {
                                ce->indirect = true;
                                ce->kids.push_back(t);
                            }
                        }
                        int known = pr && !pr->variadic ? (int)pr->params.size() : rw[k].target ? callee_of(rw[k].target).arity : -1;
                        for (size_t i = 0; i < arg_bits.size(); i++) {
                            if (known >= 0 ? (int)i >= known : !(argset & arg_bits[i]))
                                break;
                            ce->kids.push_back(reg_read(cur, fam_name(low_bit(arg_bits[i]))));
                        }
                        ep call = ce;
                        barrier(k, {&call});
                        uint32_t clob = rw[k].wr & scratch;
                        if ((live_after[k] & 1u) && (clob & 1u)) {
                            cur[ret_] = call; // the result is used: "x0 = f(...);"
                            born[ret_] = k;
                            settle(k, {ret_}, {}, {});
                        } else {
                            line(a, print(call) + ";");
                            if (clob & 1u)
                                cur.erase(ret_);
                        }
                        for (auto it = cur.begin(); it != cur.end();) {
                            bool gone = (bit(it->first) & clob) && it->first != ret_;
                            it = gone ? cur.erase(it) : std::next(it);
                        }
                        argset &= ~clob;
                        fs = {};
                        fs_set = true;
                    } else if (arm_is_br(id)) {
                        // the block's end, below
                    } else if (rw[k].wr & ~bit(sp_)) {
                        opaque(k, insn);
                    } else if (mi >= 0) {
                        barrier(k, {}); // a vector store and the like: memory changed
                    }
                    break;
                }
                if (last) {
                    ir.fall = ir.end;
                    if (arm_is_ret(id)) {
                        ir.term = term_kind::ret;
                        if (returns_value)
                            ir.cond = reg_read(cur, ret_);
                    } else if (id == ARM64_INS_B && ax.op_count >= 1 && ax.operands[0].type == ARM64_OP_IMM) {
                        uint64_t t = (uint64_t)ax.operands[0].imm;
                        bool ok = false;
                        if (arm_conditional(ax)) {
                            ir.term = term_kind::cond;
                            ir.cond = cond(ok);
                            ir.taken = t;
                        } else if (block_of.count(t)) {
                            ir.term = term_kind::jump;
                            ir.fall = t;
                        } else { // to another function: a tail call
                            auto ce = std::make_shared<expr>();
                            ce->kind = expr::k::call;
                            ce->text = callee_text(t);
                            ce->ref = t;
                            int known = callee_of(t).arity;
                            for (size_t i = 0; i < arg_bits.size(); i++) {
                                if (known >= 0 ? (int)i >= known : !(argset & arg_bits[i]))
                                    break;
                                ce->kids.push_back(reg_read(cur, fam_name(low_bit(arg_bits[i]))));
                            }
                            ir.term = term_kind::indirect;
                            ir.cond = ce;
                        }
                    } else if ((id == ARM64_INS_CBZ || id == ARM64_INS_CBNZ) && ax.op_count >= 2) {
                        ir.term = term_kind::cond;
                        ir.cond = e_bin(id == ARM64_INS_CBZ ? "==" : "!=", v(0), e_num(0));
                        ir.taken = (uint64_t)op(1).imm;
                    } else if ((id == ARM64_INS_TBZ || id == ARM64_INS_TBNZ) && ax.op_count >= 3) {
                        // one bit: the sign bit is x < 0
                        uint64_t n = (uint64_t)op(1).imm;
                        ep xv = v(0);
                        bool nz = id == ARM64_INS_TBNZ;
                        if (n == (bits32 ? 31u : 63u))
                            ir.cond = e_bin(nz ? "<" : ">=", bits32 ? e_un("(int)", xv) : xv, e_num(0));
                        else
                            ir.cond = e_bin(nz ? "!=" : "==", e_bin("&", xv, e_num(1ull << (n & 63))), e_num(0));
                        ir.term = term_kind::cond;
                        ir.taken = (uint64_t)op(2).imm;
                    } else if (arm_is_br(id)) {
                        auto t = db_.an.tables.find(a);
                        if (t != db_.an.tables.end()) {
                            ir.term = term_kind::sw;
                            ir.table = &t->second;
                            std::string f = t->second.index_reg ? reg_family(cs_reg_name(cs_, t->second.index_reg)) : std::string();
                            ir.cond = !f.empty() ? reg_read(cur, f) : v(0);
                        } else { // br x16: a tail call through a register
                            auto ce = std::make_shared<expr>();
                            ce->kind = expr::k::call;
                            ce->indirect = true;
                            ce->kids.push_back(v(0));
                            for (size_t i = 0; i < arg_bits.size() && (argset & arg_bits[i]); i++)
                                ce->kids.push_back(reg_read(cur, fam_name(low_bit(arg_bits[i]))));
                            ir.term = term_kind::indirect;
                            ir.cond = ce;
                        }
                    } else if ((arm_is_call(id) && db_.an.noret_calls.count(a)) || id == ARM64_INS_BRK ||
                               id == ARM64_INS_UDF || id == ARM64_INS_HLT) {
                        ir.term = term_kind::noreturn;
                    }
                }
            } else
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
                    ce->text = callee_text(target);
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
            vzero = (vzero & ~rw[k].vwr) | (rw[k].vzero >= 0 ? 1u << rw[k].vzero : 0u);

            if (last && !arm_) {
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
                        ce->text = callee_text(t);
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
                auto kn = known.find(kv.first);
                if (kn != known.end() && kn->second == kv.second.get() && (ir.live_in & bit(kv.first)))
                    continue; // a known address the variable holds already
                if (ir.live_out & bit(kv.first))
                    todo.push_back({kv.first, kv.second});
                else
                    spare.push_back({kv.first, kv.second});
            }
            std::vector<ep*> readers;
            if (ir.cond)
                readers.push_back(&ir.cond);
            if (flags_out[bi])
                for (ep* f : {&fs.a, &fs.b, &fs.res, &fs.pre})
                    if (*f)
                        readers.push_back(f);
            if (!todo.empty())
                emit_batch(ni ? cb.insns.back() : cb.start, todo, readers, spare);
        }
        if (flags_out[bi])
            fs_end[bi] = fs;
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
                if (lhs->kind == expr::k::un && (lhs->text == "(unsigned)" || lhs->text == "(unsigned long long)") &&
                    !lhs->kids.empty())
                    lhs = lhs->kids[0];
                sw.cond = lhs;
                break;
            }
        }
    }

    // a switch block computes the table jump's target: assignments that nothing after them
    // reads are that computation, not worth showing
    for (size_t bi = 0; bi < nb; bi++) {
        block_ir& sw = out[bi];
        if (sw.term != term_kind::sw)
            continue;
        std::string rest = sw.cond ? print(sw.cond) : std::string();
        if (flags_out[bi]) // a case tests the flags this block left
            for (const ep& f : {fs_end[bi].a, fs_end[bi].b, fs_end[bi].res, fs_end[bi].pre})
                if (f)
                    rest += " " + print(f);
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
    // written like a call: a demangled c++ name without its parameters (the header adds them)
    r.name = db.call_name(start);
    if (r.name.empty())
        r.name = db.location(start);

    if (fn && fn->thunk) {
        r.ok = true;
        std::string tn = db.call_name(fn->thunk_target);
        if (tn.empty())
            tn = db.location(fn->thunk_target);
        r.lines.push_back({0, r.name + ": thunk to " + tn, start});
        return r;
    }

    const bool arm = db.bin.arch == bin_arch::arm64;
    csh cs = 0;
    if (cs_open(arm ? CS_ARCH_ARM64 : CS_ARCH_X86, arm ? CS_MODE_ARM : db.bin.is64() ? CS_MODE_64 : CS_MODE_32, &cs) !=
        CS_ERR_OK) {
        r.error = "capstone failed to open";
        return r;
    }
    cs_option(cs, CS_OPT_DETAIL, CS_OPT_ON);
    struct arch_guard {
        bool was = g_arm;
        explicit arch_guard(bool a) { g_arm = a; }
        ~arch_guard() { g_arm = was; }
    } arch(arm);

    // ---- your names and types (db.lvars) and your prototype (db.protos) go over the
    // decompiler's own; the types also decide how memory reads print (p->next)
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
    // where the stack arguments start, from the stack pointer at the entry; arg_0 is the first
    // (x86 has the return address below them, arm64 keeps it in x30)
    int64_t stack_from = arm ? 0 : !is64 ? ptr : ptr + (db.bin.format == bin_format::pe ? 0x20 : 0);
    const int64_t arg_bias = arm ? 0 : ptr;
    auto param_key = [&](int i) {
        if (i < nregs)
            return arm ? "a" + std::to_string(i) : reg_display(arg_reg_at(i, is64, db.bin.format), is64);
        return util::fmt("arg_%llx", (unsigned long long)(stack_from - arg_bias + (i - (is64 ? nregs : 0)) * ptr));
    };

    type_view tv;
    tv.lib = &db.types;
    tv.ptr = ptr;
    if (proto)
        for (size_t i = 0; i < proto->params.size(); i++)
            if (!proto->params[i].type.empty())
                tv.vars[param_key((int)i)] = proto->params[i].type;
    if (user)
        for (const auto& v : *user)
            if (!v.second.type.empty())
                tv.vars[v.first] = v.second.type;
    // making a struct from how a variable is used (struct_from_uses): it reads the plain way
    if (g_uses)
        tv.vars.erase(g_uses->key);
    for (const auto& v : tv.vars) {
        int64_t off;
        const ctype_def* d = db.types.aggregate(v.second);
        if (d && d->size && slot_offset(v.first, ptr, off))
            tv.frame.push_back({v.first, off, d});
    }
    tv.db = &db;
    struct view_guard {
        explicit view_guard(const type_view* v) { g_types = v; }
        ~view_guard() {
            g_types = nullptr;
            g_learn = nullptr;
        }
    } guard(tv.vars.empty() ? nullptr : &tv);
    // registers set only to values of one pointer type get it: rbx = inv is a struct
    // inventory* too. a pass per step of the chain (rdx = &rbx->slots[i] needs rbx's)
    for (int pass = 0; pass < 3 && g_types; pass++) {
        std::map<std::string, std::string> learned;
        g_learn = &learned;
        std::vector<block_ir> ir0;
        std::vector<std::string> params0;
        bool rv0 = false;
        lifter lf0(db, cs);
        lf0.run(start, ir0, params0, rv0);
        g_learn = nullptr;
        bool more = false;
        for (const auto& l : learned)
            if (l.second != "?" && !tv.vars.count(l.first) && (!g_uses || l.first != g_uses->key) &&
                (db.types.pointee(l.second) || db.types.scalar_pointee(l.second))) {
                tv.vars[l.first] = l.second;
                more = true;
            }
        if (!more)
            break;
    }

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

    std::vector<std::string> pkeys = params; // register display names
    int64_t max_arg = -1;
    for (const auto& f : lf.frame)
        if (f.first >= stack_from && f.first < stack_from + 64 * ptr)
            max_arg = std::max(max_arg, f.first);
    bool stack_params = !is64 || (int)params.size() == nregs;
    int want = proto ? (int)proto->params.size() : -1;
    if (stack_params && max_arg >= 0 && want < 0)
        for (int64_t off = stack_from; off <= max_arg; off += ptr)
            pkeys.push_back(lf.frame.count(off) ? lf.frame[off].name : util::fmt("arg_%llx", (unsigned long long)(off - arg_bias)));
    if (want >= 0) { // the prototype says how many
        pkeys.resize(std::min<size_t>(pkeys.size(), (size_t)want));
        for (int i = (int)pkeys.size(); i < want; i++)
            pkeys.push_back(param_key(i));
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
        int64_t rel;
        if (slot_inside(it->second.name, rel))
            continue; // a field of a struct variable: pt.y, declared with pt
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
        auto learned = tv.vars.find(it->second.name); // what's stored in it says what it is
        if (learned != tv.vars.end())
            ty = learned->second;
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
    for (const std::string& rg : regs) {
        auto learned = tv.vars.find(rg); // a type the pointer it holds says it has
        add_var(rg, false, false, learned != tv.vars.end() ? learned->second : std::string(), -1);
    }
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

bool struct_from_uses(database& db, uint64_t func, const std::string& var, std::string& name, std::string& decl,
                      std::string& err, bool apply)
{
    const function* fn = db.an.func_containing(func);
    if (!fn) {
        err = "no function there";
        return false;
    }
    // the decompiler's key for the variable: shown as its own name, yours or the prototype's
    decompiled d = decompile(db, fn->start);
    use_collector uses;
    for (const decomp_var& v : d.vars)
        if (v.name == var || (uses.key.empty() && v.key == var))
            uses.key = v.key;
    if (uses.key.empty()) {
        err = d.ok ? "no variable " + var + " in this function" : d.error;
        return false;
    }
    g_uses = &uses;
    d = decompile(db, fn->start);
    g_uses = nullptr;
    if (!d.ok) {
        err = d.error.empty() ? "can't decompile the function" : d.error;
        return false;
    }
    if (uses.fields.empty()) {
        err = "nothing is read or written through " + var + " in this function";
        return false;
    }
    // the name: yours, or function_variable made a c name and not one taken
    if (!name.empty()) {
        bool ok = std::isalpha((unsigned char)name[0]) || name[0] == '_';
        for (char c : name)
            ok = ok && (std::isalnum((unsigned char)c) || c == '_');
        if (!ok) {
            err = "a struct's name is letters, digits and _";
            return false;
        }
    }
    std::string base;
    for (char c : db.call_name(fn->start) + "_" + var)
        base += std::isalnum((unsigned char)c) ? c : '_';
    while (base.find("__") != std::string::npos)
        base.erase(base.find("__"), 1);
    if (base.size() > 48)
        base = base.substr(base.size() - 48);
    if (base.empty() || !std::isalpha((unsigned char)base[0]))
        base = "s_" + base;
    if (name.empty()) {
        name = base;
        for (int k = 2; db.types.find(name); k++)
            name = base + "_" + std::to_string(k);
    }
    // the fields, one per offset (the widest access), gaps between them as bytes
    std::string body;
    uint64_t at = 0;
    bool aligned = true;
    for (auto it = uses.fields.begin(); it != uses.fields.end(); ++it) {
        uint64_t off = it->first;
        uint32_t w = it->second;
        auto next = std::next(it);
        if (off < at)
            continue; // inside the one before
        if (next != uses.fields.end() && off + w > next->first)
            w = (uint32_t)(next->first - off); // overlaps the next: only up to it
        if (off > at)
            body += util::fmt("    char gap_%llx[0x%llx];\n", (unsigned long long)at, (unsigned long long)(off - at));
        const char* ty = w == 1 ? "char" : w == 2 ? "short" : w == 4 ? "int" : w == 8 ? "long long" : nullptr;
        if (ty && uses.self.count(off) && w == (uint32_t)db.bin.ptr_size()) {
            body += util::fmt("    struct %s* field_%llx;\n", name.c_str(), (unsigned long long)off);
            aligned = aligned && off % w == 0;
        } else if (ty) {
            body += util::fmt("    %s field_%llx;\n", ty, (unsigned long long)off);
            aligned = aligned && off % w == 0;
        } else {
            body += util::fmt("    char field_%llx[%u];\n", (unsigned long long)off, w);
        }
        at = off + w;
    }
    decl = std::string(aligned ? "" : "#pragma pack(push, 1)\n") + "struct " + name + " {\n" + body + "};" +
           (aligned ? "" : "\n#pragma pack(pop)");
    if (!apply)
        return true;
    // declared, and the variable points to it (one undo step with the app's per-frame groups)
    if (!db.add_types(decl, err))
        return false;
    auto uv = db.lvars.find(fn->start);
    std::string shown = uv != db.lvars.end() && uv->second.count(uses.key) ? uv->second.at(uses.key).name : std::string();
    return db.set_lvar(fn->start, uses.key, shown, "struct " + name + "*", err);
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
