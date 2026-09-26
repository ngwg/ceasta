#include "core/ctypes.h"
#include "core/util.h"
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <set>

// a small c declaration parser: enough of c's type syntax for the structs of real headers, not
// a compiler. a type is a tree (a pointer to an array of ...), laid out the way gcc / clang
// (sysv) and msvc (windows) do it, for the abi set with set_abi

// base: a scalar ("unsigned int"), "struct x" / "union x" / "enum x", or a typedef's name
struct ctype_node {
    enum class k : uint8_t { base, ptr, arr, fn } kind = k::base;
    std::string base; // fn: the parameters, as written ("int, void*")
    uint64_t n = 0; // array length (0: [], a flexible array member)
    std::shared_ptr<const ctype_node> of;
};

namespace {

using tp = std::shared_ptr<const ctype_node>;

tp t_base(const std::string& b)
{
    auto t = std::make_shared<ctype_node>();
    t->base = b;
    return t;
}

tp t_wrap(ctype_node::k k, tp of, uint64_t n = 0)
{
    auto t = std::make_shared<ctype_node>();
    t->kind = k;
    t->of = std::move(of);
    t->n = n;
    return t;
}

// c text of a type with a name (may be empty) where c puts it: "int (*name)[4]"
std::string to_text(const tp& t, const std::string& inner = std::string())
{
    switch (t->kind) {
    case ctype_node::k::base:
        return inner.empty() ? t->base : t->base + " " + inner;
    case ctype_node::k::ptr: {
        std::string in = "*" + inner;
        if (t->of->kind == ctype_node::k::arr || t->of->kind == ctype_node::k::fn)
            in = "(" + in + ")";
        return to_text(t->of, in);
    }
    case ctype_node::k::arr:
        return to_text(t->of, inner + "[" + (t->n ? std::to_string(t->n) : std::string()) + "]");
    case ctype_node::k::fn:
        return to_text(t->of, inner + "(" + t->base + ")");
    }
    return "?";
}

// the way types are written as text here: "struct node*", "char[16]", "void (*)()"
std::string type_text(const tp& t)
{
    std::string s = to_text(t);
    for (size_t k; (k = s.find(" *")) != std::string::npos;)
        s.erase(k, 1);
    for (size_t k; (k = s.find(" [")) != std::string::npos;)
        s.erase(k, 1);
    return s;
}

struct tok {
    enum class k : uint8_t { id, num, punct, pack, end } kind = k::end;
    std::string s;
    uint64_t v = 0;
    int line = 1;
};

bool id_start(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == '$'; }
bool id_char(char c) { return id_start(c) || (c >= '0' && c <= '9'); }

// #pragma pack(...) as a token: v the packing, s "push" / "pop" / ""
bool pragma_pack(const std::string& line, tok& t)
{
    size_t p = line.find("pack");
    if (line.find("pragma") == std::string::npos || p == std::string::npos)
        return false;
    size_t a = line.find('(', p), b = line.find(')', p);
    std::string in = a != std::string::npos && b != std::string::npos && b > a ? line.substr(a + 1, b - a - 1) : std::string();
    t.kind = tok::k::pack;
    t.s = in.find("push") != std::string::npos ? "push" : in.find("pop") != std::string::npos ? "pop" : "";
    t.v = 0;
    for (size_t i = 0; i < in.size(); i++)
        if (in[i] >= '0' && in[i] <= '9') {
            t.v = strtoull(in.c_str() + i, nullptr, 10);
            break;
        }
    return true;
}

// #define NAME text: the macros without parameters, as the tokens they stand for
using macros = std::map<std::string, std::vector<tok>>;
bool tokenize(const std::string& s, std::vector<tok>& out, std::string& err, macros* defs);

// a preprocessor line: #define NAME text (not NAME(args)) adds a macro, #undef NAME drops one
void add_macro(const std::string& line, macros& defs)
{
    size_t p = line.find_first_not_of(" \t", 1);
    bool undef = p != std::string::npos && line.compare(p, 5, "undef") == 0;
    if (p == std::string::npos || (!undef && line.compare(p, 6, "define") != 0))
        return;
    p = line.find_first_not_of(" \t", p + (undef ? 5 : 6));
    if (p == std::string::npos || !id_start(line[p]))
        return;
    size_t e = p;
    while (e < line.size() && id_char(line[e]))
        e++;
    std::string name = line.substr(p, e - p);
    if (undef || (e < line.size() && line[e] == '(')) {
        defs.erase(name); // a macro with parameters isn't expanded
        return;
    }
    std::string body = line.substr(e);
    std::vector<tok> toks;
    std::string err;
    if (body.size() > 4096 || !tokenize(body, toks, err, &defs))
        return;
    toks.pop_back(); // the end
    defs[name] = toks;
}

bool tokenize(const std::string& s, std::vector<tok>& out, std::string& err, macros* defs = nullptr)
{
    macros own;
    if (!defs)
        defs = &own;
    int line = 1;
    bool line_start = true;
    for (size_t i = 0; i < s.size();) {
        char c = s[i];
        if (c == '\n') {
            line++;
            line_start = true;
            i++;
            continue;
        }
        if (c == ' ' || c == '\t' || c == '\r' || c == '\f' || c == '\v') {
            i++;
            continue;
        }
        if (c == '/' && i + 1 < s.size() && s[i + 1] == '/') {
            while (i < s.size() && s[i] != '\n')
                i++;
            continue;
        }
        if (c == '/' && i + 1 < s.size() && s[i + 1] == '*') {
            size_t e = s.find("*/", i + 2);
            if (e == std::string::npos) {
                err = util::fmt("line %d: a comment that doesn't end", line);
                return false;
            }
            line += (int)std::count(s.begin() + (long)i, s.begin() + (long)e, '\n');
            i = e + 2;
            continue;
        }
        if (c == '#' && line_start) { // preprocessor: #pragma pack is kept, #define read, the rest skipped
            size_t e = i;
            std::string d; // the line, its comments out (one may go on over the next lines)
            while (e < s.size() && s[e] != '\n') {
                if (s[e] == '\\' && e + 1 < s.size() && s[e + 1] == '\n') {
                    line++;
                    e += 2;
                    d += ' ';
                } else if (s.compare(e, 2, "/*") == 0) {
                    size_t ce = s.find("*/", e + 2);
                    ce = ce == std::string::npos ? s.size() : ce + 2;
                    line += (int)std::count(s.begin() + (long)e, s.begin() + (long)ce, '\n');
                    e = ce;
                    d += ' ';
                } else if (s.compare(e, 2, "//") == 0) {
                    while (e < s.size() && s[e] != '\n')
                        e++;
                } else {
                    d += s[e++];
                }
            }
            tok t;
            t.line = line;
            if (pragma_pack(d, t))
                out.push_back(t);
            else
                add_macro(d, *defs);
            i = e;
            continue;
        }
        line_start = false;
        tok t;
        t.line = line;
        if (id_start(c)) {
            size_t e = i;
            while (e < s.size() && id_char(s[e]))
                e++;
            t.kind = tok::k::id;
            t.s = s.substr(i, e - i);
            i = e;
            auto m = defs->find(t.s);
            if (m != defs->end()) { // a macro: what it stands for (nothing, for #define IN)
                for (tok x : m->second) {
                    x.line = line;
                    out.push_back(x);
                }
                continue;
            }
        } else if (c >= '0' && c <= '9') {
            size_t e = i;
            while (e < s.size() && (id_char(s[e]) || s[e] == '.'))
                e++;
            t.kind = tok::k::num;
            t.s = s.substr(i, e - i);
            t.v = strtoull(t.s.c_str(), nullptr, 0); // 0x.., 0.., decimal; suffixes (u, l) stop it
            i = e;
        } else if (c == '\'' && i + 2 < s.size() && s[i + 2] == '\'') {
            t.kind = tok::k::num;
            t.v = (unsigned char)s[i + 1];
            t.s = s.substr(i, 3);
            i += 3;
        } else {
            t.kind = tok::k::punct;
            t.s = std::string(1, c);
            for (const char* w : {"<<", ">>", "::", "->"})
                if (s.compare(i, 2, w) == 0)
                    t.s = w;
            i += t.s.size();
        }
        out.push_back(t);
        if (out.size() > 4000000) {
            err = "too much text";
            return false;
        }
    }
    tok e;
    e.line = line;
    out.push_back(e);
    return true;
}

bool is_qualifier(const std::string& w)
{
    static const char* const q[] = {"const", "volatile", "restrict", "__restrict", "__restrict__", "__ptr64", "__ptr32",
        "__unaligned", "static", "extern", "register", "inline", "__inline", "__forceinline", "mutable", "__sptr",
        "__uptr", "_Atomic", "__cdecl", "__stdcall", "__fastcall", "__thiscall", "__vectorcall", "WINAPI", "CALLBACK",
        "APIENTRY", "NTAPI", "IN", "OUT", "OPTIONAL", "_In_", "_Out_", "_Inout_", "_In_opt_", "_Out_opt_",
        "_Inout_opt_", "__nonnull", "__nullable", "_Nonnull", "_Nullable", "__extension__", "__inline__", "__const",
        "__const__", "__volatile", "__volatile__", "__restrict__", "_Noreturn", "__wur"};
    for (const char* x : q)
        if (w == x)
            return true;
    return false;
}

bool is_scalar_word(const std::string& w)
{
    static const char* const s[] = {"void", "char", "short", "int", "long", "signed", "unsigned", "float", "double",
        "_Bool", "bool", "__int8", "__int16", "__int32", "__int64", "__int128", "wchar_t", "char8_t", "char16_t",
        "char32_t", "__signed", "__signed__"};
    for (const char* x : s)
        if (w == x)
            return true;
    return false;
}

// the well-known typedefs that point to a scalar: its size
uint32_t named_pointer_target(const std::string& w)
{
    static const struct {
        const char* name;
        uint32_t size;
    } t[] = {{"LPSTR", 1}, {"LPCSTR", 1}, {"PSTR", 1}, {"PCSTR", 1}, {"PCHAR", 1}, {"PBYTE", 1}, {"LPBYTE", 1},
        {"PUCHAR", 1}, {"LPWSTR", 2}, {"LPCWSTR", 2}, {"PWSTR", 2}, {"PCWSTR", 2}, {"PWCHAR", 2}, {"PUSHORT", 2},
        {"LPWORD", 2}, {"PWORD", 2}, {"PDWORD", 4}, {"LPDWORD", 4}, {"PULONG", 4}, {"LPLONG", 4}, {"PLONG", 4},
        {"LPBOOL", 4}, {"PBOOL", 4}};
    for (const auto& x : t)
        if (w == x.name)
            return x.size;
    return 0;
}

} // namespace

// ---- scalars and well-known typedefs

bool ctypes::scalar(const std::string& word, uint32_t& size) const
{
    // -1: a pointer, -2: long (4 on windows, else the pointer size), -3: wchar_t, -4: va_list (a
    // struct on x64 sysv and arm64 linux, else a pointer)
    static const struct {
        const char* name;
        int size;
    } table[] = {
        {"void", 0}, {"char", 1}, {"signed char", 1}, {"unsigned char", 1}, {"short", 2}, {"unsigned short", 2},
        {"int", 4}, {"unsigned int", 4}, {"long", -2}, {"unsigned long", -2}, {"long long", 8},
        {"unsigned long long", 8}, {"float", 4}, {"double", 8}, {"long double", 16}, {"_Bool", 1}, {"bool", 1},
        {"__int8", 1}, {"unsigned __int8", 1}, {"__int16", 2}, {"unsigned __int16", 2}, {"__int32", 4},
        {"unsigned __int32", 4}, {"__int64", 8}, {"unsigned __int64", 8}, {"__int128", 16},
        {"unsigned __int128", 16}, {"wchar_t", -3}, {"char8_t", 1}, {"char16_t", 2}, {"char32_t", 4},
        {"_Float16", 2}, {"__fp16", 2}, {"__bf16", 2}, {"_Float32", 4}, {"_Float64", 8}, {"_Float32x", 8},
        {"_Float128", 16}, {"_Float64x", 16}, {"__float128", 16}, {"__builtin_va_list", -4}, {"va_list", -4},
        {"__int128_t", 16}, {"__uint128_t", 16},
        // stdint, posix, linux, the usual short forms
        {"int8_t", 1}, {"uint8_t", 1}, {"int16_t", 2}, {"uint16_t", 2}, {"int32_t", 4}, {"uint32_t", 4},
        {"int64_t", 8}, {"uint64_t", 8}, {"intptr_t", -1}, {"uintptr_t", -1}, {"size_t", -1}, {"ssize_t", -1},
        {"ptrdiff_t", -1}, {"off_t", 8}, {"time_t", 8}, {"pid_t", 4}, {"uid_t", 4}, {"gid_t", 4}, {"mode_t", 4},
        {"socklen_t", 4}, {"u8", 1}, {"u16", 2}, {"u32", 4}, {"u64", 8}, {"s8", 1}, {"s16", 2}, {"s32", 4},
        {"s64", 8}, {"__u8", 1}, {"__u16", 2}, {"__u32", 4}, {"__u64", 8}, {"__s8", 1}, {"__s16", 2},
        {"__s32", 4}, {"__s64", 8}, {"uchar", 1}, {"ushort", 2}, {"uint", 4}, {"ulong", -2}, {"byte", 1},
        // windows
        {"BYTE", 1}, {"UCHAR", 1}, {"CHAR", 1}, {"CCHAR", 1}, {"BOOLEAN", 1}, {"INT8", 1}, {"UINT8", 1},
        {"WORD", 2}, {"USHORT", 2}, {"SHORT", 2}, {"WCHAR", 2}, {"INT16", 2}, {"UINT16", 2}, {"ATOM", 2},
        {"DWORD", 4}, {"UINT", 4}, {"INT", 4}, {"LONG", 4}, {"ULONG", 4}, {"BOOL", 4}, {"INT32", 4},
        {"UINT32", 4}, {"DWORD32", 4}, {"LONG32", 4}, {"ULONG32", 4}, {"HRESULT", 4}, {"NTSTATUS", 4},
        {"FLOAT", 4}, {"DOUBLE", 8}, {"QWORD", 8}, {"DWORD64", 8}, {"ULONGLONG", 8}, {"LONGLONG", 8},
        {"INT64", 8}, {"UINT64", 8}, {"LONG64", 8}, {"ULONG64", 8}, {"SIZE_T", -1}, {"SSIZE_T", -1},
        {"ULONG_PTR", -1}, {"LONG_PTR", -1}, {"DWORD_PTR", -1}, {"INT_PTR", -1}, {"UINT_PTR", -1},
        {"WPARAM", -1}, {"LPARAM", -1}, {"LRESULT", -1}, {"HANDLE", -1}, {"HMODULE", -1}, {"HINSTANCE", -1},
        {"HWND", -1}, {"HKEY", -1}, {"HDC", -1}, {"HICON", -1}, {"HMENU", -1}, {"HBITMAP", -1}, {"HBRUSH", -1},
        {"HFONT", -1}, {"HGLOBAL", -1}, {"HLOCAL", -1}, {"HRSRC", -1}, {"HCURSOR", -1}, {"SOCKET", -1},
        {"FARPROC", -1}, {"LPVOID", -1}, {"PVOID", -1}, {"LPCVOID", -1}, {"LPSTR", -1}, {"LPCSTR", -1},
        {"LPWSTR", -1}, {"LPCWSTR", -1}, {"PSTR", -1}, {"PCSTR", -1}, {"PWSTR", -1}, {"PCWSTR", -1},
        {"PCHAR", -1}, {"PBYTE", -1}, {"LPBYTE", -1}, {"PDWORD", -1}, {"LPDWORD", -1}, {"PULONG", -1},
        {"PHANDLE", -1}, {"LPHANDLE", -1}, {"PSIZE_T", -1}, {"LPBOOL", -1}, {"PBOOL", -1}, {"LPWORD", -1},
        {"PWORD", -1}, {"LPLONG", -1}, {"PLONG", -1}, {"PUCHAR", -1}, {"PUSHORT", -1}, {"PWCHAR", -1},
        {"LPTSTR", -1}, {"LPCTSTR", -1}, {"PSID", -1}, {"PVOID64", 8},
    };
    for (const auto& e : table)
        if (word == e.name) {
            size = e.size >= 0 ? (uint32_t)e.size
                 : e.size == -1 ? (uint32_t)ptr_
                 : e.size == -2 ? (win_ ? 4u : (uint32_t)ptr_)
                 : e.size == -3 ? (win_ ? 2u : 4u)
                 : aapcs_       ? 32u
                 : ptr_ == 8 && !win_ && !short_ld_ ? 24u
                                : (uint32_t)ptr_;
            return true;
        }
    return false;
}

void ctypes::set_abi(int ptr_size, bool windows, bool arm64, bool apple)
{
    ptr_ = ptr_size == 4 ? 4 : 8;
    win_ = windows;
    aapcs_ = arm64 && !windows && !apple;
    short_ld_ = windows || (arm64 && apple);
    cache_.clear();
}

// ---- the parser

struct ctype_parser {
    ctypes& lib;
    bool readonly = false; // only reading a type: nothing gets defined
    std::vector<tok> t;
    size_t i = 0;
    std::string err;
    std::vector<uint32_t> packs;
    uint32_t pack = 0;
    std::vector<std::string> added;
    int depth = 0;
    std::map<std::string, int64_t> constants; // enum values, for array sizes
    int linkage = 0;                          // inside extern "C" { }
    int mode = 0;                             // __mode__(__DI__): a typedef's size in bytes
    std::vector<std::string> placeholders;    // structs being read: known while their members are
    int skipped = 0;                          // lenient: declarations it couldn't read
    std::string first_err;

    explicit ctype_parser(ctypes& l) : lib(l) {}

    // an enum's value by name: this text's, or one defined before (read in when first needed:
    // a parser is made for every type it reads)
    bool known_constants = false;
    const int64_t* constant(const std::string& n)
    {
        if (!known_constants) {
            known_constants = true;
            for (const auto& d : lib.defs_)
                for (const auto& v : d.second.values)
                    constants.insert(v);
        }
        auto it = constants.find(n);
        return it == constants.end() ? nullptr : &it->second;
    }

    const tok& cur() const { return t[i]; }
    bool at(const char* p) const { return t[i].kind == tok::k::punct && t[i].s == p; }
    bool at_id(const char* w) const { return t[i].kind == tok::k::id && t[i].s == w; }
    bool accept(const char* p)
    {
        if (!at(p))
            return false;
        i++;
        return true;
    }
    bool fail(const std::string& m)
    {
        if (err.empty())
            err = util::fmt("line %d: %s", t[i].line, m.c_str());
        return false;
    }
    std::string where() const
    {
        return t[i].kind == tok::k::end ? std::string(" at the end") : " before '" + t[i].s + "'";
    }
    bool expect(const char* p)
    {
        if (accept(p))
            return true;
        return fail(std::string("expected ") + p + where());
    }

    void skip_balanced() // at '(' / '[' / '{': past its match
    {
        int d = 0;
        do {
            if (at("(") || at("[") || at("{"))
                d++;
            else if (at(")") || at("]") || at("}"))
                d--;
            i++;
        } while (d > 0 && t[i].kind != tok::k::end);
    }

    // qualifiers, __attribute__((packed)), __declspec(align(8)), alignas(8)
    bool skip_attributes(bool* packed = nullptr, uint32_t* align = nullptr)
    {
        for (;;) {
            if (at_id("__attribute__") || at_id("__attribute") || at_id("__declspec") || at_id("alignas") ||
                at_id("_Alignas") || at_id("__asm__") || at_id("__asm") || at_id("asm")) {
                bool as = at_id("alignas") || at_id("_Alignas");
                size_t from = ++i;
                if (!at("("))
                    return fail("expected ( after an attribute");
                skip_balanced();
                for (size_t k = from; k < i; k++) {
                    if (packed && t[k].kind == tok::k::id && (t[k].s == "packed" || t[k].s == "__packed__"))
                        *packed = true;
                    // alignas(8), aligned(8), __aligned__(8), align(8): not the numbers of other attributes
                    const std::string& w = k >= 2 ? t[k - 2].s : std::string();
                    if (align && t[k].kind == tok::k::num &&
                        ((as && k == from + 1) || (t[k - 1].s == "(" && (w == "aligned" || w == "__aligned__" || w == "align"))))
                        *align = (uint32_t)std::min<uint64_t>(t[k].v, 4096);
                    if (align && (t[k].s == "aligned" || t[k].s == "__aligned__") && t[k + 1].s != "(")
                        *align = 16; // __attribute__((aligned)): the biggest there is
                    if ((t[k].s == "__mode__" || t[k].s == "mode") && t[k + 1].s == "(" && t[k + 2].kind == tok::k::id) {
                        const std::string& m = t[k + 2].s; // typedef int register_t __attribute__((__mode__(__word__)))
                        mode = m.find("QI") != std::string::npos || m.find("byte") != std::string::npos ? 1
                             : m.find("HI") != std::string::npos ? 2 : m.find("SI") != std::string::npos ? 4
                             : m.find("DI") != std::string::npos ? 8 : m.find("TI") != std::string::npos ? 16
                             : m.find("word") != std::string::npos || m.find("pointer") != std::string::npos ? lib.ptr_ : 0;
                    }
                }
                continue;
            }
            if (cur().kind == tok::k::id && is_qualifier(cur().s)) {
                i++;
                continue;
            }
            return true;
        }
    }

    void do_pragmas()
    {
        while (cur().kind == tok::k::pack) {
            const tok& p = cur();
            if (p.s == "push") {
                packs.push_back(pack);
                if (p.v)
                    pack = (uint32_t)p.v;
            } else if (p.s == "pop") {
                pack = packs.empty() ? 0 : packs.back();
                if (!packs.empty())
                    packs.pop_back();
            } else {
                pack = (uint32_t)p.v;
            }
            i++;
        }
    }

    // ---- constant expressions: array sizes, enum values

    bool type_starts(size_t k)
    {
        uint32_t sz;
        const tok& x = t[k];
        return x.kind == tok::k::id && !constant(x.s) &&
               (is_scalar_word(x.s) || is_qualifier(x.s) || x.s == "struct" || x.s == "union" || x.s == "enum" ||
                lib.find(x.s) || lib.scalar(x.s, sz));
    }

    bool cexpr(int64_t& v, int prec = 0)
    {
        if (++depth > 64)
            return fail("an expression too deep");
        bool ok = cunary(v);
        while (ok) {
            static const struct {
                const char* op;
                int p;
            } ops[] = {{"|", 1}, {"^", 2}, {"&", 3}, {"<<", 4}, {">>", 4}, {"+", 5}, {"-", 5}, {"*", 6}, {"/", 6}, {"%", 6}};
            int p = -1;
            std::string op;
            for (const auto& o : ops)
                if (at(o.op) && o.p > prec) {
                    p = o.p;
                    op = o.op;
                }
            if (p < 0)
                break;
            i++;
            int64_t r = 0;
            if (!cexpr(r, p)) {
                ok = false;
                break;
            }
            if (op == "|")
                v |= r;
            else if (op == "^")
                v ^= r;
            else if (op == "&")
                v &= r;
            else if (op == "<<")
                v = r >= 0 && r < 64 ? (int64_t)((uint64_t)v << r) : 0;
            else if (op == ">>")
                v = r >= 0 && r < 64 ? v >> r : 0;
            else if (op == "+")
                v = (int64_t)((uint64_t)v + (uint64_t)r);
            else if (op == "-")
                v = (int64_t)((uint64_t)v - (uint64_t)r);
            else if (op == "*")
                v = (int64_t)((uint64_t)v * (uint64_t)r);
            else if (r == 0)
                ok = fail("a division by zero");
            else if (op == "/")
                v = v == INT64_MIN && r == -1 ? v : v / r;
            else
                v = r == -1 ? 0 : v % r;
        }
        depth--;
        return ok;
    }

    bool cunary(int64_t& v)
    {
        if (accept("-")) {
            if (!cunary(v))
                return false;
            v = (int64_t)(0 - (uint64_t)v);
            return true;
        }
        if (accept("~")) {
            if (!cunary(v))
                return false;
            v = ~v;
            return true;
        }
        if (accept("+"))
            return cunary(v);
        if (at("(") && type_starts(i + 1)) { // a cast: (int) sizeof (x)
            i++;
            tp ty;
            return type_name(ty) && expect(")") && cunary(v);
        }
        if (accept("("))
            return cexpr(v) && expect(")");
        if (cur().kind == tok::k::num) {
            v = (int64_t)cur().v;
            i++;
            return true;
        }
        if (at_id("sizeof")) {
            i++;
            if (!expect("("))
                return false;
            tp ty;
            uint32_t sz = 0, al = 0;
            if (!type_name(ty) || !layout(ty, sz, al))
                return false;
            v = sz;
            return expect(")");
        }
        if (cur().kind == tok::k::id) {
            const int64_t* c = constant(cur().s);
            if (!c)
                return fail("unknown constant '" + cur().s + "'");
            v = *c;
            i++;
            return true;
        }
        return fail("expected a number" + where());
    }

    // ---- types

    std::string anon_name() { return util::fmt("__anon_%d", ++lib.anon_); }

    // the type specifier: scalar words, a struct / union / enum (maybe defined right here), or a
    // typedef's name
    bool specifier(tp& out)
    {
        if (!skip_attributes())
            return false;
        do_pragmas();
        if (at_id("struct") || at_id("union") || at_id("class")) {
            bool un = at_id("union");
            i++;
            return aggregate(un, out);
        }
        if (at_id("enum")) {
            i++;
            return enumeration(out);
        }
        std::vector<std::string> words;
        while (cur().kind == tok::k::id && (is_scalar_word(cur().s) || is_qualifier(cur().s))) {
            // wchar_t, bool, ... stand alone: in typedef int wchar_t it's the name
            static const char* const alone[] = {"wchar_t", "char8_t", "char16_t", "char32_t", "_Bool", "bool", "void", "float"};
            bool sa = false;
            for (const char* a : alone)
                sa = sa || cur().s == a;
            if (sa && !words.empty())
                break;
            if (!is_qualifier(cur().s))
                words.push_back(cur().s);
            i++;
        }
        if (!words.empty()) {
            bool uns = false, sgn = false;
            int longs = 0, shorts = 0;
            std::string core;
            for (const std::string& w : words) {
                if (w == "unsigned")
                    uns = true;
                else if (w == "signed" || w == "__signed" || w == "__signed__")
                    sgn = true;
                else if (w == "long")
                    longs++;
                else if (w == "short")
                    shorts++;
                else if (!core.empty())
                    return fail("'" + core + " " + w + "' isn't a type");
                else
                    core = w;
            }
            std::string b;
            if (core == "double" && longs == 1)
                b = "long double";
            else if (shorts && (core.empty() || core == "int"))
                b = "short";
            else if (longs >= 2 && (core.empty() || core == "int"))
                b = "long long";
            else if (longs == 1 && (core.empty() || core == "int"))
                b = "long";
            else if (longs || shorts)
                return fail("'" + (longs ? std::string("long ") : std::string("short ")) + core + "' isn't a type");
            else
                b = core.empty() ? "int" : core;
            if (uns) {
                if (b != "char" && b != "short" && b != "int" && b != "long" && b != "long long" && b.compare(0, 5, "__int") != 0)
                    return fail("unsigned " + b + " isn't a type");
                b = "unsigned " + b;
            } else if (sgn && b == "char") {
                b = "signed char";
            }
            out = t_base(b);
            return skip_attributes();
        }
        if (cur().kind == tok::k::id) {
            std::string w = cur().s;
            uint32_t sz;
            if (lib.find(w) || lib.scalar(w, sz)) {
                i++;
                out = t_base(w);
                return skip_attributes();
            }
            return fail("unknown type '" + w + "'");
        }
        return fail("expected a type" + where());
    }

    // struct / union [name] [{ members }]
    bool aggregate(bool un, tp& out)
    {
        bool packed = false;
        uint32_t align = 0;
        if (!skip_attributes(&packed, &align))
            return false;
        std::string name;
        if (cur().kind == tok::k::id) {
            name = cur().s;
            i++;
            if (!skip_attributes(&packed, &align))
                return false;
        }
        const char* kw = un ? "union " : "struct ";
        if (!at("{")) {
            if (name.empty())
                return fail("a struct needs a name or a body");
            out = t_base(kw + name); // a reference, maybe to one defined later (pointers are fine)
            return true;
        }
        i++;
        if (name.empty())
            name = anon_name();
        ctype_def d;
        d.k = un ? ctype_def::kind::union_ : ctype_def::kind::struct_;
        d.name = name;
        d.pack = pack;
        // known while its members are read: a member can point to it without "struct" (c++)
        if (!readonly && !lib.defs_.count(name)) {
            ctype_def fwd;
            fwd.k = d.k;
            fwd.name = name;
            lib.defs_[name] = fwd;
            placeholders.push_back(name);
        }
        struct member {
            std::string name;
            tp type;
            int bits; // -1: not a bit field
        };
        std::vector<member> members;
        while (!accept("}")) {
            if (cur().kind == tok::k::end)
                return fail("a struct without its closing }");
            if (accept(";"))
                continue;
            do_pragmas();
            if (at("}"))
                continue;
            tp base;
            if (!specifier(base))
                return false;
            if (accept(";")) { // an anonymous struct / union member: its fields show through
                if (base->kind == ctype_node::k::base && base->base.find(" __anon_") != std::string::npos)
                    members.push_back({std::string(), base, -1});
                continue;
            }
            for (;;) {
                std::string mname;
                tp mt = base;
                if (!at(":") && !declarator(base, mt, mname))
                    return false;
                int bits = -1;
                if (accept(":")) {
                    int64_t w = 0;
                    if (!cexpr(w))
                        return false;
                    if (w < 0 || w > 128)
                        return fail("a bit field's width is 0 to 128");
                    bits = (int)w;
                }
                if (!skip_attributes())
                    return false;
                if (mname.empty() && bits < 0)
                    return fail("a member without a name");
                members.push_back({mname, mt, bits});
                if (accept(","))
                    continue;
                if (!expect(";"))
                    return false;
                break;
            }
        }
        bool packed2 = false;
        if (!skip_attributes(&packed2, &align))
            return false;
        packed = packed || packed2;
        if (!lay_out(d, members.size(), [&](size_t k, std::string& n, tp& ty, int& b) {
                n = members[k].name;
                ty = members[k].type;
                b = members[k].bits;
            }, packed, align))
            return false;
        define(d);
        out = t_base(kw + name);
        return true;
    }

    // offsets, size and alignment: sysv (gcc, clang) or msvc rules, bit fields included
    template <typename F>
    bool lay_out(ctype_def& d, size_t count, F&& member, bool packed, uint32_t want_align)
    {
        bool un = d.k == ctype_def::kind::union_, win = lib.win_;
        uint64_t bp = 0, max_bytes = 0;       // the next free bit
        uint64_t ustart = 0, usize = 0;       // msvc: the open bit field unit, in bits
        uint32_t max_align = 1;
        for (size_t m = 0; m < count; m++) {
            std::string mname;
            tp mt;
            int bits;
            member(m, mname, mt, bits);
            uint32_t sz = 0, al = 1;
            if (!layout(mt, sz, al))
                return false;
            uint32_t natural = al;
            if (packed)
                al = 1;
            else if (d.pack && al > d.pack)
                al = d.pack;
            ctype_field f;
            f.name = mname;
            f.type = type_text(mt);
            f.size = sz;
            if (bits >= 0) {
                if (sz == 0 || sz > 16 || mt->kind != ctype_node::k::base)
                    return fail("a bit field of a type that isn't an integer");
                if (bits > (int)sz * 8)
                    return fail("a bit field wider than its type");
                f.bitfield = true;
                if (un) {
                    f.bits = (uint8_t)bits;
                    max_bytes = std::max<uint64_t>(max_bytes, sz);
                } else if (bits == 0) { // ends the unit: the next field starts at the type's alignment
                    if (win && usize)
                        bp = ustart + usize;
                    usize = 0;
                    uint32_t za = win ? al : packed ? 1 : natural; // sysv: #pragma pack doesn't cap it
                    bp = (bp + za * 8ull - 1) / (za * 8ull) * (za * 8ull);
                    if (lib.aapcs_ && !win && !packed)
                        max_align = std::max(max_align, za); // arm64 linux: it aligns the struct too
                    f.offset = (uint32_t)(bp / 8);
                    d.fields.push_back(f);
                    continue;
                } else if (win) {
                    if (usize != sz * 8ull || bp + (uint64_t)bits > ustart + usize) {
                        if (usize)
                            bp = ustart + usize;
                        bp = (bp + al * 8ull - 1) / (al * 8ull) * (al * 8ull);
                        ustart = bp;
                        usize = sz * 8ull;
                    }
                    f.offset = (uint32_t)(ustart / 8);
                    f.bit_offset = (uint8_t)(bp - ustart);
                    f.bits = (uint8_t)bits;
                    bp += (uint64_t)bits;
                } else {
                    // sysv: it has to fit in a unit of its type's size that starts at a multiple
                    // of its type's alignment (on i386 a long long's unit is 8 bytes, 4-aligned)
                    uint64_t step = al * 8ull, unit = bp / step * step;
                    if (!packed && !d.pack && bp + (uint64_t)bits > unit + sz * 8ull) { // #pragma pack: it may straddle
                        bp = (bp + step - 1) / step * step;
                        unit = bp;
                    }
                    f.offset = (uint32_t)(packed ? bp / 8 : unit / 8);
                    f.bit_offset = (uint8_t)(bp - f.offset * 8ull);
                    f.bits = (uint8_t)bits;
                    bp += (uint64_t)bits;
                }
                if (!mname.empty() || win)
                    max_align = std::max(max_align, al);
                d.fields.push_back(f);
                continue;
            }
            if (win && usize) {
                bp = ustart + usize;
                usize = 0;
            }
            if (un) {
                f.offset = 0;
                max_bytes = std::max<uint64_t>(max_bytes, sz);
            } else {
                uint64_t byte = (bp + 7) / 8;
                byte = (byte + al - 1) / al * al;
                f.offset = (uint32_t)byte;
                bp = (byte + sz) * 8;
                if (byte + sz > 0x7fffffff)
                    return fail("the struct is too big");
            }
            max_align = std::max(max_align, al);
            d.fields.push_back(f);
        }
        if (win && usize)
            bp = ustart + usize;
        d.packed = packed;
        d.aligned = want_align;
        if (want_align > max_align && !packed)
            max_align = want_align;
        uint64_t size = un ? max_bytes : (bp + 7) / 8;
        size = (size + max_align - 1) / max_align * max_align;
        if (size > 0x7fffffff)
            return fail("the struct is too big");
        d.size = (uint32_t)size;
        d.align = max_align;
        return true;
    }

    bool enumeration(tp& out)
    {
        if (!skip_attributes())
            return false;
        std::string name;
        if (cur().kind == tok::k::id) {
            name = cur().s;
            i++;
        }
        uint32_t size = 4;
        if (accept(":")) { // c++ / c23: the underlying type
            tp u;
            uint32_t al = 0;
            if (!specifier(u) || !layout(u, size, al))
                return false;
        }
        if (!at("{")) {
            if (name.empty())
                return fail("an enum needs a name or a body");
            out = t_base("enum " + name);
            return true;
        }
        i++;
        if (name.empty())
            name = anon_name();
        ctype_def d;
        d.k = ctype_def::kind::enum_;
        d.name = name;
        d.size = d.align = size;
        int64_t next = 0;
        while (!accept("}")) {
            if (cur().kind != tok::k::id)
                return fail("expected a name in the enum" + where());
            std::string v = cur().s;
            i++;
            if (accept("=") && !cexpr(next))
                return false;
            d.values.push_back({v, next});
            constants[v] = next;
            next = (int64_t)((uint64_t)next + 1);
            if (!accept(",") && !at("}"))
                return fail("expected , or } in the enum" + where());
            if (d.values.size() > 100000)
                return fail("too many values");
        }
        define(d);
        out = t_base("enum " + name);
        return skip_attributes();
    }

    // a declarator over base: pointers, the name (or none), arrays, a function's parameters. a
    // parenthesized part (int (*f)(int)) applies over what follows it
    bool declarator(tp base, tp& out, std::string& name)
    {
        if (++depth > 64)
            return fail("a declarator too deep");
        if (!skip_attributes())
            return false;
        while (at("*") || at("&") || at("^")) {
            i++;
            base = t_wrap(ctype_node::k::ptr, base);
            if (!skip_attributes())
                return false;
        }
        size_t inner = 0;
        const tok& nx = t[i + 1 < t.size() ? i + 1 : i];
        uint32_t sz;
        bool paren = at("(") && (nx.kind == tok::k::punct ? (nx.s == "*" || nx.s == "^" || nx.s == "&" || nx.s == "(")
                                                           : nx.kind == tok::k::id && (is_qualifier(nx.s) || nx.s == "__attribute__"));
        // typedef PVOID (NAME)(PVOID): a name in parentheses, not a parameter list
        if (at("(") && nx.kind == tok::k::id && i + 2 < t.size() && t[i + 2].kind == tok::k::punct && t[i + 2].s == ")" &&
            !is_scalar_word(nx.s) && !lib.find(nx.s) && !lib.scalar(nx.s, sz))
            paren = true;
        if (paren) {
            inner = ++i;
            int d = 1;
            while (d > 0 && cur().kind != tok::k::end) {
                if (at("("))
                    d++;
                else if (at(")"))
                    d--;
                i++;
            }
            if (d)
                return fail("a ( without its )");
        } else if (cur().kind == tok::k::id && !is_qualifier(cur().s)) {
            name = cur().s;
            i++;
        }
        std::vector<uint64_t> dims;
        bool fn = false;
        std::string params;
        for (;;) {
            if (accept("[")) {
                int64_t n = 0;
                if (!at("]") && !cexpr(n))
                    return false;
                if (n < 0 || n > 0x10000000)
                    return fail("an array of " + std::to_string(n) + " elements");
                dims.push_back((uint64_t)n);
                if (!expect("]"))
                    return false;
            } else if (at("(") && !fn) {
                size_t from = i + 1;
                skip_balanced(); // parameters: kept as text, to lay out a pointer to a function they don't matter
                for (size_t k = from; k + 1 < i; k++) {
                    const std::string &w = t[k].s, &prev = t[k - 1].s;
                    bool tight = k == from || w == "," || w == ")" || w == "]" || w == "*" || w == "[" ||
                                 prev == "(" || prev == "[" || (w == "(" && prev == ")") || (w == "." && prev == ".") ||
                                 (prev == "*" && (t[k - 2].s == "(" || t[k - 2].s == "*"));
                    params += (tight ? "" : " ") + w;
                    if (w == ",")
                        params += " ";
                }
                for (size_t k; (k = params.find("  ")) != std::string::npos;)
                    params.erase(k, 1);
                fn = true;
            } else {
                break;
            }
        }
        if (fn) {
            auto f = std::make_shared<ctype_node>();
            f->kind = ctype_node::k::fn;
            f->of = base;
            f->base = params;
            base = f;
        }
        for (size_t k = dims.size(); k-- > 0;)
            base = t_wrap(ctype_node::k::arr, base, dims[k]);
        if (inner) {
            size_t end = i;
            i = inner;
            tp t2;
            if (!declarator(base, t2, name) || !expect(")"))
                return false;
            i = end;
            base = t2;
        }
        depth--;
        out = base;
        return skip_attributes();
    }

    // a type without a name: "struct node*", "char[16]", "int (*)(int)"
    bool type_name(tp& out)
    {
        tp base;
        std::string name;
        if (!specifier(base) || !declarator(base, out, name))
            return false;
        if (!name.empty())
            return fail("a type, not a declaration of " + name);
        return true;
    }

    bool layout(const tp& ty, uint32_t& size, uint32_t& align)
    {
        std::string e;
        if (lib.layout_node(ty, size, align, e))
            return true;
        return fail(e);
    }

    void define(const ctype_def& d)
    {
        if (readonly)
            return;
        lib.defs_[d.name] = d;
        if (std::find(lib.order_.begin(), lib.order_.end(), d.name) == lib.order_.end())
            lib.order_.push_back(d.name);
        added.push_back(d.name);
    }

    // struct x / union x, not defined (yet): a pointer to it works, and x names it
    void forward(const tp& ty)
    {
        if (readonly || !ty || ty->kind != ctype_node::k::base)
            return;
        bool un = ty->base.compare(0, 6, "union ") == 0;
        if (!un && ty->base.compare(0, 7, "struct ") != 0)
            return;
        std::string name = ty->base.substr(un ? 6 : 7);
        if (lib.defs_.count(name))
            return;
        ctype_def d;
        d.k = un ? ctype_def::kind::union_ : ctype_def::kind::struct_;
        d.name = name;
        d.incomplete = true;
        define(d);
    }

    // an anonymous struct a typedef names takes that name: typedef struct { ... } point
    void adopt(const std::string& from, const std::string& to)
    {
        if (readonly || lib.defs_.count(to))
            return;
        auto it = lib.defs_.find(from);
        if (it == lib.defs_.end())
            return;
        ctype_def d = it->second;
        d.name = to;
        lib.defs_.erase(it);
        lib.defs_[to] = d;
        std::replace(lib.order_.begin(), lib.order_.end(), from, to);
        std::replace(added.begin(), added.end(), from, to);
    }

    bool declaration()
    {
        do_pragmas();
        if (cur().kind == tok::k::end || accept(";"))
            return true;
        // extern "C" { ... }: what's inside counts, the braces don't
        if (at_id("extern") && t[i + 1].kind == tok::k::punct && t[i + 1].s == "\"") {
            for (i += 2; cur().kind != tok::k::end && !at("\""); i++)
                ;
            accept("\"");
            if (accept("{")) {
                linkage++;
                return true;
            }
        }
        if (linkage && accept("}")) {
            linkage--;
            return true;
        }
        if (!skip_attributes()) // __extension__ typedef ...
            return false;
        bool td = false;
        if (at_id("typedef")) {
            td = true;
            i++;
        }
        tp base;
        if (!specifier(base))
            return false;
        if (accept(";")) {
            forward(base); // struct x; declares it, struct x { ... }; defined it already
            return true;
        }
        bool first = true;
        uint32_t sz0 = 0;
        for (;;) {
            std::string name;
            tp ty;
            mode = 0;
            if (!declarator(base, ty, name) || !skip_attributes())
                return false;
            if (mode && ty->kind == ctype_node::k::base && lib.scalar(ty->base, sz0)) {
                bool u = ty->base.compare(0, 9, "unsigned ") == 0;
                const char* w = mode == 1 ? "char" : mode == 2 ? "short" : mode == 4 ? "int" : mode == 8 ? "long long" : "__int128";
                ty = t_base(u ? std::string("unsigned ") + w : mode == 1 ? std::string("signed char") : std::string(w));
            }
            if (!td && first && ty && ty->kind == ctype_node::k::fn && at("{")) {
                skip_balanced(); // a function's definition (static inline in a header)
                return true;
            }
            if (td) {
                if (name.empty())
                    return fail("a typedef without a name");
                size_t sp = base->kind == ctype_node::k::base ? base->base.find(" __anon_") : std::string::npos;
                if (first && sp != std::string::npos && ty == base) {
                    std::string kw = base->base.substr(0, sp + 1);
                    adopt(base->base.substr(sp + 1), name);
                    base = t_base(kw + name);
                } else if (ty->kind == ctype_node::k::base &&
                           (ty->base == "struct " + name || ty->base == "union " + name || ty->base == "enum " + name)) {
                    forward(ty); // typedef struct node node: the struct has the name, maybe defined later
                } else {
                    ctype_def d; // typedef struct node node is no typedef: the struct has the name
                    d.k = ctype_def::kind::typedef_;
                    d.name = name;
                    d.target = type_text(ty);
                    std::string e;
                    uint32_t sz = 0, al = 1;
                    if (lib.layout_node(ty, sz, al, e)) {
                        d.size = sz;
                        d.align = al;
                    }
                    define(d);
                }
            }
            first = false;
            if (at("=")) { // a variable with an initializer: skipped
                while (!at(",") && !at(";") && cur().kind != tok::k::end) {
                    if (at("{") || at("("))
                        skip_balanced();
                    else
                        i++;
                }
            }
            if (accept(","))
                continue;
            return expect(";");
        }
    }

    // lenient: a declaration it can't read is skipped (up to its ;), counted in skipped
    bool run(const std::string& text, bool lenient = false)
    {
        if (!tokenize(text, t, err))
            return false;
        while (cur().kind != tok::k::end) {
            size_t from = i, mark = added.size();
            placeholders.clear();
            if (declaration())
                continue;
            if (!lenient)
                return false;
            if (!skipped++)
                first_err = err;
            err.clear();
            depth = 0;
            linkage = 0;
            for (const std::string& n : placeholders) // a struct it was in the middle of
                if (std::find(added.begin() + (std::ptrdiff_t)mark, added.end(), n) == added.end())
                    lib.defs_.erase(n);
            i = from;
            for (int d = 0; cur().kind != tok::k::end; i++) {
                if (at("{") || at("(") || at("["))
                    d++;
                else if ((at("}") || at(")") || at("]")) && d > 0)
                    d--;
                else if (at(";") && d == 0) {
                    i++;
                    break;
                }
            }
        }
        return true;
    }
};

// ---- types as trees

ctypes::node ctypes::parse_type(const std::string& text, std::string& err) const
{
    // what parses once parses the same later (a name in it is looked up when it's laid out), so
    // only that is kept: a type that isn't known yet may be defined by the next declaration
    auto c = cache_.find(text);
    if (c != cache_.end())
        return c->second;
    ctype_parser p(const_cast<ctypes&>(*this));
    p.readonly = true;
    int anon = anon_;
    tp out;
    bool ok = tokenize(text, p.t, p.err) && p.type_name(out) && p.cur().kind == tok::k::end;
    const_cast<ctypes*>(this)->anon_ = anon;
    if (!ok) {
        err = p.err.empty() ? "not a type: " + text : p.err;
        return nullptr;
    }
    if (cache_.size() > (1u << 16))
        cache_.clear();
    cache_[text] = out;
    return out;
}

std::string ctypes::base_of(const std::string& type, bool& pointer) const
{
    std::string e;
    node t = parse_type(type, e);
    pointer = false;
    for (; t && t->kind != ctype_node::k::base; t = t->of)
        pointer = pointer || t->kind == ctype_node::k::ptr || t->kind == ctype_node::k::fn;
    return t ? t->base : std::string();
}

bool ctypes::layout_node(const node& ty, uint32_t& size, uint32_t& align, std::string& err, int depth) const
{
    if (!ty) {
        err = "no type";
        return false;
    }
    if (depth > 64) {
        err = "a type that contains itself";
        return false;
    }
    switch (ty->kind) {
    case ctype_node::k::ptr:
        size = align = (uint32_t)ptr_;
        return true;
    case ctype_node::k::fn:
        err = "a function isn't a member (a pointer to one is)";
        return false;
    case ctype_node::k::arr: {
        uint32_t es = 0, ea = 1;
        if (!layout_node(ty->of, es, ea, err, depth + 1))
            return false;
        uint64_t total = (uint64_t)es * ty->n;
        if (total > 0x7fffffff) {
            err = "an array that big";
            return false;
        }
        size = (uint32_t)total;
        align = ea;
        return true;
    }
    case ctype_node::k::base:
        break;
    }
    const std::string& b = ty->base;
    uint32_t s = 0;
    if (scalar(b, s)) {
        size = s;
        align = s ? std::min<uint32_t>(s, 16) : 1;
        if (b == "long double") { // msvc and apple arm64: a double; i386 sysv: 12 bytes, 4-aligned
            size = short_ld_ ? 8 : ptr_ == 4 ? 12 : 16;
            align = short_ld_ ? 8 : ptr_ == 4 ? 4 : 16;
        } else if (b == "va_list" || b == "__builtin_va_list") {
            align = (uint32_t)ptr_;
        } else if (ptr_ == 4 && !win_ && s == 8) {
            align = 4; // i386 sysv: 8-byte scalars are 4-aligned in structs
        }
        return true;
    }
    const ctype_def* d = find(b);
    if (!d) {
        err = "unknown type '" + b + "'";
        return false;
    }
    if (d->incomplete) {
        err = "'" + b + "' is only declared, not defined";
        return false;
    }
    if (d->k == ctype_def::kind::typedef_)
        return layout_node(parse_type(d->target, err), size, align, err, depth + 1);
    size = d->size;
    align = d->align;
    return true;
}

ctypes::node ctypes::strip(node t) const
{
    for (int k = 0; t && t->kind == ctype_node::k::base && k < 32; k++) {
        const ctype_def* d = find(t->base);
        if (!d || d->k != ctype_def::kind::typedef_)
            break;
        std::string e;
        t = parse_type(d->target, e);
    }
    return t;
}

// ---- the public side

bool ctypes::add(const std::string& text, std::string& err, std::vector<std::string>* names, bool lenient)
{
    ctypes next = *this;
    ctype_parser p(next);
    err.clear();
    if (!p.run(text, lenient)) {
        err = p.err;
        return false;
    }
    // what's used by value must be defined by now (a pointer to one defined later is fine).
    // lenient: what isn't goes (and then what used it by value)
    for (bool again = true; again;) {
        again = false;
        for (const std::string& n : p.added) {
            auto it = next.defs_.find(n);
            if (it == next.defs_.end())
                continue;
            const ctype_def& d = it->second;
            for (const ctype_field& f : d.fields) {
                uint32_t sz, al;
                std::string e;
                if (next.layout_node(next.parse_type(f.type, e), sz, al, e))
                    continue;
                e = (d.name.compare(0, 7, "__anon_") == 0 ? std::string() : d.name + ".") + f.name + ": " + e;
                if (!lenient) {
                    err = e;
                    return false;
                }
                if (!p.skipped++)
                    p.first_err = e;
                next.remove(n);
                again = true;
                break;
            }
        }
    }
    if (p.skipped)
        err = util::fmt("skipped %d declaration%s it couldn't read (the first: %s)", p.skipped, p.skipped == 1 ? "" : "s",
                        p.first_err.c_str());
    // a typedef made before its struct was defined (typedef struct _IO_FILE FILE) has its size now
    for (auto& d : next.defs_)
        if (d.second.k == ctype_def::kind::typedef_) {
            std::string e;
            uint32_t sz = 0, al = 1;
            if (!next.layout_node(next.parse_type(d.second.target, e), sz, al, e))
                sz = 0, al = 1;
            d.second.size = sz;
            d.second.align = al;
        }
    *this = next;
    if (names) {
        names->clear();
        for (const std::string& n : p.added)
            if (n.compare(0, 7, "__anon_") != 0 && defs_.count(n) && std::find(names->begin(), names->end(), n) == names->end())
                names->push_back(n);
    }
    return true;
}

bool ctypes::remove(const std::string& name)
{
    const ctype_def* d = find(name);
    if (!d)
        return false;
    std::string n = d->name;
    defs_.erase(n);
    order_.erase(std::remove(order_.begin(), order_.end(), n), order_.end());
    return true;
}

void ctypes::clear()
{
    defs_.clear();
    order_.clear();
    cache_.clear();
}

const ctype_def* ctypes::find(const std::string& name) const
{
    std::string n = util::trim(name);
    for (const char* kw : {"struct ", "union ", "enum ", "class "})
        if (n.compare(0, strlen(kw), kw) == 0) {
            n = util::trim(n.substr(strlen(kw)));
            break;
        }
    auto it = defs_.find(n);
    return it == defs_.end() ? nullptr : &it->second;
}

std::string ctypes::normalize(const std::string& type)
{
    std::string out, s = util::trim(type);
    size_t i = 0;
    while (i < s.size()) {
        if (id_start(s[i])) {
            size_t e = i;
            while (e < s.size() && id_char(s[e]))
                e++;
            std::string w = s.substr(i, e - i);
            i = e;
            if (w == "const" || w == "volatile" || w == "restrict" || w == "__restrict")
                continue;
            if (!out.empty() && id_char(out.back()))
                out += ' ';
            out += w;
        } else if (s[i] == ' ' || s[i] == '\t') {
            i++;
        } else {
            if (s[i] == '(' && !out.empty() && id_char(out.back()))
                out += ' ';
            out += s[i++];
        }
    }
    return out;
}

bool ctypes::layout(const std::string& type, uint32_t& size, uint32_t& align) const
{
    std::string e;
    return layout_node(parse_type(normalize(type), e), size, align, e);
}

const ctype_def* ctypes::aggregate(const std::string& type) const
{
    std::string e;
    node t = strip(parse_type(normalize(type), e));
    if (!t || t->kind != ctype_node::k::base)
        return nullptr;
    const ctype_def* d = find(t->base);
    return d && (d->k == ctype_def::kind::struct_ || d->k == ctype_def::kind::union_) ? d : nullptr;
}

const ctype_def* ctypes::pointee(const std::string& type) const
{
    std::string e;
    node t = strip(parse_type(normalize(type), e));
    if (!t || t->kind != ctype_node::k::ptr)
        return nullptr;
    t = strip(t->of);
    if (!t || t->kind != ctype_node::k::base)
        return nullptr;
    const ctype_def* d = find(t->base);
    return d && (d->k == ctype_def::kind::struct_ || d->k == ctype_def::kind::union_) ? d : nullptr;
}

uint32_t ctypes::scalar_pointee(const std::string& type) const
{
    std::string n = normalize(type), e;
    if (uint32_t k = named_pointer_target(n))
        return k;
    node t = strip(parse_type(n, e));
    if (!t || t->kind != ctype_node::k::ptr)
        return 0;
    t = strip(t->of);
    if (!t || t->kind != ctype_node::k::base)
        return 0; // a pointer to a pointer, an array, a function
    const ctype_def* d = find(t->base);
    if (d && d->k != ctype_def::kind::enum_)
        return 0; // a struct: pointee() is the one for that
    uint32_t sz = 0, al = 0;
    return layout_node(t, sz, al, e) ? sz : 0;
}

bool ctypes::member_at(const ctype_def& s, uint64_t off, int width, std::string& path, std::string& type,
                       const std::string& index, uint32_t scale) const
{
    // in a union, the member the size of the read; else the one that holds the offset
    const ctype_field* best = nullptr;
    for (const ctype_field& f : s.fields) {
        if (f.bitfield || off < f.offset || off >= (uint64_t)f.offset + std::max<uint32_t>(f.size, 1))
            continue;
        if (!best)
            best = &f;
        if (s.k != ctype_def::kind::union_)
            break;
        if (width && f.size == (uint32_t)width && off == f.offset) {
            best = &f;
            break;
        }
    }
    if (!best)
        return false;
    const ctype_field& f = *best;
    uint64_t rel = off - f.offset;
    std::string e;
    node ft = strip(parse_type(f.type, e));
    if (!ft)
        return false;
    if (ft->kind == ctype_node::k::arr) {
        uint32_t es = 0, ea = 0;
        node et = strip(ft->of);
        if (!et || !layout_node(et, es, ea, e) || es == 0)
            return false;
        std::string ix;
        uint64_t in = rel % es;
        if (!index.empty()) {
            if (scale != es || rel >= es)
                return false;
            ix = index; // base + i * size: element i
        } else {
            ix = std::to_string(rel / es);
        }
        std::string here = f.name + "[" + ix + "]";
        const ctype_def* sub = et->kind == ctype_node::k::base ? find(et->base) : nullptr;
        if (sub && (sub->k == ctype_def::kind::struct_ || sub->k == ctype_def::kind::union_) &&
            !(in == 0 && (width == 0 || (uint32_t)width == es))) {
            std::string p2, t2;
            if (!member_at(*sub, in, width, p2, t2))
                return false;
            path = here + "." + p2;
            type = t2;
            return true;
        }
        if (in != 0 || (width && (uint32_t)width != es))
            return false;
        path = here;
        type = type_text(et);
        return true;
    }
    if (!index.empty())
        return false;
    const ctype_def* sub = ft->kind == ctype_node::k::base ? find(ft->base) : nullptr;
    if (sub && (sub->k == ctype_def::kind::struct_ || sub->k == ctype_def::kind::union_)) {
        if (rel == 0 && !f.name.empty() && (width == 0 || (uint32_t)width == sub->size)) {
            path = f.name;
            type = type_text(ft);
            return true;
        }
        std::string p2, t2;
        if (!member_at(*sub, rel, width, p2, t2))
            return false;
        path = f.name.empty() ? p2 : f.name + "." + p2;
        type = t2;
        return true;
    }
    if (rel != 0 || f.name.empty() || (width && (uint32_t)width != f.size))
        return false;
    path = f.name;
    type = type_text(ft);
    return true;
}

std::string ctypes::decl_text(const node& t, const std::string& name, int indent, bool offsets, uint32_t base) const
{
    std::string decl = to_text(t, name);
    node b = t;
    bool by_value = true;
    for (; b->kind != ctype_node::k::base; b = b->of)
        by_value = by_value && b->kind != ctype_node::k::ptr;
    const ctype_def* sub = b->base.find(" __anon_") != std::string::npos ? find(b->base) : nullptr;
    if (!sub)
        return decl;
    // a struct, union or enum without a name, written where it's used: union { ... } d_un
    std::string body;
    if (sub->k == ctype_def::kind::enum_) {
        body = "enum {";
        for (size_t k = 0; k < sub->values.size(); k++)
            body += (k ? ", " : " ") + sub->values[k].first + " = " + std::to_string(sub->values[k].second);
        body += " }";
    } else {
        body = sub->k == ctype_def::kind::union_ ? "union {\n" : "struct {\n";
        write_fields(*sub, body, indent + 1, offsets && by_value, base);
        body += std::string((size_t)indent * 4, ' ') + "}";
    }
    return body + decl.substr(b->base.size());
}

void ctypes::write_fields(const ctype_def& d, std::string& s, int indent, bool offsets, uint32_t base) const
{
    std::string pad((size_t)indent * 4, ' ');
    for (const ctype_field& f : d.fields) {
        std::string e;
        node t = parse_type(f.type, e);
        const ctype_def* sub = f.name.empty() && t && t->kind == ctype_node::k::base ? find(t->base) : nullptr;
        if (sub) { // an anonymous member, written in place
            s += pad + (sub->k == ctype_def::kind::union_ ? "union {\n" : "struct {\n");
            write_fields(*sub, s, indent + 1, offsets, base + f.offset);
            s += pad + "};\n";
            continue;
        }
        std::string line = pad + (t ? decl_text(t, f.name, indent, offsets, base + f.offset) : f.type + " " + f.name);
        if (f.bitfield)
            line += " : " + std::to_string(f.bits);
        line += ";";
        if (offsets) {
            line.resize(std::max<size_t>(line.size() + 1, 40), ' ');
            line += f.bitfield ? util::fmt("// 0x%x, bit %u", base + f.offset, f.bit_offset) : util::fmt("// 0x%x", base + f.offset);
        }
        s += line + "\n";
    }
}

std::string ctypes::text(const ctype_def& d, bool offsets) const
{
    if (d.k == ctype_def::kind::typedef_) {
        std::string e;
        node t = parse_type(d.target, e);
        return "typedef " + (t ? decl_text(t, d.name, 0, offsets, 0) : d.target + " " + d.name) + ";";
    }
    if (d.k == ctype_def::kind::enum_) {
        std::string s = "enum " + d.name + " {";
        for (size_t k = 0; k < d.values.size(); k++)
            s += (k ? ", " : " ") + d.values[k].first + " = " + std::to_string(d.values[k].second);
        return s + (d.values.empty() ? "};" : " };");
    }
    if (d.incomplete)
        return std::string(d.k == ctype_def::kind::union_ ? "union " : "struct ") + d.name + ";";
    std::string s;
    if (d.pack)
        s += util::fmt("#pragma pack(push, %u)\n", d.pack);
    s += std::string(d.k == ctype_def::kind::union_ ? "union " : "struct ") + d.name + " {";
    if (offsets)
        s += util::fmt(" // 0x%x bytes", d.size);
    s += "\n";
    write_fields(d, s, 1, offsets, 0);
    s += "}";
    if (d.packed)
        s += " __attribute__((packed))";
    if (d.aligned)
        s += util::fmt(" __attribute__((aligned(%u)))", d.aligned);
    s += ";";
    if (d.pack)
        s += "\n#pragma pack(pop)";
    return s;
}

std::string ctypes::all_text(bool offsets) const
{
    std::string s;
    for (const std::string& t : texts(offsets))
        s += t + (offsets ? "\n\n" : "\n");
    return s;
}

std::vector<std::string> ctypes::order() const
{
    std::vector<std::string> names;
    texts(false, &names, true);
    return names;
}

std::vector<std::string> ctypes::texts(bool offsets, std::vector<std::string>* names) const
{
    return texts(offsets, names, false);
}

std::vector<std::string> ctypes::texts(bool offsets, std::vector<std::string>* names, bool names_only) const
{
    // what a definition holds by value comes before it, and a typedef's name before its first
    // use, so the text reads back in one go. complete: needed by value (a typedef then needs
    // its struct too; typedef struct x y alone doesn't)
    std::vector<std::string> out;
    std::map<std::string, int> state; // 1 on the way, 2 written
    std::set<std::string> declared;   // struct x; written ahead
    std::function<void(const std::string&, bool)> visit = [&](const std::string& n, bool complete) {
        auto it = defs_.find(n);
        if (it == defs_.end() || state[n] == 1)
            return;
        const ctype_def& d = it->second;
        bool td = d.k == ctype_def::kind::typedef_;
        if (state[n] == 2 && !(td && complete))
            return;
        bool first = !state[n];
        state[n] = 1;
        std::vector<std::string> types;
        for (const ctype_field& f : d.fields)
            types.push_back(f.type);
        if (td)
            types.push_back(d.target);
        for (const std::string& ty : types) {
            std::string e;
            node t = parse_type(ty, e);
            bool by_value = !td || complete;
            while (t && t->kind != ctype_node::k::base) {
                by_value = by_value && t->kind == ctype_node::k::arr;
                t = t->of;
            }
            bool tag = t && (t->base.compare(0, 7, "struct ") == 0 || t->base.compare(0, 6, "union ") == 0);
            const ctype_def* dep = t && (by_value || !tag) ? find(t->base) : nullptr;
            if (dep && !by_value && dep->k != ctype_def::kind::typedef_ && dep->k != ctype_def::kind::enum_) {
                // a struct by its bare name through a pointer (c++ style): declared is enough
                if (!state[dep->name] && !declared.count(dep->name) && dep->name.compare(0, 7, "__anon_") != 0) {
                    declared.insert(dep->name);
                    if (!names_only) {
                        out.push_back(std::string(dep->k == ctype_def::kind::union_ ? "union " : "struct ") + dep->name + ";");
                        if (names)
                            names->push_back(dep->name);
                    }
                }
            } else if (dep) {
                visit(dep->name, by_value);
            }
        }
        state[n] = 2;
        if (first && n.compare(0, 7, "__anon_") != 0) { // an anonymous one is written where it's used
            if (!names_only)
                out.push_back(text(d, offsets));
            if (names)
                names->push_back(n);
        }
    };
    for (const std::string& n : order_)
        visit(n, false);
    return out;
}
