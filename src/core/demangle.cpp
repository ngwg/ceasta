#include "core/demangle.h"
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <memory>
#include <string>
#include <vector>

// hand-written demanglers for the common schemes. each is strict: it returns a string only when
// it understood the whole symbol, otherwise "" and the caller keeps the raw one. a wrong name is
// worse than a mangled one, so anything unexpected bails. the itanium part follows the algorithm
// of llvm's demangler (the one lldb, xcode and llvm-objdump use) and prints what it prints.
//
// the input comes from files ceasta opens, some of them hostile: recursion depth and the size of
// everything built are capped, so a crafted symbol can't blow the stack or the memory.

namespace demangle {

namespace {

const size_t max_input = 4096;   // longer symbols are left alone
const size_t max_out = 8192;     // any piece growing past this gives up
const int max_depth = 256;

bool is_digit(char c) { return c >= '0' && c <= '9'; }
bool is_lower(char c) { return c >= 'a' && c <= 'z'; }
bool is_upper(char c) { return c >= 'A' && c <= 'Z'; }

// an array's "[n]" is written with a space before it, except right after another "]"
std::string cat(const std::string& a, const std::string& b)
{
    if (!b.empty() && b[0] == '[' && !a.empty() && a.back() != ']')
        return a + " " + b;
    return a + b;
}

// ---------------------------------------------------------------- itanium (gcc / clang)

// a printed node, split the way c declarators need: a pointer to a function is
// left "int (*" + right ")(char)"
struct ty {
    std::string left, right;
    std::string base;          // what a constructor of this is called ("vector" for std::vector<int>)
    char special = 0;          // an unexpanded std:: abbreviation (Sa Sb Ss Si So Sd)
    bool fn = false;           // a function type: a pointer to it needs parens
    bool arr = false;          // an array type: likewise
    int refk = 0;              // a reference: 1 lvalue, 2 rvalue (for reference collapsing)
    std::vector<ty> pointee;   // what the reference refers to
    bool empty = false;        // an expansion of an empty pack: prints as nothing
    bool pack = false;         // a template argument pack (elements joined in elems)
    std::vector<ty> elems;

    std::string str() const { return cat(left, right); }
};

ty name_ty(const std::string& s)
{
    ty t;
    t.left = s;
    t.base = s;
    return t;
}

// printed like a name, but with no base name (unnamed types, lambdas, conversion operators)
ty plain_ty(const std::string& s)
{
    ty t;
    t.left = s;
    return t;
}

struct itanium {
    const char* s;
    size_t n;
    size_t i = 0;
    bool fail = false;
    int depth = 0;

    // the substitution table. an entry printed while expanding a pack holds one element of it
    // (dep): used again inside another expansion it's re-read from its place in the symbol
    // (start..end) for the element being printed; used anywhere else it can't be printed
    struct sub_entry {
        ty t;
        bool dep = false;
        bool rangeable = false;
        size_t start = 0, end = 0;
    };
    std::vector<sub_entry> subs;
    size_t pack_uses = 0;          // how many times a pack element was printed so far

    // template parameters in scope (T_, T0_ ...), and whether a list is bound at all
    std::vector<ty> tparams;
    bool tparams_ok = false;

    // pack expansion: printing element `index` of the pack a T_ inside refers to
    struct pack_state {
        bool active = false;
        size_t index = 0;
        bool max_set = false;
        size_t max = 0;
        bool no_subs = false;      // re-printing: add nothing to the table
    } pk;

    bool try_tpl_args = true;      // off while parsing a conversion operator's type
    bool lambda_params = false;    // in a generic lambda's parameters an unbound T_ is "auto"

    struct state {
        unsigned cv = 0;           // 1 const, 2 volatile, 4 restrict
        int ref = 0;               // 1 &, 2 &&
        bool ends_tpl = false;
        bool ctor_dtor_conv = false;
    };

    itanium(const char* p, size_t len) : s(p), n(len) {}

    struct deeper {
        itanium& p;
        explicit deeper(itanium& p_) : p(p_)
        {
            if (++p.depth > max_depth)
                p.fail = true;
        }
        ~deeper() { --p.depth; }
    };

    char peek(size_t k = 0) const { return i + k < n ? s[i + k] : 0; }
    bool eat(char c)
    {
        if (i < n && s[i] == c) {
            i++;
            return true;
        }
        return false;
    }
    bool eat(const char* lit)
    {
        size_t len = strlen(lit);
        if (i + len <= n && memcmp(s + i, lit, len) == 0) {
            i += len;
            return true;
        }
        return false;
    }
    bool bad()
    {
        fail = true;
        return false;
    }
    bool too_big(const ty& t)
    {
        if (t.left.size() + t.right.size() > max_out)
            fail = true;
        return fail;
    }

    // start / uses: where the construct began and pack_uses then. rangeable: start..i is a
    // <type> that can be parsed again on its own
    void add_sub(const ty& t, size_t start, size_t uses, bool rangeable)
    {
        if (pk.no_subs)
            return;
        if (subs.size() > 4096) {
            fail = true;
            return;
        }
        sub_entry e;
        e.t = t;
        e.dep = pack_uses > uses;
        e.rangeable = rangeable;
        e.start = start;
        e.end = i;
        subs.push_back(e);
    }

    // prints a pack-dependent substitution again for the pack element being printed now
    ty rerender(const sub_entry& e)
    {
        if (!e.rangeable || !pk.active)
            return fail = true, ty();
        size_t save_i = i, save_n = n;
        bool save_no = pk.no_subs;
        i = e.start;
        n = e.end;
        pk.no_subs = true;
        ty t = type();
        bool ok = !fail && i == e.end;
        i = save_i;
        n = save_n;
        pk.no_subs = save_no;
        if (!ok)
            return fail = true, ty();
        return t;
    }

    // <number>: returned as text so an __int128 literal stays exact. "" when there's none
    std::string number(bool neg_ok)
    {
        size_t start = i;
        if (neg_ok)
            eat('n');
        if (!is_digit(peek())) {
            i = start;
            return "";
        }
        while (is_digit(peek()))
            i++;
        return std::string(s + start, i - start);
    }
    bool positive(size_t& out)
    {
        if (!is_digit(peek()))
            return false;
        size_t v = 0;
        while (is_digit(peek())) {
            v = v * 10 + (size_t)(s[i] - '0');
            if (v > n)
                return false;
            i++;
        }
        out = v;
        return true;
    }
    // a literal's value: "n5" -> "-5"
    static std::string num_text(const std::string& v) { return !v.empty() && v[0] == 'n' ? "-" + v.substr(1) : v; }

    // ------------------------------------------------------------- names

    ty source_name()
    {
        size_t len = 0;
        if (!positive(len) || len == 0 || i + len > n) {
            fail = true;
            return ty();
        }
        std::string r(s + i, len);
        i += len;
        if (r.compare(0, 10, "_GLOBAL__N") == 0)
            return name_ty("(anonymous namespace)");
        return name_ty(r);
    }

    ty abi_tags(ty t)
    {
        while (!fail && eat('B')) {
            ty tag = source_name();
            if (fail)
                break;
            t.left += "[abi:" + tag.left + "]";
            t.special = 0;
        }
        return t;
    }

    // <operator-name>
    ty operator_name(state* st)
    {
        static const struct {
            const char* code;
            const char* name;
        } ops[] = {
            {"aN", "operator&="}, {"aS", "operator="}, {"aa", "operator&&"}, {"ad", "operator&"},
            {"an", "operator&"}, {"aw", "operator co_await"}, {"cl", "operator()"}, {"cm", "operator,"},
            {"co", "operator~"}, {"dV", "operator/="}, {"da", "operator delete[]"}, {"de", "operator*"},
            {"dl", "operator delete"}, {"dv", "operator/"}, {"eO", "operator^="}, {"eo", "operator^"},
            {"eq", "operator=="}, {"ge", "operator>="}, {"gt", "operator>"}, {"ix", "operator[]"},
            {"lS", "operator<<="}, {"le", "operator<="}, {"ls", "operator<<"}, {"lt", "operator<"},
            {"mI", "operator-="}, {"mL", "operator*="}, {"mi", "operator-"}, {"ml", "operator*"},
            {"mm", "operator--"}, {"na", "operator new[]"}, {"ne", "operator!="}, {"ng", "operator-"},
            {"nt", "operator!"}, {"nw", "operator new"}, {"oR", "operator|="}, {"oo", "operator||"},
            {"or", "operator|"}, {"pL", "operator+="}, {"pl", "operator+"}, {"pm", "operator->*"},
            {"pp", "operator++"}, {"ps", "operator+"}, {"pt", "operator->"}, {"qu", "operator?"},
            {"rM", "operator%="}, {"rS", "operator>>="}, {"rm", "operator%"}, {"rs", "operator>>"},
            {"ss", "operator<=>"},
        };
        char a = peek(), b = peek(1);
        for (const auto& o : ops)
            if (o.code[0] == a && o.code[1] == b) {
                i += 2;
                return name_ty(o.name);
            }
        if (a == 'c' && b == 'v') { // conversion operator: operator int
            i += 2;
            bool save = try_tpl_args;
            try_tpl_args = false;
            ty t = type();
            try_tpl_args = save;
            if (fail)
                return ty();
            if (st)
                st->ctor_dtor_conv = true;
            return plain_ty("operator " + t.str());
        }
        if (a == 'l' && b == 'i') { // literal operator: operator"" _km
            i += 2;
            ty t = source_name();
            if (fail)
                return ty();
            return plain_ty("operator\"\" " + t.left);
        }
        fail = true;
        return ty();
    }

    // Ut / Ul: unnamed types and lambdas
    ty unnamed_type(state* st)
    {
        if (st)
            tparams_ok = false; // the lambda's own parameters don't see the outer ones
        if (eat("Ut")) {
            std::string count = number(false);
            if (!eat('_'))
                return fail = true, ty();
            return plain_ty("'unnamed" + count + "'");
        }
        if (eat("Ul")) {
            std::string params;
            if (!eat("vE")) {
                bool first = true;
                do {
                    bool save = lambda_params;
                    lambda_params = true;
                    ty p = type();
                    lambda_params = save;
                    if (fail)
                        return ty();
                    if (!p.empty) {
                        if (!first)
                            params += ", ";
                        params += p.str();
                        first = false;
                    }
                } while (i < n && peek() != 'E');
                if (!eat('E'))
                    return fail = true, ty();
            }
            std::string count = number(false);
            if (!eat('_'))
                return fail = true, ty();
            return plain_ty("'lambda" + count + "'(" + params + ")");
        }
        if (eat("Ub")) {
            number(false);
            if (!eat('_'))
                return fail = true, ty();
            return plain_ty("'block-literal'");
        }
        fail = true;
        return ty();
    }

    // <ctor-dtor-name>, scope is the class. a std:: abbreviation used as the class is spelled
    // out ("std::basic_string<char, std::char_traits<char>, std::allocator<char>>::basic_string")
    ty ctor_dtor(ty& scope, state* st)
    {
        if (scope.special)
            expand_special(scope);
        if (eat('C')) {
            bool inherited = eat('I');
            char v = peek();
            if (v < '1' || v > '5')
                return fail = true, ty();
            i++;
            if (st)
                st->ctor_dtor_conv = true;
            if (inherited) {
                name(st);
                if (fail)
                    return ty();
            }
            return name_ty(scope.base);
        }
        if (peek() == 'D') {
            char v = peek(1);
            if (v == '0' || v == '1' || v == '2' || v == '4' || v == '5') {
                i += 2;
                if (st)
                    st->ctor_dtor_conv = true;
                return name_ty("~" + scope.base);
            }
        }
        fail = true;
        return ty();
    }

    // <unqualified-name>, composed onto scope when there is one
    ty unqualified_name(state* st, ty* scope)
    {
        deeper d(*this);
        if (peek() == 'W') // c++20 module names: not supported
            return fail = true, ty();
        if (scope && peek() == 'F') // member-like friend
            return fail = true, ty();
        eat('L');
        ty r;
        char c = peek();
        if (is_digit(c) && c != '0') {
            r = source_name();
        } else if (c == 'U') {
            r = unnamed_type(st);
        } else if (eat("DC")) {
            std::string b = "[";
            bool first = true;
            do {
                ty one = source_name();
                if (fail)
                    return ty();
                if (!first)
                    b += ", ";
                b += one.left;
                first = false;
            } while (!eat('E') && !fail && i < n);
            r = plain_ty(b + "]");
        } else if (c == 'C' || c == 'D') {
            if (!scope)
                return fail = true, ty();
            r = ctor_dtor(*scope, st);
        } else {
            r = operator_name(st);
        }
        if (fail)
            return ty();
        r = abi_tags(r);
        if (fail)
            return ty();
        if (scope) {
            ty nested;
            nested.left = scope->str() + "::" + r.left;
            nested.base = r.base;
            too_big(nested);
            return nested;
        }
        return r;
    }

    void expand_special(ty& t)
    {
        switch (t.special) {
        case 'a': t.left = "std::allocator"; t.base = "allocator"; break;
        case 'b': t.left = "std::basic_string"; t.base = "basic_string"; break;
        case 's':
            t.left = "std::basic_string<char, std::char_traits<char>, std::allocator<char>>";
            t.base = "basic_string";
            break;
        case 'i': t.left = "std::basic_istream<char, std::char_traits<char>>"; t.base = "basic_istream"; break;
        case 'o': t.left = "std::basic_ostream<char, std::char_traits<char>>"; t.base = "basic_ostream"; break;
        case 'd': t.left = "std::basic_iostream<char, std::char_traits<char>>"; t.base = "basic_iostream"; break;
        default: break;
        }
        t.special = 0;
    }

    // <substitution>
    ty substitution()
    {
        if (!eat('S'))
            return fail = true, ty();
        char c = peek();
        if (is_lower(c)) {
            ty t;
            switch (c) {
            case 'a': t.left = "std::allocator"; t.base = "allocator"; break;
            case 'b': t.left = "std::basic_string"; t.base = "basic_string"; break;
            case 's': t.left = "std::string"; t.base = "string"; break;
            case 'i': t.left = "std::istream"; t.base = "istream"; break;
            case 'o': t.left = "std::ostream"; t.base = "ostream"; break;
            case 'd': t.left = "std::iostream"; t.base = "iostream"; break;
            default: return fail = true, ty();
            }
            i++;
            t.special = c;
            // abi tags on an abbreviation make a new substitutable component
            if (peek() == 'B') {
                size_t start = i - 2, uses = pack_uses;
                t = abi_tags(t);
                if (fail)
                    return ty();
                add_sub(t, start, uses, false);
            }
            return t;
        }
        size_t index = 0;
        if (eat('_')) {
            index = 0;
        } else {
            if (!is_digit(c) && !is_upper(c))
                return fail = true, ty();
            size_t v = 0;
            while (is_digit(peek()) || is_upper(peek())) {
                v = v * 36 + (size_t)(is_digit(peek()) ? peek() - '0' : peek() - 'A' + 10);
                if (v > 100000)
                    return fail = true, ty();
                i++;
            }
            if (!eat('_'))
                return fail = true, ty();
            index = v + 1;
        }
        if (index >= subs.size())
            return fail = true, ty();
        if (!subs[index].dep)
            return subs[index].t;
        sub_entry e = subs[index]; // rerender may grow the table
        return rerender(e);
    }

    // <template-param>: T_ T0_ T1_ ...
    ty template_param()
    {
        if (!eat('T'))
            return fail = true, ty();
        if (peek() == 'L') // levels (lambdas with template parameters): not supported
            return fail = true, ty();
        size_t index = 0;
        if (!eat('_')) {
            if (!positive(index) || !eat('_'))
                return fail = true, ty();
            index++;
        }
        if (!tparams_ok || index >= tparams.size()) {
            if (lambda_params)
                return name_ty("auto");
            return fail = true, ty();
        }
        const ty& t = tparams[index];
        if (!t.pack)
            return t;
        // a pack: inside an expansion, one element at a time
        if (!pk.active)
            return fail = true, ty();
        if (!pk.max_set) {
            pk.max_set = true;
            pk.max = t.elems.size();
        } else if (pk.max != t.elems.size()) {
            return fail = true, ty();
        }
        pack_uses++;
        if (t.elems.empty()) {
            ty e;
            e.empty = true;
            return e;
        }
        if (pk.index >= t.elems.size())
            return fail = true, ty();
        return t.elems[pk.index];
    }

    // <template-args>: "<int, char>". tag: these are the arguments T_ refers to from here on
    std::string template_args(bool tag)
    {
        deeper d(*this);
        if (!eat('I'))
            return fail = true, "";
        if (tag) {
            tparams.clear();
            tparams_ok = true;
        }
        std::string r = "<";
        bool first = true;
        while (!eat('E')) {
            if (fail || i >= n)
                return fail = true, "";
            ty a = template_arg();
            if (fail)
                return "";
            if (tag)
                tparams.push_back(a);
            std::string text = a.pack ? pack_text(a) : a.str();
            if (!text.empty() || !a.empty) {
                if (!(a.pack && text.empty()) && !a.empty) {
                    if (!first)
                        r += ", ";
                    r += text;
                    first = false;
                }
            }
            if (r.size() > max_out)
                return fail = true, "";
        }
        return r + ">";
    }

    static std::string pack_text(const ty& p)
    {
        std::string r;
        bool first = true;
        for (const ty& e : p.elems) {
            if (e.empty)
                continue;
            if (!first)
                r += ", ";
            r += e.pack ? pack_text(e) : e.str();
            first = false;
        }
        return r;
    }

    ty template_arg()
    {
        deeper d(*this);
        char c = peek();
        if (c == 'X') {
            i++;
            ty e = expression();
            if (fail || !eat('E'))
                return fail = true, ty();
            return e;
        }
        if (c == 'J') {
            i++;
            ty p;
            p.pack = true;
            while (!eat('E')) {
                if (fail || i >= n)
                    return fail = true, ty();
                ty a = template_arg();
                if (fail)
                    return ty();
                p.elems.push_back(a);
            }
            p.left = pack_text(p);
            return p;
        }
        if (c == 'L') {
            if (peek(1) == 'Z') {
                i += 2;
                std::string q;
                std::string e = encoding(q);
                if (fail || !eat('E'))
                    return fail = true, ty();
                return name_ty(e);
            }
            return expr_primary();
        }
        return type();
    }

    // <expression>: only the simple forms seen in template arguments and array bounds. the
    // full grammar (with llvm's operator precedence and parentheses) is not supported
    ty expression()
    {
        deeper d(*this);
        char c = peek();
        if (c == 'T')
            return template_param();
        if (c == 'L')
            return expr_primary();
        if (c == 'a' && peek(1) == 'd') { // &name
            i += 2;
            char k = peek();
            if (k != 'L' && k != 'T')
                return fail = true, ty();
            ty e = expression();
            if (fail)
                return ty();
            return plain_ty("&" + e.str());
        }
        return fail = true, ty();
    }

    // <expr-primary>: literals in template arguments
    ty expr_primary()
    {
        deeper d(*this);
        if (!eat('L'))
            return fail = true, ty();
        static const struct {
            char code;
            const char* type;
        } ints[] = {
            {'w', "wchar_t"}, {'c', "char"}, {'a', "signed char"}, {'h', "unsigned char"}, {'s', "short"},
            {'t', "unsigned short"}, {'i', ""}, {'j', "u"}, {'l', "l"}, {'m', "ul"}, {'x', "ll"},
            {'y', "ull"}, {'n', "__int128"}, {'o', "unsigned __int128"},
        };
        char c = peek();
        for (const auto& e : ints)
            if (c == e.code) {
                i++;
                std::string v = number(true);
                if (v.empty() || !eat('E'))
                    return fail = true, ty();
                std::string t = e.type;
                if (t.size() > 3)
                    return name_ty("(" + t + ")" + num_text(v));
                return name_ty(num_text(v) + t);
            }
        if (c == 'b') {
            if (eat("b0E"))
                return name_ty("false");
            if (eat("b1E"))
                return name_ty("true");
            return fail = true, ty();
        }
        if (c == '_') {
            if (!eat("_Z"))
                return fail = true, ty();
            std::string q;
            std::string e = encoding(q);
            if (fail || !eat('E'))
                return fail = true, ty();
            return name_ty(e);
        }
        if (c == 'A') {
            ty t = type();
            if (fail || !eat('E'))
                return fail = true, ty();
            return name_ty("\"<" + t.str() + ">\"");
        }
        if (c == 'D') {
            if (eat("Dn")) {
                eat('0');
                if (eat('E'))
                    return name_ty("nullptr");
            }
            return fail = true, ty();
        }
        if (c == 'f' || c == 'd' || c == 'e' || c == 'T' || c == 'U') // floats, lambdas
            return fail = true, ty();
        // an enum (or other named type) literal: (Color)2
        ty t = type();
        if (fail)
            return ty();
        std::string v = number(true);
        if (v.empty() || !eat('E'))
            return fail = true, ty();
        return name_ty("(" + t.str() + ")" + num_text(v));
    }

    // <nested-name>: N [cv] [ref] <prefix> <unqualified-name> E
    ty nested_name(state* st)
    {
        deeper d(*this);
        size_t nstart = i, nuses = pack_uses;
        if (!eat('N'))
            return fail = true, ty();
        unsigned cv = 0;
        if (eat('r'))
            cv |= 4;
        if (eat('V'))
            cv |= 2;
        if (eat('K'))
            cv |= 1;
        int ref = 0;
        if (eat('O'))
            ref = 2;
        else if (eat('R'))
            ref = 1;
        if (st) {
            st->cv = cv;
            st->ref = ref;
        }
        ty so_far;
        bool have = false;
        bool last_args = false;
        size_t pushed = 0;
        while (!eat('E')) {
            if (fail || i >= n)
                return fail = true, ty();
            if (st)
                st->ends_tpl = false;
            char c = peek();
            if (c == 'T') {
                if (have)
                    return fail = true, ty();
                so_far = template_param();
                have = true;
                last_args = false;
            } else if (c == 'I') {
                if (!have || last_args)
                    return fail = true, ty();
                std::string args = template_args(st != nullptr);
                if (fail)
                    return ty();
                if (st)
                    st->ends_tpl = true;
                so_far.left += args;
                so_far.special = 0;
                last_args = true;
            } else if (c == 'D' && (peek(1) == 't' || peek(1) == 'T')) {
                return fail = true, ty(); // decltype
            } else if (c == 'S' && peek(1) == 't') {
                if (have)
                    return fail = true, ty();
                i += 2;
                so_far = name_ty("std");
                have = true;
                last_args = false;
                continue; // not a new substitution
            } else if (c == 'S') {
                if (have)
                    return fail = true, ty();
                so_far = substitution();
                if (fail)
                    return ty();
                have = true;
                last_args = false;
                continue; // not a new substitution
            } else {
                so_far = unqualified_name(st, have ? &so_far : nullptr);
                have = true;
                last_args = false;
            }
            if (fail || too_big(so_far))
                return ty();
            add_sub(so_far, nstart, nuses, false);
            pushed++;
            eat('M'); // an old data-member prefix
        }
        if (!have || pushed == 0)
            return fail = true, ty();
        if (!pk.no_subs)
            subs.pop_back();
        return so_far;
    }

    // <discriminator>: _ <digit> | __ <number> _
    void discriminator()
    {
        if (peek() == '_') {
            if (is_digit(peek(1))) {
                i += 2;
            } else if (peek(1) == '_') {
                size_t k = i + 2;
                while (k < n && is_digit(s[k]))
                    k++;
                if (k < n && s[k] == '_')
                    i = k + 1;
            }
        } else if (is_digit(peek())) {
            size_t k = i;
            while (k < n && is_digit(s[k]))
                k++;
            if (k == n)
                i = n;
        }
    }

    // <local-name>: Z <encoding> E <entity> [<discriminator>]
    ty local_name(state* st)
    {
        deeper d(*this);
        if (!eat('Z'))
            return fail = true, ty();
        std::string q;
        std::string enc = encoding(q);
        if (fail || !eat('E'))
            return fail = true, ty();
        if (eat('s')) {
            discriminator();
            ty t = name_ty(enc + "::string literal");
            t.base = "string literal";
            return t;
        }
        // the entity's template parameters are unrelated to the function's
        std::vector<ty> saved = tparams;
        bool saved_ok = tparams_ok;
        tparams.clear();
        tparams_ok = false;
        ty ent;
        if (eat('d')) {
            number(true);
            if (!eat('_'))
                return fail = true, ty();
            ent = name(st);
        } else {
            ent = name(st);
            discriminator();
        }
        tparams = saved;
        tparams_ok = saved_ok;
        if (fail)
            return ty();
        ty t;
        t.left = enc + "::" + ent.str();
        t.base = ent.base;
        too_big(t);
        return t;
    }

    // <unscoped-name>: [St] <unqualified-name> | <substitution>
    ty unscoped_name(state* st, bool* is_subst)
    {
        bool std_ = eat("St");
        if (peek() == 'S') {
            if (std_ || !is_subst)
                return fail = true, ty();
            ty t = substitution();
            *is_subst = true;
            return t;
        }
        if (std_) {
            ty sc = name_ty("std");
            return unqualified_name(st, &sc);
        }
        return unqualified_name(st, nullptr);
    }

    // <name>
    ty name(state* st)
    {
        deeper d(*this);
        size_t start = i, uses = pack_uses;
        if (peek() == 'N')
            return nested_name(st);
        if (peek() == 'Z')
            return local_name(st);
        bool is_subst = false;
        ty r = unscoped_name(st, &is_subst);
        if (fail)
            return ty();
        if (peek() == 'I') {
            if (!is_subst)
                add_sub(r, start, uses, true); // an unscoped template name is substitutable
            std::string args = template_args(st != nullptr);
            if (fail)
                return ty();
            if (st)
                st->ends_tpl = true;
            r.left += args;
            r.special = 0;
        } else if (is_subst) {
            return fail = true, ty();
        }
        return r;
    }

    // ------------------------------------------------------------- types

    ty pointer_like(const ty& inner, const char* op, int refk)
    {
        ty p = inner;
        int kind = refk;
        if (refk) {
            // reference collapsing: T& & -> T&, T&& & -> T&, T& && -> T&
            while (p.refk && !p.pointee.empty()) {
                kind = (kind == 1 || p.refk == 1) ? 1 : 2;
                ty next = p.pointee[0];
                p = next;
            }
            op = kind == 1 ? "&" : "&&";
        }
        ty r;
        bool wrap = p.arr || p.fn;
        r.left = p.left + (p.arr ? " " : "") + (wrap ? "(" : "") + op;
        r.right = wrap ? cat(")", p.right) : p.right;
        if (refk) {
            r.refk = kind;
            r.pointee.push_back(p);
        }
        too_big(r);
        return r;
    }

    // F [Y] <return type> <params> [ref] E, with cv qualifiers already read
    ty function_type()
    {
        deeper d(*this);
        unsigned cv = 0;
        if (eat('r'))
            cv |= 4;
        if (eat('V'))
            cv |= 2;
        if (eat('K'))
            cv |= 1;
        std::string exc;
        if (eat("Do"))
            exc = " noexcept";
        else if (peek() == 'D' && (peek(1) == 'O' || peek(1) == 'w'))
            return fail = true, ty();
        eat("Dx");
        if (!eat('F'))
            return fail = true, ty();
        eat('Y');
        ty ret = type();
        if (fail)
            return ty();
        std::string params;
        bool first = true;
        int ref = 0;
        while (true) {
            if (fail || i >= n)
                return fail = true, ty();
            if (eat('E'))
                break;
            if (eat('v'))
                continue;
            if (eat("RE")) {
                ref = 1;
                break;
            }
            if (eat("OE")) {
                ref = 2;
                break;
            }
            ty p = type();
            if (fail)
                return ty();
            if (p.empty)
                continue;
            if (!first)
                params += ", ";
            params += p.str();
            first = false;
            if (params.size() > max_out)
                return fail = true, ty();
        }
        ty f;
        f.fn = true;
        f.left = ret.left + " ";
        f.right = "(" + params + ")" + ret.right;
        if (cv & 1)
            f.right += " const";
        if (cv & 2)
            f.right += " volatile";
        if (cv & 4)
            f.right += " restrict";
        if (ref == 1)
            f.right += " &";
        if (ref == 2)
            f.right += " &&";
        f.right += exc;
        too_big(f);
        return f;
    }

    // Dp <type>: a pack expansion, printed once for every element of the pack inside
    ty pack_expansion()
    {
        deeper d(*this);
        i += 2;
        size_t start = i;
        size_t uses0 = pack_uses;
        pack_state saved = pk;
        pk = pack_state();
        pk.active = true;
        pk.index = 0;
        pk.no_subs = saved.no_subs;
        ty child = type();
        pack_state got = pk;
        pk = saved;
        if (fail)
            return ty();
        size_t end = i;
        ty r;
        if (!got.max_set) {
            // no pack inside (a function parameter pack): llvm prints it with "..."
            r.left = child.str() + "...";
        } else if (got.max == 0) {
            r.empty = true;
        } else {
            std::string out = child.str();
            for (size_t k = 1; k < got.max; k++) {
                i = start;
                pk = pack_state();
                pk.active = true;
                pk.index = k;
                pk.no_subs = true;
                ty again = type();
                bool same_size = pk.max_set && pk.max == got.max;
                pk = saved;
                if (fail || i != end || !same_size)
                    return fail = true, ty();
                out += ", " + again.str();
                if (out.size() > max_out)
                    return fail = true, ty();
            }
            i = end;
            r.left = out;
        }
        pack_uses = uses0;
        return r;
    }

    // <type>
    ty type()
    {
        deeper d(*this);
        if (fail)
            return ty();
        size_t tstart = i, tuses = pack_uses;
        ty r;
        char c = peek();
        switch (c) {
        case 'r':
        case 'V':
        case 'K': {
            size_t k = 0;
            if (peek(k) == 'r')
                k++;
            if (peek(k) == 'V')
                k++;
            if (peek(k) == 'K')
                k++;
            if (peek(k) == 'F' || (peek(k) == 'D' && (peek(k + 1) == 'o' || peek(k + 1) == 'O' ||
                                                      peek(k + 1) == 'w' || peek(k + 1) == 'x'))) {
                r = function_type();
                break;
            }
            unsigned cv = 0;
            if (eat('r'))
                cv |= 4;
            if (eat('V'))
                cv |= 2;
            if (eat('K'))
                cv |= 1;
            ty t = type();
            if (fail)
                return ty();
            r = t;
            r.base.clear();
            r.special = 0;
            r.refk = 0;
            r.pointee.clear();
            if (cv & 1)
                r.left += " const";
            if (cv & 2)
                r.left += " volatile";
            if (cv & 4)
                r.left += " restrict";
            break;
        }
        case 'U': // vendor qualifiers (objc, address spaces): not supported
            return fail = true, ty();
        case 'v': i++; return name_ty("void");
        case 'w': i++; return name_ty("wchar_t");
        case 'b': i++; return name_ty("bool");
        case 'c': i++; return name_ty("char");
        case 'a': i++; return name_ty("signed char");
        case 'h': i++; return name_ty("unsigned char");
        case 's': i++; return name_ty("short");
        case 't': i++; return name_ty("unsigned short");
        case 'i': i++; return name_ty("int");
        case 'j': i++; return name_ty("unsigned int");
        case 'l': i++; return name_ty("long");
        case 'm': i++; return name_ty("unsigned long");
        case 'x': i++; return name_ty("long long");
        case 'y': i++; return name_ty("unsigned long long");
        case 'n': i++; return name_ty("__int128");
        case 'o': i++; return name_ty("unsigned __int128");
        case 'f': i++; return name_ty("float");
        case 'd': i++; return name_ty("double");
        case 'e': i++; return name_ty("long double");
        case 'g': i++; return name_ty("__float128");
        case 'z': i++; return name_ty("...");
        case 'u': {
            i++;
            ty t = source_name();
            if (fail)
                return ty();
            r = t;
            if (eat('I')) { // a type transform: __remove_const(T)
                ty inner = type();
                if (fail || !eat('E'))
                    return fail = true, ty();
                r = plain_ty(t.left + "(" + inner.str() + ")");
            }
            break;
        }
        case 'D':
            switch (peek(1)) {
            case 'd': i += 2; return name_ty("decimal64");
            case 'e': i += 2; return name_ty("decimal128");
            case 'f': i += 2; return name_ty("decimal32");
            case 'h': i += 2; return name_ty("half");
            case 'i': i += 2; return name_ty("char32_t");
            case 's': i += 2; return name_ty("char16_t");
            case 'u': i += 2; return name_ty("char8_t");
            case 'a': i += 2; return name_ty("auto");
            case 'c': i += 2; return name_ty("decltype(auto)");
            case 'n': i += 2; return name_ty("std::nullptr_t");
            case 'F': {
                i += 2;
                if (eat("16b"))
                    return name_ty("std::bfloat16_t");
                std::string w = number(false);
                if (w.empty() || !eat('_'))
                    return fail = true, ty();
                return name_ty("_Float" + w);
            }
            case 'p':
                r = pack_expansion();
                break;
            case 'o':
            case 'O':
            case 'w':
            case 'x':
                r = function_type();
                break;
            default: // decltype, vectors, fixed point ...
                return fail = true, ty();
            }
            break;
        case 'F':
            r = function_type();
            break;
        case 'A': {
            i++;
            std::string dim;
            if (is_digit(peek())) {
                dim = number(false);
                if (!eat('_'))
                    return fail = true, ty();
            } else if (!eat('_')) {
                ty e = expression();
                if (fail || !eat('_'))
                    return fail = true, ty();
                dim = e.str();
            }
            ty base = type();
            if (fail)
                return ty();
            r.arr = true;
            r.left = base.left;
            r.right = cat("[" + dim + "]", base.right);
            break;
        }
        case 'M': {
            i++;
            ty cls = type();
            if (fail)
                return ty();
            ty mem = type();
            if (fail)
                return ty();
            bool wrap = mem.arr || mem.fn;
            r.left = mem.left + (wrap ? "(" : " ") + cls.str() + "::*";
            r.right = wrap ? cat(")", mem.right) : mem.right;
            break;
        }
        case 'T': {
            if (peek(1) == 's' || peek(1) == 'u' || peek(1) == 'e') {
                const char* kw = peek(1) == 's' ? "struct " : peek(1) == 'u' ? "union " : "enum ";
                i += 2;
                ty nm = name(nullptr);
                if (fail)
                    return ty();
                r = name_ty(kw + nm.str());
                break;
            }
            r = template_param();
            if (fail)
                return ty();
            if (try_tpl_args && peek() == 'I') {
                add_sub(r, tstart, tuses, true);
                std::string args = template_args(false);
                if (fail)
                    return ty();
                ty t;
                t.left = r.str() + args;
                t.base = r.base;
                r = t;
            }
            break;
        }
        case 'P':
        case 'R':
        case 'O': {
            i++;
            ty inner = type();
            if (fail)
                return ty();
            if (inner.empty) { // part of an empty pack
                r.empty = true;
                break;
            }
            r = pointer_like(inner, c == 'P' ? "*" : c == 'R' ? "&" : "&&", c == 'P' ? 0 : c == 'R' ? 1 : 2);
            break;
        }
        case 'C':
        case 'G': {
            i++;
            ty inner = type();
            if (fail)
                return ty();
            r.left = inner.str() + (c == 'C' ? " complex" : " imaginary");
            break;
        }
        case 'S':
            if (peek(1) != 't') {
                bool is_subst = false;
                r = unscoped_name(nullptr, &is_subst);
                if (fail)
                    return ty();
                if (peek() == 'I' && (!is_subst || try_tpl_args)) {
                    if (!is_subst)
                        add_sub(r, tstart, tuses, true);
                    std::string args = template_args(false);
                    if (fail)
                        return ty();
                    r.left += args;
                    r.special = 0;
                } else if (is_subst) {
                    return r; // a bare substitution isn't added again
                }
                break;
            }
            // St: a class-enum-type in std
            // fallthrough
        default: {
            // <class-enum-type>: a <name>
            if (!(is_digit(c) || c == 'N' || c == 'Z' || c == 'S'))
                return fail = true, ty();
            r = name(nullptr);
            if (fail)
                return ty();
            break;
        }
        }
        if (fail || too_big(r))
            return ty();
        add_sub(r, tstart, tuses, true);
        return r;
    }

    // ------------------------------------------------------------- encodings

    bool call_offset()
    {
        if (eat('h'))
            return !number(true).empty() && eat('_');
        if (eat('v'))
            return !number(true).empty() && eat('_') && !number(true).empty() && eat('_');
        return false;
    }

    std::string special_name(std::string& qual)
    {
        deeper d(*this);
        std::string r;
        if (peek() == 'T') {
            char c = peek(1);
            const char* what = nullptr;
            if (c == 'V')
                what = "vtable for ";
            else if (c == 'T')
                what = "VTT for ";
            else if (c == 'I')
                what = "typeinfo for ";
            else if (c == 'S')
                what = "typeinfo name for ";
            if (what) {
                i += 2;
                ty t = type();
                if (fail)
                    return "";
                r = what + t.str();
            } else if (c == 'c') {
                i += 2;
                if (!call_offset() || !call_offset())
                    return fail = true, "";
                std::string q;
                std::string e = encoding(q);
                if (fail)
                    return "";
                r = "covariant return thunk to " + e;
            } else if (c == 'C') {
                i += 2;
                ty first = type();
                if (fail)
                    return "";
                if (number(true).empty() || !eat('_'))
                    return fail = true, "";
                ty second = type();
                if (fail)
                    return "";
                r = "construction vtable for " + second.str() + "-in-" + first.str();
            } else if (c == 'W' || c == 'H') {
                i += 2;
                ty nm = name(nullptr);
                if (fail)
                    return "";
                r = (c == 'W' ? "thread-local wrapper routine for " : "thread-local initialization routine for ") +
                    nm.str();
            } else if (c == 'h' || c == 'v') {
                i += 1;
                bool virt = c == 'v';
                if (!call_offset())
                    return fail = true, "";
                std::string q;
                std::string e = encoding(q);
                if (fail)
                    return "";
                r = (virt ? "virtual thunk to " : "non-virtual thunk to ") + e;
            } else {
                return fail = true, "";
            }
        } else if (peek() == 'G') {
            char c = peek(1);
            if (c == 'V') {
                i += 2;
                ty nm = name(nullptr);
                if (fail)
                    return "";
                r = "guard variable for " + nm.str();
            } else if (c == 'R') {
                i += 2;
                ty nm = name(nullptr);
                if (fail)
                    return "";
                bool had_id = false;
                while (is_digit(peek()) || is_upper(peek())) {
                    i++;
                    had_id = true;
                }
                if (!eat('_') && had_id)
                    return fail = true, "";
                r = "reference temporary for " + nm.str();
            } else {
                return fail = true, "";
            }
        } else {
            return fail = true, "";
        }
        qual = r;
        return r;
    }

    // <encoding>: a function (name + parameters), a data name, or a special name. returns what
    // llvm prints; qual is the name alone
    std::string encoding(std::string& qual, std::string* sig = nullptr)
    {
        deeper d(*this);
        // an encoding's template parameters are unrelated to the surrounding ones
        std::vector<ty> saved = tparams;
        bool saved_ok = tparams_ok;
        tparams.clear();
        tparams_ok = false;
        std::string r = encoding_body(qual, sig);
        tparams = saved;
        tparams_ok = saved_ok;
        return r;
    }

    std::string encoding_body(std::string& qual, std::string* sig)
    {
        if (peek() == 'G' || peek() == 'T') {
            std::string r = special_name(qual);
            if (sig)
                *sig = r;
            return r;
        }
        state st;
        ty nm = name(&st);
        if (fail)
            return "";
        qual = nm.str();
        if (sig)
            *sig = qual;
        char c = peek();
        if (i >= n || c == 'E' || c == '.' || c == '_')
            return qual; // data
        if (eat("Ua9enable_ifI"))
            return fail = true, "";
        ty ret;
        bool has_ret = false;
        if (!st.ctor_dtor_conv && st.ends_tpl) {
            ret = type();
            if (fail)
                return "";
            has_ret = true;
        }
        std::string params;
        if (!eat('v')) {
            bool first = true;
            do {
                ty p = type();
                if (fail)
                    return "";
                if (p.empty)
                    continue;
                if (!first)
                    params += ", ";
                params += p.str();
                first = false;
                if (params.size() > max_out)
                    return fail = true, "";
            } while (i < n && peek() != 'E' && peek() != '.' && peek() != '_' && peek() != 'Q');
        }
        if (peek() == 'Q') // requires clauses: not supported
            return fail = true, "";
        std::string quals;
        if (st.cv & 1)
            quals += " const";
        if (st.cv & 2)
            quals += " volatile";
        if (st.cv & 4)
            quals += " restrict";
        if (st.ref == 1)
            quals += " &";
        if (st.ref == 2)
            quals += " &&";
        if (sig)
            *sig = qual + "(" + params + ")" + quals;
        std::string f;
        if (has_ret)
            f = ret.left + (ret.right.empty() ? " " : "");
        f += qual + "(" + params + ")";
        if (has_ret)
            f += ret.right;
        return f + quals;
    }
};

// _Z / __Z <encoding> [.suffix], and ___Z..._block_invoke (objective-c blocks)
bool run_itanium(const std::string& in, std::string& qual, std::string& full, std::string& sig)
{
    if (in.size() > max_input)
        return false;
    size_t start;
    bool block = false;
    if (in.compare(0, 4, "___Z") == 0 && in.compare(0, 5, "____Z") != 0)
        start = 4, block = true;
    else if (in.compare(0, 5, "____Z") == 0)
        start = 5, block = true;
    else if (in.compare(0, 3, "__Z") == 0)
        start = 3;
    else if (in.compare(0, 2, "_Z") == 0)
        start = 2;
    else
        return false;

    itanium it(in.data() + start, in.size() - start);
    std::string q, sg;
    std::string f = it.encoding(q, &sg);
    if (it.fail || q.empty())
        return false;
    if (block) {
        if (!it.eat("_block_invoke"))
            return false;
        bool need_num = it.eat('_');
        if (it.number(false).empty() && need_num)
            return false;
        if (it.peek() == '.')
            it.i = it.n;
        if (it.i != it.n)
            return false;
        qual = full = sig = "invocation function for block in " + f;
        return true;
    }
    if (it.peek() == '.') { // a compiler clone (.cold, .isra.0): shown, but not part of the name
        std::string suffix = " (" + std::string(it.s + it.i, it.n - it.i) + ")";
        f += suffix;
        sg += suffix;
        it.i = it.n;
    }
    if (it.i != it.n)
        return false;
    qual = q;
    full = f;
    sig = sg;
    return true;
}

// ---------------------------------------------------------------- rust, legacy mangling
//
// _ZN <len><ident>... 17h<16 hex> E: an itanium-style path whose idents carry rust escapes
// ($LT$ for <, .. for ::) and end in a hash. printed the way rustc-demangle prints it, without
// the hash: <std::io::Error as core::fmt::Display>::fmt

bool is_rust_hash(const std::string& s)
{
    if (s.size() != 17 || s[0] != 'h')
        return false;
    for (size_t k = 1; k < s.size(); k++)
        if (!is_digit(s[k]) && !(s[k] >= 'a' && s[k] <= 'f'))
            return false;
    return true;
}

bool rust_unescape(const std::string& e, std::string& out)
{
    std::string rest = e;
    if (rest.compare(0, 2, "_$") == 0)
        rest = rest.substr(1);
    while (!rest.empty()) {
        if (rest[0] == '.') {
            if (rest.size() > 1 && rest[1] == '.') {
                out += "::";
                rest = rest.substr(2);
            } else {
                out += ".";
                rest = rest.substr(1);
            }
        } else if (rest[0] == '$') {
            size_t end = rest.find('$', 1);
            if (end == std::string::npos)
                return false;
            std::string esc = rest.substr(1, end - 1);
            static const struct {
                const char* code;
                const char* text;
            } map[] = {{"SP", "@"}, {"BP", "*"}, {"RF", "&"}, {"LT", "<"}, {"GT", ">"}, {"LP", "("}, {"RP", ")"}, {"C", ","}};
            bool done = false;
            for (const auto& m : map)
                if (esc == m.code) {
                    out += m.text;
                    done = true;
                    break;
                }
            if (!done) {
                if (esc.size() < 2 || esc[0] != 'u')
                    return false;
                unsigned long v = 0;
                for (size_t k = 1; k < esc.size(); k++) {
                    char h = esc[k];
                    if (is_digit(h))
                        v = v * 16 + (unsigned long)(h - '0');
                    else if (h >= 'a' && h <= 'f')
                        v = v * 16 + (unsigned long)(h - 'a' + 10);
                    else
                        return false;
                    if (v > 0x10ffff)
                        return false;
                }
                if (v < 0x20 || v == 0x7f)
                    return false;
                // utf-8
                if (v < 0x80) {
                    out += (char)v;
                } else if (v < 0x800) {
                    out += (char)(0xc0 | (v >> 6));
                    out += (char)(0x80 | (v & 0x3f));
                } else if (v < 0x10000) {
                    out += (char)(0xe0 | (v >> 12));
                    out += (char)(0x80 | ((v >> 6) & 0x3f));
                    out += (char)(0x80 | (v & 0x3f));
                } else {
                    out += (char)(0xf0 | (v >> 18));
                    out += (char)(0x80 | ((v >> 12) & 0x3f));
                    out += (char)(0x80 | ((v >> 6) & 0x3f));
                    out += (char)(0x80 | (v & 0x3f));
                }
            }
            rest = rest.substr(end + 1);
        } else {
            size_t k = rest.find_first_of("$.");
            if (k == std::string::npos) {
                out += rest;
                rest.clear();
            } else {
                out += rest.substr(0, k);
                rest = rest.substr(k);
            }
        }
    }
    return true;
}

bool run_rust_legacy(const std::string& in, std::string& out)
{
    if (in.size() > max_input)
        return false;
    size_t k;
    if (in.compare(0, 3, "_ZN") == 0)
        k = 3;
    else if (in.compare(0, 4, "__ZN") == 0)
        k = 4;
    else
        return false;
    std::vector<std::string> parts;
    while (k < in.size() && in[k] != 'E') {
        if (!is_digit(in[k]))
            return false;
        size_t len = 0;
        while (k < in.size() && is_digit(in[k])) {
            len = len * 10 + (size_t)(in[k] - '0');
            if (len > in.size())
                return false;
            k++;
        }
        if (len == 0 || k + len > in.size())
            return false;
        parts.push_back(in.substr(k, len));
        k += len;
    }
    if (k >= in.size() || parts.size() < 2 || !is_rust_hash(parts.back()))
        return false;
    k++; // E
    std::string suffix = in.substr(k);
    size_t llvm = suffix.find(".llvm.");
    if (llvm != std::string::npos) {
        bool all = true;
        for (size_t j = llvm + 6; j < suffix.size(); j++) {
            char c = suffix[j];
            if (!(is_digit(c) || (c >= 'A' && c <= 'F') || c == '@'))
                all = false;
        }
        if (all)
            suffix = suffix.substr(0, llvm);
    }
    if (!suffix.empty() && suffix[0] != '.')
        return false;
    parts.pop_back(); // the hash
    std::string r;
    for (size_t j = 0; j < parts.size(); j++) {
        if (j)
            r += "::";
        if (!rust_unescape(parts[j], r))
            return false;
    }
    out = r + suffix;
    return true;
}

// ---------------------------------------------------------------- rust, v0 mangling (the default
// since rust 1.9x): _R <path> [<instantiating crate>]. printed like rustc-demangle's alternate
// form, which leaves out the crate hashes: <mycrate::Point<i32>>::sum, mycrate::main::{closure#0}

struct rust_v0 {
    const char* s;
    size_t n;
    size_t i = 0;
    bool fail = false;
    int depth = 0;
    std::string out;
    bool skip = false;          // parsing a path that isn't printed (an impl's own path)
    unsigned bound_lt = 0;      // lifetimes bound by enclosing for<...>

    rust_v0(const char* p, size_t len) : s(p), n(len) {}

    struct deeper {
        rust_v0& p;
        explicit deeper(rust_v0& p_) : p(p_)
        {
            if (++p.depth > max_depth)
                p.fail = true;
        }
        ~deeper() { --p.depth; }
    };

    char peek() const { return i < n ? s[i] : 0; }
    bool eat(char c)
    {
        if (i < n && s[i] == c) {
            i++;
            return true;
        }
        return false;
    }
    char next()
    {
        if (i >= n) {
            fail = true;
            return 0;
        }
        return s[i++];
    }
    void print(const std::string& t)
    {
        if (skip || fail)
            return;
        out += t;
        if (out.size() > max_out)
            fail = true;
    }

    // <base-62-number>: "_" is 0, otherwise the digits plus one
    uint64_t integer_62()
    {
        if (eat('_'))
            return 0;
        uint64_t x = 0;
        while (!eat('_')) {
            if (fail || i >= n)
                return fail = true, 0;
            char c = next();
            uint64_t d;
            if (is_digit(c))
                d = (uint64_t)(c - '0');
            else if (is_lower(c))
                d = 10 + (uint64_t)(c - 'a');
            else if (is_upper(c))
                d = 36 + (uint64_t)(c - 'A');
            else
                return fail = true, 0;
            if (x > (UINT64_MAX - d) / 62)
                return fail = true, 0;
            x = x * 62 + d;
        }
        if (x == UINT64_MAX)
            return fail = true, 0;
        return x + 1;
    }
    uint64_t opt_integer_62(char tag) { return eat(tag) ? integer_62() + 1 : 0; }
    uint64_t disambiguator() { return opt_integer_62('s'); }

    // <identifier>: [u] <len> [_] <bytes>, u marks punycode for non-ascii names
    bool ident(std::string& text)
    {
        bool puny = eat('u');
        if (!is_digit(peek()))
            return fail = true, false;
        size_t len = (size_t)(next() - '0');
        if (len != 0)
            while (is_digit(peek())) {
                len = len * 10 + (size_t)(next() - '0');
                if (len > n)
                    return fail = true, false;
            }
        eat('_');
        if (i + len > n)
            return fail = true, false;
        std::string raw(s + i, len);
        i += len;
        if (!puny) {
            text = raw;
            return true;
        }
        size_t us = raw.rfind('_');
        std::string ascii = us == std::string::npos ? "" : raw.substr(0, us);
        std::string code = us == std::string::npos ? raw : raw.substr(us + 1);
        if (code.empty())
            return fail = true, false;
        if (!punycode(ascii, code, text))
            text = "punycode{" + (ascii.empty() ? "" : ascii + "-") + code + "}";
        return true;
    }

    // rfc 3492, the way rustc-demangle decodes it (into at most 128 characters)
    static bool punycode(const std::string& ascii, const std::string& code, std::string& out)
    {
        std::vector<uint32_t> chars(ascii.begin(), ascii.end());
        const size_t base = 36, t_min = 1, t_max = 26, skew = 38;
        size_t damp = 700, bias = 72, i = 0, n = 0x80;
        size_t p = 0;
        while (p < code.size()) {
            size_t delta = 0, w = 1, k = 0;
            while (true) {
                k += base;
                size_t t = k > bias ? k - bias : 0;
                t = t < t_min ? t_min : t > t_max ? t_max : t;
                if (p >= code.size())
                    return false;
                char c = code[p++];
                size_t d;
                if (c >= 'a' && c <= 'z')
                    d = (size_t)(c - 'a');
                else if (c >= '0' && c <= '9')
                    d = 26 + (size_t)(c - '0');
                else
                    return false;
                if (d > (SIZE_MAX - delta) / w)
                    return false;
                delta += d * w;
                if (d < t)
                    break;
                if (w > SIZE_MAX / (base - t))
                    return false;
                w *= base - t;
            }
            size_t len = chars.size() + 1;
            if (i > SIZE_MAX - delta)
                return false;
            i += delta;
            n += i / len;
            i %= len;
            if (n > 0x10ffff || (n >= 0xd800 && n <= 0xdfff) || chars.size() >= 128)
                return false;
            chars.insert(chars.begin() + (long)i, (uint32_t)n);
            if (p >= code.size())
                break;
            i++;
            delta /= damp;
            damp = 2;
            delta += delta / len;
            k = 0;
            while (delta > ((base - t_min) * t_max) / 2) {
                delta /= base - t_min;
                k += base;
            }
            bias = k + ((base - t_min + 1) * delta) / (delta + skew);
        }
        out.clear();
        for (uint32_t v : chars) {
            if (v < 0x80) {
                out += (char)v;
            } else if (v < 0x800) {
                out += (char)(0xc0 | (v >> 6));
                out += (char)(0x80 | (v & 0x3f));
            } else if (v < 0x10000) {
                out += (char)(0xe0 | (v >> 12));
                out += (char)(0x80 | ((v >> 6) & 0x3f));
                out += (char)(0x80 | (v & 0x3f));
            } else {
                out += (char)(0xf0 | (v >> 18));
                out += (char)(0x80 | ((v >> 12) & 0x3f));
                out += (char)(0x80 | ((v >> 6) & 0x3f));
                out += (char)(0x80 | (v & 0x3f));
            }
        }
        return true;
    }

    // B <base-62>: the thing at an earlier position, parsed from there
    template <typename F> void backref(F f)
    {
        size_t start = i - 1;
        uint64_t pos = integer_62();
        if (fail || pos >= start)
            return (void)(fail = true);
        deeper d(*this);
        size_t save = i;
        i = (size_t)pos;
        f();
        i = save;
    }

    void lifetime(uint64_t lt)
    {
        if (skip)
            return;
        print("'");
        if (lt == 0)
            return print("_");
        if (lt > bound_lt)
            return (void)(fail = true);
        uint64_t d = bound_lt - lt;
        if (d < 26)
            print(std::string(1, (char)('a' + d)));
        else
            print("_" + std::to_string(d));
    }

    template <typename F> void in_binder(F f)
    {
        uint64_t count = opt_integer_62('G');
        if (fail)
            return;
        if (skip || count == 0)
            return f();
        if (count > 1000)
            return (void)(fail = true);
        print("for<");
        for (uint64_t k = 0; k < count; k++) {
            if (k)
                print(", ");
            bound_lt++;
            lifetime(1);
        }
        print("> ");
        f();
        bound_lt -= (unsigned)count;
    }

    template <typename F> size_t sep_list(F f, const char* sep)
    {
        size_t k = 0;
        while (!fail && !eat('E')) {
            if (i >= n)
                return fail = true, k;
            if (k)
                print(sep);
            f();
            k++;
        }
        return k;
    }

    void path(bool in_value)
    {
        deeper d(*this);
        char tag = next();
        if (fail)
            return;
        switch (tag) {
        case 'C': {
            disambiguator();
            std::string nm;
            if (!ident(nm))
                return;
            print(nm);
            break;
        }
        case 'N': {
            char ns = next();
            if (!is_upper(ns) && !is_lower(ns))
                return (void)(fail = true);
            path(in_value);
            uint64_t dis = disambiguator();
            std::string nm;
            if (!ident(nm))
                return;
            if (is_upper(ns)) {
                print("::{");
                if (ns == 'C')
                    print("closure");
                else if (ns == 'S')
                    print("shim");
                else
                    print(std::string(1, ns));
                if (!nm.empty())
                    print(":" + nm);
                print("#" + std::to_string(dis) + "}");
            } else if (!nm.empty()) {
                print("::" + nm);
            }
            break;
        }
        case 'M':
        case 'X':
        case 'Y': {
            if (tag != 'Y') {
                disambiguator();
                bool save = skip;
                skip = true;
                path(false);
                skip = save;
            }
            print("<");
            type();
            if (tag != 'M') {
                print(" as ");
                path(false);
            }
            print(">");
            break;
        }
        case 'I': {
            path(in_value);
            if (in_value)
                print("::");
            print("<");
            sep_list([&] { generic_arg(); }, ", ");
            print(">");
            break;
        }
        case 'B':
            backref([&] { path(in_value); });
            break;
        default:
            fail = true;
        }
    }

    void generic_arg()
    {
        if (eat('L')) {
            uint64_t lt = integer_62();
            if (!fail)
                lifetime(lt);
        } else if (eat('K')) {
            constant(false);
        } else {
            type();
        }
    }

    static const char* basic_type(char c)
    {
        switch (c) {
        case 'b': return "bool";
        case 'c': return "char";
        case 'e': return "str";
        case 'u': return "()";
        case 'a': return "i8";
        case 's': return "i16";
        case 'l': return "i32";
        case 'x': return "i64";
        case 'n': return "i128";
        case 'i': return "isize";
        case 'h': return "u8";
        case 't': return "u16";
        case 'm': return "u32";
        case 'y': return "u64";
        case 'o': return "u128";
        case 'j': return "usize";
        case 'f': return "f32";
        case 'd': return "f64";
        case 'z': return "!";
        case 'p': return "_";
        case 'v': return "...";
        default: return nullptr;
        }
    }

    void type()
    {
        char tag = next();
        if (fail)
            return;
        if (const char* b = basic_type(tag))
            return print(b);
        deeper d(*this);
        switch (tag) {
        case 'R':
        case 'Q': {
            print("&");
            if (eat('L')) {
                uint64_t lt = integer_62();
                if (fail)
                    return;
                if (lt != 0) {
                    lifetime(lt);
                    print(" ");
                }
            }
            if (tag != 'R')
                print("mut ");
            type();
            break;
        }
        case 'P':
        case 'O':
            print(tag == 'P' ? "*const " : "*mut ");
            type();
            break;
        case 'A':
        case 'S':
            print("[");
            type();
            if (tag == 'A') {
                print("; ");
                constant(true);
            }
            print("]");
            break;
        case 'T': {
            print("(");
            size_t count = sep_list([&] { type(); }, ", ");
            if (count == 1)
                print(",");
            print(")");
            break;
        }
        case 'F':
            in_binder([&] {
                bool is_unsafe = eat('U');
                std::string abi;
                bool has_abi = false;
                if (eat('K')) {
                    has_abi = true;
                    if (eat('C')) {
                        abi = "C";
                    } else {
                        bool puny = peek() == 'u';
                        if (!ident(abi) || abi.empty() || puny)
                            return (void)(fail = true);
                        for (char& ch : abi)
                            if (ch == '_')
                                ch = '-';
                    }
                }
                if (is_unsafe)
                    print("unsafe ");
                if (has_abi)
                    print("extern \"" + abi + "\" ");
                print("fn(");
                sep_list([&] { type(); }, ", ");
                print(")");
                if (!eat('u')) {
                    print(" -> ");
                    type();
                }
            });
            break;
        case 'D': {
            print("dyn ");
            in_binder([&] { sep_list([&] { dyn_trait(); }, " + "); });
            if (!eat('L'))
                return (void)(fail = true);
            uint64_t lt = integer_62();
            if (!fail && lt != 0) {
                print(" + ");
                lifetime(lt);
            }
            break;
        }
        case 'B':
            backref([&] { type(); });
            break;
        default:
            i--; // a path names the type
            path(false);
        }
    }

    bool path_maybe_open_generics()
    {
        if (eat('B')) {
            bool open = false;
            backref([&] { open = path_maybe_open_generics(); });
            return open;
        }
        if (eat('I')) {
            path(false);
            print("<");
            sep_list([&] { generic_arg(); }, ", ");
            return true;
        }
        path(false);
        return false;
    }

    void dyn_trait()
    {
        bool open = path_maybe_open_generics();
        while (!fail && eat('p')) {
            print(open ? ", " : "<");
            open = true;
            std::string nm;
            if (!ident(nm))
                return;
            print(nm + " = ");
            type();
        }
        if (open)
            print(">");
    }

    // hex digits up to "_"; false when it doesn't fit in 64 bits (hex keeps the digits)
    bool hex_nibbles(std::string& hex, uint64_t& v)
    {
        size_t start = i;
        while (i < n && s[i] != '_') {
            char c = s[i];
            if (!(is_digit(c) || (c >= 'a' && c <= 'f')))
                return fail = true, false;
            i++;
        }
        if (!eat('_'))
            return fail = true, false;
        hex.assign(s + start, i - 1 - start);
        size_t k = 0;
        while (k < hex.size() && hex[k] == '0')
            k++;
        std::string sig = hex.substr(k);
        if (sig.size() > 16)
            return false;
        v = 0;
        for (char c : sig)
            v = v * 16 + (uint64_t)(is_digit(c) ? c - '0' : c - 'a' + 10);
        return true;
    }

    void const_uint()
    {
        std::string hex;
        uint64_t v = 0;
        bool fits = hex_nibbles(hex, v);
        if (fail)
            return;
        print(fits ? std::to_string(v) : "0x" + hex);
    }

    void constant(bool in_value)
    {
        char tag = next();
        if (fail)
            return;
        deeper d(*this);
        switch (tag) {
        case 'p':
            print("_");
            break;
        case 'h':
        case 't':
        case 'm':
        case 'y':
        case 'o':
        case 'j':
            const_uint();
            break;
        case 'a':
        case 's':
        case 'l':
        case 'x':
        case 'n':
        case 'i':
            if (eat('n'))
                print("-");
            const_uint();
            break;
        case 'b': {
            std::string hex;
            uint64_t v = 0;
            if (!hex_nibbles(hex, v) || v > 1)
                return (void)(fail = true);
            print(v ? "true" : "false");
            break;
        }
        case 'c': {
            std::string hex;
            uint64_t v = 0;
            if (!hex_nibbles(hex, v))
                return (void)(fail = true);
            // printable ascii only; anything else would need rust's escaping rules
            if (v < 0x20 || v > 0x7e || v == '\'' || v == '\\')
                return (void)(fail = true);
            print(std::string("'") + (char)v + "'");
            break;
        }
        case 'B':
            backref([&] { constant(in_value); });
            break;
        default: // str, reference, array, tuple and struct constants: not supported
            fail = true;
        }
    }
};

bool run_rust_v0(const std::string& in, std::string& out)
{
    if (in.size() > max_input)
        return false;
    size_t k;
    if (in.compare(0, 2, "_R") == 0)
        k = 2;
    else if (in.compare(0, 3, "__R") == 0)
        k = 3;
    else
        return false;
    std::string sym = in.substr(k);
    size_t llvm = sym.find(".llvm.");
    if (llvm != std::string::npos) {
        bool all = true;
        for (size_t j = llvm + 6; j < sym.size(); j++) {
            char c = sym[j];
            if (!(is_digit(c) || (c >= 'A' && c <= 'F') || c == '@'))
                all = false;
        }
        if (all)
            sym = sym.substr(0, llvm);
    }
    if (sym.empty() || !is_upper(sym[0]))
        return false;
    for (char c : sym)
        if ((unsigned char)c & 0x80)
            return false;
    rust_v0 p(sym.data(), sym.size());
    p.path(true); // a value path: generic arguments print as ::<...>
    if (p.fail)
        return false;
    // the instantiating crate: parsed, not printed
    if (p.i < p.n && is_upper(p.s[p.i])) {
        bool save = p.skip;
        p.skip = true;
        p.path(false);
        p.skip = save;
        if (p.fail)
            return false;
    }
    std::string suffix = sym.substr(p.i);
    if (!suffix.empty()) {
        if (suffix[0] != '.')
            return false;
        for (char c : suffix)
            if ((unsigned char)c < 0x21 || (unsigned char)c > 0x7e)
                return false;
    }
    out = p.out + suffix;
    return true;
}

// ---------------------------------------------------------------- msvc: ?name@scope@@<encoding>
//
// a node tree like llvm's (llvm-undname prints the same text): types print in two halves around
// what they declare, and names can refer back to earlier names and parameter types.

struct msvc {
    enum kind { k_prim, k_tag, k_ptr, k_arr, k_func, k_custom, k_named, k_intrin, k_structor, k_convop,
                k_litop, k_qname, k_tpref, k_int, k_fsym, k_vsym, k_table };
    enum { q_const = 1, q_volatile = 2, q_restrict = 4, q_unaligned = 8, q_ptr64 = 16 };
    enum { fc_public = 1, fc_protected = 2, fc_private = 4, fc_global = 8, fc_static = 16, fc_virtual = 32,
           fc_far = 64, fc_extern_c = 128, fc_no_params = 256, fc_this_static = 512, fc_this_virtual = 1024,
           fc_this_virtual_ex = 2048 };
    enum { of_no_cc = 1, of_no_tag = 2, of_no_access = 4, of_no_member = 8, of_no_ret = 16, of_no_vartype = 32 };

    struct node {
        kind k = k_prim;
        std::string s;               // a primitive's name, a tag keyword, an identifier, an operator
        unsigned quals = 0;
        int aff = 0;                 // pointer: 1 *, 2 &, 3 &&
        node* a = nullptr;           // pointee / element / return type / class / target / name
        node* b = nullptr;           // member pointer's class / symbol's signature or type / table target
        std::vector<node*> list;     // parameters / components / dimensions
        std::vector<node*> tparams;  // template arguments of an identifier
        bool has_tparams = false;
        bool is_dtor = false, variadic = false, no_except = false, member_ptr = false, neg = false;
        bool has_params = false;     // a function type with a parameter list (X means none: void)
        int refq = 0;                // function ref qualifier: 1 &, 2 &&
        unsigned fc = 0;
        int cc = 0;
        uint64_t value = 0;
        int sc = 0;                  // variable storage class: 1 private, 2 protected, 3 public static
        std::vector<int64_t> offsets;
        bool thunk = false;          // a thunk's signature: printed with "[thunk]: "
    };

    const char* s;
    size_t n;
    size_t i = 0;
    bool fail = false;
    int depth = 0;
    std::vector<std::unique_ptr<node>> arena;

    struct backrefs {
        std::vector<node*> names;   // up to 10
        std::vector<node*> params;  // up to 10
    } br;

    msvc(const char* p, size_t len) : s(p), n(len) {}

    struct deeper {
        msvc& p;
        explicit deeper(msvc& p_) : p(p_)
        {
            if (++p.depth > max_depth)
                p.fail = true;
        }
        ~deeper() { --p.depth; }
    };

    node* make(kind k)
    {
        if (arena.size() > 20000) {
            fail = true;
            arena.emplace_back(new node());
            return arena.back().get();
        }
        arena.emplace_back(new node());
        arena.back()->k = k;
        return arena.back().get();
    }
    char peek(size_t k = 0) const { return i + k < n ? s[i + k] : 0; }
    bool starts(const char* lit) const
    {
        size_t len = strlen(lit);
        return i + len <= n && memcmp(s + i, lit, len) == 0;
    }
    bool eat(const char* lit)
    {
        if (!starts(lit))
            return false;
        i += strlen(lit);
        return true;
    }
    bool eat(char c)
    {
        if (i < n && s[i] == c) {
            i++;
            return true;
        }
        return false;
    }
    bool empty() const { return i >= n; }

    // ------------------------------------------------------------- numbers and simple names

    // <number>: [?] 0-9 (meaning 1..10), or hex digits written A-P ending in @
    bool number(uint64_t& v, bool& neg)
    {
        neg = eat('?');
        if (is_digit(peek())) {
            v = (uint64_t)(s[i] - '0') + 1;
            i++;
            return true;
        }
        v = 0;
        for (size_t k = i; k < n; k++) {
            char c = s[k];
            if (c == '@') {
                i = k + 1;
                return true;
            }
            if (c < 'A' || c > 'P' || v > (UINT64_MAX >> 4))
                break;
            v = (v << 4) + (uint64_t)(c - 'A');
        }
        fail = true;
        return false;
    }
    int64_t signed_number()
    {
        uint64_t v = 0;
        bool neg = false;
        if (!number(v, neg))
            return 0;
        if (v > (uint64_t)INT64_MAX)
            return fail = true, 0;
        return neg ? -(int64_t)v : (int64_t)v;
    }
    uint64_t unsigned_number()
    {
        uint64_t v = 0;
        bool neg = false;
        if (!number(v, neg))
            return 0;
        if (neg)
            fail = true;
        return v;
    }

    void memorize(const std::string& name)
    {
        if (br.names.size() >= 10)
            return;
        for (node* x : br.names)
            if (x->s == name)
                return;
        node* nm = make(k_named);
        nm->s = name;
        br.names.push_back(nm);
    }
    void memorize(node* id)
    {
        std::string text;
        out(text, id, 0);
        memorize(text);
    }

    std::string simple_string(bool remember)
    {
        for (size_t k = i; k < n; k++) {
            if (s[k] != '@')
                continue;
            if (k == i)
                break;
            std::string r(s + i, k - i);
            i = k + 1;
            if (remember)
                memorize(r);
            return r;
        }
        fail = true;
        return "";
    }
    node* simple_name(bool remember)
    {
        std::string r = simple_string(remember);
        if (fail)
            return nullptr;
        node* nm = make(k_named);
        nm->s = r;
        return nm;
    }
    node* backref_name()
    {
        size_t k = (size_t)(s[i] - '0');
        if (k >= br.names.size())
            return fail = true, nullptr;
        i++;
        return br.names[k];
    }

    // ------------------------------------------------------------- identifiers

    node* intrinsic(const char* text)
    {
        if (!text)
            return fail = true, nullptr;
        node* x = make(k_intrin);
        x->s = text;
        return x;
    }

    node* function_identifier()
    {
        i++; // ?
        if (empty())
            return fail = true, nullptr;
        static const char* const basic[36] = {
            nullptr, nullptr, "operator new", "operator delete", "operator=", "operator>>", "operator<<",
            "operator!", "operator==", "operator!=", "operator[]", nullptr, "operator->", "operator*",
            "operator++", "operator--", "operator-", "operator+", "operator&", "operator->*", "operator/",
            "operator%", "operator<", "operator<=", "operator>", "operator>=", "operator,", "operator()",
            "operator~", "operator^", "operator|", "operator&&", "operator||", "operator*=", "operator+=",
            "operator-="};
        static const char* const under[36] = {
            "operator/=", "operator%=", "operator>>=", "operator<<=", "operator&=", "operator|=", "operator^=",
            nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, "`vbase dtor'", "`vector deleting dtor'",
            "`default ctor closure'", "`scalar deleting dtor'", "`vector ctor iterator'", "`vector dtor iterator'",
            "`vector vbase ctor iterator'", "`virtual displacement map'", "`eh vector ctor iterator'",
            "`eh vector dtor iterator'", "`eh vector vbase ctor iterator'", "`copy ctor closure'", nullptr,
            nullptr, nullptr, nullptr, "`local vftable ctor closure'", "operator new[]", "operator delete[]",
            nullptr, nullptr, nullptr, nullptr};
        static const char* const double_under[36] = {
            nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
            "`managed vector ctor iterator'", "`managed vector dtor iterator'", "`EH vector copy ctor iterator'",
            "`EH vector vbase copy ctor iterator'", nullptr, nullptr, "`vector copy ctor iterator'",
            "`vector vbase copy constructor iterator'", "`managed vector vbase copy constructor iterator'",
            nullptr, nullptr, "operator co_await", "operator<=>", nullptr, nullptr, nullptr, nullptr, nullptr,
            nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr};
        auto index = [](char c) -> int {
            if (c >= '0' && c <= '9')
                return c - '0';
            if (c >= 'A' && c <= 'Z')
                return 10 + c - 'A';
            return -1;
        };
        if (eat("__")) {
            if (empty())
                return fail = true, nullptr;
            char c = s[i++];
            if (c == 'K') { // operator ""_name
                std::string nm = simple_string(false);
                if (fail)
                    return nullptr;
                node* x = make(k_litop);
                x->s = nm;
                return x;
            }
            int k = index(c);
            return intrinsic(k < 0 ? nullptr : double_under[k]);
        }
        if (eat('_')) {
            if (empty())
                return fail = true, nullptr;
            int k = index(s[i++]);
            return intrinsic(k < 0 ? nullptr : under[k]);
        }
        char c = s[i++];
        if (c == '0' || c == '1') {
            node* x = make(k_structor);
            x->is_dtor = c == '1';
            return x;
        }
        if (c == 'B')
            return make(k_convop);
        int k = index(c);
        return intrinsic(k < 0 ? nullptr : basic[k]);
    }

    // ?$ <name> <template arguments> @: arguments get a fresh back-reference table
    node* template_instantiation(bool remember_template)
    {
        deeper d(*this);
        i += 2; // ?$
        backrefs outer;
        std::swap(outer, br);
        node* id = unqualified_symbol_name(true);
        if (!fail && id)
            template_params(id);
        std::swap(outer, br);
        if (fail)
            return nullptr;
        if (remember_template) {
            if (id->k == k_convop || id->k == k_structor)
                return fail = true, nullptr;
            memorize(id);
        }
        return id;
    }

    node* unqualified_symbol_name(bool remember_simple)
    {
        if (is_digit(peek()))
            return backref_name();
        if (starts("?$"))
            return template_instantiation(false);
        if (peek() == '?')
            return function_identifier();
        return simple_name(remember_simple);
    }

    node* unqualified_type_name()
    {
        if (is_digit(peek()))
            return backref_name();
        if (starts("?$"))
            return template_instantiation(true);
        return simple_name(true);
    }

    bool local_scope_pattern() const
    {
        if (peek() != '?')
            return false;
        size_t k = i + 1;
        size_t end = k;
        while (end < n && s[end] != '?')
            end++;
        if (end >= n || end == k)
            return false;
        std::string c(s + k, end - k);
        if (c.size() == 1)
            return c[0] == '@' || is_digit(c[0]);
        if (c.back() != '@')
            return false;
        c.pop_back();
        if (c[0] < 'B' || c[0] > 'P')
            return false;
        for (size_t j = 1; j < c.size(); j++)
            if (c[j] < 'A' || c[j] > 'P')
                return false;
        return true;
    }

    node* scope_piece()
    {
        if (is_digit(peek()))
            return backref_name();
        if (starts("?$"))
            return template_instantiation(true);
        if (starts("?A")) { // anonymous namespace: ?A0x1234@
            i += 2;
            size_t end = i;
            while (end < n && s[end] != '@')
                end++;
            if (end >= n)
                return fail = true, nullptr;
            memorize(std::string(s + i, end - i)); // llvm remembers the key, not the text
            i = end + 1;
            node* x = make(k_named);
            x->s = "`anonymous namespace'";
            return x;
        }
        if (local_scope_pattern()) { // ?1??f@@YAXXZ: a function's local scope
            deeper d(*this);
            i++;
            uint64_t num = 0;
            bool neg = false;
            if (!number(num, neg))
                return nullptr;
            eat('?');
            node* scope = parse();
            if (fail)
                return nullptr;
            std::string text = "`";
            out(text, scope, 0);
            text += "'::`" + std::to_string(num) + "'";
            node* x = make(k_named);
            x->s = text;
            return x;
        }
        return simple_name(true);
    }

    node* scope_chain(node* inner)
    {
        node* q = make(k_qname);
        std::vector<node*> rev{inner};
        while (!eat('@')) {
            if (fail || empty())
                return fail = true, nullptr;
            node* piece = scope_piece();
            if (fail)
                return nullptr;
            rev.push_back(piece);
            if (rev.size() > 256)
                return fail = true, nullptr;
        }
        q->list.assign(rev.rbegin(), rev.rend());
        return q;
    }

    node* fully_qualified_symbol_name()
    {
        node* id = unqualified_symbol_name(true);
        if (fail)
            return nullptr;
        node* q = scope_chain(id);
        if (fail)
            return nullptr;
        if (id->k == k_structor) {
            if (q->list.size() < 2)
                return fail = true, nullptr;
            id->a = q->list[q->list.size() - 2];
        }
        return q;
    }

    node* fully_qualified_type_name()
    {
        node* id = unqualified_type_name();
        if (fail)
            return nullptr;
        return scope_chain(id);
    }

    // ------------------------------------------------------------- template arguments

    void template_params(node* id)
    {
        id->has_tparams = true;
        while (!starts("@")) {
            if (fail || empty())
                return (void)(fail = true);
            if (eat("$S") || eat("$$V") || eat("$$$V") || eat("$$Z"))
                continue;
            node* arg = nullptr;
            if (eat("$M")) // auto non-type parameter: its type isn't printed
                return (void)(fail = true);
            if (eat("$$Y")) {
                arg = fully_qualified_type_name();
            } else if (eat("$$B")) {
                arg = type(0);
            } else if (eat("$$C")) {
                arg = type(2);
            } else if (starts("$1") || starts("$H") || starts("$I") || starts("$J")) {
                i++;
                char inh = s[i++];
                node* t = make(k_tpref);
                t->member_ptr = true;
                t->aff = 1;
                if (peek() == '?') {
                    t->a = parse();
                    if (fail || !t->a || !t->a->a)
                        return (void)(fail = true);
                    node* qn = t->a->a;
                    memorize(qn->list.back());
                }
                int count = inh == 'J' ? 3 : inh == 'I' ? 2 : inh == 'H' ? 1 : 0;
                for (int k = 0; k < count; k++)
                    t->offsets.push_back(signed_number());
                arg = t;
            } else if (starts("$E?")) {
                i += 2;
                node* t = make(k_tpref);
                t->a = parse();
                t->aff = 2;
                arg = t;
            } else if (starts("$F") || starts("$G")) {
                i++;
                char inh = s[i++];
                node* t = make(k_tpref);
                t->member_ptr = true;
                int count = inh == 'G' ? 3 : 2;
                for (int k = 0; k < count; k++)
                    t->offsets.push_back(signed_number());
                arg = t;
            } else if (eat("$0")) {
                uint64_t v = 0;
                bool neg = false;
                if (!number(v, neg))
                    return;
                arg = make(k_int);
                arg->value = v;
                arg->neg = neg;
            } else {
                arg = type(0);
            }
            if (fail || !arg)
                return (void)(fail = true);
            id->tparams.push_back(arg);
            if (id->tparams.size() > 256)
                return (void)(fail = true);
        }
        eat('@');
    }

    // ------------------------------------------------------------- types

    // qualifiers after a pointer / on a function: Q R S T are member ones
    unsigned qualifiers(bool& member)
    {
        if (empty())
            return fail = true, 0;
        char c = s[i++];
        member = c >= 'Q' && c <= 'T';
        switch (c) {
        case 'Q': case 'A': return 0;
        case 'R': case 'B': return q_const;
        case 'S': case 'C': return q_volatile;
        case 'T': case 'D': return q_const | q_volatile;
        default: return fail = true, 0;
        }
    }
    unsigned ext_qualifiers()
    {
        unsigned q = 0;
        if (eat('E'))
            q |= q_ptr64;
        if (eat('I'))
            q |= q_restrict;
        if (eat('F'))
            q |= q_unaligned;
        return q;
    }

    int calling_convention()
    {
        if (empty())
            return fail = true, 0;
        switch (s[i++]) {
        case 'A': case 'B': return 1;  // __cdecl
        case 'C': case 'D': return 2;  // __pascal
        case 'E': case 'F': return 3;  // __thiscall
        case 'G': case 'H': return 4;  // __stdcall
        case 'I': case 'J': return 5;  // __fastcall
        case 'M': case 'N': return 6;  // __clrcall
        case 'O': case 'P': return 7;  // __eabi
        case 'Q': return 8;            // __vectorcall
        case 'S': return 9;            // swiftcall
        case 'W': return 10;           // swiftasynccall
        default: return 0;
        }
    }

    // qmm: 0 drop, 1 result (optional ?<quals>), 2 mangle (quals first)
    node* type(int qmm)
    {
        deeper d(*this);
        if (fail)
            return nullptr;
        unsigned quals = 0;
        bool member = false;
        if (qmm == 2)
            quals = qualifiers(member);
        else if (qmm == 1 && eat('?'))
            quals = qualifiers(member);
        if (fail || empty())
            return fail = true, nullptr;
        node* t = nullptr;
        char c = peek();
        if (c == 'T' || c == 'U' || c == 'V' || c == 'W') {
            t = class_type();
        } else if (starts("$$Q") || c == 'A' || c == 'P' || c == 'Q' || c == 'R' || c == 'S') {
            bool bad = false;
            bool mem = is_member_pointer(bad);
            if (bad)
                return fail = true, nullptr;
            t = mem ? member_pointer_type() : pointer_type();
        } else if (c == 'Y') {
            t = array_type();
        } else if (starts("$$A8@@")) {
            i += 6;
            t = function_type(true);
        } else if (starts("$$A6")) {
            i += 4;
            t = function_type(false);
        } else if (c == '?') {
            i++;
            node* x = make(k_custom);
            x->a = unqualified_type_name();
            if (fail || !eat('@'))
                return fail = true, nullptr;
            t = x;
        } else {
            t = primitive_type();
        }
        if (fail || !t)
            return fail = true, nullptr;
        t->quals |= quals;
        return t;
    }

    bool is_member_pointer(bool& bad)
    {
        size_t k = i;
        char c = s[k++];
        if (c == '$' || c == 'A')
            return false;
        if (k >= n)
            return bad = true, false;
        if (is_digit(s[k])) {
            if (s[k] != '6' && s[k] != '8')
                return bad = true, false;
            return s[k] == '8';
        }
        if (k < n && s[k] == 'E')
            k++;
        if (k < n && s[k] == 'I')
            k++;
        if (k < n && s[k] == 'F')
            k++;
        if (k >= n)
            return bad = true, false;
        switch (s[k]) {
        case 'A': case 'B': case 'C': case 'D': return false;
        case 'Q': case 'R': case 'S': case 'T': return true;
        default: return bad = true, false;
        }
    }

    void pointer_cv(node* p)
    {
        if (eat("$$Q")) {
            p->aff = 3;
            return;
        }
        char c = s[i++];
        switch (c) {
        case 'A': p->aff = 2; break;
        case 'P': p->aff = 1; break;
        case 'Q': p->aff = 1; p->quals = q_const; break;
        case 'R': p->aff = 1; p->quals = q_volatile; break;
        case 'S': p->aff = 1; p->quals = q_const | q_volatile; break;
        default: fail = true;
        }
    }

    node* pointer_type()
    {
        node* p = make(k_ptr);
        pointer_cv(p);
        if (fail)
            return nullptr;
        if (eat('6')) {
            p->a = function_type(false);
            return p;
        }
        p->quals |= ext_qualifiers();
        p->a = type(2);
        return p;
    }

    node* member_pointer_type()
    {
        node* p = make(k_ptr);
        pointer_cv(p);
        if (fail)
            return nullptr;
        p->quals |= ext_qualifiers();
        if (eat('8')) {
            p->b = fully_qualified_type_name();
            if (fail)
                return nullptr;
            p->a = function_type(true);
        } else {
            bool member = false;
            unsigned pq = qualifiers(member);
            if (fail)
                return nullptr;
            if (!member)
                return fail = true, nullptr;
            p->b = fully_qualified_type_name();
            if (fail)
                return nullptr;
            p->a = type(0);
            if (p->a)
                p->a->quals = pq;
        }
        return p;
    }

    node* class_type()
    {
        node* t = make(k_tag);
        char c = s[i++];
        switch (c) {
        case 'T': t->s = "union"; break;
        case 'U': t->s = "struct"; break;
        case 'V': t->s = "class"; break;
        case 'W':
            if (!eat('4'))
                return fail = true, nullptr;
            t->s = "enum";
            break;
        }
        t->a = fully_qualified_type_name();
        return fail ? nullptr : t;
    }

    node* array_type()
    {
        i++; // Y
        uint64_t rank = 0;
        bool neg = false;
        if (!number(rank, neg) || neg || rank == 0 || rank > 64)
            return fail = true, nullptr;
        node* a = make(k_arr);
        for (uint64_t k = 0; k < rank; k++) {
            uint64_t dim = 0;
            if (!number(dim, neg) || neg)
                return fail = true, nullptr;
            node* x = make(k_int);
            x->value = dim;
            a->list.push_back(x);
        }
        if (eat("$$C")) {
            bool member = false;
            a->quals = qualifiers(member);
            if (member)
                return fail = true, nullptr;
        }
        a->a = type(0);
        return fail ? nullptr : a;
    }

    node* primitive_type()
    {
        if (eat("$$T"))
            return prim("std::nullptr_t");
        char c = s[i++];
        switch (c) {
        case 'X': return prim("void");
        case 'D': return prim("char");
        case 'C': return prim("signed char");
        case 'E': return prim("unsigned char");
        case 'F': return prim("short");
        case 'G': return prim("unsigned short");
        case 'H': return prim("int");
        case 'I': return prim("unsigned int");
        case 'J': return prim("long");
        case 'K': return prim("unsigned long");
        case 'M': return prim("float");
        case 'N': return prim("double");
        case 'O': return prim("long double");
        case '_': {
            if (empty())
                return fail = true, nullptr;
            char d = s[i++];
            switch (d) {
            case 'N': return prim("bool");
            case 'J': return prim("__int64");
            case 'K': return prim("unsigned __int64");
            case 'W': return prim("wchar_t");
            case 'Q': return prim("char8_t");
            case 'S': return prim("char16_t");
            case 'U': return prim("char32_t");
            }
            break;
        }
        }
        return fail = true, nullptr;
    }
    node* prim(const char* name)
    {
        node* x = make(k_prim);
        x->s = name;
        return x;
    }

    node* function_type(bool this_quals)
    {
        deeper d(*this);
        node* f = make(k_func);
        if (this_quals) {
            f->quals = ext_qualifiers();
            if (eat('G'))
                f->refq = 1;
            else if (eat('H'))
                f->refq = 2;
            bool member = false;
            f->quals |= qualifiers(member);
            if (fail)
                return nullptr;
        }
        f->cc = calling_convention();
        if (fail)
            return nullptr;
        if (!eat('@')) { // structors have no return type
            f->a = type(1);
            if (fail)
                return nullptr;
        }
        // parameters: X for none, else types up to @ (or Z for varargs)
        if (!eat('X')) {
            f->has_params = true;
            while (!fail && !starts("@") && !starts("Z")) {
                if (empty())
                    return fail = true, nullptr;
                if (is_digit(peek())) {
                    size_t k = (size_t)(s[i] - '0');
                    if (k >= br.params.size())
                        return fail = true, nullptr;
                    i++;
                    f->list.push_back(br.params[k]);
                    continue;
                }
                size_t before = i;
                node* t = type(0);
                if (fail || !t)
                    return fail = true, nullptr;
                f->list.push_back(t);
                if (br.params.size() <= 9 && i - before > 1)
                    br.params.push_back(t);
                if (f->list.size() > 256)
                    return fail = true, nullptr;
            }
            if (fail)
                return nullptr;
            if (!eat('@')) {
                if (eat('Z'))
                    f->variadic = true;
                else
                    return fail = true, nullptr;
            }
        }
        // throw specification
        if (eat("_E"))
            f->no_except = true;
        else if (!eat('Z'))
            return fail = true, nullptr;
        return f;
    }

    // ------------------------------------------------------------- symbols

    unsigned function_class()
    {
        if (empty())
            return fail = true, 0;
        char c = s[i++];
        switch (c) {
        case '9': return fc_extern_c | fc_no_params;
        case 'A': return fc_private;
        case 'B': return fc_private | fc_far;
        case 'C': return fc_private | fc_static;
        case 'D': return fc_private | fc_static | fc_far;
        case 'E': return fc_private | fc_virtual;
        case 'F': return fc_private | fc_virtual | fc_far;
        case 'G': return fc_private | fc_this_static;
        case 'H': return fc_private | fc_this_static | fc_far;
        case 'I': return fc_protected;
        case 'J': return fc_protected | fc_far;
        case 'K': return fc_protected | fc_static;
        case 'L': return fc_protected | fc_static | fc_far;
        case 'M': return fc_protected | fc_virtual;
        case 'N': return fc_protected | fc_virtual | fc_far;
        case 'O': return fc_protected | fc_virtual | fc_this_static;
        case 'P': return fc_protected | fc_virtual | fc_this_static | fc_far;
        case 'Q': return fc_public;
        case 'R': return fc_public | fc_far;
        case 'S': return fc_public | fc_static;
        case 'T': return fc_public | fc_static | fc_far;
        case 'U': return fc_public | fc_virtual;
        case 'V': return fc_public | fc_virtual | fc_far;
        case 'W': return fc_public | fc_virtual | fc_this_static;
        case 'X': return fc_public | fc_virtual | fc_this_static | fc_far;
        case 'Y': return fc_global;
        case 'Z': return fc_global | fc_far;
        case '$': {
            unsigned v = fc_this_virtual;
            if (eat('R'))
                v |= fc_this_virtual_ex;
            if (empty())
                break;
            switch (s[i++]) {
            case '0': return fc_private | fc_virtual | v;
            case '1': return fc_private | fc_virtual | v | fc_far;
            case '2': return fc_protected | fc_virtual | v;
            case '3': return fc_protected | fc_virtual | v | fc_far;
            case '4': return fc_public | fc_virtual | v;
            case '5': return fc_public | fc_virtual | v | fc_far;
            }
            break;
        }
        }
        return fail = true, 0;
    }

    node* function_encoding()
    {
        unsigned extra = eat("$$J0") ? fc_extern_c : 0;
        if (empty())
            return fail = true, nullptr;
        unsigned fc = function_class() | extra;
        if (fail)
            return nullptr;
        std::vector<int64_t> offsets;
        if (fc & fc_this_static) {
            offsets.push_back(signed_number());
        } else if (fc & fc_this_virtual) {
            if (fc & fc_this_virtual_ex) {
                offsets.push_back(signed_number());
                offsets.push_back(signed_number());
            }
            offsets.push_back(signed_number());
            offsets.push_back(signed_number());
        }
        node* sig;
        if (fc & fc_no_params) {
            sig = make(k_func);
        } else {
            sig = function_type(!(fc & (fc_global | fc_static)));
            if (fail)
                return nullptr;
        }
        sig->fc = fc;
        sig->offsets = offsets;
        sig->thunk = (fc & (fc_this_static | fc_this_virtual)) != 0;
        node* f = make(k_fsym);
        f->b = sig;
        return f;
    }

    node* variable_encoding(int sc)
    {
        node* v = make(k_vsym);
        v->sc = sc;
        v->b = type(0);
        if (fail)
            return nullptr;
        if (v->b->k == k_ptr) {
            v->b->quals |= ext_qualifiers();
            bool member = false;
            unsigned extra = qualifiers(member);
            if (fail)
                return nullptr;
            if (v->b->b) // a member pointer names its class again
                fully_qualified_type_name();
            if (v->b->a)
                v->b->a->quals |= extra;
        } else {
            bool member = false;
            v->b->quals = qualifiers(member);
        }
        return fail ? nullptr : v;
    }

    node* special_table(const char* what)
    {
        node* id = make(k_named);
        id->s = what;
        node* q = scope_chain(id);
        if (fail || empty())
            return fail = true, nullptr;
        char c = s[i++];
        if (c != '6' && c != '7')
            return fail = true, nullptr;
        node* t = make(k_table);
        t->a = q;
        bool member = false;
        t->quals = qualifiers(member);
        if (fail)
            return nullptr;
        if (!eat('@')) {
            t->b = fully_qualified_type_name();
            eat('@'); // ends the list of bases the table is for
        }
        return fail ? nullptr : t;
    }

    node* untyped_variable(const char* what)
    {
        node* id = make(k_named);
        id->s = what;
        node* v = make(k_vsym);
        v->a = scope_chain(id);
        if (fail || !eat('8'))
            return fail = true, nullptr;
        return v;
    }

    // after the leading ?: a special symbol (vftable, rtti), or name + encoding
    node* parse()
    {
        deeper d(*this);
        if (!eat('?'))
            return fail = true, nullptr;
        if (eat("?_7"))
            return special_table("`vftable'");
        if (eat("?_8"))
            return special_table("`vbtable'");
        if (eat("?_S"))
            return special_table("`local vftable'");
        if (eat("?_R4"))
            return special_table("`RTTI Complete Object Locator'");
        if (eat("?_R0")) {
            node* t = type(1);
            if (fail || !eat("@8") || !empty())
                return fail = true, nullptr;
            node* v = make(k_vsym);
            node* id = make(k_named);
            id->s = "`RTTI Type Descriptor'";
            node* q = make(k_qname);
            q->list.push_back(id);
            v->a = q;
            v->b = t;
            return v;
        }
        if (eat("?_R1")) {
            uint64_t nv = unsigned_number();
            int64_t vbptr = signed_number();
            uint64_t vbtable = unsigned_number();
            uint64_t flags = unsigned_number();
            if (fail)
                return nullptr;
            node* id = make(k_named);
            id->s = "`RTTI Base Class Descriptor at (" + std::to_string(nv) + ", " + std::to_string(vbptr) + ", " +
                    std::to_string(vbtable) + ", " + std::to_string(flags) + ")'";
            node* v = make(k_vsym);
            v->a = scope_chain(id);
            eat('8');
            return fail ? nullptr : v;
        }
        if (eat("?_R2"))
            return untyped_variable("`RTTI Base Class Array'");
        if (eat("?_R3"))
            return untyped_variable("`RTTI Class Hierarchy Descriptor'");
        if (eat("?_9")) {
            node* id = make(k_named);
            node* f = make(k_fsym);
            node* sig = make(k_func);
            sig->fc = fc_no_params;
            sig->thunk = true;
            f->b = sig;
            f->a = scope_chain(id);
            if (fail || !eat("$B"))
                return fail = true, nullptr;
            uint64_t off = unsigned_number();
            if (fail || !eat('A'))
                return fail = true, nullptr;
            sig->cc = calling_convention();
            id->s = "`vcall'{" + std::to_string(off) + ", {flat}}";
            return fail ? nullptr : f;
        }
        // string literals, guards, initializers (only in object files): not supported
        if (starts("?_A") || starts("?_B") || starts("?_C") || starts("?_P") ||
            starts("?__E") || starts("?__F") || starts("?__J") || starts("?@"))
            return fail = true, nullptr;
        node* qn = fully_qualified_symbol_name();
        if (fail || empty())
            return fail = true, nullptr;
        node* sym;
        char c = peek();
        if (c >= '0' && c <= '4') {
            i++;
            int sc = c == '0' ? 1 : c == '1' ? 2 : c == '2' ? 3 : 0;
            sym = variable_encoding(sc);
        } else {
            sym = function_encoding();
        }
        if (fail || !sym)
            return fail = true, nullptr;
        sym->a = qn;
        node* last = qn->list.back();
        if (last->k == k_convop) {
            if (sym->k != k_fsym || !sym->b->a)
                return fail = true, nullptr;
            last->a = sym->b->a; // the target type is the return type
        }
        return sym;
    }

    // ------------------------------------------------------------- printing (as llvm-undname)

    static void space_if_needed(std::string& o)
    {
        if (o.empty())
            return;
        char c = o.back();
        if (is_digit(c) || is_lower(c) || is_upper(c) || c == '>')
            o += ' ';
    }
    static void quals_out(std::string& o, unsigned q, bool before, bool after)
    {
        size_t p = o.size();
        if (q & q_const) {
            if (before)
                o += ' ';
            o += "const";
            before = true;
        }
        if (q & q_volatile) {
            if (before)
                o += ' ';
            o += "volatile";
            before = true;
        }
        if (q & q_restrict) {
            if (before)
                o += ' ';
            o += "__restrict";
        }
        if (after && o.size() > p)
            o += ' ';
    }
    static void cc_out(std::string& o, int cc)
    {
        space_if_needed(o);
        static const char* const names[] = {"", "__cdecl", "__pascal", "__thiscall", "__stdcall", "__fastcall",
            "__clrcall", "__eabi", "__vectorcall", "__attribute__((__swiftcall__)) ",
            "__attribute__((__swiftasynccall__)) "};
        if (cc > 0 && cc <= 10)
            o += names[cc];
    }

    void tparams_out(std::string& o, const node* id, unsigned fl)
    {
        if (!id->has_tparams)
            return;
        o += '<';
        for (size_t k = 0; k < id->tparams.size(); k++) {
            if (k)
                o += ", ";
            out(o, id->tparams[k], fl);
        }
        o += '>';
    }

    void pre(std::string& o, const node* t, unsigned fl)
    {
        if (o.size() > max_out * 2)
            return (void)(fail = true);
        switch (t->k) {
        case k_prim:
            o += t->s;
            quals_out(o, t->quals, true, false);
            break;
        case k_tag:
            if (!(fl & of_no_tag))
                o += t->s + " ";
            out(o, t->a, fl);
            quals_out(o, t->quals, true, false);
            break;
        case k_custom:
            out(o, t->a, fl);
            break;
        case k_arr:
            pre(o, t->a, fl);
            quals_out(o, t->quals, true, false);
            break;
        case k_ptr: {
            const node* pe = t->a;
            if (pe->k == k_func)
                pre(o, pe, of_no_cc);
            else
                pre(o, pe, fl);
            space_if_needed(o);
            if (t->quals & q_unaligned)
                o += "__unaligned ";
            if (pe->k == k_arr) {
                o += '(';
            } else if (pe->k == k_func) {
                o += '(';
                cc_out(o, pe->cc);
                o += ' ';
            }
            if (t->b) {
                out(o, t->b, fl);
                o += "::";
            }
            o += t->aff == 1 ? "*" : t->aff == 2 ? "&" : "&&";
            quals_out(o, t->quals, false, false);
            break;
        }
        case k_func:
            func_pre(o, t, fl);
            break;
        default:
            break;
        }
    }

    void post(std::string& o, const node* t, unsigned fl)
    {
        switch (t->k) {
        case k_arr:
            o += '[';
            for (size_t k = 0; k < t->list.size(); k++) {
                if (k)
                    o += "][";
                if (t->list[k]->value != 0)
                    o += std::to_string(t->list[k]->value);
            }
            o += ']';
            post(o, t->a, fl);
            break;
        case k_ptr:
            if (t->a->k == k_arr || t->a->k == k_func)
                o += ')';
            post(o, t->a, fl);
            break;
        case k_func:
            func_post(o, t, fl);
            break;
        default:
            break;
        }
    }

    void func_pre(std::string& o, const node* f, unsigned fl)
    {
        if (f->thunk)
            o += "[thunk]: ";
        if (!(fl & of_no_access)) {
            if (f->fc & fc_public)
                o += "public: ";
            if (f->fc & fc_protected)
                o += "protected: ";
            if (f->fc & fc_private)
                o += "private: ";
        }
        if (!(fl & of_no_member)) {
            if (!(f->fc & fc_global) && (f->fc & fc_static))
                o += "static ";
            if (f->fc & fc_virtual)
                o += "virtual ";
            if (f->fc & fc_extern_c)
                o += "extern \"C\" ";
        }
        if (!(fl & of_no_ret) && f->a) {
            pre(o, f->a, fl);
            o += ' ';
        }
        if (!(fl & of_no_cc))
            cc_out(o, f->cc);
    }

    void func_post(std::string& o, const node* f, unsigned fl)
    {
        auto s32 = [](int64_t v) { return std::to_string((int32_t)(uint32_t)(uint64_t)v); };
        auto u32 = [](int64_t v) { return std::to_string((uint32_t)(uint64_t)v); };
        if (f->fc & fc_this_static) {
            o += "`adjustor{" + u32(f->offsets.empty() ? 0 : f->offsets[0]) + "}'";
        } else if (f->fc & fc_this_virtual) {
            if (f->fc & fc_this_virtual_ex && f->offsets.size() == 4)
                o += "`vtordispex{" + s32(f->offsets[0]) + ", " + s32(f->offsets[1]) + ", " + s32(f->offsets[2]) +
                     ", " + u32(f->offsets[3]) + "}'";
            else if (f->offsets.size() >= 2)
                o += "`vtordisp{" + s32(f->offsets[0]) + ", " + u32(f->offsets[1]) + "}'";
        }
        if (!(f->fc & fc_no_params)) {
            o += '(';
            if (f->has_params) {
                for (size_t k = 0; k < f->list.size(); k++) {
                    if (k)
                        o += ", ";
                    out(o, f->list[k], fl);
                }
            } else {
                o += "void";
            }
            if (f->variadic) {
                if (o.back() != '(')
                    o += ", ";
                o += "...";
            }
            o += ')';
        }
        if (f->quals & q_const)
            o += " const";
        if (f->quals & q_volatile)
            o += " volatile";
        if (f->quals & q_restrict)
            o += " __restrict";
        if (f->quals & q_unaligned)
            o += " __unaligned";
        if (f->no_except)
            o += " noexcept";
        if (f->refq == 1)
            o += " &";
        else if (f->refq == 2)
            o += " &&";
        if (!(fl & of_no_ret) && f->a)
            post(o, f->a, fl);
    }

    void out(std::string& o, const node* x, unsigned fl)
    {
        if (!x || fail)
            return;
        deeper d(*this);
        if (fail)
            return;
        switch (x->k) {
        case k_prim:
        case k_tag:
        case k_custom:
        case k_arr:
        case k_ptr:
        case k_func:
            pre(o, x, fl);
            post(o, x, fl);
            break;
        case k_named:
        case k_intrin:
            o += x->s;
            tparams_out(o, x, fl);
            break;
        case k_structor:
            if (x->is_dtor)
                o += '~';
            out(o, x->a, fl);
            tparams_out(o, x, fl);
            break;
        case k_convop:
            o += "operator";
            tparams_out(o, x, fl);
            o += ' ';
            out(o, x->a, fl);
            break;
        case k_litop:
            o += "operator \"\"" + x->s;
            tparams_out(o, x, fl);
            break;
        case k_qname:
            for (size_t k = 0; k < x->list.size(); k++) {
                if (k)
                    o += "::";
                out(o, x->list[k], fl);
            }
            break;
        case k_int:
            if (x->neg)
                o += '-';
            o += std::to_string(x->value);
            break;
        case k_tpref:
            if (!x->offsets.empty())
                o += '{';
            else if (x->aff == 1)
                o += '&';
            if (x->a) {
                out(o, x->a, fl);
                if (!x->offsets.empty())
                    o += ", ";
            }
            for (size_t k = 0; k < x->offsets.size(); k++) {
                if (k)
                    o += ", ";
                o += std::to_string(x->offsets[k]);
            }
            if (!x->offsets.empty())
                o += '}';
            break;
        case k_fsym:
            pre(o, x->b, fl);
            space_if_needed(o);
            out(o, x->a, fl);
            post(o, x->b, fl);
            break;
        case k_vsym: {
            const char* acc = x->sc == 1 ? "private" : x->sc == 2 ? "protected" : x->sc == 3 ? "public" : nullptr;
            if (!(fl & of_no_access) && acc)
                o += std::string(acc) + ": ";
            if (!(fl & of_no_member) && acc)
                o += "static ";
            if (!(fl & of_no_vartype) && x->b) {
                pre(o, x->b, fl);
                space_if_needed(o);
            }
            out(o, x->a, fl);
            if (!(fl & of_no_vartype) && x->b)
                post(o, x->b, fl);
            break;
        }
        case k_table:
            quals_out(o, x->quals, false, true);
            out(o, x->a, fl);
            if (x->b) {
                o += "{for `";
                out(o, x->b, fl);
                o += "'}";
            }
            break;
        }
    }
};

const unsigned msvc_short_flags = msvc::of_no_cc | msvc::of_no_access | msvc::of_no_member | msvc::of_no_ret |
                                  msvc::of_no_vartype;

// name_out: the name alone; display_out: a function's name with parameters, else the name;
// full_out: llvm-undname's text with its --no-* flags
bool run_msvc(const std::string& in, std::string& name_out, std::string& display_out, std::string& full_out)
{
    if (in.size() > max_input || in.empty() || in[0] != '?')
        return false;
    msvc m(in.data(), in.size());
    msvc::node* sym = m.parse();
    if (m.fail || !sym || !m.empty())
        return false;
    std::string full;
    m.out(full, sym, msvc_short_flags);
    std::string nm;
    if (sym->k == msvc::k_vsym && sym->b) { // rtti type descriptor: keep the type in the name
        m.out(nm, sym, 0);
    } else if (sym->k == msvc::k_table) {
        m.out(nm, sym->a, msvc_short_flags);
        if (sym->b) {
            nm += "{for `";
            m.out(nm, sym->b, msvc_short_flags);
            nm += "'}";
        }
    } else {
        m.out(nm, sym->a, msvc_short_flags);
    }
    if (m.fail || full.size() > max_out || nm.empty() || nm.size() > max_out)
        return false;
    name_out = nm;
    display_out = sym->k == msvc::k_fsym ? full : nm;
    full_out = full;
    return true;
}

// ---- shorter c++ library names, for the listing (full() keeps the exact spelling) ----
//
//   std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char>>     std::string
//   std::vector<int, std::allocator<int>>                                              std::vector<int>
//   std::map<int, char, std::less<int>, std::allocator<std::pair<int const, char>>>    std::map<int, char>
//
// template arguments that are the defaults go, the way the source spells the type, and the
// inline namespaces the libraries hide their versions in (__cxx11, __1). anything the scan
// doesn't follow comes back unchanged

struct simplifier {
    const std::string& s;
    size_t i = 0;
    int depth = 0;
    bool bad = false;

    explicit simplifier(const std::string& text) : s(text) {}

    static bool ident(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'; }

    // msvc names say class / struct / union / enum before types; compare without them
    static std::string norm(const std::string& x)
    {
        std::string r;
        for (size_t k = 0; k < x.size();) {
            bool start = k == 0 || x[k - 1] == '<' || x[k - 1] == ' ' || x[k - 1] == ',' || x[k - 1] == '(';
            size_t skip = 0;
            if (start)
                for (const char* w : {"class ", "struct ", "union ", "enum "})
                    if (x.compare(k, strlen(w), w) == 0)
                        skip = strlen(w);
            if (skip) {
                k += skip;
                continue;
            }
            r += x[k++];
        }
        return r;
    }

    // the default of template argument k of std template t, given the arguments before it
    static std::string default_arg(const std::string& t, const std::vector<std::string>& a, size_t k)
    {
        const std::string& a0 = a[0];
        auto is = [&](std::initializer_list<const char*> names) {
            for (const char* n : names)
                if (t == n)
                    return true;
            return false;
        };
        if (is({"std::vector", "std::deque", "std::list", "std::forward_list"}))
            return k == 1 ? "std::allocator<" + a0 + ">" : "";
        if (is({"std::set", "std::multiset"}))
            return k == 1 ? "std::less<" + a0 + ">" : k == 2 ? "std::allocator<" + a0 + ">" : "";
        if (is({"std::map", "std::multimap"}))
            return k == 2 ? "std::less<" + a0 + ">" : k == 3 ? "std::allocator<std::pair<" + a0 + " const, " + a[1] + ">>" : "";
        if (is({"std::unordered_set", "std::unordered_multiset"}))
            return k == 1 ? "std::hash<" + a0 + ">" : k == 2 ? "std::equal_to<" + a0 + ">" : k == 3 ? "std::allocator<" + a0 + ">" : "";
        if (is({"std::unordered_map", "std::unordered_multimap"}))
            return k == 2 ? "std::hash<" + a0 + ">" : k == 3 ? "std::equal_to<" + a0 + ">"
                : k == 4 ? "std::allocator<std::pair<" + a0 + " const, " + a[1] + ">>" : "";
        if (is({"std::basic_string", "std::basic_ostringstream", "std::basic_istringstream", "std::basic_stringstream",
                "std::basic_stringbuf"}))
            return k == 1 ? "std::char_traits<" + a0 + ">" : k == 2 ? "std::allocator<" + a0 + ">" : "";
        if (is({"std::basic_string_view", "std::basic_ostream", "std::basic_istream", "std::basic_iostream", "std::basic_ios",
                "std::basic_streambuf", "std::basic_filebuf", "std::basic_ofstream", "std::basic_ifstream", "std::basic_fstream",
                "std::istreambuf_iterator", "std::ostreambuf_iterator"}))
            return k == 1 ? "std::char_traits<" + a0 + ">" : "";
        if (t == "std::basic_regex")
            return k == 1 ? "std::regex_traits<" + a0 + ">" : "";
        if (t == "std::unique_ptr")
            return k == 1 ? "std::default_delete<" + a0 + ">" : "";
        if (t == "std::queue" || t == "std::stack")
            return k == 1 ? "std::deque<" + a0 + ">" : "";
        if (t == "std::priority_queue")
            return k == 1 ? "std::vector<" + a0 + ">" : k == 2 ? "std::less<" + a0 + ">" : "";
        return "";
    }

    // name<args>, shortened. member: name is "::vector" of an enclosing std template, the way
    // msvc names a constructor (std::vector<int>::vector<int, std::allocator<int>>)
    static std::string render(const std::string& name, std::vector<std::string> a, bool member)
    {
        // the template the rules look at: std::vector. a member named like its class (msvc's
        // constructors: std::string::basic_string<char, ...>) goes by that class
        std::string t = member ? "std" + name : name;
        size_t last = t.rfind("::");
        if (t.compare(0, 5, "std::") == 0 && last != std::string::npos) {
            std::string x = "std::" + t.substr(last + 2 + (t.compare(last + 2, 1, "~") == 0));
            member = member || x != t;
            t = x;
        }
        if (t.compare(0, 5, "std::") == 0 && !a.empty()) {
            std::vector<std::string> na;
            for (const std::string& x : a)
                na.push_back(norm(x));
            while (na.size() > 1) {
                std::string d = default_arg(t, na, na.size() - 1);
                if (d.empty() || d != na.back())
                    break;
                na.pop_back();
                a.pop_back();
            }
            if (a.size() == 1 && !member) {
                static const char* const strings[][2] = {
                    {"std::basic_string", "string"}, {"std::basic_string_view", "string_view"},
                    {"std::basic_ostream", "ostream"}, {"std::basic_istream", "istream"}, {"std::basic_iostream", "iostream"},
                    {"std::basic_ios", "ios"}, {"std::basic_streambuf", "streambuf"}, {"std::basic_filebuf", "filebuf"},
                    {"std::basic_ofstream", "ofstream"}, {"std::basic_ifstream", "ifstream"}, {"std::basic_fstream", "fstream"},
                    {"std::basic_ostringstream", "ostringstream"}, {"std::basic_istringstream", "istringstream"},
                    {"std::basic_stringstream", "stringstream"}, {"std::basic_stringbuf", "stringbuf"},
                    {"std::basic_regex", "regex"}};
                const std::string& c = na[0];
                const char* pre = c == "char" ? "" : c == "wchar_t" ? "w" : nullptr;
                bool str = t == "std::basic_string" || t == "std::basic_string_view";
                if (!pre && str)
                    pre = c == "char8_t" ? "u8" : c == "char16_t" ? "u16" : c == "char32_t" ? "u32" : nullptr;
                if (pre)
                    for (const auto& e : strings)
                        if (t == e[0])
                            return std::string("std::") + pre + e[1];
            }
        }
        std::string r = name + "<";
        for (size_t k = 0; k < a.size(); k++)
            r += (k ? ", " : "") + a[k];
        return r + ">";
    }

    // from '<': the arguments, each shortened, to the matching '>'
    std::string tlist(const std::string& name, bool member = false)
    {
        i++;
        std::vector<std::string> args;
        for (;;) {
            std::string a = walk(1);
            if (bad || i >= s.size())
                return bad = true, "";
            size_t b = a.find_first_not_of(' ');
            args.push_back(b == std::string::npos ? std::string() : a.substr(b));
            if (s[i++] == '>')
                break;
        }
        if (args.size() == 1 && args[0].empty())
            args.clear();
        return render(name, args, member);
    }

    // out ends with "...>::name": the enclosing template's name (before its '<') is a std:: one
    static bool std_member(const std::string& out, size_t k)
    {
        if (k < 3 || out.compare(k, 2, "::") != 0 || out[k - 1] != '>')
            return false;
        int d = 0;
        size_t j = k;
        while (j > 0) {
            char c = out[--j];
            if (c == '>')
                d++;
            else if (c == '<' && --d == 0)
                break;
        }
        if (d != 0)
            return false;
        size_t e = j;
        while (j > 0 && (ident(out[j - 1]) || out[j - 1] == ':'))
            j--;
        return out.compare(j, 5, "std::") == 0 && e - j > 5;
    }

    // mode 0: to the end. 1: one template argument (stops before ',' or '>' outside parentheses).
    // 2: inside parentheses (stops after the closing one)
    std::string walk(int mode)
    {
        std::string out;
        if (++depth > 64)
            return bad = true, out;
        while (i < s.size() && !bad) {
            char c = s[i];
            if (mode == 1 && (c == ',' || c == '>'))
                break;
            if (c == ')') {
                if (mode != 2)
                    return bad = true, out;
                out += c;
                i++;
                break;
            }
            if (c == '(') {
                out += c;
                i++;
                out += walk(2);
                continue;
            }
            // operator<, operator<<, operator->, ...: which of those it is decides where a
            // template argument list starts ("operator<<<char>" is operator<< of <char>)
            size_t ol = out.size();
            if ((c == '<' || c == '>' || c == '-') && ol >= 8 && out.compare(ol - 8, 8, "operator") == 0 &&
                (ol == 8 || !ident(out[ol - 9]))) {
                std::string op;
                for (const char* o : {"<=>", "<<=", ">>=", "->*", "<<", ">>", "<=", ">=", "->", "<", ">"}) {
                    size_t len = strlen(o);
                    if (s.compare(i, len, o) != 0)
                        continue;
                    char after = i + len < s.size() ? s[i + len] : '\0';
                    if (after == '(' || after == '<' || after == '\0' || after == ' ' || after == ')' ||
                        (mode == 1 && (after == ',' || after == '>'))) {
                        op = o;
                        break;
                    }
                }
                if (op.empty())
                    return bad = true, out;
                out += op;
                i += op.size();
                if (i < s.size() && s[i] == '<')
                    out += tlist("");
                continue;
            }
            if (c == '<' && !out.empty() && ident(out.back())) {
                size_t k = out.size();
                while (k > 0) {
                    if (ident(out[k - 1]))
                        k--;
                    else if (k >= 2 && out[k - 1] == ':' && out[k - 2] == ':')
                        k -= 2;
                    else if (k >= 3 && out[k - 1] == '~' && out[k - 2] == ':' && out[k - 3] == ':')
                        k--; // a destructor
                    else
                        break;
                }
                // msvc: "class std::vector<...>" keeps its word
                std::string name = out.substr(k);
                bool member = std_member(out, k) && name.find("::", 2) == std::string::npos;
                out.resize(k);
                out += tlist(name, member);
                continue;
            }
            out += c;
            i++;
        }
        depth--;
        return out;
    }
};

std::string simplify(const std::string& in)
{
    if (in.find('<') == std::string::npos && in.find("std::__") == std::string::npos)
        return in;
    // the inline namespaces: std::__cxx11::basic_string (libstdc++), std::__1::vector (libc++)
    std::string t;
    t.reserve(in.size());
    for (size_t k = 0; k < in.size();) {
        if (in.compare(k, 7, "std::__") == 0 && (k == 0 || !simplifier::ident(in[k - 1]))) {
            size_t skip = 0;
            for (const char* ns : {"std::__cxx11::", "std::__1::", "std::__2::", "std::__ndk1::"})
                if (in.compare(k, strlen(ns), ns) == 0)
                    skip = strlen(ns);
            if (skip) {
                t += "std::";
                k += skip;
                continue;
            }
        }
        t += in[k++];
    }
    simplifier sp(t);
    std::string r = sp.walk(0);
    return sp.bad || sp.i != t.size() ? t : r;
}

} // namespace

bool is_mangled(const std::string& s)
{
    if (s.size() > 2 && s[0] == '_' && s[1] == 'Z')
        return true;
    if (s.size() > 3 && s[0] == '_' && s[1] == '_' && s[2] == 'Z')
        return true;
    if (s.size() > 4 && s.compare(0, 4, "___Z") == 0)
        return true;
    if (s.size() > 2 && s[0] == '_' && s[1] == 'R')
        return true;
    if (!s.empty() && s[0] == '?')
        return true;
    return false;
}

result run(const std::string& s)
{
    result r;
    if (!is_mangled(s))
        return r;
    std::string x;
    if (run_rust_legacy(s, x) || run_rust_v0(s, x)) {
        r.ok = true;
        r.display = r.name = x;
        return r;
    }
    std::string q, f, sig;
    if (run_itanium(s, q, f, sig) || run_msvc(s, q, sig, f)) {
        r.ok = true;
        r.display = simplify(sig);
        r.name = simplify(q);
        return r;
    }
    return r;
}

std::string name(const std::string& s)
{
    return run(s).name;
}

std::string full(const std::string& s)
{
    if (!is_mangled(s))
        return "";
    std::string x;
    if (run_rust_legacy(s, x) || run_rust_v0(s, x))
        return x;
    std::string q, f, sig;
    if (run_itanium(s, q, f, sig) || run_msvc(s, q, sig, f))
        return f;
    return "";
}

} // namespace demangle
