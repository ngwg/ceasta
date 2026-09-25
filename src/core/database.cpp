#include "core/database.h"
#include "core/os.h"
#include "core/util.h"
#include <algorithm>
#include <cctype>

namespace {

bool is_alnum(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

bool is_name_char(char c)
{
    return is_alnum(c) || (c != 0 && strchr("_@$?.:<>~", c) != nullptr);
}

// names we generate ourselves ("sub_401000"), gives back the address
bool parse_auto(const std::string& s, uint64_t& out)
{
    static const char* const prefixes[] = {"sub_", "loc_", "unk_", "byte_", "word_", "dword_",
        "qword_", "xmmword_", "off_", "jpt_", "asc_"};
    for (const char* p : prefixes) {
        size_t n = strlen(p);
        if (s.size() > n && s.compare(0, n, p) == 0)
            return util::parse_hex(s.substr(n), out);
    }
    return false;
}

// "Hello world" -> "aHelloWorld", like ida
std::string string_name(const std::string& text)
{
    std::string out = "a";
    bool up = true;
    for (char c : text) {
        if (is_alnum(c)) {
            out += (up && c >= 'a' && c <= 'z') ? (char)(c - 'a' + 'A') : c;
            up = false;
        } else {
            up = true;
        }
        if (out.size() >= 24)
            break;
    }
    return out.size() > 1 ? out : std::string();
}

bool replace_hex_token(std::string& s, uint64_t v, const std::string& repl)
{
    std::string tok = "0x" + util::hex_lower(v);
    size_t p = 0;
    while ((p = s.find(tok, p)) != std::string::npos) {
        size_t e = p + tok.size();
        bool left_ok = p == 0 || !is_alnum(s[p - 1]);
        bool right_ok = e >= s.size() || util::hex_digit(s[e]) < 0;
        if (left_ok && right_ok) {
            s.replace(p, tok.size(), repl);
            return true;
        }
        p = e;
    }
    return false;
}

std::string escape_line(const std::string& s)
{
    std::string out;
    for (char c : s) {
        if (c == '\\')
            out += "\\\\";
        else if (c == '\n')
            out += "\\n";
        else if (c == '\r')
            out += "\\r";
        else
            out += c;
    }
    return out;
}

std::string unescape_line(const std::string& s)
{
    std::string out;
    for (size_t i = 0; i < s.size(); i++) {
        if (s[i] == '\\' && i + 1 < s.size()) {
            char n = s[++i];
            out += n == 'n' ? '\n' : n == 'r' ? '\r' : n;
        } else {
            out += s[i];
        }
    }
    return out;
}

const char* perm_text(uint32_t p)
{
    static const char* const t[] = {"---", "r--", "-w-", "rw-", "--x", "r-x", "-wx", "rwx"};
    return t[p & 7];
}

}

void database::build()
{
    dis_.open(bin.arch);
    digits_ = bin.max_addr() > 0x100000000ull ? 16 : 8;
    crc = util::crc32(bin.file.data(), bin.file.size());
    build_names();
    rows_dirty_ = true;
}

void database::claim_name(uint64_t a, const std::string& base)
{
    if (base.empty() || names_.count(a))
        return;
    std::string n = base;
    for (int i = 0; by_name_.count(n); i++)
        n = base + "_" + std::to_string(i);
    names_[a] = n;
    by_name_[n] = a;
}

void database::build_names()
{
    names_.clear();
    by_name_.clear();
    // strongest names first, an address keeps the first name it gets
    for (const symbol_entry& s : bin.symbols)
        claim_name(s.addr, s.name);
    for (const export_entry& e : bin.exports)
        if (e.addr)
            claim_name(e.addr, e.name);
    for (const import_entry& im : bin.imports)
        claim_name(im.slot, im.name);
    if (bin.has_entry)
        claim_name(bin.entry, "start");

    std::vector<std::pair<uint64_t, uint32_t>> thunks(an.thunk_import.begin(), an.thunk_import.end());
    std::sort(thunks.begin(), thunks.end());
    for (const auto& t : thunks)
        claim_name(t.first, "j_" + bin.imports[t.second].name);
    for (const function& f : an.funcs) {
        if (!f.thunk || an.thunk_import.count(f.start))
            continue;
        auto it = names_.find(f.thunk_target);
        if (it != names_.end())
            claim_name(f.start, "j_" + it->second);
    }
    for (const string_item& s : an.strings) {
        std::string n = string_name(s.text);
        claim_name(s.addr, n.empty() ? "asc_" + util::hex(s.addr) : n);
    }
    std::vector<uint64_t> tables;
    for (const auto& t : an.tables)
        tables.push_back(t.second.table);
    std::sort(tables.begin(), tables.end());
    for (uint64_t t : tables)
        claim_name(t, "jpt_" + util::hex(t));
    for (const auto& u : user_names)
        by_name_[u.second] = u.first;
}

std::string database::auto_name(uint64_t a) const
{
    uint8_t f = an.flags_at(a);
    if (f & fl_func)
        return "sub_" + util::hex(a);
    if (f & fl_code)
        return (f & fl_label) ? "loc_" + util::hex(a) : std::string();
    if (f & fl_data) {
        auto it = an.data_sizes.find(a);
        uint8_t sz = it != an.data_sizes.end() ? it->second : 1;
        uint64_t v;
        if (sz == bin.ptr_size() && bin.read_ptr(a, v) && v && bin.is_mapped(v))
            return "off_" + util::hex(a);
        const char* p = sz == 1 ? "byte_" : sz == 2 ? "word_" : sz == 4 ? "dword_" : sz == 8 ? "qword_" : sz == 16 ? "xmmword_" : "unk_";
        return p + util::hex(a);
    }
    if (f & fl_str)
        return "asc_" + util::hex(a);
    if (f & fl_label)
        return "unk_" + util::hex(a);
    return std::string();
}

std::string database::name_at(uint64_t a) const
{
    auto u = user_names.find(a);
    if (u != user_names.end())
        return u->second;
    auto n = names_.find(a);
    if (n != names_.end())
        return n->second;
    return auto_name(a);
}

std::string database::location(uint64_t a) const
{
    std::string n = name_at(a);
    if (!n.empty())
        return n;
    const function* f = an.func_containing(a);
    if (f)
        return name_at(f->start) + "+" + util::hex(a - f->start);
    // inside a named variable (an array, a struct): buf+2
    uint64_t head = an.item_head(a);
    if (head != a && !(n = name_at(head)).empty())
        return n + "+" + util::hex(a - head);
    return fmt_addr(a);
}

bool database::check_name(uint64_t a, const std::string& name, std::string& err) const
{
    std::string n = util::trim(name);
    if (!bin.is_mapped(a)) {
        err = "address " + fmt_addr(a) + " isn't mapped";
        return false;
    }
    if (n.empty())
        return true;
    if (n.size() > 255) {
        err = "name is too long";
        return false;
    }
    for (char c : n)
        if (!is_name_char(c)) {
            err = "names can only use letters, digits and _ @ $ ? . : < > ~";
            return false;
        }
    if (n[0] >= '0' && n[0] <= '9') {
        err = "names can't start with a digit";
        return false;
    }
    uint64_t dummy;
    if (parse_auto(n, dummy)) {
        err = "that prefix is used for automatic names";
        return false;
    }
    auto used = by_name_.find(n);
    if (used != by_name_.end() && used->second != a) {
        err = "name is already used at " + fmt_addr(used->second);
        return false;
    }
    return true;
}

// ---- names an ai suggested

bool database::suggest(uint64_t addr, const std::string& var, const std::string& name, const std::string& reason,
                       std::string& err)
{
    std::string n = util::trim(name);
    if (n.empty()) {
        err = "the name is empty";
        return false;
    }
    if (var.empty() ? !check_name(addr, n, err) : (!is_identifier(n) || is_reserved_word(n))) {
        if (!var.empty())
            err = "a variable's name is letters, digits and _, and not a c keyword";
        return false;
    }
    std::string why = util::trim(reason);
    for (char& c : why)
        if (c == '\n' || c == '\r' || c == '\t')
            c = ' ';
    for (suggestion& s : suggestions)
        if (s.addr == addr && s.var == var) {
            s.name = n;
            s.reason = why;
            dirty = true;
            return true;
        }
    suggestions.push_back({addr, var, n, why});
    dirty = true;
    return true;
}

bool database::accept_suggestion(size_t i, std::string& err)
{
    if (i >= suggestions.size())
        return false;
    suggestion s = suggestions[i];
    bool ok;
    if (s.var.empty()) {
        ok = set_name(s.addr, s.name, err);
    } else {
        std::string type;
        auto f = lvars.find(s.addr);
        if (f != lvars.end() && f->second.count(s.var))
            type = f->second.at(s.var).type;
        ok = set_lvar(s.addr, s.var, s.name, type, err);
    }
    if (ok) {
        suggestions.erase(suggestions.begin() + (std::ptrdiff_t)i);
        dirty = true;
    }
    return ok;
}

void database::reject_suggestion(size_t i)
{
    if (i < suggestions.size()) {
        suggestions.erase(suggestions.begin() + (std::ptrdiff_t)i);
        dirty = true;
    }
}

bool database::set_name(uint64_t a, const std::string& name, std::string& err)
{
    std::string n = util::trim(name);
    if (!bin.is_mapped(a)) {
        err = "address " + fmt_addr(a) + " isn't mapped";
        return false;
    }
    auto old = user_names.find(a);
    std::string before = old != user_names.end() ? old->second : std::string();
    if (n.empty()) {
        record(edit_kind::name, a, before, std::string());
        if (old != user_names.end()) {
            auto b = by_name_.find(old->second);
            if (b != by_name_.end() && b->second == a)
                by_name_.erase(b);
            user_names.erase(old);
            // a stored name (symbol, import) becomes visible again
            auto s = names_.find(a);
            if (s != names_.end())
                by_name_[s->second] = a;
            dirty = true;
            arg_notes_.clear();
            noted_funcs_.clear();
        }
        return true;
    }
    if (n.size() > 255) {
        err = "name is too long";
        return false;
    }
    for (char c : n)
        if (!is_name_char(c)) {
            err = "names can only use letters, digits and _ @ $ ? . : < > ~";
            return false;
        }
    if (n[0] >= '0' && n[0] <= '9') {
        err = "names can't start with a digit";
        return false;
    }
    uint64_t dummy;
    if (parse_auto(n, dummy)) {
        err = "that prefix is used for automatic names";
        return false;
    }
    auto used = by_name_.find(n);
    if (used != by_name_.end() && used->second != a) {
        err = "name is already used at " + fmt_addr(used->second);
        return false;
    }
    if (old != user_names.end()) {
        auto b = by_name_.find(old->second);
        if (b != by_name_.end() && b->second == a)
            by_name_.erase(b);
    }
    record(edit_kind::name, a, before, n);
    user_names[a] = n;
    by_name_[n] = a;
    dirty = true;
    arg_notes_.clear(); // a name can make a call a well-known one (strcpy, CreateFileW)
    noted_funcs_.clear();
    // a named spot inside code needs its own label line
    uint8_t f = an.flags_at(a);
    bool tail = (f & fl_tail) && !(f & (fl_code | fl_str | fl_data));
    if (!tail && !(f & (fl_func | fl_label))) {
        an.add_flags(a, fl_label);
        rows_dirty_ = true;
    }
    return true;
}

std::string database::comment_at(uint64_t a) const
{
    auto it = user_comments.find(a);
    return it == user_comments.end() ? std::string() : it->second;
}

void database::set_comment(uint64_t a, const std::string& text)
{
    record(edit_kind::comment, a, comment_at(a), text);
    if (text.empty())
        user_comments.erase(a);
    else
        user_comments[a] = text;
    dirty = true;
}

void database::set_bookmark(uint64_t a, bool on, const std::string& note)
{
    auto it = bookmarks.find(a);
    // "+note" stands for a bookmark (even with an empty note), "" for none
    std::string before = it == bookmarks.end() ? std::string() : "+" + it->second;
    std::string after = on ? "+" + note : std::string();
    record(edit_kind::bookmark, a, before, after);
    if (on)
        bookmarks[a] = note;
    else if (it != bookmarks.end())
        bookmarks.erase(it);
    dirty = true;
}

// ---- the decompiler's variables and prototypes

static bool good_type(const std::string& t)
{
    if (t.size() > 120)
        return false;
    for (char c : t)
        if (!(std::isalnum((unsigned char)c) || c == '_' || c == ' ' || c == '*' || c == '&' || c == '[' || c == ']'))
            return false;
    return true;
}

bool database::set_lvar(uint64_t func, const std::string& key, const std::string& name, const std::string& type,
                        std::string& err)
{
    std::string n = util::trim(name), t = util::trim(type);
    if (!is_identifier(key)) {
        err = "no such variable";
        return false;
    }
    if (!n.empty() && (!is_identifier(n) || is_reserved_word(n))) {
        err = "a variable's name is letters, digits and _, and not a c keyword";
        return false;
    }
    if (!t.empty() && !good_type(t)) {
        err = "a type is words, * and [] (int, char*, DWORD, struct header*)";
        return false;
    }
    std::map<std::string, lvar>& vars = lvars[func];
    if (!n.empty())
        for (const auto& v : vars)
            if (v.first != key && (v.second.name == n || (v.second.name.empty() && v.first == n))) {
                err = "another variable in this function is called " + n;
                return false;
            }
    auto it = vars.find(key);
    std::string before = it == vars.end() ? std::string() : key + "\n" + it->second.name + "\t" + it->second.type;
    std::string after = n.empty() && t.empty() ? std::string() : key + "\n" + n + "\t" + t;
    record(edit_kind::lvar, func, before.empty() ? key + "\n\t" : before, after.empty() ? key + "\n\t" : after);
    if (n.empty() && t.empty()) {
        if (it != vars.end())
            vars.erase(it);
        if (vars.empty())
            lvars.erase(func);
    } else {
        vars[key] = {n, t};
    }
    dirty = true;
    return true;
}

bool database::set_proto(uint64_t func, const std::string& text, std::string& err)
{
    auto it = protos.find(func);
    std::string before = it == protos.end() ? std::string() : format_prototype(it->second);
    if (util::trim(text).empty()) {
        record(edit_kind::proto, func, before, std::string());
        if (it != protos.end())
            protos.erase(it);
        arg_notes_.clear();
        noted_funcs_.clear();
        dirty = true;
        return true;
    }
    prototype p;
    if (!parse_prototype(text, p, err))
        return false;
    for (const proto_param& pp : p.params)
        if (!good_type(pp.type) && pp.type.find("(*") == std::string::npos) {
            err = "the type of " + pp.name + " isn't one: " + pp.type;
            return false;
        }
    if (!good_type(p.ret)) {
        err = "the return type isn't one: " + p.ret;
        return false;
    }
    // a new name in the prototype renames the function
    std::string cur = name_at(func);
    if (!cur.empty() && p.name != cur && !applying_ && !set_name(func, p.name, err))
        return false;
    record(edit_kind::proto, func, before, format_prototype(p));
    protos[func] = p;
    arg_notes_.clear();
    noted_funcs_.clear();
    dirty = true;
    return true;
}

const prototype* database::callee_proto(uint64_t target) const
{
    auto own = protos.find(target);
    if (own != protos.end())
        return &own->second;
    const function* f = an.func_containing(target);
    if (f && f->start == target && f->thunk && f->thunk_target) { // a thunk: where it jumps
        auto p = protos.find(f->thunk_target);
        if (p != protos.end())
            return &p->second;
        if (const prototype* k = known_prototype(name_at(f->thunk_target)))
            return k;
    }
    std::string n = name_at(target);
    return n.empty() ? nullptr : known_prototype(n);
}

namespace {

// the 64-bit register a register name is part of: "r8d" -> "r8", "ecx" -> "rcx"
std::string reg64(const std::string& r)
{
    static const std::map<std::string, std::string> m = {
        {"rcx", "rcx"}, {"ecx", "rcx"}, {"cx", "rcx"}, {"cl", "rcx"}, {"rdx", "rdx"}, {"edx", "rdx"}, {"dx", "rdx"},
        {"dl", "rdx"}, {"rdi", "rdi"}, {"edi", "rdi"}, {"di", "rdi"}, {"dil", "rdi"}, {"rsi", "rsi"}, {"esi", "rsi"},
        {"si", "rsi"}, {"sil", "rsi"}};
    auto it = m.find(r);
    if (it != m.end())
        return it->second;
    if (r.size() >= 2 && r[0] == 'r' && std::isdigit((unsigned char)r[1])) {
        size_t e = 1;
        while (e < r.size() && std::isdigit((unsigned char)r[e]))
            e++;
        return r.substr(0, e);
    }
    return std::string();
}

bool writes_first(const char* m)
{
    static const std::set<std::string> w = {"mov", "movzx", "movsx", "movsxd", "movabs", "lea", "xor", "or", "and",
        "add", "sub", "inc", "dec", "neg", "not", "shl", "shr", "sar", "imul", "pop", "movd", "movq"};
    return w.count(m) != 0;
}

} // namespace

// for every call in f to something with a known prototype: the instructions before it that set
// its arguments (the closest one per argument), back to a label or another call
void database::note_args(const function& f)
{
    noted_funcs_.insert(f.start);
    std::vector<uint64_t> heads;
    for (uint64_t a = f.start; a < f.end && heads.size() < 200000;) {
        uint32_t sz = an.item_size(a);
        if (an.flags_at(a) & fl_code)
            heads.push_back(a);
        a += sz ? sz : 1;
    }
    bool pe = bin.format == bin_format::pe, x64 = bin.is64();
    static const char* const win64[] = {"rcx", "rdx", "r8", "r9"};
    static const char* const sysv[] = {"rdi", "rsi", "rdx", "rcx", "r8", "r9"};
    for (size_t i = 0; i < heads.size(); i++) {
        insn call;
        if (!decode(heads[i], call) || call.kind != flow::call)
            continue;
        const prototype* p = nullptr;
        if (call.has_target && !call.indirect)
            p = callee_proto(call.target);
        else if (call.has_mem && !call.is_lea) // call [__imp_CreateFileW]
            p = known_prototype(name_at(call.mem));
        if (!p || p->params.empty())
            continue;
        size_t nregs = !x64 ? 0 : pe ? 4 : 6;
        std::vector<bool> done(p->params.size(), false);
        int pushes = 0;
        for (size_t j = i; j-- > 0 && i - j <= 24;) {
            insn in;
            if (!decode(heads[j], in) || in.kind != flow::normal)
                break;
            int arg = -1;
            if (!x64 && std::string(in.mnem) == "push")
                arg = pushes++;
            else if (in.mem_write && in.has_mem_op && !in.mem_index && in.mem_base) {
                // a stack argument: [rsp + 0x20 + 8 * n] on win64, [rsp + 8 * n] on system v / x86
                std::string base = reg_name(in.mem_base);
                if (base == "rsp" || base == "esp") {
                    int64_t off = in.mem_disp - (x64 && pe ? 0x20 : 0);
                    int ptr = x64 ? 8 : 4;
                    if (off >= 0 && off % ptr == 0)
                        arg = (int)nregs + (int)(off / ptr);
                }
            } else if (x64 && in.reg0 && !in.mem_write && writes_first(in.mnem)) {
                std::string r = reg64(reg_name(in.reg0));
                for (size_t k = 0; k < nregs; k++)
                    if (r == (pe ? win64[k] : sysv[k]))
                        arg = (int)k;
            }
            if (arg >= 0 && arg < (int)done.size() && !done[(size_t)arg]) {
                done[(size_t)arg] = true;
                arg_notes_[heads[j]] = p->params[(size_t)arg].name;
            }
            if (an.flags_at(heads[j]) & fl_label)
                break; // other paths come in here
        }
    }
}

std::string database::arg_note(uint64_t a)
{
    const function* f = an.func_containing(a);
    if (!f)
        return std::string();
    if (!noted_funcs_.count(f->start))
        note_args(*f);
    auto it = arg_notes_.find(a);
    return it == arg_notes_.end() ? std::string() : it->second;
}

void database::record(edit_kind k, uint64_t a, const std::string& before, const std::string& after)
{
    if (!record_edits || applying_ || before == after)
        return;
    undo_log_.push_back({k, a, before, after, edit_group});
    if (undo_log_.size() > 10000)
        undo_log_.erase(undo_log_.begin(), undo_log_.begin() + 1000);
    redo_log_.clear();
}

// puts one edit's before (undo) or after (redo) state back
std::string database::apply(const edit& e, bool forward)
{
    const std::string& v = forward ? e.after : e.before;
    std::string where = fmt_addr(e.addr), err;
    switch (e.kind) {
    case edit_kind::name:
        set_name(e.addr, v, err);
        return v.empty() ? "name at " + where : "name " + v + " at " + where;
    case edit_kind::comment:
        set_comment(e.addr, v);
        return "comment at " + where;
    case edit_kind::bookmark:
        set_bookmark(e.addr, !v.empty(), v.empty() ? std::string() : v.substr(1));
        return "bookmark at " + where;
    case edit_kind::lvar: { // "key\nname\ttype"
        size_t nl = v.find('\n'), tab = v.find('\t');
        if (nl == std::string::npos || tab == std::string::npos || tab < nl)
            return std::string();
        std::string key = v.substr(0, nl);
        set_lvar(e.addr, key, v.substr(nl + 1, tab - nl - 1), v.substr(tab + 1), err);
        return "variable " + key + " in " + location(e.addr);
    }
    case edit_kind::proto:
        set_proto(e.addr, v, err);
        return "prototype of " + location(e.addr);
    }
    return std::string();
}

std::string database::undo()
{
    if (undo_log_.empty())
        return std::string();
    uint64_t g = undo_log_.back().group;
    std::string what;
    int n = 0;
    applying_ = true;
    while (!undo_log_.empty() && undo_log_.back().group == g) {
        edit e = undo_log_.back();
        undo_log_.pop_back();
        what = apply(e, false);
        redo_log_.push_back(e);
        n++;
    }
    applying_ = false;
    dirty = true;
    rows_dirty_ = true;
    return n > 1 ? util::fmt("%d changes", n) : what;
}

std::string database::redo()
{
    if (redo_log_.empty())
        return std::string();
    uint64_t g = redo_log_.back().group;
    std::string what;
    int n = 0;
    applying_ = true;
    while (!redo_log_.empty() && redo_log_.back().group == g) {
        edit e = redo_log_.back();
        redo_log_.pop_back();
        what = apply(e, true);
        undo_log_.push_back(e);
        n++;
    }
    applying_ = false;
    dirty = true;
    rows_dirty_ = true;
    return n > 1 ? util::fmt("%d changes", n) : what;
}

bool database::resolve(const std::string& text, uint64_t& out) const
{
    std::string t = util::trim(text);
    if (t.empty())
        return false;
    auto n = by_name_.find(t);
    if (n != by_name_.end()) {
        out = n->second;
        return true;
    }
    uint64_t v;
    if (parse_auto(t, v)) {
        out = v;
        return true;
    }
    if (util::parse_hex(t, v)) {
        out = v;
        return true;
    }
    size_t plus = t.rfind('+');
    if (plus != std::string::npos && plus > 0) {
        uint64_t base, off;
        if (resolve(t.substr(0, plus), base) && util::parse_hex(t.substr(plus + 1), off)) {
            out = base + off;
            return true;
        }
    }
    return false;
}

std::string database::fmt_addr(uint64_t a) const
{
    return util::fmt(digits_ == 16 ? "%016llX" : "%08llX", (unsigned long long)a);
}

bool database::uninit(uint64_t a) const
{
    const segment* s = bin.seg_at(a);
    return s && a - s->start >= s->file_size;
}

std::string database::seg_name(uint64_t a) const
{
    const segment* s = bin.seg_at(a);
    return s ? s->name : std::string();
}

// ---- listing ----

const std::vector<row>& database::rows()
{
    if (rows_dirty_)
        build_rows();
    return rows_;
}

void database::build_rows()
{
    rows_.clear();
    rows_.reserve((size_t)std::min<uint64_t>(an.insn_count + an.strings.size() + 4096, 1u << 22));
    for (size_t si = 0; si < bin.segments.size(); si++) {
        const segment& s = bin.segments[si];
        const std::vector<uint8_t>& fl = an.flags[si];
        rows_.push_back({s.start, 0, row_kind::seg});
        uint64_t off = 0, size = s.size();
        while (off < size) {
            uint64_t a = s.start + off;
            uint8_t f = fl[(size_t)off];
            bool named = user_names.count(a) != 0;
            if (f & fl_func) {
                rows_.push_back({a, 0, row_kind::blank});
                rows_.push_back({a, 0, row_kind::func});
            } else if ((f & fl_code) && ((f & fl_label) || named)) {
                rows_.push_back({a, 0, row_kind::label});
            }
            row r;
            r.addr = a;
            if (f & (fl_code | fl_str | fl_data)) {
                r.size = an.item_size(a);
                r.kind = (f & fl_code) ? row_kind::code : (f & fl_str) ? row_kind::string : row_kind::data;
            } else if (off >= s.file_size) {
                // uninitialized space (.bss) collapses into one "dup(?)" line
                uint64_t n = 1;
                while (off + n < size && n < 0xffffffffu && fl[(size_t)(off + n)] == 0 && !user_names.count(a + n))
                    n++;
                r.size = (uint32_t)n;
                r.kind = row_kind::unknown;
            } else {
                // unexplored bytes, up to 16 per line, split at anything with a name
                uint32_t n = 1;
                while (off + n < size && off + n < s.file_size && n < 16 && ((a + n) & 15) != 0 &&
                       fl[(size_t)(off + n)] == 0 && !user_names.count(a + n))
                    n++;
                r.size = n;
                r.kind = row_kind::unknown;
            }
            rows_.push_back(r);
            off += r.size;
        }
    }
    rows_dirty_ = false;
}

size_t database::row_of(uint64_t a)
{
    const std::vector<row>& r = rows();
    if (r.empty())
        return 0;
    auto it = std::upper_bound(r.begin(), r.end(), a, [](uint64_t v, const row& x) { return v < x.addr; });
    if (it == r.begin())
        return 0;
    return (size_t)(it - r.begin()) - 1;
}

std::string database::insn_text(const insn& in) const
{
    std::string ops = in.ops;
    if (in.has_target && !in.indirect) {
        std::string n = name_at(in.target);
        if (!n.empty())
            ops = n;
    } else {
        if (in.has_mem && bin.is_mapped(in.mem)) {
            std::string n = name_at(in.mem);
            if (in.mem_rip) {
                size_t p = ops.find("rip");
                if (p == std::string::npos)
                    p = ops.find("eip");
                size_t close = p == std::string::npos ? p : ops.find(']', p);
                if (close != std::string::npos)
                    ops = ops.substr(0, p) + (n.empty() ? "0x" + util::hex_lower(in.mem) : n) + ops.substr(close);
            } else if (!n.empty()) {
                replace_hex_token(ops, in.mem, n);
            }
        }
        // [reg*4 + table] style operands: name the displacement when it's a known place
        if (!in.has_mem && in.has_mem_op && in.mem_disp >= 0x10000) {
            uint64_t d = (uint64_t)in.mem_disp & (bin.is64() ? ~0ull : 0xffffffffull);
            if (bin.is_mapped(d)) {
                std::string n = name_at(d);
                if (!n.empty())
                    replace_hex_token(ops, d, n);
            }
        }
        if (in.has_imm) {
            auto refs = an.refs_from(in.addr);
            for (const xref* x = refs.first; x != refs.second; x++) {
                if (x->to == in.imm && x->type == xref_type::offset) {
                    std::string n = name_at(in.imm);
                    if (!n.empty())
                        replace_hex_token(ops, in.imm, "offset " + n);
                    break;
                }
            }
        }
    }
    std::string out = in.mnem;
    if (!ops.empty()) {
        out.append(out.size() < 8 ? 8 - out.size() : 1, ' ');
        out += ops;
    }
    return out;
}

std::string database::item_text(uint64_t a, uint32_t size, line_text& out) const
{
    std::string name = name_at(a);
    std::string prefix = name.empty() ? std::string() : name + " ";
    auto imp = an.slot_import.find(a);
    if (imp != an.slot_import.end()) {
        const import_entry& e = bin.imports[imp->second];
        out.auto_comment = e.lib.empty() ? "import" : "import from " + e.lib;
        return prefix + (bin.is64() ? "dq ?" : "dd ?");
    }
    auto ds = an.data_sizes.find(a);
    uint32_t sz = ds != an.data_sizes.end() ? ds->second : size;
    if (sz == 1 || sz == 2 || sz == 4 || sz == 8) {
        uint8_t buf[8] = {};
        bin.read(a, buf, sz);
        uint64_t v = 0;
        for (uint32_t i = 0; i < sz; i++)
            v |= (uint64_t)buf[i] << (8 * i);
        const char* dir = sz == 1 ? "db " : sz == 2 ? "dw " : sz == 4 ? "dd " : "dq ";
        if (uninit(a))
            return prefix + dir + "?";
        if ((int)sz == bin.ptr_size() && v && bin.is_mapped(v)) {
            std::string n = name_at(v);
            out.target = v;
            return prefix + dir + "offset " + (n.empty() ? fmt_addr(v) : n);
        }
        return prefix + dir + "0x" + util::hex(v);
    }
    std::string bytes;
    for (uint32_t i = 0; i < sz && i < 16; i++) {
        uint8_t c = 0;
        bin.read_u8(a + i, c);
        bytes += util::fmt(i ? ", %02X" : "%02X", c);
    }
    return prefix + "db " + bytes;
}

void database::format(const row& r, line_text& out)
{
    out = line_text();
    std::string seg = seg_name(r.addr);
    out.addr = seg + ":" + fmt_addr(r.addr);
    switch (r.kind) {
    case row_kind::blank:
        out.addr.clear();
        return;
    case row_kind::seg: {
        const segment* s = bin.seg_at(r.addr);
        if (s)
            out.text = util::fmt("; segment %s  %s  %s - %s  (0x%llX bytes)", s->name.c_str(), perm_text(s->perms),
                fmt_addr(s->start).c_str(), fmt_addr(s->end).c_str(), (unsigned long long)s->size());
        out.style = ls_segment;
        return;
    }
    case row_kind::func: {
        out.text = name_at(r.addr) + " proc";
        const function* f = an.func_at(r.addr);
        auto refs = an.refs_to(r.addr);
        size_t n = (size_t)(refs.second - refs.first);
        if (f && f->thunk)
            out.auto_comment = "thunk to " + location(f->thunk_target);
        else if (n)
            out.auto_comment = util::fmt("%zu xref%s", n, n == 1 ? "" : "s");
        out.style = ls_func;
        return;
    }
    case row_kind::label: {
        out.text = name_at(r.addr) + ":";
        auto refs = an.refs_to(r.addr);
        size_t n = (size_t)(refs.second - refs.first);
        if (n)
            out.auto_comment = "xref " + location(refs.first->from) + (n > 1 ? util::fmt(" (+%zu)", n - 1) : std::string());
        out.style = ls_label;
        return;
    }
    case row_kind::code: {
        insn in;
        out.comment = comment_at(r.addr);
        if (!dis_.decode(bin, r.addr, in)) {
            out.text = "db ??";
            return;
        }
        for (int i = 0; i < in.size && i < 8; i++)
            out.bytes += util::fmt(i ? " %02X" : "%02X", in.bytes[i]);
        if (in.size > 8)
            out.bytes += " ..";
        out.text = insn_text(in);
        if (in.kind == flow::call)
            out.style = ls_call;
        else if (in.kind == flow::jump || in.kind == flow::cond)
            out.style = ls_jump;
        else if (in.kind == flow::ret || in.kind == flow::stop)
            out.style = ls_ret;
        else if (ins::is_nop(in.id))
            out.style = ls_nop;
        if (in.has_target && !in.indirect)
            out.target = in.target;
        else if (in.has_mem && bin.is_mapped(in.mem))
            out.target = in.mem;
        else if (in.has_imm && bin.is_mapped(in.imm) && (an.flags_at(in.imm) & (fl_label | fl_str | fl_func)))
            out.target = in.imm;
        uint64_t cand[3] = {in.has_target ? in.target : 0, in.has_mem ? in.mem : 0, in.has_imm ? in.imm : 0};
        for (uint64_t c : cand) {
            const string_item* s = c ? an.string_at(c) : nullptr;
            if (s) {
                out.auto_comment = std::string(s->wide ? "L\"" : "\"") + util::escape(s->text, 80) + "\"";
                break;
            }
        }
        std::string note = arg_note(r.addr);
        if (!note.empty())
            out.auto_comment = out.auto_comment.empty() ? note : note + " = " + out.auto_comment;
        auto t = an.tables.find(r.addr);
        if (t != an.tables.end())
            out.auto_comment = util::fmt("switch jump, %u cases", t->second.entries);
        if (an.noret_calls.count(r.addr))
            out.auto_comment = out.auto_comment.empty() ? "no return" : out.auto_comment + ", no return";
        return;
    }
    case row_kind::string: {
        const string_item* s = an.string_at(r.addr);
        out.comment = comment_at(r.addr);
        out.style = ls_string;
        if (s)
            out.text = name_at(r.addr) + (s->wide ? " du \"" : " db \"") + util::escape(s->text, 200) + "\",0";
        else
            out.text = item_text(r.addr, r.size, out);
        return;
    }
    case row_kind::data:
        out.comment = comment_at(r.addr);
        out.style = ls_data;
        out.text = item_text(r.addr, r.size, out);
        return;
    case row_kind::unknown: {
        out.comment = comment_at(r.addr);
        out.style = ls_unknown;
        std::string name = name_at(r.addr);
        if (uninit(r.addr)) {
            out.text = (name.empty() ? std::string() : name + " ") + "db 0x" + util::hex(r.size) + " dup(?)";
            return;
        }
        std::string hex, ascii;
        for (uint32_t i = 0; i < r.size; i++) {
            uint8_t c = 0;
            bin.read_u8(r.addr + i, c);
            hex += util::fmt(i ? " %02X" : "%02X", c);
            ascii += (c >= 32 && c < 127) ? (char)c : '.';
        }
        out.text = (name.empty() ? std::string() : name + " ") + "db " + hex;
        out.auto_comment = ascii;
        return;
    }
    }
}

std::vector<uint64_t> database::find_bytes(const std::string& pattern, uint64_t from, size_t max_results) const
{
    std::vector<int> pat; // -1 = wildcard
    for (const std::string& tok : util::split(pattern, " ,\t")) {
        if (tok == "?" || tok == "??") {
            pat.push_back(-1);
            continue;
        }
        if (tok.size() % 2)
            return {};
        for (size_t i = 0; i < tok.size(); i += 2) {
            if (tok[i] == '?' && tok[i + 1] == '?') {
                pat.push_back(-1);
                continue;
            }
            int hi = util::hex_digit(tok[i]), lo = util::hex_digit(tok[i + 1]);
            if (hi < 0 || lo < 0)
                return {};
            pat.push_back(hi * 16 + lo);
        }
    }
    std::vector<uint64_t> out;
    if (pat.empty())
        return out;
    for (const segment& s : bin.segments) {
        if (s.end <= from || s.size() < pat.size())
            continue;
        uint64_t first = from > s.start ? from - s.start : 0;
        for (uint64_t i = first; i + pat.size() <= s.size(); i++) {
            size_t k = 0;
            while (k < pat.size() && (pat[k] < 0 || s.data[(size_t)(i + k)] == (uint8_t)pat[k]))
                k++;
            if (k == pat.size()) {
                out.push_back(s.start + i);
                if (out.size() >= max_results)
                    return out;
            }
        }
    }
    return out;
}

// ---- saved names / comments / breakpoints ----

std::string database::db_path() const
{
    std::string safe;
    for (char c : bin.name)
        safe += (is_alnum(c) || c == '.' || c == '-' || c == '_') ? c : '_';
    if (safe.empty())
        safe = "file";
    return os::join(os::join(os::user_dir(), "db"), safe + "-" + util::fmt("%08X", crc) + ".ceasta");
}

// a committable project file that sits next to the binary. when it exists, ceasta reads it and
// writes to it, so a team (or an ai) can keep names and comments in version control.
std::string database::project_path() const { return project_file.empty() ? bin.path + ".ceasta" : project_file; }

std::string database::annotations_path() const { return os::exists(project_path()) ? project_path() : db_path(); }

bool database::add_xref(uint64_t from, uint64_t to, xref_type type)
{
    if (!bin.is_mapped(from) || !bin.is_mapped(to))
        return false;
    xref x{from, to, type};
    // keep an.xto sorted by (to, from, type)
    auto to_less = [](const xref& a, const xref& b) {
        if (a.to != b.to)
            return a.to < b.to;
        if (a.from != b.from)
            return a.from < b.from;
        return a.type < b.type;
    };
    auto it = std::lower_bound(an.xto.begin(), an.xto.end(), x, to_less);
    if (it != an.xto.end() && it->to == to && it->from == from && it->type == type)
        return false; // already known
    an.xto.insert(it, x);
    // keep an.xfrom sorted by (from, to)
    auto from_less = [](const xref& a, const xref& b) {
        return a.from != b.from ? a.from < b.from : a.to < b.to;
    };
    an.xfrom.insert(std::lower_bound(an.xfrom.begin(), an.xfrom.end(), x, from_less), x);
    uint8_t f = an.flags_at(to);
    bool tail = (f & fl_tail) && !(f & (fl_code | fl_str | fl_data));
    if (!tail && !(f & (fl_func | fl_label)))
        an.add_flags(to, fl_label);
    extra_xrefs.push_back(x);
    rows_dirty_ = true;
    dirty = true;
    return true;
}

std::string database::serialize(bool with_program) const
{
    // sorted (user_names / user_comments are std::map, breakpoints std::set), so the file is
    // stable line by line and diffs cleanly
    std::string s = "ceasta 1\nfile " + bin.name + "\n" + util::fmt("crc %08X\n", crc);
    if (bin.format == bin_format::raw)
        s += util::fmt("load raw %s %llx\n", bin.is64() ? "x64" : "x86", (unsigned long long)bin.base);
    for (const auto& n : user_names)
        s += "name " + util::hex(n.first) + " " + n.second + "\n";
    for (const auto& c : user_comments)
        s += "comment " + util::hex(c.first) + " " + escape_line(c.second) + "\n";
    for (uint64_t b : breakpoints) {
        s += "bp " + util::hex(b) + "\n";
        auto c = bp_conditions.find(b);
        if (c != bp_conditions.end() && !c->second.empty())
            s += "bpcond " + util::hex(b) + " " + escape_line(c->second) + "\n";
    }
    for (const auto& b : bookmarks)
        s += "bookmark " + util::hex(b.first) + (b.second.empty() ? std::string() : " " + escape_line(b.second)) + "\n";
    for (const xref& x : extra_xrefs)
        s += "xref " + util::hex(x.from) + " " + util::hex(x.to) + " " + std::to_string((int)x.type) + "\n";
    for (const auto& p : protos)
        s += "proto " + util::hex(p.first) + " " + format_prototype(p.second) + "\n";
    for (const auto& f : lvars)
        for (const auto& v : f.second) // "lvar <func> <key> <name>\t<type>"
            s += "lvar " + util::hex(f.first) + " " + v.first + " " + v.second.name + "\t" + v.second.type + "\n";
    for (const suggestion& g : suggestions) // "suggest <addr> <variable or -> <name>\t<reason>"
        s += "suggest " + util::hex(g.addr) + " " + (g.var.empty() ? "-" : g.var) + " " + g.name + "\t" +
             escape_line(g.reason) + "\n";
    if (saved_cursor)
        s += util::fmt("view %llx %d\n", (unsigned long long)saved_cursor, saved_view);
    if (with_program && !bin.file.empty()) {
        // the program itself, so the database opens without the original file
        s += util::fmt("program %zu %08X\n", bin.file.size(), crc);
        std::string b64 = util::base64_encode(bin.file.data(), bin.file.size());
        for (size_t i = 0; i < b64.size(); i += 76)
            s += b64.substr(i, 76) + "\n";
        s += "end\n";
    }
    return s;
}

bool database::write_annotations(const std::string& path, std::string& err, bool with_program) const
{
    std::string s = serialize(with_program);
    size_t slash = path.find_last_of("/\\");
    if (slash != std::string::npos)
        os::make_dirs(path.substr(0, slash));
    return os::write_file(path, s, err);
}

bool database::save(std::string& err) const
{
    // keep the private copy in the user dir up to date, and the project / database file this
    // session works with (a project the user started next to the binary counts too)
    bool ok = write_annotations(db_path(), err);
    if (!project_file.empty() || os::exists(project_path())) {
        std::string e;
        if (!write_annotations(project_path(), e, project_has_program)) {
            err = e;
            ok = false;
        }
    }
    return ok;
}

bool database::save_project(std::string& err) const
{
    return write_annotations(project_path(), err, project_has_program);
}

bool database::load_annotations(std::string& err)
{
    // the project file next to the binary wins over the private copy, so a committed file is
    // what a fresh checkout sees
    std::string path = annotations_path();
    if (!os::exists(path))
        return true;
    std::vector<uint8_t> bytes;
    if (!os::read_file(path, bytes, err))
        return false;
    std::string text(bytes.begin(), bytes.end());
    size_t pos = 0;
    int line_no = 0;
    while (pos < text.size()) {
        size_t nl = text.find('\n', pos);
        std::string line = text.substr(pos, nl == std::string::npos ? std::string::npos : nl - pos);
        pos = nl == std::string::npos ? text.size() : nl + 1;
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line_no++ == 0) {
            if (line.compare(0, 6, "ceasta") != 0) {
                err = "not a ceasta database: " + path;
                return false;
            }
            continue;
        }
        if (line.compare(0, 8, "program ") == 0) {
            // the program's bytes: loading already has them. skip its lines up to the one that is
            // just "end" (a base64 line is never 3 characters long)
            project_has_program = true;
            while (pos < text.size()) {
                size_t e = text.find('\n', pos);
                size_t len = (e == std::string::npos ? text.size() : e) - pos;
                bool last = (len == 3 || (len == 4 && text[pos + 3] == '\r')) && text.compare(pos, 3, "end") == 0;
                pos = e == std::string::npos ? text.size() : e + 1;
                if (last)
                    break;
            }
            continue;
        }
        size_t sp1 = line.find(' ');
        if (sp1 == std::string::npos)
            continue;
        std::string kind = line.substr(0, sp1);
        if (kind == "view") { // "view <cursor> <mode>"
            uint64_t c = 0;
            size_t sp = line.find(' ', sp1 + 1);
            if (util::parse_hex(line.substr(sp1 + 1, sp == std::string::npos ? std::string::npos : sp - sp1 - 1), c)) {
                saved_cursor = c;
                saved_view = sp == std::string::npos ? 0 : atoi(line.c_str() + sp + 1);
            }
            continue;
        }
        size_t sp2 = line.find(' ', sp1 + 1);
        uint64_t a;
        if (!util::parse_hex(line.substr(sp1 + 1, sp2 == std::string::npos ? std::string::npos : sp2 - sp1 - 1), a))
            continue;
        std::string rest = sp2 == std::string::npos ? std::string() : line.substr(sp2 + 1);
        std::string e;
        if (kind == "name")
            set_name(a, rest, e);
        else if (kind == "comment")
            set_comment(a, unescape_line(rest));
        else if (kind == "bp" && bin.is_mapped(a))
            breakpoints.insert(a);
        else if (kind == "bookmark" && bin.is_mapped(a))
            bookmarks[a] = unescape_line(rest);
        else if (kind == "bpcond" && bin.is_mapped(a))
            bp_conditions[a] = unescape_line(rest);
        else if (kind == "proto")
            set_proto(a, rest, e);
        else if (kind == "suggest") {
            size_t sp = rest.find(' '), tab = rest.find('\t');
            if (sp != std::string::npos && tab != std::string::npos && tab > sp) {
                std::string var = rest.substr(0, sp);
                suggest(a, var == "-" ? std::string() : var, rest.substr(sp + 1, tab - sp - 1),
                        unescape_line(rest.substr(tab + 1)), e);
            }
        } else if (kind == "lvar") {
            size_t sp = rest.find(' '), tab = rest.find('\t');
            if (sp != std::string::npos && tab != std::string::npos && tab > sp)
                set_lvar(a, rest.substr(0, sp), rest.substr(sp + 1, tab - sp - 1), rest.substr(tab + 1), e);
        }
        else if (kind == "xref") {
            // "xref <from> <to> <kind>": a runtime-learned cross reference
            uint64_t to = 0;
            int k = 0;
            size_t sp3 = rest.find(' ');
            if (sp3 != std::string::npos && util::parse_hex(rest.substr(0, sp3), to)) {
                k = atoi(rest.c_str() + sp3 + 1);
                if (k >= 0 && k <= (int)xref_type::offset)
                    add_xref(a, to, (xref_type)k);
            }
        }
    }
    dirty = false;
    return true;
}

std::unique_ptr<database> open_database(const std::string& path, const load_options& opts,
    analysis_progress* progress, std::string& err)
{
    std::unique_ptr<database> db(new database());
    if (opts.force_raw) {
        std::vector<uint8_t> bytes;
        if (!os::read_file(path, bytes, err))
            return nullptr;
        loader::raw(std::move(bytes), path, opts.raw_base, opts.raw_arch, db->bin);
    } else if (!loader::open(path, db->bin, err)) {
        return nullptr;
    }
    if (!analyze(db->bin, db->an, progress)) {
        err = (progress && progress->cancel.load()) ? "cancelled" : "analysis failed";
        return nullptr;
    }
    db->build();
    db->info = inspect(db->bin);
    db->project_file = opts.project;
    if (db->project_file.empty() && os::exists(db->project_path()))
        db->project_file = db->project_path(); // a project someone started next to the file
    std::string e;
    if (!db->load_annotations(e))
        db->bin.notes.push_back("couldn't read saved names: " + e);
    db->rows();
    return db;
}

bool is_project_file(const std::string& path)
{
    std::string l = util::lower(path);
    return l.size() > 7 && l.compare(l.size() - 7, 7, ".ceasta") == 0;
}

bool read_project_info(const std::string& project, project_info& out, std::string& err)
{
    out = project_info();
    std::vector<uint8_t> bytes;
    if (!os::read_file(project, bytes, err))
        return false;
    std::string text(bytes.begin(), bytes.end());
    if (text.compare(0, 6, "ceasta") != 0) {
        err = "not a ceasta project";
        return false;
    }
    size_t pos = 0;
    while (pos < text.size()) {
        size_t nl = text.find('\n', pos);
        std::string line = text.substr(pos, nl == std::string::npos ? std::string::npos : nl - pos);
        pos = nl == std::string::npos ? text.size() : nl + 1;
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line.compare(0, 5, "file ") == 0) {
            std::string n = util::trim(line.substr(5));
            // a bare file name only: the project decides nothing about other folders
            if (n.find_first_of("/\\:") == std::string::npos && n != "." && n != "..")
                out.name = n;
        } else if (line.compare(0, 4, "crc ") == 0) {
            uint64_t c = 0;
            if (util::parse_hex(line.substr(4), c)) {
                out.crc = (uint32_t)c;
                out.has_crc = true;
            }
        } else if (line.compare(0, 9, "load raw ") == 0) {
            out.opts.force_raw = true;
            out.opts.raw_arch = line.compare(9, 3, "x86") == 0 ? bin_arch::x86 : bin_arch::x64;
            size_t sp = line.find(' ', 9);
            if (sp != std::string::npos)
                util::parse_hex(line.substr(sp + 1), out.opts.raw_base);
        } else if (line.compare(0, 8, "program ") == 0) {
            out.has_program = true;
            break; // the rest is the program's bytes
        }
    }
    return true;
}

namespace {

bool crc_matches(const std::string& path, const project_info& info)
{
    if (!os::exists(path))
        return false;
    if (!info.has_crc)
        return true;
    std::vector<uint8_t> b;
    std::string e;
    return os::read_file(path, b, e) && util::crc32(b.data(), b.size()) == info.crc;
}

// decode the program inside the project into a file
bool extract_program(const std::string& project, const std::string& to, std::string& err)
{
    std::vector<uint8_t> bytes;
    if (!os::read_file(project, bytes, err))
        return false;
    std::string text(bytes.begin(), bytes.end());
    size_t at = text.find("\nprogram ");
    if (at == std::string::npos) {
        err = "the project has no copy of the program";
        return false;
    }
    size_t nl = text.find('\n', at + 1);
    size_t size = (size_t)strtoull(text.c_str() + at + 9, nullptr, 10);
    std::vector<uint8_t> prog;
    prog.reserve(size);
    size_t pos = nl == std::string::npos ? text.size() : nl + 1;
    while (pos < text.size()) {
        size_t e = text.find('\n', pos);
        std::string line = text.substr(pos, e == std::string::npos ? std::string::npos : e - pos);
        pos = e == std::string::npos ? text.size() : e + 1;
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (line == "end")
            break;
        if (!util::base64_decode(line, prog)) {
            err = "the program inside the project is damaged";
            return false;
        }
    }
    if (prog.size() != size) {
        err = "the program inside the project is cut short";
        return false;
    }
    size_t slash = to.find_last_of("/\\");
    if (slash != std::string::npos)
        os::make_dirs(to.substr(0, slash));
    if (!os::write_file(to, std::string(prog.begin(), prog.end()), err))
        return false;
    os::make_executable(to); // so the debugger can start it
    return true;
}

} // namespace

std::string project_program(const std::string& project, const project_info& info, std::string& note)
{
    note.clear();
    std::vector<std::string> candidates;
    if (is_project_file(project))
        candidates.push_back(project.substr(0, project.size() - 7)); // "<x>.ceasta" -> "<x>"
    if (!info.name.empty()) {
        size_t slash = project.find_last_of("/\\");
        candidates.push_back(slash == std::string::npos ? info.name : os::join(project.substr(0, slash), info.name));
    }
    for (const std::string& c : candidates)
        if (crc_matches(c, info))
            return c;
    if (info.has_program) {
        // the copy inside, written out once to the user folder (by crc, so versions don't clash)
        std::string name = info.name.empty() ? std::string("program") : info.name;
        std::string out = os::join(os::join(os::join(os::user_dir(), "programs"), util::fmt("%08X", info.crc)), name);
        std::string err;
        if (crc_matches(out, info) || extract_program(project, out, err)) {
            note = "using the copy of " + name + " saved inside the project";
            return out;
        }
        note = err;
    }
    for (const std::string& c : candidates)
        if (os::exists(c)) {
            note = c + " changed since the project was saved - names and comments may not line up";
            return c;
        }
    return std::string();
}

std::unique_ptr<database> open_any(const std::string& path, load_options opts, analysis_progress* progress,
    std::string& err, std::string* note)
{
    if (!is_project_file(path) || opts.force_raw)
        return open_database(path, opts, progress, err);
    project_info info;
    if (!read_project_info(path, info, err))
        return nullptr;
    std::string n;
    std::string target = project_program(path, info, n);
    if (note)
        *note = n;
    if (target.empty()) {
        err = "can't find " + (info.name.empty() ? std::string("the program") : info.name) + " for " + path +
              " (and the project holds no copy of it)";
        return nullptr;
    }
    load_options o = info.opts;
    o.project = path;
    return open_database(target, o, progress, err);
}
