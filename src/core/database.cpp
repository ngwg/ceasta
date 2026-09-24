#include "core/database.h"
#include "core/os.h"
#include "core/util.h"
#include <algorithm>

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
    return fmt_addr(a);
}

bool database::set_name(uint64_t a, const std::string& name, std::string& err)
{
    std::string n = util::trim(name);
    if (!bin.is_mapped(a)) {
        err = "address " + fmt_addr(a) + " isn't mapped";
        return false;
    }
    auto old = user_names.find(a);
    if (n.empty()) {
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
    user_names[a] = n;
    by_name_[n] = a;
    dirty = true;
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
    if (text.empty())
        user_comments.erase(a);
    else
        user_comments[a] = text;
    dirty = true;
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

bool database::save(std::string& err) const
{
    std::string s = "ceasta 1\nfile " + bin.name + "\n";
    for (const auto& n : user_names)
        s += "name " + util::hex(n.first) + " " + n.second + "\n";
    for (const auto& c : user_comments)
        s += "comment " + util::hex(c.first) + " " + escape_line(c.second) + "\n";
    for (uint64_t b : breakpoints)
        s += "bp " + util::hex(b) + "\n";
    std::string path = db_path();
    size_t slash = path.find_last_of("/\\");
    if (slash != std::string::npos)
        os::make_dirs(path.substr(0, slash));
    return os::write_file(path, s, err);
}

bool database::load_annotations(std::string& err)
{
    std::string path = db_path();
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
        size_t sp1 = line.find(' ');
        if (sp1 == std::string::npos)
            continue;
        std::string kind = line.substr(0, sp1);
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
    std::string e;
    if (!db->load_annotations(e))
        db->bin.notes.push_back("couldn't read saved names: " + e);
    db->rows();
    return db;
}
