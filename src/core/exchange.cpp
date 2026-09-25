#include "core/exchange.h"
#include "core/database.h"
#include "core/json.h"
#include "core/os.h"
#include "core/util.h"
#include <cctype>
#include <cstring>

namespace {

// a python string literal: the file is utf-8, so only quotes, backslashes and control
// characters need escaping
std::string py(const std::string& s)
{
    std::string out = "\"";
    for (unsigned char c : s) {
        if (c == '\\' || c == '"')
            out += '\\', out += (char)c;
        else if (c == '\n')
            out += "\\n";
        else if (c == '\r')
            out += "\\r";
        else if (c == '\t')
            out += "\\t";
        else if (c < 32)
            out += util::fmt("\\x%02x", c);
        else
            out += (char)c;
    }
    return out + "\"";
}

std::string rva(const database& db, uint64_t a) { return util::fmt("0x%llx", (unsigned long long)(a - db.bin.base)); }

// a prototype in the other tool's c: its name, then the calling convention ida and ghidra take
std::string c_proto(const database& db, uint64_t f, const prototype& p)
{
    prototype q = p;
    std::string n = db.name_at(f);
    if (!n.empty())
        q.name = n;
    return format_prototype(q) + ";";
}

std::string header(const database& db, const char* tool, const char* how)
{
    return util::fmt("# ceasta: names, comments, prototypes and breakpoints for %s\n# sha256 %s\n# %s: %s\n",
        db.bin.name.c_str(), db.info.sha256.c_str(), tool, how);
}

// the names a tool made up itself: nothing to carry over
bool automatic(const std::string& n)
{
    static const char* const prefixes[] = {"sub_", "loc_", "locret_", "off_", "byte_", "word_", "dword_", "qword_", "xmmword_",
        "unk_", "asc_", "stru_", "nullsub_", "def_", "jpt_", "j_sub_", "FUN_", "LAB_", "DAT_", "PTR_", "SUB_", "EXT_",
        "thunk_FUN_", "switchD_", "caseD_", "s_", "u_", "BYTE_", "WORD_", "DWORD_", "QWORD_", "Elf64_", "Elf32_",
        "DAT_", "UNK_", "LAB_"};
    for (const char* p : prefixes) {
        size_t len = strlen(p);
        if (n.size() > len && n.compare(0, len, p) == 0)
            return true;
    }
    return n.empty();
}

} // namespace

std::string export_ida(const database& db)
{
    std::string s = "# -*- coding: utf-8 -*-\n" + header(db, "ida", "File > Script file... runs it");
    s += "import idc\nimport ida_nalt\n\nbase = ida_nalt.get_imagebase()\n\nnames = [\n";
    for (const auto& n : db.user_names)
        s += "    (" + rva(db, n.first) + ", " + py(n.second) + "),\n";
    s += "]\ncomments = [\n";
    for (const auto& c : db.user_comments)
        s += "    (" + rva(db, c.first) + ", " + py(c.second) + "),\n";
    s += "]\nprototypes = [\n";
    for (const auto& p : db.protos)
        s += "    (" + rva(db, p.first) + ", " + py(c_proto(db, p.first, p.second)) + "),\n";
    s += "]\nbreakpoints = [";
    for (uint64_t b : db.breakpoints)
        s += rva(db, b) + ", ";
    s += "]\n\n"
         "for off, name in names:\n"
         "    idc.set_name(base + off, name, idc.SN_NOWARN | idc.SN_NOCHECK)\n"
         "for off, text in comments:\n"
         "    idc.set_cmt(base + off, text, 0)\n"
         "typed = 0\n"
         "for off, proto in prototypes:\n"
         "    if idc.SetType(base + off, proto):\n"
         "        typed += 1\n"
         "for off in breakpoints:\n"
         "    idc.add_bpt(base + off)\n"
         "print(\"ceasta: %d names, %d comments, %d of %d prototypes, %d breakpoints\" % "
         "(len(names), len(comments), typed, len(prototypes), len(breakpoints)))\n";
    return s;
}

std::string export_ghidra(const database& db)
{
    std::string s = "# -*- coding: utf-8 -*-\n" + header(db, "ghidra", "Window > Script Manager, add this folder, run it") +
                    "# @category ceasta\n"
                    "from ghidra.program.model.symbol import SourceType\n\n"
                    "base = currentProgram.getImageBase()\n\nnames = [\n";
    for (const auto& n : db.user_names)
        s += "    (" + rva(db, n.first) + ", " + py(n.second) + "),\n";
    s += "]\ncomments = [\n";
    for (const auto& c : db.user_comments)
        s += "    (" + rva(db, c.first) + ", " + py(c.second) + "),\n";
    s += "]\nprototypes = [\n";
    for (const auto& p : db.protos)
        s += "    (" + rva(db, p.first) + ", " + py(c_proto(db, p.first, p.second)) + "),\n";
    s += "]\nbookmarks = [\n";
    for (const auto& b : db.bookmarks)
        s += "    (" + rva(db, b.first) + ", " + py(b.second) + "),\n";
    s += "]\n\n"
         "named = 0\n"
         "for off, name in names:\n"
         "    a = base.add(off)\n"
         "    f = getFunctionAt(a)\n"
         "    try:\n"
         "        if f is not None:\n"
         "            f.setName(name, SourceType.USER_DEFINED)\n"
         "        else:\n"
         "            createLabel(a, name, True, SourceType.USER_DEFINED)\n"
         "        named += 1\n"
         "    except Exception as e:\n"
         "        print(\"ceasta: can't name %s %s: %s\" % (a, name, e))\n"
         "for off, text in comments:\n"
         "    setEOLComment(base.add(off), text)\n"
         "for off, note in bookmarks:\n"
         "    createBookmark(base.add(off), \"ceasta\", note or \"bookmark\")\n"
         "typed = 0\n"
         "try:\n"
         "    from ghidra.app.util.cparser.C import CParserUtils\n"
         "    from ghidra.app.cmd.function import ApplyFunctionSignatureCmd\n"
         "    for off, proto in prototypes:\n"
         "        f = getFunctionAt(base.add(off))\n"
         "        if f is None:\n"
         "            continue\n"
         "        try:\n"
         "            sig = CParserUtils.parseSignature(state.getTool(), currentProgram, proto)\n"
         "            if sig is not None and ApplyFunctionSignatureCmd(f.getEntryPoint(), sig, SourceType.USER_DEFINED)"
         ".applyTo(currentProgram, monitor):\n"
         "                typed += 1\n"
         "        except Exception as e:\n"
         "            print(\"ceasta: can't apply %s: %s\" % (proto, e))\n"
         "except ImportError:\n"
         "    pass\n"
         "print(\"ceasta: %d names, %d comments, %d of %d prototypes\" % (named, len(comments), typed, len(prototypes)))\n";
    return s;
}

std::string export_x64dbg(const database& db)
{
    // x64dbg keeps addresses per module, as offsets into it
    std::string mod = db.bin.name;
    json::value root = json::value::make_object();
    json::value& labels = root["labels"];
    labels = json::value::make_array();
    for (const auto& n : db.user_names) {
        json::value e = json::value::make_object();
        e["module"] = mod;
        e["address"] = rva(db, n.first);
        e["manual"] = true;
        e["text"] = n.second;
        labels.push(std::move(e));
    }
    json::value& comments = root["comments"];
    comments = json::value::make_array();
    for (const auto& c : db.user_comments) {
        json::value e = json::value::make_object();
        e["module"] = mod;
        e["address"] = rva(db, c.first);
        e["manual"] = true;
        std::string t = c.second;
        for (char& ch : t)
            if (ch == '\n' || ch == '\r')
                ch = ' '; // one line each in x64dbg
        e["text"] = t;
        comments.push(std::move(e));
    }
    json::value& marks = root["bookmarks"];
    marks = json::value::make_array();
    for (const auto& b : db.bookmarks) {
        json::value e = json::value::make_object();
        e["module"] = mod;
        e["address"] = rva(db, b.first);
        e["manual"] = true;
        marks.push(std::move(e));
    }
    json::value& bps = root["breakpoints"];
    bps = json::value::make_array();
    for (uint64_t b : db.breakpoints) {
        json::value e = json::value::make_object();
        e["address"] = rva(db, b);
        e["enabled"] = true;
        e["titantype"] = 0;
        e["oldbytes"] = 0;
        e["type"] = 0; // a software breakpoint
        e["name"] = "";
        e["module"] = mod;
        e["breakCondition"] = "";
        e["logText"] = "";
        e["logCondition"] = "";
        e["commandText"] = "";
        e["commandCondition"] = "";
        e["hitCount"] = 0;
        e["fastResume"] = false;
        e["silent"] = false;
        e["singleshoot"] = false;
        bps.push(std::move(e));
    }
    return json::dump(root) + "\n";
}

std::string import_result::summary() const
{
    if (!error.empty())
        return error;
    std::string s = format + ": ";
    std::string parts;
    auto add = [&](int n, const char* what) {
        if (n)
            parts += (parts.empty() ? "" : ", ") + util::fmt("%d %s", n, what);
    };
    add(names, "names");
    add(comments, "comments");
    add(prototypes, "prototypes");
    add(bookmarks, "bookmarks");
    add(breakpoints, "breakpoints");
    s += parts.empty() ? "nothing new" : parts;
    if (skipped)
        s += util::fmt(" (%d skipped: automatic names, or ones that don't fit)", skipped);
    return s;
}

namespace {

void take_name(database& db, uint64_t a, const std::string& name, import_result& r)
{
    std::string err;
    if (automatic(name) || !db.bin.is_mapped(a)) {
        r.skipped++;
        return;
    }
    if (db.name_at(a) == name)
        return;
    if (db.set_name(a, name, err))
        r.names++;
    else
        r.skipped++;
}

void take_comment(database& db, uint64_t a, const std::string& text, import_result& r)
{
    std::string t = util::trim(text);
    if (t.empty() || !db.bin.is_mapped(a) || db.comment_at(a) == t)
        return;
    db.set_comment(a, t);
    r.comments++;
}

uint64_t hexnum(const json::value* v)
{
    if (!v)
        return 0;
    if (v->is_number())
        return (uint64_t)v->num();
    uint64_t x = 0;
    util::parse_hex(v->str(), x);
    return x;
}

// x64dbg: {"labels": [{"module", "address" (an offset in the module), "text"}], "comments", ...}
void import_x64dbg(database& db, const json::value& root, import_result& r)
{
    r.format = "x64dbg database";
    std::string mod = util::lower(db.bin.name);
    auto mine = [&](const json::value& e) {
        const json::value* m = e.get("module");
        return !m || m->str().empty() || util::lower(m->str()) == mod;
    };
    auto each = [&](const char* key, auto&& fn) {
        const json::value* arr = root.get(key);
        if (!arr || !arr->is_array())
            return;
        for (const json::value& e : *arr->a)
            if (e.is_object()) {
                if (mine(e))
                    fn(e, db.bin.base + hexnum(e.get("address")));
                else
                    r.skipped++;
            }
    };
    each("labels", [&](const json::value& e, uint64_t a) { take_name(db, a, util::trim(e.get("text") ? e.get("text")->str() : ""), r); });
    each("comments", [&](const json::value& e, uint64_t a) { take_comment(db, a, e.get("text") ? e.get("text")->str() : "", r); });
    each("bookmarks", [&](const json::value&, uint64_t a) {
        if (db.bin.is_mapped(a) && !db.bookmarks.count(a)) {
            db.set_bookmark(a, true);
            r.bookmarks++;
        }
    });
    each("breakpoints", [&](const json::value& e, uint64_t a) {
        const json::value* t = e.get("type");
        if ((!t || t->num() == 0) && db.bin.is_mapped(a) && !db.breakpoints.count(a)) {
            db.breakpoints.insert(a);
            db.dirty = true;
            r.breakpoints++;
        }
    });
    each("functions", [&](const json::value&, uint64_t) {}); // the analysis finds those itself
}

// the json scripts/ida_to_ceasta.py and scripts/ghidra_to_ceasta.py write:
// {"format": "ceasta-names", "names": [{"rva", "name"}], "comments": [{"rva", "text"}], "prototypes": [...]}
void import_ceasta_json(database& db, const json::value& root, import_result& r)
{
    const json::value* from = root.get("from");
    r.format = from && !from->str().empty() ? from->str() + " names" : "names";
    auto each = [&](const char* key, auto&& fn) {
        const json::value* arr = root.get(key);
        if (arr && arr->is_array())
            for (const json::value& e : *arr->a)
                if (e.is_object())
                    fn(e, db.bin.base + hexnum(e.get("rva")));
    };
    each("names", [&](const json::value& e, uint64_t a) { take_name(db, a, util::trim(e.get("name") ? e.get("name")->str() : ""), r); });
    each("comments", [&](const json::value& e, uint64_t a) { take_comment(db, a, e.get("text") ? e.get("text")->str() : "", r); });
    each("prototypes", [&](const json::value& e, uint64_t a) {
        std::string err, text = e.get("prototype") ? e.get("prototype")->str() : std::string();
        const function* f = db.an.func_containing(a);
        if (!f || f->start != a || text.empty()) {
            r.skipped++;
            return;
        }
        // the other tool's types may not parse here: what does is taken, under the name the
        // function has here (a prototype renames, an import shouldn't)
        prototype p;
        if (!parse_prototype(text, p, err)) {
            r.skipped++;
            return;
        }
        if (!db.name_at(a).empty())
            p.name = db.name_at(a);
        if (db.set_proto(a, format_prototype(p), err))
            r.prototypes++;
        else
            r.skipped++;
    });
}

// a .map file (ida: File > Produce file > Create MAP file; msvc's linker /MAP):
//   segments  " 0001:00000000 00012345H .text  CODE"
//   publics   " 0001:00000040       main   (00401040 f  main.obj)"
void import_map(database& db, const std::string& text, import_result& r)
{
    r.format = "map file";
    std::vector<std::string> map_segs; // by the map's segment number, from its segment list
    std::vector<std::string> lines = util::split(text, "\n");
    auto parse_ref = [](const std::string& t, unsigned& seg, uint64_t& off, size_t& end) {
        // "0001:00000040": four hex digits, a colon, 8 or 16 hex digits
        size_t i = 0;
        while (i < t.size() && t[i] == ' ')
            i++;
        size_t c = t.find(':', i);
        if (c == std::string::npos || c - i != 4)
            return false;
        uint64_t s = 0;
        if (!util::parse_hex(t.substr(i, 4), s))
            return false;
        size_t j = c + 1;
        while (j < t.size() && std::isxdigit((unsigned char)t[j]))
            j++;
        if (j - c - 1 < 8 || !util::parse_hex(t.substr(c + 1, j - c - 1), off))
            return false;
        seg = (unsigned)s;
        end = j;
        return true;
    };
    for (const std::string& raw : lines) {
        std::string t = raw;
        if (!t.empty() && t.back() == '\r')
            t.pop_back();
        unsigned seg;
        uint64_t off;
        size_t end;
        if (!parse_ref(t, seg, off, end))
            continue;
        std::vector<std::string> rest;
        for (const std::string& w : util::split(t.substr(end), " \t"))
            if (!w.empty())
                rest.push_back(w);
        if (rest.size() >= 2 && rest[0].size() >= 2 && (rest[0].back() == 'H' || rest[0].back() == 'h')) {
            // the segment list: length, then the name
            if (map_segs.size() < seg)
                map_segs.resize(seg);
            if (seg)
                map_segs[seg - 1] = rest[1];
            continue;
        }
        if (rest.empty())
            continue;
        std::string name = rest[0];
        uint64_t a = 0;
        uint64_t va = 0;
        if (rest.size() >= 2 && rest[1].size() >= 8 && util::parse_hex(rest[1], va) && db.bin.is_mapped(va)) {
            a = va; // msvc lists the address itself (rva + base)
        } else {
            // the segment by its name in the map's list, else by its number
            const segment* sg = nullptr;
            if (seg && seg <= map_segs.size())
                for (const segment& s : db.bin.segments)
                    if (s.name == map_segs[seg - 1])
                        sg = &s;
            if (!sg && seg && seg <= db.bin.segments.size())
                sg = &db.bin.segments[seg - 1];
            if (!sg) {
                r.skipped++;
                continue;
            }
            a = sg->start + off;
        }
        take_name(db, a, name, r);
    }
}

} // namespace

import_result import_names(database& db, const std::string& path)
{
    import_result r;
    std::vector<uint8_t> bytes;
    std::string err;
    if (!os::read_file(path, bytes, err)) {
        r.error = "can't read " + path + ": " + err;
        return r;
    }
    std::string text(bytes.begin(), bytes.end());
    size_t first = text.find_first_not_of(" \t\r\n");
    if (first != std::string::npos && text[first] == '{') {
        json::value root;
        if (!json::parse(text, root, err)) {
            r.error = "not valid json: " + err;
            return r;
        }
        const json::value* fmt = root.get("format");
        if (fmt && fmt->str() == "ceasta-names")
            import_ceasta_json(db, root, r);
        else if (root.get("labels") || root.get("comments") || root.get("breakpoints") || root.get("bookmarks"))
            import_x64dbg(db, root, r);
        else
            r.error = "a json file, but not an x64dbg database or ceasta's names";
        return r;
    }
    import_map(db, text, r);
    if (!r.names && !r.skipped)
        r.error = "no names found: ceasta reads x64dbg databases (.dd64 / .dd32), .map files, and the json of "
                  "scripts/ida_to_ceasta.py and scripts/ghidra_to_ceasta.py";
    return r;
}
