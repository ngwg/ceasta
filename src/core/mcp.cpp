#include "core/mcp.h"

#include "core/database.h"
#include "core/debugger.h"
#include "core/dbg_stack.h"
#include "core/dbg_trace.h"
#include "core/decompiler.h"
#include "core/diff.h"
#include "core/kuna.h"
#include "core/lua_host.h"
#include "core/os.h"
#include "core/util.h"
#include "version.h"

#include <algorithm>
#include <exception>

namespace {

std::string hexa(uint64_t v) { return "0x" + util::hex_lower(v); }

// ------------------------------------------------------------------ argument helpers

json::value schema(std::initializer_list<std::pair<const char*, json::value>> props,
                   std::initializer_list<const char*> required = {})
{
    json::value s = json::value::make_object();
    s["type"] = "object";
    json::value& p = s["properties"];
    p = json::value::make_object();
    for (const auto& kv : props)
        p[kv.first] = kv.second;
    if (required.size()) {
        json::value& r = s["required"];
        for (const char* k : required)
            r.push(k);
    }
    return s;
}

json::value prop(const char* type, const char* description)
{
    json::value v = json::value::make_object();
    v["type"] = type;
    v["description"] = description;
    return v;
}

// an address argument: hex ("0x401000"), a name ("main"), name+offset ("main+0x10") or a number
bool arg_addr(database& db, const json::value& args, const char* key, uint64_t& out, std::string& err)
{
    const json::value* v = args.get(key);
    if (!v || v->is_null()) {
        err = std::string("missing argument: ") + key;
        return false;
    }
    if (v->is_number()) {
        out = (uint64_t)v->n;
        return true;
    }
    std::string t = util::trim(v->str());
    if (t.empty()) {
        err = std::string("empty argument: ") + key;
        return false;
    }
    if (db.resolve(t, out))
        return true;
    size_t plus = t.find('+');
    uint64_t base = 0, off = 0;
    if (plus != std::string::npos && db.resolve(util::trim(t.substr(0, plus)), base) &&
        util::parse_hex(util::trim(t.substr(plus + 1)), off)) {
        out = base + off;
        return true;
    }
    err = "unknown address or name: " + t;
    return false;
}

int arg_int(const json::value& args, const char* key, int fallback, int lo, int hi)
{
    const json::value* v = args.get(key);
    long long n = fallback;
    if (v && v->is_number())
        n = (long long)v->n;
    else if (v && v->is_string() && !v->s.empty())
        n = strtoll(v->s.c_str(), nullptr, 0);
    return (int)std::max<long long>(lo, std::min<long long>(hi, n));
}

std::string arg_str(const json::value& args, const char* key)
{
    const json::value* v = args.get(key);
    return v ? v->str() : std::string();
}

bool arg_bool(const json::value& args, const char* key, bool fallback)
{
    const json::value* v = args.get(key);
    if (!v)
        return fallback;
    if (v->is_bool())
        return v->b;
    if (v->is_string())
        return v->s == "true" || v->s == "1" || v->s == "yes";
    return fallback;
}

// ------------------------------------------------------------------ text helpers

const size_t max_output = 120 * 1024;

void cap(std::string& out)
{
    if (out.size() > max_output) {
        size_t cut = out.rfind('\n', max_output);
        out.resize(cut == std::string::npos ? max_output : cut);
        out += "\n... (output cut at " + std::to_string(max_output / 1024) + " KB, ask for less)";
    }
}

std::string listing_line(database& db, const row& r)
{
    line_text t;
    db.format(r, t);
    if (r.kind == row_kind::blank)
        return std::string();
    std::string s = util::fmt("%-22s %s", t.addr.c_str(), t.text.c_str());
    std::string c = t.comment.empty() ? t.auto_comment
                                      : (t.auto_comment.empty() ? t.comment : t.comment + " | " + t.auto_comment);
    if (!c.empty())
        s += "  ; " + c;
    while (!s.empty() && s.back() == ' ')
        s.pop_back();
    return s;
}

std::string byte_view(uint64_t addr, const uint8_t* p, size_t n)
{
    std::string out;
    for (size_t i = 0; i < n; i += 16) {
        out += util::fmt("%016llx  ", (unsigned long long)(addr + i));
        for (size_t k = 0; k < 16; k++)
            out += i + k < n ? util::fmt("%02x ", p[i + k]) : std::string("   ");
        out += " ";
        for (size_t k = 0; k < 16 && i + k < n; k++)
            out += p[i + k] >= 0x20 && p[i + k] < 0x7F ? (char)p[i + k] : '.';
        out += "\n";
    }
    return out;
}

// paging for the list tools
struct page {
    int offset = 0, limit = 0;
    size_t total = 0, shown = 0;
    std::string body;
    void add(size_t index, const std::string& line)
    {
        total = index + 1;
        if ((int)index >= offset && (int)index < offset + limit) {
            body += line + "\n";
            shown++;
        }
    }
    std::string finish(const std::string& what) const
    {
        std::string head = shown ? util::fmt("%s %d-%d of %zu\n", what.c_str(), offset + 1, offset + (int)shown, total)
                                 : util::fmt("%s: none%s (%zu in total)\n", what.c_str(),
                                             offset ? " at this offset" : "", total);
        std::string tail;
        if ((size_t)(offset + (int)shown) < total)
            tail = util::fmt("... %zu more, pass offset %d\n", total - (size_t)(offset + (int)shown), offset + (int)shown);
        return head + body + tail;
    }
};

page make_page(const json::value& args, int def_limit)
{
    page p;
    p.offset = arg_int(args, "offset", 0, 0, 1 << 30);
    p.limit = arg_int(args, "limit", def_limit, 1, 2000);
    return p;
}

const char* const xref_kinds[] = {"call", "jump", "read", "write", "offset"};

database* need_db(mcp_server& s, std::string& out)
{
    database* db = s.get_db ? s.get_db() : nullptr;
    if (!db)
        out = "no file is open in ceasta";
    return db;
}

} // namespace

// ------------------------------------------------------------------ read-only tools

namespace {

using tool = mcp_server::tool;

void add_read_tools(std::vector<tool>& t)
{
    auto add = [&](const char* name, const char* desc, json::value sch, tool::run_t fn) {
        tool x;
        x.name = name;
        x.description = desc;
        x.schema = std::move(sch);
        x.run = std::move(fn);
        t.push_back(std::move(x));
    };

    add("get_binary_info",
        "Overview of the loaded file: format, architecture, entry point, base address, segments with their entropy, "
        "imported libraries, security flags, hashes (md5, sha256, imphash), version info, resources, warnings "
        "(packed, an embedded program, an overlay, .net), and how many functions, imports, exports and strings the "
        "analysis found. A good first call.",
        schema({}), [](mcp_server& s, const json::value&, std::string& out) {
            database* db = need_db(s, out);
            if (!db)
                return false;
            const binary& b = db->bin;
            out += "file      " + b.path + "\n";
            out += util::fmt("format    %s %s (%s)\n", format_name(b.format), arch_name(b.arch), b.kind.c_str());
            out += "base      " + hexa(b.base) + "\n";
            out += "entry     " + (b.has_entry ? hexa(b.entry) + " " + db->name_at(b.entry) : std::string("none")) + "\n";
            out += util::fmt("counts    %zu functions, %zu imports, %zu exports, %zu strings\n", db->an.funcs.size(),
                             b.imports.size(), b.exports.size(), db->an.strings.size());
            if (!b.libs.empty()) {
                out += "libraries";
                for (const std::string& l : b.libs)
                    out += " " + l;
                out += "\n";
            }
            out += "segments\n";
            for (const segment& sg : b.segments)
                out += util::fmt("  %-12s %s - %s  %c%c%c\n", sg.name.c_str(), hexa(sg.start).c_str(),
                                 hexa(sg.end).c_str(), (sg.perms & perm_r) ? 'r' : '-', (sg.perms & perm_w) ? 'w' : '-',
                                 (sg.perms & perm_x) ? 'x' : '-');
            for (const std::string& n : b.notes)
                out += "note: " + n + "\n";
            const file_info& fi = db->info;
            for (const file_info::row& r : fi.header)
                if (r.label != "file" && r.label != "entry point" && r.label != "image base" && r.label != "format")
                    out += util::fmt("%-9s %s\n", r.label.c_str(), r.value.c_str());
            out += "md5       " + fi.md5 + "\nsha256    " + fi.sha256 + "\n";
            if (!fi.imphash.empty())
                out += "imphash   " + fi.imphash + "\n";
            for (const file_info::row& r : fi.version)
                out += "version   " + r.label + ": " + r.value + "\n";
            out += "sections (entropy, 8 = random)\n";
            for (const file_info::section& sc : fi.sections)
                out += util::fmt("  %-12s %s  %s  %.2f\n", sc.name.c_str(), hexa(sc.addr).c_str(), sc.perms.c_str(), sc.entropy);
            size_t shown = 0;
            for (const file_info::resource& r : fi.resources)
                if (shown++ < 40)
                    out += util::fmt("resource  %s/%s %llu bytes, entropy %.2f%s\n", r.type.c_str(), r.name.c_str(),
                        (unsigned long long)r.size, r.entropy, r.note.empty() ? "" : (", " + r.note).c_str());
            for (const std::string& w : fi.warnings)
                out += "warning: " + w + "\n";
            return true;
        });

    add("list_functions",
        "Functions found by the analysis: address, size and name, sorted by address. Names like sub_401000 are "
        "not yet named. Use filter for a case-insensitive name search and offset/limit to page.",
        schema({{"filter", prop("string", "only names containing this")},
                {"offset", prop("integer", "skip this many matches (paging)")},
                {"limit", prop("integer", "at most this many (default 200)")}}),
        [](mcp_server& s, const json::value& args, std::string& out) {
            database* db = need_db(s, out);
            if (!db)
                return false;
            std::string filter = arg_str(args, "filter");
            page p = make_page(args, 200);
            size_t i = 0;
            for (const function& f : db->an.funcs) {
                std::string name = db->name_at(f.start);
                if (!util::icontains(name, filter))
                    continue;
                p.add(i++, util::fmt("%s  size 0x%llx  %s%s", hexa(f.start).c_str(),
                                     (unsigned long long)(f.end - f.start), name.c_str(), f.thunk ? "  (thunk)" : ""));
            }
            out = p.finish(filter.empty() ? "functions" : "functions matching \"" + filter + "\"");
            return true;
        });

    add("decompile_function",
        "C-like pseudocode for the function at or containing an address or name. Stack variables are local_1c "
        "(0x1c below the return address) and arg_0, arg_4 (stack arguments); registers stand in for the other "
        "values (rdi, rsi, ... are the arguments on system v; rcx, rdx, r8, r9 on windows). Calls to well-known "
        "functions (windows api, libc) get their real arguments. rename_variable, set_variable_type and "
        "set_function_prototype make it read better. Check the disassembly when something looks off.",
        schema({{"function", prop("string", "name or address of the function, or any address inside it")}},
               {"function"}),
        [](mcp_server& s, const json::value& args, std::string& out) {
            database* db = need_db(s, out);
            uint64_t a;
            if (!db || !arg_addr(*db, args, "function", a, out))
                return false;
            const function* f = db->an.func_containing(a);
            if (!f) {
                out = "no function at " + hexa(a) + " (list_functions shows them)";
                return false;
            }
            out = "// " + db->location(f->start) + " at " + hexa(f->start) + "\n" + decompile_text(*db, f->start);
            cap(out);
            return true;
        });

    add("decompile_with_kuna",
        "The same function decompiled by kuna, a decompiler ported from Ghidra's that the user has installed. It is "
        "often better than decompile_function on optimized code, and it also reads arm64. It names things itself "
        "(sub_401000, dat_404010, a0 for arguments), so renames and types set in ceasta don't show up here; its "
        "addresses are the same as ceasta's. Use it for a second opinion on a hard function.",
        schema({{"function", prop("string", "name or address of the function, or any address inside it")}},
               {"function"}),
        [](mcp_server& s, const json::value& args, std::string& out) {
            // what kuna needs comes from the database; kuna itself runs here, off the owner
            // thread, so a slow run doesn't hold the app up
            std::string file, why, name;
            uint64_t start = 0;
            bool ok = false;
            s.run([&] {
                database* db = need_db(s, out);
                uint64_t a;
                if (!db || !arg_addr(*db, args, "function", a, out))
                    return;
                const function* f = db->an.func_containing(a);
                if (!f) {
                    out = "no function at " + hexa(a) + " (list_functions shows them)";
                    return;
                }
                why = kuna_unsupported(db->bin);
                if (why.empty())
                    file = kuna_input(db->bin, why);
                start = f->start;
                name = db->location(f->start);
                ok = true;
            });
            if (!ok)
                return false;
            if (!why.empty()) {
                out = why;
                return false;
            }
            kuna_result k = kuna_decompile(s.opts.kuna, file, start, 120000, &s.stopping);
            if (!k.ok) {
                out = k.error;
                return false;
            }
            out = "// kuna: " + name + " at " + hexa(start) + (k.name.empty() || k.name == name ? "" : " (kuna calls it " + k.name + ")") +
                  "\n" + k.code;
            cap(out);
            return true;
        });
    t.back().owner = false;
    t.back().kuna = true;

    add("disassemble",
        "The listing from an address: instructions with names in place of addresses, labels, data and comments.",
        schema({{"address", prop("string", "where to start: hex address or name")},
                {"count", prop("integer", "how many lines (default 60, at most 800)")}},
               {"address"}),
        [](mcp_server& s, const json::value& args, std::string& out) {
            database* db = need_db(s, out);
            uint64_t a;
            if (!db || !arg_addr(*db, args, "address", a, out))
                return false;
            int n = arg_int(args, "count", 60, 1, 800);
            const std::vector<row>& rows = db->rows();
            for (size_t i = db->row_of(a); i < rows.size() && n > 0; i++) {
                std::string l = listing_line(*db, rows[i]);
                if (!l.empty()) {
                    out += l + "\n";
                    n--;
                }
            }
            return true;
        });

    add("disassemble_function", "The whole listing of the function at or containing an address or name.",
        schema({{"function", prop("string", "name or address of the function, or any address inside it")}},
               {"function"}),
        [](mcp_server& s, const json::value& args, std::string& out) {
            database* db = need_db(s, out);
            uint64_t a;
            if (!db || !arg_addr(*db, args, "function", a, out))
                return false;
            const function* f = db->an.func_containing(a);
            if (!f) {
                out = "no function at " + hexa(a);
                return false;
            }
            const std::vector<row>& rows = db->rows();
            size_t i = db->row_of(f->start);
            while (i > 0 && rows[i - 1].addr == f->start)
                i--;
            int lines = 0;
            for (; i < rows.size() && rows[i].addr < f->end && lines < 3000; i++, lines++) {
                std::string l = listing_line(*db, rows[i]);
                if (!l.empty())
                    out += l + "\n";
            }
            cap(out);
            return true;
        });
}

} // namespace

namespace {

void add_query_tools(std::vector<tool>& t)
{
    auto add = [&](const char* name, const char* desc, json::value sch, tool::run_t fn) {
        tool x;
        x.name = name;
        x.description = desc;
        x.schema = std::move(sch);
        x.run = std::move(fn);
        t.push_back(std::move(x));
    };

    add("list_types",
        "The C types declared for this file (define_types, create_struct_from_usage, the user's): structs, unions, "
        "enums and typedefs with each field's offset and size. With a name, just that one.",
        schema({{"name", prop("string", "one type: node, struct node, a typedef's name")}}),
        [](mcp_server& s, const json::value& args, std::string& out) {
            database* db = need_db(s, out);
            if (!db)
                return false;
            std::string n = util::trim(arg_str(args, "name"));
            if (!n.empty()) {
                const ctype_def* d = db->types.find(n);
                if (!d) {
                    out = "no type " + n;
                    return false;
                }
                out = db->types.text(*d);
                return true;
            }
            out = db->types.all_text(true);
            if (out.empty())
                out = "no types are declared (define_types adds them)";
            return true;
        });

    add("get_xrefs_to",
        "Who references an address: calls, jumps, data reads / writes and pointers to it, each with the function "
        "it comes from. Use it to find the callers of a function or the users of a string or global.",
        schema({{"address", prop("string", "hex address or name")},
                {"limit", prop("integer", "at most this many (default 300)")}},
               {"address"}),
        [](mcp_server& s, const json::value& args, std::string& out) {
            database* db = need_db(s, out);
            uint64_t a;
            if (!db || !arg_addr(*db, args, "address", a, out))
                return false;
            int limit = arg_int(args, "limit", 300, 1, 5000);
            auto refs = db->an.refs_to(a);
            size_t n = (size_t)(refs.second - refs.first);
            out = util::fmt("%zu references to %s (%s)\n", n, db->location(a).c_str(), hexa(a).c_str());
            int shown = 0;
            for (const xref* x = refs.first; x != refs.second && shown < limit; x++, shown++)
                out += util::fmt("%s  %-6s %s\n", hexa(x->from).c_str(), xref_kinds[(int)x->type],
                                 db->location(x->from).c_str());
            if ((size_t)shown < n)
                out += util::fmt("... %zu more\n", n - (size_t)shown);
            return true;
        });

    add("get_xrefs_from",
        "What an instruction references, or with whole_function what a whole function references: the functions "
        "it calls, the strings and globals it uses.",
        schema({{"address", prop("string", "hex address or name")},
                {"whole_function", prop("boolean", "everything referenced from the function containing address")}},
               {"address"}),
        [](mcp_server& s, const json::value& args, std::string& out) {
            database* db = need_db(s, out);
            uint64_t a;
            if (!db || !arg_addr(*db, args, "address", a, out))
                return false;
            uint64_t lo = a, hi = a + 1;
            if (arg_bool(args, "whole_function", false)) {
                const function* f = db->an.func_containing(a);
                if (!f) {
                    out = "no function at " + hexa(a);
                    return false;
                }
                lo = f->start;
                hi = f->end;
            }
            const std::vector<xref>& xs = db->an.xfrom;
            auto it = std::lower_bound(xs.begin(), xs.end(), lo, [](const xref& x, uint64_t v) { return x.from < v; });
            size_t n = 0;
            for (; it != xs.end() && it->from < hi && n < 2000; ++it, n++)
                out += util::fmt("%s  %-6s -> %s  %s\n", hexa(it->from).c_str(), xref_kinds[(int)it->type],
                                 hexa(it->to).c_str(), db->location(it->to).c_str());
            if (!n)
                out = "no references from " + db->location(a) + "\n";
            return true;
        });

    add("list_strings",
        "Strings found in the file (ascii and utf-16) with their addresses. Filter is a case-insensitive "
        "substring. get_xrefs_to on a string's address shows the code that uses it.",
        schema({{"filter", prop("string", "only strings containing this")},
                {"offset", prop("integer", "skip this many matches (paging)")},
                {"limit", prop("integer", "at most this many (default 200)")}}),
        [](mcp_server& s, const json::value& args, std::string& out) {
            database* db = need_db(s, out);
            if (!db)
                return false;
            std::string filter = arg_str(args, "filter");
            page p = make_page(args, 200);
            size_t i = 0;
            for (const string_item& st : db->an.strings) {
                if (!util::icontains(st.text, filter))
                    continue;
                p.add(i++, hexa(st.addr) + "  " + (st.wide ? "L" : "") + "\"" + util::escape(st.text, 300) + "\"");
            }
            out = p.finish(filter.empty() ? "strings" : "strings containing \"" + filter + "\"");
            return true;
        });

    add("list_imports", "Imported functions (library and name) with the address of their slot.",
        schema({{"filter", prop("string", "only names containing this")}}),
        [](mcp_server& s, const json::value& args, std::string& out) {
            database* db = need_db(s, out);
            if (!db)
                return false;
            std::string filter = arg_str(args, "filter");
            size_t n = 0;
            for (const import_entry& e : db->bin.imports)
                if (util::icontains(e.name, filter) && n++ < 3000)
                    out += hexa(e.slot) + "  " + (e.lib.empty() ? std::string("?") : e.lib) + "!" + e.name + "\n";
            if (!n)
                out = "no imports" + (filter.empty() ? std::string() : " matching \"" + filter + "\"") + "\n";
            return true;
        });

    add("list_exports", "Exported symbols with their addresses.",
        schema({{"filter", prop("string", "only names containing this")}}),
        [](mcp_server& s, const json::value& args, std::string& out) {
            database* db = need_db(s, out);
            if (!db)
                return false;
            std::string filter = arg_str(args, "filter");
            size_t n = 0;
            for (const export_entry& e : db->bin.exports)
                if (util::icontains(e.name, filter) && n++ < 3000)
                    out += (e.forward.empty() ? hexa(e.addr) : std::string("forward")) + "  " + e.name +
                           (e.forward.empty() ? std::string() : " -> " + e.forward) + "\n";
            if (!n)
                out = "no exports" + (filter.empty() ? std::string() : " matching \"" + filter + "\"") + "\n";
            return true;
        });

    add("read_bytes", "Bytes of the file as loaded, shown as a hex + ascii view.",
        schema({{"address", prop("string", "hex address or name")},
                {"length", prop("integer", "how many bytes (default 128, at most 4096)")}},
               {"address"}),
        [](mcp_server& s, const json::value& args, std::string& out) {
            database* db = need_db(s, out);
            uint64_t a;
            if (!db || !arg_addr(*db, args, "address", a, out))
                return false;
            std::vector<uint8_t> buf((size_t)arg_int(args, "length", 128, 1, 4096));
            size_t n = db->bin.read(a, buf.data(), buf.size());
            if (!n) {
                out = hexa(a) + " is not in the file";
                return false;
            }
            out = byte_view(a, buf.data(), n);
            return true;
        });

    add("search_bytes",
        "Find a byte pattern in the file, like \"48 8b ?? 05\" (?? matches any byte). Good for constants: crypto "
        "tables, magic numbers, known instruction sequences.",
        schema({{"pattern", prop("string", "hex bytes separated by spaces, ?? for any byte")}}, {"pattern"}),
        [](mcp_server& s, const json::value& args, std::string& out) {
            database* db = need_db(s, out);
            if (!db)
                return false;
            std::vector<uint64_t> hits = db->find_bytes(arg_str(args, "pattern"), 0, 300);
            for (uint64_t h : hits)
                out += hexa(h) + "  " + db->location(h) + "\n";
            if (hits.empty())
                out = "no matches (or a malformed pattern)\n";
            return true;
        });

    add("lookup",
        "What is at an address, or who has a name: the address, the name, the function it is in, its segment, and "
        "whether it is an import, an export or a string.",
        schema({{"what", prop("string", "hex address or name")}}, {"what"}),
        [](mcp_server& s, const json::value& args, std::string& out) {
            database* db = need_db(s, out);
            uint64_t a;
            if (!db || !arg_addr(*db, args, "what", a, out))
                return false;
            out = "address   " + hexa(a) + "\n";
            std::string n = db->name_at(a);
            if (!n.empty())
                out += "name      " + n + "\n";
            out += "location  " + db->location(a) + "\n";
            std::string sg = db->seg_name(a);
            out += "segment   " + (sg.empty() ? std::string("(not in the file)") : sg) + "\n";
            if (const function* f = db->an.func_containing(a))
                out += util::fmt("function  %s at %s, size 0x%llx\n", db->name_at(f->start).c_str(),
                                 hexa(f->start).c_str(), (unsigned long long)(f->end - f->start));
            for (const import_entry& e : db->bin.imports)
                if (e.slot == a)
                    out += "import    " + e.lib + "!" + e.name + "\n";
            for (const string_item& st : db->an.strings)
                if (st.addr == a)
                    out += "string    \"" + util::escape(st.text, 300) + "\"\n";
            std::string c = db->comment_at(a);
            if (!c.empty())
                out += "comment   " + c + "\n";
            return true;
        });

    add("diff_binary",
        "Compare the open file with another one on disk at the function level and report what changed - "
        "which functions are identical, which changed (with a similarity score), which were added or "
        "removed. Matching ignores load addresses, so it works across builds.",
        schema({{"path", prop("string", "path to the other file to compare against")},
                {"limit", prop("integer", "at most this many entries per section (default 60)")}},
               {"path"}),
        [](mcp_server& s, const json::value& args, std::string& out) {
            database* db = need_db(s, out);
            if (!db)
                return false;
            std::string path = arg_str(args, "path"), err;
            load_options lo;
            // two universal mach-o files: compare the same part of each
            lo.has_slice = db->bin.format == bin_format::macho;
            lo.slice = db->bin.arch;
            std::unique_ptr<database> other = open_database(path, lo, nullptr, err);
            if (!other) {
                out = "can't open " + path + ": " + err;
                return false;
            }
            int limit = arg_int(args, "limit", 60, 1, 1000);
            diff_result d = diff_databases(*db, *other);
            out = util::fmt("this file: %zu functions, %s: %zu functions\n", d.funcs_a, other->bin.name.c_str(),
                            d.funcs_b);
            out += util::fmt("identical %zu, changed %zu, added %zu, removed %zu\n", d.identical.size(),
                             d.changed.size(), d.added.size(), d.removed.size());
            int n = 0;
            if (!d.changed.empty())
                out += "\nchanged (most different first):\n";
            for (const diff_pair& p : d.changed) {
                if (n++ >= limit) {
                    out += util::fmt("... %zu more\n", d.changed.size() - (size_t)limit);
                    break;
                }
                out += util::fmt("  %3.0f%%  %-28s  %s -> %s\n", p.similarity * 100, p.name.c_str(),
                                 hexa(p.a).c_str(), hexa(p.b).c_str());
            }
            n = 0;
            if (!d.added.empty())
                out += "\nadded (only in the other file):\n";
            for (uint64_t x : d.added) {
                if (n++ >= limit)
                    break;
                out += "  " + hexa(x) + "  " + other->location(x) + "\n";
            }
            n = 0;
            if (!d.removed.empty())
                out += "\nremoved (only in this file):\n";
            for (uint64_t x : d.removed) {
                if (n++ >= limit)
                    break;
                out += "  " + hexa(x) + "  " + db->location(x) + "\n";
            }
            cap(out);
            return true;
        });

    add("get_basic_blocks", "The control flow graph of a function: its basic blocks and the edges between them.",
        schema({{"function", prop("string", "name or address of the function")}}, {"function"}),
        [](mcp_server& s, const json::value& args, std::string& out) {
            database* db = need_db(s, out);
            uint64_t a;
            if (!db || !arg_addr(*db, args, "function", a, out))
                return false;
            const function* f = db->an.func_containing(a);
            cfg g;
            if (!f || !build_cfg(db->bin, db->an, f->start, g)) {
                out = "no function at " + hexa(a);
                return false;
            }
            static const char* const kinds[] = {"next", "taken", "not_taken", "jump", "table"};
            for (size_t i = 0; i < g.blocks.size(); i++) {
                const cfg_block& b = g.blocks[i];
                out += util::fmt("block %zu  %s - %s  (%zu instructions)", i, hexa(b.start).c_str(),
                                 hexa(b.end).c_str(), b.insns.size());
                for (const cfg_edge& e : b.succ)
                    out += util::fmt("  -> %u %s", e.to, kinds[(int)e.kind]);
                out += "\n";
            }
            if (g.truncated)
                out += "(truncated)\n";
            return true;
        });
}

} // namespace

namespace {

// the cli server keeps the files on disk current after every edit
void autosave(mcp_server& s, database& db)
{
    std::string err;
    if (s.opts.autosave && db.save(err))
        db.dirty = false;
}

void add_edit_tools(std::vector<tool>& t)
{
    tool rn;
    rn.name = "rename";
    rn.description =
        "Give an address (usually a function or a global) a name. It shows everywhere in ceasta - listing, "
        "pseudocode, xrefs - and is saved with the user's project. Name functions by what they do "
        "(parse_config, decrypt_string). An empty name removes the user's name.";
    rn.schema = schema({{"address", prop("string", "hex address or current name")},
                        {"name", prop("string", "the new name")}},
                       {"address", "name"});
    rn.writes = true;
    rn.run = [](mcp_server& s, const json::value& args, std::string& out) {
        database* db = need_db(s, out);
        uint64_t a;
        if (!db || !arg_addr(*db, args, "address", a, out))
            return false;
        std::string old = db->location(a), err;
        std::string name = util::trim(arg_str(args, "name"));
        if (!db->set_name(a, name, err)) {
            out = "can't rename " + old + ": " + err;
            return false;
        }
        autosave(s, *db);
        if (s.on_changed)
            s.on_changed();
        out = name.empty() ? "removed the name at " + hexa(a) : "renamed " + old + " to " + name;
        return true;
    };
    t.push_back(std::move(rn));

    tool cm;
    cm.name = "set_comment";
    cm.description =
        "Put a comment on an address; it shows in the listing next to the instruction and is saved with the "
        "project. An empty comment removes it.";
    cm.schema = schema({{"address", prop("string", "hex address or name")},
                        {"comment", prop("string", "the text")}},
                       {"address", "comment"});
    cm.writes = true;
    cm.run = [](mcp_server& s, const json::value& args, std::string& out) {
        database* db = need_db(s, out);
        uint64_t a;
        if (!db || !arg_addr(*db, args, "address", a, out))
            return false;
        db->set_comment(a, arg_str(args, "comment"));
        autosave(s, *db);
        if (s.on_changed)
            s.on_changed();
        out = "comment set at " + db->location(a);
        return true;
    };
    t.push_back(std::move(cm));

    // the pseudocode's variables and prototypes
    auto func_of = [](database& db, const json::value& args, uint64_t& f, std::string& out) {
        uint64_t a = 0;
        if (!arg_addr(db, args, "function", a, out))
            return false;
        const function* fn = db.an.func_containing(a);
        if (!fn) {
            out = "no function at " + hexa(a);
            return false;
        }
        f = fn->start;
        return true;
    };
    // a variable by the name the pseudocode shows now (or its automatic name)
    auto var_key = [](database& db, uint64_t f, const std::string& name, std::string& key, std::string& out) {
        decompiled d = decompile(db, f);
        for (const decomp_var& v : d.vars)
            if (v.name == name || v.key == name) {
                key = v.key;
                return true;
            }
        std::string all;
        for (const decomp_var& v : d.vars)
            all += (all.empty() ? "" : ", ") + v.name;
        out = "no variable " + name + " in " + db.location(f) + (all.empty() ? std::string() : " (it has: " + all + ")");
        return false;
    };

    tool rv;
    rv.name = "rename_variable";
    rv.description =
        "Rename a variable in a function's pseudocode: a parameter (rdi, arg_0), a stack variable (local_1c) or a "
        "register the code keeps a value in (rax). Use the name decompile_function shows. Saved with the project; "
        "an empty name goes back to the automatic one.";
    rv.schema = schema({{"function", prop("string", "the function: name or address")},
                        {"variable", prop("string", "the variable as the pseudocode shows it")},
                        {"name", prop("string", "the new name")}},
                       {"function", "variable", "name"});
    rv.writes = true;
    rv.run = [func_of, var_key](mcp_server& s, const json::value& args, std::string& out) {
        database* db = need_db(s, out);
        uint64_t f = 0;
        std::string key, err;
        if (!db || !func_of(*db, args, f, out) || !var_key(*db, f, util::trim(arg_str(args, "variable")), key, out))
            return false;
        std::string type;
        auto it = db->lvars.find(f);
        if (it != db->lvars.end() && it->second.count(key))
            type = it->second.at(key).type;
        std::string name = util::trim(arg_str(args, "name"));
        if (!db->set_lvar(f, key, name == key ? std::string() : name, type, err)) {
            out = "can't rename it: " + err;
            return false;
        }
        autosave(s, *db);
        if (s.on_changed)
            s.on_changed();
        out = "renamed " + arg_str(args, "variable") + " to " + (name.empty() ? key : name) + " in " + db->location(f);
        return true;
    };
    t.push_back(std::move(rv));

    tool vt;
    vt.name = "set_variable_type";
    vt.description =
        "Give a variable of a function's pseudocode a type (int, char*, DWORD, struct header*, char[16]). The "
        "declaration and the signature show it, and a pointer to a struct you declared (define_types) reads as "
        "p->field. Empty goes back to the automatic type.";
    vt.schema = schema({{"function", prop("string", "the function: name or address")},
                        {"variable", prop("string", "the variable as the pseudocode shows it")},
                        {"type", prop("string", "the c type")}},
                       {"function", "variable", "type"});
    vt.writes = true;
    vt.run = [func_of, var_key](mcp_server& s, const json::value& args, std::string& out) {
        database* db = need_db(s, out);
        uint64_t f = 0;
        std::string key, err;
        if (!db || !func_of(*db, args, f, out) || !var_key(*db, f, util::trim(arg_str(args, "variable")), key, out))
            return false;
        std::string name;
        auto it = db->lvars.find(f);
        if (it != db->lvars.end() && it->second.count(key))
            name = it->second.at(key).name;
        if (!db->set_lvar(f, key, name, util::trim(arg_str(args, "type")), err)) {
            out = "can't set the type: " + err;
            return false;
        }
        autosave(s, *db);
        if (s.on_changed)
            s.on_changed();
        out = "set the type of " + arg_str(args, "variable") + " in " + db->location(f);
        return true;
    };
    t.push_back(std::move(vt));

    tool fp;
    fp.name = "set_function_prototype";
    fp.description =
        "Set a function's prototype in c: \"int check_key(const char* key, int len)\". Its parameters take those "
        "names and types in its pseudocode, a new name renames the function, and calls to it get that many "
        "arguments. An empty prototype goes back to what the decompiler works out.";
    fp.schema = schema({{"function", prop("string", "the function: name or address")},
                        {"prototype", prop("string", "return type, name, parameters")}},
                       {"function", "prototype"});
    fp.writes = true;
    fp.run = [func_of](mcp_server& s, const json::value& args, std::string& out) {
        database* db = need_db(s, out);
        uint64_t f = 0;
        std::string err;
        if (!db || !func_of(*db, args, f, out))
            return false;
        if (!db->set_proto(f, arg_str(args, "prototype"), err)) {
            out = "can't set it: " + err;
            return false;
        }
        autosave(s, *db);
        if (s.on_changed)
            s.on_changed();
        auto p = db->protos.find(f);
        out = p == db->protos.end() ? "removed the prototype of " + db->location(f)
                                    : "prototype of " + db->location(f) + ": " + format_prototype(p->second);
        return true;
    };
    t.push_back(std::move(fp));

    // c types: structs, unions, enums, typedefs
    tool dt;
    dt.name = "define_types";
    dt.description =
        "Declare C types - structs, unions, enums, typedefs - in C: \"struct node { int value; struct node* "
        "next; };\". They're laid out the way this file's compiler would (pointer size, windows or not, "
        "#pragma pack, bit fields), saved with the project, and a variable typed as a pointer to a struct "
        "(set_variable_type) reads as p->field in the pseudocode. A definition with a name already there replaces "
        "it: use it to rename the fields of a struct you made with create_struct_from_usage.";
    dt.schema = schema({{"declarations", prop("string", "c declarations")}}, {"declarations"});
    dt.writes = true;
    dt.run = [](mcp_server& s, const json::value& args, std::string& out) {
        database* db = need_db(s, out);
        std::string err;
        std::vector<std::string> names;
        if (!db)
            return false;
        if (!db->add_types(arg_str(args, "declarations"), err, &names)) {
            out = "can't declare them: " + err;
            return false;
        }
        autosave(s, *db);
        if (s.on_changed)
            s.on_changed();
        out = names.empty() ? "nothing was defined (declarations of types only: struct, union, enum, typedef)\n" : "";
        for (const std::string& n : names)
            if (const ctype_def* d = db->types.find(n))
                out += db->types.text(*d) + "\n";
        return true;
    };
    t.push_back(std::move(dt));

    tool cs;
    cs.name = "create_struct_from_usage";
    cs.description =
        "Make a struct from how a variable of a function is used: a field at every offset the code reads or "
        "writes through it (field_18, sized by the access; a field it follows to the next one points to the "
        "struct), bytes for the gaps. The struct is declared and the variable typed as a pointer to it, so the "
        "pseudocode reads p->field_18. Rename the fields with define_types when you know what they are.";
    cs.schema = schema({{"function", prop("string", "the function: name or address")},
                        {"variable", prop("string", "the variable as the pseudocode shows it (a pointer)")},
                        {"name", prop("string", "the struct's name (optional, one is made up)")}},
                       {"function", "variable"});
    cs.writes = true;
    cs.run = [func_of](mcp_server& s, const json::value& args, std::string& out) {
        database* db = need_db(s, out);
        uint64_t f = 0;
        if (!db || !func_of(*db, args, f, out))
            return false;
        std::string name = util::trim(arg_str(args, "name")), decl, err;
        if (!struct_from_uses(*db, f, util::trim(arg_str(args, "variable")), name, decl, err, true)) {
            out = "can't make it: " + err;
            return false;
        }
        autosave(s, *db);
        if (s.on_changed)
            s.on_changed();
        const ctype_def* d = db->types.find(name);
        out = (d ? db->types.text(*d) : decl) + "\n" + arg_str(args, "variable") + " is a struct " + name + "* now";
        return true;
    };
    t.push_back(std::move(cs));

    // names for the user to review, instead of renaming right away
    tool sg;
    sg.name = "suggest_name";
    sg.description =
        "Propose a name for a function or global without renaming it: the user reviews your suggestions in "
        "ceasta (AI > Review suggested names) and accepts or rejects each. Prefer this over rename when you're "
        "naming many things or aren't sure. Give a one-line reason (what it does, the evidence).";
    sg.schema = schema({{"address", prop("string", "hex address or current name")},
                        {"name", prop("string", "the proposed name, like parse_config")},
                        {"reason", prop("string", "why, in one line")}},
                       {"address", "name"});
    sg.writes = true;
    sg.run = [](mcp_server& s, const json::value& args, std::string& out) {
        database* db = need_db(s, out);
        uint64_t a;
        std::string err;
        if (!db || !arg_addr(*db, args, "address", a, out))
            return false;
        if (!db->suggest(a, std::string(), arg_str(args, "name"), arg_str(args, "reason"), err)) {
            out = "can't suggest that: " + err;
            return false;
        }
        autosave(s, *db);
        if (s.on_changed)
            s.on_changed();
        out = util::fmt("suggested %s for %s (%zu waiting for review)", util::trim(arg_str(args, "name")).c_str(),
                        db->location(a).c_str(), db->suggestions.size());
        return true;
    };
    t.push_back(std::move(sg));

    tool sv;
    sv.name = "suggest_variable_name";
    sv.description =
        "Propose a name for a variable of a function's pseudocode (as decompile_function shows it) for the user "
        "to review, like suggest_name.";
    sv.schema = schema({{"function", prop("string", "the function: name or address")},
                        {"variable", prop("string", "the variable as the pseudocode shows it")},
                        {"name", prop("string", "the proposed name")},
                        {"reason", prop("string", "why, in one line")}},
                       {"function", "variable", "name"});
    sv.writes = true;
    sv.run = [func_of, var_key](mcp_server& s, const json::value& args, std::string& out) {
        database* db = need_db(s, out);
        uint64_t f = 0;
        std::string key, err;
        if (!db || !func_of(*db, args, f, out) || !var_key(*db, f, util::trim(arg_str(args, "variable")), key, out))
            return false;
        if (!db->suggest(f, key, arg_str(args, "name"), arg_str(args, "reason"), err)) {
            out = "can't suggest that: " + err;
            return false;
        }
        autosave(s, *db);
        if (s.on_changed)
            s.on_changed();
        out = util::fmt("suggested %s for %s in %s (%zu waiting for review)", util::trim(arg_str(args, "name")).c_str(),
                        arg_str(args, "variable").c_str(), db->location(f).c_str(), db->suggestions.size());
        return true;
    };
    t.push_back(std::move(sv));

    tool sp;
    sp.name = "save_project";
    sp.description =
        "Save every name, comment and breakpoint to the project file: the database the user has open, or "
        "\"<file>.ceasta\" next to the binary (plain sorted text, meant for version control), so the user - or "
        "the next session - picks up the work.";
    sp.schema = schema({});
    sp.writes = true;
    sp.run = [](mcp_server& s, const json::value&, std::string& out) {
        database* db = need_db(s, out);
        if (!db)
            return false;
        std::string err;
        if (!db->save_project(err) || !db->save(err)) {
            out = "can't write the project file: " + err;
            return false;
        }
        db->dirty = false;
        if (s.on_changed)
            s.on_changed();
        out = "wrote " + db->project_path();
        return true;
    };
    t.push_back(std::move(sp));

    tool lua;
    lua.name = "run_lua";
    lua.description =
        "Run Lua with ceasta's scripting api (ceasta.functions(), ceasta.decompile(addr), ceasta.xrefs_to(addr), "
        "ceasta.read(addr, n), ceasta.rename(addr, name), ceasta.log(...)). Expressions print their value. The "
        "script can also use Lua's io and os libraries, so it runs with the user's file access.";
    lua.schema = schema({{"code", prop("string", "lua source")}}, {"code"});
    lua.lua = true;
    lua.writes = true;
    lua.run = [](mcp_server& s, const json::value& args, std::string& out) {
        database* db = need_db(s, out);
        lua_host* L = s.get_lua ? s.get_lua() : nullptr;
        if (!db || !L) {
            if (db && !L)
                out = "lua isn't available here";
            return false;
        }
        std::function<void(const std::string&, int)> old = L->bridge().log;
        std::string captured;
        L->bridge().log = [&](const std::string& line, int level) {
            captured += (level >= 2 ? "error: " : level == 1 ? "warning: " : "") + line + "\n";
        };
        bool ok = L->run_console(arg_str(args, "code"));
        L->bridge().log = old;
        if (s.on_changed)
            s.on_changed();
        out = captured.empty() ? (ok ? "(done, no output)" : "(failed)") : captured;
        cap(out);
        return ok;
    };
    t.push_back(std::move(lua));
}

} // namespace

// ------------------------------------------------------------------ debugger tools (opt in)

namespace {

debugger* dbg_of(mcp_server& s) { return s.debug.get ? s.debug.get() : nullptr; }

// a runtime value -> something to recognize it by: a name in the file, module+offset, or a string
std::string symbolize(mcp_server& s, database& db, debugger& d, uint64_t v)
{
    uint64_t st = 0;
    if (v && s.debug.to_static && s.debug.to_static(v, st)) {
        std::string loc = db.location(st);
        if (!loc.empty())
            return loc;
    }
    for (const dbg_module& m : d.modules())
        if (m.base && v >= m.base && v < m.base + m.size)
            return m.name + "+0x" + util::hex_lower(v - m.base);
    if (v > 0x10000) {
        char buf[72] = {};
        size_t n = d.read(v, buf, sizeof(buf) - 1);
        size_t len = 0;
        while (len < n && buf[len] >= 0x20 && buf[len] < 0x7F)
            len++;
        if (len >= 4 && (len < n ? buf[len] == 0 : true))
            return "\"" + util::escape(std::string(buf, len), 64) + "\"";
    }
    return std::string();
}

// a watched runtime address, by name when it's in the file
std::string watch_where(mcp_server& s, database& db, debugger& d, uint64_t a)
{
    std::string sym = symbolize(s, db, d, a);
    return sym.empty() || sym[0] == '"' ? hexa(a) : sym + " (" + hexa(a) + ")";
}

std::string where_text(mcp_server& s, database& db, debugger& d, uint64_t pc)
{
    uint64_t st = 0;
    if (s.debug.to_static && s.debug.to_static(pc, st)) {
        std::string out = db.location(st) + " (static " + hexa(st) + ", runtime " + hexa(pc) + ")";
        insn in;
        if (db.decode(st, in))
            out += "\n  next: " + db.insn_text(in);
        return out;
    }
    std::string sym = symbolize(s, db, d, pc);
    return hexa(pc) + (sym.empty() ? std::string(" (outside the file)") : " (" + sym + ")");
}

std::string state_text(mcp_server& s, database& db)
{
    debugger* d = dbg_of(s);
    if (!d || d->state() == dbg_state::none) {
        if (d && d->exit_code() != 0)
            return util::fmt("no process (the last one exited with code %d)", d->exit_code());
        return "no process is being debugged (debug_start starts the file)";
    }
    if (d->state() == dbg_state::running)
        return "running (debug_pause stops it)";
    std::string why = d->stop_reason();
    for (const debugger::watch& w : d->watches()) { // "watchpoint: write to counter (0x...)"
        std::string hex = util::hex(w.addr);
        if (why.size() > hex.size() && why.compare(why.size() - hex.size(), hex.size(), hex) == 0 &&
            why.compare(0, 10, "watchpoint") == 0)
            why = why.substr(0, why.size() - hex.size()) + watch_where(s, db, *d, w.addr);
    }
    return "stopped: " + why + "\nat " + where_text(s, db, *d, d->pc()) + "\n";
}

debugger* stopped_dbg(mcp_server& s, std::string& out)
{
    debugger* d = dbg_of(s);
    if (!d || d->state() == dbg_state::none) {
        out = "no process is being debugged (debug_start starts the file)";
        return nullptr;
    }
    if (d->state() != dbg_state::stopped) {
        out = "the program is running; debug_pause stops it";
        return nullptr;
    }
    return d;
}

// "address" of a live-memory tool: a register name, a name or address of the file (moved to
// where it is in the process), or a raw runtime address
bool live_addr(mcp_server& s, database& db, debugger& d, const json::value& args, uint64_t& a, std::string& out)
{
    std::string t = util::lower(util::trim(arg_str(args, "address")));
    for (const reg_value& r : d.registers())
        if (!t.empty() && util::lower(r.name) == t) {
            a = r.value;
            return true;
        }
    if (!arg_addr(db, args, "address", a, out))
        return false;
    if (db.bin.is_mapped(a) && s.debug.to_runtime)
        a = s.debug.to_runtime(a);
    return true;
}

// after a run command: wait for the stop, then describe where it is
bool finish_run(mcp_server& s, int timeout_ms, std::string& out)
{
    bool stopped = s.wait_stop(timeout_ms);
    s.run([&] {
        database* db = s.get_db ? s.get_db() : nullptr;
        if (!stopped)
            out = util::fmt("still running after %d ms - it may be waiting for input, in a long loop, or past the "
                            "part you care about. debug_pause stops it, debug_continue waits more.\n", timeout_ms);
        else
            out = db ? state_text(s, *db) : std::string("no file");
    });
    return true;
}

void add_debug_tools(std::vector<tool>& t)
{
    auto add = [&](const char* name, const char* desc, json::value sch, tool::run_t fn, bool waits) {
        tool x;
        x.name = name;
        x.description = desc;
        x.schema = std::move(sch);
        x.debug = true;
        x.writes = true;
        x.owner = !waits; // run/wait tools manage the owner thread themselves
        x.run = std::move(fn);
        t.push_back(std::move(x));
    };

    add("debug_start",
        "Start the loaded file under the debugger; it stops at its entry point. One process at a time. This runs "
        "the program on this machine, so treat an untrusted target the way you would running it yourself.",
        schema({{"args", prop("string", "command line arguments for the program")}}),
        [](mcp_server& s, const json::value& args, std::string& out) {
            std::string err;
            bool ok = false;
            s.run([&] {
                debugger* d = dbg_of(s);
                if (d && d->state() != dbg_state::none) {
                    err = "a process is already being debugged (debug_kill ends it)";
                    return;
                }
                ok = s.debug.start && s.debug.start(arg_str(args, "args"), err);
            });
            if (!ok) {
                out = "can't start: " + err;
                return false;
            }
            return finish_run(s, 20000, out);
        },
        true);

    add("debug_status", "Whether a process is being debugged, and if stopped, where and why.", schema({}),
        [](mcp_server& s, const json::value&, std::string& out) {
            database* db = s.get_db ? s.get_db() : nullptr;
            out = db ? state_text(s, *db) : std::string("no file");
            return true;
        },
        false);

    add("debug_continue", "Let the program run until a breakpoint, a fault, its exit, or the timeout.",
        schema({{"timeout_ms", prop("integer", "how long to wait for a stop (default 15000, at most 120000)")}}),
        [](mcp_server& s, const json::value& args, std::string& out) {
            bool ok = false;
            std::string err;
            s.run([&] {
                if (!stopped_dbg(s, out))
                    return;
                ok = s.debug.cont && s.debug.cont(err);
            });
            if (!ok) {
                if (out.empty())
                    out = "can't continue: " + err;
                return false;
            }
            return finish_run(s, arg_int(args, "timeout_ms", 15000, 100, 120000), out);
        },
        true);

    add("debug_step_into", "Execute one instruction, entering calls.",
        schema({{"count", prop("integer", "how many instructions (default 1, at most 200)")}}),
        [](mcp_server& s, const json::value& args, std::string& out) {
            int n = arg_int(args, "count", 1, 1, 200);
            for (int i = 0; i < n; i++) {
                bool ok = false;
                std::string err;
                s.run([&] {
                    if (!stopped_dbg(s, out))
                        return;
                    ok = s.debug.step_into && s.debug.step_into(err);
                });
                if (!ok)
                    return i > 0 ? finish_run(s, 1000, out) : (out.empty() ? (out = "can't step: " + err, false) : false);
                out.clear();
                if (!s.wait_stop(10000))
                    break;
            }
            return finish_run(s, 1000, out);
        },
        true);

    add("debug_step_over", "Execute one instruction; a call runs to its return.",
        schema({{"count", prop("integer", "how many instructions (default 1, at most 200)")}}),
        [](mcp_server& s, const json::value& args, std::string& out) {
            int n = arg_int(args, "count", 1, 1, 200);
            for (int i = 0; i < n; i++) {
                bool ok = false;
                std::string err;
                s.run([&] {
                    if (!stopped_dbg(s, out))
                        return;
                    ok = s.debug.step_over && s.debug.step_over(err);
                });
                if (!ok)
                    return i > 0 ? finish_run(s, 1000, out) : (out.empty() ? (out = "can't step: " + err, false) : false);
                out.clear();
                if (!s.wait_stop(15000))
                    break;
            }
            return finish_run(s, 1000, out);
        },
        true);

    add("debug_step_out", "Run until the current function returns (calls in between run at full speed), then stop in "
        "the caller.",
        schema({{"timeout_ms", prop("integer", "how long to keep stepping (default 15000)")}}),
        [](mcp_server& s, const json::value& args, std::string& out) {
            uint64_t until = os::now_ms() + (uint64_t)arg_int(args, "timeout_ms", 15000, 100, 120000);
            for (int guard = 0; guard < 1000000; guard++) {
                bool ok = false, last = false;
                std::string err;
                s.run([&] {
                    debugger* d = stopped_dbg(s, out);
                    if (!d)
                        return;
                    last = d->about_to_return();
                    ok = s.debug.step_over && s.debug.step_over(err);
                });
                if (!ok) {
                    if (out.empty())
                        out = "can't step: " + err;
                    return false;
                }
                out.clear();
                if (!s.wait_stop((int)std::max<int64_t>(100, (int64_t)(until - std::min(until, os::now_ms())))))
                    break;
                std::string why;
                s.run([&] {
                    debugger* d = dbg_of(s);
                    why = d ? d->stop_reason() : std::string();
                });
                if (last || (why != "step" && why != "step over") || os::now_ms() >= until)
                    break;
            }
            return finish_run(s, 1000, out);
        },
        true);

    add("debug_step_back", "Undo the last steps: puts back the memory and registers they changed. Only steps "
        "(debug_step_into / debug_step_over) are recorded; continuing or stepping over a call starts over.",
        schema({{"count", prop("integer", "how many steps (default 1)")}}),
        [](mcp_server& s, const json::value& args, std::string& out) {
            int n = arg_int(args, "count", 1, 1, 100000), done = 0;
            std::string err;
            s.run([&] {
                debugger* d = stopped_dbg(s, out);
                if (!d)
                    return;
                for (; done < n; done++)
                    if (!d->step_back(err))
                        break;
                database* db = s.get_db ? s.get_db() : nullptr;
                out = util::fmt("went back %d step%s", done, done == 1 ? "" : "s") + (done < n ? " (" + err + ")" : "") +
                      util::fmt(", %zu more can be undone\n", d->steps_recorded()) + (db ? state_text(s, *db) : std::string());
            });
            return done > 0;
        },
        true);

    add("debug_run_to", "Run until an address or name is reached (or a breakpoint, or the timeout).",
        schema({{"address", prop("string", "hex address or name in the file")},
                {"timeout_ms", prop("integer", "how long to wait (default 15000)")}},
               {"address"}),
        [](mcp_server& s, const json::value& args, std::string& out) {
            bool ok = false;
            std::string err;
            s.run([&] {
                database* db = s.get_db ? s.get_db() : nullptr;
                uint64_t a;
                if (!db || !stopped_dbg(s, out))
                    return;
                if (!arg_addr(*db, args, "address", a, err))
                    return;
                ok = s.debug.run_to && s.debug.run_to(a, err);
            });
            if (!ok) {
                if (out.empty())
                    out = "can't run: " + err;
                return false;
            }
            return finish_run(s, arg_int(args, "timeout_ms", 15000, 100, 120000), out);
        },
        true);

    add("debug_pause", "Stop the running program where it is.", schema({}),
        [](mcp_server& s, const json::value&, std::string& out) {
            bool ok = false;
            std::string err;
            s.run([&] {
                debugger* d = dbg_of(s);
                if (!d || d->state() != dbg_state::running) {
                    err = "it isn't running";
                    return;
                }
                ok = s.debug.pause && s.debug.pause(err);
            });
            if (!ok) {
                out = "can't pause: " + err;
                return false;
            }
            s.wait_stop(5000);
            s.run([&] {
                database* db = s.get_db ? s.get_db() : nullptr;
                out = db ? state_text(s, *db) : std::string();
            });
            return true;
        },
        true);

    add("debug_kill", "End the debugged process.", schema({}),
        [](mcp_server& s, const json::value&, std::string& out) {
            debugger* d = dbg_of(s);
            if (!d || d->state() == dbg_state::none) {
                out = "no process";
                return true;
            }
            if (s.debug.kill)
                s.debug.kill();
            out = "killed";
            return true;
        },
        false);
}

} // namespace

namespace {

void add_debug_inspect_tools(std::vector<tool>& t)
{
    auto add = [&](const char* name, const char* desc, json::value sch, tool::run_t fn) {
        tool x;
        x.name = name;
        x.description = desc;
        x.schema = std::move(sch);
        x.debug = true;
        x.writes = true;
        x.run = std::move(fn);
        t.push_back(std::move(x));
    };

    add("debug_set_breakpoint",
        "Break when execution reaches an address or name of the file. Works before debug_start too; addresses "
        "follow the program when it loads somewhere else (aslr / pie). With a condition it only stops when the "
        "condition holds: a Lua expression over the registers (rax, ecx, ...), hits (how often it was reached), "
        "and memory readers u8/u16/u32/u64(addr), str(addr), wstr(addr) - e.g. \"rdi == 3\", \"hits == 100\", "
        "\"str(rcx) == 'admin'\".",
        schema({{"address", prop("string", "hex address or name")},
                {"condition", prop("string", "optional: stop only when this Lua expression is true")}},
               {"address"}),
        [](mcp_server& s, const json::value& args, std::string& out) {
            database* db = need_db(s, out);
            uint64_t a;
            std::string err;
            if (!db || !arg_addr(*db, args, "address", a, out))
                return false;
            std::string cond = util::trim(arg_str(args, "condition"));
            if (!s.debug.add_bp || !s.debug.add_bp(a, err)) {
                out = "can't set it: " + err;
                return false;
            }
            if (s.debug.set_condition && !s.debug.set_condition(a, cond, err)) {
                out = "the breakpoint is set, but the condition isn't valid: " + err;
                return false;
            }
            if (s.on_changed)
                s.on_changed();
            out = "breakpoint at " + db->location(a) + " (" + hexa(a) + ")" + (cond.empty() ? "" : " when " + cond);
            return true;
        });

    add("debug_remove_breakpoint", "Remove a breakpoint.",
        schema({{"address", prop("string", "hex address or name")}}, {"address"}),
        [](mcp_server& s, const json::value& args, std::string& out) {
            database* db = need_db(s, out);
            uint64_t a;
            if (!db || !arg_addr(*db, args, "address", a, out))
                return false;
            bool ok = s.debug.del_bp && s.debug.del_bp(a);
            if (s.on_changed)
                s.on_changed();
            out = ok ? "removed the breakpoint at " + db->location(a) : "no breakpoint at " + db->location(a);
            return ok;
        });

    add("debug_list_breakpoints", "The breakpoints (static addresses of the file) and the watches (runtime addresses).",
        schema({}),
        [](mcp_server& s, const json::value&, std::string& out) {
            database* db = need_db(s, out);
            if (!db)
                return false;
            std::vector<uint64_t> b = s.debug.bps ? s.debug.bps() : std::vector<uint64_t>();
            for (uint64_t a : b) {
                std::string c = s.debug.condition_of ? s.debug.condition_of(a) : std::string();
                out += hexa(a) + "  " + db->location(a) + (c.empty() ? std::string() : "  when " + c) + "\n";
            }
            if (b.empty())
                out = "no breakpoints\n";
            debugger* d = dbg_of(s);
            if (d)
                for (const debugger::watch& w : d->watches())
                    out += util::fmt("watch %s, %d byte%s, stops after a %s\n", watch_where(s, *db, *d, w.addr).c_str(), w.size,
                        w.size == 1 ? "" : "s", w.access ? "read or write" : "write");
            return true;
        });

    add("debug_watch",
        "A watchpoint: the program stops right after an instruction writes the memory (with access: reads or "
        "writes it) - find who changes a variable, a flag, a buffer. Address as for debug_read_memory: a register, "
        "a name or address of the file, or a runtime address (heap, stack). 1, 2, 4 or 8 bytes, aligned to the "
        "size; up to 4 at once; they last for this run. The stop reason reads \"watchpoint: write to ...\". "
        "remove=true takes it away. The program has to be stopped.",
        schema({{"address", prop("string", "register name, file name/address, or runtime address")},
                {"size", prop("integer", "bytes: 1, 2, 4 or 8 (default 4)")},
                {"access", prop("boolean", "stop on reads too, not only writes (default false)")},
                {"remove", prop("boolean", "remove the watch at this address instead")}},
               {"address"}),
        [](mcp_server& s, const json::value& args, std::string& out) {
            database* db = need_db(s, out);
            debugger* d = db ? stopped_dbg(s, out) : nullptr;
            uint64_t a = 0;
            if (!d || !live_addr(s, *db, *d, args, a, out))
                return false;
            if (arg_bool(args, "remove", false)) {
                bool ok = d->del_watch(a);
                out = ok ? "stopped watching " + watch_where(s, *db, *d, a) : "no watch at " + watch_where(s, *db, *d, a);
                return ok;
            }
            int size = arg_int(args, "size", 4, 1, 8);
            bool access = arg_bool(args, "access", false);
            std::string err;
            if (!d->add_watch(a, size, access, err)) {
                out = "can't watch it: " + err;
                return false;
            }
            out = util::fmt("watching %s, %d byte%s: the program stops after a %s. debug_continue runs to it.",
                watch_where(s, *db, *d, a).c_str(), size, size == 1 ? "" : "s", access ? "read or write" : "write");
            return true;
        });

    add("debug_backtrace",
        "The call stack: how the stopped thread got here. The function it's in, then each caller (the call that "
        "made the frame and where it returns to). Read from the stack without unwind tables, so treat deep frames "
        "as a good guess.",
        schema({{"limit", prop("integer", "how many frames (default 32)")}}),
        [](mcp_server& s, const json::value& args, std::string& out) {
            database* db = need_db(s, out);
            debugger* d = db ? stopped_dbg(s, out) : nullptr;
            if (!d)
                return false;
            auto func_start = [&s, db](uint64_t rt) -> uint64_t {
                uint64_t st = 0;
                if (!s.debug.to_static || !s.debug.to_static(rt, st))
                    return 0;
                const function* f = db->an.func_containing(st);
                return f && s.debug.to_runtime ? s.debug.to_runtime(f->start) : 0;
            };
            std::vector<stack_frame> fr = dbg_call_stack(*d, arg_int(args, "limit", 32, 1, 256), func_start);
            for (size_t i = 0; i < fr.size(); i++) {
                std::string sym = symbolize(s, *db, *d, i ? fr[i].call : fr[i].pc);
                out += util::fmt("#%zu  %s", i, (sym.empty() ? hexa(i ? fr[i].call : fr[i].pc) : sym).c_str());
                out += i ? "  (call at " + hexa(fr[i].call) + ", returns to " + hexa(fr[i].pc) + ")\n" : "  (here, " + hexa(fr[i].pc) + ")\n";
            }
            return true;
        });

    add("debug_memory_map",
        "The running program's memory map: each region's range, access (r/w/x) and what it is (a module or file, "
        "[heap], [stack]). filter keeps the lines that contain it (e.g. \"libc\", \"rwx\", \"stack\").",
        schema({{"filter", prop("string", "optional: only lines containing this")}}),
        [](mcp_server& s, const json::value& args, std::string& out) {
            debugger* d = stopped_dbg(s, out);
            if (!d)
                return false;
            std::string f = util::lower(util::trim(arg_str(args, "filter")));
            int n = 0;
            for (const dbg_region& r : d->regions()) {
                std::string line = util::fmt("%s-%s %s %s", hexa(r.base).c_str(), hexa(r.base + r.size).c_str(), r.perms.c_str(),
                    r.what.c_str());
                if (!f.empty() && util::lower(line).find(f) == std::string::npos)
                    continue;
                out += line + "\n";
                if (++n >= 2000) {
                    out += "(more left out)\n";
                    break;
                }
            }
            if (out.empty())
                out = f.empty() ? "no memory map\n" : "nothing matches " + f + "\n";
            return true;
        });

    add("debug_get_registers",
        "The registers of the stopped thread, each with what it points at when that's recognizable: a name in the "
        "file, a module+offset, or a string.",
        schema({}), [](mcp_server& s, const json::value&, std::string& out) {
            database* db = need_db(s, out);
            debugger* d = db ? stopped_dbg(s, out) : nullptr;
            if (!d)
                return false;
            for (const reg_value& r : d->registers()) {
                out += util::fmt("%-7s %016llx", r.name.c_str(), (unsigned long long)r.value);
                if (r.name != "eflags" && r.name != "rflags") {
                    std::string sym = symbolize(s, *db, *d, r.value);
                    if (!sym.empty())
                        out += "  " + sym;
                }
                out += "\n";
            }
            return true;
        });

    add("debug_set_register", "Change a register of the stopped thread (e.g. rax, rip, eflags).",
        schema({{"name", prop("string", "register name")}, {"value", prop("string", "new value, hex")}},
               {"name", "value"}),
        [](mcp_server& s, const json::value& args, std::string& out) {
            debugger* d = stopped_dbg(s, out);
            uint64_t v;
            std::string err;
            if (!d)
                return false;
            if (!util::parse_hex(arg_str(args, "value"), v)) {
                out = "value must be hex";
                return false;
            }
            if (!d->set_register(util::lower(arg_str(args, "name")), v, err)) {
                out = "can't set it: " + err;
                return false;
            }
            out = arg_str(args, "name") + " = " + hexa(v);
            return true;
        });

    add("debug_read_memory",
        "Read the running program's live memory as a hex + ascii view. Address can be a register name (rsp, rdi), "
        "a name or address of the file, or a raw runtime address.",
        schema({{"address", prop("string", "register name, file name/address, or runtime address")},
                {"length", prop("integer", "how many bytes (default 128, at most 4096)")}},
               {"address"}),
        [](mcp_server& s, const json::value& args, std::string& out) {
            database* db = need_db(s, out);
            debugger* d = db ? stopped_dbg(s, out) : nullptr;
            if (!d)
                return false;
            uint64_t a = 0;
            if (!live_addr(s, *db, *d, args, a, out))
                return false;
            std::vector<uint8_t> buf((size_t)arg_int(args, "length", 128, 1, 4096));
            size_t n = d->read(a, buf.data(), buf.size());
            if (!n) {
                out = hexa(a) + " is not readable in the process";
                return false;
            }
            out = byte_view(a, buf.data(), n);
            return true;
        });

    add("debug_write_memory", "Write bytes into the running program's memory.",
        schema({{"address", prop("string", "register name, file name/address, or runtime address")},
                {"bytes", prop("string", "hex bytes, e.g. \"90 90 c3\"")}},
               {"address", "bytes"}),
        [](mcp_server& s, const json::value& args, std::string& out) {
            database* db = need_db(s, out);
            debugger* d = db ? stopped_dbg(s, out) : nullptr;
            if (!d)
                return false;
            uint64_t a = 0;
            if (!live_addr(s, *db, *d, args, a, out))
                return false;
            std::vector<uint8_t> bytes;
            for (const std::string& tok : util::split(arg_str(args, "bytes"), " ,")) {
                uint64_t v;
                if (tok.empty())
                    continue;
                if (!util::parse_hex(tok, v) || v > 0xFF) {
                    out = "bad byte: " + tok;
                    return false;
                }
                bytes.push_back((uint8_t)v);
            }
            std::string err;
            if (bytes.empty() || !d->write(a, bytes.data(), bytes.size(), err)) {
                out = bytes.empty() ? "no bytes given" : "can't write: " + err;
                return false;
            }
            out = util::fmt("wrote %zu bytes at %s", bytes.size(), hexa(a).c_str());
            return true;
        });

    add("debug_call",
        "Call a function in the stopped program and get its return value, then every register is "
        "restored. Great for exercising one routine - decrypt a string, validate a key, hash a buffer. "
        "Each argument is a number (passed as-is), or a string: a name or hex address is passed as that "
        "(runtime) address, anything else is written into the target as a c string and its pointer is "
        "passed. 64-bit targets only.",
        schema({{"function", prop("string", "name or address to call")},
                {"args", []{ json::value a = prop("array", "arguments, in order"); a["items"] = json::value::make_object(); return a; }()}},
               {"function"}),
        [](mcp_server& s, const json::value& args, std::string& out) {
            database* db = need_db(s, out);
            debugger* d = db ? stopped_dbg(s, out) : nullptr;
            if (!d)
                return false;
            uint64_t func;
            if (!arg_addr(*db, args, "function", func, out))
                return false;
            if (db->bin.is_mapped(func) && s.debug.to_runtime)
                func = s.debug.to_runtime(func);
            // materialize the arguments; strings that aren't a name/number get written to a
            // scratch area well below the stack pointer
            uint64_t sp = d->sp();
            uint64_t scratch = sp - 0x8000;
            std::vector<uint64_t> vals;
            const json::value* av = args.get("args");
            if (av && av->is_array())
                for (const json::value& item : *av->a) {
                    if (item.is_number()) {
                        vals.push_back((uint64_t)item.n);
                        continue;
                    }
                    std::string t = item.str();
                    uint64_t v;
                    if (db->resolve(t, v)) {
                        vals.push_back(db->bin.is_mapped(v) && s.debug.to_runtime ? s.debug.to_runtime(v) : v);
                    } else if (util::parse_hex(t, v)) {
                        vals.push_back(v);
                    } else {
                        size_t need = (t.size() + 1 + 15) & ~size_t(15);
                        scratch -= need;
                        std::string err;
                        d->write(scratch, t.c_str(), t.size() + 1, err);
                        vals.push_back(scratch);
                    }
                }
            uint64_t result = 0;
            std::string err;
            if (!d->call(func, vals, result, err)) {
                out = "the call failed: " + err;
                return false;
            }
            out = "returned 0x" + util::hex_lower(result) + " (" + std::to_string((long long)result) + ")";
            std::string sym = symbolize(s, *db, *d, result);
            if (!sym.empty())
                out += "\n         " + sym;
            return true;
        });

    add("debug_trace",
        "Single-step the stopped program for up to `count` instructions and record the target of "
        "every indirect call / jump it takes (a call through a pointer, a vtable dispatch, a jump "
        "table). Those targets become cross-references the static analysis couldn't find, and are "
        "saved with the project. Stepping is slow, so keep the count modest and set a breakpoint "
        "first to trace a specific spot.",
        schema({{"count", prop("integer", "how many instructions to step (default 2000, at most 200000)")}}),
        [](mcp_server& s, const json::value& args, std::string& out) {
            database* db = need_db(s, out);
            debugger* d = db ? stopped_dbg(s, out) : nullptr;
            if (!d)
                return false;
            int max = arg_int(args, "count", 2000, 1, 200000);
            int found = 0;
            std::string err, list;
            int stepped = dbg_trace(*d, max, [&](uint64_t from, uint64_t to, bool is_call) {
                uint64_t sf, st;
                if (s.debug.to_static && s.debug.to_static(from, sf) && s.debug.to_static(to, st) &&
                    db->add_xref(sf, st, is_call ? xref_type::call : xref_type::jump)) {
                    found++;
                    if (found <= 200)
                        list += util::fmt("  %-4s %s -> %s\n", is_call ? "call" : "jmp", db->location(sf).c_str(),
                                          db->location(st).c_str());
                }
            }, err);
            if (s.on_changed && found)
                s.on_changed();
            out = util::fmt("stepped %d instructions, found %d new indirect target%s\n", stepped, found,
                            found == 1 ? "" : "s");
            out += list;
            if (d->state() != dbg_state::stopped)
                out += "(the program is no longer stopped)\n";
            cap(out);
            return true;
        });

    add("debug_decompile_here",
        "Pseudocode for the function the program is stopped in, with the current line marked, followed "
        "by the argument registers and their live values (a name in the file, or a string). The fast way "
        "to see what a routine is doing with the data it actually has right now.",
        schema({}), [](mcp_server& s, const json::value&, std::string& out) {
            database* db = need_db(s, out);
            debugger* d = db ? stopped_dbg(s, out) : nullptr;
            if (!d)
                return false;
            uint64_t st = 0;
            if (!s.debug.to_static || !s.debug.to_static(d->pc(), st)) {
                out = "the program is stopped outside the loaded file (" + hexa(d->pc()) + ")";
                return false;
            }
            const function* f = db->an.func_containing(st);
            if (!f) {
                out = "no function at " + hexa(st);
                return false;
            }
            out = "// " + db->location(f->start) + ", stopped at " + hexa(st) + "\n";
            out += decompile_text_marked(*db, f->start, st);
            out += "\nlive registers:\n";
            for (const reg_value& r : d->registers()) {
                if (r.name == "eflags" || r.name == "rflags" || r.name == "rsp" || r.name == "rip")
                    continue;
                std::string sym = symbolize(s, *db, *d, r.value);
                if (!sym.empty())
                    out += util::fmt("  %-5s %016llx  %s\n", r.name.c_str(), (unsigned long long)r.value,
                                     sym.c_str());
            }
            cap(out);
            return true;
        });

}

} // namespace

// ------------------------------------------------------------------ the tool registry

const std::vector<mcp_server::tool>& mcp_all_tools()
{
    static const std::vector<mcp_server::tool> all = [] {
        std::vector<mcp_server::tool> t;
        add_read_tools(t);
        add_query_tools(t);
        add_edit_tools(t);
        add_debug_tools(t);
        add_debug_inspect_tools(t);
        return t;
    }();
    return all;
}

std::vector<const mcp_server::tool*> mcp_server::tools() const
{
    std::vector<const tool*> out;
    for (const tool& t : mcp_all_tools()) {
        if (t.debug && !opts.allow_debug)
            continue;
        if (t.lua && !opts.allow_lua)
            continue;
        if (t.kuna && opts.kuna.empty())
            continue;
        out.push_back(&t);
    }
    return out;
}

// ------------------------------------------------------------------ owner thread + waiting

void mcp_server::run(const std::function<void()>& fn)
{
    if (stopping)
        return;
    if (on_owner)
        on_owner(fn);
    else
        fn();
}

bool mcp_server::wait_stop(int timeout_ms)
{
    uint64_t until = os::now_ms() + (uint64_t)timeout_ms;
    for (;;) {
        bool done = false;
        run([&] {
            if (debug.pump)
                debug.pump();
            debugger* d = debug.get ? debug.get() : nullptr;
            done = !d || d->state() != dbg_state::running;
        });
        if (done)
            return true;
        if (os::now_ms() >= until || stopping)
            return false;
        os::sleep_ms(10);
    }
}

// ------------------------------------------------------------------ json-rpc / mcp protocol

namespace {

json::value rpc_error(const json::value& id, int code, const std::string& message)
{
    json::value r = json::value::make_object();
    r["jsonrpc"] = "2.0";
    r["id"] = id.is_null() ? json::value() : id;
    json::value& e = r["error"];
    e["code"] = code;
    e["message"] = message;
    return r;
}

json::value rpc_result(const json::value& id, json::value result)
{
    json::value r = json::value::make_object();
    r["jsonrpc"] = "2.0";
    r["id"] = id;
    r["result"] = std::move(result);
    return r;
}

// ---- prompts: ready-made requests the client offers the user (claude code lists them as
// /mcp__ceasta__<name>). {function} and {limit} in the text are the arguments

struct prompt_arg {
    const char* name;
    const char* description;
    bool required;
};

struct prompt_def {
    const char* name;
    const char* description;
    std::vector<prompt_arg> args;
    const char* text;
    bool debug; // uses the debugger tools
};

const std::vector<prompt_def>& prompt_list()
{
    static const std::vector<prompt_def> p = {
        {"triage", "A first look at the binary: what it is, what stands out, and where to read next.", {},
         "Take a first look at the binary open in ceasta. Call get_binary_info (format, architecture, entry point, "
         "sections), then list_imports and pick out what stands out: networking, crypto, process and memory "
         "manipulation (VirtualAlloc, WriteProcessMemory, CreateRemoteThread), anti-debugging, registry and service "
         "changes. Then list_strings for urls, ip addresses, file paths, registry keys, commands and error messages, "
         "and decompile_function on the entry point and main. Finish with a short summary: what the program probably "
         "is and does, anything suspicious, and the 3 to 5 functions most worth reading next, with their addresses "
         "and why.",
         false},
        {"explain_function", "What a function does, its parameters and result, with names for it and its variables.",
         {{"function", "the function: name or address", true}},
         "Explain what {function} does in the binary open in ceasta. Read it with decompile_function (and "
         "disassemble_function where the pseudocode looks off), see who calls it with get_xrefs_to, and look at the "
         "functions it calls and the strings it uses. Say in a few sentences what it does, what its parameters and "
         "return value mean, and anything unusual (error paths, loops over buffers, constants). Then propose names "
         "for review: suggest_name for the function and suggest_variable_name for its parameters and important "
         "locals. If the user asked you to go ahead, use rename, rename_variable and set_function_prototype "
         "directly instead.",
         false},
        {"rename_pass", "Name the unnamed functions (sub_...), bottom-up. The names wait for your review in ceasta.",
         {{"limit", "at most this many functions (default 30)", false}},
         "Name the unnamed functions of the binary open in ceasta (the sub_... ones). Get them with list_functions. "
         "Work bottom-up: functions that call nothing unnamed first, since their names help with their callers. For "
         "each one: decompile_function, get_xrefs_from for what it calls, and a look at its strings. When you can "
         "tell what it does, call suggest_name with a short verb_noun name (parse_header, decrypt_config, "
         "send_beacon) and a one-line reason. Skip what you can't tell rather than guessing, and skip library code. "
         "Stop after {limit} functions, then list what you named and what you skipped. The user reviews your "
         "suggestions in ceasta under AI > Review suggested names.",
         false},
        {"find_crypto", "Find cryptography: crypto api calls, well-known constants, xor loops.", {},
         "Find cryptography in the binary open in ceasta. Check list_imports for crypto apis (CryptEncrypt, "
         "CryptDecrypt, BCrypt*, EVP_*). Search for well-known constants with search_bytes: the aes s-box "
         "(63 7c 77 7b f2 6b 6f c5), sha-256 (98 2f 8a 42 91 44 37 71), the md5 / sha-1 initial values "
         "(01 23 45 67 89 ab cd ef), crc32 (20 83 b8 ed); and look with decompile_function for loops that run 256 "
         "times (rc4 key scheduling) or xor a buffer with a key. For each find, say which algorithm it is and where "
         "(function and address), what key or data it works on if you can tell, and suggest a name for the "
         "function with suggest_name.",
         false},
        {"trace_function", "Run the program to a function under the debugger and watch what it gets and returns.",
         {{"function", "the function: name or address", true}},
         "Use ceasta's debugger to watch {function} run. debug_set_breakpoint on it, debug_start, then "
         "debug_continue until it stops there. Show its arguments: debug_get_registers, and debug_read_memory on the "
         "ones that point at memory (strings, buffers, structures). Then debug_step_out to let it return, and read "
         "the result (rax / eax) and anything it wrote. debug_backtrace shows who called it. Summarize what it was "
         "given and what it did with it, then end the program with debug_kill.",
         true},
    };
    return p;
}

// a tools/call result: text content, with isError set when the tool failed
json::value tool_content(const std::string& text, bool is_error)
{
    json::value r = json::value::make_object();
    json::value& content = r["content"];
    content = json::value::make_array();
    json::value item = json::value::make_object();
    item["type"] = "text";
    item["text"] = text.empty() ? std::string("(no output)") : text;
    content.push(std::move(item));
    if (is_error)
        r["isError"] = true;
    return r;
}

} // namespace

json::value mcp_server::call_tool(const json::value& params, std::string& activity)
{
    std::string name = params.get("name") ? params.get("name")->str() : std::string();
    const json::value* a = params.get("arguments");
    json::value args = a && a->is_object() ? *a : json::value::make_object();

    const tool* found = nullptr;
    for (const tool* t : tools())
        if (t->name == name) {
            found = t;
            break;
        }
    if (!found) {
        activity = "unknown tool: " + name;
        return tool_content("unknown tool: " + name + " (call tools/list for the available ones)", true);
    }

    activity = name;
    std::string out;
    bool ok = false;
    try {
        if (found->owner)
            run([&] { ok = found->run(*this, args, out); });
        else
            ok = found->run(*this, args, out); // manages the owner thread itself
    } catch (const std::exception& e) {
        out = std::string("tool error: ") + e.what();
        ok = false;
    } catch (...) {
        out = "tool error";
        ok = false;
    }
    return tool_content(out, !ok);
}

json::value mcp_server::dispatch(const json::value& msg)
{
    const json::value* idp = msg.get("id");
    json::value id = idp ? *idp : json::value();
    std::string method = msg.get("method") ? msg.get("method")->str() : std::string();
    const json::value* params = msg.get("params");
    json::value empty = json::value::make_object();
    const json::value& p = params ? *params : empty;
    bool is_notification = !idp;

    if (method == "initialize") {
        const json::value* pv = p.get("protocolVersion");
        if (pv && pv->is_string() && !pv->s.empty())
            negotiated_ = pv->s;
        json::value r = json::value::make_object();
        r["protocolVersion"] = negotiated_;
        json::value& caps = r["capabilities"];
        caps = json::value::make_object();
        json::value& tcap = caps["tools"];
        tcap = json::value::make_object();
        json::value& pcap = caps["prompts"];
        pcap = json::value::make_object();
        json::value& info = r["serverInfo"];
        info["name"] = "ceasta";
        info["version"] = CEASTA_VERSION;
        r["instructions"] =
            "ceasta is a reverse engineering tool. These tools inspect the binary the user has open: "
            "decompile_function and disassemble to read code, list_functions / list_strings / get_xrefs_to to "
            "navigate, and rename / set_comment / rename_variable / set_function_prototype to record what you learn. "
            "Start with get_binary_info.";
        return rpc_result(id, std::move(r));
    }
    if (method == "notifications/initialized" || method == "notifications/cancelled")
        return json::value(); // nothing to send back
    if (method == "ping")
        return rpc_result(id, json::value::make_object());
    if (method == "tools/list") {
        json::value r = json::value::make_object();
        json::value& list = r["tools"];
        list = json::value::make_array();
        for (const tool* t : tools()) {
            json::value item = json::value::make_object();
            item["name"] = t->name;
            item["description"] = t->description;
            item["inputSchema"] = t->schema;
            json::value& ann = item["annotations"];
            ann["readOnlyHint"] = !t->writes;
            if (t->debug)
                ann["destructiveHint"] = true;
            list.push(std::move(item));
        }
        return rpc_result(id, std::move(r));
    }
    if (method == "tools/call") {
        std::string activity;
        json::value result = call_tool(p, activity);
        if (on_activity)
            on_activity(activity);
        return rpc_result(id, std::move(result));
    }
    if (method == "prompts/list") {
        json::value r = json::value::make_object();
        json::value& list = r["prompts"];
        list = json::value::make_array();
        for (const prompt_def& pd : prompt_list()) {
            if (pd.debug && !opts.allow_debug)
                continue;
            json::value item = json::value::make_object();
            item["name"] = pd.name;
            item["description"] = pd.description;
            json::value& args = item["arguments"];
            args = json::value::make_array();
            for (const prompt_arg& a : pd.args) {
                json::value arg = json::value::make_object();
                arg["name"] = a.name;
                arg["description"] = a.description;
                arg["required"] = a.required;
                args.push(std::move(arg));
            }
            list.push(std::move(item));
        }
        return rpc_result(id, std::move(r));
    }
    if (method == "prompts/get") {
        std::string name = p.get("name") ? p.get("name")->str() : std::string();
        const json::value* given = p.get("arguments");
        for (const prompt_def& pd : prompt_list()) {
            if (name != pd.name || (pd.debug && !opts.allow_debug))
                continue;
            std::string text = pd.text;
            for (const prompt_arg& a : pd.args) {
                const json::value* v = given && given->is_object() ? given->get(a.name) : nullptr;
                std::string val = v ? util::trim(v->str()) : std::string();
                if (val.empty() && a.required)
                    return rpc_error(id, -32602, std::string("the prompt needs ") + a.name);
                if (val.empty())
                    val = std::string(a.name) == "limit" ? "30" : "";
                std::string key = std::string("{") + a.name + "}";
                for (size_t at = text.find(key); at != std::string::npos; at = text.find(key, at + val.size()))
                    text.replace(at, key.size(), val);
            }
            json::value r = json::value::make_object();
            r["description"] = pd.description;
            json::value& msgs = r["messages"];
            msgs = json::value::make_array();
            json::value m = json::value::make_object();
            m["role"] = "user";
            json::value& c = m["content"];
            c["type"] = "text";
            c["text"] = text;
            msgs.push(std::move(m));
            return rpc_result(id, std::move(r));
        }
        return rpc_error(id, -32602, "no prompt called " + name);
    }
    if (method == "resources/list") {
        json::value r = json::value::make_object();
        r["resources"] = json::value::make_array();
        return rpc_result(id, std::move(r));
    }
    if (is_notification)
        return json::value();
    return rpc_error(id, -32601, "method not found: " + method);
}

std::string mcp_server::handle(const std::string& message)
{
    json::value msg;
    std::string err;
    if (!json::parse(message, msg, err))
        return json::dump(rpc_error(json::value(), -32700, "parse error: " + err));

    if (msg.is_array()) { // a batch
        json::value out = json::value::make_array();
        for (const json::value& m : *msg.a) {
            json::value r = dispatch(m);
            if (!r.is_null())
                out.push(std::move(r));
        }
        return out.size() ? json::dump(out) : std::string();
    }
    if (!msg.is_object())
        return json::dump(rpc_error(json::value(), -32600, "invalid request"));
    json::value r = dispatch(msg);
    return r.is_null() ? std::string() : json::dump(r);
}
