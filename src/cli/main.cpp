#include "cli/dbg_repl.h"
#include "cli/mcp_cmd.h"
#include "core/database.h"
#include "core/diff.h"
#include "core/os.h"
#include "core/search.h"
#include "core/signatures.h"
#include "core/decompiler.h"
#include "core/lua_host.h"
#include "core/debugger.h"
#include "core/os.h"
#include "core/util.h"
#include "version.h"
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

// command line front end. same core as the gui, handy for scripts and ci.

static void usage()
{
    printf("ceasta-cli %s\n\n"
           "usage: ceasta-cli <command> <file> [args] [options]\n\n"
           "commands:\n"
           "  info <file>                   format, entry point, segments, loader notes\n"
           "  funcs <file>                  functions: address, size, name\n"
           "  imports <file>                imported functions\n"
           "  exports <file>                exported symbols\n"
           "  strings <file>                strings found by the analysis\n"
           "  disasm <file> [where] [n]     n listing lines starting at where (default: entry)\n"
           "  func <file> <where>           listing of one function\n"
           "  decompile <file> <where>      pseudocode for one function\n"
           "  graph <file> <where>          basic blocks and edges of a function\n"
           "  xrefs <file> <where>          references to an address\n"
           "  find <file> <pattern>         byte search, like \"48 8b ?? 05\"\n"
           "  search <file> <text>          find text in functions, names, imports, exports, strings,\n"
           "                                comments and segments\n"
           "  diff <old> <new>              match functions between two files, show what changed\n"
           "  export <file>                 write a committable project file (<file>.ceasta)\n"
           "  sigmake <file> [out.sig]      make library signatures from a file that has symbols\n"
           "  sigapply <file> <in.sig>      name matching functions (--save to keep them)\n"
           "  run <file> <script.lua>       run a lua script against the file (ceasta.* api)\n"
           "                                with --debug the file is started and stopped at its entry first,\n"
           "                                so ceasta.dbg.* works (windows x64, linux x64)\n"
           "  dbg <program> [args...]       interactive debugger (break, step, registers, memory)\n"
           "  mcp <file> [options]          serve the file to an ai client over the model context\n"
           "                                protocol (stdio, or --http PORT); ceasta-cli mcp --help\n"
           "  debug <exe> [steps]           debugger smoke test: break on entry, step, run to exit\n\n"
           "options:\n"
           "  --raw32 / --raw64             load the file as raw code\n"
           "  --base <hex>                  base address for raw files\n"
           "\"where\" is a hex address or any name (sub_401000, start, main, ...)\n",
        CEASTA_VERSION);
}

static std::string line_for(database& db, const row& r)
{
    line_text t;
    db.format(r, t);
    if (r.kind == row_kind::blank)
        return std::string();
    std::string s = util::fmt("%-26s %-24s %s", t.addr.c_str(), t.bytes.c_str(), t.text.c_str());
    std::string c = t.comment.empty() ? t.auto_comment : (t.auto_comment.empty() ? t.comment : t.comment + " | " + t.auto_comment);
    if (!c.empty())
        s += "  ; " + c;
    while (!s.empty() && s.back() == ' ')
        s.pop_back();
    return s;
}

static bool where(database& db, const std::vector<std::string>& args, size_t i, uint64_t& out)
{
    if (i >= args.size()) {
        if (!db.bin.has_entry) {
            fprintf(stderr, "no entry point, give an address\n");
            return false;
        }
        out = db.bin.entry;
        return true;
    }
    if (!db.resolve(args[i], out)) {
        fprintf(stderr, "unknown address or name: %s\n", args[i].c_str());
        return false;
    }
    return true;
}

// scripted debug session used by ci: stop at the entry point, put a breakpoint on the first
// function the entry calls (through the relocated address), run to it, step, run to the end.
static int cmd_debug(const std::vector<std::string>& args)
{
    if (args.size() < 2) {
        usage();
        return 2;
    }
    int steps = args.size() > 2 ? atoi(args[2].c_str()) : 5;
    if (!debugger::supported()) {
        fprintf(stderr, "this build has no debugger (it needs windows x64 or linux x64)\n");
        return 1;
    }
    std::string err;
    load_options opts;
    std::unique_ptr<database> db = open_database(args[1], opts, nullptr, err);
    if (!db) {
        fprintf(stderr, "can't analyze %s: %s\n", args[1].c_str(), err.c_str());
        return 1;
    }
    // first direct call target reachable from the entry point
    uint64_t target = 0;
    uint64_t a = db->bin.entry;
    for (int i = 0; i < 64 && !target; i++) {
        insn in;
        if (!db->decode(a, in))
            break;
        if (in.kind == flow::call && in.has_target && !in.indirect && db->bin.is_code(in.target))
            target = in.target;
        if (in.kind == flow::jump && in.has_target && !in.indirect)
            a = in.target;
        else if (in.kind == flow::ret || in.kind == flow::stop)
            break;
        else
            a = in.next();
    }

    debugger dbg;
    dbg.on_log = [](const std::string& s) { printf("[dbg] %s\n", s.c_str()); };
    int failures = 0;
    auto check = [&](bool ok, const std::string& what) {
        printf("%s %s\n", ok ? "ok  " : "FAIL", what.c_str());
        if (!ok)
            failures++;
    };
    auto wait_stop = [&](int ms) {
        uint64_t until = os::now_ms() + (uint64_t)ms;
        while (os::now_ms() < until) {
            dbg.poll(50);
            if (dbg.state() != dbg_state::running)
                return true;
        }
        return false;
    };
    if (!dbg.start(args[1], "", "", err)) {
        fprintf(stderr, "start failed: %s\n", err.c_str());
        return 1;
    }
    bool stopped = wait_stop(15000) && dbg.state() == dbg_state::stopped;
    check(stopped, "stopped at the entry point (" + dbg.stop_reason() + ")");
    if (!stopped) {
        dbg.kill();
        return 1;
    }
    uint64_t delta = dbg.image_base() - db->bin.base;
    printf("image base %s (static %s), %s process\n", util::hex(dbg.image_base()).c_str(), util::hex(db->bin.base).c_str(),
        dbg.is64() ? "64 bit" : "32 bit");
    check(dbg.pc() == db->bin.entry + delta, "pc is the relocated entry point " + util::hex(db->bin.entry + delta));

    if (target) {
        uint64_t rt = target + delta;
        check(dbg.add_bp(rt, err), "breakpoint on " + db->location(target) + " at " + util::hex(rt) + " " + err);
        check(dbg.cont(err), "continue " + err);
        stopped = wait_stop(15000) && dbg.state() == dbg_state::stopped;
        check(stopped && dbg.pc() == rt && dbg.stop_reason() == "breakpoint",
            "hit the breakpoint (pc " + util::hex(dbg.pc()) + ", " + dbg.stop_reason() + ")");
        uint8_t first = 0;
        check(dbg.read(rt, &first, 1) == 1 && first != 0xCC, "memory reads hide the int3");
    }
    for (int i = 0; i < steps && dbg.state() == dbg_state::stopped; i++) {
        uint64_t before = dbg.pc();
        if (!dbg.step_over(err)) {
            check(false, "step over: " + err);
            break;
        }
        stopped = wait_stop(15000) && dbg.state() == dbg_state::stopped;
        check(stopped && dbg.pc() != before, "step " + std::to_string(i + 1) + ": " + util::hex(before) + " -> " + util::hex(dbg.pc()));
        if (!stopped)
            break;
    }
    for (const reg_value& r : dbg.registers())
        printf("  %-6s %s\n", r.name.c_str(), util::hex(r.value).c_str());
    if (dbg.state() == dbg_state::stopped) {
        dbg.del_bp(target + delta);
        check(dbg.cont(err), "continue to the end " + err);
    }
    bool exited = wait_stop(30000) && dbg.state() == dbg_state::none;
    check(exited, util::fmt("process exited (code %d)", dbg.exit_code()));
    if (dbg.state() != dbg_state::none)
        dbg.kill();
    printf("%s\n", failures ? "debugger test FAILED" : "debugger test passed");
    return failures ? 1 : 0;
}

// diff two analyzed files at the function level
static int cmd_diff(const std::vector<std::string>& args, const load_options& opts)
{
    if (args.size() < 3) {
        fprintf(stderr, "usage: ceasta-cli diff <old-file> <new-file>\n");
        return 2;
    }
    std::string ea, eb;
    std::unique_ptr<database> a = open_database(args[1], opts, nullptr, ea);
    std::unique_ptr<database> b = open_database(args[2], opts, nullptr, eb);
    if (!a) {
        fprintf(stderr, "can't open %s: %s\n", args[1].c_str(), ea.c_str());
        return 1;
    }
    if (!b) {
        fprintf(stderr, "can't open %s: %s\n", args[2].c_str(), eb.c_str());
        return 1;
    }
    diff_result d = diff_databases(*a, *b);
    printf("a: %s  (%zu functions)\n", a->bin.name.c_str(), d.funcs_a);
    printf("b: %s  (%zu functions)\n", b->bin.name.c_str(), d.funcs_b);
    printf("identical %zu, changed %zu, added %zu, removed %zu\n\n", d.identical.size(), d.changed.size(),
           d.added.size(), d.removed.size());

    if (!d.changed.empty()) {
        printf("changed (most different first):\n");
        for (const diff_pair& p : d.changed)
            printf("  %3.0f%%  %-30s  %s -> %s\n", p.similarity * 100, p.name.c_str(),
                   a->fmt_addr(p.a).c_str(), b->fmt_addr(p.b).c_str());
        printf("\n");
    }
    if (!d.added.empty()) {
        printf("added (only in b):\n");
        for (uint64_t x : d.added)
            printf("  %s  %s\n", b->fmt_addr(x).c_str(), b->location(x).c_str());
        printf("\n");
    }
    if (!d.removed.empty()) {
        printf("removed (only in a):\n");
        for (uint64_t x : d.removed)
            printf("  %s  %s\n", a->fmt_addr(x).c_str(), a->location(x).c_str());
    }
    return 0;
}

int main(int argc, char** argv)
{
    // the interactive debugger takes the target's own arguments verbatim, so it
    // is dispatched before the flag parsing below
    if (argc >= 2 && strcmp(argv[1], "dbg") == 0)
        return cmd_dbg(argc - 2, argv + 2);
    // the mcp server takes its own options; keep them out of the flag parsing below
    if (argc >= 2 && strcmp(argv[1], "mcp") == 0)
        return cmd_mcp(argc - 2, argv + 2);

    std::vector<std::string> args;
    load_options opts;
    bool debug_mode = false;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--raw32" || a == "--raw64") {
            opts.force_raw = true;
            opts.raw_arch = a == "--raw32" ? bin_arch::x86 : bin_arch::x64;
        } else if (a == "--base" && i + 1 < argc) {
            if (!util::parse_hex(argv[++i], opts.raw_base)) {
                fprintf(stderr, "bad base address\n");
                return 2;
            }
        } else if (a == "--debug") {
            debug_mode = true;
        } else if (a == "-h" || a == "--help") {
            usage();
            return 0;
        } else if (a == "--version") {
            printf("ceasta-cli %s\n", CEASTA_VERSION);
            return 0;
        } else {
            args.push_back(a);
        }
    }
    if (args.size() < 2) {
        usage();
        return 2;
    }
    const std::string& cmd = args[0];
    if (cmd == "debug")
        return cmd_debug(args);
    if (cmd == "diff")
        return cmd_diff(args, opts);

    std::string err;
    std::unique_ptr<database> dbp = open_database(args[1], opts, nullptr, err);
    if (!dbp) {
        fprintf(stderr, "error: %s\n", err.c_str());
        return 1;
    }
    database& db = *dbp;
    const binary& b = db.bin;

    if (cmd == "info") {
        printf("file      %s\n", b.path.c_str());
        printf("format    %s %s (%s)\n", format_name(b.format), arch_name(b.arch), b.kind.c_str());
        printf("base      %s\n", db.fmt_addr(b.base).c_str());
        printf("entry     %s\n", b.has_entry ? (db.fmt_addr(b.entry) + " " + db.name_at(b.entry)).c_str() : "none");
        printf("crc32     %08X\n", db.crc);
        printf("counts    %zu functions, %zu imports, %zu exports, %zu strings, %llu instructions\n",
            db.an.funcs.size(), b.imports.size(), b.exports.size(), db.an.strings.size(), (unsigned long long)db.an.insn_count);
        if (!b.libs.empty()) {
            printf("libs     ");
            for (const std::string& l : b.libs)
                printf(" %s", l.c_str());
            printf("\n");
        }
        printf("segments\n");
        for (const segment& s : b.segments)
            printf("  %-10s %s - %s  %c%c%c  file 0x%llx\n", s.name.c_str(), db.fmt_addr(s.start).c_str(), db.fmt_addr(s.end).c_str(),
                (s.perms & perm_r) ? 'r' : '-', (s.perms & perm_w) ? 'w' : '-', (s.perms & perm_x) ? 'x' : '-',
                (unsigned long long)s.file_size);
        for (const std::string& n : b.notes)
            printf("note: %s\n", n.c_str());
        return 0;
    }
    if (cmd == "funcs") {
        for (const function& f : db.an.funcs)
            printf("%s  %6llx  %s\n", db.fmt_addr(f.start).c_str(), (unsigned long long)(f.end - f.start), db.name_at(f.start).c_str());
        return 0;
    }
    if (cmd == "imports") {
        for (const import_entry& e : b.imports)
            printf("%s  %s!%s\n", db.fmt_addr(e.slot).c_str(), e.lib.empty() ? "?" : e.lib.c_str(), e.name.c_str());
        return 0;
    }
    if (cmd == "exports") {
        for (const export_entry& e : b.exports) {
            if (e.forward.empty())
                printf("%s  %5u  %s\n", db.fmt_addr(e.addr).c_str(), e.ordinal, e.name.c_str());
            else
                printf("%-*s  %5u  %s -> %s\n", (int)db.fmt_addr(0).size(), "forward", e.ordinal, e.name.c_str(), e.forward.c_str());
        }
        return 0;
    }
    if (cmd == "strings") {
        for (const string_item& s : db.an.strings)
            printf("%s  %s\"%s\"\n", db.fmt_addr(s.addr).c_str(), s.wide ? "L" : "", util::escape(s.text, 200).c_str());
        return 0;
    }
    if (cmd == "disasm") {
        uint64_t a;
        if (!where(db, args, 2, a))
            return 1;
        int n = args.size() > 3 ? atoi(args[3].c_str()) : 40;
        const std::vector<row>& rows = db.rows();
        for (size_t i = db.row_of(a); i < rows.size() && n > 0; i++, n--)
            printf("%s\n", line_for(db, rows[i]).c_str());
        return 0;
    }
    if (cmd == "func") {
        uint64_t a;
        if (!where(db, args, 2, a))
            return 1;
        const function* f = db.an.func_containing(a);
        if (!f) {
            fprintf(stderr, "no function at %s\n", db.fmt_addr(a).c_str());
            return 1;
        }
        const std::vector<row>& rows = db.rows();
        size_t i = db.row_of(f->start);
        while (i > 0 && rows[i - 1].addr == f->start)
            i--;
        for (; i < rows.size() && rows[i].addr < f->end; i++)
            printf("%s\n", line_for(db, rows[i]).c_str());
        return 0;
    }
    if (cmd == "decompile" || cmd == "pseudo") {
        uint64_t a;
        if (!where(db, args, 2, a))
            return 1;
        const function* f = db.an.func_containing(a);
        if (!f) {
            fprintf(stderr, "no function at %s\n", db.fmt_addr(a).c_str());
            return 1;
        }
        printf("%s", decompile_text(db, f->start).c_str());
        return 0;
    }
    if (cmd == "graph") {
        uint64_t a;
        if (!where(db, args, 2, a))
            return 1;
        const function* f = db.an.func_containing(a);
        cfg g;
        if (!f || !build_cfg(b, db.an, f->start, g)) {
            fprintf(stderr, "no function at %s\n", db.fmt_addr(a).c_str());
            return 1;
        }
        static const char* const kinds[] = {"next", "taken", "not_taken", "jump", "table"};
        for (size_t i = 0; i < g.blocks.size(); i++) {
            const cfg_block& blk = g.blocks[i];
            printf("block %zu  %s - %s  (%zu insns)\n", i, db.fmt_addr(blk.start).c_str(), db.fmt_addr(blk.end).c_str(), blk.insns.size());
            for (const cfg_edge& e : blk.succ)
                printf("    -> %u %s\n", e.to, kinds[(int)e.kind]);
        }
        if (g.truncated)
            printf("(truncated)\n");
        return 0;
    }
    if (cmd == "xrefs") {
        uint64_t a;
        if (!where(db, args, 2, a))
            return 1;
        static const char* const kinds[] = {"call", "jump", "read", "write", "offset"};
        auto refs = db.an.refs_to(a);
        for (const xref* x = refs.first; x != refs.second; x++)
            printf("%s  %-6s %s\n", db.fmt_addr(x->from).c_str(), kinds[(int)x->type], db.location(x->from).c_str());
        return 0;
    }
    if (cmd == "find") {
        if (args.size() < 3) {
            usage();
            return 2;
        }
        for (uint64_t a : db.find_bytes(args[2], 0, 1000))
            printf("%s  %s\n", db.fmt_addr(a).c_str(), db.location(a).c_str());
        return 0;
    }
    if (cmd == "search") {
        if (args.size() < 3) {
            usage();
            return 2;
        }
        bool cut = false;
        std::vector<search_hit> hits = search_everything(db, args[2], sk_all, 200, &cut);
        for (const search_hit& h : hits) {
            std::string at = h.addr || h.kind != hit_kind::export_ ? db.fmt_addr(h.addr)
                                                                   : util::fmt("%-*s", (int)db.fmt_addr(0).size(), "forward");
            printf("%-8s  %s  %s%s%s\n", hit_kind_name(h.kind), at.c_str(), h.text.c_str(), h.extra.empty() ? "" : "    ",
                h.extra.c_str());
        }
        if (cut)
            printf("(there are more: this shows up to 200 of each kind)\n");
        if (hits.empty()) {
            fprintf(stderr, "nothing matches \"%s\"\n", args[2].c_str());
            return 1;
        }
        return 0;
    }
    if (cmd == "export") {
        std::string e;
        if (!db.save_project(e)) {
            fprintf(stderr, "can't write the project file: %s\n", e.c_str());
            return 1;
        }
        printf("wrote %s\n", db.project_path().c_str());
        return 0;
    }
    if (cmd == "sigmake") {
        std::vector<signature> sigs = make_signatures(db);
        std::string out = args.size() > 2 ? args[2] : b.path + ".sig";
        std::string e;
        if (!os::write_file(out, signatures_to_text(sigs), e)) {
            fprintf(stderr, "can't write %s: %s\n", out.c_str(), e.c_str());
            return 1;
        }
        printf("wrote %zu signatures to %s\n", sigs.size(), out.c_str());
        return 0;
    }
    if (cmd == "sigapply") {
        if (args.size() < 3) {
            fprintf(stderr, "usage: ceasta-cli sigapply <file> <sigs.sig> [--save]\n");
            return 2;
        }
        std::vector<uint8_t> bytes;
        std::string e;
        if (!os::read_file(args[2], bytes, e)) {
            fprintf(stderr, "can't read %s: %s\n", args[2].c_str(), e.c_str());
            return 1;
        }
        bool save = false;
        for (const std::string& a : args)
            if (a == "--save")
                save = true;
        std::vector<signature> sigs = signatures_from_text(std::string(bytes.begin(), bytes.end()));
        std::vector<sig_match> m = match_signatures(db, sigs, save);
        for (const sig_match& hit : m)
            printf("%s  %s\n", db.fmt_addr(hit.addr).c_str(), hit.name.c_str());
        printf("%zu signatures, matched %zu function%s%s\n", sigs.size(), m.size(), m.size() == 1 ? "" : "s",
               save ? " (saved to the project file)" : "");
        if (save && !m.empty())
            db.save_project(e);
        return 0;
    }
    if (cmd == "run") {
        if (args.size() < 3) {
            usage();
            return 2;
        }
        debugger dbg;
        uint64_t delta = 0;
        bool live = false;
        if (debug_mode) {
            if (!debugger::supported()) {
                fprintf(stderr, "--debug needs a build with the debugger (windows x64 or linux x64)\n");
                return 1;
            }
            dbg.on_log = [](const std::string& m) { printf("[dbg] %s\n", m.c_str()); };
            if (!dbg.start(b.path, "", "", err)) {
                fprintf(stderr, "can't start %s: %s\n", b.path.c_str(), err.c_str());
                return 1;
            }
            uint64_t until = os::now_ms() + 15000;
            while (dbg.state() == dbg_state::running && os::now_ms() < until)
                dbg.poll(50);
            if (dbg.state() != dbg_state::stopped) {
                fprintf(stderr, "the program didn't stop at its entry point\n");
                dbg.kill();
                return 1;
            }
            delta = dbg.image_base() - b.base;
            live = true;
        }
        lua_host lua;
        lua_bridge br;
        br.db = &db;
        br.dbg = debug_mode ? &dbg : nullptr;
        br.log = [](const std::string& s, int level) { fprintf(level > 1 ? stderr : stdout, "%s\n", s.c_str()); };
        uint64_t here = b.has_entry ? b.entry : b.min_addr();
        br.here = [&]() { return here; };
        br.jump = [&](uint64_t a) { here = a; };
        br.to_runtime = [&](uint64_t a) { return live ? a + delta : a; };
        br.to_static = [&](uint64_t a, uint64_t& out) {
            if (!live || !b.is_mapped(a - delta))
                return false;
            out = a - delta;
            return true;
        };
        lua.init(br);
        lua.fire("load");
        bool ok = lua.run_file(args[2]);
        // if the script only registered commands, run them so it does something
        for (size_t i = 0; i < lua.commands().size(); i++) {
            printf("--- %s\n", lua.commands()[i].name.c_str());
            ok = lua.run_command(i) && ok;
        }
        if (dbg.state() != dbg_state::none)
            dbg.kill();
        return ok ? 0 : 1;
    }
    usage();
    return 2;
}
