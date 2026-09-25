#include "cli/mcp_cmd.h"

#include "core/bp_cond.h"
#include "core/database.h"
#include "core/debugger.h"
#include "core/kuna.h"
#include "core/lua_host.h"
#include "core/mcp.h"
#include "core/mcp_transport.h"
#include "core/os.h"
#include "core/util.h"
#include "version.h"

#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <set>
#include <string>

// serves one file over MCP. read-only tools are always on; --allow-debug adds the tools that
// run the program, --allow-lua adds the one that runs arbitrary lua.

namespace {

void mcp_usage()
{
    fprintf(stderr,
        "usage: ceasta-cli mcp <file> [options]\n\n"
        "serves the file to an ai client (claude code / desktop, cursor, ...) over the model\n"
        "context protocol. by default it speaks over stdin/stdout - the shape those clients launch.\n\n"
        "options:\n"
        "  --http [addr:]port   serve http on localhost instead of stdio (e.g. --http 8744)\n"
        "  --allow-debug        add the tools that run the program under the debugger\n"
        "  --allow-lua          add run_lua (runs any lua, with file and shell access)\n"
        "  --raw32 / --raw64    load the file as raw x86 / x64 code\n"
        "  --raw-arm64          load the file as raw arm64 code\n"
        "  --base <hex>         base address for raw files\n"
        "  --arch x64|arm64     which part of a universal mach-o file to open\n"
        "  --kuna-path <file>   where kuna is, for decompile_with_kuna (default: kuna on PATH)\n");
}

// the debugger, as the mcp tools reach it, for a single-threaded cli. addresses coming in are
// static (the listing's); the debugger works in runtime addresses.
struct cli_debug {
    database* db = nullptr;
    debugger dbg;
    uint64_t delta = 0;
    bool have_delta = false;
    bool applied = false;   // pending breakpoints written into the process
    std::set<uint64_t> bps; // static addresses the user asked for
    std::map<uint64_t, std::string> conds; // their conditions (static address)
    std::map<uint64_t, int> hits;
    bp_conditions eval;

    uint64_t to_rt(uint64_t st) const { return st + delta; }
    bool to_st(uint64_t rt, uint64_t& out) const
    {
        if (!have_delta || !db)
            return false;
        out = rt - delta;
        return db->bin.is_mapped(out);
    }
    // once the process is up, learn where it loaded; plant the queued breakpoints only while it
    // is stopped (a ptrace memory write needs a stopped tracee)
    void pump()
    {
        dbg.poll(0);
        dbg_state st = dbg.state();
        if (st == dbg_state::none) {
            have_delta = applied = false;
            return;
        }
        if (!have_delta && dbg.image_base()) {
            delta = dbg.image_base() - db->bin.base;
            have_delta = true;
        }
        if (have_delta && !applied && st == dbg_state::stopped) {
            std::string err;
            for (uint64_t s : bps)
                dbg.add_bp(to_rt(s), err);
            applied = true;
        }
        // a breakpoint whose condition is false: keep going
        uint64_t at = 0;
        for (int i = 0; i < 256 && dbg.state() == dbg_state::stopped && dbg.stop_reason() == "breakpoint" &&
                        to_st(dbg.pc(), at) && conds.count(at); i++) {
            std::string err;
            if (eval.check(dbg, conds[at], ++hits[at], err) || !dbg.cont(err))
                break;
            dbg.poll(0);
        }
    }
};

void fill_link(mcp_server& s, cli_debug& c)
{
    s.debug.get = [&c] { return &c.dbg; };
    s.debug.pump = [&c] { c.pump(); };
    s.debug.to_runtime = [&c](uint64_t st) { return c.to_rt(st); };
    s.debug.to_static = [&c](uint64_t rt, uint64_t& out) { return c.to_st(rt, out); };
    s.debug.start = [&c](const std::string& args, std::string& err) {
        c.have_delta = false;
        c.dbg.break_on_entry = true;
        return c.dbg.start(c.db->bin.path, args, "", err);
    };
    s.debug.cont = [&c](std::string& err) { return c.dbg.cont(err); };
    s.debug.step_into = [&c](std::string& err) { return c.dbg.step_into(err); };
    s.debug.step_over = [&c](std::string& err) { return c.dbg.step_over(err); };
    s.debug.pause = [&c](std::string& err) { return c.dbg.pause(err); };
    s.debug.run_to = [&c](uint64_t st, std::string& err) { return c.dbg.run_to(c.to_rt(st), err); };
    s.debug.kill = [&c] { c.dbg.kill(); };
    s.debug.add_bp = [&c](uint64_t st, std::string& err) {
        c.bps.insert(st);
        if (c.have_delta && c.dbg.state() != dbg_state::none)
            return c.dbg.add_bp(c.to_rt(st), err);
        return true; // queued until the process starts
    };
    s.debug.del_bp = [&c](uint64_t st) {
        bool had = c.bps.erase(st) > 0;
        c.conds.erase(st);
        if (c.have_delta && c.dbg.state() != dbg_state::none)
            c.dbg.del_bp(c.to_rt(st));
        return had;
    };
    s.debug.bps = [&c] { return std::vector<uint64_t>(c.bps.begin(), c.bps.end()); };
    s.debug.set_condition = [&c](uint64_t st, const std::string& cond, std::string& err) {
        if (!cond.empty() && !c.eval.valid(cond, err))
            return false;
        if (cond.empty())
            c.conds.erase(st);
        else
            c.conds[st] = cond;
        return true;
    };
    s.debug.condition_of = [&c](uint64_t st) {
        auto it = c.conds.find(st);
        return it == c.conds.end() ? std::string() : it->second;
    };
}

} // namespace

int cmd_mcp(int argc, char** argv)
{
    load_options opts;
    mcp_options mopts;
    std::string file, http, kuna_path;
    bool use_http = false;
    for (int i = 0; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--allow-debug")
            mopts.allow_debug = true;
        else if (a == "--allow-lua")
            mopts.allow_lua = true;
        else if (a == "--http" && i + 1 < argc) {
            use_http = true;
            http = argv[++i];
        } else if (a == "--raw32" || a == "--raw64" || a == "--raw-arm64") {
            opts.force_raw = true;
            opts.raw_arch = a == "--raw32" ? bin_arch::x86 : a == "--raw64" ? bin_arch::x64 : bin_arch::arm64;
        } else if (a == "--arch" && i + 1 < argc) {
            opts.has_slice = true;
            if (!parse_arch(argv[++i], opts.slice)) {
                fprintf(stderr, "--arch takes x64 or arm64\n");
                return 2;
            }
        } else if (a == "--base" && i + 1 < argc) {
            util::parse_hex(argv[++i], opts.raw_base);
        } else if (a == "--kuna-path" && i + 1 < argc) {
            kuna_path = argv[++i];
        } else if (a == "-h" || a == "--help") {
            mcp_usage();
            return 0;
        } else if (!a.empty() && a[0] != '-' && file.empty()) {
            file = a;
        } else {
            fprintf(stderr, "unknown option: %s\n", a.c_str());
            return 2;
        }
    }
    if (file.empty()) {
        mcp_usage();
        return 2;
    }

    std::string err;
    std::unique_ptr<database> db = open_any(file, opts, nullptr, err);
    if (!db) {
        fprintf(stderr, "can't open %s: %s\n", file.c_str(), err.c_str());
        return 1;
    }

    if (mopts.allow_debug && !debugger::supported()) {
        fprintf(stderr, "note: --allow-debug needs a build with the debugger (windows x64 or linux x64); "
                        "the debugger tools will be off\n");
        mopts.allow_debug = false;
    }

    // kuna, the second decompiler, when it's installed (decompile_with_kuna)
    mopts.kuna = kuna_find(kuna_path);
    if (!kuna_path.empty() && mopts.kuna.empty())
        fprintf(stderr, "note: there's no kuna program at %s; decompile_with_kuna will be off\n", kuna_path.c_str());

    mcp_server server;
    server.opts = mopts;
    server.get_db = [&] { return db.get(); };

    // lua, only when allowed
    lua_host lua;
    lua_bridge br;
    cli_debug cdbg;
    cdbg.db = db.get();
    uint64_t here = db->bin.has_entry ? db->bin.entry : db->bin.min_addr();
    if (mopts.allow_lua) {
        br.db = db.get();
        br.dbg = mopts.allow_debug ? &cdbg.dbg : nullptr;
        br.log = [](const std::string&, int) {};
        br.here = [&here] { return here; };
        br.jump = [&here](uint64_t a) { here = a; };
        br.to_runtime = [&cdbg](uint64_t a) { return cdbg.to_rt(a); };
        br.to_static = [&cdbg](uint64_t a, uint64_t& out) { return cdbg.to_st(a, out); };
        lua.init(br);
        server.get_lua = [&lua] { return &lua; };
    }

    if (mopts.allow_debug)
        fill_link(server, cdbg);

    // to stderr, so it never mixes into the stdio json stream
    server.on_activity = [](const std::string& name) { fprintf(stderr, "[mcp] %s\n", name.c_str()); };

    if (use_http) {
        int port = 0;
        std::string addr = "127.0.0.1";
        size_t colon = http.rfind(':');
        if (colon != std::string::npos) {
            addr = http.substr(0, colon);
            port = atoi(http.c_str() + colon + 1);
        } else {
            port = atoi(http.c_str());
        }
        if (port <= 0 || port > 65535) {
            fprintf(stderr, "bad --http value: %s\n", http.c_str());
            return 2;
        }
        fprintf(stderr, "ceasta %s: serving %s over http\n", CEASTA_VERSION, db->bin.name.c_str());
        std::string herr;
        int rc = mcp_serve_http(server, port, addr, [] { return false; }, herr,
                                [](const std::string& url) { fprintf(stderr, "listening on %s\n", url.c_str()); });
        if (rc != 0)
            fprintf(stderr, "%s\n", herr.c_str());
        return rc;
    }

    fprintf(stderr, "ceasta %s: serving %s over stdio (%zu tools%s%s%s)\n", CEASTA_VERSION, db->bin.name.c_str(),
            server.tools().size(), mopts.allow_debug ? ", debugger on" : "", mopts.allow_lua ? ", lua on" : "",
            mopts.kuna.empty() ? "" : ", kuna on");
    return mcp_serve_stdio(server);
}
