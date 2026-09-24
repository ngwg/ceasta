#include "cli/dbg_repl.h"

#include "core/database.h"
#include "core/debugger.h"
#include "core/decompiler.h"
#include "core/disasm.h"
#include "core/lua_host.h"
#include "core/os.h"
#include "core/util.h"

#include <cinttypes>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

// an interactive terminal debugger. small, but it uses ceasta's analysis so the
// listing shows real names and you can decompile the function you're stopped in.

namespace {

std::unique_ptr<database> g_db;
debugger g_dbg;
uint64_t g_delta = 0;        // runtime - static, for the main image
bool g_have_delta = false;

uint64_t to_rt(uint64_t st) { return st + g_delta; }
bool in_image(uint64_t rt, uint64_t& st)
{
    if (!g_have_delta || !g_db)
        return false;
    st = rt - g_delta;
    return g_db->bin.is_mapped(st);
}

// a location label for a runtime address: a name if it maps into our image,
// otherwise the module + offset
std::string loc_rt(uint64_t rt)
{
    uint64_t st;
    if (in_image(rt, st))
        return g_db->location(st);
    for (const dbg_module& m : g_dbg.modules())
        if (m.size && rt >= m.base && rt < m.base + m.size)
            return util::fmt("%s+%llX", m.name.c_str(), (unsigned long long)(rt - m.base));
    return util::hex(rt);
}

// one disassembled line at a runtime address; names when it's in our image
std::string disasm_rt(uint64_t rt, uint32_t& size)
{
    size = 1;
    uint64_t st;
    if (in_image(rt, st)) {
        insn in;
        if (g_db->decode(st, in)) {
            size = in.size ? in.size : 1;
            return g_db->insn_text(in);
        }
    }
    uint8_t buf[16];
    size_t n = g_dbg.read(rt, buf, sizeof(buf));
    disassembler dis;
    insn in;
    if (n && dis.open(g_dbg.is64() ? bin_arch::x64 : bin_arch::x86) && dis.decode(buf, n, rt, in)) {
        size = in.size ? in.size : 1;
        std::string s = in.mnem;
        if (in.ops[0])
            s += std::string(" ") + in.ops;
        return s;
    }
    return "??";
}

bool wait_stop(int timeout_ms = 60000)
{
    uint64_t until = os::now_ms() + (uint64_t)timeout_ms;
    while (g_dbg.state() == dbg_state::running && os::now_ms() < until)
        g_dbg.poll(50);
    return g_dbg.state() != dbg_state::running;
}

void show_stop()
{
    if (g_dbg.state() == dbg_state::none) {
        printf("program exited (code %d)\n", g_dbg.exit_code());
        return;
    }
    uint64_t pc = g_dbg.pc();
    uint32_t sz = 0;
    std::string ins = disasm_rt(pc, sz);
    std::string why = g_dbg.stop_reason();
    printf("\n%s  %s\n    %s\n", loc_rt(pc).c_str(), why.empty() ? "" : ("(" + why + ")").c_str(), ins.c_str());
}

// resolve a command token to a runtime address. names and hex are static
// (listing) addresses; "$pc"/"$sp" are the live registers.
bool resolve_rt(const std::string& tok, uint64_t& rt)
{
    if (tok == "$pc" || tok == "pc") { rt = g_dbg.pc(); return true; }
    if (tok == "$sp" || tok == "sp") { rt = g_dbg.sp(); return true; }
    uint64_t st = 0;
    if (g_db && g_db->resolve(tok, st)) { rt = to_rt(st); return true; }
    uint64_t v = 0;
    if (util::parse_hex(tok, v)) { rt = to_rt(v); return true; } // treat as a static address
    return false;
}

void cmd_regs()
{
    int i = 0;
    for (const reg_value& r : g_dbg.registers()) {
        printf("%-7s %016" PRIx64 "   ", r.name.c_str(), r.value);
        if (++i % 3 == 0)
            printf("\n");
    }
    if (i % 3)
        printf("\n");
}

void cmd_disasm(uint64_t rt, int count)
{
    for (int i = 0; i < count; i++) {
        uint32_t sz = 0;
        std::string ins = disasm_rt(rt, sz);
        printf("  %-24s %s\n", loc_rt(rt).c_str(), ins.c_str());
        rt += sz;
    }
}

void cmd_stack(int count)
{
    uint64_t sp = g_dbg.sp();
    int ptr = g_dbg.is64() ? 8 : 4;
    for (int i = 0; i < count; i++) {
        uint64_t a = sp + (uint64_t)i * ptr, v = 0;
        if (g_dbg.read(a, &v, ptr) != (size_t)ptr)
            break;
        if (ptr == 4)
            v &= 0xffffffff;
        std::string tag;
        uint64_t st;
        if (in_image(v, st) || (v > 0x1000))
            tag = "  " + loc_rt(v);
        printf("  %016" PRIx64 ":  %016" PRIx64 "%s\n", a, v, tag.c_str());
    }
}

void cmd_mem(uint64_t rt, int n)
{
    std::vector<uint8_t> buf((size_t)n);
    size_t got = g_dbg.read(rt, buf.data(), (size_t)n);
    for (size_t off = 0; off < got; off += 16) {
        printf("  %016" PRIx64 "  ", rt + off);
        std::string asc;
        for (size_t j = 0; j < 16; j++) {
            if (off + j < got) {
                printf("%02X ", buf[off + j]);
                char c = (char)buf[off + j];
                asc += (c >= 32 && c < 127) ? c : '.';
            } else {
                printf("   ");
            }
        }
        printf(" %s\n", asc.c_str());
    }
    if (got == 0)
        printf("  can't read memory at %s\n", util::hex(rt).c_str());
}

void help()
{
    printf(
        "commands (addresses accept a name, hex, $pc or $sp):\n"
        "  c                 continue\n"
        "  si [n]            step into (n times)\n"
        "  ni [n]            step over\n"
        "  until <addr>      run to an address\n"
        "  b <addr>          set a breakpoint     bd <addr>  delete    bl  list\n"
        "  r                 registers            set <reg> <val>\n"
        "  u [addr] [n]      disassemble          dec [addr]  decompile the function\n"
        "  x <addr> [n]      hex dump memory      k [n]  stack\n"
        "  bt                where am i (pc + function)\n"
        "  mods              modules              threads / thread <tid>\n"
        "  lua <code>        run lua (ceasta.dbg.* is live)\n"
        "  q                 quit\n");
}

} // namespace

int cmd_dbg(int argc, char** argv)
{
    if (argc < 1) {
        fprintf(stderr, "usage: ceasta-cli dbg <program> [args...]\n");
        return 2;
    }
    if (!debugger::supported()) {
        fprintf(stderr, "this build has no debugger (it needs windows x64 or linux x64)\n");
        return 1;
    }
    std::string path = argv[0];
    std::string prog_args;
    for (int i = 1; i < argc; i++)
        prog_args += (i > 1 ? " " : "") + std::string(argv[i]);

    std::string err;
    load_options opts;
    g_db = open_database(path, opts, nullptr, err);
    if (!g_db) {
        fprintf(stderr, "error: %s\n", err.c_str());
        return 1;
    }

    g_dbg.on_log = [](const std::string& s) { printf("[dbg] %s\n", s.c_str()); };
    if (!g_dbg.start(path, prog_args, "", err)) {
        fprintf(stderr, "can't start %s: %s\n", path.c_str(), err.c_str());
        return 1;
    }
    if (!wait_stop(20000) || g_dbg.state() != dbg_state::stopped) {
        fprintf(stderr, "the program didn't stop at its entry point\n");
        g_dbg.kill();
        return 1;
    }
    g_delta = g_dbg.image_base() - g_db->bin.base;
    g_have_delta = true;

    // ctrl+c should pause the target, not kill the debugger
    signal(SIGINT, [](int) {});

    // a lua bridge so `lua ...` can drive ceasta.dbg.*
    lua_host lua;
    lua_bridge br;
    br.db = g_db.get();
    br.dbg = &g_dbg;
    br.log = [](const std::string& s, int) { printf("%s\n", s.c_str()); };
    uint64_t cursor = g_db->bin.has_entry ? g_db->bin.entry : g_db->bin.min_addr();
    br.here = [&]() { return cursor; };
    br.jump = [&](uint64_t a) { cursor = a; };
    br.to_runtime = [&](uint64_t a) { return to_rt(a); };
    br.to_static = [&](uint64_t a, uint64_t& out) { return in_image(a, out); };
    lua.init(br);
    lua.fire("load");

    printf("ceasta debugger. type 'help' for commands, 'q' to quit.\n");
    show_stop();

    char line[1024];
    while (true) {
        printf("(ceasta) ");
        fflush(stdout);
        if (!fgets(line, sizeof(line), stdin))
            break;
        std::vector<std::string> tok;
        for (const std::string& t : util::split(util::trim(line), " "))
            if (!t.empty())
                tok.push_back(t);
        if (tok.empty())
            continue;
        const std::string& c = tok[0];
        bool running_gone = g_dbg.state() == dbg_state::none;

        if (c == "q" || c == "quit" || c == "exit")
            break;
        if (c == "help" || c == "?") {
            help();
            continue;
        }
        if (running_gone && c != "lua") {
            printf("the program has exited (code %d). 'q' to quit.\n", g_dbg.exit_code());
            continue;
        }

        if (c == "c" || c == "continue") {
            if (!g_dbg.cont(err)) { printf("%s\n", err.c_str()); continue; }
            wait_stop(24 * 3600 * 1000);
            show_stop();
        } else if (c == "si" || c == "step") {
            int n = tok.size() > 1 ? atoi(tok[1].c_str()) : 1;
            for (int i = 0; i < n && g_dbg.state() == dbg_state::stopped; i++) {
                if (!g_dbg.step_into(err)) { printf("%s\n", err.c_str()); break; }
                wait_stop();
            }
            show_stop();
        } else if (c == "ni" || c == "next") {
            int n = tok.size() > 1 ? atoi(tok[1].c_str()) : 1;
            for (int i = 0; i < n && g_dbg.state() == dbg_state::stopped; i++) {
                if (!g_dbg.step_over(err)) { printf("%s\n", err.c_str()); break; }
                wait_stop();
            }
            show_stop();
        } else if (c == "until" || c == "runto") {
            uint64_t rt;
            if (tok.size() < 2 || !resolve_rt(tok[1], rt)) { printf("need an address\n"); continue; }
            if (!g_dbg.run_to(rt, err)) { printf("%s\n", err.c_str()); continue; }
            wait_stop(24 * 3600 * 1000);
            show_stop();
        } else if (c == "b" || c == "break") {
            uint64_t rt;
            if (tok.size() < 2 || !resolve_rt(tok[1], rt)) { printf("need an address\n"); continue; }
            if (g_dbg.add_bp(rt, err)) printf("breakpoint at %s\n", loc_rt(rt).c_str());
            else printf("%s\n", err.c_str());
        } else if (c == "bd" || c == "delete") {
            uint64_t rt;
            if (tok.size() < 2 || !resolve_rt(tok[1], rt)) { printf("need an address\n"); continue; }
            printf(g_dbg.del_bp(rt) ? "deleted\n" : "no breakpoint there\n");
        } else if (c == "bl") {
            for (uint64_t a : g_dbg.bps())
                printf("  %s\n", loc_rt(a).c_str());
        } else if (c == "r" || c == "regs") {
            cmd_regs();
        } else if (c == "set") {
            uint64_t v;
            if (tok.size() < 3 || !util::parse_hex(tok[2], v)) { printf("usage: set <reg> <hexvalue>\n"); continue; }
            printf("%s\n", g_dbg.set_register(tok[1], v, err) ? "ok" : err.c_str());
        } else if (c == "u" || c == "disasm") {
            uint64_t rt = g_dbg.pc();
            if (tok.size() > 1 && !resolve_rt(tok[1], rt)) { printf("bad address\n"); continue; }
            int n = tok.size() > 2 ? atoi(tok[2].c_str()) : 10;
            cmd_disasm(rt, n);
        } else if (c == "dec" || c == "decompile") {
            uint64_t rt = g_dbg.pc(), st;
            if (tok.size() > 1 && !resolve_rt(tok[1], rt)) { printf("bad address\n"); continue; }
            if (!in_image(rt, st)) { printf("not in the loaded image\n"); continue; }
            printf("%s", decompile_text(*g_db, st).c_str());
        } else if (c == "x" || c == "mem") {
            uint64_t rt;
            if (tok.size() < 2 || !resolve_rt(tok[1], rt)) { printf("need an address\n"); continue; }
            int n = tok.size() > 2 ? atoi(tok[2].c_str()) : 64;
            cmd_mem(rt, n);
        } else if (c == "k" || c == "stack") {
            cmd_stack(tok.size() > 1 ? atoi(tok[1].c_str()) : 8);
        } else if (c == "bt" || c == "where") {
            uint64_t pc = g_dbg.pc();
            printf("pc = %s (%s)\n", util::hex(pc).c_str(), loc_rt(pc).c_str());
        } else if (c == "mods" || c == "modules") {
            for (const dbg_module& m : g_dbg.modules())
                printf("  %016" PRIx64 "  %s\n", m.base, m.name.c_str());
        } else if (c == "threads") {
            for (const dbg_thread& t : g_dbg.threads())
                printf("  tid %u  pc %s%s\n", t.id, util::hex(t.pc).c_str(), t.id == g_dbg.tid() ? "  *" : "");
        } else if (c == "thread") {
            if (tok.size() < 2 || !g_dbg.select_thread((uint32_t)atoi(tok[1].c_str()))) printf("no such thread\n");
            else show_stop();
        } else if (c == "lua") {
            std::string code = util::trim(std::string(line).substr(3));
            lua.run_console(code);
        } else {
            printf("unknown command '%s' (try 'help')\n", c.c_str());
        }
    }

    if (g_dbg.state() != dbg_state::none)
        g_dbg.kill();
    return 0;
}
