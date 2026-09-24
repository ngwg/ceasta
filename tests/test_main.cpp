// ceasta test suite. builds against the core, runs on the fixtures in tests/fixtures.
// usage: ceasta-tests <fixtures-dir>
#include "core/analysis.h"
#include "core/database.h"
#include "core/disasm.h"
#include "core/lua_host.h"
#include "core/os.h"
#include "core/util.h"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

static int g_checks = 0;
static int g_fails = 0;
static std::string g_group;

static void group(const char* name)
{
    g_group = name;
    printf("\n[%s]\n", name);
}

#define CHECK(cond, ...)                                                            \
    do {                                                                           \
        g_checks++;                                                                \
        if (cond) {                                                                \
            printf("  ok   %s\n", desc(__VA_ARGS__).c_str());                      \
        } else {                                                                   \
            g_fails++;                                                             \
            printf("  FAIL %s   (%s:%d)\n", desc(__VA_ARGS__).c_str(), __FILE__, __LINE__); \
        }                                                                          \
    } while (0)

template <typename... A>
static std::string desc(const char* fmt, A... args)
{
    return util::fmt(fmt, args...);
}
static std::string desc(const char* s) { return s; }

static std::string g_dir;
static std::unique_ptr<database> load(const std::string& file)
{
    load_options o;
    std::string err;
    auto db = open_database(os::join(g_dir, file), o, nullptr, err);
    if (!db)
        printf("  FAIL could not load %s: %s\n", file.c_str(), err.c_str()), g_fails++, g_checks++;
    return db;
}

static const function* find_func(database& db, const std::string& name)
{
    for (const function& f : db.an.funcs)
        if (db.name_at(f.start) == name)
            return &f;
    return nullptr;
}

static bool has_import(const binary& b, const std::string& name)
{
    for (const import_entry& e : b.imports)
        if (e.name == name)
            return true;
    return false;
}

// count instructions with a given mnemonic in a function
static int count_mnem(database& db, const function& f, const char* mnem)
{
    int n = 0;
    uint64_t a = f.start;
    while (a < f.end) {
        insn in;
        if (!db.decode(a, in))
            break;
        if (strcmp(in.mnem, mnem) == 0)
            n++;
        a = in.next();
    }
    return n;
}

static void test_loader(const std::string& file, bin_format fmt, bin_arch arch, bool expect_entry)
{
    group(("loader " + file).c_str());
    auto dbp = load(file);
    if (!dbp)
        return;
    database& db = *dbp;
    const binary& b = db.bin;
    CHECK(b.format == fmt, "format is %s", format_name(fmt));
    CHECK(b.arch == arch, "arch is %s", arch_name(arch));
    CHECK(!b.segments.empty(), "has segments");
    CHECK(b.has_entry == expect_entry, "entry point present == %d", expect_entry);
    if (expect_entry) {
        CHECK(b.is_code(b.entry), "entry %s is in executable memory", db.fmt_addr(b.entry).c_str());
        CHECK(db.an.flags_at(b.entry) & fl_code, "entry decodes as code");
    }
    CHECK(db.an.funcs.size() >= 3, "found %zu functions (>=3)", db.an.funcs.size());
    CHECK(db.an.insn_count > 20, "decoded %llu instructions", (unsigned long long)db.an.insn_count);
    // segments are sorted and don't overlap
    bool sorted = true;
    for (size_t i = 1; i < b.segments.size(); i++)
        if (b.segments[i].start < b.segments[i - 1].end)
            sorted = false;
    CHECK(sorted, "segments sorted and non-overlapping");
    // every function start decodes and lands in code
    bool all_code = true;
    for (const function& f : db.an.funcs)
        if (!b.is_code(f.start))
            all_code = false;
    CHECK(all_code, "all function starts are in code");
}

static void test_imports(const std::string& file, bin_format fmt)
{
    group(("imports " + file).c_str());
    auto dbp = load(file);
    if (!dbp)
        return;
    const binary& b = dbp->bin;
    // the sample prints, so it imports puts or printf one way or another
    CHECK(has_import(b, "puts") || has_import(b, "printf"), "imports puts or printf");
    if (fmt == bin_format::pe)
        CHECK(!b.libs.empty(), "records imported dlls (%zu)", b.libs.size());
}

static void test_switch(const std::string& file)
{
    group(("switch table " + file).c_str());
    auto dbp = load(file);
    if (!dbp)
        return;
    database& db = *dbp;
    // classify() has an 8 case switch, expect a table with 8 targets somewhere
    bool found = false;
    for (const auto& kv : db.an.tables)
        if (kv.second.targets.size() >= 7)
            found = true;
    CHECK(found, "recovered a jump table with >=7 targets");
}

static void test_names_symbols(const std::string& file)
{
    group(("symbols " + file).c_str());
    auto dbp = load(file);
    if (!dbp)
        return;
    database& db = *dbp;
    // elf fixtures keep their symbol table, so real names must survive
    CHECK(find_func(db, "classify") != nullptr, "function 'classify' named from symbols");
    CHECK(find_func(db, "checksum") != nullptr, "function 'checksum' named from symbols");
    const function* main_fn = find_func(db, "main");
    CHECK(main_fn != nullptr, "function 'main' named from symbols");
    if (main_fn)
        CHECK(count_mnem(db, *main_fn, "call") >= 2, "main makes at least two calls");
}

static void test_annotations(const std::string& file)
{
    group("names, comments, resolve");
    auto dbp = load(file);
    if (!dbp)
        return;
    database& db = *dbp;
    uint64_t a = db.bin.entry;
    std::string err;
    CHECK(db.set_name(a, "my_entry", err), "set a user name (%s)", err.c_str());
    CHECK(db.name_at(a) == "my_entry", "user name reads back");
    uint64_t r = 0;
    CHECK(db.resolve("my_entry", r) && r == a, "resolve name -> address");
    CHECK(!db.set_name(a, "bad name!", err), "reject an invalid name");
    CHECK(!db.set_name(a, "sub_1234", err), "reject an auto-name prefix");
    db.set_comment(a, "hello");
    CHECK(db.comment_at(a) == "hello", "comment reads back");
    uint64_t hexr = 0;
    CHECK(db.resolve("0x" + util::hex_lower(a), hexr) && hexr == a, "resolve hex string");
    CHECK(db.set_name(a, "", err), "clearing a name restores the default");
    CHECK(db.name_at(a) != "my_entry", "default name after clear");
}

static void test_persistence(const std::string& file)
{
    group("save / load annotations");
    auto dbp = load(file);
    if (!dbp)
        return;
    database& db = *dbp;
    uint64_t a = db.an.funcs.size() > 1 ? db.an.funcs[1].start : db.bin.entry;
    std::string err;
    db.set_name(a, "persisted_fn", err);
    db.set_comment(a, "note that survives");
    db.breakpoints.insert(a);
    CHECK(db.save(err), "save database (%s)", err.c_str());
    std::string path = db.db_path();

    auto db2p = load(file); // reloads annotations from disk in open_database
    bool ok = false;
    if (db2p)
        ok = db2p->name_at(a) == "persisted_fn" && db2p->comment_at(a) == "note that survives" && db2p->breakpoints.count(a);
    CHECK(ok, "name, comment and breakpoint reloaded");
    os::write_file(path, "", err); // leave a tiny file, don't pollute
    remove(path.c_str());
}

static void test_disasm_roundtrip(const std::string& file)
{
    group(("decode covers items " + file).c_str());
    auto dbp = load(file);
    if (!dbp)
        return;
    database& db = *dbp;
    // every code item's decoded size must match the analysis item size
    int mismatches = 0, checked = 0;
    for (const function& f : db.an.funcs) {
        uint64_t a = f.start;
        while (a < f.end && checked < 5000) {
            if (!(db.an.flags_at(a) & fl_code))
                break;
            insn in;
            if (!db.decode(a, in))
                break;
            if (in.size != db.an.item_size(a))
                mismatches++;
            checked++;
            a += in.size;
        }
    }
    CHECK(mismatches == 0, "%d/%d decoded sizes match the listing", checked - mismatches, checked);
}

static void test_find(const std::string& file)
{
    group("byte search");
    auto dbp = load(file);
    if (!dbp)
        return;
    database& db = *dbp;
    // grab the first few bytes at the entry and search for them back
    uint8_t buf[4];
    if (db.bin.read(db.bin.entry, buf, 4) == 4) {
        std::string pat = util::fmt("%02X %02X ?? %02X", buf[0], buf[1], buf[3]);
        auto hits = db.find_bytes(pat, 0, 100);
        bool found_entry = false;
        for (uint64_t h : hits)
            if (h == db.bin.entry)
                found_entry = true;
        CHECK(found_entry, "wildcard search finds the entry bytes (%zu hits)", hits.size());
    }
    CHECK(db.find_bytes("zznothex", 0, 10).empty(), "invalid pattern returns nothing");
}

static void test_cfg(const std::string& file)
{
    group("control flow graph");
    auto dbp = load(file);
    if (!dbp)
        return;
    database& db = *dbp;
    const function* f = find_func(db, "classify");
    if (!f)
        f = db.an.funcs.empty() ? nullptr : &db.an.funcs[0];
    if (!f) {
        CHECK(false, "no function to graph");
        return;
    }
    cfg g;
    CHECK(build_cfg(db.bin, db.an, f->start, g), "built a cfg for %s", db.name_at(f->start).c_str());
    CHECK(!g.blocks.empty(), "cfg has %zu blocks", g.blocks.size());
    CHECK(g.blocks[0].start == f->start, "entry block starts at the function");
    // every edge points at a real block
    bool edges_ok = true;
    for (const cfg_block& blk : g.blocks)
        for (const cfg_edge& e : blk.succ)
            if (e.to >= g.blocks.size())
                edges_ok = false;
    CHECK(edges_ok, "all cfg edges are in range");
}

static void test_lua()
{
    group("lua host");
    lua_host lua;
    lua_bridge br;
    int errors = 0;
    br.log = [&](const std::string&, int level) { if (level >= 2) errors++; };
    CHECK(lua.init(br), "lua state created");
    CHECK(lua.run_string("assert(1 + 1 == 2)", "t"), "run a simple chunk");
    CHECK(lua.run_string("x = ceasta.resolve", "t") && true, "ceasta table exists");
    errors = 0;
    CHECK(!lua.run_string("error('boom')", "t") && errors == 1, "errors are reported, not fatal");
    // sandbox / watchdog: an infinite loop must be cancelled, not hang
    lua.timeout_ms = 500;
    errors = 0;
    bool done = !lua.run_string("while true do end", "t");
    CHECK(done && errors == 1, "runaway loop is cancelled by the watchdog");
}

static void test_lua_api(const std::string& file)
{
    group("lua api against a file");
    auto dbp = load(file);
    if (!dbp)
        return;
    lua_host lua;
    lua_bridge br;
    br.db = dbp.get();
    int errors = 0;
    br.log = [&](const std::string&, int level) { if (level >= 2) errors++; };
    lua.init(br);
    const char* script =
        "local f = ceasta.file()\n"
        "assert(f.bits == 32 or f.bits == 64)\n"
        "assert(#ceasta.functions() > 0, 'no functions')\n"
        "assert(#ceasta.strings() > 0, 'no strings')\n"
        "local ins = ceasta.disasm(f.entry)\n"
        "assert(ins and ins.size > 0, 'entry did not decode')\n"
        "assert(ceasta.is_code(f.entry), 'entry not code')\n"
        "local ok = ceasta.set_name(f.entry, 'lua_named')\n"
        "assert(ok and ceasta.name(f.entry) == 'lua_named', 'set_name failed')\n"
        "assert(ceasta.resolve('lua_named') == f.entry, 'resolve failed')\n";
    CHECK(lua.run_string(script, "api") && errors == 0, "core api works from lua");
}

// loaders parse untrusted files: mutated and truncated inputs must never crash
static void test_fuzz(const std::string& file, int rounds)
{
    group(("fuzz " + file).c_str());
    std::vector<uint8_t> orig;
    std::string err;
    if (!os::read_file(os::join(g_dir, file), orig, err)) {
        CHECK(false, "read %s", file.c_str());
        return;
    }
    uint64_t seed = 0x9E3779B97F4A7C15ull ^ orig.size();
    auto rnd = [&]() {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        return seed;
    };
    int loaded = 0;
    for (int r = 0; r < rounds; r++) {
        std::vector<uint8_t> bytes = orig;
        int kind = (int)(rnd() % 4);
        if (kind == 0) {
            bytes.resize((size_t)(rnd() % bytes.size())); // truncate
        } else {
            int flips = 1 + (int)(rnd() % 16);
            for (int i = 0; i < flips; i++) {
                // mostly hit the headers, sometimes anywhere
                size_t span = kind == 1 ? std::min<size_t>(bytes.size(), 4096) : bytes.size();
                bytes[(size_t)(rnd() % span)] = (uint8_t)rnd();
            }
        }
        binary b;
        if (!loader::from_bytes(std::move(bytes), file, b, err))
            continue;
        analysis an;
        analyze(b, an, nullptr);
        database db;
        db.bin = std::move(b);
        db.an = std::move(an);
        db.build();
        // walk part of the listing, formatting touches most of the lookup code
        const std::vector<row>& rows = db.rows();
        line_text t;
        for (size_t i = 0; i < rows.size() && i < 3000; i++)
            db.format(rows[i], t);
        loaded++;
    }
    CHECK(true, "%d mutated inputs handled without crashing (%d loaded)", rounds, loaded);
}

int main(int argc, char** argv)
{
    g_dir = argc > 1 ? argv[1] : "tests/fixtures";
    printf("ceasta tests, fixtures in %s\n", g_dir.c_str());

    test_loader("sample64.exe", bin_format::pe, bin_arch::x64, true);
    test_loader("sample32.exe", bin_format::pe, bin_arch::x86, true);
    test_loader("sample64.dll", bin_format::pe, bin_arch::x64, true);
    test_loader("sample64.elf", bin_format::elf, bin_arch::x64, true);
    test_loader("sample32.elf", bin_format::elf, bin_arch::x86, true);

    test_imports("sample64.exe", bin_format::pe);
    test_imports("sample64.elf", bin_format::elf);

    test_switch("sample64.exe");
    test_switch("sample32.exe");
    test_switch("sample64.elf");
    test_switch("sample32.elf");

    test_names_symbols("sample64.elf");
    test_names_symbols("sample32.elf");

    test_disasm_roundtrip("sample64.exe");
    test_disasm_roundtrip("sample64.elf");

    test_annotations("sample64.elf");
    test_persistence("sample64.elf");
    test_find("sample64.elf");
    test_cfg("sample64.elf");
    test_cfg("sample64.exe");

    test_lua();
    test_lua_api("sample64.elf");

    const char* fuzz_env = getenv("CEASTA_FUZZ_ROUNDS");
    int rounds = fuzz_env ? atoi(fuzz_env) : 60;
    for (const char* f : {"sample64.exe", "sample32.exe", "sample64.dll", "sample64.elf", "sample32.elf"})
        test_fuzz(f, rounds);

    printf("\n%d checks, %d failed\n", g_checks, g_fails);
    return g_fails == 0 ? 0 : 1;
}
