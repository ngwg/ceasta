#include "core/lua_host.h"
#include "core/database.h"
#include "core/debugger.h"
#include "core/os.h"
#include "core/util.h"

// lua is compiled as c++ (see CMakeLists.txt), so no extern "C" here: lua errors are
// c++ exceptions and unwind our frames properly instead of longjmp-ing over them
#include "lauxlib.h"
#include "lua.h"
#include "lualib.h"

#include <algorithm>
#include <type_traits>

#ifndef CEASTA_LUA_VERSION
#define CEASTA_LUA_VERSION "ceasta lua api 1 (" LUA_VERSION ")"
#endif

// ---- helpers to move between lua and c++ ----

namespace {

// the host pointer lives in lua's per state extra space, so it's reachable from api
// functions, debug hooks and coroutines alike (an upvalue isn't visible inside a hook)
lua_host* host_of(lua_State* L)
{
    return *static_cast<lua_host**>(lua_getextraspace(L));
}

// addresses cross the boundary as strings, so 64 bit values survive lua's doubles
uint64_t check_addr(lua_State* L, int idx)
{
    if (lua_type(L, idx) == LUA_TSTRING) {
        uint64_t v;
        std::string s = lua_tostring(L, idx);
        lua_host* h = host_of(L);
        if (h && h->bridge().db && h->bridge().db->resolve(s, v))
            return v;
        if (util::parse_hex(s, v))
            return v;
        return (uint64_t)luaL_error(L, "can't resolve address '%s'", s.c_str());
    }
    if (lua_isinteger(L, idx))
        return (uint64_t)lua_tointeger(L, idx);
    return (uint64_t)(int64_t)luaL_checknumber(L, idx);
}

// push a 64 bit address, as an integer when it fits lua's integer exactly
void push_addr(lua_State* L, uint64_t v)
{
    lua_pushinteger(L, (lua_Integer)v);
}

database* need_db(lua_State* L)
{
    lua_host* h = host_of(L);
    database* db = h ? h->bridge().db : nullptr;
    if (!db)
        luaL_error(L, "no file is loaded");
    return db;
}

// the debug hook cancels a plugin that runs too long or that the app asked to stop
void time_hook(lua_State* L, lua_Debug*)
{
    lua_host* h = host_of(L);
    if (h && !h->check_deadline()) {
        lua_sethook(L, nullptr, 0, 0);
        luaL_error(L, "plugin cancelled (ran longer than the time limit)");
    }
}

}

// ---- the ceasta.* api ----

namespace {

int api_log(lua_State* L)
{
    int n = lua_gettop(L);
    std::string msg;
    for (int i = 1; i <= n; i++) {
        size_t len = 0;
        const char* s = luaL_tolstring(L, i, &len); // works on any type
        msg.append(s, len);
        lua_pop(L, 1);
        if (i < n)
            msg += "\t";
    }
    host_of(L)->log(msg, 0);
    return 0;
}

int api_warn(lua_State* L)
{
    host_of(L)->log(luaL_checkstring(L, 1), 1);
    return 0;
}

int api_file_info(lua_State* L)
{
    database* db = need_db(L);
    const binary& b = db->bin;
    lua_newtable(L);
    auto set_s = [&](const char* k, const std::string& v) { lua_pushstring(L, v.c_str()); lua_setfield(L, -2, k); };
    auto set_a = [&](const char* k, uint64_t v) { push_addr(L, v); lua_setfield(L, -2, k); };
    set_s("path", b.path);
    set_s("name", b.name);
    set_s("format", format_name(b.format));
    set_s("arch", arch_name(b.arch));
    set_s("kind", b.kind);
    set_a("base", b.base);
    set_a("entry", b.entry);
    lua_pushboolean(L, b.has_entry);
    lua_setfield(L, -2, "has_entry");
    lua_pushinteger(L, b.is64() ? 64 : 32);
    lua_setfield(L, -2, "bits");
    return 1;
}

int api_read(lua_State* L)
{
    database* db = need_db(L);
    uint64_t a = check_addr(L, 1);
    lua_Integer n = luaL_checkinteger(L, 2);
    if (n < 0 || n > (1 << 20))
        return luaL_error(L, "read length out of range");
    std::string buf((size_t)n, '\0');
    size_t got = db->bin.read(a, &buf[0], (size_t)n);
    buf.resize(got);
    lua_pushlstring(L, buf.data(), buf.size());
    return 1;
}

template <typename T>
int read_int(lua_State* L, bool sign)
{
    database* db = need_db(L);
    uint64_t a = check_addr(L, 1);
    T v = 0;
    if (db->bin.read(a, &v, sizeof(T)) != sizeof(T)) {
        lua_pushnil(L);
        return 1;
    }
    if (sign)
        lua_pushinteger(L, (lua_Integer)(int64_t)(typename std::make_signed<T>::type)v);
    else
        push_addr(L, (uint64_t)v);
    return 1;
}

int api_read_u8(lua_State* L) { return read_int<uint8_t>(L, false); }
int api_read_u16(lua_State* L) { return read_int<uint16_t>(L, false); }
int api_read_u32(lua_State* L) { return read_int<uint32_t>(L, false); }
int api_read_u64(lua_State* L) { return read_int<uint64_t>(L, false); }
int api_read_i32(lua_State* L) { return read_int<uint32_t>(L, true); }

int api_read_ptr(lua_State* L)
{
    database* db = need_db(L);
    uint64_t a = check_addr(L, 1), v;
    if (db->bin.read_ptr(a, v))
        push_addr(L, v);
    else
        lua_pushnil(L);
    return 1;
}

int api_read_cstr(lua_State* L)
{
    database* db = need_db(L);
    uint64_t a = check_addr(L, 1);
    lua_Integer max = luaL_optinteger(L, 2, 1024);
    std::string s = db->bin.read_cstr(a, (size_t)std::max<lua_Integer>(0, max));
    lua_pushstring(L, s.c_str());
    return 1;
}

int api_is_mapped(lua_State* L)
{
    lua_pushboolean(L, need_db(L)->bin.is_mapped(check_addr(L, 1)));
    return 1;
}

int api_is_code(lua_State* L)
{
    lua_pushboolean(L, need_db(L)->bin.is_code(check_addr(L, 1)));
    return 1;
}

int api_name(lua_State* L)
{
    database* db = need_db(L);
    lua_pushstring(L, db->name_at(check_addr(L, 1)).c_str());
    return 1;
}

int api_location(lua_State* L)
{
    database* db = need_db(L);
    lua_pushstring(L, db->location(check_addr(L, 1)).c_str());
    return 1;
}

int api_set_name(lua_State* L)
{
    database* db = need_db(L);
    uint64_t a = check_addr(L, 1);
    std::string name = luaL_checkstring(L, 2);
    std::string err;
    if (!db->set_name(a, name, err)) {
        lua_pushboolean(L, false);
        lua_pushstring(L, err.c_str());
        return 2;
    }
    lua_pushboolean(L, true);
    return 1;
}

int api_resolve(lua_State* L)
{
    database* db = need_db(L);
    uint64_t a;
    if (db->resolve(luaL_checkstring(L, 1), a))
        push_addr(L, a);
    else
        lua_pushnil(L);
    return 1;
}

int api_comment(lua_State* L)
{
    lua_pushstring(L, need_db(L)->comment_at(check_addr(L, 1)).c_str());
    return 1;
}

int api_set_comment(lua_State* L)
{
    database* db = need_db(L);
    db->set_comment(check_addr(L, 1), luaL_checkstring(L, 2));
    return 0;
}

int api_disasm(lua_State* L)
{
    database* db = need_db(L);
    uint64_t a = check_addr(L, 1);
    insn in;
    if (!db->decode(a, in)) {
        lua_pushnil(L);
        return 1;
    }
    lua_newtable(L);
    push_addr(L, in.addr);
    lua_setfield(L, -2, "addr");
    lua_pushinteger(L, in.size);
    lua_setfield(L, -2, "size");
    lua_pushstring(L, in.mnem);
    lua_setfield(L, -2, "mnemonic");
    lua_pushstring(L, in.ops);
    lua_setfield(L, -2, "operands");
    lua_pushstring(L, db->insn_text(in).c_str());
    lua_setfield(L, -2, "text");
    static const char* const kinds[] = {"normal", "jump", "cond", "call", "ret", "stop"};
    lua_pushstring(L, kinds[(int)in.kind]);
    lua_setfield(L, -2, "flow");
    if (in.has_target && !in.indirect) {
        push_addr(L, in.target);
        lua_setfield(L, -2, "target");
    }
    return 1;
}

int api_next_addr(lua_State* L)
{
    database* db = need_db(L);
    uint64_t a = check_addr(L, 1);
    push_addr(L, a + std::max<uint32_t>(db->an.item_size(a), 1));
    return 1;
}

// iterators return a plain array of tables, easy to use with ipairs
void begin_array(lua_State* L) { lua_newtable(L); }
void array_push(lua_State* L, int& i) { lua_rawseti(L, -2, ++i); }

int api_functions(lua_State* L)
{
    database* db = need_db(L);
    begin_array(L);
    int i = 0;
    for (const function& f : db->an.funcs) {
        lua_newtable(L);
        push_addr(L, f.start);
        lua_setfield(L, -2, "addr");
        push_addr(L, f.end - f.start);
        lua_setfield(L, -2, "size");
        lua_pushstring(L, db->name_at(f.start).c_str());
        lua_setfield(L, -2, "name");
        lua_pushboolean(L, f.thunk);
        lua_setfield(L, -2, "thunk");
        array_push(L, i);
    }
    return 1;
}

int api_imports(lua_State* L)
{
    database* db = need_db(L);
    begin_array(L);
    int i = 0;
    for (const import_entry& e : db->bin.imports) {
        lua_newtable(L);
        push_addr(L, e.slot);
        lua_setfield(L, -2, "slot");
        lua_pushstring(L, e.lib.c_str());
        lua_setfield(L, -2, "lib");
        lua_pushstring(L, e.name.c_str());
        lua_setfield(L, -2, "name");
        array_push(L, i);
    }
    return 1;
}

int api_exports(lua_State* L)
{
    database* db = need_db(L);
    begin_array(L);
    int i = 0;
    for (const export_entry& e : db->bin.exports) {
        lua_newtable(L);
        push_addr(L, e.addr);
        lua_setfield(L, -2, "addr");
        lua_pushinteger(L, e.ordinal);
        lua_setfield(L, -2, "ordinal");
        lua_pushstring(L, e.name.c_str());
        lua_setfield(L, -2, "name");
        if (!e.forward.empty()) {
            lua_pushstring(L, e.forward.c_str());
            lua_setfield(L, -2, "forward");
        }
        array_push(L, i);
    }
    return 1;
}

int api_strings(lua_State* L)
{
    database* db = need_db(L);
    begin_array(L);
    int i = 0;
    for (const string_item& s : db->an.strings) {
        lua_newtable(L);
        push_addr(L, s.addr);
        lua_setfield(L, -2, "addr");
        lua_pushstring(L, s.text.c_str());
        lua_setfield(L, -2, "text");
        lua_pushboolean(L, s.wide);
        lua_setfield(L, -2, "wide");
        array_push(L, i);
    }
    return 1;
}

int api_xrefs_to(lua_State* L)
{
    database* db = need_db(L);
    uint64_t a = check_addr(L, 1);
    static const char* const kinds[] = {"call", "jump", "read", "write", "offset"};
    begin_array(L);
    int i = 0;
    auto refs = db->an.refs_to(a);
    for (const xref* x = refs.first; x != refs.second; x++) {
        lua_newtable(L);
        push_addr(L, x->from);
        lua_setfield(L, -2, "from");
        push_addr(L, x->to);
        lua_setfield(L, -2, "to");
        lua_pushstring(L, kinds[(int)x->type]);
        lua_setfield(L, -2, "type");
        array_push(L, i);
    }
    return 1;
}

int api_find(lua_State* L)
{
    database* db = need_db(L);
    std::string pat = luaL_checkstring(L, 1);
    uint64_t from = lua_gettop(L) >= 2 ? check_addr(L, 2) : 0;
    lua_Integer max = luaL_optinteger(L, 3, 1000);
    begin_array(L);
    int i = 0;
    for (uint64_t a : db->find_bytes(pat, from, (size_t)std::max<lua_Integer>(1, max))) {
        push_addr(L, a);
        array_push(L, i);
    }
    return 1;
}

int api_here(lua_State* L)
{
    lua_host* h = host_of(L);
    push_addr(L, h->bridge().here ? h->bridge().here() : 0);
    return 1;
}

int api_goto(lua_State* L)
{
    lua_host* h = host_of(L);
    uint64_t a = check_addr(L, 1);
    if (h->bridge().jump)
        h->bridge().jump(a);
    return 0;
}

int api_register_command(lua_State* L)
{
    const char* name = luaL_checkstring(L, 1);
    luaL_checktype(L, 2, LUA_TFUNCTION);
    const char* help = luaL_optstring(L, 3, "");
    lua_pushvalue(L, 2);
    int ref = luaL_ref(L, LUA_REGISTRYINDEX);
    host_of(L)->add_command(name, help, ref);
    return 0;
}

int api_on(lua_State* L)
{
    const char* event = luaL_checkstring(L, 1);
    luaL_checktype(L, 2, LUA_TFUNCTION);
    lua_pushvalue(L, 2);
    int ref = luaL_ref(L, LUA_REGISTRYINDEX);
    host_of(L)->add_handler(event, ref);
    return 0;
}

// ---- debugger sub table ----

debugger* need_dbg(lua_State* L)
{
    lua_host* h = host_of(L);
    debugger* d = h ? h->bridge().dbg : nullptr;
    if (!d)
        luaL_error(L, "the debugger isn't available in this build");
    return d;
}

int dbg_state_fn(lua_State* L)
{
    debugger* d = need_dbg(L);
    const char* s = d->state() == dbg_state::running ? "running" : d->state() == dbg_state::stopped ? "stopped" : "none";
    lua_pushstring(L, s);
    return 1;
}

int dbg_pc(lua_State* L)
{
    push_addr(L, need_dbg(L)->pc());
    return 1;
}

int dbg_reg(lua_State* L)
{
    debugger* d = need_dbg(L);
    std::string want = util::lower(luaL_checkstring(L, 1));
    for (const reg_value& r : d->registers())
        if (r.name == want) {
            push_addr(L, r.value);
            return 1;
        }
    lua_pushnil(L);
    return 1;
}

int dbg_regs(lua_State* L)
{
    debugger* d = need_dbg(L);
    lua_newtable(L);
    for (const reg_value& r : d->registers()) {
        push_addr(L, r.value);
        lua_setfield(L, -2, r.name.c_str());
    }
    return 1;
}

int dbg_read(lua_State* L)
{
    debugger* d = need_dbg(L);
    uint64_t a = check_addr(L, 1);
    lua_Integer n = luaL_checkinteger(L, 2);
    if (n < 0 || n > (1 << 20))
        return luaL_error(L, "read length out of range");
    std::string buf((size_t)n, '\0');
    buf.resize(d->read(a, &buf[0], (size_t)n));
    lua_pushlstring(L, buf.data(), buf.size());
    return 1;
}

int dbg_write(lua_State* L)
{
    debugger* d = need_dbg(L);
    uint64_t a = check_addr(L, 1);
    size_t n = 0;
    const char* data = luaL_checklstring(L, 2, &n);
    std::string err;
    if (!d->write(a, data, n, err)) {
        lua_pushboolean(L, false);
        lua_pushstring(L, err.c_str());
        return 2;
    }
    lua_pushboolean(L, true);
    return 1;
}

// simple actions share this shape: (fn)(err) -> ok, err
int dbg_action(lua_State* L, bool (debugger::*fn)(std::string&))
{
    debugger* d = need_dbg(L);
    std::string err;
    if (!(d->*fn)(err)) {
        lua_pushboolean(L, false);
        lua_pushstring(L, err.c_str());
        return 2;
    }
    lua_pushboolean(L, true);
    return 1;
}

int dbg_cont(lua_State* L) { return dbg_action(L, &debugger::cont); }
int dbg_step_into(lua_State* L) { return dbg_action(L, &debugger::step_into); }
int dbg_step_over(lua_State* L) { return dbg_action(L, &debugger::step_over); }
int dbg_pause(lua_State* L) { return dbg_action(L, &debugger::pause); }

int dbg_add_bp(lua_State* L)
{
    debugger* d = need_dbg(L);
    uint64_t a = check_addr(L, 1);
    std::string err;
    if (!d->add_bp(a, err)) {
        lua_pushboolean(L, false);
        lua_pushstring(L, err.c_str());
        return 2;
    }
    lua_pushboolean(L, true);
    return 1;
}

int dbg_del_bp(lua_State* L)
{
    lua_pushboolean(L, need_dbg(L)->del_bp(check_addr(L, 1)));
    return 1;
}

}

// ---- lua_host ----

lua_host::lua_host() = default;

lua_host::~lua_host()
{
    shutdown();
}

void lua_host::shutdown()
{
    if (L_) {
        lua_close(L_);
        L_ = nullptr;
    }
    commands_.clear();
    handlers_.clear();
}

void lua_host::log(const std::string& s, int level)
{
    if (bridge_.log)
        bridge_.log(s, level);
}

bool lua_host::check_deadline() const
{
    return !(deadline_ && os::now_ms() > deadline_);
}

static const luaL_Reg api_funcs[] = {
    {"log", api_log}, {"warn", api_warn}, {"file", api_file_info},
    {"read", api_read}, {"read_u8", api_read_u8}, {"read_u16", api_read_u16}, {"read_u32", api_read_u32},
    {"read_u64", api_read_u64}, {"read_i32", api_read_i32}, {"read_ptr", api_read_ptr}, {"read_cstr", api_read_cstr},
    {"is_mapped", api_is_mapped}, {"is_code", api_is_code},
    {"name", api_name}, {"location", api_location}, {"set_name", api_set_name}, {"resolve", api_resolve},
    {"comment", api_comment}, {"set_comment", api_set_comment},
    {"disasm", api_disasm}, {"next_addr", api_next_addr},
    {"functions", api_functions}, {"imports", api_imports}, {"exports", api_exports},
    {"strings", api_strings}, {"xrefs_to", api_xrefs_to}, {"find", api_find},
    {"here", api_here}, {"goto_addr", api_goto},
    {"register_command", api_register_command}, {"on", api_on},
    {nullptr, nullptr},
};

static const luaL_Reg dbg_funcs[] = {
    {"state", dbg_state_fn}, {"pc", dbg_pc}, {"reg", dbg_reg}, {"regs", dbg_regs},
    {"read", dbg_read}, {"write", dbg_write},
    {"cont", dbg_cont}, {"step_into", dbg_step_into}, {"step_over", dbg_step_over}, {"pause", dbg_pause},
    {"add_bp", dbg_add_bp}, {"del_bp", dbg_del_bp},
    {nullptr, nullptr},
};

void lua_host::open_api()
{
    lua_newtable(L_);
    luaL_setfuncs(L_, api_funcs, 0);

    lua_newtable(L_); // ceasta.dbg
    luaL_setfuncs(L_, dbg_funcs, 0);
    lua_setfield(L_, -2, "dbg");

    lua_pushstring(L_, CEASTA_LUA_VERSION);
    lua_setfield(L_, -2, "version");
    lua_setglobal(L_, "ceasta");

    // print() should go to the console/log, not stdout
    lua_pushcfunction(L_, api_log);
    lua_setglobal(L_, "print");
}

bool lua_host::init(const lua_bridge& bridge)
{
    shutdown();
    bridge_ = bridge;
    L_ = luaL_newstate();
    if (!L_)
        return false;
    *static_cast<lua_host**>(lua_getextraspace(L_)) = this;
    luaL_openlibs(L_);
    open_api();
    return true;
}

bool lua_host::call(int nargs, int nresults)
{
    // install the watchdog only at the top level call
    bool top = depth_ == 0;
    if (top) {
        deadline_ = timeout_ms > 0 ? os::now_ms() + (uint64_t)timeout_ms : 0;
        lua_sethook(L_, time_hook, LUA_MASKCOUNT, 100000);
    }
    depth_++;
    int rc = lua_pcall(L_, nargs, nresults, 0);
    depth_--;
    if (top)
        lua_sethook(L_, nullptr, 0, 0);
    if (rc != LUA_OK) {
        std::string err = lua_tostring(L_, -1) ? lua_tostring(L_, -1) : "error";
        lua_pop(L_, 1);
        log(err, 2);
        return false;
    }
    return true;
}

bool lua_host::run_string(const std::string& code, const std::string& chunk)
{
    if (!L_)
        return false;
    std::string name = "=" + chunk;
    if (luaL_loadbuffer(L_, code.data(), code.size(), name.c_str()) != LUA_OK) {
        std::string err = lua_tostring(L_, -1) ? lua_tostring(L_, -1) : "syntax error";
        lua_pop(L_, 1);
        log(err, 2);
        return false;
    }
    return call(0, 0);
}

bool lua_host::run_console(const std::string& code)
{
    if (!L_)
        return false;
    // try it as "return <expr>" first so the console prints values
    std::string expr = "return " + code;
    if (luaL_loadbuffer(L_, expr.data(), expr.size(), "=console") == LUA_OK) {
        int base = lua_gettop(L_) - 1;
        if (!call(0, LUA_MULTRET))
            return false;
        int n = lua_gettop(L_) - base;
        for (int i = 0; i < n; i++) {
            size_t len = 0;
            const char* s = luaL_tolstring(L_, base + 1 + i, &len);
            log(std::string(s, len), 0);
            lua_pop(L_, 1);
        }
        lua_settop(L_, base);
        return true;
    }
    lua_pop(L_, 1); // the failed "return ..." chunk
    return run_string(code, "console");
}

bool lua_host::run_file(const std::string& path)
{
    std::vector<uint8_t> bytes;
    std::string err;
    if (!os::read_file(path, bytes, err)) {
        log(err, 2);
        return false;
    }
    size_t slash = path.find_last_of("/\\");
    current_plugin_ = slash == std::string::npos ? path : path.substr(slash + 1);
    bool ok = run_string(std::string(bytes.begin(), bytes.end()), current_plugin_);
    current_plugin_.clear();
    return ok;
}

int lua_host::load_plugins(const std::vector<std::string>& dirs)
{
    dirs_ = dirs;
    return reload_plugins();
}

int lua_host::reload_plugins()
{
    // drop old commands / handlers and their registry refs
    for (const lua_command& c : commands_)
        luaL_unref(L_, LUA_REGISTRYINDEX, c.ref);
    for (const auto& h : handlers_)
        luaL_unref(L_, LUA_REGISTRYINDEX, h.second);
    commands_.clear();
    handlers_.clear();
    files_.clear();

    int ok = 0;
    for (const std::string& dir : dirs_) {
        for (const std::string& file : os::list_files(dir, ".lua")) {
            files_.push_back(file);
            if (run_file(file))
                ok++;
        }
    }
    std::sort(commands_.begin(), commands_.end(),
        [](const lua_command& a, const lua_command& b) { return a.name < b.name; });
    return ok;
}

void lua_host::add_command(const std::string& name, const std::string& help, int ref)
{
    for (lua_command& c : commands_)
        if (c.name == name) {
            luaL_unref(L_, LUA_REGISTRYINDEX, c.ref);
            c.help = help;
            c.ref = ref;
            c.plugin = current_plugin_;
            return;
        }
    commands_.push_back({name, help, current_plugin_, ref});
}

void lua_host::add_handler(const std::string& event, int ref)
{
    handlers_.push_back({event, ref});
}

bool lua_host::run_command(size_t index)
{
    if (index >= commands_.size())
        return false;
    lua_rawgeti(L_, LUA_REGISTRYINDEX, commands_[index].ref);
    return call(0, 0);
}

bool lua_host::run_command(const std::string& name)
{
    for (size_t i = 0; i < commands_.size(); i++)
        if (commands_[i].name == name)
            return run_command(i);
    log("no such command: " + name, 2);
    return false;
}

void lua_host::fire(const std::string& event, int64_t arg)
{
    if (!L_)
        return;
    for (const auto& h : handlers_) {
        if (h.first != event)
            continue;
        lua_rawgeti(L_, LUA_REGISTRYINDEX, h.second);
        lua_pushinteger(L_, (lua_Integer)arg);
        call(1, 0);
    }
}
