#include "core/bp_cond.h"
#include "core/debugger.h"
#include "core/util.h"

// lua is compiled as c++ (see CMakeLists.txt): no extern "C"
#include "lauxlib.h"
#include "lua.h"
#include "lualib.h"

namespace {

debugger* dbg_of(lua_State* L) { return (debugger*)lua_touserdata(L, lua_upvalueindex(1)); }

// u8(addr) .. u64(addr): read the program's memory; nil when it can't be read
template <typename T>
int read_n(lua_State* L)
{
    debugger* d = dbg_of(L);
    uint64_t a = (uint64_t)luaL_checkinteger(L, 1);
    T v = 0;
    if (!d || d->read(a, &v, sizeof(v)) != sizeof(v)) {
        lua_pushnil(L);
        return 1;
    }
    lua_pushinteger(L, (lua_Integer)v);
    return 1;
}

// str(addr [, max]) / wstr(addr [, max]): a nul terminated string (utf-16 read as ascii)
int read_str(lua_State* L, bool wide)
{
    debugger* d = dbg_of(L);
    uint64_t a = (uint64_t)luaL_checkinteger(L, 1);
    lua_Integer max = luaL_optinteger(L, 2, 256);
    std::string out;
    for (lua_Integer i = 0; d && i < max && i < 4096; i++) {
        uint16_t c = 0;
        if (d->read(a + (uint64_t)(i * (wide ? 2 : 1)), &c, wide ? 2 : 1) != (size_t)(wide ? 2 : 1) || c == 0)
            break;
        out += (char)(c < 256 ? c : '?');
    }
    lua_pushlstring(L, out.data(), out.size());
    return 1;
}
int read_str8(lua_State* L) { return read_str(L, false); }
int read_str16(lua_State* L) { return read_str(L, true); }

// a condition gets a million lua instructions, then it's stopped
void count_hook(lua_State* L, lua_Debug*) { luaL_error(L, "the condition took too long"); }

} // namespace

bp_conditions::bp_conditions()
{
    L_ = luaL_newstate();
    if (!L_)
        return;
    // only what a condition needs: math and string, nothing that reaches files or the os
    luaL_requiref(L_, "math", luaopen_math, 1);
    luaL_requiref(L_, "string", luaopen_string, 1);
    lua_pop(L_, 2);
}

bp_conditions::~bp_conditions()
{
    if (L_)
        lua_close(L_);
}

bool bp_conditions::valid(const std::string& expr, std::string& err)
{
    if (!L_) {
        err = "no lua";
        return false;
    }
    std::string code = "return (" + expr + ")";
    if (luaL_loadbufferx(L_, code.data(), code.size(), "=condition", "t") != LUA_OK) {
        const char* m = lua_tostring(L_, -1);
        err = m ? m : "bad expression";
        lua_pop(L_, 1);
        return false;
    }
    lua_pop(L_, 1);
    return true;
}

bool bp_conditions::check(debugger& d, const std::string& expr, int hits, std::string& err)
{
    if (!L_ || util::trim(expr).empty())
        return true;
    auto it = compiled_.find(expr);
    if (it == compiled_.end()) {
        std::string code = "return (" + expr + ")";
        if (luaL_loadbufferx(L_, code.data(), code.size(), "=condition", "t") != LUA_OK) {
            const char* m = lua_tostring(L_, -1);
            err = m ? m : "bad expression";
            lua_pop(L_, 1);
            return true;
        }
        it = compiled_.emplace(expr, luaL_ref(L_, LUA_REGISTRYINDEX)).first;
    }
    lua_rawgeti(L_, LUA_REGISTRYINDEX, it->second);

    // the environment it sees: the registers right now, and a few readers
    lua_newtable(L_);
    static const struct {
        const char* full;
        const char* low32;
    } views[] = {
        {"rax", "eax"}, {"rbx", "ebx"}, {"rcx", "ecx"}, {"rdx", "edx"}, {"rsi", "esi"}, {"rdi", "edi"},
        {"rbp", "ebp"}, {"rsp", "esp"}, {"r8", "r8d"}, {"r9", "r9d"}, {"r10", "r10d"}, {"r11", "r11d"},
        {"r12", "r12d"}, {"r13", "r13d"}, {"r14", "r14d"}, {"r15", "r15d"},
    };
    for (const reg_value& r : d.registers()) {
        lua_pushinteger(L_, (lua_Integer)r.value);
        lua_setfield(L_, -2, r.name.c_str());
        for (const auto& v : views)
            if (r.name == v.full) {
                lua_pushinteger(L_, (lua_Integer)(r.value & 0xffffffffull));
                lua_setfield(L_, -2, v.low32);
            }
    }
    lua_pushinteger(L_, (lua_Integer)d.pc());
    lua_setfield(L_, -2, "pc");
    lua_pushinteger(L_, (lua_Integer)d.sp());
    lua_setfield(L_, -2, "sp");
    lua_pushinteger(L_, hits);
    lua_setfield(L_, -2, "hits");
    static const struct {
        const char* name;
        lua_CFunction fn;
    } readers[] = {
        {"u8", read_n<uint8_t>}, {"u16", read_n<uint16_t>}, {"u32", read_n<uint32_t>}, {"u64", read_n<uint64_t>},
        {"str", read_str8}, {"wstr", read_str16},
    };
    for (const auto& r : readers) {
        lua_pushlightuserdata(L_, &d);
        lua_pushcclosure(L_, r.fn, 1);
        lua_setfield(L_, -2, r.name);
    }
    lua_getglobal(L_, "math");
    lua_setfield(L_, -2, "math");
    lua_getglobal(L_, "string");
    lua_setfield(L_, -2, "string");
    if (!lua_setupvalue(L_, -2, 1)) // it becomes the expression's _ENV
        lua_pop(L_, 1);

    lua_sethook(L_, count_hook, LUA_MASKCOUNT, 1000000);
    int rc = lua_pcall(L_, 0, 1, 0);
    lua_sethook(L_, nullptr, 0, 0);
    if (rc != LUA_OK) {
        const char* m = lua_tostring(L_, -1);
        err = m ? m : "the condition failed";
        lua_pop(L_, 1);
        return true;
    }
    bool stop = lua_toboolean(L_, -1) != 0;
    lua_pop(L_, 1);
    return stop;
}
