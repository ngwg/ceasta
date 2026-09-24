#pragma once
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

// runs lua plugins and the console. plugins talk to the app through the ceasta.* api.
// main thread only.

class database;
class debugger;
struct lua_State;

// what plugins can reach, filled in by the app (or the cli)
struct lua_bridge {
    database* db = nullptr;
    debugger* dbg = nullptr;
    std::function<void(const std::string&, int)> log; // level 0 info, 1 warning, 2 error
    std::function<uint64_t()> here;                    // cursor address
    std::function<void(uint64_t)> jump;                // move the cursor
    std::function<uint64_t(uint64_t)> to_runtime;      // static -> debuggee address
    std::function<uint64_t(uint64_t)> to_static;       // debuggee -> static address
};

struct lua_command {
    std::string name;
    std::string help;
    std::string plugin;
    int ref = 0;
};

class lua_host {
public:
    lua_host();
    ~lua_host();
    lua_host(const lua_host&) = delete;
    lua_host& operator=(const lua_host&) = delete;

    bool init(const lua_bridge& bridge);
    void shutdown();
    lua_bridge& bridge() { return bridge_; }

    // loads every .lua file in the folders, returns how many loaded without errors
    int load_plugins(const std::vector<std::string>& dirs);
    int reload_plugins();
    const std::vector<std::string>& plugin_files() const { return files_; }
    const std::vector<lua_command>& commands() const { return commands_; }
    bool run_command(size_t index);
    bool run_command(const std::string& name);

    // console input: expressions print their value, statements just run
    bool run_console(const std::string& code);
    bool run_string(const std::string& code, const std::string& chunk_name);
    bool run_file(const std::string& path);

    // "load" (analysis done), "stop" (debugger stopped, arg = static pc), "exit" (arg = exit code)
    void fire(const std::string& event, int64_t arg = 0);

    int timeout_ms = 30000;

    // used by the api functions
    void log(const std::string& s, int level = 0);
    void add_command(const std::string& name, const std::string& help, int ref);
    void add_handler(const std::string& event, int ref);
    bool check_deadline() const;

private:
    bool call(int nargs, int nresults);
    void open_api();

    lua_State* L_ = nullptr;
    lua_bridge bridge_;
    std::vector<std::string> dirs_;
    std::vector<std::string> files_;
    std::vector<lua_command> commands_;
    std::vector<std::pair<std::string, int>> handlers_;
    std::string current_plugin_;
    uint64_t deadline_ = 0;
    int depth_ = 0;
};
