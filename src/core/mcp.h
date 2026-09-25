#pragma once
#include "core/json.h"
#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

// model context protocol server: lets an ai client (claude code, claude desktop, cursor, ...)
// read the loaded file, decompile, rename, comment - and, when allowed, run the program under
// the debugger. transport-free: feed it json-rpc messages (stdio or http, see mcp_http.h).

class database;
class debugger;
class lua_host;

// the debugger as the tools see it. the cli and the gui each fill one in. every call happens
// on the thread that owns the debugger. addresses are static (the listing's) unless it says
// runtime.
struct mcp_debug_link {
    std::function<debugger*()> get;                                         // null: no debugger
    std::function<bool(const std::string& args, std::string& err)> start;  // stops at the entry point
    std::function<bool(std::string& err)> cont, step_into, step_over, pause;
    std::function<bool(uint64_t addr, std::string& err)> run_to;
    std::function<void()> kill;
    std::function<bool(uint64_t addr, std::string& err)> add_bp;
    std::function<bool(uint64_t addr)> del_bp;
    std::function<std::vector<uint64_t>()> bps;
    std::function<uint64_t(uint64_t)> to_runtime;
    std::function<bool(uint64_t runtime, uint64_t& out)> to_static; // false outside the image
    std::function<void()> pump; // handle pending debug events (the cli polls here, the gui every frame)
};

struct mcp_options {
    bool allow_debug = false; // tools that run the program and change its state
    bool allow_lua = false;   // run_lua runs any code, with file and os access
    // write each rename / comment to disk right away (the cli server has no save of its own).
    // the gui turns it off: there the ai's edits wait for the user's save, like their own
    bool autosave = true;
};

class mcp_server {
public:
    mcp_options opts;
    std::function<database*()> get_db;
    mcp_debug_link debug;               // used when opts.allow_debug
    std::function<lua_host*()> get_lua; // used when opts.allow_lua
    // runs fn on the thread that owns the database / debugger and waits for it. unset: here
    std::function<void(const std::function<void()>&)> on_owner;
    std::function<void(const std::string&)> on_activity; // a line per tool call, for a log
    std::function<void()> on_changed;                    // names, comments or breakpoints changed
    // set while the host shuts the server down: owner-thread work is skipped and waits end, so
    // a request in flight finishes quickly (with an error)
    std::atomic<bool> stopping{false};

    // one json-rpc message (or a batch) in, the reply out; "" when nothing goes back
    std::string handle(const std::string& message);

    struct tool {
        using run_t = std::function<bool(mcp_server&, const json::value& args, std::string& out)>;
        std::string name;
        std::string description;
        json::value schema;   // json schema of the arguments
        bool debug = false;   // needs allow_debug
        bool lua = false;     // needs allow_lua
        bool writes = false;  // changes the project or the program
        bool owner = true;    // the handler runs on the owner thread as a whole
        run_t run;
    };
    std::vector<const tool*> tools() const; // the ones these options enable

    // helpers for the tools
    void run(const std::function<void()>& fn);
    bool wait_stop(int timeout_ms); // true when the debuggee stopped or ended in time

private:
    json::value dispatch(const json::value& msg);
    json::value call_tool(const json::value& params, std::string& activity);
    std::string negotiated_ = "2025-06-18";
};

// every tool the server knows (the enabled subset is what tools/list shows)
const std::vector<mcp_server::tool>& mcp_all_tools();
