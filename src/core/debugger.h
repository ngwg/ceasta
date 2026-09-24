#pragma once
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

// user mode debugger. windows only (win32 debug api), other systems get a stub that
// reports it isn't supported. everything runs on the calling (ui) thread: call poll() often.
// all addresses here are runtime addresses, the app maps them to/from the static listing.

enum class dbg_state { none, running, stopped };

struct reg_value {
    std::string name;
    uint64_t value = 0;
};

struct dbg_module {
    std::string name;
    std::string path;
    uint64_t base = 0;
    uint64_t size = 0;
};

struct dbg_thread {
    uint32_t id = 0;
    uint64_t pc = 0;
};

class debugger {
public:
    debugger();
    ~debugger();
    debugger(const debugger&) = delete;
    debugger& operator=(const debugger&) = delete;

    static bool supported();

    // starts exe under the debugger. args = command line after the exe, cwd may be empty
    bool start(const std::string& exe, const std::string& args, const std::string& cwd, std::string& err);
    bool attach(uint32_t pid, std::string& err);
    void detach();
    void kill();
    // handles pending debug events, waits up to timeout_ms for one while running
    void poll(uint32_t timeout_ms = 0);

    dbg_state state() const;
    bool cont(std::string& err);
    bool step_into(std::string& err);
    bool step_over(std::string& err);   // runs calls to their return address
    bool run_to(uint64_t addr, std::string& err);
    bool pause(std::string& err);

    bool add_bp(uint64_t addr, std::string& err);
    bool del_bp(uint64_t addr);
    bool has_bp(uint64_t addr) const;
    std::vector<uint64_t> bps() const;

    uint64_t pc() const;
    uint64_t sp() const;
    std::vector<reg_value> registers() const;
    bool set_register(const std::string& name, uint64_t value, std::string& err);
    // live memory, our breakpoint bytes are hidden
    size_t read(uint64_t addr, void* out, size_t n) const;
    bool write(uint64_t addr, const void* in, size_t n, std::string& err);

    bool is64() const;
    uint64_t image_base() const;    // runtime base of the main module
    uint32_t pid() const;
    uint32_t tid() const;
    int exit_code() const;
    std::string stop_reason() const;
    std::vector<dbg_module> modules() const;
    std::vector<dbg_thread> threads() const;
    bool select_thread(uint32_t tid);

    bool break_on_entry = true;
    std::function<void(const std::string&)> on_log;
    std::function<void()> on_created;   // process is mapped, a good time to set breakpoints
    std::function<void()> on_stop;
    std::function<void(int)> on_exit;

    struct impl;

private:
    std::unique_ptr<impl> d;
};

// processes for the attach dialog (windows only, empty elsewhere)
struct process_info {
    uint32_t pid = 0;
    std::string name;
};
std::vector<process_info> list_processes();
