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

    // going back: every step_into / step_over first notes the registers and the memory the
    // instruction is about to write, and step_back puts them back, one step at a time. code that
    // runs without being stepped (continue, run to, call, a call stepped over, a system call)
    // isn't recorded, so going back stops there. the thread's own writes only
    bool step_back(std::string& err);
    size_t steps_recorded() const; // how many steps step_back can undo from here
    // the instruction at the pc returns from the function (step out stops after it)
    bool about_to_return() const;

    // watchpoints: the cpu stops the program right after an instruction writes memory in the
    // watched range (or reads or writes it, with access). up to 4, each 1, 2, 4 or 8 bytes and
    // aligned to its size. runtime addresses, for this process (they go when it ends); every
    // thread is watched. the stop reason starts with "watchpoint"
    struct watch {
        uint64_t addr = 0;
        int size = 0;
        bool access = false;
    };
    bool add_watch(uint64_t addr, int size, bool access, std::string& err);
    bool del_watch(uint64_t addr);
    std::vector<watch> watches() const;

    bool add_bp(uint64_t addr, std::string& err);
    bool del_bp(uint64_t addr);
    bool has_bp(uint64_t addr) const;
    std::vector<uint64_t> bps() const;

    uint64_t pc() const;
    uint64_t sp() const;
    // call a function in the stopped target: set the arguments per the abi, run it, return its
    // result (rax), then restore every register. 64-bit targets only. args are raw values;
    // write a string into memory first and pass its address. our breakpoints are lifted for the
    // duration, and a fault or breakpoint inside the call is an error (registers still restored).
    bool call(uint64_t func, const std::vector<uint64_t>& args, uint64_t& result, std::string& err);
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
    // the backends' own run / step / call; the public ones record steps around them
    bool raw_cont(std::string& err);
    bool raw_step_into(std::string& err);
    bool raw_step_over(std::string& err);
    bool raw_run_to(uint64_t addr, std::string& err);
    bool raw_call(uint64_t func, const std::vector<uint64_t>& args, uint64_t& result, std::string& err);
    void record_step(bool over);
    void forget_steps();
    // watchpoints: the list for the current process, dr7 for it, and the backend's write to the
    // threads' debug registers
    std::vector<watch> active_watches() const;
    static uint64_t watch_dr7(const std::vector<watch>& w);
    static std::string watch_text(const watch& w); // the stop reason
    bool apply_watches(std::string& err);
    std::vector<watch> watch_list_;
    uint32_t watch_pid_ = 0;

    std::unique_ptr<impl> d;
    std::shared_ptr<struct step_history> hist_;
};

// processes for the attach dialog (windows only, empty elsewhere)
struct process_info {
    uint32_t pid = 0;
    std::string name;
};
std::vector<process_info> list_processes();
