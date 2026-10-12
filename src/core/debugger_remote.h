#pragma once
#include "core/debugger.h"

#ifdef CEASTA_LINUX_DEBUGGER

#include <cstdint>
#include <string>
#include <vector>

// the qemu-user backend of the linux debugger: the program is a mips executable, so the
// debugger runs it under qemu-mipsel and talks the gdb remote serial protocol to its stub
// (-g port). the guest's registers, memory and breakpoints come through the protocol; the
// qemu process itself is just a host container. everything lives in debugger_remote.cpp.

struct remote_state;

namespace remote {

bool available(); // is there a qemu mips emulator on PATH?
bool start(remote_state*& r, const std::string& exe, const std::string& args, const std::string& cwd,
    bool break_on_entry, const std::function<void(const std::string&)>& log, std::string& err);
void destroy(remote_state* r);

void poll(remote_state* r, uint32_t timeout_ms);
dbg_state state(remote_state* r);
bool cont(remote_state* r, bool step, std::string& err);
bool step_over(remote_state* r, std::string& err);
bool run_to(remote_state* r, uint64_t addr, std::string& err);
bool pause(remote_state* r, std::string& err);
bool set_bp(remote_state* r, uint64_t addr, bool on, std::string& err);
bool has_bp(remote_state* r, uint64_t addr);
std::vector<uint64_t> bps(remote_state* r);
bool read(remote_state* r, uint64_t addr, void* out, size_t n);
bool write(remote_state* r, uint64_t addr, const void* in, size_t n);
std::vector<reg_value> registers(remote_state* r);
bool set_register(remote_state* r, const std::string& name, uint64_t v, std::string& err);
uint64_t pc(remote_state* r);
uint64_t image_base(remote_state* r);
uint32_t pid(remote_state* r);
int exit_code(remote_state* r);
std::string stop_reason(remote_state* r);
std::vector<dbg_region> regions(remote_state* r);
std::vector<dbg_module> modules(remote_state* r);
bool apply_watches(remote_state* r, const std::vector<debugger::watch>& watches, std::string& err);

} // namespace remote

#endif
