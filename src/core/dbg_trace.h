#pragma once
#include <cstdint>
#include <functional>
#include <string>

class debugger;

// single-step the stopped target for up to max_insns instructions, calling back with the target
// of every indirect call / jump it executes (the target an indirect branch resolved to, which
// the static analysis can't see). runtime addresses. stops early at a breakpoint or on exit.
// returns how many instructions were stepped. built on the public debugger api, so it works
// wherever the debugger does.
int dbg_trace(debugger& d, int max_insns,
              const std::function<void(uint64_t from, uint64_t to, bool is_call)>& on_indirect,
              std::string& err);
