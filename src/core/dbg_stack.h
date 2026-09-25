#pragma once
#include <cstdint>
#include <functional>
#include <vector>

class debugger;

// how the stopped thread got here. frame 0 is the pc; every frame after it is a return address
// found on the stack. x64 code seldom keeps a frame pointer, so the stack is read slot by slot
// for values that point into executable memory just past a call instruction, the guess a
// debugger makes without unwind tables. func_start (optional) gives the start of the function
// an address is in, 0 when unknown: a direct call has to go to the function the frame below is
// in, which drops stale return addresses that locals left behind. runtime addresses.
struct stack_frame {
    uint64_t pc = 0;   // the pc (frame 0) or the return address
    uint64_t slot = 0; // where on the stack the return address is (0 for frame 0)
    uint64_t call = 0; // the call instruction just before the return address (0 for frame 0)
};

std::vector<stack_frame> dbg_call_stack(debugger& d, int max_frames = 64,
                                        const std::function<uint64_t(uint64_t)>& func_start = nullptr);
