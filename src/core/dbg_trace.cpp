#include "core/dbg_trace.h"

#include "core/debugger.h"
#include "core/disasm.h"
#include "core/os.h"

int dbg_trace(debugger& d, int max_insns,
              const std::function<void(uint64_t from, uint64_t to, bool is_call)>& on_indirect, std::string& err)
{
    disassembler dis;
    if (!dis.open(d.is64() ? bin_arch::x64 : bin_arch::x86)) {
        err = "can't open the disassembler";
        return 0;
    }
    int n = 0;
    for (; n < max_insns && d.state() == dbg_state::stopped; n++) {
        uint64_t pc = d.pc();
        uint8_t buf[16];
        size_t got = d.read(pc, buf, sizeof(buf));
        insn in;
        bool indirect = got && dis.decode(buf, got, pc, in) && in.indirect &&
                        (in.kind == flow::call || in.kind == flow::jump);
        bool is_call = indirect && in.kind == flow::call;

        if (!d.step_into(err))
            return n;
        // the step runs on the debugger's own thread; wait for it to come back to a stop
        uint64_t until = os::now_ms() + 5000;
        while (d.state() == dbg_state::running && os::now_ms() < until)
            d.poll(20);
        if (d.state() != dbg_state::stopped)
            return n + 1; // exited, or a breakpoint / signal ended the step

        if (indirect) {
            uint64_t to = d.pc(); // stepping into the branch lands on its resolved target
            if (to != pc + in.size) // ignore a not-taken conditional (shouldn't happen for jmp/call)
                on_indirect(pc, to, is_call);
        }
    }
    return n;
}
