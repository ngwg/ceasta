// the parts of the debugger every backend shares: recording steps so they can be undone
#include "core/debugger.h"
#include "core/disasm.h"
#include <deque>

struct step_history {
    uint32_t pid = 0;
    std::vector<std::string> names; // register names, in the order each record keeps values
    struct record {
        uint32_t tid = 0;
        bool barrier = false; // the step ran code that isn't recorded: can't go back past it
        std::vector<uint64_t> regs;
        std::vector<std::pair<uint64_t, std::vector<uint8_t>>> mem; // the bytes it overwrote
    };
    std::deque<record> steps;
    size_t bytes = 0;
    size_t undoable = 0; // records at the end with no barrier among them

    void push(record r)
    {
        undoable = r.barrier ? 0 : undoable + 1;
        for (const auto& m : r.mem)
            bytes += m.second.size();
        steps.push_back(std::move(r));
    }
    void pop_back()
    {
        const record& r = steps.back();
        for (const auto& m : r.mem)
            bytes -= m.second.size();
        bool barrier = r.barrier;
        steps.pop_back();
        if (!barrier) {
            undoable--;
        } else { // count again from the new end
            undoable = 0;
            for (auto it = steps.rbegin(); it != steps.rend() && !it->barrier; ++it)
                undoable++;
        }
    }
    void pop_front()
    {
        for (const auto& m : steps.front().mem)
            bytes -= m.second.size();
        steps.pop_front();
        if (undoable > steps.size())
            undoable = steps.size();
    }
    void clear()
    {
        steps.clear();
        bytes = 0;
        undoable = 0;
    }
};

namespace {

const size_t max_steps = 100000;
const size_t max_bytes = 64u << 20;

// the history belongs to one process; another one (or none) starts it over
step_history& history(std::shared_ptr<step_history>& h, uint32_t pid)
{
    if (!h)
        h = std::make_shared<step_history>();
    if (h->pid != pid) {
        *h = step_history();
        h->pid = pid;
    }
    return *h;
}

} // namespace

void debugger::record_step(bool over)
{
    std::vector<reg_value> regs = registers();
    if (regs.empty())
        return;
    step_history& h = history(hist_, pid());
    if (h.names.empty() || h.names.size() != regs.size()) {
        h.clear();
        h.names.clear();
        for (const reg_value& r : regs)
            h.names.push_back(r.name);
    }
    step_history::record rec;
    rec.tid = tid();
    for (const reg_value& r : regs)
        rec.regs.push_back(r.value);

    uint64_t at = pc();
    uint8_t buf[16];
    size_t n = read(at, buf, sizeof(buf));
    disassembler dis;
    insn in;
    if (!n || !dis.open(is64() ? bin_arch::x64 : bin_arch::x86) || !dis.decode(buf, n, at, in)) {
        rec.barrier = true;
    } else if (over && in.kind == flow::call) {
        rec.barrier = true; // the whole call runs at full speed
    } else {
        auto value = [&](const char* name, uint64_t& v) {
            for (const reg_value& r : regs)
                if (r.name == name) {
                    v = r.value;
                    return true;
                }
            return false;
        };
        std::vector<disassembler::mem_write> w;
        if (!dis.writes(buf, n, at, value, w)) {
            rec.barrier = true;
        } else {
            for (const disassembler::mem_write& m : w) {
                std::vector<uint8_t> old(m.size);
                // memory that can't be read can't be written either: the instruction faults
                if (read(m.addr, old.data(), m.size) != m.size)
                    continue;
                rec.mem.push_back({m.addr, std::move(old)});
            }
        }
    }
    h.push(std::move(rec));
    while (h.steps.size() > max_steps || h.bytes > max_bytes)
        h.pop_front();
}

void debugger::forget_steps()
{
    if (hist_)
        hist_->clear();
}

bool debugger::step_into(std::string& err)
{
    bool record = state() == dbg_state::stopped;
    if (record)
        record_step(false);
    if (raw_step_into(err))
        return true;
    if (record && hist_ && !hist_->steps.empty()) // it didn't happen
        hist_->pop_back();
    return false;
}

bool debugger::step_over(std::string& err)
{
    bool record = state() == dbg_state::stopped;
    if (record)
        record_step(true);
    if (raw_step_over(err))
        return true;
    if (record && hist_ && !hist_->steps.empty())
        hist_->pop_back();
    return false;
}

bool debugger::cont(std::string& err)
{
    forget_steps();
    return raw_cont(err);
}

bool debugger::run_to(uint64_t addr, std::string& err)
{
    forget_steps();
    return raw_run_to(addr, err);
}

bool debugger::call(uint64_t func, const std::vector<uint64_t>& args, uint64_t& result, std::string& err)
{
    forget_steps(); // the function's writes aren't recorded
    return raw_call(func, args, result, err);
}

size_t debugger::steps_recorded() const
{
    if (!hist_ || hist_->pid != pid() || state() == dbg_state::none)
        return 0;
    return hist_->undoable;
}

bool debugger::step_back(std::string& err)
{
    if (state() != dbg_state::stopped) {
        err = "the program isn't stopped";
        return false;
    }
    if (!hist_ || hist_->pid != pid() || hist_->steps.empty()) {
        err = "nothing to go back to - only steps (f7 / f8) are recorded, and continuing starts over";
        return false;
    }
    step_history& h = *hist_;
    step_history::record& rec = h.steps.back();
    if (rec.barrier) {
        err = "can't go back past this step: it ran code that wasn't recorded (a call stepped over, a system call)";
        return false;
    }
    if (rec.tid != tid()) {
        err = "the last recorded step ran on another thread";
        return false;
    }
    // the memory it wrote, then the registers that changed
    for (auto it = rec.mem.rbegin(); it != rec.mem.rend(); ++it)
        if (!write(it->first, it->second.data(), it->second.size(), err))
            return false;
    std::vector<reg_value> now = registers();
    for (size_t i = 0; i < rec.regs.size() && i < h.names.size(); i++) {
        if (i < now.size() && now[i].name == h.names[i] && now[i].value == rec.regs[i])
            continue;
        if (!set_register(h.names[i], rec.regs[i], err))
            return false;
    }
    h.pop_back();
    return true;
}

bool debugger::about_to_return() const
{
    if (state() != dbg_state::stopped)
        return false;
    uint8_t buf[16];
    size_t n = read(pc(), buf, sizeof(buf));
    disassembler dis;
    insn in;
    return n && dis.open(is64() ? bin_arch::x64 : bin_arch::x86) && dis.decode(buf, n, pc(), in) && in.kind == flow::ret;
}
