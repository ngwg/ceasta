#pragma once
#include "core/binary.h"
#include <cstddef>
#include <cstdint>
#include <functional>
#include <vector>

// thin wrapper over capstone. not thread safe, use one per thread.

enum class flow : uint8_t {
    normal,  // falls through to the next instruction
    jump,    // unconditional jump
    cond,    // conditional jump, also falls through
    call,    // call, falls through
    ret,     // ret / iret
    stop,    // hlt, ud2, int3, int 29h. no fall through
};

struct insn {
    uint64_t addr = 0;
    uint8_t size = 0;
    uint8_t bytes[16] = {};
    unsigned id = 0;            // capstone x86_insn id
    char mnem[32] = {};
    char ops[160] = {};
    flow kind = flow::normal;
    bool indirect = false;      // branch through a register or memory
    bool has_target = false;    // direct branch target
    uint64_t target = 0;
    bool has_mem = false;       // memory operand with a known address (rip relative or absolute)
    uint64_t mem = 0;
    uint8_t mem_size = 0;
    bool mem_rip = false;
    bool is_lea = false;        // mem is an address, not an access
    bool mem_write = false;     // the memory operand is written
    bool has_imm = false;       // non branch immediate operand
    uint64_t imm = 0;
    // raw memory operand parts, used for jump tables and got relative plt stubs
    bool has_mem_op = false;
    unsigned mem_base = 0, mem_index = 0;
    int mem_scale = 0;
    int64_t mem_disp = 0;
    unsigned reg0 = 0, reg1 = 0; // first two register operands

    bool is_branch() const { return kind == flow::jump || kind == flow::cond || kind == flow::call; }
    uint64_t next() const { return addr + size; }
};

class disassembler {
public:
    disassembler() = default;
    ~disassembler();
    disassembler(const disassembler&) = delete;
    disassembler& operator=(const disassembler&) = delete;

    bool open(bin_arch arch);
    bool ok() const { return handle_ != 0; }
    bin_arch arch() const { return arch_; }
    // decodes one instruction from buf (n bytes available) that lives at addr
    bool decode(const uint8_t* buf, size_t n, uint64_t addr, insn& out);
    bool decode(const binary& b, uint64_t addr, insn& out);
    const char* reg_name(unsigned reg) const;

    // the memory the instruction in buf writes when it runs, worked out from its operands and
    // the registers' current values (reg gives one by name: "rdi", "esp", "eflags", ...). false
    // when that can't be known ahead: a system call, an fs / gs relative write, a string write
    // longer than 1 MB, ...
    struct mem_write {
        uint64_t addr;
        uint32_t size;
    };
    bool writes(const uint8_t* buf, size_t n, uint64_t addr,
        const std::function<bool(const char* reg, uint64_t& value)>& reg, std::vector<mem_write>& out);

private:
    void close();
    size_t handle_ = 0;        // csh
    void* scratch_ = nullptr;  // cs_insn from cs_malloc
    bin_arch arch_ = bin_arch::x64;
};

// register ids the analysis needs without including capstone everywhere
namespace regs {
unsigned rip();
unsigned eip();
unsigned ebx();
bool same_reg(unsigned a, unsigned b); // eax vs rax etc count as the same register
}

namespace ins {
bool is_nop(unsigned id);
bool is_endbr(unsigned id);
bool is_movsxd(unsigned id);
bool is_move(unsigned id); // mov, movsxd, movzx, movsx
bool is_add(unsigned id);
bool is_cmp(unsigned id);
bool is_ja(unsigned id);
bool is_jae(unsigned id);
bool is_push(unsigned id);
// rare in compiled code, common when data gets decoded as code (port io, bcd, far jumps, ...)
bool is_suspicious(unsigned id);
}
