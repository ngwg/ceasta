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
    unsigned id = 0;            // capstone x86_insn id (arm64_insn when arm is set)
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

    // arm64. registers are numbered for the fields below: x0..x30 (and w0..w30) are 0..30, sp 31
    bool arm = false;
    bool has_page = false;      // adrp: reg0 gets the 4 KB page "page"
    uint64_t page = 0;
    unsigned reg2 = 0;          // third register operand (add x0, x1, w2, sxtw #2)
    uint8_t ext = 0;            // how that last register operand is extended (a64_ext), and shifted
    uint8_t shift = 0;
    bool mem_signed = false;    // the load sign-extends (ldrsb, ldrsh, ldrsw)
    bool sets_flags = false;    // cmp, adds, ...: the condition flags change
    uint8_t nwr = 0;            // general registers it writes, by number
    uint8_t wr[3] = {};

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
    bool decode_arm64(const uint8_t* buf, size_t n, uint64_t addr, insn& out);
    size_t handle_ = 0;        // csh
    void* scratch_ = nullptr;  // cs_insn from cs_malloc
    bin_arch arch_ = bin_arch::x64;
};

// arm64 register extends, for insn::ext
enum a64_ext : uint8_t { a64_none, a64_lsl, a64_uxtb, a64_uxth, a64_uxtw, a64_uxtx, a64_sxtb, a64_sxth, a64_sxtw, a64_sxtx };

// register ids the analysis needs without including capstone everywhere
namespace regs {
unsigned rip();
unsigned eip();
unsigned ebx();
bool same_reg(unsigned a, unsigned b); // eax vs rax etc count as the same register
// arm64: the number of a general register (w5 and x5 are 5, sp is 31), -1 for anything else
int a64_num(unsigned reg);
}

namespace ins {
// any architecture
bool is_nop(const insn& in);
bool is_endbr(const insn& in);   // endbr64 / endbr32, bti on arm64: a landing pad that does nothing
// rare in compiled code, common when data gets decoded as code (port io, bcd, far jumps, ...)
bool is_suspicious(const insn& in);
// x86 only
bool is_movsxd(const insn& in);
bool is_move(const insn& in); // mov, movsxd, movzx, movsx
bool is_add(const insn& in);
bool is_cmp(const insn& in);
bool is_ja(const insn& in);
bool is_jae(const insn& in);
bool is_push(const insn& in);
// arm64 only
bool a64_adrp(const insn& in);
bool a64_add_imm(const insn& in);   // add xd, xn, #imm
bool a64_add_reg(const insn& in);   // add xd, xn, xm (maybe extended / shifted)
bool a64_mov_reg(const insn& in);   // mov xd, xn
bool a64_cmp_imm(const insn& in);   // cmp wn, #imm
bool a64_bhi(const insn& in);       // b.hi: unsigned greater
bool a64_bhs(const insn& in);       // b.hs / b.cs: unsigned greater or equal
bool a64_bls(const insn& in);       // b.ls: unsigned lower or same
bool a64_blo(const insn& in);       // b.lo / b.cc: unsigned lower
bool a64_prologue(uint32_t word);   // stp x29, x30, [sp, #-n]! / sub sp, sp, #n / paciasp / bti c
bool a64_gap_before(uint32_t word); // ret, b, br, nop, brk, zero: what comes before a function
}
