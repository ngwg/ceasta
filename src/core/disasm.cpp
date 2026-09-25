#include "core/disasm.h"
#include <capstone/capstone.h>
#include <algorithm>
#include <cstdio>
#include <cstring>

disassembler::~disassembler()
{
    close();
}

void disassembler::close()
{
    if (scratch_) {
        cs_free((cs_insn*)scratch_, 1);
        scratch_ = nullptr;
    }
    if (handle_) {
        csh h = (csh)handle_;
        cs_close(&h);
        handle_ = 0;
    }
}

bool disassembler::open(bin_arch arch)
{
    close();
    csh h = 0;
    if (cs_open(CS_ARCH_X86, arch == bin_arch::x64 ? CS_MODE_64 : CS_MODE_32, &h) != CS_ERR_OK)
        return false;
    cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
    scratch_ = cs_malloc(h);
    if (!scratch_) {
        cs_close(&h);
        return false;
    }
    handle_ = (size_t)h;
    arch_ = arch;
    return true;
}

const char* disassembler::reg_name(unsigned reg) const
{
    const char* n = handle_ ? cs_reg_name((csh)handle_, reg) : nullptr;
    return n ? n : "";
}

static bool in_group(const cs_detail* d, uint8_t g)
{
    for (uint8_t i = 0; i < d->groups_count; i++)
        if (d->groups[i] == g)
            return true;
    return false;
}

bool disassembler::decode(const uint8_t* buf, size_t n, uint64_t addr, insn& out)
{
    out = insn();
    if (!handle_ || !buf || n == 0)
        return false;
    const uint8_t* code = buf;
    size_t size = std::min<size_t>(n, 15); // longest x86 instruction
    uint64_t a = addr;
    cs_insn* ci = (cs_insn*)scratch_;
    if (!cs_disasm_iter((csh)handle_, &code, &size, &a, ci))
        return false;

    out.addr = addr;
    out.size = (uint8_t)ci->size;
    memcpy(out.bytes, ci->bytes, std::min<size_t>(ci->size, sizeof(out.bytes)));
    out.id = ci->id;
    snprintf(out.mnem, sizeof(out.mnem), "%s", ci->mnemonic);
    snprintf(out.ops, sizeof(out.ops), "%s", ci->op_str);

    const cs_detail* d = ci->detail;
    const cs_x86& x = d->x86;
    bool is_jump = in_group(d, CS_GRP_JUMP);
    bool is_call = in_group(d, CS_GRP_CALL);
    bool is_ret = in_group(d, CS_GRP_RET) || in_group(d, CS_GRP_IRET);
    bool far = ci->id == X86_INS_LJMP || ci->id == X86_INS_LCALL;

    if (is_call)
        out.kind = flow::call;
    else if (is_ret)
        out.kind = flow::ret;
    else if (is_jump)
        out.kind = (ci->id == X86_INS_JMP || ci->id == X86_INS_LJMP) ? flow::jump : flow::cond;
    else if (ci->id == X86_INS_HLT || ci->id == X86_INS_UD2 || ci->id == X86_INS_UD1 || ci->id == X86_INS_UD0 || ci->id == X86_INS_INT3)
        out.kind = flow::stop;
    else if (ci->id == X86_INS_INT && x.op_count == 1 && x.operands[0].type == X86_OP_IMM && x.operands[0].imm == 0x29)
        out.kind = flow::stop; // __fastfail
    out.is_lea = ci->id == X86_INS_LEA;

    bool branch = is_jump || is_call;
    uint64_t mask = arch_ == bin_arch::x64 ? ~0ull : 0xffffffffull;
    int regs_seen = 0;
    for (uint8_t i = 0; i < x.op_count && i < 8; i++) {
        const cs_x86_op& op = x.operands[i];
        if (op.type == X86_OP_IMM) {
            if (branch && !far) {
                out.has_target = true;
                out.target = (uint64_t)op.imm & mask;
            } else if (!out.has_imm) {
                out.has_imm = true;
                out.imm = (uint64_t)op.imm & mask;
            }
        } else if (op.type == X86_OP_REG) {
            if (branch)
                out.indirect = true;
            if (regs_seen == 0)
                out.reg0 = op.reg;
            else if (regs_seen == 1)
                out.reg1 = op.reg;
            regs_seen++;
        } else if (op.type == X86_OP_MEM) {
            if (branch)
                out.indirect = true;
            out.has_mem_op = true;
            out.mem_base = op.mem.base;
            out.mem_index = op.mem.index;
            out.mem_scale = op.mem.scale;
            out.mem_disp = op.mem.disp;
            out.mem_size = op.size;
            out.mem_write = (op.access & CS_AC_WRITE) != 0;
            bool seg_rel = op.mem.segment == X86_REG_FS || op.mem.segment == X86_REG_GS;
            if (op.mem.base == X86_REG_RIP && op.mem.index == X86_REG_INVALID) {
                out.has_mem = true;
                out.mem_rip = true;
                out.mem = addr + ci->size + (uint64_t)op.mem.disp;
            } else if (op.mem.base == X86_REG_EIP && op.mem.index == X86_REG_INVALID) {
                out.has_mem = true;
                out.mem_rip = true;
                out.mem = (addr + ci->size + (uint64_t)op.mem.disp) & 0xffffffffull;
            } else if (op.mem.base == X86_REG_INVALID && op.mem.index == X86_REG_INVALID && !seg_rel) {
                out.has_mem = true;
                out.mem = (uint64_t)op.mem.disp & mask;
            }
        }
    }
    if (far)
        out.indirect = true;
    if (out.indirect)
        out.has_target = false;
    return true;
}

bool disassembler::decode(const binary& b, uint64_t addr, insn& out)
{
    uint8_t buf[16];
    size_t n = b.read(addr, buf, sizeof(buf));
    if (n == 0) {
        out = insn();
        return false;
    }
    return decode(buf, n, addr, out);
}

namespace regs {

unsigned rip() { return X86_REG_RIP; }
unsigned eip() { return X86_REG_EIP; }
unsigned ebx() { return X86_REG_EBX; }

static unsigned canon(unsigned r)
{
    switch (r) {
    case X86_REG_AL: case X86_REG_AH: case X86_REG_AX: case X86_REG_EAX: case X86_REG_RAX: return X86_REG_RAX;
    case X86_REG_BL: case X86_REG_BH: case X86_REG_BX: case X86_REG_EBX: case X86_REG_RBX: return X86_REG_RBX;
    case X86_REG_CL: case X86_REG_CH: case X86_REG_CX: case X86_REG_ECX: case X86_REG_RCX: return X86_REG_RCX;
    case X86_REG_DL: case X86_REG_DH: case X86_REG_DX: case X86_REG_EDX: case X86_REG_RDX: return X86_REG_RDX;
    case X86_REG_SIL: case X86_REG_SI: case X86_REG_ESI: case X86_REG_RSI: return X86_REG_RSI;
    case X86_REG_DIL: case X86_REG_DI: case X86_REG_EDI: case X86_REG_RDI: return X86_REG_RDI;
    case X86_REG_BPL: case X86_REG_BP: case X86_REG_EBP: case X86_REG_RBP: return X86_REG_RBP;
    case X86_REG_SPL: case X86_REG_SP: case X86_REG_ESP: case X86_REG_RSP: return X86_REG_RSP;
    case X86_REG_R8B: case X86_REG_R8W: case X86_REG_R8D: case X86_REG_R8: return X86_REG_R8;
    case X86_REG_R9B: case X86_REG_R9W: case X86_REG_R9D: case X86_REG_R9: return X86_REG_R9;
    case X86_REG_R10B: case X86_REG_R10W: case X86_REG_R10D: case X86_REG_R10: return X86_REG_R10;
    case X86_REG_R11B: case X86_REG_R11W: case X86_REG_R11D: case X86_REG_R11: return X86_REG_R11;
    case X86_REG_R12B: case X86_REG_R12W: case X86_REG_R12D: case X86_REG_R12: return X86_REG_R12;
    case X86_REG_R13B: case X86_REG_R13W: case X86_REG_R13D: case X86_REG_R13: return X86_REG_R13;
    case X86_REG_R14B: case X86_REG_R14W: case X86_REG_R14D: case X86_REG_R14: return X86_REG_R14;
    case X86_REG_R15B: case X86_REG_R15W: case X86_REG_R15D: case X86_REG_R15: return X86_REG_R15;
    default: return r;
    }
}

bool same_reg(unsigned a, unsigned b)
{
    return a != X86_REG_INVALID && canon(a) == canon(b);
}

}

namespace ins {

bool is_nop(unsigned id) { return id == X86_INS_NOP; }
bool is_endbr(unsigned id) { return id == X86_INS_ENDBR64 || id == X86_INS_ENDBR32; }
bool is_movsxd(unsigned id) { return id == X86_INS_MOVSXD; }
bool is_move(unsigned id) { return id == X86_INS_MOV || id == X86_INS_MOVSXD || id == X86_INS_MOVZX || id == X86_INS_MOVSX; }
bool is_add(unsigned id) { return id == X86_INS_ADD; }
bool is_cmp(unsigned id) { return id == X86_INS_CMP; }
bool is_ja(unsigned id) { return id == X86_INS_JA; }
bool is_jae(unsigned id) { return id == X86_INS_JAE; }
bool is_push(unsigned id) { return id == X86_INS_PUSH; }

bool is_suspicious(unsigned id)
{
    switch (id) {
    case X86_INS_IN: case X86_INS_OUT: case X86_INS_INSB: case X86_INS_INSD: case X86_INS_INSW:
    case X86_INS_OUTSB: case X86_INS_OUTSD: case X86_INS_OUTSW: case X86_INS_CLI: case X86_INS_STI:
    case X86_INS_HLT: case X86_INS_IRET: case X86_INS_IRETD: case X86_INS_IRETQ: case X86_INS_LJMP:
    case X86_INS_LCALL: case X86_INS_RETF: case X86_INS_INTO: case X86_INS_BOUND: case X86_INS_ARPL:
    case X86_INS_AAA: case X86_INS_AAD: case X86_INS_AAM: case X86_INS_AAS: case X86_INS_DAA:
    case X86_INS_DAS: case X86_INS_LES: case X86_INS_LDS: case X86_INS_SALC: case X86_INS_INT1:
    case X86_INS_SYSEXIT: case X86_INS_SYSRET:
        return true;
    default:
        return false;
    }
}

}

// ---- what an instruction writes (for undoing steps) ----

namespace {

// the full register a sub-register lives in, named the way the debugger names it
const char* full_reg_name(unsigned r, bool x64)
{
    if (r == X86_REG_EIP || r == X86_REG_IP || r == X86_REG_RIP)
        return x64 ? "rip" : "eip";
    static const struct {
        unsigned r64;
        const char* n64;
        const char* n32;
    } table[] = {
        {X86_REG_RAX, "rax", "eax"}, {X86_REG_RBX, "rbx", "ebx"}, {X86_REG_RCX, "rcx", "ecx"},
        {X86_REG_RDX, "rdx", "edx"}, {X86_REG_RSI, "rsi", "esi"}, {X86_REG_RDI, "rdi", "edi"},
        {X86_REG_RBP, "rbp", "ebp"}, {X86_REG_RSP, "rsp", "esp"}, {X86_REG_R8, "r8", nullptr},
        {X86_REG_R9, "r9", nullptr}, {X86_REG_R10, "r10", nullptr}, {X86_REG_R11, "r11", nullptr},
        {X86_REG_R12, "r12", nullptr}, {X86_REG_R13, "r13", nullptr}, {X86_REG_R14, "r14", nullptr},
        {X86_REG_R15, "r15", nullptr},
    };
    for (const auto& t : table)
        if (regs::same_reg(r, t.r64))
            return x64 ? t.n64 : t.n32;
    return nullptr;
}

bool is_32bit_reg(unsigned r)
{
    switch (r) {
    case X86_REG_EAX: case X86_REG_EBX: case X86_REG_ECX: case X86_REG_EDX: case X86_REG_ESI: case X86_REG_EDI:
    case X86_REG_EBP: case X86_REG_ESP: case X86_REG_EIP: case X86_REG_R8D: case X86_REG_R9D: case X86_REG_R10D:
    case X86_REG_R11D: case X86_REG_R12D: case X86_REG_R13D: case X86_REG_R14D: case X86_REG_R15D:
        return true;
    default:
        return false;
    }
}

} // namespace

bool disassembler::writes(const uint8_t* buf, size_t n, uint64_t addr,
    const std::function<bool(const char* reg, uint64_t& value)>& reg, std::vector<mem_write>& out)
{
    out.clear();
    if (!handle_ || !buf || n == 0)
        return false;
    const uint8_t* code = buf;
    size_t size = std::min<size_t>(n, 15);
    uint64_t a = addr;
    cs_insn* ci = (cs_insn*)scratch_;
    if (!cs_disasm_iter((csh)handle_, &code, &size, &a, ci))
        return false;
    const cs_detail* d = ci->detail;
    const cs_x86& x = d->x86;
    bool x64 = arch_ == bin_arch::x64;
    uint64_t ptr = x64 ? 8 : 4;
    auto value = [&](unsigned r, uint64_t& v) {
        const char* name = full_reg_name(r, x64);
        if (!name || !reg(name, v))
            return false;
        if (!x64 || is_32bit_reg(r))
            v &= 0xffffffffull;
        return true;
    };
    unsigned id = ci->id;

    // the kernel, or a far transfer, can write anywhere
    if (in_group(d, CS_GRP_INT) || id == X86_INS_SYSCALL || id == X86_INS_SYSENTER || id == X86_INS_INT ||
        id == X86_INS_INTO || id == X86_INS_LCALL || id == X86_INS_ENTER || id == X86_INS_MASKMOVDQU ||
        id == X86_INS_MASKMOVQ || id == X86_INS_VMASKMOVDQU)
        return false;

    // the stack: push and call write just below the stack pointer
    uint64_t sp = 0;
    uint32_t pushed = 0;
    if (id == X86_INS_CALL)
        pushed = (uint32_t)ptr;
    else if (id == X86_INS_PUSH)
        pushed = x.op_count && x.operands[0].size ? x.operands[0].size : (uint32_t)ptr;
    else if (id == X86_INS_PUSHFQ)
        pushed = 8;
    else if (id == X86_INS_PUSHFD)
        pushed = 4;
    else if (id == X86_INS_PUSHF)
        pushed = 2;
    else if (id == X86_INS_PUSHAL)
        pushed = 32;
    else if (id == X86_INS_PUSHAW)
        pushed = 16;
    if (pushed) {
        if (!value(x64 ? X86_REG_RSP : X86_REG_ESP, sp))
            return false;
        out.push_back({sp - pushed, pushed});
        if (id != X86_INS_PUSH) // a push can still read memory, but it writes only the stack
            return true;
    }

    // string writes: stos / movs, maybe repeated rcx times, up or down by the direction flag
    bool str = id == X86_INS_STOSB || id == X86_INS_STOSW || id == X86_INS_STOSD || id == X86_INS_STOSQ ||
               id == X86_INS_MOVSB || id == X86_INS_MOVSW || id == X86_INS_MOVSQ ||
               (id == X86_INS_MOVSD && x.op_count == 2 && x.operands[0].type == X86_OP_MEM && x.operands[1].type == X86_OP_MEM);
    if (str) {
        uint32_t elem = x.op_count ? x.operands[0].size : 0;
        if (!elem)
            return false;
        uint64_t di = 0, count = 1, flags = 0;
        if (!value(x64 ? X86_REG_RDI : X86_REG_EDI, di) || !reg("eflags", flags))
            return false;
        if (x.prefix[0] == X86_PREFIX_REP || x.prefix[0] == X86_PREFIX_REPNE) {
            if (!value(x64 ? X86_REG_RCX : X86_REG_ECX, count))
                return false;
            if (count == 0)
                return true; // nothing happens
        }
        if (count > (1u << 20) / elem)
            return false; // too much to keep
        uint64_t len = count * elem;
        bool down = (flags >> 10) & 1;
        out.push_back({down ? di + elem - len : di, (uint32_t)len});
        return true;
    }

    // everything else: memory operands it writes
    for (uint8_t i = 0; i < x.op_count && i < 8; i++) {
        const cs_x86_op& op = x.operands[i];
        if (op.type != X86_OP_MEM || !(op.access & CS_AC_WRITE))
            continue;
        if (op.mem.segment == X86_REG_FS || op.mem.segment == X86_REG_GS || op.size == 0)
            return false;
        uint64_t ea = (uint64_t)op.mem.disp;
        if (op.mem.base == X86_REG_RIP || op.mem.base == X86_REG_EIP) {
            ea += addr + ci->size;
        } else if (op.mem.base != X86_REG_INVALID) {
            uint64_t b = 0;
            if (!value(op.mem.base, b))
                return false;
            ea += b;
        }
        if (op.mem.index != X86_REG_INVALID) {
            uint64_t ix = 0;
            if (!value(op.mem.index, ix))
                return false;
            ea += ix * (uint64_t)op.mem.scale;
        }
        if (!x64)
            ea &= 0xffffffffull;
        out.push_back({ea, op.size});
    }
    return true;
}
