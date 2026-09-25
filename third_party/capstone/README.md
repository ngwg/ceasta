# capstone

Capstone 5.0.9 disassembler, trimmed down to the core + the x86 and aarch64 modules
(x86: 16/32/64-bit, intel and at&t printers; aarch64: arm64 a64). The `*_reduce*` tables are left out
since `CAPSTONE_X86_REDUCE` is never defined.

- source: https://www.capstone-engine.org (BSD license, see `LICENSE.TXT`)
- build defines: `CAPSTONE_HAS_X86`, `CAPSTONE_HAS_ARM64`, `CAPSTONE_USE_SYS_DYN_MEM`
- used by `src/core/disasm.*`
