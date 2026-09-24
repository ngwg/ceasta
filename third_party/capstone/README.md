# capstone

Capstone 5.0.9 disassembler, trimmed down to the core + the x86 module
(16/32/64-bit, intel and at&t printers). The `*_reduce*` tables are left out
since `CAPSTONE_X86_REDUCE` is never defined.

- source: https://www.capstone-engine.org (BSD license, see `LICENSE.TXT`)
- build defines: `CAPSTONE_HAS_X86`, `CAPSTONE_USE_SYS_DYN_MEM`
- used by `src/core/disasm.*`
