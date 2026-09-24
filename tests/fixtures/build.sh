#!/bin/sh
# rebuilds the test binaries with zig (pip install ziglang).
# pe files are stripped to keep them small, the elf files keep .symtab on purpose.
set -e
cd "$(dirname "$0")"
ZIG="python3 -m ziglang"
$ZIG cc -target x86_64-windows-gnu -O2 -s src/sample.c -o sample64.exe -luser32
$ZIG cc -target x86-windows-gnu -O2 -s src/sample.c -o sample32.exe -luser32
$ZIG cc -target x86_64-windows-gnu -O2 -s -shared src/sample.c -o sample64.dll -luser32
$ZIG cc -target x86_64-linux-gnu -O2 src/sample.c -o sample64.elf
$ZIG cc -target x86-linux-gnu -O2 src/sample.c -o sample32.elf
rm -f *.pdb *.lib
