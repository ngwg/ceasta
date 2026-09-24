# changelog

## v0.8.2 - 2026-09-24

- decompiler fixes - it could print code that doesn't do what the program does
  - values a later block reads were dropped: a loop could lose its counter increment, a function its return value
  - nothing reads a register after it changed any more, when an assignment has to be written out early
  - calls get their real arguments: functions in the binary are checked for what they read, and values a compiler keeps in registers across a call to a small function survive it
  - setcc, cmov, div / idiv, mul, rol / ror, bswap, popcnt are lifted (`rax == 5`, `a ? b : c`, `/` and `%`, `__rol(x, 5)`); anything else shows as `__asm { ... }` instead of vanishing
  - loops with more than one exit, top-tested loops that compute before their test, and tail calls through pointers come out right
  - switch cases are written inside the switch, and functions whose result no caller reads are `void`
- the linux download's release note mentions the terminal debugger

## v0.8.1 - 2026-09-24

- licensed under GPLv3 - the license now ships in the installer, the zip and the linux download
- reworked readme: badges, "one function, three ways", a download table, clearer platform notes
- a contributing guide and issue templates for bug reports / feature requests

## v0.8.0 - 2026-09-24

- linux debugger, built on ptrace - the debugger is no longer windows only
  - breakpoints, step into / over, run to, pause, registers, stack, live memory
  - 64 and 32 bit programs, pie / aslr handled, breakpoint bytes hidden from reads
- `ceasta-cli dbg <program>`: an interactive terminal debugger with ceasta's
  names, disassembly and decompiler built in (b / c / si / ni / until / r / x /
  u / dec / k / lua). works on linux and windows
- `ceasta.dbg.*` and `run --debug` work on linux too
- the icon is flat and centered now (was clipped)

## v0.7.0 - 2026-09-24

- decompiler: c-like pseudocode for a function (f5, or the Pseudocode tab)
  - lifts x86 / x64 to expressions, recovers conditions from the flags
  - structures the control flow: if / else, while, do / while, switch, gotos only where needed
  - names calls, arguments from the calling convention, string and global names
  - `ceasta-cli decompile <file> <where>` and `ceasta.decompile(addr)` in lua
- cleaner, calmer look and a light theme (View > Theme), square edges, panel headers
- a real icon

## v0.6.0 - 2026-09-24

- real binaries now, the mock data is gone
  - pe loader: exe / dll / sys, 32 + 64 bit, imports (delay load too), exports, .pdata, tls callbacks, relocations, coff symbols
  - elf loader: x86 / x64, symbols, plt / got imports, pie
  - raw shellcode (file > open as raw code)
- disassembly with capstone (x86 only build of it)
- auto analysis in the background with a progress bar
  - functions from the entry, exports, symbols, .pdata, calls, pointers in data, prologues
  - switch tables, xrefs, strings (ascii + utf-16), thunks, noreturn calls
- ida style listing: names instead of addresses, labels, xref comments, string comments
- function graph (space), zoom with ctrl + wheel, drag to pan
- debugger on windows: start / attach, breakpoints, step into / over, run to cursor, pause, registers, stack, live hex. 32 bit programs through wow64, aslr handled
- lua plugins + lua console, 5 plugins included
- rename, comments, jump, xrefs, byte search, back / forward. saved per file
- new simple layout
  - one window, fixed panels, drag the lines to resize, no floating windows
  - functions left, listing / graph middle, info + cpu right, output bottom
  - bigger monospace font, ctrl + / - for text size
  - every menu item shows its shortcut, tooltips on the toolbar
  - welcome screen with recent files, drag and drop to open
- ceasta-cli command line tool
- cmake build, visual studio solution updated (core / lua / capstone as their own projects)
- installer (inno setup) + portable zip on the releases page
- tests: core, fuzzed loaders, headless ui, debugger, installer. ci on linux and windows

## v0.5 - 2026-09-22

- default dock positions now
- functions left, ida view center
- imports top right, cpu bottom right
- output bottom
- no more windows piled on top of each other

## v0.4 - 2026-09-21

- flattened the ui, less nesting
- left is just functions now, no tabs
- ida view is just nav + list, 4 cols
- right is one list with imports then strings
- bottom is output + hex side by side, no tabs
- still ida-like, just cleaner

## v0.3 - 2026-09-21

- split ui into folders, no more one big app.cpp
- added `src/ui/` with a file per panel
  - top_bar, left_panel, ida_view, right_panel, cpu_panel, bottom_panel
- added `src/widgets/` for shared bits
  - nav_band + addr label
- moved mock data to `src/data/`
- same look, just organized better

## v0.2 - 2026-09-21

- more filled ida-like layout
- added graph / text toggle with simple block graph
- added nav band on top of ida view
- left panel now has tabs
  - funcs with filter
  - segments
  - structs
- ida view has address, bytes, code, comment, xref columns
- right panel has tabs
  - imports
  - strings with length
  - xrefs
- bottom panel has tabs
  - output log
  - console (mock)
  - hex with ascii
- cpu window with regs + stack table
- more mock data, still no real parsing

## v0.1 - 2026-09-21

- first real version, opens a window now
- added imgui (win32 + dx11 backend)
- basic ida-like layout with docking
  - functions list with filter
  - disassembly view with colors
  - hex view, strings, registers, output log
- visual studio solution, just open `ceasta.sln` and build x64
- mock data for now, no real pe parsing yet

## v0.0 - 2026-09-21

- initial commit, empty main
