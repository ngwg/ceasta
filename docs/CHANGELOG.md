# changelog

## v0.13.0 - 2026-09-26

- **readable names**: c++ symbols are demangled - gcc / clang (`_ZNSt6vector...`) and msvc
  (`?Load@Config@@...`) - and so are rust's (legacy and v0). the listing shows a function with
  its parameters, so overloads stay apart; pseudocode calls it by name
  (`std::vector<int>::push_back(...)`); library types read the way the source spells them:
  `std::string`, `std::vector<int>`, `std::map<int, char>`. the mangled name still finds it. the
  names are what llvm-cxxfilt, llvm-undname and rustc-demangle print (checked on 190,000 of
  them)
- **objective-c**: method names from a mac program's own metadata, stripped or not -
  `-[NSString(MyAdditions) trimmed]`, `+[AppDelegate shared]`. selector stubs are
  `objc_msgSend$alloc`, and selector and class references and instance variables get names
  (`mov rsi, [selRef_count]`). swift classes go by their swift name (`MyApp.AppDelegate`)
- **go**: every function's name from the go runtime's own table, stripped programs too - go 1.2
  to today, linux / windows / macos, x86 / x64 / arm64. go's panics and exits are known not to
  return, and its switch tables are read
- **structs**: declare c types - structs, unions, enums, typedefs - and a variable typed as a
  pointer to one reads `p->next`, `p->items[i].name`, `&p->hdr`, not `*(long long*)(p + 8)`.
  - **C types** (shift+f1, edit menu): the list and an editor; offsets as comments. laid out the
    way the file's compiler does it - pointer size, windows or not, `#pragma pack`, bit fields,
    `__attribute__((packed, aligned))` (checked against clang on eight targets)
  - **make a struct from how it's used** (right-click a variable in the pseudocode): a field at
    every offset the code reads or writes through it, sized by the access, and a field it
    follows to the next one points to the struct (a list's `next`). name the fields and the
    pseudocode follows
  - **a c header's types** (file > import, or `ceasta-cli import <file> x.h`): real headers
    work - `#define` constants, inline functions and `extern "C"` are skipped over, and what
    can't be read is left out and counted. all of windows.h (9,983 types) takes a third of a
    second; preprocess a header that includes others (`gcc -E -P`, `cl /EP`)
  - a stack variable of a struct type reads `d.x`; registers set from a typed pointer get its
    type (`rbx = inv` is a `struct inventory*` too)
  - saved with the project, one `type` line each; `ceasta-cli types <file>` lists them; the ida
    and ghidra exports declare them before the prototypes that use them
  - for the ai: `define_types`, `list_types`, `create_struct_from_usage`; in lua:
    `ceasta.types()`, `add_types`, `set_var_type`, `struct_from_uses`
- **analysis**
  - c++ and rust cleanup code (exception landing pads) in linux programs belongs to its
    function; it used to show up as hundreds of made-up functions
  - more switch tables: a table base loaded before a loop, a jump through a register (go), a
    bound check with other instructions between, and tables with no bound (a rust enum's tag)
  - rust (and -fno-plt c / c++) calls functions of its own file through the got: those calls
    go to the function now, and rust's panics are known not to return
  - on the programs checked, every decoded instruction is where objdump puts it (v0.12 was off
    in 45 to 5,583 places per program), with thousands fewer bogus `sub_` functions
- pseudocode calls an import by its name: `memcmp(...)`, not `j_memcmp(...)`
- signatures keep the mangled name, so a stripped program gets the readable one back
- search finds a file's data names too (`selRef_init`, a global), not only the ones you renamed
- esc that closes a right-click menu doesn't also go back to where you were

## v0.12.0 - 2026-09-25

- **macos**: `ceasta-x.y.z-macos.dmg` (the app) and `ceasta-cli-x.y.z-macos.tar.gz`, one build
  for apple silicon and intel, macos 11 or newer. the app uses the system's open / save panels
  and cmd for the shortcuts; plugins you add go in `~/Library/Application Support/ceasta`.
  signed ad-hoc, not notarized: the first launch needs right-click > open (or open anyway in
  privacy & security). no debugger on macos yet
- **mach-o files**, on every system: macos / ios programs, libraries, bundles and object
  files, x86_64 and arm64 (arm64e too), and universal files (`--arch x64|arm64`, the palette's
  "part" actions, and a `.ceasta` file remembers which part). imports come from dyld's bind
  info or chained fixups (the pointers are decoded, so data reads right), stubs call imports by
  name, exports from the export trie, exact function starts, and c++ / rust landing pads stay
  inside their function. names lose mach-o's leading underscore (`printf`, not `_printf`), so
  prototypes and calls that don't return are known
- **file info for mach-o**: minimum os and sdk, uuid, libraries and rpaths, pie / nx / canary /
  fortify / pac, the code signature (signer and team, ad-hoc, hardened runtime, library
  validation) and the entitlements, with warnings for the ones that let code in
  (get-task-allow, disable-library-validation, dyld environment variables, jit), fairplay
  encryption, upx and overlays
- kuna reads mach-o files too (a universal file's part is handed over on its own)
- analysis: in a file that lists every function start, code found by heuristics (a switch
  nobody resolved, a pointer into the middle) stays in the function around it; an
  instruction decoded past a call that doesn't return can't swallow the next function
- fixes: "open my plugins folder" works on linux too; a client hanging up on the http mcp
  server can't end ceasta with SIGPIPE; a kuna run finished while debugging on linux doesn't
  wait out its time limit

## v0.11.0 - 2026-09-25

- **arm64**: pe (windows on arm) and elf (linux) arm64 programs open next to x86 / x64 ones -
  listing, graph, xrefs, strings, switch tables, import stubs, signatures and diff. addresses
  built over two instructions (adrp + add / ldr) read as names (`adrp x0, aHello@page` /
  `add x0, x0, aHello@pageoff  ; "hello"`), calls through the got name the import, and the
  switch tables gcc, clang and msvc make are followed. raw arm64 code: file > open raw,
  `--raw-arm64`. the decompiler and the debugger are still x86 / x64 only, and say so
- **the linux gui is a download**: `ceasta-x.y.z-linux-x64.AppImage` - chmod +x and run
  (ubuntu 22.04 or newer and the like). the cli tarball is built on 22.04 too now
- **one file for your work, like ida's .i64**: ctrl+s writes `<file>.ceasta` next to the
  program with your names, comments, breakpoints, where you were, and the program itself, so
  it opens later - or on another machine - without the original
- **undo / redo** (ctrl+z / ctrl+y) for names, comments, types, prototypes and bookmarks, and
  **bookmarks** (alt+m marks the line, ctrl+m lists them)
- **a calmer window**: a slimmer toolbar (the debug buttons only while debugging), one small
  view switch (listing / graph / pseudocode / both), and ctrl+shift+p - every action and
  plugin command in one searchable list
- **debugger**
  - step back (shift+f7): steps are recorded, back undoes registers and memory
  - step out (ctrl+f9)
  - conditional breakpoints (shift+f2): `rdi == 3`, `hits == 100`, `str(rcx) == 'admin'`,
    run in a sandbox
  - watchpoints: stop when the program writes (or reads) a variable - f2 on data, or the hex
    view's right click; up to 4, on every thread
  - a call stack tab that works on optimized code without unwind info, and a memory map tab;
    the hex view can show process memory (the heap, a stack)
  - linux: multi-threaded programs, and libraries loaded after start show up by name
- **decompiler**
  - stack variables (`local_1c`, `arg_4`), declared at the top; buffers become arrays
  - calls get their real arguments, 32-bit stack arguments and win64 stores included, and
    imports are called by name: `CreateFileA(arg_0, 0x40000000, 1, 0, 2, 0x80, 0)`
  - ~350 known prototypes (windows api, c library, posix) give the argument count, and the
    listing names what each instruction passes: `mov r8d, 0x30  ; dwLength`
  - click a name and every use lights up: n renames it, y sets a variable's type or edits a
    function's prototype, enter follows it
  - both (shift+f5): the listing and the pseudocode side by side, following each other
- **file info** (the file tab, `ceasta-cli info`, the ai): headers, security flags (aslr, dep,
  cfg, signed / pie, nx, relro, canary, fortify), md5 / sha256 / imphash, sections with
  entropy, resources, version info, and warnings - packed (upx, aspack, themida, vmprotect,
  ...), overlay, tls callbacks, an entry point in an odd section
- **ida, ghidra and x64dbg**: file > export for writes an idapython script, a ghidra script
  or an x64dbg database with your names, comments, prototypes and breakpoints; file > import
  names reads x64dbg databases, .map files and the json of `scripts/ida_to_ceasta.py` /
  `scripts/ghidra_to_ceasta.py`. the same as `ceasta-cli export` / `import`
- **a second decompiler, kuna** (#12): with [kuna](https://github.com/Noelo-Lab/kuna) installed,
  the pseudocode view gets a `ceasta | kuna` switch showing its output for the same function -
  run in the background, kept per function, lines linked to the listing, arm64 included.
  nothing of it is bundled: ceasta runs kuna's command line tool (on PATH, or view > second
  decompiler). also `ceasta-cli decompile --kuna` and the ai's `decompile_with_kuna`
- **ai**: ready-made mcp prompts (triage, explain_function, rename_pass, find_crypto,
  trace_function) and names you review before they're applied (ai > review suggested names);
  new tools for variables, prototypes, watchpoints, stepping back and out, and the memory map
- analysis: elf unwind tables give exact function starts (gcc's `.cold` parts stay inside
  their function), and a tail jump to an import stub no longer grows the caller over
  everything in between
- fixes: long listings could never scroll their last rows into view; a listing that comes
  back into view scrolls to the cursor

## v0.10.0 - 2026-09-25

- search everything (ctrl+f, edit > search, the toolbar): functions, names, imports, exports,
  strings, comments and segments in one box - exact matches first, up / down / enter to jump,
  and strings say where they're used. the info panel's box searches its lists and the tabs
  count the matches. `ceasta-cli search <file> <text>` does the same from a terminal
- debugger: a steps box by the step buttons (and in the debug menu) - f7 / f8 run that many
  instructions at once without freezing the window; a breakpoint, a fault or the exit ends it
  early, and the output gets one line instead of one per instruction
- the ai server in the app: ai > connect an ai starts the mcp server for the open file and shows
  what to paste into claude code / cursor. the ai works on what you see - its renames, comments
  and breakpoints show up live, and its debug session is the window's debugger
- saving: nothing is saved behind your back any more. closing the window, closing the file or
  opening another one asks first (save / don't save / cancel), the title shows a `*` while there
  are unsaved changes, and file > save project as... writes a `.ceasta` project wherever you
  like - open it (ctrl+o or drop it on the window) to pick up where you left off
- mcp over http only answers programs on this machine: requests from web pages of other sites
  and dns-rebinding hosts are refused, and a stalled connection can't hold the server
- linux debugger: the program no longer inherits ceasta's open files and sockets

## v0.9.0 - 2026-09-24

- a built-in mcp server: connect an ai (claude code / desktop, cursor, ...) to the open binary
  - `ceasta-cli mcp <file>` (stdio) or `--http <port>`; read, decompile, xrefs, rename, comment
  - `--allow-debug` adds the debugger tools: breakpoints, stepping, registers, memory, and
    debug_call (call a function and get its result), debug_trace, debug_decompile_here
  - `--allow-lua` adds run_lua. see docs/mcp.md
- call a function in the running program: repl `call`, lua `ceasta.dbg.call`, mcp debug_call
- live pseudocode: stopped in a function, the current line is marked (repl `dec`, mcp)
- runtime xrefs: `trace` records the targets of indirect calls / jumps the program takes
- binary diff: `ceasta-cli diff <old> <new>` and the diff_binary mcp tool
- library signatures: `sigmake` / `sigapply` name known functions in a stripped binary
- project files: names / comments / breakpoints save to a committable `<binary>.ceasta`
- experimental linux gui (glfw + opengl3), off by default (`-DCEASTA_LINUX_GUI=ON`)

## v0.8.2 - 2026-09-24

- decompiler fixes - it could print code that doesn't do what the program does
  - values a later block reads were dropped: a loop could lose its counter increment, a function its return value
  - nothing reads a register after it changed any more, when an assignment has to be written out early
  - calls get their real arguments: functions in the binary are checked for what they read, and values a compiler keeps in registers across a call to a small function survive it
  - setcc, cmov, div / idiv, mul, rol / ror, bswap, popcnt are lifted (`rax == 5`, `a ? b : c`, `/` and `%`, `__rol(x, 5)`); anything else shows as `__asm { ... }` instead of vanishing
  - loops with more than one exit, top-tested loops that compute before their test, and tail calls (a jump into another function, or through a pointer) come out right
  - switch cases are written inside the switch, and functions whose result no caller reads are `void`
  - every goto has its label - a jump back to code that was already written had none
- the pseudocode screenshot shows the new switch output
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
