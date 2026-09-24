# ceasta

disassembler + debugger in one, c++ with imgui. ida style listing and function graph, an x64dbg style debugger, and lua plugins.

![listing](docs/listing.png)

## download

get it from the [releases page](https://github.com/ngwg/ceasta/releases):

- `ceasta-x.y.z-setup.exe` - installer for windows 10/11 x64. installs for your user (no admin needed), start menu entry, optional desktop icon, optional "open with ceasta" in the right-click menu of .exe/.dll/.sys files, optional PATH entry for the cli.
- `ceasta-x.y.z-windows-x64.zip` - portable, unzip and run `ceasta.exe`.
- `ceasta-cli-x.y.z-linux-x64.tar.gz` - the command line tool for linux.

## what it does

- opens pe files (exe, dll, sys - 32 and 64 bit), elf (x86 / x64) and raw shellcode
- auto analysis: functions (entry, exports, symbols, .pdata, tls callbacks, calls, pointers in data), switch tables, xrefs, strings (ascii + utf-16), imports / exports, thunks, noreturn calls
- ida style listing: names instead of addresses, labels, xref and string comments
- function graph (space): colored edges, zoom with ctrl + wheel, drag to pan
- decompiler (f5): c-like pseudocode for a function - if / else, while / do, switch, calls with names
- debugger (windows): start or attach, breakpoints, step into / over, run to cursor, pause, registers, stack, live memory in the hex view. 32 bit programs work too (wow64), aslr is handled
- rename, comments, jump to address or name, xrefs, byte search, back / forward
- names, comments and breakpoints are saved per file (in `%APPDATA%\ceasta\db`)
- lua plugins and a lua console
- `ceasta-cli` for scripts and ci

## layout

one window, nothing floating around:

- top: menu and toolbar
- left: functions
- middle: overview band, then the listing or the graph
- right: imports / exports / strings / segments / xrefs, with the debugger (registers + stack) under it
- bottom: output + lua console, hex, breakpoints, modules
- drag the lines between panels to resize, the view menu hides panels, ctrl + / ctrl - changes the text size

![graph](docs/graph.png)

## keys

| key | what |
|-----|------|
| ctrl+o | open a file |
| g | jump to address or name |
| enter / double click | follow the operand |
| esc / ctrl+enter | back / forward |
| n | rename |
| ; | comment |
| x | references to here |
| space | listing / graph |
| f5 | pseudocode (decompiler) |
| alt+b | search bytes |
| f9 | start debugging / continue |
| f7 / f8 | step into / step over |
| f4 | run to cursor |
| f2 | toggle breakpoint |
| f12 | pause |
| ctrl+f2 | stop debugging |
| ctrl+s | save names and comments |
| f1 | all shortcuts |

## plugins

plugins are lua files in `plugins/` (next to the program) or in `%APPDATA%\ceasta\plugins`. they add commands to the plugins menu. five come with it: file summary, crypto finder, wrapper namer, strings report, call tracer (debugger).

```lua
ceasta.register_command("Count calls", function()
    local n = 0
    for _, fn in ipairs(ceasta.functions()) do
        n = n + #ceasta.xrefs_to(fn.addr)
    end
    ceasta.log(n .. " references to functions")
end)
```

the whole api is in [plugins/README.md](plugins/README.md). the output panel has a lua prompt too, try `ceasta.name(ceasta.here())`.

## cli

```
ceasta-cli info file.exe            format, entry, segments
ceasta-cli funcs file.exe           functions
ceasta-cli disasm file.exe main 40  listing from a name or address
ceasta-cli graph file.exe start     basic blocks of a function
ceasta-cli decompile file.exe main  pseudocode for a function
ceasta-cli xrefs file.exe CreateFileW
ceasta-cli find file.exe "48 8b ?? 05"
ceasta-cli run file.exe script.lua  run a plugin / script
```

## build

windows:

- visual studio 2022: open `ceasta.sln`, pick `Release | x64`, build. the program ends up in `build\msvc\Release` with the plugins next to it
- or cmake: `cmake -S . -B build` then `cmake --build build --config Release`
- release files (zip + installer, needs [inno setup 6](https://jrsoftware.org/isinfo.php)): `powershell -ExecutionPolicy Bypass -File installer\package.ps1`

linux builds the core, the cli and the tests (the gui is windows only):

```
cmake -S . -B build && cmake --build build -j && ctest --test-dir build
```

everything needed is in the repo, nothing to install besides the compiler.

## code

- `src/app.*` - state, actions and the main layout
- `src/ui/` - one file per panel (top_bar, left_panel, ida_view, graph_view, right_panel, cpu_panel, bottom_panel, status_bar, dialogs)
- `src/widgets/` - small shared bits (nav_band, splitter)
- `src/core/` - no ui code: loaders (`binary`, `pe`, `elf`), `disasm` (capstone), `analysis`, `database`, `lua_host`, `debugger`, `os`
- `src/cli/` - ceasta-cli
- `src/main.cpp` - the win32 + directx 11 window
- `plugins/` - lua plugins that ship with it
- `tests/` - core tests with fuzzed inputs, headless ui tests, test binaries
- `installer/` - inno setup script, packaging and install test scripts
- `msvc/` - visual studio projects for the libraries
- `third_party/` - imgui, capstone (x86 only), lua 5.4. licenses in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)
