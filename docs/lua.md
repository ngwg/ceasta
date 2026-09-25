# ceasta lua scripting

ceasta embeds [Lua 5.4](https://www.lua.org/manual/5.4/). you can automate the
analysis, rename and comment in bulk, drive the debugger, or add your own
commands to the menu — all from plain `.lua` files, with no build step.

- [where scripts live](#where-scripts-live)
- [three ways to run lua](#three-ways-to-run-lua)
- [a first plugin](#a-first-plugin)
- [addresses](#addresses)
- [api: `ceasta.*`](#api-ceasta)
- [api: `ceasta.dbg.*`](#api-ceastadbg-debugger)
- [events](#events)
- [examples](#examples)
- [the shipped plugins](#the-shipped-plugins)
- [limits and safety](#limits-and-safety)

---

## where scripts live

ceasta loads every `.lua` file from two folders at startup, and again when you
pick **Plugins → Reload plugins**:

- next to the program: `<install>/plugins/`
- per user: `%APPDATA%\ceasta\plugins\` on windows, `~/.config/ceasta/plugins/` on linux

drop a file in the per-user folder to add your own without touching the install
(**Plugins → Open my plugins folder** jumps there).

## three ways to run lua

1. **plugins** — a file that calls `ceasta.register_command(...)`; each command
   shows up in the **Plugins** menu.
2. **the console** — the prompt at the bottom of the **Output** tab. type an
   expression to print its value (`ceasta.name(ceasta.here())`) or a statement to
   run it. up/down walk the history.
3. **the command line** — `ceasta-cli run file.exe script.lua`. the script runs,
   then every command it registered runs too, so a plugin works headless. add
   `--debug` to start the file under the debugger first (windows), so the
   `ceasta.dbg.*` calls work.

## a first plugin

```lua
-- hello.lua  -  copy this to start your own
ceasta.register_command("My summary", function()
    local f = ceasta.file()
    ceasta.log(("%s: %s, entry %X"):format(f.name, f.format, f.entry))
    for _, fn in ipairs(ceasta.functions()) do
        if fn.size > 0x400 then
            ceasta.set_comment(fn.addr, "big function")
        end
    end
end, "optional help text shown as a tooltip")
```

## addresses

every function that takes an address accepts:

- a number — `0x401000`
- a hex string — `"0x401000"` or `"401000"`
- a name — `"main"`, `"sub_401000"`, `"CreateFileW"`

addresses always come **back** as integers. these are static (listing)
addresses; while debugging, translate with `ceasta.dbg.to_static` /
`ceasta.dbg.to_runtime` (aslr moves the image).

---

## api: `ceasta.*`

### output

| call | what it does |
|------|--------------|
| `log(...)` | write a line to the output panel. `print(...)` works too |
| `warn(msg)` | write a warning line |

### the loaded file

`file()` returns a table:

```lua
{ path, name, format, arch, kind, base, entry, has_entry, bits }
-- format: "pe" | "elf" | "mach-o" | "raw"   arch: "x86" | "x64" | "arm64"   bits: 32 | 64
-- kind: "exe (console)", "dll", "elf pie", ...
```

### reading memory (the file image)

| call | returns |
|------|---------|
| `read(addr, n)` | up to `n` bytes as a string |
| `read_u8/16/32/64(addr)` | an unsigned integer, or nil if unmapped |
| `read_i32(addr)` | a signed 32-bit integer |
| `read_ptr(addr)` | a pointer-sized integer (4 or 8 bytes) |
| `read_cstr(addr [,max])` | a nul-terminated ascii string |
| `is_mapped(addr)` | is the address inside a segment |
| `is_code(addr)` | is it inside executable memory |

### names and comments

| call | returns |
|------|---------|
| `name(addr)` | the name at `addr`, or `""` |
| `location(addr)` | a name, or `func+offset`, or the plain address |
| `set_name(addr, name)` | `true`, or `false, err` (rejects invalid / auto-name prefixes) |
| `resolve(text)` | the address for a name / hex string, or nil |
| `comment(addr)` | the user comment at `addr` |
| `set_comment(addr, text)` | sets it (empty clears it) |

### disassembly and decompilation

| call | returns |
|------|---------|
| `disasm(addr)` | `{ addr, size, mnemonic, operands, text, flow, target? }` or nil |
| `next_addr(addr)` | the address of the next item |
| `decompile(addr)` | c-like pseudocode (a string) for the function containing `addr` |

`flow` is one of `"normal"`, `"jump"`, `"cond"`, `"call"`, `"ret"`, `"stop"`.
`target` is set for a direct branch or call.

### listings of things

each returns an array of tables (use with `ipairs`):

| call | element |
|------|---------|
| `functions()` | `{ addr, size, name, thunk }` |
| `imports()` | `{ name, lib, slot }` |
| `exports()` | `{ name, addr, ordinal }` |
| `strings()` | `{ addr, text, wide }` |
| `xrefs_to(addr)` | `{ from, to, type }` — `type` is `"call"`/`"jump"`/`"read"`/`"write"`/`"offset"` |

### searching

`find(pattern [,from [,max]])` — a byte search, returns an array of addresses.
`??` is a wildcard byte:

```lua
for _, a in ipairs(ceasta.find("48 8b ?? 05")) do ceasta.log(("%X"):format(a)) end
```

### the cursor and commands

| call | what it does |
|------|--------------|
| `here()` | the cursor address in the disassembly view |
| `goto_addr(addr)` | move the cursor there |
| `register_command(name, fn [,help])` | add a command to the Plugins menu |
| `on(event, fn)` | run `fn` on an app event (see [events](#events)) |

---

## api: `ceasta.dbg.*` (debugger)

available while a process is loaded under the debugger (windows, or linux with `ceasta-cli dbg` / `run --debug`)
(start with **F9**, or `ceasta-cli run ... --debug`). addresses here are
**runtime** addresses.

### state

| call | returns |
|------|---------|
| `state()` | `"none"` \| `"running"` \| `"stopped"` |
| `pc()` | the program counter |
| `sp()` | the stack pointer |
| `reg(name)` | one register by name, e.g. `reg("rax")` |
| `regs()` | a table of all registers |

### reading and writing the live process

| call | returns |
|------|---------|
| `read(addr, n)` | `n` bytes as a string |
| `read_ptr(addr)` | a pointer-sized integer |
| `write(addr, bytes)` | `true`, or `false, err` |

### running

| call | what it does |
|------|--------------|
| `step_into()` | one instruction; **waits** until the target stops, returns true |
| `step_over()` | steps over calls; waits; returns true |
| `step_out()` | steps over until the function has returned; true when back in the caller |
| `step_back()` | undoes the last recorded step (registers and the memory it wrote) |
| `run_to(addr)` | runs until `addr` (or it stops); waits; returns true |
| `call(func, args...)` | calls a function (a name or an address) in the stopped program and returns its result; a string argument that isn't a name is written into the target and passed as a pointer. 64-bit targets |
| `trace([n])` | runs up to `n` steps (2000) and records the targets of indirect calls / jumps as xrefs; returns how many were new |
| `cont()` | continue, returns right away |
| `pause()` | request a stop, returns right away |
| `wait([ms])` | wait for the next stop, returns the new state |
| `add_bp(addr)` / `del_bp(addr)` | a breakpoint at a runtime address |

### aslr translation

| call | returns |
|------|---------|
| `to_static(addr)` | the listing address for a runtime address, or nil if outside the image |
| `to_runtime(addr)` | the runtime address for a listing address |

---

## events

`ceasta.on(event, fn)` registers a handler:

| event | when | argument |
|-------|------|----------|
| `"load"` | analysis finished | — |
| `"stop"` | the debugger stopped | the static pc |
| `"exit"` | the debuggee exited | the exit code |

```lua
ceasta.on("load", function() ceasta.log("ready: " .. ceasta.file().name) end)
ceasta.on("stop", function(pc) ceasta.log("stopped at " .. ceasta.location(pc)) end)
```

## examples

count how many functions are referenced:

```lua
ceasta.register_command("Count referenced functions", function()
    local n = 0
    for _, fn in ipairs(ceasta.functions()) do
        if #ceasta.xrefs_to(fn.addr) > 0 then n = n + 1 end
    end
    ceasta.log(n .. " functions have xrefs")
end)
```

dump the pseudocode of every big function to the log:

```lua
ceasta.register_command("Decompile big functions", function()
    for _, fn in ipairs(ceasta.functions()) do
        if fn.size > 0x200 and not fn.thunk then
            ceasta.log(ceasta.decompile(fn.addr))
        end
    end
end)
```

single-step the stopped target and log each call (debugger):

```lua
ceasta.register_command("Trace calls", function()
    local dbg = ceasta.dbg
    if dbg.state() ~= "stopped" then return ceasta.warn("stop the target first (F9)") end
    for _ = 1, 2000 do
        local pc = dbg.to_static(dbg.pc())
        local ins = pc and ceasta.disasm(pc)
        if not ins then break end
        if ins.flow == "call" and ins.target then
            ceasta.log("call -> " .. ceasta.location(ins.target))
        end
        if not dbg.step_into() then break end
    end
end)
```

## the shipped plugins

the `plugins/` folder has five worked examples you can read and copy:

| file | what it does |
|------|--------------|
| `hello.lua` | prints a file summary — the smallest useful plugin |
| `find_crypto.lua` | flags and renames functions that look like crypto / hashing |
| `name_wrappers.lua` | renames one-call wrapper functions to `w_<callee>` |
| `strings_report.lua` | groups urls / paths / registry keys / format strings |
| `trace_calls.lua` | debugger plugin: single-steps a stopped target and logs calls |

## limits and safety

- plugins run on the ui thread with a time limit (30 s by default), so a runaway
  loop is cancelled instead of freezing the program.
- an error in a plugin is reported in the output panel; it does not crash ceasta.
- the `ceasta-cli` sandbox and the tests never start or attach to a process.
