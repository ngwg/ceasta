# ceasta plugins

Plugins are plain [Lua](https://www.lua.org/) scripts. ceasta loads every `.lua`
file in this folder at startup and again whenever you pick **Plugins → Reload plugins**.
It also loads plugins from your user folder, so you can add your own without
touching the install:

- next to the program: `<install>/plugins/`
- per user: `%APPDATA%\ceasta\plugins\` (Windows), `~/.config/ceasta/plugins/` (Linux)

A plugin usually registers one or more commands. Each command shows up in the
**Plugins** menu. You can also type Lua straight into the prompt of the
**Output** tab at the bottom (**Plugins → Lua console** jumps there).

Plugins run without the gui too: `ceasta-cli run file.exe my_plugin.lua` loads
the file, runs the script and then every command it registered. Add `--debug`
to start the file under the debugger first (Windows), so `ceasta.dbg.*` works.

## The files here

| file | what it does |
|------|--------------|
| `hello.lua` | one command that prints a file summary — copy it to start your own |
| `find_crypto.lua` | flags and renames functions that look like crypto / hashing |
| `name_wrappers.lua` | renames one-call wrapper functions to `w_<callee>` |
| `strings_report.lua` | groups urls / paths / registry keys / format strings |
| `trace_calls.lua` | debugger plugin: single-steps a stopped target and logs calls |

## Writing a plugin

```lua
-- addr arguments accept a number, a hex string ("0x401000"), or a name ("main").
-- addresses come back as integers.
ceasta.register_command("My command", function()
    local f = ceasta.file()                 -- { name, format, arch, kind, base, entry, bits, has_entry }
    ceasta.log("loaded " .. f.name)
    for _, fn in ipairs(ceasta.functions()) do   -- { addr, size, name, thunk }
        if fn.size > 0x400 then
            ceasta.set_comment(fn.addr, "big function")
        end
    end
end, "optional help text")

-- react to app events: "load", "stop" (arg = pc), "exit" (arg = code)
ceasta.on("load", function() ceasta.log("analysis finished") end)
```

## API reference

`ceasta.*`

- `log(...)`, `warn(msg)` — write to the output log (`print` also works)
- `file()` — `{ path, name, format, arch, kind, base, entry, has_entry, bits }`
- `read(addr, n)` → string · `read_u8/16/32/64(addr)` · `read_i32(addr)` · `read_ptr(addr)` · `read_cstr(addr [,max])`
- `is_mapped(addr)` · `is_code(addr)`
- `name(addr)` · `location(addr)` · `set_name(addr, name)` → ok[,err] · `resolve(text)` → addr|nil
- `comment(addr)` · `set_comment(addr, text)`
- `disasm(addr)` → `{ addr, size, mnemonic, operands, text, flow, target? }` · `next_addr(addr)`
- `decompile(addr)` → a string of c-like pseudocode for the function containing `addr`
  (`flow` is `"normal"`, `"jump"`, `"cond"`, `"call"`, `"ret"` or `"stop"`, `target` is set for direct branches)
- `functions()` · `imports()` · `exports()` · `strings()` · `xrefs_to(addr)` — arrays of tables
- `find(pattern [,from [,max]])` — byte search like `"48 8b ?? 05"`, returns addresses
- `here()` · `goto_addr(addr)` — the cursor in the disassembly view
- `register_command(name, fn [,help])` · `on(event, fn)`

`ceasta.dbg.*` (Windows build, while debugging)

- `state()` → `"none" | "running" | "stopped"` · `pc()` · `sp()`
- `reg(name)` · `regs()` → table · `read(addr, n)` · `read_ptr(addr)` · `write(addr, bytes)` → ok[,err]
- `step_into()` · `step_over()` · `run_to(addr)` — wait until the target stops again, return true when it did
- `cont()` · `pause()` — return right away, `wait([ms])` waits for the next stop and returns the state
- `add_bp(addr)` · `del_bp(addr)` — runtime addresses
- `to_static(addr)` → listing address or nil · `to_runtime(addr)` — they differ when aslr moved the program

Plugins run on the UI thread with a time limit (30 s by default) so a runaway
loop can't freeze the program.
