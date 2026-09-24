# ceasta plugins

these are Lua scripts. ceasta loads every `.lua` file in this folder at startup
and again on **Plugins → Reload plugins**. it also loads plugins from your user
folder, so you can add your own without touching the install:

- next to the program: `<install>/plugins/`
- per user: `%APPDATA%\ceasta\plugins\` (windows), `~/.config/ceasta/plugins/` (linux)

## the files here

| file | what it does |
|------|--------------|
| `hello.lua` | one command that prints a file summary — copy it to start your own |
| `find_crypto.lua` | flags and renames functions that look like crypto / hashing |
| `name_wrappers.lua` | renames one-call wrapper functions to `w_<callee>` |
| `strings_report.lua` | groups urls / paths / registry keys / format strings |
| `trace_calls.lua` | debugger plugin: single-steps a stopped target and logs calls |

## quick start

```lua
ceasta.register_command("My command", function()
    local f = ceasta.file()               -- { name, format, arch, kind, base, entry, bits, has_entry }
    ceasta.log("loaded " .. f.name)
    for _, fn in ipairs(ceasta.functions()) do   -- { addr, size, name, thunk }
        if fn.size > 0x400 then
            ceasta.set_comment(fn.addr, "big function")
        end
    end
end, "optional help text")
```

## the full guide

the complete api (`ceasta.*`, the `ceasta.dbg.*` debugger calls, events, the
cli, and more examples) is in the **Lua scripting guide**:

https://github.com/ngwg/ceasta/blob/main/docs/lua.md

plugins run on the ui thread with a 30 s time limit, so a runaway loop can't
freeze the program.
