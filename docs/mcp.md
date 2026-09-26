# connect an AI to ceasta (MCP)

ceasta has a built-in [Model Context Protocol](https://modelcontextprotocol.io) server, so an
AI client — Claude Code, Claude Desktop, Cursor, or anything that speaks MCP — can read the
binary you're looking at, decompile it, rename functions, and, when you allow it, drive the
debugger. No plugin, no bridge: it's one command.

```
ceasta-cli mcp <file>                 # talk over stdin/stdout (what the clients launch)
ceasta-cli mcp <file> --http 8744     # or a localhost http server
ceasta-cli mcp <file> --allow-debug   # also expose the tools that run the program
ceasta-cli mcp <file> --allow-lua     # also expose run_lua (runs arbitrary lua)
ceasta-cli mcp <file> --arch arm64    # a universal mac file: its arm64 part (default x86_64)
```

## from the app

In ceasta itself: **AI > Connect an AI...**, then **Start the server**. It serves the file you
have open at `http://127.0.0.1:8744/mcp` (the port is yours to change there) and shows what to
paste into your client — for Claude Code:

```
claude mcp add --transport http ceasta http://127.0.0.1:8744/mcp
```

Cursor, VS Code and other clients take the same URL as an MCP server. The AI then works on
exactly what you see: its renames, comments and breakpoints show up in the window straight away
(and wait for your save, like your own edits), and with *let it use the debugger* ticked its
debug session is the window's debugger, so you can watch it step. Every call is logged in the
output panel, and the status bar shows the server and its call count. The server stops when
you close ceasta.

## quick start (command line)

**Claude Code** — one line:

```
claude mcp add ceasta -- ceasta-cli mcp /path/to/target.exe
```

**Claude Desktop / Cursor** — add this to the client's MCP config
(`claude_desktop_config.json`, or Cursor's `mcp.json`):

```json
{
  "mcpServers": {
    "ceasta": {
      "command": "ceasta-cli",
      "args": ["mcp", "/path/to/target.exe"]
    }
  }
}
```

Then ask the model things like *"what does the function at 0x401000 do?"*, *"find the code that
builds the license string and rename the functions"*, or *"set a breakpoint on check_key, run
it with the argument test123, and tell me what the comparison is."*

## what the AI can do

Always on (read and annotate):

| tool | what it does |
|------|--------------|
| `get_binary_info` | format, arch, entry, segments, counts, and the file info: security flags, hashes, sections with entropy, packer warnings |
| `list_functions` / `list_strings` / `list_imports` / `list_exports` | browse, with a filter |
| `decompile_function` | C-like pseudocode (x86 / x64), with the function's variables |
| `decompile_with_kuna` | the same function from [kuna](https://github.com/Noelo-Lab/kuna), a second decompiler — only there when kuna is installed (on PATH, set in the app, or `--kuna-path`) |
| `disassemble` / `disassemble_function` | the listing, with names (arm64 too) |
| `get_xrefs_to` / `get_xrefs_from` | callers and callees |
| `read_bytes` / `search_bytes` / `lookup` / `get_basic_blocks` | bytes, patterns, what's at an address, the CFG |
| `diff_binary` | compare with another file, function by function |
| `rename` / `set_comment` | record what it learns (saved with the project) |
| `rename_variable` / `set_variable_type` / `set_function_prototype` | name and type a function's variables, give it a prototype (`int check_key(const char* key)`) — the pseudocode and the callers use them |
| `define_types` / `list_types` | declare structs, unions, enums and typedefs in c, and read them back with each field's offset — a variable typed as a pointer to a struct reads `p->field` |
| `create_struct_from_usage` | a struct from how a variable is used (a field at every offset read or written through it), declared and applied; rename its fields with `define_types` |
| `suggest_name` / `suggest_variable_name` | propose a name with a reason instead of applying it: it waits for you in **AI > Review suggested names** |
| `save_project` | write a committable `<file>.ceasta` |

With `--allow-debug` (these run the program on your machine):

`debug_start` / `debug_continue` / `debug_step_into` / `debug_step_over` / `debug_step_out` /
`debug_step_back` / `debug_run_to` / `debug_pause` / `debug_kill` / `debug_status`,
`debug_set_breakpoint` (with an optional condition like `rdi == 3`) / `debug_remove_breakpoint` /
`debug_list_breakpoints`, `debug_watch` (stop when memory is written or read),
`debug_get_registers` / `debug_set_register`, `debug_read_memory` / `debug_write_memory`,
`debug_backtrace` (the call stack), `debug_memory_map`, `debug_trace` (record indirect call
targets), `debug_call` (call a function and get its result), and `debug_decompile_here` (the
pseudocode of the function you're stopped in, with the current line marked and the argument
registers' live values).

With `--allow-lua`: `run_lua`, which runs any Lua with ceasta's [scripting API](lua.md) — and
Lua's `io` / `os`, so it has your file access.

## ready-made prompts

The server also offers prompts — in Claude Code they're commands like
`/mcp__ceasta__triage`:

| prompt | what it asks for |
|--------|------------------|
| `triage` | a first look: what the binary is, what stands out, where to read next |
| `explain_function` | what one function does, its parameters and result, with suggested names |
| `rename_pass` | names for the unnamed functions (`sub_...`), bottom-up, as suggestions you review |
| `find_crypto` | crypto api calls, well-known constants, xor loops |
| `trace_function` | run to a function under the debugger and watch what it gets and returns (with `--allow-debug`) |

## reviewing what the AI names

`rename` applies a name right away. `suggest_name` / `suggest_variable_name` (what
`rename_pass` uses) don't: each suggestion is checked (a taken or malformed name is refused),
saved with the project, and listed in **AI > Review suggested names** — the status bar says
how many are waiting. Accept or reject each one (Enter / Delete), or all at once; accepting is
one undo step.

## a note on trust

- The read and annotate tools only touch the file and ceasta's own project data.
- `--allow-debug` (*let it use the debugger* in the app) **runs the target program** on your
  machine. Don't point it at malware outside a VM, the same as you wouldn't run that program
  yourself.
- `--allow-lua` (*let it run Lua*) lets the model run arbitrary code. Turn it on only when you
  want that.
- The http server only answers programs on this machine: it listens on 127.0.0.1, and turns
  away requests that come from a web page of another site (`Origin`) or name another host
  (`Host`, so a dns-rebinding page can't reach it either).

Names and comments the AI writes are plain text you can read, diff, and commit: in the app they
are saved with yours (File > Save, or a `.ceasta` project via File > Save project as...);
`ceasta-cli mcp` writes them right away, to ceasta's user folder and to `<file>.ceasta` next to
the binary once `save_project` has created it.
