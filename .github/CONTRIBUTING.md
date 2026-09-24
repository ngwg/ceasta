# contributing to ceasta

thanks for looking. issues and pull requests are welcome.

## license

ceasta is [GPLv3](../LICENSE). anything you contribute is shipped under the same
license.

## building

see [build](../README.md#build) in the readme — everything is vendored, you only
need a compiler (visual studio 2022 on windows, gcc or clang on linux).

## where things live

see [code](../README.md#code) in the readme. roughly: `src/core/` has no ui
(loaders, analysis, decompiler, debuggers, lua), `src/ui/` is one file per panel,
`src/cli/` is `ceasta-cli`.

## pull requests

- keep a change focused on one thing
- match the code around it: 4-space indent, short lowercase comments, no new
  dependencies without talking about it first (everything is vendored on purpose)
- it has to build on windows (msvc) and linux (gcc) — ci checks both on every push
- say what you changed and how you checked it

## bugs

use the bug report template. the most useful thing is the kind of file
(e.g. "64-bit pe exe", "elf x86 pie") and, if you can share it, the file itself
or where to get it.

## plugins

plugins are plain lua, see the [lua guide](../docs/lua.md). a good general plugin
can go in `plugins/` through a pull request.
