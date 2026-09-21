# changelog

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
