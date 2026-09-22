# changelog

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
