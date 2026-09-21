# ceasta

small reversing tool in c++ with imgui. still wip.

right now it just opens a window with a fake ida-like layout so i can test the ui. no real binary loading yet.

# build

- needs visual studio 2022 + windows sdk
- open `ceasta.sln` and hit build (x64)
- imgui is already in `third_party/imgui`, nothing else to install

# run

just run it, it loads with mock data. use the view menu to show/hide panels.

# layout

- `src/` - app code
- `third_party/imgui` - imgui
