cmake_minimum_required(VERSION 3.16)
project(ceasta VERSION 0.6.0 LANGUAGES C CXX)

# ceasta: disassembler + debugger.
#   core (loaders, analysis, lua, debugger) builds everywhere, the gui is windows / directx 11.
#   cmake -B build && cmake --build build --config Release

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "build type" FORCE)
endif()

if(WIN32)
    set(ceasta_gui_default ON)
else()
    set(ceasta_gui_default OFF)
endif()
option(CEASTA_BUILD_GUI "build the gui (windows only)" ${ceasta_gui_default})

if(MSVC)
    # static runtime, so the exe runs without the vc++ redistributable
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
    add_compile_options(/utf-8 /MP)
endif()

find_package(Threads REQUIRED)

# ---- third party ----

file(GLOB capstone_sources CONFIGURE_DEPENDS
    third_party/capstone/*.c
    third_party/capstone/arch/X86/*.c)
add_library(capstone STATIC ${capstone_sources})
target_include_directories(capstone PUBLIC third_party/capstone/include PRIVATE third_party/capstone)
target_compile_definitions(capstone PUBLIC CAPSTONE_HAS_X86 CAPSTONE_USE_SYS_DYN_MEM)

file(GLOB lua_sources CONFIGURE_DEPENDS third_party/lua/*.c)
# compiled as c++ so lua errors are exceptions that unwind c++ frames (not longjmp)
set_source_files_properties(${lua_sources} PROPERTIES LANGUAGE CXX)
add_library(lua STATIC ${lua_sources})
target_include_directories(lua PUBLIC third_party/lua)
if(UNIX)
    target_compile_definitions(lua PRIVATE LUA_USE_POSIX)
endif()

set(imgui_sources
    third_party/imgui/imgui.cpp
    third_party/imgui/imgui_draw.cpp
    third_party/imgui/imgui_tables.cpp
    third_party/imgui/imgui_widgets.cpp)
add_library(imgui STATIC ${imgui_sources})
target_include_directories(imgui PUBLIC third_party/imgui third_party/imgui/backends)

foreach(lib capstone lua imgui)
    if(MSVC)
        target_compile_options(${lib} PRIVATE /W0)
    else()
        target_compile_options(${lib} PRIVATE -w)
    endif()
endforeach()

function(ceasta_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W3 /sdl)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra)
    endif()
endfunction()

# ---- core: loaders, analysis, database, lua, debugger ----

add_library(ceasta_core STATIC
    src/core/analysis.cpp
    src/core/binary.cpp
    src/core/database.cpp
    src/core/debugger.cpp
    src/core/decompiler.cpp
    src/core/disasm.cpp
    src/core/elf.cpp
    src/core/lua_host.cpp
    src/core/os.cpp
    src/core/pe.cpp)
target_include_directories(ceasta_core PUBLIC src)
target_link_libraries(ceasta_core PUBLIC capstone lua Threads::Threads)
if(WIN32)
    target_link_libraries(ceasta_core PUBLIC shell32)
endif()
ceasta_warnings(ceasta_core)

# ---- ui: app state + panels, no platform code ----

set(ui_sources
    src/app.cpp
    src/ui/bottom_panel.cpp
    src/ui/cpu_panel.cpp
    src/ui/dialogs.cpp
    src/ui/graph_view.cpp
    src/ui/ida_view.cpp
    src/ui/left_panel.cpp
    src/ui/pseudo_view.cpp
    src/ui/right_panel.cpp
    src/ui/status_bar.cpp
    src/ui/top_bar.cpp)
add_library(ceasta_ui STATIC ${ui_sources})
target_link_libraries(ceasta_ui PUBLIC ceasta_core imgui)
ceasta_warnings(ceasta_ui)

# ---- programs ----

add_executable(ceasta-cli src/cli/main.cpp)
target_link_libraries(ceasta-cli PRIVATE ceasta_core)
ceasta_warnings(ceasta-cli)

if(CEASTA_BUILD_GUI)
    add_executable(ceasta WIN32
        src/main.cpp
        src/ceasta.rc
        third_party/imgui/backends/imgui_impl_win32.cpp
        third_party/imgui/backends/imgui_impl_dx11.cpp)
    target_compile_definitions(ceasta PRIVATE UNICODE _UNICODE)
    target_link_libraries(ceasta PRIVATE ceasta_ui d3d11 dxgi dwmapi comdlg32)
    if(MSVC)
        target_link_libraries(ceasta PRIVATE d3dcompiler)
    else()
        target_link_libraries(ceasta PRIVATE d3dcompiler_47)
    endif()
    ceasta_warnings(ceasta)
    # plugins next to the program, so it finds them when run from the build folder
    add_custom_command(TARGET ceasta POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/plugins $<TARGET_FILE_DIR:ceasta>/plugins)
endif()

# ---- install / package layout (what the installer ships) ----

install(TARGETS ceasta-cli RUNTIME DESTINATION .)
if(CEASTA_BUILD_GUI)
    install(TARGETS ceasta RUNTIME DESTINATION .)
endif()
install(DIRECTORY plugins/ DESTINATION plugins)
install(FILES README.md docs/CHANGELOG.md docs/THIRD_PARTY_NOTICES.md DESTINATION .)
