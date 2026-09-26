cmake_minimum_required(VERSION 3.16)
# macos: runs on 11 (big sur, the first for apple silicon) and later. set before project()
set(CMAKE_OSX_DEPLOYMENT_TARGET "11.0" CACHE STRING "the oldest macos ceasta runs on")
project(ceasta VERSION 0.12.0 LANGUAGES C CXX)

# ceasta: disassembler + debugger.
#   core (loaders, analysis, lua, debugger) builds everywhere. the gui: windows / directx 11,
#   linux (glfw + opengl, -DCEASTA_LINUX_GUI=ON), macos (ceasta.app, glfw + opengl).
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
    third_party/capstone/arch/X86/*.c
    third_party/capstone/arch/AArch64/*.c)
add_library(capstone STATIC ${capstone_sources})
target_include_directories(capstone PUBLIC third_party/capstone/include PRIVATE third_party/capstone)
target_compile_definitions(capstone PUBLIC CAPSTONE_HAS_X86 CAPSTONE_HAS_ARM64 CAPSTONE_USE_SYS_DYN_MEM)

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
    src/core/bp_cond.cpp
    src/core/database.cpp
    src/core/dbg_stack.cpp
    src/core/dbg_trace.cpp
    src/core/debugger.cpp
    src/core/debugger_linux.cpp
    src/core/debugger_steps.cpp
    src/core/decompiler.cpp
    src/core/demangle.cpp
    src/core/diff.cpp
    src/core/disasm.cpp
    src/core/elf.cpp
    src/core/golang.cpp
    src/core/exchange.cpp
    src/core/fileinfo.cpp
    src/core/json.cpp
    src/core/kuna.cpp
    src/core/lua_host.cpp
    src/core/macho.cpp
    src/core/mcp.cpp
    src/core/mcp_transport.cpp
    src/core/os.cpp
    src/core/pe.cpp
    src/core/process.cpp
    src/core/protos.cpp
    src/core/search.cpp
    src/core/signatures.cpp)
target_include_directories(ceasta_core PUBLIC src)
target_link_libraries(ceasta_core PUBLIC capstone lua Threads::Threads)
if(WIN32)
    target_link_libraries(ceasta_core PUBLIC shell32 ws2_32)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
    # the ptrace based debugger (x64 linux host, debugs 64 and 32 bit programs)
    target_compile_definitions(ceasta_core PUBLIC CEASTA_LINUX_DEBUGGER)
endif()
ceasta_warnings(ceasta_core)

# ---- ui: app state + panels, no platform code ----

set(ui_sources
    src/app.cpp
    src/app_mcp.cpp
    src/ui/bottom_panel.cpp
    src/ui/cpu_panel.cpp
    src/ui/dialogs.cpp
    src/ui/graph_view.cpp
    src/ui/ida_view.cpp
    src/ui/left_panel.cpp
    src/ui/palette.cpp
    src/ui/pseudo_view.cpp
    src/ui/right_panel.cpp
    src/ui/status_bar.cpp
    src/ui/top_bar.cpp)
add_library(ceasta_ui STATIC ${ui_sources})
target_link_libraries(ceasta_ui PUBLIC ceasta_core imgui)
ceasta_warnings(ceasta_ui)

# ---- programs ----

add_executable(ceasta-cli src/cli/main.cpp src/cli/dbg_repl.cpp src/cli/mcp_cmd.cpp)
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

# ---- experimental linux gui (glfw + opengl3), off by default ----
# cmake -B build -DCEASTA_LINUX_GUI=ON  (needs libglfw3-dev and an opengl dev package)
option(CEASTA_LINUX_GUI "build the experimental linux gui (glfw + opengl3)" OFF)
if(CEASTA_LINUX_GUI AND NOT WIN32 AND NOT APPLE)
    find_package(glfw3 QUIET)
    find_package(OpenGL QUIET)
    if(glfw3_FOUND AND OpenGL_FOUND)
        add_executable(ceasta
            src/main_glfw.cpp
            third_party/imgui/backends/imgui_impl_glfw.cpp
            third_party/imgui/backends/imgui_impl_opengl3.cpp)
        target_link_libraries(ceasta PRIVATE ceasta_ui glfw OpenGL::GL)
        add_custom_command(TARGET ceasta POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/plugins $<TARGET_FILE_DIR:ceasta>/plugins)
    else()
        message(WARNING "CEASTA_LINUX_GUI is on but glfw3 / OpenGL were not found; skipping the gui")
    endif()
endif()

# ---- macos app (glfw + opengl3): ceasta.app ----
# needs glfw: brew install glfw, or -DCMAKE_PREFIX_PATH=<where a glfw build is installed>
if(APPLE)
    option(CEASTA_MAC_GUI "build ceasta.app (needs glfw)" ON)
endif()
if(APPLE AND CEASTA_MAC_GUI)
    find_package(glfw3 QUIET)
    find_package(OpenGL QUIET)
    if(glfw3_FOUND AND OpenGL_FOUND)
        enable_language(OBJCXX)
        set(mac_icon ${CMAKE_CURRENT_SOURCE_DIR}/packaging/macos/ceasta.icns)
        set_source_files_properties(${mac_icon} PROPERTIES MACOSX_PACKAGE_LOCATION Resources)
        add_executable(ceasta MACOSX_BUNDLE
            src/main_glfw.cpp
            src/mac_platform.mm
            third_party/imgui/backends/imgui_impl_glfw.cpp
            third_party/imgui/backends/imgui_impl_opengl3.cpp
            ${mac_icon})
        # what a static glfw needs too
        target_link_libraries(ceasta PRIVATE ceasta_ui glfw OpenGL::GL "-framework Cocoa" "-framework IOKit"
            "-framework CoreFoundation" "-framework QuartzCore")
        set_target_properties(ceasta PROPERTIES
            MACOSX_BUNDLE_INFO_PLIST ${CMAKE_CURRENT_SOURCE_DIR}/packaging/macos/Info.plist.in
            MACOSX_BUNDLE_SHORT_VERSION_STRING ${PROJECT_VERSION}
            MACOSX_BUNDLE_BUNDLE_VERSION ${PROJECT_VERSION})
        ceasta_warnings(ceasta)
        # the plugins that ship with it live in the bundle's Resources folder
        add_custom_command(TARGET ceasta POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/plugins
                    $<TARGET_BUNDLE_CONTENT_DIR:ceasta>/Resources/plugins)
    else()
        message(WARNING "glfw or OpenGL not found: ceasta.app isn't built (brew install glfw)")
    endif()
endif()

# ---- install / package layout (what the installer ships) ----

install(TARGETS ceasta-cli RUNTIME DESTINATION .)
if(CEASTA_BUILD_GUI)
    install(TARGETS ceasta RUNTIME DESTINATION .)
endif()
install(DIRECTORY plugins/ DESTINATION plugins)
install(FILES README.md LICENSE docs/CHANGELOG.md docs/THIRD_PARTY_NOTICES.md DESTINATION .)
