// drives the real ui code headless (imgui null backend) with imgui asserts turned into
// hard failures: loads each fixture, opens every dialog and view, then clicks, drags and
// types at random for a while. any imgui misuse or crash fails the test.
// usage: ceasta-ui-tests <fixtures-dir> [plugins-dir]
#include "app.h"
#include "core/os.h"
#include "imgui.h"
#include "imgui_impl_null.h"
#include "theme.h"
#include "ui_snapshot.h"
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <thread>

static int g_fails = 0;
#define EXPECT(cond, msg)                                           \
    do {                                                            \
        if (cond) {                                                 \
            printf("  ok   %s\n", msg);                             \
        } else {                                                    \
            printf("  FAIL %s  (%s:%d)\n", msg, __FILE__, __LINE__); \
            g_fails++;                                              \
        }                                                           \
    } while (0)

static std::string g_snap_dir; // CEASTA_UI_SNAPSHOT=<dir> writes screenshots there

static void frame(app_state& s, const char* snap = nullptr)
{
    app_pre_frame(s);
    ImGui_ImplNull_NewFrame();
    ImGui::NewFrame();
    app_frame(s);
    ImGui::Render();
    ImGui_ImplNullRender_RenderDrawData(ImGui::GetDrawData());
    if (snap && !g_snap_dir.empty())
        snapshot::save(ImGui::GetDrawData(), os::join(g_snap_dir, std::string(snap) + ".ppm"));
}

// a couple of frames so layout settles, then a screenshot
static void snap(app_state& s, const char* name)
{
    for (int i = 0; i < 3; i++)
        frame(s);
    frame(s, name);
}

static void frames(app_state& s, int n)
{
    for (int i = 0; i < n; i++)
        frame(s);
}

static void key(app_state& s, ImGuiKey k, ImGuiKey mod = ImGuiKey_None)
{
    ImGuiIO& io = ImGui::GetIO();
    if (mod != ImGuiKey_None)
        io.AddKeyEvent(mod, true);
    io.AddKeyEvent(k, true);
    frame(s);
    io.AddKeyEvent(k, false);
    if (mod != ImGuiKey_None)
        io.AddKeyEvent(mod, false);
    frame(s);
}

static bool wait_loaded(app_state& s)
{
    for (int i = 0; i < 3000 && app_loading(s); i++) {
        frame(s);
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    frame(s);
    return !app_loading(s) && s.db != nullptr;
}

static void exercise_file(app_state& s, const std::string& path)
{
    printf("\n[%s]\n", path.c_str());
    app_open(s, path);
    EXPECT(wait_loaded(s), "file loaded through the background job");
    if (!s.db)
        return;
    std::string base = path.substr(path.find_last_of("/\\") + 1);
    snap(s, (base + "-listing").c_str());
    EXPECT(!s.db->rows().empty(), "listing has rows");

    // views and panels
    s.view = center_view::graph;
    frames(s, 5);
    {
        // graph of the function with the most blocks among the first few, it looks the most like a graph
        const function* best = nullptr;
        size_t best_n = 0;
        for (size_t i = 0; i < s.db->an.funcs.size() && i < 200; i++) {
            cfg g;
            if (build_cfg(s.db->bin, s.db->an, s.db->an.funcs[i].start, g) && g.blocks.size() > best_n && g.blocks.size() < 16) {
                best_n = g.blocks.size();
                best = &s.db->an.funcs[i];
            }
        }
        if (best)
            app_jump(s, best->start);
        snap(s, (base + "-graph").c_str());
    }
    for (size_t i = 0; i < s.db->an.funcs.size() && i < 40; i++) {
        app_jump(s, s.db->an.funcs[i].start);
        frames(s, 2);
    }
    EXPECT(true, "graph view drew 40 functions");
    s.view = center_view::listing;
    for (int t = 0; t < 5; t++) {
        s.right_tab_request = t;
        frames(s, 2);
    }
    for (int t = 0; t < 4; t++) {
        s.bottom_tab_request = t;
        frames(s, 2);
    }
    snprintf(s.func_filter, sizeof(s.func_filter), "sub");
    snprintf(s.info_filter, sizeof(s.info_filter), "a");
    frames(s, 3);
    s.func_filter[0] = s.info_filter[0] = 0;
    EXPECT(true, "all tabs drawn with and without filters");

    // every dialog, closed with escape
    dialog_kind kinds[] = {dialog_kind::jump, dialog_kind::rename, dialog_kind::comment, dialog_kind::xrefs, dialog_kind::search,
        dialog_kind::open_raw, dialog_kind::attach, dialog_kind::run_args, dialog_kind::about, dialog_kind::shortcuts};
    for (dialog_kind k : kinds) {
        app_open_dialog_kind(s, k, s.cursor);
        frames(s, 3);
        if (k == dialog_kind::xrefs)
            snap(s, (base + "-xrefs-dialog").c_str());
        key(s, ImGuiKey_Escape);
        frames(s, 2);
    }
    EXPECT(s.dialog.kind == dialog_kind::none, "every dialog opens and closes");

    // keyboard: follow a direct call with enter, come back with esc
    uint64_t call_at = 0, call_to = 0;
    for (const function& f : s.db->an.funcs) {
        for (uint64_t a = f.start; a < f.end && !call_at;) {
            insn in;
            if (!s.db->decode(a, in))
                break;
            if (in.kind == flow::call && in.has_target && !in.indirect && s.db->bin.is_mapped(in.target)) {
                call_at = a;
                call_to = in.target;
            }
            a = in.next();
        }
        if (call_at)
            break;
    }
    if (call_at) {
        app_jump(s, call_at);
        frames(s, 2);
        key(s, ImGuiKey_Enter);
        EXPECT(s.cursor == call_to, "enter follows a call to its target");
        key(s, ImGuiKey_Escape);
        EXPECT(s.cursor == call_at, "esc goes back to the call");
    }
    key(s, ImGuiKey_F2);
    EXPECT(s.db->breakpoints.count(s.cursor) == 1, "F2 sets a breakpoint");
    key(s, ImGuiKey_F2);
    EXPECT(s.db->breakpoints.count(s.cursor) == 0, "F2 again removes it");
    key(s, ImGuiKey_Equal, ImGuiMod_Ctrl);
    key(s, ImGuiKey_Minus, ImGuiMod_Ctrl);
    key(s, ImGuiKey_Space);
    key(s, ImGuiKey_Space);
    std::string err;
    EXPECT(s.db->set_name(s.cursor, "ui_test_name", err), "rename through the database");
    app_names_changed(s);
    frames(s, 3);

    // plugins and console
    for (size_t i = 0; i < s.lua.commands().size(); i++) {
        s.lua.run_command(i);
        app_names_changed(s);
        frames(s, 2);
    }
    snprintf(s.console, sizeof(s.console), "%s", "print(ceasta.name(ceasta.here()))");
    s.lua.run_console(s.console);
    frames(s, 3);
    EXPECT(true, "plugin commands and console ran");
}

// random input for a while: clicks, drags, wheel, shortcut keys. deterministic seed
static void monkey(app_state& s, int n)
{
    ImGuiIO& io = ImGui::GetIO();
    uint32_t seed = 12345;
    auto rnd = [&]() {
        seed = seed * 1664525u + 1013904223u;
        return seed >> 8;
    };
    const ImGuiKey keys[] = {ImGuiKey_G, ImGuiKey_N, ImGuiKey_X, ImGuiKey_Space, ImGuiKey_Escape, ImGuiKey_Enter,
        ImGuiKey_UpArrow, ImGuiKey_DownArrow, ImGuiKey_PageDown, ImGuiKey_PageUp, ImGuiKey_F2, ImGuiKey_F9, ImGuiKey_F7,
        ImGuiKey_F8, ImGuiKey_F1, ImGuiKey_Tab, ImGuiKey_A, ImGuiKey_1, ImGuiKey_Backspace, ImGuiKey_Semicolon};
    for (int i = 0; i < n; i++) {
        float x = (float)(rnd() % 1920), y = (float)(rnd() % 1080);
        io.AddMousePosEvent(x, y);
        switch (rnd() % 8) {
        case 0:
        case 1:
            io.AddMouseButtonEvent(0, true);
            frame(s);
            io.AddMouseButtonEvent(0, false);
            break;
        case 2:
            io.AddMouseButtonEvent(1, true);
            frame(s);
            io.AddMouseButtonEvent(1, false);
            break;
        case 3:
            io.AddMouseWheelEvent(0, (rnd() % 2) ? 1.0f : -1.0f);
            break;
        case 4: { // drag
            io.AddMouseButtonEvent(0, true);
            frame(s);
            io.AddMousePosEvent(x + (float)(rnd() % 200) - 100, y + (float)(rnd() % 200) - 100);
            frame(s);
            io.AddMouseButtonEvent(0, false);
            break;
        }
        case 5: {
            ImGuiKey k = keys[rnd() % (sizeof(keys) / sizeof(keys[0]))];
            io.AddKeyEvent(k, true);
            frame(s);
            io.AddKeyEvent(k, false);
            break;
        }
        default:
            break;
        }
        frame(s);
        if (app_loading(s))
            wait_loaded(s);
    }
    // close whatever is open
    for (int i = 0; i < 4; i++)
        key(s, ImGuiKey_Escape);
}

int main(int argc, char** argv)
{
    std::string fixtures = argc > 1 ? argv[1] : "tests/fixtures";
    std::string plugins = argc > 2 ? argv[2] : "plugins";

    // keep settings and saved names out of the real user folder
    std::filesystem::path tmp = std::filesystem::temp_directory_path() / "ceasta-ui-test";
    std::filesystem::create_directories(tmp);
#ifdef _WIN32
    _putenv_s("APPDATA", tmp.string().c_str());
#else
    setenv("XDG_CONFIG_HOME", tmp.string().c_str(), 1);
#endif
    // user plugins folder = the repo's plugins, so the plugin menu has real commands
    std::filesystem::path user_plugins = tmp / "ceasta" / "plugins";
    std::filesystem::create_directories(user_plugins);
    for (const char* p : {"hello.lua", "find_crypto.lua", "name_wrappers.lua", "strings_report.lua", "trace_calls.lua"})
        std::filesystem::copy_file(std::filesystem::path(plugins) / p, user_plugins / p, std::filesystem::copy_options::overwrite_existing);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui::GetIO().IniFilename = nullptr;
    ImGui_ImplNull_Init();
    theme::apply_theme();
    theme::load_fonts();

    static app_state s;
    s.sandboxed = true;
    platform_api platform;
    std::string next_open = os::join(fixtures, "sample32.exe");
    platform.open_file_dialog = [&](const char*) { return next_open; };
    platform.set_title = [](const std::string&) {};
    platform.quit = []() {};
    if (const char* d = getenv("CEASTA_UI_SNAPSHOT"))
        g_snap_dir = d;
    printf("[startup]\n");
    app_init(s, platform, {});
    frames(s, 10);
    snap(s, "welcome");
    EXPECT(s.db == nullptr, "starts on the welcome screen");
    EXPECT(s.lua.commands().size() >= 5, "plugins loaded into the menu");

    for (const char* f : {"sample64.exe", "sample32.exe", "sample64.dll", "sample64.elf", "sample32.elf"})
        exercise_file(s, os::join(fixtures, f));

    printf("\n[monkey]\n");
    monkey(s, 1500);
    EXPECT(true, "1500 random input frames without an imgui assert or crash");

    printf("\n[close + reopen]\n");
    app_close_file(s);
    frames(s, 5);
    EXPECT(s.db == nullptr, "closing returns to the welcome screen");
    app_open(s, os::join(fixtures, "sample64.elf"));
    EXPECT(wait_loaded(s), "reopen after close");
    EXPECT(s.db && s.db->name_at(s.db->bin.entry) != "", "entry has a name after reload");

    app_shutdown(s);
    ImGui_ImplNull_Shutdown();
    ImGui::DestroyContext();
    std::error_code ec;
    std::filesystem::remove_all(tmp, ec);
    printf("\n%s (%d failed)\n", g_fails ? "FAILED" : "all ui checks passed", g_fails);
    return g_fails ? 1 : 0;
}
