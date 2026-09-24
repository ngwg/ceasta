#pragma once
#include "core/database.h"
#include "core/debugger.h"
#include "core/lua_host.h"
#include "theme.h"
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <vector>

// what the window host provides (main.cpp on windows, stubs in the ui tests)
struct platform_api {
    std::function<std::string(const char* title)> open_file_dialog; // "" when cancelled
    std::function<void(const std::string&)> set_title;
    std::function<void()> quit;
};

struct log_line {
    std::string text;
    int level = 0; // 0 info, 1 warning, 2 error, 3 console echo
};

// file load + analysis running on a worker thread
struct load_job {
    std::thread worker;
    analysis_progress progress;
    std::atomic<bool> done{false};
    std::unique_ptr<database> result;
    std::string error;
    std::string path;
};

enum class center_view { listing, graph, pseudo };

enum class dialog_kind { none, jump, rename, comment, xrefs, search, open_raw, attach, run_args, about, shortcuts };

struct dialog_state {
    dialog_kind kind = dialog_kind::none;
    bool just_opened = false;
    uint64_t addr = 0;
    char buf[512] = {};
    std::string error;
    std::vector<uint64_t> results;
    int raw_arch = 1; // 0 x86, 1 x64
    char raw_base[32] = "0";
    std::vector<process_info> procs;
    char filter[128] = {};
};

struct app_state {
    platform_api platform;
    std::unique_ptr<database> db;
    std::unique_ptr<load_job> job;
    lua_host lua;
    debugger dbg;
    uint64_t version = 0; // bumps whenever names / comments / analysis change

    // navigation
    uint64_t cursor = 0;
    std::vector<uint64_t> back;
    std::vector<uint64_t> forward;
    bool scroll_to_cursor = false;
    center_view view = center_view::listing;

    // layout, in unscaled pixels, saved in settings.ini
    float left_w = 300.0f;
    float right_w = 400.0f;
    float bottom_h = 230.0f;
    float right_split = 0.5f;
    bool show_left = true;
    bool show_right = true;
    bool show_bottom = true;
    float font_size = 15.0f;
    float dpi_scale = 1.0f;

    // panels
    int right_tab_request = -1;
    int bottom_tab_request = -1;
    char func_filter[128] = {};
    char info_filter[128] = {};
    std::vector<log_line> log;
    bool log_to_bottom = true;
    char console[1024] = {};
    std::vector<std::string> console_history;
    int history_pos = -1;
    bool focus_console = false;
    uint64_t hex_addr = 0;
    bool hex_follow = true;
    bool hex_live = false;

    dialog_state dialog;

    // debugger
    std::string debug_args;
    bool dbg_mapped = false;   // runtime addresses of the main image map onto the listing
    uint64_t dbg_delta = 0;    // runtime base - static base
    uint64_t dbg_image_size = 0;

    // view options
    bool show_bytes = true;
    theme::ui_theme theme = theme::ui_theme::dark;

    // main window placement, restored by the host
    int win_w = 0;
    int win_h = 0;
    bool win_max = false;

    std::vector<std::string> recent;
    std::string settings_path;
    bool sandboxed = false; // tests: never start / attach to processes or open the shell
};

void app_init(app_state& s, const platform_api& platform, const std::vector<std::string>& args);
// before ImGui::NewFrame: applies the font size
void app_pre_frame(app_state& s);
// between ImGui::NewFrame and ImGui::Render
void app_frame(app_state& s);
void app_shutdown(app_state& s);

void app_log(app_state& s, const std::string& text, int level = 0);
void app_open(app_state& s, const std::string& path, const load_options& opts = load_options());
void app_open_dialog(app_state& s);
void app_close_file(app_state& s);
void app_save(app_state& s);
void app_save_project(app_state& s);
bool app_loading(const app_state& s);

void app_jump(app_state& s, uint64_t addr, bool remember = true);
void app_back(app_state& s);
void app_forward(app_state& s);
bool app_follow(app_state& s, uint64_t addr); // jump to what the line at addr points at
void app_names_changed(app_state& s);
void app_set_font_size(app_state& s, float size);
void app_set_theme(app_state& s, theme::ui_theme t);
void app_open_dialog_kind(app_state& s, dialog_kind kind, uint64_t addr = 0);

// debugger, addresses are static (listing) unless said otherwise
bool app_can_debug(const app_state& s, std::string* why = nullptr);
void app_toggle_bp(app_state& s, uint64_t addr);
void dbg_start(app_state& s);
void dbg_attach(app_state& s, uint32_t pid);
void dbg_continue(app_state& s);
void dbg_step_into(app_state& s);
void dbg_step_over(app_state& s);
void dbg_run_to_cursor(app_state& s);
void dbg_pause(app_state& s);
void dbg_stop(app_state& s);
void dbg_detach(app_state& s);
bool app_to_static(const app_state& s, uint64_t runtime, uint64_t& out);
uint64_t app_to_runtime(const app_state& s, uint64_t addr);
// static address of the debuggee's pc, when it's inside the loaded image
bool app_pc_static(const app_state& s, uint64_t& out);
