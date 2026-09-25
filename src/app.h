#pragma once
#include "core/bp_cond.h"
#include "core/database.h"
#include "core/debugger.h"
#include "core/lua_host.h"
#include "core/search.h"
#include "theme.h"
#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <thread>
#include <vector>

// what the window host provides (main.cpp on windows, stubs in the ui tests)
struct platform_api {
    std::function<std::string(const char* title)> open_file_dialog; // "" when cancelled
    // "" when cancelled; suggested is the path to start from
    std::function<std::string(const char* title, const std::string& suggested)> save_file_dialog;
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

enum class dialog_kind { none, jump, rename, comment, xrefs, search, find, open_raw, attach, run_args, about, shortcuts,
    save_changes, ai, palette, bookmarks, bp_condition };

struct app_mcp; // the built-in mcp server, when it's running (app_mcp.cpp)

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
    // search everything (find): the hits for the query / kinds / version they were made for
    std::vector<search_hit> hits;
    std::string hits_query;
    unsigned hits_kinds = 0;
    uint64_t hits_version = ~0ull;
    bool hits_cut = false;
    int sel = 0;
    bool refocus = false;
    bool proceed = false; // save_changes answered with save / don't save
    int run_action = -1;  // palette: the action to run once it has closed
};

struct app_state {
    platform_api platform;
    std::unique_ptr<database> db;
    std::unique_ptr<load_job> job;
    lua_host lua;
    debugger dbg;
    uint64_t version = 0; // bumps whenever names / comments / analysis change
    uint64_t frame_no = 0;

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
    std::string search_text;         // the last search everything query (ctrl+f)
    unsigned search_kinds = sk_all;
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
    int step_count = 1;        // instructions per step: f7 / f8 and the step buttons use it
    int steps_left = 0;        // a multi-instruction step in progress (run a batch per frame)
    int steps_done = 0;
    int steps_wanted = 0;
    bool step_over_mode = false;
    bool step_in_flight = false;
    bool step_until_return = false; // the multi-step is a step out
    bp_conditions conditions;         // evaluates breakpoint conditions
    std::map<uint64_t, int> bp_hits;  // per breakpoint (static address), this run
    bool auto_continue = false;       // a breakpoint whose condition was false: keep running
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

    // the ai server (ai menu): serves the open file over mcp to a client on this machine
    std::shared_ptr<app_mcp> mcp;
    int mcp_port = 8744;
    bool mcp_allow_debug = false;
    bool mcp_allow_lua = false;

    // unsaved changes: what to do once "save changes?" is answered (close, open, quit)
    std::function<void()> pending_close;
    bool quit_confirmed = false; // the window may close without asking again
    bool title_dirty = false;    // the title shows the unsaved mark

    std::vector<std::string> recent;
    std::string settings_path;
    bool sandboxed = false; // tests: never start / attach to processes or open the shell
};

void app_init(app_state& s, const platform_api& platform, const std::vector<std::string>& args);
// before ImGui::NewFrame: applies the font size
void app_pre_frame(app_state& s);
// instead of a frame while the window is minimized: keeps the debugger and the ai server going
void app_background(app_state& s);
// between ImGui::NewFrame and ImGui::Render
void app_frame(app_state& s);
void app_shutdown(app_state& s);

void app_log(app_state& s, const std::string& text, int level = 0);
void app_open(app_state& s, const std::string& path, const load_options& opts = load_options());
void app_open_dialog(app_state& s);
void app_close_file(app_state& s);
void app_save(app_state& s);
void app_save_as(app_state& s); // pick where the project file goes
// the window is about to close (its close button, alt+f4): true when it may close now. with
// unsaved changes it asks first and returns false; the answer then closes it via platform.quit
bool app_request_close(app_state& s);
void app_quit(app_state& s); // file > exit
bool app_loading(const app_state& s);

void app_jump(app_state& s, uint64_t addr, bool remember = true);
void app_back(app_state& s);
void app_forward(app_state& s);
bool app_follow(app_state& s, uint64_t addr); // jump to what the line at addr points at
void app_names_changed(app_state& s);
void app_undo(app_state& s);
void app_redo(app_state& s);
void app_toggle_bookmark(app_state& s, uint64_t addr);
void app_set_font_size(app_state& s, float size);
void app_set_theme(app_state& s, theme::ui_theme t);
void app_open_dialog_kind(app_state& s, dialog_kind kind, uint64_t addr = 0);

// debugger, addresses are static (listing) unless said otherwise
bool app_can_debug(const app_state& s, std::string* why = nullptr);
void app_toggle_bp(app_state& s, uint64_t addr);
// a condition for the breakpoint at addr (adds the breakpoint); "" makes it unconditional
bool app_set_bp_condition(app_state& s, uint64_t addr, const std::string& expr, std::string& err);
// poll the debugger, and keep going past breakpoints whose condition is false
void app_dbg_pump(app_state& s, uint32_t timeout_ms = 0);
void dbg_start(app_state& s);
void dbg_attach(app_state& s, uint32_t pid);
void dbg_continue(app_state& s);
void dbg_step_into(app_state& s);
void dbg_step_over(app_state& s);
bool dbg_stepping(const app_state& s); // a multi-instruction step is still going
void dbg_step_out(app_state& s);       // run until the current function returns
void dbg_step_back(app_state& s);      // undo the last steps (as many as a step does)
void dbg_run_to_cursor(app_state& s);
void dbg_pause(app_state& s);
void dbg_stop(app_state& s);
void dbg_detach(app_state& s);
bool app_to_static(const app_state& s, uint64_t runtime, uint64_t& out);

// the ai server: an mcp client (claude code, cursor, ...) on this machine works on the open file.
// tool calls run on the ui thread, between frames
bool app_mcp_start(app_state& s);
void app_mcp_stop(app_state& s);
bool app_mcp_running(const app_state& s);    // started and not failed
std::string app_mcp_url(const app_state& s); // where it listens, "" until then
std::string app_mcp_error(const app_state& s);
int app_mcp_calls(const app_state& s);
void app_mcp_pump(app_state& s);             // every frame: runs the tool calls that are waiting
uint64_t app_to_runtime(const app_state& s, uint64_t addr);
// static address of the debuggee's pc, when it's inside the loaded image
bool app_pc_static(const app_state& s, uint64_t& out);
