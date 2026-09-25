#include "app.h"
#include "core/os.h"
#include "core/util.h"
#include "imgui.h"
#include "theme.h"
#include "ui/bottom_panel.h"
#include "ui/cpu_panel.h"
#include "ui/dialogs.h"
#include "ui/ida_view.h"
#include "ui/left_panel.h"
#include "ui/right_panel.h"
#include "ui/status_bar.h"
#include "ui/top_bar.h"
#include "version.h"
#include "widgets/splitter.h"
#include <algorithm>
#include <cstdlib>

// ---- settings (settings.ini in the user folder, key=value lines) ----

static void load_settings(app_state& s)
{
    std::vector<uint8_t> bytes;
    std::string err;
    if (!os::read_file(s.settings_path, bytes, err))
        return;
    std::string text(bytes.begin(), bytes.end());
    for (const std::string& raw : util::split(text, "\n")) {
        std::string line = util::trim(raw);
        size_t eq = line.find('=');
        if (eq == std::string::npos)
            continue;
        std::string k = line.substr(0, eq), v = line.substr(eq + 1);
        float f = (float)atof(v.c_str());
        if (k == "font_size")
            s.font_size = std::min(32.0f, std::max(10.0f, f));
        else if (k == "left_w")
            s.left_w = f;
        else if (k == "right_w")
            s.right_w = f;
        else if (k == "bottom_h")
            s.bottom_h = f;
        else if (k == "right_split")
            s.right_split = std::min(0.9f, std::max(0.1f, f));
        else if (k == "show_left")
            s.show_left = v == "1";
        else if (k == "show_right")
            s.show_right = v == "1";
        else if (k == "show_bottom")
            s.show_bottom = v == "1";
        else if (k == "show_bytes")
            s.show_bytes = v == "1";
        else if (k == "theme")
            s.theme = v == "light" ? theme::ui_theme::light
                    : v == "contrast" ? theme::ui_theme::contrast
                                      : theme::ui_theme::dark;
        else if (k == "break_on_entry")
            s.dbg.break_on_entry = v == "1";
        else if (k == "debug_args")
            s.debug_args = v;
        else if (k == "step_count")
            s.step_count = std::min(100000, std::max(1, atoi(v.c_str())));
        else if (k == "win_w")
            s.win_w = atoi(v.c_str());
        else if (k == "win_h")
            s.win_h = atoi(v.c_str());
        else if (k == "win_max")
            s.win_max = v == "1";
        else if (k == "recent" && s.recent.size() < 10)
            s.recent.push_back(v);
    }
}

static void save_settings(app_state& s)
{
    std::string o;
    o += util::fmt("font_size=%g\nleft_w=%g\nright_w=%g\nbottom_h=%g\nright_split=%g\n", s.font_size, s.left_w, s.right_w,
        s.bottom_h, s.right_split);
    o += util::fmt("show_left=%d\nshow_right=%d\nshow_bottom=%d\nshow_bytes=%d\nbreak_on_entry=%d\n", s.show_left,
        s.show_right, s.show_bottom, s.show_bytes, s.dbg.break_on_entry);
    o += util::fmt("win_w=%d\nwin_h=%d\nwin_max=%d\n", s.win_w, s.win_h, s.win_max);
    const char* tname = s.theme == theme::ui_theme::light ? "light"
                      : s.theme == theme::ui_theme::contrast ? "contrast" : "dark";
    o += std::string("theme=") + tname + "\n";
    o += "debug_args=" + s.debug_args + "\n";
    o += util::fmt("step_count=%d\n", s.step_count);
    for (const std::string& r : s.recent)
        o += "recent=" + r + "\n";
    std::string err;
    os::write_file(s.settings_path, o, err);
}

static void add_recent(app_state& s, const std::string& path)
{
    s.recent.erase(std::remove(s.recent.begin(), s.recent.end(), path), s.recent.end());
    s.recent.insert(s.recent.begin(), path);
    if (s.recent.size() > 10)
        s.recent.resize(10);
    save_settings(s);
}

static void set_title(app_state& s)
{
    if (!s.platform.set_title)
        return;
    std::string t = "ceasta";
    if (s.db)
        t = (s.db->dirty ? "*" : "") + s.db->bin.name + " - ceasta";
    s.title_dirty = s.db && s.db->dirty;
    s.platform.set_title(t);
}

// ---- log ----

void app_log(app_state& s, const std::string& text, int level)
{
    for (const std::string& line : util::split(text, "\n"))
        s.log.push_back({line, level});
    if (text.empty())
        s.log.push_back({std::string(), level});
    if (s.log.size() > 20000)
        s.log.erase(s.log.begin(), s.log.begin() + 4000);
    s.log_to_bottom = true;
}

// ---- files ----

bool app_loading(const app_state& s)
{
    return s.job != nullptr;
}

// with unsaved changes, asks "save changes?" and returns true: then runs `then` once the
// answer is save or don't save (and never, on cancel)
static bool ask_to_save(app_state& s, std::function<void()> then)
{
    if (!s.db || !s.db->dirty)
        return false;
    dialogs::open(s, dialog_kind::save_changes, 0);
    s.pending_close = std::move(then);
    return true;
}

static void start_open(app_state& s, const std::string& path, load_options opts)
{
    std::string target = path;
    if (is_project_file(path) && !opts.force_raw) {
        // a project: open the file it belongs to, with the project's names and comments
        std::string name;
        target = project_binary(path, name);
        if (target.empty() && s.platform.open_file_dialog)
            target = s.platform.open_file_dialog(("Where is " + (name.empty() ? std::string("the file for this project") : name) + "?").c_str());
        if (target.empty()) {
            app_log(s, "can't find the file " + path + " belongs to" + (name.empty() ? std::string() : " (" + name + ")") +
                ": keep the project next to it", 2);
            return;
        }
        opts.project = path;
    }
    if (s.dbg.state() != dbg_state::none) {
        app_log(s, "ending the debug session to open another file", 1);
        dbg_stop(s);
    }
    s.job.reset(new load_job());
    load_job* job = s.job.get();
    job->path = target;
    job->worker = std::thread([job, target, opts]() {
        job->result = open_database(target, opts, &job->progress, job->error);
        job->done.store(true);
    });
    app_log(s, "loading " + target + (opts.project.empty() ? std::string() : " with " + opts.project));
}

void app_open(app_state& s, const std::string& path, const load_options& opts)
{
    if (path.empty())
        return;
    if (s.job) {
        app_log(s, "still loading " + s.job->path + ", wait for it or cancel it first", 1);
        return;
    }
    if (ask_to_save(s, [&s, path, opts]() { start_open(s, path, opts); }))
        return;
    start_open(s, path, opts);
}

void app_open_dialog(app_state& s)
{
    if (!s.platform.open_file_dialog)
        return;
    std::string path = s.platform.open_file_dialog("Open a file to analyze");
    if (!path.empty())
        app_open(s, path);
}

static void finish_job(app_state& s)
{
    if (!s.job || !s.job->done.load())
        return;
    std::unique_ptr<load_job> job = std::move(s.job);
    job->worker.join();
    if (!job->result) {
        app_log(s, "can't open " + job->path + ": " + job->error, 2);
        return;
    }
    s.db = std::move(job->result);
    s.lua.bridge().db = s.db.get();
    s.back.clear();
    s.forward.clear();
    s.version++;
    s.dbg_mapped = false;
    const binary& b = s.db->bin;
    s.cursor = b.has_entry ? b.entry : b.min_addr();
    s.hex_addr = s.cursor;
    s.scroll_to_cursor = true;
    for (const std::string& n : b.notes)
        app_log(s, n, 1);
    app_log(s, util::fmt("%s: %s %s %s, %zu functions, %zu imports, %zu strings", b.name.c_str(), format_name(b.format),
        arch_name(b.arch), b.kind.c_str(), s.db->an.funcs.size(), b.imports.size(), s.db->an.strings.size()));
    if (!s.db->user_names.empty() || !s.db->user_comments.empty())
        app_log(s, util::fmt("restored %zu names and %zu comments from %s", s.db->user_names.size(),
            s.db->user_comments.size(), s.db->annotations_path().c_str()));
    add_recent(s, b.path);
    set_title(s);
    s.lua.fire("load");
    app_names_changed(s);
}

void app_save(app_state& s)
{
    if (!s.db || !s.db->dirty)
        return;
    std::string err;
    if (s.db->save(err)) {
        s.db->dirty = false;
        app_log(s, "saved to " + s.db->annotations_path());
    } else {
        app_log(s, "couldn't save: " + err, 2);
    }
}

void app_save_as(app_state& s)
{
    if (!s.db || !s.platform.save_file_dialog)
        return;
    std::string path = s.platform.save_file_dialog("Save the project as", s.db->project_path());
    if (path.empty())
        return;
    if (!is_project_file(path))
        path += ".ceasta";
    std::string old = s.db->project_file;
    s.db->project_file = path;
    std::string err;
    if (s.db->save_project(err) && s.db->save(err)) {
        s.db->dirty = false;
        app_log(s, "saved the project to " + path + " (open it to pick up where you left off)");
    } else {
        s.db->project_file = old;
        app_log(s, "couldn't save the project: " + err, 2);
    }
}

static void close_now(app_state& s)
{
    if (s.dbg.state() != dbg_state::none)
        dbg_stop(s);
    s.db.reset();
    s.lua.bridge().db = nullptr;
    s.back.clear();
    s.forward.clear();
    s.cursor = 0;
    s.version++;
    set_title(s);
}

void app_close_file(app_state& s)
{
    if (!ask_to_save(s, [&s]() { close_now(s); }))
        close_now(s);
}

bool app_request_close(app_state& s)
{
    if (s.quit_confirmed)
        return true;
    return !ask_to_save(s, [&s]() {
        s.quit_confirmed = true;
        if (s.platform.quit)
            s.platform.quit();
    });
}

void app_quit(app_state& s)
{
    if (app_request_close(s) && s.platform.quit) {
        s.quit_confirmed = true;
        s.platform.quit();
    }
}

// ---- navigation ----

void app_jump(app_state& s, uint64_t addr, bool remember)
{
    if (!s.db)
        return;
    if (!s.db->bin.is_mapped(addr)) {
        app_log(s, "address " + s.db->fmt_addr(addr) + " isn't part of the file", 1);
        return;
    }
    if (remember && addr != s.cursor) {
        s.back.push_back(s.cursor);
        if (s.back.size() > 256)
            s.back.erase(s.back.begin());
        s.forward.clear();
    }
    s.cursor = addr;
    s.scroll_to_cursor = true;
    if (s.hex_follow)
        s.hex_addr = addr;
}

void app_back(app_state& s)
{
    if (s.back.empty())
        return;
    s.forward.push_back(s.cursor);
    s.cursor = s.back.back();
    s.back.pop_back();
    s.scroll_to_cursor = true;
    if (s.hex_follow)
        s.hex_addr = s.cursor;
}

void app_forward(app_state& s)
{
    if (s.forward.empty())
        return;
    s.back.push_back(s.cursor);
    s.cursor = s.forward.back();
    s.forward.pop_back();
    s.scroll_to_cursor = true;
    if (s.hex_follow)
        s.hex_addr = s.cursor;
}

bool app_follow(app_state& s, uint64_t addr)
{
    if (!s.db)
        return false;
    row r;
    r.addr = addr;
    uint8_t f = s.db->an.flags_at(addr);
    r.kind = (f & fl_code) ? row_kind::code : (f & fl_data) ? row_kind::data : (f & fl_str) ? row_kind::string : row_kind::unknown;
    r.size = s.db->an.item_size(addr);
    line_text t;
    s.db->format(r, t);
    if (t.target && s.db->bin.is_mapped(t.target)) {
        app_jump(s, t.target);
        return true;
    }
    return false;
}

void app_names_changed(app_state& s)
{
    s.version++;
}

void app_set_font_size(app_state& s, float size)
{
    s.font_size = std::min(32.0f, std::max(10.0f, size));
}

void app_set_theme(app_state& s, theme::ui_theme t)
{
    s.theme = t;
    theme::apply_theme(t);
    save_settings(s);
}

void app_open_dialog_kind(app_state& s, dialog_kind kind, uint64_t addr)
{
    dialogs::open(s, kind, addr);
}

// ---- debugger glue ----

bool app_can_debug(const app_state& s, std::string* why)
{
    std::string w;
#ifdef _WIN32
    const bin_format native = bin_format::pe;
    const char* native_name = "a windows .exe";
#else
    const bin_format native = bin_format::elf;
    const char* native_name = "a linux elf executable";
#endif
    if (s.sandboxed)
        w = "debugging is disabled in this session";
    else if (!debugger::supported())
        w = "the debugger isn't available in this build";
    else if (!s.db)
        w = std::string("open ") + native_name + " first";
    else if (s.db->bin.format != native)
        w = std::string("only ") + native_name + " can be debugged here";
    else if (s.db->bin.kind == "dll" || s.db->bin.kind == "elf shared object")
        w = "a library can't run on its own: start its program, then use attach";
    else if (s.db->bin.kind == "elf object" || s.db->bin.kind == "elf core")
        w = "this elf file isn't a program that can run";
    if (why)
        *why = w;
    return w.empty();
}

bool app_to_static(const app_state& s, uint64_t runtime, uint64_t& out)
{
    if (!s.dbg_mapped || !s.db)
        return false;
    uint64_t base = s.db->bin.base + s.dbg_delta;
    if (runtime < base || runtime >= base + s.dbg_image_size)
        return false;
    out = runtime - s.dbg_delta;
    return s.db->bin.is_mapped(out);
}

uint64_t app_to_runtime(const app_state& s, uint64_t addr)
{
    return s.dbg_mapped ? addr + s.dbg_delta : addr;
}

bool app_pc_static(const app_state& s, uint64_t& out)
{
    return s.dbg.state() == dbg_state::stopped && app_to_static(s, s.dbg.pc(), out);
}

static void map_debuggee(app_state& s)
{
    s.dbg_mapped = false;
    if (!s.db)
        return;
    std::vector<dbg_module> mods = s.dbg.modules();
    if (mods.empty() || util::lower(mods[0].name) != util::lower(s.db->bin.name)) {
        app_log(s, "the process isn't the loaded file, the listing won't follow the debugger", 1);
        return;
    }
    s.dbg_delta = s.dbg.image_base() - s.db->bin.base;
    s.dbg_image_size = mods[0].size ? mods[0].size : s.db->bin.max_addr() - s.db->bin.base;
    s.dbg_mapped = true;
    if (s.dbg_delta)
        app_log(s, "image relocated (aslr), runtime base " + util::hex(s.dbg.image_base()));
    for (uint64_t bp : s.db->breakpoints) {
        std::string err;
        if (!s.dbg.add_bp(bp + s.dbg_delta, err))
            app_log(s, "breakpoint at " + s.db->fmt_addr(bp) + ": " + err, 1);
    }
}

void app_toggle_bp(app_state& s, uint64_t addr)
{
    if (!s.db || !s.db->bin.is_mapped(addr))
        return;
    bool live = s.dbg.state() != dbg_state::none && s.dbg_mapped;
    if (s.db->breakpoints.count(addr)) {
        s.db->breakpoints.erase(addr);
        if (live)
            s.dbg.del_bp(addr + s.dbg_delta);
        app_log(s, "breakpoint removed at " + s.db->location(addr));
    } else {
        s.db->breakpoints.insert(addr);
        std::string err;
        if (live && !s.dbg.add_bp(addr + s.dbg_delta, err))
            app_log(s, "can't set breakpoint: " + err, 2);
        else
            app_log(s, "breakpoint set at " + s.db->location(addr));
    }
    s.db->dirty = true;
    s.version++;
}

void dbg_start(app_state& s)
{
    std::string why;
    if (!app_can_debug(s, &why)) {
        app_log(s, "can't debug: " + why, 1);
        return;
    }
    if (s.dbg.state() != dbg_state::none)
        return;
    std::string err;
    if (!s.dbg.start(s.db->bin.path, s.debug_args, "", err))
        app_log(s, err, 2);
    else
        app_log(s, "debugging " + s.db->bin.path + (s.dbg.break_on_entry ? " (will stop at the entry point)" : ""));
}

void dbg_attach(app_state& s, uint32_t pid)
{
    if (s.sandboxed || !debugger::supported()) {
        app_log(s, "the debugger is only available in the windows x64 build", 1);
        return;
    }
    std::string err;
    if (!s.dbg.attach(pid, err))
        app_log(s, err, 2);
    else
        app_log(s, util::fmt("attaching to process %u", pid));
}

static void dbg_do(app_state& s, bool (debugger::*fn)(std::string&))
{
    std::string err;
    if (!(s.dbg.*fn)(err))
        app_log(s, err, 1);
}

// a debugger command ends a multi-step; the step already under way finishes on its own
static void cancel_steps(app_state& s)
{
    s.steps_left = 0;
}

void dbg_continue(app_state& s)
{
    if (dbg_stepping(s)) {
        cancel_steps(s);
        return;
    }
    if (s.dbg.state() == dbg_state::none)
        dbg_start(s);
    else if (s.dbg.state() == dbg_state::stopped)
        dbg_do(s, &debugger::cont);
}

bool dbg_stepping(const app_state& s)
{
    return s.steps_left > 0 || s.step_in_flight;
}

static std::string pc_where(const app_state& s)
{
    uint64_t st = 0;
    return app_to_static(s, s.dbg.pc(), st) ? s.db->location(st) : util::hex(s.dbg.pc());
}

// one line for a whole multi-step, instead of one per instruction
static void steps_finished(app_state& s, int wanted)
{
    int done = s.steps_done;
    const char* what = s.step_over_mode ? "stepped over" : "stepped into";
    if (s.dbg.state() != dbg_state::stopped)
        app_log(s, util::fmt("[debug] the program ended after %d of %d steps", done, wanted));
    else if (done < wanted)
        app_log(s, util::fmt("[debug] stopped after %d of %d steps: %s at %s", done, wanted, s.dbg.stop_reason().c_str(),
            pc_where(s).c_str()));
    else
        app_log(s, util::fmt("[debug] %s %d instructions, now at %s", what, done, pc_where(s).c_str()));
}

// runs the steps of a multi-step for about 10 ms per frame, so thousands of them don't freeze
// the window. a breakpoint, a fault or the exit ends it early.
static void run_steps(app_state& s)
{
    int wanted = s.steps_done + s.steps_left + (s.step_in_flight ? 1 : 0);
    uint64_t until = os::now_ms() + 10;
    uint64_t step_began = os::now_ms();
    for (;;) {
        if (s.dbg.state() == dbg_state::running) {
            // a single step lands within microseconds: check again right away at first, and
            // only wait in longer naps for a call that's being stepped over
            bool fresh = os::now_ms() - step_began < 2;
            s.dbg.poll(fresh ? 0 : 1);
            if (s.dbg.state() == dbg_state::running) {
                if (os::now_ms() >= until)
                    return; // still in a step (a long call being stepped over): next frame
                if (fresh)
                    std::this_thread::yield();
                continue;
            }
        }
        if (s.step_in_flight) {
            s.step_in_flight = false;
            s.steps_done++;
            std::string why = s.dbg.stop_reason();
            if (s.dbg.state() != dbg_state::stopped || (why != "step" && why != "step over"))
                s.steps_left = 0;
        }
        if (s.steps_left <= 0 || s.dbg.state() != dbg_state::stopped)
            break;
        if (os::now_ms() >= until)
            return;
        std::string err;
        if (!(s.step_over_mode ? s.dbg.step_over(err) : s.dbg.step_into(err))) {
            app_log(s, err, 1);
            s.steps_left = 0;
            break;
        }
        s.steps_left--;
        s.step_in_flight = true;
        step_began = os::now_ms();
    }
    s.steps_left = 0;
    steps_finished(s, wanted);
}

static void begin_steps(app_state& s, bool over)
{
    if (s.dbg.state() == dbg_state::none) {
        dbg_start(s);
        return;
    }
    if (s.dbg.state() != dbg_state::stopped || dbg_stepping(s))
        return;
    if (s.step_count <= 1) {
        dbg_do(s, over ? &debugger::step_over : &debugger::step_into);
        return;
    }
    s.steps_left = s.step_count;
    s.steps_done = 0;
    s.step_over_mode = over;
    s.step_in_flight = false;
    run_steps(s);
}

void dbg_step_into(app_state& s)
{
    begin_steps(s, false);
}

void dbg_step_over(app_state& s)
{
    begin_steps(s, true);
}

void dbg_run_to_cursor(app_state& s)
{
    if (s.dbg.state() != dbg_state::stopped || !s.dbg_mapped || dbg_stepping(s))
        return;
    std::string err;
    if (!s.dbg.run_to(app_to_runtime(s, s.cursor), err))
        app_log(s, err, 1);
}

void dbg_pause(app_state& s)
{
    cancel_steps(s);
    if (s.dbg.state() == dbg_state::running)
        dbg_do(s, &debugger::pause);
}

void dbg_stop(app_state& s)
{
    cancel_steps(s);
    if (s.dbg.state() == dbg_state::none)
        return;
    s.dbg.kill();
    s.dbg_mapped = false;
}

void dbg_detach(app_state& s)
{
    cancel_steps(s);
    if (s.dbg.state() == dbg_state::none)
        return;
    s.dbg.detach();
    s.dbg_mapped = false;
}

static void setup_debugger(app_state& s)
{
    s.dbg.on_log = [&s](const std::string& m) { app_log(s, "[debug] " + m); };
    s.dbg.on_created = [&s]() { map_debuggee(s); };
    s.dbg.on_stop = [&s]() {
        uint64_t pc_static = 0;
        bool mapped = app_to_static(s, s.dbg.pc(), pc_static);
        std::string where = mapped ? s.db->location(pc_static) : util::hex(s.dbg.pc());
        if (!dbg_stepping(s)) // a multi-step logs one line when it ends
            app_log(s, "[debug] stopped: " + s.dbg.stop_reason() + " at " + where);
        if (mapped)
            app_jump(s, pc_static, false);
        s.lua.fire("stop", (int64_t)(mapped ? pc_static : s.dbg.pc()));
    };
    s.dbg.on_exit = [&s](int code) {
        s.dbg_mapped = false;
        s.lua.fire("exit", code);
    };
}

// ---- lua ----

static void setup_lua(app_state& s)
{
    lua_bridge br;
    br.db = s.db.get();
    br.dbg = &s.dbg;
    br.log = [&s](const std::string& t, int level) { app_log(s, t, level); };
    br.here = [&s]() { return s.cursor; };
    br.jump = [&s](uint64_t a) { app_jump(s, a); };
    br.to_runtime = [&s](uint64_t a) { return app_to_runtime(s, a); };
    br.to_static = [&s](uint64_t a, uint64_t& out) { return app_to_static(s, a, out); };
    s.lua.init(br);
    std::string user_plugins = os::join(os::user_dir(), "plugins");
    os::make_dirs(user_plugins);
    int ok = s.lua.load_plugins({os::join(os::exe_dir(), "plugins"), user_plugins});
    if (!s.lua.plugin_files().empty())
        app_log(s, util::fmt("loaded %d of %zu plugins, %zu commands in the plugins menu", ok, s.lua.plugin_files().size(),
            s.lua.commands().size()));
}

// ---- init / frame / shutdown ----

void app_init(app_state& s, const platform_api& platform, const std::vector<std::string>& args)
{
    s.platform = platform;
    s.settings_path = os::join(os::user_dir(), "settings.ini");
    load_settings(s);
    theme::apply_theme(s.theme);
    setup_debugger(s);
    app_log(s, "ceasta " CEASTA_VERSION " - open a file with ctrl+o or drop one on the window. f1 lists the shortcuts.");
    setup_lua(s);
    for (const std::string& a : args)
        if (!a.empty() && a[0] != '-') {
            app_open(s, a);
            break;
        }
    set_title(s);
}

void app_pre_frame(app_state& s)
{
    ImGui::GetStyle().FontSizeBase = s.font_size;
}

void app_shutdown(app_state& s)
{
    if (s.job) {
        s.job->progress.cancel.store(true);
        s.job->worker.join();
        s.job.reset();
    }
    if (s.dbg.state() != dbg_state::none)
        dbg_stop(s);
    // unsaved changes were offered a save when the window closed; nothing is written here
    save_settings(s);
    s.lua.shutdown();
}

static bool plain_key(ImGuiKey k)
{
    ImGuiIO& io = ImGui::GetIO();
    return !io.WantTextInput && !io.KeyCtrl && !io.KeyAlt && ImGui::IsKeyPressed(k, false);
}

static void shortcuts(app_state& s)
{
    ImGuiIO& io = ImGui::GetIO();
    // a dialog (even one closing this frame) or a context menu owns the keyboard
    bool popup = ImGui::IsPopupOpen("", ImGuiPopupFlags_AnyPopupId | ImGuiPopupFlags_AnyPopupLevel);
    if (popup || s.dialog.kind != dialog_kind::none)
        return;
    if (ImGui::IsKeyChordPressed(ImGuiMod_Ctrl | ImGuiKey_O))
        app_open_dialog(s);
    if (ImGui::IsKeyChordPressed(ImGuiMod_Ctrl | ImGuiKey_S))
        app_save(s);
    if (ImGui::IsKeyChordPressed(ImGuiMod_Ctrl | ImGuiMod_Shift | ImGuiKey_S))
        app_save_as(s);
    if (ImGui::IsKeyChordPressed(ImGuiMod_Ctrl | ImGuiKey_Equal) || ImGui::IsKeyChordPressed(ImGuiMod_Ctrl | ImGuiKey_KeypadAdd))
        app_set_font_size(s, s.font_size + 1);
    if (ImGui::IsKeyChordPressed(ImGuiMod_Ctrl | ImGuiKey_Minus) || ImGui::IsKeyChordPressed(ImGuiMod_Ctrl | ImGuiKey_KeypadSubtract))
        app_set_font_size(s, s.font_size - 1);
    if (ImGui::IsKeyChordPressed(ImGuiMod_Ctrl | ImGuiKey_0))
        app_set_font_size(s, 15);
    if (ImGui::IsKeyPressed(ImGuiKey_F1, false))
        dialogs::open(s, dialog_kind::shortcuts, 0);

    // debugger keys work everywhere
    if (ImGui::IsKeyChordPressed(ImGuiMod_Ctrl | ImGuiKey_F2))
        dbg_stop(s);
    else if (!io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_F2, false))
        app_toggle_bp(s, s.cursor);
    if (ImGui::IsKeyPressed(ImGuiKey_F9, false))
        dbg_continue(s);
    if (ImGui::IsKeyPressed(ImGuiKey_F7, false))
        dbg_step_into(s);
    if (ImGui::IsKeyPressed(ImGuiKey_F8, false))
        dbg_step_over(s);
    if (ImGui::IsKeyPressed(ImGuiKey_F4, false))
        dbg_run_to_cursor(s);
    if (ImGui::IsKeyPressed(ImGuiKey_F12, false))
        dbg_pause(s);

    if (!s.db)
        return;
    // ida style keys, only when not typing
    if (plain_key(ImGuiKey_G))
        dialogs::open(s, dialog_kind::jump, s.cursor);
    if (plain_key(ImGuiKey_N))
        dialogs::open(s, dialog_kind::rename, s.cursor);
    if (plain_key(ImGuiKey_Semicolon))
        dialogs::open(s, dialog_kind::comment, s.cursor);
    if (plain_key(ImGuiKey_X))
        dialogs::open(s, dialog_kind::xrefs, s.cursor);
    if (plain_key(ImGuiKey_Space))
        s.view = s.view == center_view::listing ? center_view::graph : center_view::listing;
    if (ImGui::IsKeyPressed(ImGuiKey_F5, false))
        s.view = s.view == center_view::pseudo ? center_view::listing : center_view::pseudo;
    if (plain_key(ImGuiKey_Escape))
        app_back(s);
    if (plain_key(ImGuiKey_Enter) || plain_key(ImGuiKey_KeypadEnter))
        app_follow(s, s.cursor);
    if (ImGui::IsKeyChordPressed(ImGuiMod_Ctrl | ImGuiKey_Enter) || ImGui::IsKeyChordPressed(ImGuiMod_Alt | ImGuiKey_RightArrow))
        app_forward(s);
    if (ImGui::IsKeyChordPressed(ImGuiMod_Alt | ImGuiKey_LeftArrow))
        app_back(s);
    if (ImGui::IsKeyChordPressed(ImGuiMod_Alt | ImGuiKey_B))
        dialogs::open(s, dialog_kind::search, s.cursor);
    if (ImGui::IsKeyChordPressed(ImGuiMod_Ctrl | ImGuiKey_F))
        dialogs::open(s, dialog_kind::find, s.cursor);
}

void app_frame(app_state& s)
{
    finish_job(s);
    if ((s.db && s.db->dirty) != s.title_dirty)
        set_title(s);
    if (dbg_stepping(s))
        run_steps(s);
    if (s.dbg.state() == dbg_state::running)
        s.dbg.poll(0);

    ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(vp->WorkPos);
    ImGui::SetNextWindowSize(vp->WorkSize);
    ImGuiWindowFlags flags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize |
                             ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoBringToFrontOnFocus |
                             ImGuiWindowFlags_MenuBar | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse;
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
    ImGui::Begin("##ceasta", nullptr, flags);
    ImGui::PopStyleVar();

    top_bar::draw(s);

    // one fixed layout: functions | view | info + cpu, output across the bottom, status line.
    // every region is placed explicitly, so panels keep the normal item spacing inside
    float sc = s.dpi_scale;
    float bar = 5.0f * sc;
    ImVec2 origin = ImGui::GetCursorPos();
    ImVec2 avail = ImGui::GetContentRegionAvail();
    float status_h = ImGui::GetFrameHeight();
    float body_h = std::max(120.0f * sc, avail.y - status_h);
    float bottom_h = 0.0f;
    if (s.show_bottom)
        bottom_h = std::max(80.0f * sc, std::min(s.bottom_h * sc, body_h - 150.0f * sc));
    float top_h = body_h - (s.show_bottom ? bottom_h + bar : 0.0f);
    float left_w = s.show_left ? std::max(120.0f * sc, std::min(s.left_w * sc, avail.x * 0.45f)) : 0.0f;
    float right_w = s.show_right ? std::max(160.0f * sc, std::min(s.right_w * sc, avail.x * 0.45f)) : 0.0f;
    float x = origin.x;

    if (s.show_left) {
        ImGui::SetCursorPos(ImVec2(x, origin.y));
        ImGui::BeginChild("##left", ImVec2(left_w, top_h), ImGuiChildFlags_Borders);
        left_panel::draw(s);
        ImGui::EndChild();
        x += left_w;
        ImGui::SetCursorPos(ImVec2(x, origin.y));
        widgets::splitter("##split_left", true, bar, top_h, &s.left_w, 120.0f, 900.0f, 1.0f, sc);
        x += bar;
    }
    float center_w = std::max(50.0f * sc, origin.x + avail.x - x - (s.show_right ? right_w + bar : 0.0f));
    ImGui::SetCursorPos(ImVec2(x, origin.y));
    ImGui::BeginChild("##center", ImVec2(center_w, top_h), ImGuiChildFlags_Borders);
    ida_view::draw(s);
    ImGui::EndChild();
    x += center_w;
    if (s.show_right) {
        ImGui::SetCursorPos(ImVec2(x, origin.y));
        widgets::splitter("##split_right", true, bar, top_h, &s.right_w, 160.0f, 900.0f, -1.0f, sc);
        x += bar;
        float usable = std::max(1.0f, top_h - bar);
        float info_h = std::min(std::max(60.0f * sc, usable * s.right_split), usable - 60.0f * sc);
        ImGui::SetCursorPos(ImVec2(x, origin.y));
        ImGui::BeginChild("##info", ImVec2(right_w, info_h), ImGuiChildFlags_Borders);
        right_panel::draw(s);
        ImGui::EndChild();
        ImGui::SetCursorPos(ImVec2(x, origin.y + info_h));
        float split_px = info_h;
        if (widgets::splitter("##split_cpu", false, bar, right_w, &split_px, 60.0f * sc, usable - 60.0f * sc, 1.0f, 1.0f))
            s.right_split = split_px / usable;
        ImGui::SetCursorPos(ImVec2(x, origin.y + info_h + bar));
        ImGui::BeginChild("##cpu", ImVec2(right_w, top_h - info_h - bar), ImGuiChildFlags_Borders);
        cpu_panel::draw(s);
        ImGui::EndChild();
    }
    if (s.show_bottom) {
        ImGui::SetCursorPos(ImVec2(origin.x, origin.y + top_h));
        widgets::splitter("##split_bottom", false, bar, avail.x, &s.bottom_h, 80.0f, 1200.0f, -1.0f, sc);
        ImGui::SetCursorPos(ImVec2(origin.x, origin.y + top_h + bar));
        ImGui::BeginChild("##bottom", ImVec2(avail.x, bottom_h), ImGuiChildFlags_Borders);
        bottom_panel::draw(s);
        ImGui::EndChild();
    }
    ImGui::SetCursorPos(ImVec2(origin.x, origin.y + body_h));
    status_bar::draw(s);
    ImGui::End();

    dialogs::draw(s);
    shortcuts(s);
}
