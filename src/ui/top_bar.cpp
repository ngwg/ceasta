#include "ui/top_bar.h"
#include "core/os.h"
#include "core/util.h"
#include "imgui.h"
#include "ui/dialogs.h"
#include <algorithm>

namespace top_bar {

static void file_menu(app_state& s)
{
    if (!ImGui::BeginMenu("File"))
        return;
    if (ImGui::MenuItem("Open...", "Ctrl+O", false, !app_loading(s)))
        app_open_dialog(s);
    if (ImGui::MenuItem("Open as raw code...", nullptr, false, !app_loading(s)))
        dialogs::open(s, dialog_kind::open_raw, 0);
    if (ImGui::BeginMenu("Open recent", !s.recent.empty() && !app_loading(s))) {
        std::string pick;
        for (const std::string& r : s.recent)
            if (ImGui::MenuItem(r.c_str()))
                pick = r;
        ImGui::EndMenu();
        if (!pick.empty())
            app_open(s, pick);
    }
    ImGui::Separator();
    if (ImGui::MenuItem("Save", "Ctrl+S", false, s.db && (s.db->dirty || s.db->project_file.empty())))
        app_save(s);
    ImGui::SetItemTooltip("one .ceasta file with the program and all your work - open it later or on another pc");
    if (ImGui::MenuItem("Save as...", "Ctrl+Shift+S", false, s.db && s.platform.save_file_dialog))
        app_save_as(s);
    if (ImGui::MenuItem("Close file", nullptr, false, s.db != nullptr))
        app_close_file(s);
    ImGui::Separator();
    if (ImGui::MenuItem("Exit", "Alt+F4"))
        app_quit(s);
    ImGui::EndMenu();
}

static void edit_menu(app_state& s)
{
    if (!ImGui::BeginMenu("Edit"))
        return;
    bool has = s.db != nullptr;
    if (ImGui::MenuItem("Undo", "Ctrl+Z", false, has && s.db->can_undo()))
        app_undo(s);
    if (ImGui::MenuItem("Redo", "Ctrl+Y", false, has && s.db->can_redo()))
        app_redo(s);
    ImGui::Separator();
    if (ImGui::MenuItem("Rename...", "N", false, has))
        dialogs::open(s, dialog_kind::rename, s.cursor);
    if (ImGui::MenuItem("Comment...", ";", false, has))
        dialogs::open(s, dialog_kind::comment, s.cursor);
    ImGui::Separator();
    if (ImGui::MenuItem("Search...", "Ctrl+F", false, has))
        dialogs::open(s, dialog_kind::find, s.cursor);
    if (ImGui::MenuItem("Search bytes...", "Alt+B", false, has))
        dialogs::open(s, dialog_kind::search, s.cursor);
    if (ImGui::MenuItem("Copy address", nullptr, false, has))
        ImGui::SetClipboardText(s.db->fmt_addr(s.cursor).c_str());
    ImGui::Separator();
    if (ImGui::MenuItem("Bookmark this line", "Alt+M", false, has))
        app_toggle_bookmark(s, s.cursor);
    if (ImGui::MenuItem("Bookmarks...", "Ctrl+M", false, has))
        dialogs::open(s, dialog_kind::bookmarks, s.cursor);
    ImGui::EndMenu();
}

static void jump_menu(app_state& s)
{
    if (!ImGui::BeginMenu("Jump"))
        return;
    bool has = s.db != nullptr;
    if (ImGui::MenuItem("Jump to address or name...", "G", false, has))
        dialogs::open(s, dialog_kind::jump, s.cursor);
    if (ImGui::MenuItem("Follow operand", "Enter", false, has))
        app_follow(s, s.cursor);
    if (ImGui::MenuItem("Back", "Esc", false, !s.back.empty()))
        app_back(s);
    if (ImGui::MenuItem("Forward", "Ctrl+Enter", false, !s.forward.empty()))
        app_forward(s);
    ImGui::Separator();
    if (ImGui::MenuItem("Entry point", nullptr, false, has && s.db->bin.has_entry))
        app_jump(s, s.db->bin.entry);
    if (ImGui::MenuItem("References to here...", "X", false, has))
        dialogs::open(s, dialog_kind::xrefs, s.cursor);
    ImGui::EndMenu();
}

static void view_menu(app_state& s)
{
    if (!ImGui::BeginMenu("View"))
        return;
    if (ImGui::MenuItem("Disassembly listing", "Space", s.view == center_view::listing))
        s.view = center_view::listing;
    if (ImGui::MenuItem("Function graph", "Space", s.view == center_view::graph))
        s.view = center_view::graph;
    if (ImGui::MenuItem("Pseudocode", "F5", s.view == center_view::pseudo))
        s.view = center_view::pseudo;
    if (ImGui::MenuItem("Listing and pseudocode", "Shift+F5", s.view == center_view::split))
        s.view = center_view::split;
    ImGui::Separator();
    ImGui::MenuItem("Functions panel", nullptr, &s.show_left);
    ImGui::MenuItem("Info and CPU panels", nullptr, &s.show_right);
    ImGui::MenuItem("Output panel", nullptr, &s.show_bottom);
    ImGui::MenuItem("Opcode bytes", nullptr, &s.show_bytes);
    ImGui::Separator();
    if (ImGui::BeginMenu("Theme")) {
        if (ImGui::MenuItem("Dark", nullptr, s.theme == theme::ui_theme::dark))
            app_set_theme(s, theme::ui_theme::dark);
        if (ImGui::MenuItem("Light", nullptr, s.theme == theme::ui_theme::light))
            app_set_theme(s, theme::ui_theme::light);
        if (ImGui::MenuItem("High contrast", nullptr, s.theme == theme::ui_theme::contrast))
            app_set_theme(s, theme::ui_theme::contrast);
        ImGui::EndMenu();
    }
    if (ImGui::MenuItem("Bigger text", "Ctrl+="))
        app_set_font_size(s, s.font_size + 1);
    if (ImGui::MenuItem("Smaller text", "Ctrl+-"))
        app_set_font_size(s, s.font_size - 1);
    if (ImGui::MenuItem("Reset text size", "Ctrl+0"))
        app_set_font_size(s, 15);
    ImGui::EndMenu();
}

static void debug_menu(app_state& s)
{
    if (!ImGui::BeginMenu("Debug"))
        return;
    dbg_state st = s.dbg.state();
    std::string why;
    bool can = app_can_debug(s, &why);
    const char* run_label = st == dbg_state::stopped ? "Continue" : "Start debugging";
    if (ImGui::MenuItem(run_label, "F9", false, (st == dbg_state::none && can) || st == dbg_state::stopped))
        dbg_continue(s);
    if (!can && st == dbg_state::none)
        ImGui::SetItemTooltip("%s", why.c_str());
    bool can_step = st == dbg_state::stopped && !dbg_stepping(s);
    std::string times = s.step_count > 1 ? util::fmt(" x%d", s.step_count) : std::string();
    if (ImGui::MenuItem(("Step into" + times).c_str(), "F7", false, can_step))
        dbg_step_into(s);
    if (ImGui::MenuItem(("Step over" + times).c_str(), "F8", false, can_step))
        dbg_step_over(s);
    if (ImGui::MenuItem("Step out (run until return)", "Ctrl+F9", false, can_step))
        dbg_step_out(s);
    if (ImGui::MenuItem(("Step back" + times).c_str(), "Shift+F7", false, can_step && s.dbg.steps_recorded()))
        dbg_step_back(s);
    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 7);
    if (ImGui::InputInt("instructions per step", &s.step_count, 1, 10))
        s.step_count = std::min(100000, std::max(1, s.step_count));
    ImGui::SetItemTooltip("F7 / F8 run this many instructions at once");
    if (ImGui::MenuItem("Run to cursor", "F4", false, st == dbg_state::stopped && s.dbg_mapped))
        dbg_run_to_cursor(s);
    if (ImGui::MenuItem("Pause", "F12", false, st == dbg_state::running))
        dbg_pause(s);
    if (ImGui::MenuItem("Stop (kill process)", "Ctrl+F2", false, st != dbg_state::none))
        dbg_stop(s);
    if (ImGui::MenuItem("Detach", nullptr, false, st != dbg_state::none))
        dbg_detach(s);
    ImGui::Separator();
    if (ImGui::MenuItem("Toggle breakpoint", "F2", false, s.db != nullptr))
        app_bp_key(s, s.cursor);
    if (ImGui::MenuItem("Breakpoint condition...", "Shift+F2", false, s.db != nullptr))
        dialogs::open(s, dialog_kind::bp_condition, s.cursor);
    if (ImGui::MenuItem("Watch memory...", "F2 on data", false, s.db != nullptr))
        dialogs::open(s, dialog_kind::watch, s.cursor);
    if (ImGui::MenuItem("Attach to process...", nullptr, false, debugger::supported() && st == dbg_state::none))
        dialogs::open(s, dialog_kind::attach, 0);
    if (ImGui::MenuItem("Program arguments...", nullptr, false, st == dbg_state::none))
        dialogs::open(s, dialog_kind::run_args, 0);
    ImGui::MenuItem("Break at the entry point", nullptr, &s.dbg.break_on_entry);
    ImGui::EndMenu();
}

static void ai_menu(app_state& s)
{
    if (!ImGui::BeginMenu("AI"))
        return;
    bool running = app_mcp_running(s);
    if (ImGui::MenuItem("Connect an AI..."))
        dialogs::open(s, dialog_kind::ai, 0);
    if (ImGui::MenuItem(running ? "Stop the AI server" : "Start the AI server")) {
        if (running)
            app_mcp_stop(s);
        else
            app_mcp_start(s);
    }
    ImGui::SetItemTooltip("serves the open file over MCP to an AI client on this computer");
    if (ImGui::MenuItem("Copy the Claude Code command"))
        ImGui::SetClipboardText(util::fmt("claude mcp add --transport http ceasta http://127.0.0.1:%d/mcp", s.mcp_port).c_str());
    ImGui::Separator();
    ImGui::MenuItem("Let it use the debugger", nullptr, &s.mcp_allow_debug, !running && debugger::supported());
    ImGui::SetItemTooltip("start, step and inspect the program (it runs on this computer)%s",
        running ? "\nstop the server to change this" : "");
    ImGui::MenuItem("Let it run Lua", nullptr, &s.mcp_allow_lua, !running);
    ImGui::SetItemTooltip("any code, with file and shell access%s", running ? "\nstop the server to change this" : "");
    ImGui::EndMenu();
}

static void plugins_menu(app_state& s)
{
    if (!ImGui::BeginMenu("Plugins"))
        return;
    const std::vector<lua_command>& cmds = s.lua.commands();
    if (cmds.empty())
        ImGui::TextDisabled("no plugin commands");
    int run = -1;
    for (size_t i = 0; i < cmds.size(); i++) {
        if (ImGui::MenuItem(cmds[i].name.c_str(), nullptr, false, s.db != nullptr))
            run = (int)i;
        std::string tip = cmds[i].help.empty() ? cmds[i].plugin : cmds[i].help + "\n(" + cmds[i].plugin + ")";
        if (!tip.empty())
            ImGui::SetItemTooltip("%s", tip.c_str());
    }
    ImGui::Separator();
    if (ImGui::MenuItem("Reload plugins")) {
        int ok = s.lua.reload_plugins();
        app_log(s, util::fmt("reloaded %d of %zu plugins", ok, s.lua.plugin_files().size()));
    }
    if (ImGui::MenuItem("Open my plugins folder", nullptr, false, !s.sandboxed))
        os::open_in_shell(os::join(os::user_dir(), "plugins"));
    if (ImGui::MenuItem("Lua console"))
        s.bottom_tab_request = 0, s.show_bottom = true, s.focus_console = true;
    ImGui::EndMenu();
    if (run >= 0) {
        s.lua.run_command((size_t)run);
        app_names_changed(s);
    }
}

static void help_menu(app_state& s)
{
    if (!ImGui::BeginMenu("Help"))
        return;
    if (ImGui::MenuItem("All actions...", "Ctrl+Shift+P"))
        dialogs::open(s, dialog_kind::palette, s.cursor);
    if (ImGui::MenuItem("Keyboard shortcuts", "F1"))
        dialogs::open(s, dialog_kind::shortcuts, 0);
    if (ImGui::MenuItem("About ceasta"))
        dialogs::open(s, dialog_kind::about, 0);
    ImGui::EndMenu();
}

// toolbar button with a tooltip naming its shortcut
static bool tool(const char* label, const char* tip, bool enabled = true)
{
    ImGui::BeginDisabled(!enabled);
    bool r = ImGui::Button(label);
    ImGui::EndDisabled();
    ImGui::SetItemTooltip("%s", tip);
    return r;
}

// looks like a search box; clicking it opens search (which also jumps to addresses and names)
static void search_field(app_state& s, float width)
{
    ImGui::BeginDisabled(!s.db);
    ImGui::PushStyleColor(ImGuiCol_Button, ImGui::GetStyleColorVec4(ImGuiCol_FrameBg));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImGui::GetStyleColorVec4(ImGuiCol_FrameBgHovered));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImGui::GetStyleColorVec4(ImGuiCol_FrameBgActive));
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled));
    ImGui::PushStyleVar(ImGuiStyleVar_ButtonTextAlign, ImVec2(0.0f, 0.5f));
    bool clicked = ImGui::Button("search or jump to...###tb_search", ImVec2(width, 0));
    ImGui::PopStyleVar();
    ImGui::PopStyleColor(4);
    ImGui::EndDisabled();
    ImGui::SetItemTooltip("functions, names, imports, strings, comments or an address (Ctrl+F)\nevery action: Ctrl+Shift+P");
    if (clicked)
        dialogs::open(s, dialog_kind::find, s.cursor);
}

// the debugger's buttons: just Run until there is a process, the rest while debugging
static void debug_buttons(app_state& s)
{
    dbg_state ds = s.dbg.state();
    if (ds == dbg_state::none) {
        std::string why;
        bool can = app_can_debug(s, &why);
        if (tool("Run", can ? "start debugging (F9)" : why.c_str(), can))
            dbg_continue(s);
        return;
    }
    bool stopped = ds == dbg_state::stopped && !dbg_stepping(s);
    if (tool("Continue", "run to the next breakpoint (F9)", stopped))
        dbg_continue(s);
    ImGui::SameLine();
    std::string times = s.step_count > 1 ? util::fmt(" x%d", s.step_count) : std::string();
    if (tool(("Step in" + times + "###step_in").c_str(), "step into (F7)", stopped))
        dbg_step_into(s);
    ImGui::SameLine();
    if (tool(("Step over" + times + "###step_over").c_str(), "step over (F8)", stopped))
        dbg_step_over(s);
    ImGui::SameLine(0, 2);
    ImGui::AlignTextToFramePadding();
    ImGui::TextDisabled("x");
    ImGui::SameLine(0, 2);
    ImGui::SetNextItemWidth(ImGui::CalcTextSize("000000").x + ImGui::GetStyle().FramePadding.x * 2);
    if (ImGui::InputInt("##step_count", &s.step_count, 0, 0))
        s.step_count = std::min(100000, std::max(1, s.step_count));
    ImGui::SetItemTooltip("instructions per step: F7 / F8 run this many at once");
    ImGui::SameLine();
    if (tool("Step out", "run until this function returns (Ctrl+F9)", stopped))
        dbg_step_out(s);
    ImGui::SameLine();
    size_t back = s.dbg.steps_recorded();
    if (tool("Back", back ? util::fmt("step back - undo the last step (Shift+F7), %zu can be undone", back).c_str()
                          : "step back (Shift+F7): steps you take with F7 / F8 can be undone",
            stopped && back))
        dbg_step_back(s);
    ImGui::SameLine();
    if (tool("Pause", "break into the running program (F12)", ds == dbg_state::running || dbg_stepping(s)))
        dbg_pause(s);
    ImGui::SameLine();
    if (tool("Stop", "end the debugged program (Ctrl+F2)", true))
        dbg_stop(s);
}

static void toolbar(app_state& s)
{
    ImGuiStyle& st = ImGui::GetStyle();
    ImGui::SetCursorPos(ImVec2(st.ItemSpacing.x, ImGui::GetCursorPosY() + st.ItemSpacing.y));
    if (tool("Open", "open a file or a .ceasta database (Ctrl+O)", !app_loading(s)))
        app_open_dialog(s);
    ImGui::SameLine();
    if (tool("<", "back (Esc, mouse back)", !s.back.empty()))
        app_back(s);
    ImGui::SameLine(0, 2);
    if (tool(">", "forward (Ctrl+Enter, mouse forward)", !s.forward.empty()))
        app_forward(s);
    ImGui::SameLine();
    search_field(s, ImGui::GetFontSize() * 18);
    ImGui::SameLine(0, st.ItemSpacing.x * 3);
    debug_buttons(s);
    if (s.db) {
        // what's open, on the right
        const binary& b = s.db->bin;
        std::string what = util::fmt("%s  -  %s %s", b.name.c_str(), format_name(b.format), arch_name(b.arch));
        float w = ImGui::CalcTextSize(what.c_str()).x;
        float right = ImGui::GetWindowWidth() - st.ItemSpacing.x * 2 - w;
        ImGui::SameLine(0, st.ItemSpacing.x * 3);
        if (ImGui::GetCursorPosX() < right)
            ImGui::SetCursorPosX(right);
        ImGui::AlignTextToFramePadding();
        ImGui::TextDisabled("%s", what.c_str());
        ImGui::SetItemTooltip("%s", b.kind.c_str());
    }
    ImGui::Dummy(ImVec2(0, st.ItemSpacing.y));
}

void draw(app_state& s)
{
    if (ImGui::BeginMenuBar()) {
        file_menu(s);
        edit_menu(s);
        jump_menu(s);
        view_menu(s);
        debug_menu(s);
        ai_menu(s);
        plugins_menu(s);
        help_menu(s);
        ImGui::EndMenuBar();
    }
    toolbar(s);
    ImGui::Separator();
}

}
