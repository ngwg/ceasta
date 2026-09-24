#include "ui/top_bar.h"
#include "core/os.h"
#include "core/util.h"
#include "imgui.h"
#include "ui/dialogs.h"

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
    if (ImGui::MenuItem("Save names and comments", "Ctrl+S", false, s.db != nullptr))
        app_save(s);
    if (ImGui::MenuItem("Save project file (next to the binary)", nullptr, false, s.db != nullptr))
        app_save_project(s);
    if (ImGui::MenuItem("Close file", nullptr, false, s.db != nullptr))
        app_close_file(s);
    ImGui::Separator();
    if (ImGui::MenuItem("Exit", "Alt+F4") && s.platform.quit)
        s.platform.quit();
    ImGui::EndMenu();
}

static void edit_menu(app_state& s)
{
    if (!ImGui::BeginMenu("Edit"))
        return;
    bool has = s.db != nullptr;
    if (ImGui::MenuItem("Rename...", "N", false, has))
        dialogs::open(s, dialog_kind::rename, s.cursor);
    if (ImGui::MenuItem("Comment...", ";", false, has))
        dialogs::open(s, dialog_kind::comment, s.cursor);
    ImGui::Separator();
    if (ImGui::MenuItem("Search bytes...", "Alt+B", false, has))
        dialogs::open(s, dialog_kind::search, s.cursor);
    if (ImGui::MenuItem("Copy address", nullptr, false, has))
        ImGui::SetClipboardText(s.db->fmt_addr(s.cursor).c_str());
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
    if (ImGui::MenuItem("Step into", "F7", false, st == dbg_state::stopped))
        dbg_step_into(s);
    if (ImGui::MenuItem("Step over", "F8", false, st == dbg_state::stopped))
        dbg_step_over(s);
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
        app_toggle_bp(s, s.cursor);
    if (ImGui::MenuItem("Attach to process...", nullptr, false, debugger::supported() && st == dbg_state::none))
        dialogs::open(s, dialog_kind::attach, 0);
    if (ImGui::MenuItem("Program arguments...", nullptr, false, st == dbg_state::none))
        dialogs::open(s, dialog_kind::run_args, 0);
    ImGui::MenuItem("Break at the entry point", nullptr, &s.dbg.break_on_entry);
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

static void toolbar(app_state& s)
{
    ImGuiStyle& st = ImGui::GetStyle();
    ImGui::SetCursorPos(ImVec2(st.ItemSpacing.x, ImGui::GetCursorPosY() + st.ItemSpacing.y));
    bool has = s.db != nullptr;
    if (tool("Open", "open a file to analyze (Ctrl+O)", !app_loading(s)))
        app_open_dialog(s);
    ImGui::SameLine();
    if (tool("<", "back (Esc)", !s.back.empty()))
        app_back(s);
    ImGui::SameLine(0, 2);
    if (tool(">", "forward (Ctrl+Enter)", !s.forward.empty()))
        app_forward(s);
    ImGui::SameLine();
    if (tool("Jump", "jump to an address or name (G)", has))
        dialogs::open(s, dialog_kind::jump, s.cursor);
    ImGui::SameLine();
    const char* view_label = s.view == center_view::listing ? "Graph" : "Listing";
    if (tool(view_label, "switch between the listing and the function graph (Space)", has))
        s.view = s.view == center_view::listing ? center_view::graph : center_view::listing;

    ImGui::SameLine(0, st.ItemSpacing.x * 4);
    dbg_state ds = s.dbg.state();
    std::string why;
    bool can = app_can_debug(s, &why);
    if (tool(ds == dbg_state::stopped ? "Continue" : "Run", can || ds != dbg_state::none ? "start debugging / continue (F9)" : why.c_str(),
            (ds == dbg_state::none && can) || ds == dbg_state::stopped))
        dbg_continue(s);
    ImGui::SameLine();
    if (tool("Step in", "step into (F7)", ds == dbg_state::stopped))
        dbg_step_into(s);
    ImGui::SameLine();
    if (tool("Step over", "step over (F8)", ds == dbg_state::stopped))
        dbg_step_over(s);
    ImGui::SameLine();
    if (tool("Pause", "break into the running program (F12)", ds == dbg_state::running))
        dbg_pause(s);
    ImGui::SameLine();
    if (tool("Stop", "kill the debugged process (Ctrl+F2)", ds != dbg_state::none))
        dbg_stop(s);

    ImGui::SameLine(0, st.ItemSpacing.x * 4);
    if (s.db) {
        const binary& b = s.db->bin;
        ImGui::AlignTextToFramePadding();
        ImGui::TextDisabled("%s  |  %s %s  |  %s", b.name.c_str(), format_name(b.format), arch_name(b.arch), b.kind.c_str());
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
        plugins_menu(s);
        help_menu(s);
        ImGui::EndMenuBar();
    }
    toolbar(s);
    ImGui::Separator();
}

}
