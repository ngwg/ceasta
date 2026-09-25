#include "ui/palette.h"
#include "core/util.h"
#include "imgui.h"
#include "theme.h"
#include "ui/dialogs.h"
#include <algorithm>

namespace palette {

namespace {

struct action {
    const char* group;
    const char* name;
    const char* keys;
    bool (*enabled)(const app_state&);
    void (*run)(app_state&);
};

bool always(const app_state&) { return true; }
bool has_file(const app_state& s) { return s.db != nullptr; }
bool not_loading(const app_state& s) { return !app_loading(s); }
bool dirty(const app_state& s) { return s.db && (s.db->dirty || s.db->project_file.empty()); }
bool no_process(const app_state& s) { return s.dbg.state() == dbg_state::none; }
bool has_process(const app_state& s) { return s.dbg.state() != dbg_state::none; }
bool stopped(const app_state& s) { return s.dbg.state() == dbg_state::stopped && !dbg_stepping(s); }
bool running(const app_state& s) { return s.dbg.state() == dbg_state::running || dbg_stepping(s); }
bool can_start(const app_state& s) { return (s.dbg.state() == dbg_state::none && app_can_debug(s)) || stopped(s); }

void open_dialog(app_state& s, dialog_kind k) { dialogs::open(s, k, s.cursor); }

} // namespace

static const std::vector<action>& actions()
{
    static const std::vector<action> list = {
        {"File", "Open...", "Ctrl+O", not_loading, [](app_state& s) { app_open_dialog(s); }},
        {"File", "Open as raw code...", "", not_loading, [](app_state& s) { open_dialog(s, dialog_kind::open_raw); }},
        {"File", "Save", "Ctrl+S", dirty, [](app_state& s) { app_save(s); }},
        {"File", "Save as...", "Ctrl+Shift+S", has_file, [](app_state& s) { app_save_as(s); }},
        {"File", "Close file", "", has_file, [](app_state& s) { app_close_file(s); }},
        {"File", "Exit", "Alt+F4", always, [](app_state& s) { app_quit(s); }},

        {"Edit", "Undo", "Ctrl+Z", [](const app_state& s) { return s.db && s.db->can_undo(); }, [](app_state& s) { app_undo(s); }},
        {"Edit", "Redo", "Ctrl+Y", [](const app_state& s) { return s.db && s.db->can_redo(); }, [](app_state& s) { app_redo(s); }},
        {"Edit", "Bookmark this line", "Alt+M", has_file, [](app_state& s) { app_toggle_bookmark(s, s.cursor); }},
        {"Edit", "Bookmarks...", "Ctrl+M", has_file, [](app_state& s) { open_dialog(s, dialog_kind::bookmarks); }},
        {"Edit", "Rename...", "N", has_file, [](app_state& s) { open_dialog(s, dialog_kind::rename); }},
        {"Edit", "Comment...", ";", has_file, [](app_state& s) { open_dialog(s, dialog_kind::comment); }},
        {"Edit", "Search names, imports, strings...", "Ctrl+F", has_file, [](app_state& s) { open_dialog(s, dialog_kind::find); }},
        {"Edit", "Search bytes...", "Alt+B", has_file, [](app_state& s) { open_dialog(s, dialog_kind::search); }},
        {"Edit", "Copy address", "", has_file, [](app_state& s) { ImGui::SetClipboardText(s.db->fmt_addr(s.cursor).c_str()); }},

        {"Jump", "Jump to address or name...", "G", has_file, [](app_state& s) { open_dialog(s, dialog_kind::jump); }},
        {"Jump", "Follow operand", "Enter", has_file, [](app_state& s) { app_follow(s, s.cursor); }},
        {"Jump", "Back", "Esc", [](const app_state& s) { return !s.back.empty(); }, [](app_state& s) { app_back(s); }},
        {"Jump", "Forward", "Ctrl+Enter", [](const app_state& s) { return !s.forward.empty(); }, [](app_state& s) { app_forward(s); }},
        {"Jump", "Entry point", "", [](const app_state& s) { return s.db && s.db->bin.has_entry; },
            [](app_state& s) { app_jump(s, s.db->bin.entry); }},
        {"Jump", "References to here...", "X", has_file, [](app_state& s) { open_dialog(s, dialog_kind::xrefs); }},

        {"View", "Listing", "Space", has_file, [](app_state& s) { s.view = center_view::listing; }},
        {"View", "Function graph", "Space", has_file, [](app_state& s) { s.view = center_view::graph; }},
        {"View", "Pseudocode (decompiler)", "F5", has_file, [](app_state& s) { s.view = center_view::pseudo; }},
        {"View", "Show / hide the functions panel", "", always, [](app_state& s) { s.show_left = !s.show_left; }},
        {"View", "Show / hide the info panel", "", always, [](app_state& s) { s.show_right = !s.show_right; }},
        {"View", "Show / hide the output panel", "", always, [](app_state& s) { s.show_bottom = !s.show_bottom; }},
        {"View", "Show / hide opcode bytes", "", always, [](app_state& s) { s.show_bytes = !s.show_bytes; }},
        {"View", "Bigger text", "Ctrl+=", always, [](app_state& s) { app_set_font_size(s, s.font_size + 1); }},
        {"View", "Smaller text", "Ctrl+-", always, [](app_state& s) { app_set_font_size(s, s.font_size - 1); }},
        {"View", "Dark theme", "", always, [](app_state& s) { app_set_theme(s, theme::ui_theme::dark); }},
        {"View", "Light theme", "", always, [](app_state& s) { app_set_theme(s, theme::ui_theme::light); }},
        {"View", "High contrast theme", "", always, [](app_state& s) { app_set_theme(s, theme::ui_theme::contrast); }},

        {"Debug", "Start debugging / continue", "F9", can_start, [](app_state& s) { dbg_continue(s); }},
        {"Debug", "Step into", "F7", stopped, [](app_state& s) { dbg_step_into(s); }},
        {"Debug", "Step over", "F8", stopped, [](app_state& s) { dbg_step_over(s); }},
        {"Debug", "Step out (run until this function returns)", "Ctrl+F9", stopped, [](app_state& s) { dbg_step_out(s); }},
        {"Debug", "Step back (undo the last step)", "Shift+F7",
            [](const app_state& s) { return stopped(s) && s.dbg.steps_recorded() > 0; }, [](app_state& s) { dbg_step_back(s); }},
        {"Debug", "Run to cursor", "F4", [](const app_state& s) { return stopped(s) && s.dbg_mapped; },
            [](app_state& s) { dbg_run_to_cursor(s); }},
        {"Debug", "Pause", "F12", running, [](app_state& s) { dbg_pause(s); }},
        {"Debug", "Stop (end the program)", "Ctrl+F2", has_process, [](app_state& s) { dbg_stop(s); }},
        {"Debug", "Detach", "", has_process, [](app_state& s) { dbg_detach(s); }},
        {"Debug", "Toggle breakpoint", "F2", has_file, [](app_state& s) { app_bp_key(s, s.cursor); }},
        {"Debug", "Watch memory (stop when it's written)...", "F2 on data", has_file,
            [](app_state& s) { open_dialog(s, dialog_kind::watch); }},
        {"Debug", "Call stack (how it got here)", "", has_process,
            [](app_state& s) { s.bottom_tab_request = 3, s.show_bottom = true; }},
        {"Debug", "Memory map", "", has_process, [](app_state& s) { s.bottom_tab_request = 4, s.show_bottom = true; }},
        {"Debug", "Breakpoint condition (stop only when...)", "Shift+F2", has_file,
            [](app_state& s) { open_dialog(s, dialog_kind::bp_condition); }},
        {"Debug", "Attach to a process...", "", [](const app_state& s) { return no_process(s) && debugger::supported(); },
            [](app_state& s) { open_dialog(s, dialog_kind::attach); }},
        {"Debug", "Program arguments...", "", no_process, [](app_state& s) { open_dialog(s, dialog_kind::run_args); }},
        {"Debug", "Stop at the entry point: on / off", "", always,
            [](app_state& s) { s.dbg.break_on_entry = !s.dbg.break_on_entry; }},

        {"AI", "Connect an AI...", "", always, [](app_state& s) { open_dialog(s, dialog_kind::ai); }},
        {"AI", "Start / stop the AI server", "", always,
            [](app_state& s) { app_mcp_running(s) ? app_mcp_stop(s) : (void)app_mcp_start(s); }},

        {"Help", "Keyboard shortcuts", "F1", always, [](app_state& s) { open_dialog(s, dialog_kind::shortcuts); }},
        {"Help", "About ceasta", "", always, [](app_state& s) { open_dialog(s, dialog_kind::about); }},
    };
    return list;
}

namespace {

// up / down in the box move the selection
int palette_keys(ImGuiInputTextCallbackData* cb)
{
    int* move = (int*)cb->UserData;
    if (cb->EventFlag == ImGuiInputTextFlags_CallbackHistory)
        *move += cb->EventKey == ImGuiKey_UpArrow ? -1 : 1;
    return 0;
}

// every word of the query is in the text, in any order and case
bool matches(const std::string& text, const std::vector<std::string>& words)
{
    for (const std::string& w : words)
        if (!util::icontains(text, w))
            return false;
    return true;
}

bool enabled(const app_state& s, int index)
{
    const std::vector<action>& list = actions();
    if (index < (int)list.size())
        return list[(size_t)index].enabled(s);
    return s.db != nullptr; // a plugin command
}

} // namespace

void draw(app_state& s, dialog_state& d)
{
    const std::vector<action>& list = actions();
    const std::vector<lua_command>& cmds = s.lua.commands();
    if (ImGui::IsWindowAppearing())
        ImGui::SetKeyboardFocusHere();
    int move = 0;
    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 36);
    bool enter = ImGui::InputTextWithHint("##palette", "what do you want to do?", d.buf, sizeof(d.buf),
        ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_CallbackHistory, palette_keys, &move);

    std::string q = util::trim(d.buf);
    if (q != d.hits_query) {
        d.hits_query = q;
        d.sel = 0;
    }
    std::vector<std::string> words = util::split(q, " ");
    std::vector<int> shown;
    for (size_t i = 0; i < list.size(); i++)
        if (matches(std::string(list[i].group) + " " + list[i].name, words))
            shown.push_back((int)i);
    for (size_t i = 0; i < cmds.size(); i++)
        if (matches("Plugins " + cmds[i].name, words))
            shown.push_back((int)(list.size() + i));
    int n = (int)shown.size();
    if (n)
        d.sel = std::max(0, std::min(n - 1, d.sel + move));

    int pick = -1;
    ImVec2 size(ImGui::GetFontSize() * 36, ImGui::GetTextLineHeightWithSpacing() * 14);
    if (ImGui::BeginTable("##actions", 2, ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit, size)) {
        ImGui::TableSetupColumn("action", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("keys");
        for (int i = 0; i < n; i++) {
            int idx = shown[(size_t)i];
            bool on = enabled(s, idx);
            bool plugin = idx >= (int)list.size();
            const char* group = plugin ? "Plugins" : list[(size_t)idx].group;
            const std::string& name = plugin ? cmds[(size_t)(idx - (int)list.size())].name : std::string(list[(size_t)idx].name);
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::PushID(i);
            std::string label = std::string(group) + ":  " + name;
            ImGuiSelectableFlags sf = ImGuiSelectableFlags_SpanAllColumns | (on ? 0 : ImGuiSelectableFlags_Disabled);
            if (ImGui::Selectable(label.c_str(), i == d.sel, sf))
                pick = idx;
            if (move && i == d.sel)
                ImGui::SetScrollHereY();
            ImGui::PopID();
            ImGui::TableNextColumn();
            if (!plugin && list[(size_t)idx].keys[0])
                ImGui::TextDisabled("%s", list[(size_t)idx].keys);
        }
        ImGui::EndTable();
    }
    if (enter && n && enabled(s, shown[(size_t)d.sel]))
        pick = shown[(size_t)d.sel];
    ImGui::TextDisabled(n ? "enter runs it, esc closes" : "nothing matches");
    if (pick >= 0) {
        d.run_action = pick;
        ImGui::CloseCurrentPopup();
    }
}

void run(app_state& s, int index)
{
    const std::vector<action>& list = actions();
    if (index < 0 || !enabled(s, index))
        return;
    if (index < (int)list.size()) {
        list[(size_t)index].run(s);
        return;
    }
    s.lua.run_command((size_t)(index - (int)list.size()));
    app_names_changed(s);
}

}
