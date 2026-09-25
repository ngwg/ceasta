#include "ui/status_bar.h"
#include "core/util.h"
#include "ui/dialogs.h"
#include "imgui.h"
#include "theme.h"

namespace status_bar {

void draw(app_state& s)
{
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 p = ImGui::GetCursorScreenPos();
    float w = ImGui::GetWindowWidth();
    float h = ImGui::GetFrameHeight();
    dl->AddRectFilled(p, ImVec2(p.x + w, p.y + h), ImGui::GetColorU32(ImGuiCol_MenuBarBg));
    ImGui::SetCursorScreenPos(ImVec2(p.x + ImGui::GetStyle().ItemSpacing.x, p.y));
    ImGui::AlignTextToFramePadding();

    // state first: what the program is doing right now
    if (s.job) {
        ImGui::TextColored(ImVec4(0.9f, 0.8f, 0.4f, 1), "analyzing %d%%", s.job->progress.percent.load());
    } else if (dbg_stepping(s)) {
        ImGui::TextColored(ImVec4(0.5f, 0.9f, 0.5f, 1), "debugging: stepping (%d of %d)", s.steps_done, s.steps_wanted);
    } else if (s.dbg.state() == dbg_state::running) {
        ImGui::TextColored(ImVec4(0.5f, 0.9f, 0.5f, 1), "debugging: running");
    } else if (s.dbg.state() == dbg_state::stopped) {
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(theme::pc_arrow), "debugging: stopped (%s)", app_stop_text(s).c_str());
    } else {
        ImGui::TextDisabled("ready");
    }
    if (s.db) {
        database& db = *s.db;
        ImGui::SameLine(0, 24);
        ImGui::TextDisabled("|");
        ImGui::SameLine();
        ImGui::Text("%s:%s", db.seg_name(s.cursor).c_str(), db.fmt_addr(s.cursor).c_str());
        ImGui::SameLine();
        ImGui::TextDisabled("%s", db.location(s.cursor).c_str());
        ImGui::SameLine(0, 24);
        ImGui::TextDisabled("|  %zu functions  %s%s", db.an.funcs.size(), db.dirty ? theme::keys("  unsaved changes (ctrl+s)") : "",
            db.breakpoints.empty() ? "" : util::fmt("  %zu breakpoints", db.breakpoints.size()).c_str());
    }
    // names an ai suggested: a click opens the review
    if (s.db && !s.db->suggestions.empty()) {
        ImGui::SameLine(0, 24);
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(theme::call));
        std::string t = util::fmt("|  %zu suggested name%s to review", s.db->suggestions.size(), s.db->suggestions.size() == 1 ? "" : "s");
        ImGui::TextUnformatted(t.c_str());
        ImGui::PopStyleColor();
        if (ImGui::IsItemHovered())
            ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
        if (ImGui::IsItemClicked())
            dialogs::open(s, dialog_kind::review, 0);
    }
    if (s.mcp) {
        std::string url = app_mcp_url(s), err = app_mcp_error(s);
        ImGui::SameLine(0, 24);
        if (!err.empty())
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(theme::log_error), "|  ai server couldn't listen on :%d", s.mcp_port);
        else if (!url.empty())
            ImGui::TextColored(ImVec4(0.5f, 0.9f, 0.5f, 1), "|  ai server on :%d  (%d calls)", s.mcp_port, app_mcp_calls(s));
        else
            ImGui::TextDisabled("|  ai server starting");
    }
    // the dummy makes the status line a real item so the window accounts for it
    ImGui::SetCursorScreenPos(p);
    ImGui::Dummy(ImVec2(w, h));
}

}
