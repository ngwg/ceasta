#include "ui/bottom_panel.h"
#include "core/util.h"
#include "imgui.h"
#include "theme.h"
#include "ui/dialogs.h"
#include <algorithm>
#include <cstring>

namespace bottom_panel {

static int history_cb(ImGuiInputTextCallbackData* data)
{
    app_state& s = *(app_state*)data->UserData;
    if (data->EventFlag != ImGuiInputTextFlags_CallbackHistory || s.console_history.empty())
        return 0;
    int n = (int)s.console_history.size();
    if (data->EventKey == ImGuiKey_UpArrow)
        s.history_pos = s.history_pos < 0 ? n - 1 : std::max(0, s.history_pos - 1);
    else if (data->EventKey == ImGuiKey_DownArrow)
        s.history_pos = s.history_pos < 0 ? -1 : (s.history_pos + 1 >= n ? -1 : s.history_pos + 1);
    data->DeleteChars(0, data->BufTextLen);
    if (s.history_pos >= 0)
        data->InsertChars(0, s.console_history[(size_t)s.history_pos].c_str());
    return 0;
}

static void output(app_state& s)
{
    float input_h = ImGui::GetFrameHeightWithSpacing();
    ImGui::BeginChild("##log", ImVec2(0, -input_h), ImGuiChildFlags_None, ImGuiWindowFlags_HorizontalScrollbar);
    ImGuiListClipper clip;
    clip.Begin((int)s.log.size());
    while (clip.Step())
        for (int i = clip.DisplayStart; i < clip.DisplayEnd; i++) {
            const log_line& l = s.log[(size_t)i];
            ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(theme::log_color(l.level)));
            ImGui::TextUnformatted(l.text.c_str());
            ImGui::PopStyleColor();
        }
    if (s.log_to_bottom) {
        ImGui::SetScrollHereY(1.0f);
        s.log_to_bottom = false;
    }
    if (ImGui::BeginPopupContextWindow("##log_ctx")) {
        if (ImGui::MenuItem("Copy all")) {
            std::string all;
            for (const log_line& l : s.log)
                all += l.text + "\n";
            ImGui::SetClipboardText(all.c_str());
        }
        if (ImGui::MenuItem("Clear"))
            s.log.clear();
        ImGui::EndPopup();
    }
    ImGui::EndChild();

    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(theme::log_echo), "Lua>");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(-ImGui::CalcTextSize("Clear").x - ImGui::GetStyle().FramePadding.x * 2 - ImGui::GetStyle().ItemSpacing.x);
    if (s.focus_console) {
        ImGui::SetKeyboardFocusHere();
        s.focus_console = false;
    }
    ImGuiInputTextFlags fl = ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_CallbackHistory;
    if (ImGui::InputTextWithHint("##console", "type lua and press enter, e.g.  ceasta.name(ceasta.here())", s.console,
            sizeof(s.console), fl, history_cb, &s)) {
        std::string code = util::trim(s.console);
        if (!code.empty()) {
            app_log(s, "> " + code, 3);
            s.console_history.push_back(code);
            if (s.console_history.size() > 200)
                s.console_history.erase(s.console_history.begin());
            s.history_pos = -1;
            s.lua.run_console(code);
            app_names_changed(s);
        }
        s.console[0] = '\0';
        ImGui::SetKeyboardFocusHere(-1);
    }
    ImGui::SameLine();
    if (ImGui::Button("Clear"))
        s.log.clear();
}

static void hex(app_state& s)
{
    if (!s.db) {
        ImGui::TextDisabled("no file loaded");
        return;
    }
    database& db = *s.db;
    ImGui::Checkbox("follow cursor", &s.hex_follow);
    ImGui::SameLine();
    bool live_ok = s.dbg.state() == dbg_state::stopped && s.dbg_mapped;
    ImGui::BeginDisabled(!live_ok);
    ImGui::Checkbox("live memory", &s.hex_live);
    ImGui::EndDisabled();
    ImGui::SetItemTooltip("show the debugged process's memory instead of the file");
    bool live = live_ok && s.hex_live;

    const segment* seg = db.bin.seg_at(s.hex_addr);
    if (!seg)
        seg = db.bin.seg_at(s.cursor);
    if (!seg) {
        ImGui::TextDisabled("nothing mapped here");
        return;
    }
    ImGui::SameLine();
    ImGui::TextDisabled("%s  %s - %s", seg->name.c_str(), db.fmt_addr(seg->start).c_str(), db.fmt_addr(seg->end).c_str());

    uint64_t first = seg->start & ~15ull;
    uint64_t rows = (seg->end - first + 15) / 16;
    uint64_t sel = s.hex_addr;
    uint32_t sel_len = std::max<uint32_t>(1, db.an.item_size(db.an.item_head(sel)));
    uint64_t sel_head = db.an.item_head(sel);
    float cw = ImGui::CalcTextSize("0").x;
    float lh = ImGui::GetTextLineHeightWithSpacing();

    ImGui::BeginChild("##hex", ImVec2(0, 0), ImGuiChildFlags_None, ImGuiWindowFlags_NoNav);
    ImDrawList* dl = ImGui::GetWindowDrawList();
    int target_row = (int)((sel_head - first) / 16);
    ImGuiListClipper clip;
    clip.Begin((int)std::min<uint64_t>(rows, 0x7fffffff), lh);
    if (s.hex_follow)
        clip.IncludeItemByIndex(target_row);
    static uint64_t last_scrolled = ~0ull;
    while (clip.Step()) {
        for (int r = clip.DisplayStart; r < clip.DisplayEnd; r++) {
            uint64_t a = first + (uint64_t)r * 16;
            if (r == target_row && last_scrolled != sel_head) {
                float y = r * lh;
                if (y < ImGui::GetScrollY() || y + lh > ImGui::GetScrollY() + ImGui::GetWindowHeight())
                    ImGui::SetScrollHereY(0.4f);
                last_scrolled = sel_head;
            }
            uint8_t buf[16] = {};
            bool have[16] = {};
            if (live) {
                size_t got = s.dbg.read(app_to_runtime(s, a), buf, 16);
                for (size_t i = 0; i < 16; i++)
                    have[i] = i < got && seg->contains(a + i);
            } else {
                for (int i = 0; i < 16; i++)
                    have[i] = seg->contains(a + (uint64_t)i) && db.bin.read_u8(a + (uint64_t)i, buf[i]);
            }
            ImVec2 p = ImGui::GetCursorScreenPos();
            std::string addr = db.fmt_addr(a);
            dl->AddText(p, theme::addr, addr.c_str());
            float hx = p.x + cw * (float)(addr.size() + 2);
            float ax = hx + cw * 50;
            for (int i = 0; i < 16; i++) {
                float x = hx + cw * (float)(i * 3 + (i >= 8 ? 1 : 0));
                uint64_t ba = a + (uint64_t)i;
                bool in_sel = ba >= sel_head && ba < sel_head + sel_len;
                if (in_sel) {
                    dl->AddRectFilled(ImVec2(x - 1, p.y), ImVec2(x + cw * 2 + 1, p.y + lh - 1), theme::row_selected);
                    dl->AddRectFilled(ImVec2(ax + cw * i, p.y), ImVec2(ax + cw * (i + 1), p.y + lh - 1), theme::row_selected);
                }
                if (!have[i]) {
                    dl->AddText(ImVec2(x, p.y), theme::nop, "..");
                    continue;
                }
                char hx2[3];
                snprintf(hx2, sizeof(hx2), "%02X", buf[i]);
                dl->AddText(ImVec2(x, p.y), buf[i] ? theme::text : theme::nop, hx2);
                char c[2] = {(buf[i] >= 32 && buf[i] < 127) ? (char)buf[i] : '.', 0};
                dl->AddText(ImVec2(ax + cw * i, p.y), theme::string, c);
            }
            // clicks select the byte under the mouse
            ImGui::PushID(r);
            ImGui::InvisibleButton("##hexrow", ImVec2(std::max(ax + cw * 17 - p.x, 1.0f), lh));
            if (ImGui::IsItemClicked()) {
                float mx = ImGui::GetIO().MousePos.x;
                int col = -1;
                if (mx >= hx && mx < hx + cw * 48)
                    col = std::min(15, (int)((mx - hx) / (cw * 3)));
                else if (mx >= ax && mx < ax + cw * 16)
                    col = (int)((mx - ax) / cw);
                if (col >= 0 && seg->contains(a + (uint64_t)col)) {
                    s.hex_addr = a + (uint64_t)col;
                    bool follow = s.hex_follow;
                    s.hex_follow = false; // don't bounce back to the listing cursor
                    app_jump(s, db.an.item_head(s.hex_addr));
                    s.hex_follow = follow;
                }
            }
            ImGui::PopID();
        }
    }
    ImGui::EndChild();
}

static void breakpoints(app_state& s)
{
    if (!s.db) {
        ImGui::TextDisabled("no file loaded");
        return;
    }
    database& db = *s.db;
    if (db.breakpoints.empty()) {
        ImGui::TextDisabled("no breakpoints. select a line and press F2.");
        return;
    }
    uint64_t remove = 0;
    bool clear = ImGui::Button("Remove all");
    if (ImGui::BeginTable("##bps", 4, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_BordersInnerV)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Address");
        ImGui::TableSetupColumn("Where");
        ImGui::TableSetupColumn("Instruction", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Stops when", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();
        int i = 0;
        for (uint64_t a : db.breakpoints) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::PushID(i++);
            if (ImGui::Selectable(db.fmt_addr(a).c_str(), false, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick)) {
                app_jump(s, a);
                if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left))
                    dialogs::open(s, dialog_kind::bp_condition, a);
            }
            if (ImGui::BeginPopupContextItem("##bp_ctx")) {
                if (ImGui::MenuItem("Condition...", "Shift+F2"))
                    dialogs::open(s, dialog_kind::bp_condition, a);
                if (ImGui::MenuItem("Remove"))
                    remove = a;
                ImGui::EndPopup();
            }
            ImGui::PopID();
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(db.location(a).c_str());
            ImGui::TableNextColumn();
            insn in;
            if (db.decode(a, in))
                ImGui::TextDisabled("%s", db.insn_text(in).c_str());
            ImGui::TableNextColumn();
            auto c = db.bp_conditions.find(a);
            if (c != db.bp_conditions.end()) {
                auto h = s.bp_hits.find(a);
                ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(theme::call), "%s", c->second.c_str());
                if (h != s.bp_hits.end()) {
                    ImGui::SameLine();
                    ImGui::TextDisabled("(%d hits)", h->second);
                }
            } else {
                ImGui::TextDisabled("always");
            }
        }
        ImGui::EndTable();
    }
    if (remove)
        app_toggle_bp(s, remove);
    if (clear) {
        std::vector<uint64_t> all(db.breakpoints.begin(), db.breakpoints.end());
        for (uint64_t a : all)
            app_toggle_bp(s, a);
    }
}

static void modules(app_state& s)
{
    if (s.dbg.state() == dbg_state::none) {
        ImGui::TextDisabled("loaded modules show up here while debugging");
        return;
    }
    std::vector<dbg_module> mods = s.dbg.modules();
    if (!ImGui::BeginTable("##mods", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_BordersInnerV))
        return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("Name");
    ImGui::TableSetupColumn("Base");
    ImGui::TableSetupColumn("Path", ImGuiTableColumnFlags_WidthStretch);
    ImGui::TableHeadersRow();
    for (const dbg_module& m : mods) {
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(m.name.c_str());
        ImGui::TableNextColumn();
        ImGui::TextDisabled("%s", util::hex(m.base).c_str());
        ImGui::TableNextColumn();
        ImGui::TextDisabled("%s", m.path.c_str());
    }
    ImGui::EndTable();
}

void draw(app_state& s)
{
    if (ImGui::BeginTabBar("##bottom_tabs")) {
        auto tab = [&](const char* label, int index) {
            ImGuiTabItemFlags fl = s.bottom_tab_request == index ? ImGuiTabItemFlags_SetSelected : 0;
            return ImGui::BeginTabItem(label, nullptr, fl);
        };
        if (tab("Output", 0)) {
            output(s);
            ImGui::EndTabItem();
        }
        if (tab("Hex", 1)) {
            hex(s);
            ImGui::EndTabItem();
        }
        std::string bp_label = util::fmt("Breakpoints (%zu)###bps", s.db ? s.db->breakpoints.size() : (size_t)0);
        if (tab(bp_label.c_str(), 2)) {
            breakpoints(s);
            ImGui::EndTabItem();
        }
        if (tab("Modules", 3)) {
            modules(s);
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
    s.bottom_tab_request = -1;
}

}
