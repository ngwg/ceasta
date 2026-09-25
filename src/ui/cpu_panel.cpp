#include "ui/cpu_panel.h"
#include "core/util.h"
#include "imgui.h"
#include "theme.h"
#include <cstring>

namespace cpu_panel {

// what a runtime value points at: a name in the listing, a string, or nothing
static std::string describe(app_state& s, uint64_t v)
{
    uint64_t st;
    if (!s.db || !app_to_static(s, v, st))
        return std::string();
    const string_item* str = s.db->an.string_at(st);
    if (str)
        return "\"" + util::escape(str->text, 40) + "\"";
    return s.db->location(st);
}

static void registers(app_state& s)
{
    std::vector<reg_value> regs = s.dbg.registers();
    int digits = s.dbg.is64() ? 16 : 8;
    if (!ImGui::BeginTable("##regs", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_BordersInnerV))
        return;
    ImGui::TableSetupColumn("reg");
    ImGui::TableSetupColumn("value");
    ImGui::TableSetupColumn("points to", ImGuiTableColumnFlags_WidthStretch);
    int i = 0;
    for (const reg_value& r : regs) {
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        ImGui::TextDisabled("%s", r.name.c_str());
        ImGui::TableNextColumn();
        ImGui::PushID(i++);
        std::string v = util::fmt(digits == 16 ? "%016llX" : "%08llX", (unsigned long long)r.value);
        if (r.name == "eflags")
            v = util::fmt("%08llX", (unsigned long long)r.value);
        bool is_pc = r.name == "rip" || r.name == "eip";
        ImGui::PushStyleColor(ImGuiCol_Text, is_pc ? ImGui::ColorConvertU32ToFloat4(theme::pc_arrow) : ImGui::GetStyleColorVec4(ImGuiCol_Text));
        ImGui::Selectable(v.c_str(), false, ImGuiSelectableFlags_AllowDoubleClick);
        ImGui::PopStyleColor();
        if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
            uint64_t st;
            if (app_to_static(s, r.value, st))
                app_jump(s, st);
        }
        if (ImGui::BeginPopupContextItem("##reg_ctx")) {
            if (ImGui::MenuItem("Copy value"))
                ImGui::SetClipboardText(v.c_str());
            uint64_t st;
            if (ImGui::MenuItem("Show in listing", nullptr, false, app_to_static(s, r.value, st)))
                app_jump(s, st);
            if (ImGui::MenuItem("Show in hex"))
                app_show_memory(s, r.value);
            ImGui::EndPopup();
        }
        ImGui::PopID();
        ImGui::TableNextColumn();
        if (r.name == "eflags") {
            static const struct {
                int bit;
                const char* name;
            } fl[] = {{0, "CF"}, {2, "PF"}, {4, "AF"}, {6, "ZF"}, {7, "SF"}, {8, "TF"}, {9, "IF"}, {10, "DF"}, {11, "OF"}};
            std::string set;
            for (const auto& f : fl)
                if (r.value & (1ull << f.bit))
                    set += std::string(set.empty() ? "" : " ") + f.name;
            ImGui::TextDisabled("%s", set.c_str());
        } else {
            std::string d = describe(s, r.value);
            if (!d.empty())
                ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(theme::label), "%s", d.c_str());
        }
    }
    ImGui::EndTable();
}

static void stack(app_state& s)
{
    int ps = s.dbg.is64() ? 8 : 4;
    uint64_t sp = s.dbg.sp();
    ImGui::TextDisabled("stack");
    if (!ImGui::BeginTable("##stack", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersInnerV))
        return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("address");
    ImGui::TableSetupColumn("value");
    ImGui::TableSetupColumn("points to", ImGuiTableColumnFlags_WidthStretch);
    ImGui::TableHeadersRow();
    const int count = 64;
    uint8_t buf[64 * 8];
    size_t got = s.dbg.read(sp, buf, (size_t)(count * ps));
    for (int i = 0; i < count && (size_t)((i + 1) * ps) <= got; i++) {
        uint64_t v = 0;
        memcpy(&v, buf + i * ps, (size_t)ps);
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        ImGui::TextDisabled(ps == 8 ? "%016llX" : "%08llX", (unsigned long long)(sp + (uint64_t)(i * ps)));
        ImGui::TableNextColumn();
        ImGui::PushID(i);
        std::string vs = util::fmt(ps == 8 ? "%016llX" : "%08llX", (unsigned long long)v);
        ImGui::Selectable(vs.c_str(), false, ImGuiSelectableFlags_AllowDoubleClick);
        if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
            uint64_t st;
            if (app_to_static(s, v, st))
                app_jump(s, st);
        }
        if (ImGui::BeginPopupContextItem("##stack_ctx")) {
            uint64_t st;
            if (ImGui::MenuItem("Show in listing", nullptr, false, app_to_static(s, v, st)))
                app_jump(s, st);
            if (ImGui::MenuItem("Show in hex (what it points to)"))
                app_show_memory(s, v);
            if (ImGui::MenuItem("Show this stack slot in hex"))
                app_show_memory(s, sp + (uint64_t)(i * ps));
            if (ImGui::MenuItem("Copy value"))
                ImGui::SetClipboardText(vs.c_str());
            ImGui::EndPopup();
        }
        ImGui::PopID();
        ImGui::TableNextColumn();
        std::string d = describe(s, v);
        if (!d.empty())
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(theme::label), "%s", d.c_str());
    }
    ImGui::EndTable();
}

void draw(app_state& s)
{
    // the buttons live in the toolbar; this panel is what the program looks like right now
    dbg_state st = s.dbg.state();
    if (st == dbg_state::none) {
        ImGui::TextDisabled("no program is being debugged");
        return;
    }
    if (st == dbg_state::running) {
        ImGui::TextColored(ImVec4(0.5f, 0.9f, 0.5f, 1), "running  (pid %u)", s.dbg.pid());
        return;
    }
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(theme::pc_arrow), "stopped: %s", app_stop_text(s).c_str());
    ImGui::SameLine();
    ImGui::TextDisabled("pid %u  thread %u", s.dbg.pid(), s.dbg.tid());
    ImGui::Separator();
    registers(s);
    ImGui::Separator();
    stack(s);
}

}
