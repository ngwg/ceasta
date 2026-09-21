#include "ui/left_panel.h"
#include "data/mock_data.h"
#include "imgui.h"
#include <cstring>
#include <cstdio>

namespace left_panel {

void draw(app_state& state)
{
    if (!state.show_left)
        return;
    ImGui::Begin("browser", &state.show_left);
    if (ImGui::BeginTabBar("left_tabs")) {
        if (ImGui::BeginTabItem("funcs")) {
            int n = sizeof(mock_funcs) / sizeof(mock_funcs[0]);
            for (int i = 0; i < n; i++) {
                if (state.filter[0] != '\0' && strstr(mock_funcs[i].name, state.filter) == nullptr)
                    continue;
                char label[160];
                snprintf(label, sizeof(label), "%08x  %-14s %04x", mock_funcs[i].addr, mock_funcs[i].name, mock_funcs[i].size);
                if (ImGui::Selectable(label, state.selected_func == i))
                    state.selected_func = i;
            }
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("segments")) {
            if (ImGui::BeginTable("seg_table", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY)) {
                ImGui::TableSetupColumn("name");
                ImGui::TableSetupColumn("range");
                ImGui::TableSetupColumn("perms");
                ImGui::TableHeadersRow();
                int n = sizeof(mock_segments) / sizeof(mock_segments[0]);
                for (int i = 0; i < n; i++) {
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();
                    ImGui::Text("%s", mock_segments[i].name);
                    ImGui::TableNextColumn();
                    ImGui::TextDisabled("%08x-%08x", mock_segments[i].start, mock_segments[i].end);
                    ImGui::TableNextColumn();
                    ImGui::Text("%s", mock_segments[i].perms);
                }
                ImGui::EndTable();
            }
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("structs")) {
            ImGui::TextDisabled("dos_header");
            ImGui::BulletText("e_magic : dw");
            ImGui::BulletText("e_lfanew : dd");
            ImGui::TextDisabled("pe_header");
            ImGui::BulletText("machine : dw");
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
    ImGui::End();
}

}
