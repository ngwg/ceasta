#include "ui/right_panel.h"
#include "data/mock_data.h"
#include "imgui.h"

namespace right_panel {

void draw(app_state& state)
{
    if (!state.show_right)
        return;
    ImGui::Begin("imports / strings", &state.show_right);
    if (ImGui::BeginTabBar("right_tabs")) {
        if (ImGui::BeginTabItem("imports")) {
            if (ImGui::BeginTable("imp_table", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY)) {
                ImGui::TableSetupColumn("addr", ImGuiTableColumnFlags_WidthFixed, 80);
                ImGui::TableSetupColumn("dll", ImGuiTableColumnFlags_WidthFixed, 100);
                ImGui::TableSetupColumn("name", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableHeadersRow();
                int n = sizeof(mock_imports) / sizeof(mock_imports[0]);
                for (int i = 0; i < n; i++) {
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();
                    ImGui::TextDisabled("%08x", mock_imports[i].addr);
                    ImGui::TableNextColumn();
                    ImGui::Text("%s", mock_imports[i].dll);
                    ImGui::TableNextColumn();
                    ImGui::TextColored(ImVec4(1, 0.85f, 0.4f, 1), "%s", mock_imports[i].name);
                }
                ImGui::EndTable();
            }
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("strings")) {
            if (ImGui::BeginTable("str_table", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY)) {
                ImGui::TableSetupColumn("addr", ImGuiTableColumnFlags_WidthFixed, 80);
                ImGui::TableSetupColumn("len", ImGuiTableColumnFlags_WidthFixed, 40);
                ImGui::TableSetupColumn("text", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableHeadersRow();
                int n = sizeof(mock_strings) / sizeof(mock_strings[0]);
                for (int i = 0; i < n; i++) {
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();
                    ImGui::TextDisabled("%08x", mock_strings[i].addr);
                    ImGui::TableNextColumn();
                    ImGui::TextDisabled("%d", mock_strings[i].len);
                    ImGui::TableNextColumn();
                    ImGui::Text("%s", mock_strings[i].text);
                }
                ImGui::EndTable();
            }
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("xrefs")) {
            ImGui::TextDisabled("xrefs to main_loop");
            ImGui::BulletText("0x401006 call from start+6");
            ImGui::BulletText("0x401123 call from main_loop+3");
            ImGui::Separator();
            ImGui::TextDisabled("xrefs to decrypt_block");
            ImGui::BulletText("0x401014 call from start+14");
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
    ImGui::End();
}

}
