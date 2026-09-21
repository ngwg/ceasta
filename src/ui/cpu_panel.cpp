#include "ui/cpu_panel.h"
#include "data/mock_data.h"
#include "imgui.h"

namespace cpu_panel {

void draw(app_state& state)
{
    if (!state.show_regs)
        return;
    ImGui::Begin("cpu", &state.show_regs);
    if (ImGui::BeginTable("reg_table", 2, ImGuiTableFlags_RowBg)) {
        int n = sizeof(mock_regs) / sizeof(mock_regs[0]);
        for (int i = 0; i < n; i++) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextDisabled("%s", mock_regs[i][0]);
            ImGui::TableNextColumn();
            if (i == 8)
                ImGui::TextColored(ImVec4(1, 0.6f, 0.3f, 1), "%s", mock_regs[i][1]);
            else
                ImGui::Text("%s", mock_regs[i][1]);
        }
        ImGui::EndTable();
    }
    ImGui::Separator();
    ImGui::TextDisabled("stack");
    if (ImGui::BeginTable("stack_table", 2, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("addr", ImGuiTableColumnFlags_WidthFixed, 80);
        ImGui::TableSetupColumn("val", ImGuiTableColumnFlags_WidthStretch);
        const char* addrs[] = {"0019ff30", "0019ff34", "0019ff38", "0019ff3c", "0019ff40"};
        const char* vals[] = {"0c104000", "40ff1900", "00000000", "20114000", "00000001"};
        for (int i = 0; i < 5; i++) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextDisabled("%s", addrs[i]);
            ImGui::TableNextColumn();
            ImGui::Text("%s", vals[i]);
        }
        ImGui::EndTable();
    }
    ImGui::End();
}

}
