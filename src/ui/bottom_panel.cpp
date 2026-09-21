#include "ui/bottom_panel.h"
#include "data/mock_data.h"
#include "imgui.h"
#include <cstdio>

namespace bottom_panel {

static void hex_tab()
{
    if (ImGui::BeginTable("hex_table", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("off", ImGuiTableColumnFlags_WidthFixed, 78);
        ImGui::TableSetupColumn("hex", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("ascii", ImGuiTableColumnFlags_WidthFixed, 130);
        ImGui::TableHeadersRow();
        for (int row = 0; row < 16; row++) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextDisabled("%08x", 0x403000 + row * 16);
            ImGui::TableNextColumn();
            char line[96] = {};
            int p = 0;
            for (int col = 0; col < 16; col++) {
                unsigned char v = (row * 16 + col < (int)sizeof(mock_hex)) ? mock_hex[row * 16 + col] : (unsigned char)(row * 7 + col * 13);
                p += snprintf(line + p, sizeof(line) - p, "%02x ", v);
            }
            ImGui::Text("%s", line);
            ImGui::TableNextColumn();
            char asc[20] = {};
            for (int col = 0; col < 16; col++) {
                unsigned char v = (row * 16 + col < (int)sizeof(mock_hex)) ? mock_hex[row * 16 + col] : (unsigned char)(row + col);
                asc[col] = (v >= 32 && v < 127) ? (char)v : '.';
            }
            asc[16] = '\0';
            ImGui::TextDisabled("%s", asc);
        }
        ImGui::EndTable();
    }
}

void draw(app_state& state)
{
    if (!state.show_bottom)
        return;
    ImGui::Begin("output / hex", &state.show_bottom);
    if (ImGui::BeginTabBar("bottom_tabs")) {
        if (ImGui::BeginTabItem("output")) {
            if (ImGui::Button("clear"))
                state.log_len = 0, state.log_buf[0] = '\0';
            ImGui::SameLine();
            ImGui::TextDisabled("log");
            ImGui::Separator();
            ImGui::BeginChild("log_scroll", ImVec2(0, 0), false, ImGuiWindowFlags_HorizontalScrollbar);
            ImGui::TextUnformatted(state.log_buf);
            if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
                ImGui::SetScrollHereY(1.0f);
            ImGui::EndChild();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("console")) {
            ImGui::TextDisabled("python console (mock)");
            ImGui::Separator();
            ImGui::Text(">>> print(hex(0x401000))");
            ImGui::Text("0x401000");
            static char cmd[256] = {};
            ImGui::InputTextWithHint("##cmd", "type command, enter", cmd, sizeof(cmd), ImGuiInputTextFlags_EnterReturnsTrue);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("hex")) {
            hex_tab();
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
    ImGui::End();
}

}
