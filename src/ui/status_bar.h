#pragma once
#include "app.h"
#include "data/mock_data.h"
#include "imgui.h"

namespace status_bar {

inline void draw(app_state& state)
{
    ImGuiViewport* view = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(ImVec2(view->Pos.x, view->Pos.y + view->Size.y - 22));
    ImGui::SetNextWindowSize(ImVec2(view->Size.x, 22));
    ImGui::Begin("status", nullptr,
        ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove);
    int n = sizeof(mock_funcs) / sizeof(mock_funcs[0]);
    ImGui::TextDisabled("ready | %d funcs | %s | eip %08x", n, state.file_name, mock_lines[state.selected_line].addr);
    ImGui::End();
}

}
