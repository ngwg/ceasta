#pragma once
#include "imgui.h"

inline void apply_theme()
{
    ImGui::StyleColorsDark();

    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding = 4.0f;
    style.FrameRounding = 3.0f;
    style.ScrollbarRounding = 3.0f;
    style.GrabRounding = 3.0f;
    style.TabRounding = 4.0f;
    style.WindowBorderSize = 1.0f;
    style.FrameBorderSize = 0.0f;
    style.WindowPadding = ImVec2(8, 8);
    style.FramePadding = ImVec2(6, 3);
    style.ItemSpacing = ImVec2(8, 4);

    ImVec4* colors = style.Colors;
    colors[ImGuiCol_WindowBg] = ImVec4(0.10f, 0.11f, 0.13f, 1.0f);
    colors[ImGuiCol_ChildBg] = ImVec4(0.08f, 0.09f, 0.11f, 1.0f);
    colors[ImGuiCol_MenuBarBg] = ImVec4(0.13f, 0.14f, 0.17f, 1.0f);
    colors[ImGuiCol_TitleBg] = ImVec4(0.13f, 0.14f, 0.17f, 1.0f);
    colors[ImGuiCol_TitleBgActive] = ImVec4(0.16f, 0.20f, 0.28f, 1.0f);
    colors[ImGuiCol_Header] = ImVec4(0.20f, 0.26f, 0.38f, 1.0f);
    colors[ImGuiCol_HeaderHovered] = ImVec4(0.26f, 0.34f, 0.48f, 1.0f);
    colors[ImGuiCol_Button] = ImVec4(0.20f, 0.26f, 0.38f, 1.0f);
    colors[ImGuiCol_ButtonHovered] = ImVec4(0.28f, 0.36f, 0.52f, 1.0f);
    colors[ImGuiCol_Tab] = ImVec4(0.13f, 0.14f, 0.17f, 1.0f);
    colors[ImGuiCol_TabActive] = ImVec4(0.20f, 0.26f, 0.38f, 1.0f);
    colors[ImGuiCol_TableHeaderBg] = ImVec4(0.14f, 0.16f, 0.20f, 1.0f);
    colors[ImGuiCol_TableBorderLight] = ImVec4(0.22f, 0.24f, 0.28f, 1.0f);
}
