#pragma once
#include "imgui.h"

namespace widgets {

inline void nav_band()
{
    ImVec2 size = ImGui::GetContentRegionAvail();
    size.y = 14;
    ImDrawList* draw = ImGui::GetWindowDrawList();
    ImVec2 pos = ImGui::GetCursorScreenPos();
    draw->AddRectFilled(pos, ImVec2(pos.x + size.x, pos.y + size.y), IM_COL32(20, 22, 28, 255));
    float x = pos.x;
    auto block = [&](float w, ImU32 col) {
        draw->AddRectFilled(ImVec2(x + 1, pos.y + 1), ImVec2(x + w - 1, pos.y + size.y - 1), col);
        x += w;
    };
    block(size.x * 0.45f, IM_COL32(64, 110, 180, 255));
    block(size.x * 0.15f, IM_COL32(90, 140, 90, 255));
    block(size.x * 0.20f, IM_COL32(150, 130, 70, 255));
    block(size.x * 0.20f, IM_COL32(80, 80, 90, 255));
    ImGui::Dummy(size);
}

inline void addr(unsigned int a, bool hot = false)
{
    if (hot)
        ImGui::TextColored(ImVec4(0.45f, 0.65f, 1.0f, 1.0f), "%08x", a);
    else
        ImGui::TextDisabled("%08x", a);
}

}
