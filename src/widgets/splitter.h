#pragma once
#include "imgui.h"
#include <algorithm>

namespace widgets {

// thin bar between two panels, drag it to resize. size is kept unscaled (divided by
// scale) so the layout survives dpi changes. sign flips the direction for panels that
// grow the other way (right column, bottom strip). returns true while dragging.
inline bool splitter(const char* id, bool vertical, float thickness, float length, float* size,
    float min_size, float max_size, float sign, float scale)
{
    ImVec2 pos = ImGui::GetCursorScreenPos();
    ImVec2 dim = vertical ? ImVec2(thickness, length) : ImVec2(length, thickness);
    ImGui::InvisibleButton(id, ImVec2(std::max(dim.x, 1.0f), std::max(dim.y, 1.0f)));
    bool hovered = ImGui::IsItemHovered();
    bool active = ImGui::IsItemActive();
    if (hovered || active)
        ImGui::SetMouseCursor(vertical ? ImGuiMouseCursor_ResizeEW : ImGuiMouseCursor_ResizeNS);
    if (active) {
        ImGuiIO& io = ImGui::GetIO();
        float d = (vertical ? io.MouseDelta.x : io.MouseDelta.y) * sign / (scale > 0 ? scale : 1.0f);
        *size = std::min(max_size, std::max(min_size, *size + d));
    }
    ImU32 col = ImGui::GetColorU32(active ? ImGuiCol_SeparatorActive : hovered ? ImGuiCol_SeparatorHovered : ImGuiCol_WindowBg);
    ImGui::GetWindowDrawList()->AddRectFilled(pos, ImVec2(pos.x + dim.x, pos.y + dim.y), col);
    return active;
}

}
