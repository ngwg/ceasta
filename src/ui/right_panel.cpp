#include "ui/right_panel.h"
#include "data/mock_data.h"
#include "imgui.h"

namespace right_panel {

void draw(app_state& state)
{
    if (!state.show_right)
        return;
    ImGui::Begin("imports", &state.show_right);
    int n = sizeof(mock_imports) / sizeof(mock_imports[0]);
    for (int i = 0; i < n; i++) {
        ImGui::TextDisabled("%08x", mock_imports[i].addr);
        ImGui::SameLine(90);
        ImGui::Text("%s!%s", mock_imports[i].dll, mock_imports[i].name);
    }
    ImGui::Separator();
    ImGui::TextDisabled("strings");
    int m = sizeof(mock_strings) / sizeof(mock_strings[0]);
    for (int i = 0; i < m; i++) {
        ImGui::TextDisabled("%08x", mock_strings[i].addr);
        ImGui::SameLine(90);
        ImGui::Text("%s", mock_strings[i].text);
    }
    ImGui::End();
}

}
