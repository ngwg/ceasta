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
    ImGui::Begin("functions", &state.show_left);
    int n = sizeof(mock_funcs) / sizeof(mock_funcs[0]);
    for (int i = 0; i < n; i++) {
        if (state.filter[0] != '\0' && strstr(mock_funcs[i].name, state.filter) == nullptr)
            continue;
        char label[160];
        snprintf(label, sizeof(label), "%08x  %-14s", mock_funcs[i].addr, mock_funcs[i].name);
        if (ImGui::Selectable(label, state.selected_func == i))
            state.selected_func = i;
    }
    ImGui::End();
}

}
