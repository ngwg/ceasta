#include "app.h"
#include "ui/top_bar.h"
#include "ui/left_panel.h"
#include "ui/ida_view.h"
#include "ui/right_panel.h"
#include "ui/cpu_panel.h"
#include "ui/bottom_panel.h"
#include "ui/status_bar.h"
#include "imgui.h"
#include <cstring>

void app_init(app_state& state)
{
    state.filter[0] = '\0';
    state.jump_buf[0] = '\0';
    app_log(state, "ceasta started");
    app_log(state, "loaded sample.exe (mock)");
}

void app_log(app_state& state, const char* text)
{
    int n = (int)strlen(text);
    if (state.log_len + n + 2 >= (int)sizeof(state.log_buf))
        return;
    memcpy(state.log_buf + state.log_len, text, n);
    state.log_len += n;
    state.log_buf[state.log_len++] = '\n';
    state.log_buf[state.log_len] = '\0';
}

void app_render(app_state& state)
{
    ImGui::DockSpaceOverViewport(0, ImGui::GetMainViewport(), ImGuiDockNodeFlags_PassthruCentralNode);

    top_bar::draw(state);
    left_panel::draw(state);
    ida_view::draw(state);
    right_panel::draw(state);
    cpu_panel::draw(state);
    bottom_panel::draw(state);
    status_bar::draw(state);

    if (state.show_demo)
        ImGui::ShowDemoWindow(&state.show_demo);
}
