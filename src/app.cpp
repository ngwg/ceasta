#include "app.h"
#include "ui/top_bar.h"
#include "ui/left_panel.h"
#include "ui/ida_view.h"
#include "ui/right_panel.h"
#include "ui/cpu_panel.h"
#include "ui/bottom_panel.h"
#include "ui/status_bar.h"
#include "imgui.h"
#include "imgui_internal.h"
#include <cstring>

static void build_layout(app_state& state)
{
    ImGuiViewport* view = ImGui::GetMainViewport();
    ImGuiID root = ImGui::GetID("ceasta_root");
    ImGui::DockBuilderRemoveNode(root);
    ImGui::DockBuilderAddNode(root, ImGuiDockNodeFlags_DockSpace);
    ImGui::DockBuilderSetNodeSize(root, view->Size);

    ImGuiID left, rest;
    ImGui::DockBuilderSplitNode(root, ImGuiDir_Left, 0.17f, &left, &rest);
    ImGuiID right, center;
    ImGui::DockBuilderSplitNode(rest, ImGuiDir_Right, 0.24f, &right, &center);
    ImGuiID bottom, mid;
    ImGui::DockBuilderSplitNode(center, ImGuiDir_Down, 0.30f, &bottom, &mid);
    ImGuiID right_top, right_bottom;
    ImGui::DockBuilderSplitNode(right, ImGuiDir_Down, 0.55f, &right_bottom, &right_top);

    ImGui::DockBuilderDockWindow("functions", left);
    ImGui::DockBuilderDockWindow("ida view", mid);
    ImGui::DockBuilderDockWindow("imports", right_top);
    ImGui::DockBuilderDockWindow("cpu", right_bottom);
    ImGui::DockBuilderDockWindow("output", bottom);
    ImGui::DockBuilderFinish(root);
    state.layout_done = true;
}

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
    if (!state.layout_done)
        build_layout(state);
    ImGuiID root = ImGui::GetID("ceasta_root");
    ImGui::DockSpaceOverViewport(root, ImGui::GetMainViewport(), ImGuiDockNodeFlags_PassthruCentralNode);

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
