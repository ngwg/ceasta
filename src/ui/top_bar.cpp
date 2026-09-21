#include "ui/top_bar.h"
#include "imgui.h"
#include <Windows.h>
#include <cstdio>

namespace top_bar {

void draw(app_state& state)
{
    ImGuiWindowFlags flags = ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoTitleBar |
        ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_MenuBar;
    ImGui::Begin("top_bar", nullptr, flags);

    if (ImGui::BeginMenuBar()) {
        if (ImGui::BeginMenu("file")) {
            ImGui::MenuItem("open...", "ctrl+o");
            ImGui::MenuItem("close database");
            ImGui::Separator();
            if (ImGui::MenuItem("exit"))
                PostQuitMessage(0);
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("edit")) {
            ImGui::MenuItem("rename", "n");
            ImGui::MenuItem("comment", ";");
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("jump")) {
            ImGui::MenuItem("jump to address", "g");
            ImGui::MenuItem("back", "esc");
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("search")) {
            ImGui::MenuItem("text...", "alt+t");
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("view")) {
            ImGui::MenuItem("left panel", nullptr, &state.show_left);
            ImGui::MenuItem("ida view", nullptr, &state.show_view);
            ImGui::MenuItem("right panel", nullptr, &state.show_right);
            ImGui::MenuItem("bottom panel", nullptr, &state.show_bottom);
            ImGui::MenuItem("registers", nullptr, &state.show_regs);
            ImGui::Separator();
            ImGui::MenuItem("graph mode", nullptr, &state.graph_mode);
            ImGui::MenuItem("imgui demo", nullptr, &state.show_demo);
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("debugger")) {
            ImGui::MenuItem("start", "f9");
            ImGui::MenuItem("step over", "f8");
            ImGui::MenuItem("step in", "f7");
            ImGui::EndMenu();
        }
        ImGui::EndMenuBar();
    }

    if (ImGui::Button("<"))
        app_log(state, "back (mock)");
    ImGui::SameLine();
    if (ImGui::Button(">"))
        app_log(state, "forward (mock)");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(120);
    if (ImGui::InputTextWithHint("##jump", "0x401000", state.jump_buf, sizeof(state.jump_buf), ImGuiInputTextFlags_EnterReturnsTrue)) {
        char tmp[64];
        snprintf(tmp, sizeof(tmp), "jump -> %s (mock)", state.jump_buf);
        app_log(state, tmp);
    }
    ImGui::SameLine();
    if (ImGui::Button(state.graph_mode ? "text" : "graph"))
        state.graph_mode = !state.graph_mode;
    ImGui::SameLine();
    if (ImGui::Button("run"))
        app_log(state, "run (mock)");
    ImGui::SameLine();
    if (ImGui::Button("step"))
        app_log(state, "step (mock)");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(200);
    ImGui::InputTextWithHint("##filter", "filter", state.filter, sizeof(state.filter));
    ImGui::SameLine();
    ImGui::TextDisabled("%s | x86 | pe32", state.file_name);

    ImGui::End();
}

}
