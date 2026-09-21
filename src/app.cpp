#include "app.h"
#include "mock_data.h"
#include "imgui.h"
#include <Windows.h>
#include <cstring>
#include <cstdio>

void app_init(app_state& state)
{
    state.filter[0] = '\0';
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

static void render_menu_bar(app_state& state)
{
    if (ImGui::BeginMenuBar()) {
        if (ImGui::BeginMenu("file")) {
            ImGui::MenuItem("open binary...", "ctrl+o");
            ImGui::Separator();
            if (ImGui::MenuItem("exit"))
                PostQuitMessage(0);
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("view")) {
            ImGui::MenuItem("functions", nullptr, &state.show_functions);
            ImGui::MenuItem("disassembly", nullptr, &state.show_disasm);
            ImGui::MenuItem("hex", nullptr, &state.show_hex);
            ImGui::MenuItem("strings", nullptr, &state.show_strings);
            ImGui::MenuItem("registers", nullptr, &state.show_regs);
            ImGui::MenuItem("output", nullptr, &state.show_log);
            ImGui::Separator();
            ImGui::MenuItem("imgui demo", nullptr, &state.show_demo);
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("debug")) {
            ImGui::MenuItem("run", "f9");
            ImGui::MenuItem("step over", "f8");
            ImGui::MenuItem("step in", "f7");
            ImGui::EndMenu();
        }
        ImGui::EndMenuBar();
    }
}

static void render_tool_bar(app_state& state)
{
    if (ImGui::Button("open"))
        app_log(state, "open clicked (mock)");
    ImGui::SameLine();
    if (ImGui::Button("run"))
        app_log(state, "run (mock)");
    ImGui::SameLine();
    if (ImGui::Button("step"))
        app_log(state, "step (mock)");
    ImGui::SameLine();
    if (ImGui::Button("stop"))
        app_log(state, "stop (mock)");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(220);
    ImGui::InputTextWithHint("##filter", "filter functions", state.filter, sizeof(state.filter));
    ImGui::SameLine();
    ImGui::TextDisabled("%s | x86 | 32bit", state.file_name);
}

static void render_functions(app_state& state)
{
    if (!state.show_functions)
        return;
    ImGui::Begin("functions", &state.show_functions);
    int count = sizeof(mock_funcs) / sizeof(mock_funcs[0]);
    for (int i = 0; i < count; i++) {
        if (state.filter[0] != '\0' && strstr(mock_funcs[i].name, state.filter) == nullptr)
            continue;
        char label[128];
        snprintf(label, sizeof(label), "%08x  %s", mock_funcs[i].addr, mock_funcs[i].name);
        if (ImGui::Selectable(label, state.selected_func == i)) {
            state.selected_func = i;
            state.selected_line = 0;
        }
    }
    ImGui::End();
}

static ImVec4 kind_color(int kind)
{
    if (kind == 1)
        return ImVec4(0.55f, 0.80f, 1.0f, 1.0f);
    if (kind == 2)
        return ImVec4(1.0f, 0.85f, 0.40f, 1.0f);
    if (kind == 3)
        return ImVec4(1.0f, 0.45f, 0.45f, 1.0f);
    return ImVec4(0.85f, 0.87f, 0.90f, 1.0f);
}

static void render_disasm(app_state& state)
{
    if (!state.show_disasm)
        return;
    ImGui::Begin("disassembly", &state.show_disasm);
    if (ImGui::BeginTable("disasm_table", 4, ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("address", ImGuiTableColumnFlags_WidthFixed, 80);
        ImGui::TableSetupColumn("bytes", ImGuiTableColumnFlags_WidthFixed, 130);
        ImGui::TableSetupColumn("mnemonic", ImGuiTableColumnFlags_WidthFixed, 70);
        ImGui::TableSetupColumn("operands", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();
        int count = sizeof(mock_lines) / sizeof(mock_lines[0]);
        for (int i = 0; i < count; i++) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            if (state.selected_line == i)
                ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, ImGui::GetColorU32(ImVec4(0.20f, 0.26f, 0.38f, 1.0f)));
            ImGui::TextDisabled("%08x", mock_lines[i].addr);
            ImGui::TableNextColumn();
            ImGui::TextDisabled("%s", mock_lines[i].bytes);
            ImGui::TableNextColumn();
            ImGui::TextColored(kind_color(mock_lines[i].kind), "%s", mock_lines[i].mnemonic);
            ImGui::TableNextColumn();
            ImGui::Text("%s", mock_lines[i].operands);
            if (ImGui::IsItemHovered() && ImGui::IsMouseClicked(0))
                state.selected_line = i;
        }
        ImGui::EndTable();
    }
    ImGui::End();
}

static void render_hex(app_state& state)
{
    if (!state.show_hex)
        return;
    ImGui::Begin("hex", &state.show_hex);
    if (ImGui::BeginTable("hex_table", 17, ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("off", ImGuiTableColumnFlags_WidthFixed, 80);
        for (int b = 0; b < 16; b++) {
            char h[8];
            snprintf(h, sizeof(h), "%02x", b);
            ImGui::TableSetupColumn(h, ImGuiTableColumnFlags_WidthFixed, 28);
        }
        ImGui::TableHeadersRow();
        for (int row = 0; row < 8; row++) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextDisabled("%08x", 0x403000 + row * 16);
            for (int col = 0; col < 16; col++) {
                ImGui::TableNextColumn();
                unsigned char v = (row * 16 + col < (int)sizeof(mock_hex)) ? mock_hex[row * 16 + col] : (unsigned char)(row + col);
                ImGui::Text("%02x", v);
            }
        }
        ImGui::EndTable();
    }
    ImGui::End();
}

static void render_strings(app_state& state)
{
    if (!state.show_strings)
        return;
    ImGui::Begin("strings", &state.show_strings);
    if (ImGui::BeginTable("str_table", 2, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("addr", ImGuiTableColumnFlags_WidthFixed, 90);
        ImGui::TableSetupColumn("text", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();
        int count = sizeof(mock_strings) / sizeof(mock_strings[0]);
        for (int i = 0; i < count; i++) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextDisabled("%08x", mock_strings[i].addr);
            ImGui::TableNextColumn();
            ImGui::Text("%s", mock_strings[i].text);
        }
        ImGui::EndTable();
    }
    ImGui::End();
}

static void render_regs(app_state& state)
{
    if (!state.show_regs)
        return;
    ImGui::Begin("registers", &state.show_regs);
    int count = sizeof(mock_regs) / sizeof(mock_regs[0]);
    for (int i = 0; i < count; i++) {
        ImGui::TextDisabled("%s", mock_regs[i][0]);
        ImGui::SameLine(60);
        if (i == 8)
            ImGui::TextColored(ImVec4(1, 0.6f, 0.3f, 1), "%s", mock_regs[i][1]);
        else
            ImGui::Text("%s", mock_regs[i][1]);
    }
    ImGui::Separator();
    ImGui::TextDisabled("stack");
    ImGui::Text("0019ff30  0c 10 40 00");
    ImGui::Text("0019ff34  40 ff 19 00");
    ImGui::End();
}

static void render_log(app_state& state)
{
    if (!state.show_log)
        return;
    ImGui::Begin("output", &state.show_log);
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
    ImGui::End();
}

void app_render(app_state& state)
{
    ImGui::DockSpaceOverViewport(0, ImGui::GetMainViewport(), ImGuiDockNodeFlags_PassthruCentralNode);

    ImGuiWindowFlags bar_flags = ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoTitleBar |
        ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_MenuBar;
    ImGui::Begin("top_bar", nullptr, bar_flags);
    render_menu_bar(state);
    render_tool_bar(state);
    ImGui::End();

    render_functions(state);
    render_disasm(state);
    render_hex(state);
    render_strings(state);
    render_regs(state);
    render_log(state);

    if (state.show_demo)
        ImGui::ShowDemoWindow(&state.show_demo);

    ImGuiViewport* view = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(ImVec2(view->Pos.x, view->Pos.y + view->Size.y - 22));
    ImGui::SetNextWindowSize(ImVec2(view->Size.x, 22));
    ImGui::Begin("status", nullptr,
        ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove);
    ImGui::TextDisabled("ready | %d funcs | sel %08x", 6, mock_lines[state.selected_line].addr);
    ImGui::End();
}
