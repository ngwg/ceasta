#include "app.h"
#include "mock_data.h"
#include "imgui.h"
#include <Windows.h>
#include <cstring>
#include <cstdio>
#include <utility>

void app_init(app_state& state)
{
    state.filter[0] = '\0';
    state.jump_buf[0] = '\0';
    app_log(state, "ceasta started");
    app_log(state, "loaded sample.exe (mock)");
    app_log(state, ".text 0x401000-0x402000 | .rdata 0x403000-0x404000");
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
            ImGui::MenuItem("patch byte", nullptr);
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("jump")) {
            ImGui::MenuItem("jump to address", "g");
            ImGui::MenuItem("jump to function", "ctrl+f");
            ImGui::MenuItem("back", "esc");
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("search")) {
            ImGui::MenuItem("text...", "alt+t");
            ImGui::MenuItem("next", "ctrl+n");
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
            ImGui::MenuItem("toggle breakpoint", "f2");
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("windows")) {
            ImGui::MenuItem("reset layout");
            ImGui::EndMenu();
        }
        ImGui::EndMenuBar();
    }
}

static void render_tool_bar(app_state& state)
{
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
    if (ImGui::Button("xrefs"))
        state.right_tab = 2;
    ImGui::SameLine();
    ImGui::SetNextItemWidth(200);
    ImGui::InputTextWithHint("##filter", "filter", state.filter, sizeof(state.filter));
    ImGui::SameLine();
    ImGui::TextDisabled("%s | x86 | pe32", state.file_name);
}

static void render_nav_band()
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

static void render_left(app_state& state)
{
    if (!state.show_left)
        return;
    ImGui::Begin("browser", &state.show_left);
    if (ImGui::BeginTabBar("left_tabs")) {
        if (ImGui::BeginTabItem("funcs")) {
            int count = sizeof(mock_funcs) / sizeof(mock_funcs[0]);
            for (int i = 0; i < count; i++) {
                if (state.filter[0] != '\0' && strstr(mock_funcs[i].name, state.filter) == nullptr)
                    continue;
                char label[160];
                snprintf(label, sizeof(label), "%08x  %-14s %04x", mock_funcs[i].addr, mock_funcs[i].name, mock_funcs[i].size);
                if (ImGui::Selectable(label, state.selected_func == i))
                    state.selected_func = i;
            }
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("segments")) {
            if (ImGui::BeginTable("seg_table", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY)) {
                ImGui::TableSetupColumn("name");
                ImGui::TableSetupColumn("range");
                ImGui::TableSetupColumn("perms");
                ImGui::TableHeadersRow();
                int n = sizeof(mock_segments) / sizeof(mock_segments[0]);
                for (int i = 0; i < n; i++) {
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();
                    ImGui::Text("%s", mock_segments[i].name);
                    ImGui::TableNextColumn();
                    ImGui::TextDisabled("%08x-%08x", mock_segments[i].start, mock_segments[i].end);
                    ImGui::TableNextColumn();
                    ImGui::Text("%s", mock_segments[i].perms);
                }
                ImGui::EndTable();
            }
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("structs")) {
            ImGui::TextDisabled("dos_header");
            ImGui::BulletText("e_magic : dw");
            ImGui::BulletText("e_lfanew : dd");
            ImGui::TextDisabled("pe_header");
            ImGui::BulletText("machine : dw");
            ImGui::BulletText("sections : dw");
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
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

static void render_text_view(app_state& state)
{
    if (ImGui::BeginTable("disasm_table", 5, ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("address", ImGuiTableColumnFlags_WidthFixed, 78);
        ImGui::TableSetupColumn("bytes", ImGuiTableColumnFlags_WidthFixed, 118);
        ImGui::TableSetupColumn("code", ImGuiTableColumnFlags_WidthFixed, 200);
        ImGui::TableSetupColumn("comment", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("xref", ImGuiTableColumnFlags_WidthFixed, 70);
        ImGui::TableHeadersRow();
        int count = sizeof(mock_lines) / sizeof(mock_lines[0]);
        for (int i = 0; i < count; i++) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            if (state.selected_line == i)
                ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, ImGui::GetColorU32(ImVec4(0.20f, 0.26f, 0.38f, 1.0f)));
            bool is_func_start = (i == 0 || i == 14);
            if (is_func_start)
                ImGui::TextColored(ImVec4(0.45f, 0.65f, 1.0f, 1.0f), "%08x", mock_lines[i].addr);
            else
                ImGui::TextDisabled("%08x", mock_lines[i].addr);
            ImGui::TableNextColumn();
            ImGui::TextDisabled("%s", mock_lines[i].bytes);
            ImGui::TableNextColumn();
            ImGui::TextColored(kind_color(mock_lines[i].kind), "%-5s %s", mock_lines[i].mnemonic, mock_lines[i].operands);
            ImGui::TableNextColumn();
            ImGui::TextColored(ImVec4(0.45f, 0.75f, 0.55f, 1.0f), "%s", mock_lines[i].comment);
            ImGui::TableNextColumn();
            if (mock_lines[i].kind == 2)
                ImGui::TextDisabled("xref");
            else
                ImGui::TextDisabled("");
            if (ImGui::IsItemHovered() && ImGui::IsMouseClicked(0))
                state.selected_line = i;
        }
        ImGui::EndTable();
    }
}

static void render_graph_view(app_state& state)
{
    ImGui::BeginChild("graph_scroll", ImVec2(0, 0), false, ImGuiWindowFlags_HorizontalScrollbar);
    ImDrawList* draw = ImGui::GetWindowDrawList();
    ImVec2 origin = ImGui::GetCursorScreenPos();

    auto node = [&](const char* title, const char** rows, int nrows, ImVec2 pos, ImVec2 size, ImU32 edge_col) {
        ImVec2 a = ImVec2(origin.x + pos.x, origin.y + pos.y);
        ImVec2 b = ImVec2(a.x + size.x, a.y + size.y);
        draw->AddRectFilled(a, b, IM_COL32(24, 27, 34, 255), 6.0f);
        draw->AddRect(a, b, IM_COL32(70, 90, 130, 255), 6.0f, 0, 1.5f);
        draw->AddRectFilled(a, ImVec2(b.x, a.y + 22), IM_COL32(38, 48, 68, 255), 6.0f, ImDrawFlags_RoundCornersTop);
        draw->AddText(ImVec2(a.x + 8, a.y + 4), IM_COL32(160, 190, 255, 255), title);
        for (int i = 0; i < nrows; i++)
            draw->AddText(ImVec2(a.x + 8, a.y + 28 + i * 16), IM_COL32(210, 215, 220, 255), rows[i]);
        return std::pair<ImVec2, ImVec2>(a, b);
    };

    // anchor points from node rects to draw edges between blocks
    const char* head_rows[] = {"push ebp", "mov ebp, esp", "call parse_header", "test eax, eax", "jz 0x401021"};
    const char* yes_rows[] = {"push 0x403000", "call decrypt_block", "jmp 0x401023"};
    const char* no_rows[] = {"xor eax, eax", "mov esp, ebp", "pop ebp", "ret"};
    auto head = node("0x401000 head", head_rows, 5, ImVec2(220, 10), ImVec2(280, 130), 0);
    auto yes = node("0x40100f taken:no", yes_rows, 3, ImVec2(40, 180), ImVec2(260, 100), 0);
    auto no = node("0x401021 taken:yes", no_rows, 4, ImVec2(380, 180), ImVec2(260, 116), 0);

    ImVec2 h_bot = ImVec2((head.first.x + head.second.x) * 0.5f, head.second.y);
    ImVec2 y_top = ImVec2((yes.first.x + yes.second.x) * 0.5f, yes.first.y);
    ImVec2 n_top = ImVec2((no.first.x + no.second.x) * 0.5f, no.first.y);
    draw->AddBezierCubic(h_bot, ImVec2(h_bot.x - 80, h_bot.y + 30), ImVec2(y_top.x, y_top.y - 30), y_top, IM_COL32(100, 200, 120, 255), 2.0f, 0);
    draw->AddBezierCubic(h_bot, ImVec2(h_bot.x + 80, h_bot.y + 30), ImVec2(n_top.x, n_top.y - 30), n_top, IM_COL32(220, 110, 110, 255), 2.0f, 0);
    draw->AddText(ImVec2(y_top.x - 60, y_top.y - 24), IM_COL32(100, 200, 120, 255), "no");
    draw->AddText(ImVec2(n_top.x + 30, n_top.y - 24), IM_COL32(220, 110, 110, 255), "yes");

    ImGui::Dummy(ImVec2(700, 340));
    ImGui::EndChild();
    (void)state;
}

static void render_view(app_state& state)
{
    if (!state.show_view)
        return;
    ImGui::Begin("ida view", &state.show_view);
    render_nav_band();
    ImGui::Checkbox("graph", &state.graph_mode);
    ImGui::SameLine();
    ImGui::TextDisabled("main_loop | %d lines | f5: pseudo (mock)", (int)(sizeof(mock_lines) / sizeof(mock_lines[0])));
    ImGui::Separator();
    if (state.graph_mode)
        render_graph_view(state);
    else
        render_text_view(state);
    ImGui::End();
}

static void render_right(app_state& state)
{
    if (!state.show_right)
        return;
    ImGui::Begin("imports / strings", &state.show_right);
    if (ImGui::BeginTabBar("right_tabs")) {
        if (ImGui::BeginTabItem("imports")) {
            if (ImGui::BeginTable("imp_table", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY)) {
                ImGui::TableSetupColumn("addr", ImGuiTableColumnFlags_WidthFixed, 80);
                ImGui::TableSetupColumn("dll", ImGuiTableColumnFlags_WidthFixed, 100);
                ImGui::TableSetupColumn("name", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableHeadersRow();
                int n = sizeof(mock_imports) / sizeof(mock_imports[0]);
                for (int i = 0; i < n; i++) {
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();
                    ImGui::TextDisabled("%08x", mock_imports[i].addr);
                    ImGui::TableNextColumn();
                    ImGui::Text("%s", mock_imports[i].dll);
                    ImGui::TableNextColumn();
                    ImGui::TextColored(ImVec4(1, 0.85f, 0.4f, 1), "%s", mock_imports[i].name);
                }
                ImGui::EndTable();
            }
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("strings")) {
            if (ImGui::BeginTable("str_table", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY)) {
                ImGui::TableSetupColumn("addr", ImGuiTableColumnFlags_WidthFixed, 80);
                ImGui::TableSetupColumn("len", ImGuiTableColumnFlags_WidthFixed, 40);
                ImGui::TableSetupColumn("text", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableHeadersRow();
                int n = sizeof(mock_strings) / sizeof(mock_strings[0]);
                for (int i = 0; i < n; i++) {
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();
                    ImGui::TextDisabled("%08x", mock_strings[i].addr);
                    ImGui::TableNextColumn();
                    ImGui::TextDisabled("%d", mock_strings[i].len);
                    ImGui::TableNextColumn();
                    ImGui::Text("%s", mock_strings[i].text);
                }
                ImGui::EndTable();
            }
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("xrefs")) {
            ImGui::TextDisabled("xrefs to main_loop");
            ImGui::BulletText("0x401006 call from start+6");
            ImGui::BulletText("0x401123 call from main_loop+3");
            ImGui::Separator();
            ImGui::TextDisabled("xrefs to decrypt_block");
            ImGui::BulletText("0x401014 call from start+14");
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
    ImGui::End();
}

static void render_regs(app_state& state)
{
    if (!state.show_regs)
        return;
    ImGui::Begin("cpu", &state.show_regs);
    if (ImGui::BeginTable("reg_table", 2, ImGuiTableFlags_RowBg)) {
        int n = sizeof(mock_regs) / sizeof(mock_regs[0]);
        for (int i = 0; i < n; i++) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextDisabled("%s", mock_regs[i][0]);
            ImGui::TableNextColumn();
            if (i == 8)
                ImGui::TextColored(ImVec4(1, 0.6f, 0.3f, 1), "%s", mock_regs[i][1]);
            else
                ImGui::Text("%s", mock_regs[i][1]);
        }
        ImGui::EndTable();
    }
    ImGui::Separator();
    ImGui::TextDisabled("stack");
    if (ImGui::BeginTable("stack_table", 2, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("addr", ImGuiTableColumnFlags_WidthFixed, 80);
        ImGui::TableSetupColumn("val", ImGuiTableColumnFlags_WidthStretch);
        const char* addrs[] = {"0019ff30", "0019ff34", "0019ff38", "0019ff3c", "0019ff40"};
        const char* vals[] = {"0c104000", "40ff1900", "00000000", "20114000", "00000001"};
        for (int i = 0; i < 5; i++) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextDisabled("%s", addrs[i]);
            ImGui::TableNextColumn();
            ImGui::Text("%s", vals[i]);
        }
        ImGui::EndTable();
    }
    ImGui::End();
    (void)state;
}

static void render_hex_tab()
{
    if (ImGui::BeginTable("hex_table", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("off", ImGuiTableColumnFlags_WidthFixed, 78);
        ImGui::TableSetupColumn("hex", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("ascii", ImGuiTableColumnFlags_WidthFixed, 130);
        ImGui::TableHeadersRow();
        for (int row = 0; row < 16; row++) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextDisabled("%08x", 0x403000 + row * 16);
            ImGui::TableNextColumn();
            char line[96] = {};
            int p = 0;
            for (int col = 0; col < 16; col++) {
                unsigned char v = (row * 16 + col < (int)sizeof(mock_hex)) ? mock_hex[row * 16 + col] : (unsigned char)(row * 7 + col * 13);
                p += snprintf(line + p, sizeof(line) - p, "%02x ", v);
            }
            ImGui::Text("%s", line);
            ImGui::TableNextColumn();
            char asc[20] = {};
            for (int col = 0; col < 16; col++) {
                unsigned char v = (row * 16 + col < (int)sizeof(mock_hex)) ? mock_hex[row * 16 + col] : (unsigned char)(row + col);
                asc[col] = (v >= 32 && v < 127) ? (char)v : '.';
            }
            asc[16] = '\0';
            ImGui::TextDisabled("%s", asc);
        }
        ImGui::EndTable();
    }
}

static void render_bottom(app_state& state)
{
    if (!state.show_bottom)
        return;
    ImGui::Begin("output / hex", &state.show_bottom);
    if (ImGui::BeginTabBar("bottom_tabs")) {
        if (ImGui::BeginTabItem("output")) {
            if (ImGui::Button("clear"))
                state.log_len = 0, state.log_buf[0] = '\0';
            ImGui::SameLine();
            ImGui::TextDisabled("ida-like log");
            ImGui::Separator();
            ImGui::BeginChild("log_scroll", ImVec2(0, 0), false, ImGuiWindowFlags_HorizontalScrollbar);
            ImGui::TextUnformatted(state.log_buf);
            if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
                ImGui::SetScrollHereY(1.0f);
            ImGui::EndChild();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("console")) {
            ImGui::TextDisabled("python console (mock)");
            ImGui::Separator();
            ImGui::Text(">>> print(hex(0x401000))");
            ImGui::Text("0x401000");
            static char cmd[256] = {};
            ImGui::InputTextWithHint("##cmd", "type command, enter", cmd, sizeof(cmd), ImGuiInputTextFlags_EnterReturnsTrue);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("hex")) {
            render_hex_tab();
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
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

    render_left(state);
    render_view(state);
    render_right(state);
    render_regs(state);
    render_bottom(state);

    if (state.show_demo)
        ImGui::ShowDemoWindow(&state.show_demo);

    ImGuiViewport* view = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(ImVec2(view->Pos.x, view->Pos.y + view->Size.y - 22));
    ImGui::SetNextWindowSize(ImVec2(view->Size.x, 22));
    ImGui::Begin("status", nullptr,
        ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove);
    int func_count = sizeof(mock_funcs) / sizeof(mock_funcs[0]);
    ImGui::TextDisabled("ready | %d funcs | %s | eip %08x | esp 0019ff30 | ida-like mock",
        func_count, state.file_name, mock_lines[state.selected_line].addr);
    ImGui::End();
}
