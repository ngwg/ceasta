#include "ui/ida_view.h"
#include "data/mock_data.h"
#include "widgets/nav_band.h"
#include "imgui.h"
#include <utility>

namespace ida_view {

static ImVec4 color_for(int kind)
{
    if (kind == 1)
        return ImVec4(0.55f, 0.80f, 1.0f, 1.0f);
    if (kind == 2)
        return ImVec4(1.0f, 0.85f, 0.40f, 1.0f);
    if (kind == 3)
        return ImVec4(1.0f, 0.45f, 0.45f, 1.0f);
    return ImVec4(0.85f, 0.87f, 0.90f, 1.0f);
}

static void text_list(app_state& state)
{
    if (ImGui::BeginTable("disasm_table", 5, ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("address", ImGuiTableColumnFlags_WidthFixed, 78);
        ImGui::TableSetupColumn("bytes", ImGuiTableColumnFlags_WidthFixed, 118);
        ImGui::TableSetupColumn("code", ImGuiTableColumnFlags_WidthFixed, 200);
        ImGui::TableSetupColumn("comment", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("xref", ImGuiTableColumnFlags_WidthFixed, 70);
        ImGui::TableHeadersRow();
        int n = sizeof(mock_lines) / sizeof(mock_lines[0]);
        for (int i = 0; i < n; i++) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            if (state.selected_line == i)
                ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, ImGui::GetColorU32(ImVec4(0.20f, 0.26f, 0.38f, 1.0f)));
            widgets::addr(mock_lines[i].addr, i == 0 || i == 14);
            ImGui::TableNextColumn();
            ImGui::TextDisabled("%s", mock_lines[i].bytes);
            ImGui::TableNextColumn();
            ImGui::TextColored(color_for(mock_lines[i].kind), "%-5s %s", mock_lines[i].mnemonic, mock_lines[i].operands);
            ImGui::TableNextColumn();
            ImGui::TextColored(ImVec4(0.45f, 0.75f, 0.55f, 1.0f), "%s", mock_lines[i].comment);
            ImGui::TableNextColumn();
            ImGui::TextDisabled("%s", mock_lines[i].kind == 2 ? "xref" : "");
            if (ImGui::IsItemHovered() && ImGui::IsMouseClicked(0))
                state.selected_line = i;
        }
        ImGui::EndTable();
    }
}

static void graph(app_state&)
{
    ImGui::BeginChild("graph_scroll", ImVec2(0, 0), false, ImGuiWindowFlags_HorizontalScrollbar);
    ImDrawList* draw = ImGui::GetWindowDrawList();
    ImVec2 origin = ImGui::GetCursorScreenPos();

    auto block = [&](const char* title, const char** rows, int nrows, ImVec2 pos, ImVec2 size) {
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

    // edges curve from bottom of head block to tops of branch blocks
    const char* head_rows[] = {"push ebp", "mov ebp, esp", "call parse_header", "test eax, eax", "jz 0x401021"};
    const char* yes_rows[] = {"push 0x403000", "call decrypt_block", "jmp 0x401023"};
    const char* no_rows[] = {"xor eax, eax", "mov esp, ebp", "pop ebp", "ret"};
    auto head = block("0x401000 head", head_rows, 5, ImVec2(220, 10), ImVec2(280, 130));
    auto yes = block("0x40100f taken:no", yes_rows, 3, ImVec2(40, 180), ImVec2(260, 100));
    auto no = block("0x401021 taken:yes", no_rows, 4, ImVec2(380, 180), ImVec2(260, 116));

    ImVec2 h_bot = ImVec2((head.first.x + head.second.x) * 0.5f, head.second.y);
    ImVec2 y_top = ImVec2((yes.first.x + yes.second.x) * 0.5f, yes.first.y);
    ImVec2 n_top = ImVec2((no.first.x + no.second.x) * 0.5f, no.first.y);
    draw->AddBezierCubic(h_bot, ImVec2(h_bot.x - 80, h_bot.y + 30), ImVec2(y_top.x, y_top.y - 30), y_top, IM_COL32(100, 200, 120, 255), 2.0f, 0);
    draw->AddBezierCubic(h_bot, ImVec2(h_bot.x + 80, h_bot.y + 30), ImVec2(n_top.x, n_top.y - 30), n_top, IM_COL32(220, 110, 110, 255), 2.0f, 0);

    ImGui::Dummy(ImVec2(700, 340));
    ImGui::EndChild();
}

void draw(app_state& state)
{
    if (!state.show_view)
        return;
    ImGui::Begin("ida view", &state.show_view);
    widgets::nav_band();
    ImGui::Checkbox("graph", &state.graph_mode);
    ImGui::SameLine();
    ImGui::TextDisabled("main_loop | %d lines", (int)(sizeof(mock_lines) / sizeof(mock_lines[0])));
    ImGui::Separator();
    if (state.graph_mode)
        graph(state);
    else
        text_list(state);
    ImGui::End();
}

}
