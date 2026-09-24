#pragma once
#include "core/database.h"
#include "core/os.h"
#include "imgui.h"

// look of the app: colors, fonts, spacing

namespace theme {

// listing colors
constexpr ImU32 addr = IM_COL32(120, 132, 150, 255);
constexpr ImU32 bytes = IM_COL32(96, 104, 118, 255);
constexpr ImU32 text = IM_COL32(220, 224, 230, 255);
constexpr ImU32 comment = IM_COL32(120, 200, 140, 255);
constexpr ImU32 auto_comment = IM_COL32(110, 150, 120, 255);
constexpr ImU32 jump = IM_COL32(120, 190, 255, 255);
constexpr ImU32 call = IM_COL32(255, 205, 110, 255);
constexpr ImU32 ret = IM_COL32(255, 120, 120, 255);
constexpr ImU32 nop = IM_COL32(110, 116, 128, 255);
constexpr ImU32 data = IM_COL32(200, 170, 240, 255);
constexpr ImU32 string = IM_COL32(240, 200, 150, 255);
constexpr ImU32 label = IM_COL32(150, 210, 255, 255);
constexpr ImU32 func = IM_COL32(255, 230, 140, 255);
constexpr ImU32 segment = IM_COL32(140, 150, 170, 255);
constexpr ImU32 unknown = IM_COL32(150, 130, 110, 255);

// row backgrounds
constexpr ImU32 row_selected = IM_COL32(52, 72, 110, 255);
constexpr ImU32 row_pc = IM_COL32(110, 90, 30, 255);
constexpr ImU32 row_hover = IM_COL32(40, 46, 58, 255);
constexpr ImU32 bp = IM_COL32(230, 70, 70, 255);
constexpr ImU32 pc_arrow = IM_COL32(255, 210, 80, 255);

// nav band
constexpr ImU32 band_bg = IM_COL32(20, 22, 28, 255);
constexpr ImU32 band_code = IM_COL32(70, 120, 200, 255);
constexpr ImU32 band_func = IM_COL32(90, 150, 230, 255);
constexpr ImU32 band_data = IM_COL32(150, 150, 165, 255);
constexpr ImU32 band_string = IM_COL32(200, 160, 90, 255);
constexpr ImU32 band_unknown = IM_COL32(60, 56, 52, 255);
constexpr ImU32 band_cursor = IM_COL32(255, 230, 80, 255);

// log levels
constexpr ImU32 log_info = IM_COL32(210, 214, 220, 255);
constexpr ImU32 log_warn = IM_COL32(240, 200, 100, 255);
constexpr ImU32 log_error = IM_COL32(255, 110, 110, 255);
constexpr ImU32 log_echo = IM_COL32(130, 170, 230, 255);

inline ImU32 style_color(line_style s)
{
    switch (s) {
    case ls_jump: return jump;
    case ls_call: return call;
    case ls_ret: return ret;
    case ls_nop: return nop;
    case ls_data: return data;
    case ls_string: return string;
    case ls_label: return label;
    case ls_func: return func;
    case ls_segment: return segment;
    case ls_unknown: return unknown;
    default: return text;
    }
}

inline ImU32 log_color(int level)
{
    return level == 1 ? log_warn : level == 2 ? log_error : level == 3 ? log_echo : log_info;
}

inline void apply_theme()
{
    ImGui::StyleColorsDark();
    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding = 0.0f;
    style.ChildRounding = 0.0f;
    style.FrameRounding = 3.0f;
    style.PopupRounding = 4.0f;
    style.ScrollbarRounding = 3.0f;
    style.GrabRounding = 3.0f;
    style.TabRounding = 3.0f;
    style.WindowBorderSize = 0.0f;
    style.ChildBorderSize = 1.0f;
    style.FrameBorderSize = 0.0f;
    style.WindowPadding = ImVec2(8, 6);
    style.FramePadding = ImVec2(7, 4);
    style.ItemSpacing = ImVec2(8, 5);
    style.ItemInnerSpacing = ImVec2(6, 4);
    style.ScrollbarSize = 14.0f;

    ImVec4* c = style.Colors;
    c[ImGuiCol_Text] = ImVec4(0.88f, 0.89f, 0.91f, 1.0f);
    c[ImGuiCol_TextDisabled] = ImVec4(0.52f, 0.55f, 0.60f, 1.0f);
    c[ImGuiCol_WindowBg] = ImVec4(0.10f, 0.11f, 0.13f, 1.0f);
    c[ImGuiCol_ChildBg] = ImVec4(0.08f, 0.09f, 0.11f, 1.0f);
    c[ImGuiCol_PopupBg] = ImVec4(0.12f, 0.13f, 0.16f, 0.98f);
    c[ImGuiCol_Border] = ImVec4(0.22f, 0.24f, 0.28f, 1.0f);
    c[ImGuiCol_FrameBg] = ImVec4(0.15f, 0.16f, 0.19f, 1.0f);
    c[ImGuiCol_FrameBgHovered] = ImVec4(0.20f, 0.22f, 0.27f, 1.0f);
    c[ImGuiCol_FrameBgActive] = ImVec4(0.24f, 0.27f, 0.33f, 1.0f);
    c[ImGuiCol_MenuBarBg] = ImVec4(0.13f, 0.14f, 0.17f, 1.0f);
    c[ImGuiCol_TitleBg] = ImVec4(0.13f, 0.14f, 0.17f, 1.0f);
    c[ImGuiCol_TitleBgActive] = ImVec4(0.16f, 0.20f, 0.28f, 1.0f);
    c[ImGuiCol_Header] = ImVec4(0.20f, 0.28f, 0.43f, 1.0f);
    c[ImGuiCol_HeaderHovered] = ImVec4(0.26f, 0.34f, 0.50f, 1.0f);
    c[ImGuiCol_HeaderActive] = ImVec4(0.30f, 0.40f, 0.58f, 1.0f);
    c[ImGuiCol_Button] = ImVec4(0.19f, 0.24f, 0.34f, 1.0f);
    c[ImGuiCol_ButtonHovered] = ImVec4(0.26f, 0.34f, 0.50f, 1.0f);
    c[ImGuiCol_ButtonActive] = ImVec4(0.30f, 0.40f, 0.58f, 1.0f);
    c[ImGuiCol_Tab] = ImVec4(0.13f, 0.14f, 0.17f, 1.0f);
    c[ImGuiCol_TabHovered] = ImVec4(0.26f, 0.34f, 0.50f, 1.0f);
    c[ImGuiCol_TabSelected] = ImVec4(0.20f, 0.28f, 0.43f, 1.0f);
    c[ImGuiCol_TableHeaderBg] = ImVec4(0.14f, 0.16f, 0.20f, 1.0f);
    c[ImGuiCol_TableBorderLight] = ImVec4(0.20f, 0.22f, 0.26f, 1.0f);
    c[ImGuiCol_TableRowBgAlt] = ImVec4(1.0f, 1.0f, 1.0f, 0.025f);
    c[ImGuiCol_Separator] = ImVec4(0.22f, 0.24f, 0.28f, 1.0f);
    c[ImGuiCol_SeparatorHovered] = ImVec4(0.35f, 0.50f, 0.80f, 1.0f);
    c[ImGuiCol_SeparatorActive] = ImVec4(0.45f, 0.60f, 0.95f, 1.0f);
    c[ImGuiCol_NavCursor] = ImVec4(0.45f, 0.65f, 1.0f, 1.0f);
}

// monospace everywhere: listings line up and the rest still reads fine
inline void load_fonts()
{
    ImGuiIO& io = ImGui::GetIO();
    const char* candidates[] = {
#ifdef _WIN32
        "C:\\Windows\\Fonts\\consola.ttf",
        "C:\\Windows\\Fonts\\cour.ttf",
#else
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/TTF/DejaVuSansMono.ttf",
#endif
    };
    for (const char* path : candidates) {
        if (os::exists(path) && io.Fonts->AddFontFromFileTTF(path))
            return;
    }
    io.Fonts->AddFontDefaultVector();
}

}
