#pragma once
#include "core/database.h"
#include "core/os.h"
#include "imgui.h"

// look of the app. three themes (dark, light, high contrast). the listing and
// pseudocode colors are plain globals so a theme change updates them live.

namespace theme {

enum class ui_theme { dark, light, contrast };

inline const char* theme_name(ui_theme t)
{
    switch (t) {
    case ui_theme::light: return "light";
    case ui_theme::contrast: return "high contrast";
    default: return "dark";
    }
}

// ---- listing / syntax colors (set by apply_theme) ----
inline ImU32 addr = IM_COL32(120, 132, 150, 255);
inline ImU32 bytes = IM_COL32(96, 104, 118, 255);
inline ImU32 text = IM_COL32(220, 224, 230, 255);
inline ImU32 comment = IM_COL32(120, 200, 140, 255);
inline ImU32 auto_comment = IM_COL32(110, 150, 120, 255);
inline ImU32 jump = IM_COL32(120, 190, 255, 255);
inline ImU32 call = IM_COL32(255, 205, 110, 255);
inline ImU32 ret = IM_COL32(255, 120, 120, 255);
inline ImU32 nop = IM_COL32(110, 116, 128, 255);
inline ImU32 data = IM_COL32(200, 170, 240, 255);
inline ImU32 string = IM_COL32(240, 200, 150, 255);
inline ImU32 label = IM_COL32(150, 210, 255, 255);
inline ImU32 func = IM_COL32(255, 230, 140, 255);
inline ImU32 segment = IM_COL32(140, 150, 170, 255);
inline ImU32 unknown = IM_COL32(150, 130, 110, 255);

// pseudocode tokens
inline ImU32 kw = IM_COL32(198, 149, 230, 255);
inline ImU32 ctype = IM_COL32(120, 200, 165, 255);
inline ImU32 number = IM_COL32(230, 185, 140, 255);
inline ImU32 punct = IM_COL32(150, 156, 168, 255);

// row backgrounds / markers
inline ImU32 row_selected = IM_COL32(52, 72, 110, 255);
inline ImU32 row_pc = IM_COL32(110, 90, 30, 255);
inline ImU32 row_hover = IM_COL32(40, 46, 58, 255);
inline ImU32 bp = IM_COL32(230, 70, 70, 255);
inline ImU32 pc_arrow = IM_COL32(255, 210, 80, 255);

// nav band
inline ImU32 band_bg = IM_COL32(20, 22, 28, 255);
inline ImU32 band_code = IM_COL32(70, 120, 200, 255);
inline ImU32 band_func = IM_COL32(90, 150, 230, 255);
inline ImU32 band_data = IM_COL32(150, 150, 165, 255);
inline ImU32 band_string = IM_COL32(200, 160, 90, 255);
inline ImU32 band_unknown = IM_COL32(60, 56, 52, 255);
inline ImU32 band_cursor = IM_COL32(255, 230, 80, 255);

// log levels
inline ImU32 log_info = IM_COL32(210, 214, 220, 255);
inline ImU32 log_warn = IM_COL32(240, 200, 100, 255);
inline ImU32 log_error = IM_COL32(255, 110, 110, 255);
inline ImU32 log_echo = IM_COL32(130, 170, 230, 255);

// a subtle panel-header background, set per theme
inline ImU32 header_bg = IM_COL32(26, 28, 34, 255);
inline ImU32 header_text = IM_COL32(150, 158, 172, 255);

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

inline void apply_theme(ui_theme t = ui_theme::dark)
{
    ImGuiStyle& style = ImGui::GetStyle();
    // squared, dense chrome - like a real tools window, not a rounded widget kit
    style.WindowRounding = 0.0f;
    style.ChildRounding = 0.0f;
    style.FrameRounding = 2.0f;
    style.PopupRounding = 2.0f;
    style.ScrollbarRounding = 0.0f;
    style.GrabRounding = 2.0f;
    style.TabRounding = 0.0f;
    style.WindowBorderSize = 0.0f;
    style.ChildBorderSize = 1.0f;
    style.FrameBorderSize = 1.0f;
    style.TabBorderSize = 0.0f;
    style.WindowPadding = ImVec2(8, 6);
    style.FramePadding = ImVec2(7, 4);
    style.ItemSpacing = ImVec2(8, 5);
    style.ItemInnerSpacing = ImVec2(6, 4);
    style.ScrollbarSize = 14.0f;
    style.GrabMinSize = 12.0f;
    style.SeparatorTextBorderSize = 1.0f;

    if (t == ui_theme::light)
        ImGui::StyleColorsLight();
    else
        ImGui::StyleColorsDark();
    ImVec4* c = style.Colors;

    if (t == ui_theme::dark) {
        c[ImGuiCol_Text] = ImVec4(0.87f, 0.89f, 0.91f, 1.0f);
        c[ImGuiCol_TextDisabled] = ImVec4(0.50f, 0.53f, 0.58f, 1.0f);
        c[ImGuiCol_WindowBg] = ImVec4(0.115f, 0.125f, 0.145f, 1.0f);
        c[ImGuiCol_ChildBg] = ImVec4(0.095f, 0.103f, 0.120f, 1.0f);
        c[ImGuiCol_PopupBg] = ImVec4(0.13f, 0.14f, 0.16f, 0.98f);
        c[ImGuiCol_Border] = ImVec4(0.02f, 0.02f, 0.03f, 0.85f);
        c[ImGuiCol_FrameBg] = ImVec4(0.16f, 0.17f, 0.20f, 1.0f);
        c[ImGuiCol_FrameBgHovered] = ImVec4(0.21f, 0.23f, 0.27f, 1.0f);
        c[ImGuiCol_FrameBgActive] = ImVec4(0.25f, 0.28f, 0.33f, 1.0f);
        c[ImGuiCol_MenuBarBg] = ImVec4(0.145f, 0.155f, 0.180f, 1.0f);
        c[ImGuiCol_TitleBg] = ImVec4(0.10f, 0.11f, 0.13f, 1.0f);
        c[ImGuiCol_TitleBgActive] = ImVec4(0.14f, 0.16f, 0.20f, 1.0f);
        c[ImGuiCol_Header] = ImVec4(0.22f, 0.30f, 0.42f, 1.0f);
        c[ImGuiCol_HeaderHovered] = ImVec4(0.26f, 0.35f, 0.48f, 1.0f);
        c[ImGuiCol_HeaderActive] = ImVec4(0.30f, 0.40f, 0.54f, 1.0f);
        c[ImGuiCol_Button] = ImVec4(0.20f, 0.22f, 0.27f, 1.0f);
        c[ImGuiCol_ButtonHovered] = ImVec4(0.27f, 0.31f, 0.38f, 1.0f);
        c[ImGuiCol_ButtonActive] = ImVec4(0.33f, 0.39f, 0.48f, 1.0f);
        c[ImGuiCol_Tab] = ImVec4(0.13f, 0.14f, 0.17f, 1.0f);
        c[ImGuiCol_TabHovered] = ImVec4(0.24f, 0.31f, 0.42f, 1.0f);
        c[ImGuiCol_TabSelected] = ImVec4(0.20f, 0.27f, 0.38f, 1.0f);
        c[ImGuiCol_TabDimmed] = ImVec4(0.12f, 0.13f, 0.15f, 1.0f);
        c[ImGuiCol_TabDimmedSelected] = ImVec4(0.17f, 0.20f, 0.26f, 1.0f);
        c[ImGuiCol_TableHeaderBg] = ImVec4(0.16f, 0.17f, 0.21f, 1.0f);
        c[ImGuiCol_TableBorderStrong] = ImVec4(0.02f, 0.02f, 0.03f, 1.0f);
        c[ImGuiCol_TableBorderLight] = ImVec4(0.20f, 0.22f, 0.26f, 1.0f);
        c[ImGuiCol_TableRowBgAlt] = ImVec4(1.0f, 1.0f, 1.0f, 0.022f);
        c[ImGuiCol_Separator] = ImVec4(0.02f, 0.02f, 0.03f, 0.9f);
        c[ImGuiCol_SeparatorHovered] = ImVec4(0.32f, 0.46f, 0.72f, 1.0f);
        c[ImGuiCol_SeparatorActive] = ImVec4(0.42f, 0.56f, 0.88f, 1.0f);
        c[ImGuiCol_ScrollbarBg] = ImVec4(0.09f, 0.10f, 0.12f, 1.0f);
        c[ImGuiCol_ScrollbarGrab] = ImVec4(0.24f, 0.26f, 0.31f, 1.0f);
        c[ImGuiCol_NavCursor] = ImVec4(0.45f, 0.65f, 1.0f, 1.0f);

        header_bg = IM_COL32(30, 33, 40, 255);
        header_text = IM_COL32(148, 156, 170, 255);
        row_selected = IM_COL32(48, 66, 100, 255);
        row_pc = IM_COL32(96, 80, 30, 255);
        row_hover = IM_COL32(40, 46, 58, 255);
        // listing colors keep their (dark) defaults set above
        addr = IM_COL32(120, 132, 150, 255);
        bytes = IM_COL32(96, 104, 118, 255);
        text = IM_COL32(220, 224, 230, 255);
        comment = IM_COL32(120, 200, 140, 255);
        auto_comment = IM_COL32(110, 150, 120, 255);
        jump = IM_COL32(120, 190, 255, 255);
        call = IM_COL32(255, 205, 110, 255);
        ret = IM_COL32(255, 120, 120, 255);
        nop = IM_COL32(110, 116, 128, 255);
        data = IM_COL32(200, 170, 240, 255);
        string = IM_COL32(240, 200, 150, 255);
        label = IM_COL32(150, 210, 255, 255);
        func = IM_COL32(255, 230, 140, 255);
        segment = IM_COL32(140, 150, 170, 255);
        unknown = IM_COL32(150, 130, 110, 255);
        kw = IM_COL32(198, 149, 230, 255);
        ctype = IM_COL32(120, 200, 165, 255);
        number = IM_COL32(230, 185, 140, 255);
        punct = IM_COL32(150, 156, 168, 255);
        band_bg = IM_COL32(20, 22, 28, 255);
        band_code = IM_COL32(70, 120, 200, 255);
        band_data = IM_COL32(150, 150, 165, 255);
        band_string = IM_COL32(200, 160, 90, 255);
        band_unknown = IM_COL32(52, 50, 58, 255);
        band_cursor = IM_COL32(255, 230, 80, 255);
        log_info = IM_COL32(210, 214, 220, 255);
        log_warn = IM_COL32(240, 200, 100, 255);
        log_error = IM_COL32(255, 110, 110, 255);
        log_echo = IM_COL32(130, 170, 230, 255);
    } else if (t == ui_theme::light) {
        c[ImGuiCol_Text] = ImVec4(0.13f, 0.15f, 0.18f, 1.0f);
        c[ImGuiCol_TextDisabled] = ImVec4(0.50f, 0.53f, 0.58f, 1.0f);
        c[ImGuiCol_WindowBg] = ImVec4(0.95f, 0.955f, 0.96f, 1.0f);
        c[ImGuiCol_ChildBg] = ImVec4(0.985f, 0.985f, 0.99f, 1.0f);
        c[ImGuiCol_PopupBg] = ImVec4(0.99f, 0.99f, 1.0f, 1.0f);
        c[ImGuiCol_Border] = ImVec4(0.70f, 0.72f, 0.76f, 1.0f);
        c[ImGuiCol_FrameBg] = ImVec4(1.0f, 1.0f, 1.0f, 1.0f);
        c[ImGuiCol_FrameBgHovered] = ImVec4(0.93f, 0.95f, 0.99f, 1.0f);
        c[ImGuiCol_FrameBgActive] = ImVec4(0.86f, 0.91f, 0.99f, 1.0f);
        c[ImGuiCol_MenuBarBg] = ImVec4(0.91f, 0.92f, 0.94f, 1.0f);
        c[ImGuiCol_TitleBg] = ImVec4(0.88f, 0.89f, 0.91f, 1.0f);
        c[ImGuiCol_TitleBgActive] = ImVec4(0.80f, 0.85f, 0.93f, 1.0f);
        c[ImGuiCol_Header] = ImVec4(0.72f, 0.82f, 0.96f, 1.0f);
        c[ImGuiCol_HeaderHovered] = ImVec4(0.66f, 0.78f, 0.95f, 1.0f);
        c[ImGuiCol_HeaderActive] = ImVec4(0.58f, 0.73f, 0.94f, 1.0f);
        c[ImGuiCol_Button] = ImVec4(0.90f, 0.91f, 0.94f, 1.0f);
        c[ImGuiCol_ButtonHovered] = ImVec4(0.82f, 0.87f, 0.95f, 1.0f);
        c[ImGuiCol_ButtonActive] = ImVec4(0.72f, 0.81f, 0.93f, 1.0f);
        c[ImGuiCol_Tab] = ImVec4(0.86f, 0.87f, 0.90f, 1.0f);
        c[ImGuiCol_TabHovered] = ImVec4(0.74f, 0.82f, 0.94f, 1.0f);
        c[ImGuiCol_TabSelected] = ImVec4(0.95f, 0.965f, 0.99f, 1.0f);
        c[ImGuiCol_TableHeaderBg] = ImVec4(0.90f, 0.91f, 0.94f, 1.0f);
        c[ImGuiCol_TableBorderStrong] = ImVec4(0.66f, 0.68f, 0.72f, 1.0f);
        c[ImGuiCol_TableBorderLight] = ImVec4(0.80f, 0.82f, 0.85f, 1.0f);
        c[ImGuiCol_TableRowBgAlt] = ImVec4(0.0f, 0.0f, 0.0f, 0.03f);
        c[ImGuiCol_Separator] = ImVec4(0.68f, 0.70f, 0.74f, 1.0f);
        c[ImGuiCol_ScrollbarBg] = ImVec4(0.92f, 0.93f, 0.95f, 1.0f);
        c[ImGuiCol_ScrollbarGrab] = ImVec4(0.72f, 0.74f, 0.78f, 1.0f);
        c[ImGuiCol_NavCursor] = ImVec4(0.20f, 0.45f, 0.85f, 1.0f);

        header_bg = IM_COL32(224, 227, 232, 255);
        header_text = IM_COL32(78, 86, 100, 255);
        row_selected = IM_COL32(200, 218, 248, 255);
        row_pc = IM_COL32(250, 236, 190, 255);
        row_hover = IM_COL32(232, 236, 242, 255);
        addr = IM_COL32(120, 128, 140, 255);
        bytes = IM_COL32(150, 156, 165, 255);
        text = IM_COL32(34, 38, 46, 255);
        comment = IM_COL32(40, 130, 70, 255);
        auto_comment = IM_COL32(90, 140, 105, 255);
        jump = IM_COL32(30, 100, 200, 255);
        call = IM_COL32(170, 100, 20, 255);
        ret = IM_COL32(200, 45, 45, 255);
        nop = IM_COL32(150, 155, 162, 255);
        data = IM_COL32(130, 80, 190, 255);
        string = IM_COL32(150, 95, 40, 255);
        label = IM_COL32(40, 110, 200, 255);
        func = IM_COL32(150, 105, 20, 255);
        segment = IM_COL32(90, 100, 120, 255);
        unknown = IM_COL32(150, 110, 80, 255);
        kw = IM_COL32(140, 60, 175, 255);
        ctype = IM_COL32(30, 130, 110, 255);
        number = IM_COL32(160, 95, 30, 255);
        punct = IM_COL32(90, 96, 108, 255);
        band_bg = IM_COL32(226, 228, 232, 255);
        band_code = IM_COL32(90, 140, 220, 255);
        band_data = IM_COL32(150, 155, 168, 255);
        band_string = IM_COL32(210, 160, 80, 255);
        band_unknown = IM_COL32(205, 205, 210, 255);
        band_cursor = IM_COL32(210, 150, 20, 255);
        log_info = IM_COL32(40, 44, 52, 255);
        log_warn = IM_COL32(175, 120, 10, 255);
        log_error = IM_COL32(200, 45, 45, 255);
        log_echo = IM_COL32(40, 100, 190, 255);
    } else { // high contrast
        c[ImGuiCol_Text] = ImVec4(1.0f, 1.0f, 1.0f, 1.0f);
        c[ImGuiCol_TextDisabled] = ImVec4(0.70f, 0.72f, 0.75f, 1.0f);
        c[ImGuiCol_WindowBg] = ImVec4(0.0f, 0.0f, 0.0f, 1.0f);
        c[ImGuiCol_ChildBg] = ImVec4(0.02f, 0.02f, 0.03f, 1.0f);
        c[ImGuiCol_PopupBg] = ImVec4(0.03f, 0.03f, 0.05f, 1.0f);
        c[ImGuiCol_Border] = ImVec4(0.55f, 0.58f, 0.65f, 1.0f);
        c[ImGuiCol_FrameBg] = ImVec4(0.10f, 0.10f, 0.13f, 1.0f);
        c[ImGuiCol_FrameBgHovered] = ImVec4(0.18f, 0.20f, 0.26f, 1.0f);
        c[ImGuiCol_FrameBgActive] = ImVec4(0.24f, 0.30f, 0.40f, 1.0f);
        c[ImGuiCol_MenuBarBg] = ImVec4(0.05f, 0.05f, 0.07f, 1.0f);
        c[ImGuiCol_TitleBg] = ImVec4(0.0f, 0.0f, 0.0f, 1.0f);
        c[ImGuiCol_TitleBgActive] = ImVec4(0.10f, 0.14f, 0.22f, 1.0f);
        c[ImGuiCol_Header] = ImVec4(0.10f, 0.34f, 0.62f, 1.0f);
        c[ImGuiCol_HeaderHovered] = ImVec4(0.16f, 0.42f, 0.72f, 1.0f);
        c[ImGuiCol_HeaderActive] = ImVec4(0.22f, 0.50f, 0.82f, 1.0f);
        c[ImGuiCol_Button] = ImVec4(0.14f, 0.16f, 0.22f, 1.0f);
        c[ImGuiCol_ButtonHovered] = ImVec4(0.22f, 0.30f, 0.44f, 1.0f);
        c[ImGuiCol_ButtonActive] = ImVec4(0.30f, 0.42f, 0.62f, 1.0f);
        c[ImGuiCol_Tab] = ImVec4(0.06f, 0.06f, 0.09f, 1.0f);
        c[ImGuiCol_TabHovered] = ImVec4(0.20f, 0.40f, 0.66f, 1.0f);
        c[ImGuiCol_TabSelected] = ImVec4(0.14f, 0.34f, 0.58f, 1.0f);
        c[ImGuiCol_TableHeaderBg] = ImVec4(0.10f, 0.11f, 0.15f, 1.0f);
        c[ImGuiCol_TableBorderStrong] = ImVec4(0.55f, 0.58f, 0.65f, 1.0f);
        c[ImGuiCol_TableBorderLight] = ImVec4(0.35f, 0.38f, 0.44f, 1.0f);
        c[ImGuiCol_TableRowBgAlt] = ImVec4(1.0f, 1.0f, 1.0f, 0.04f);
        c[ImGuiCol_Separator] = ImVec4(0.45f, 0.48f, 0.55f, 1.0f);
        c[ImGuiCol_ScrollbarBg] = ImVec4(0.0f, 0.0f, 0.0f, 1.0f);
        c[ImGuiCol_ScrollbarGrab] = ImVec4(0.35f, 0.38f, 0.45f, 1.0f);
        c[ImGuiCol_NavCursor] = ImVec4(0.40f, 0.70f, 1.0f, 1.0f);

        header_bg = IM_COL32(14, 16, 22, 255);
        header_text = IM_COL32(200, 206, 216, 255);
        row_selected = IM_COL32(30, 80, 150, 255);
        row_pc = IM_COL32(150, 120, 20, 255);
        row_hover = IM_COL32(30, 36, 50, 255);
        addr = IM_COL32(170, 180, 195, 255);
        bytes = IM_COL32(150, 158, 170, 255);
        text = IM_COL32(240, 242, 246, 255);
        comment = IM_COL32(110, 235, 140, 255);
        auto_comment = IM_COL32(120, 200, 140, 255);
        jump = IM_COL32(120, 200, 255, 255);
        call = IM_COL32(255, 215, 110, 255);
        ret = IM_COL32(255, 130, 130, 255);
        nop = IM_COL32(150, 156, 168, 255);
        data = IM_COL32(215, 180, 255, 255);
        string = IM_COL32(255, 210, 150, 255);
        label = IM_COL32(150, 215, 255, 255);
        func = IM_COL32(255, 235, 150, 255);
        segment = IM_COL32(180, 190, 205, 255);
        unknown = IM_COL32(200, 170, 140, 255);
        kw = IM_COL32(220, 170, 250, 255);
        ctype = IM_COL32(130, 225, 185, 255);
        number = IM_COL32(255, 200, 150, 255);
        punct = IM_COL32(200, 206, 216, 255);
        band_bg = IM_COL32(0, 0, 0, 255);
        band_code = IM_COL32(80, 150, 240, 255);
        band_data = IM_COL32(180, 185, 200, 255);
        band_string = IM_COL32(230, 180, 90, 255);
        band_unknown = IM_COL32(60, 62, 72, 255);
        band_cursor = IM_COL32(255, 235, 90, 255);
        log_info = IM_COL32(235, 238, 244, 255);
        log_warn = IM_COL32(255, 210, 110, 255);
        log_error = IM_COL32(255, 120, 120, 255);
        log_echo = IM_COL32(140, 190, 255, 255);
    }
    band_func = band_code;
    pc_arrow = band_cursor;
    bp = IM_COL32(230, 70, 70, 255);
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

} // namespace theme
