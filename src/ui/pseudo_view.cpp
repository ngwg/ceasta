#include "ui/pseudo_view.h"

#include "core/decompiler.h"
#include "imgui.h"
#include "theme.h"

#include <cctype>
#include <set>
#include <string>

namespace pseudo_view {

// cache the last decompiled function so we don't rerun it every frame
struct cache {
    const database* db = nullptr;
    uint64_t func = 0;
    uint64_t version = ~0ull;
    decompiled result;
};

static bool is_keyword(const std::string& w)
{
    static const std::set<std::string> kw = {
        "if", "else", "while", "do", "for", "switch", "case", "default",
        "return", "goto", "break", "continue", "sizeof"};
    return kw.count(w) != 0;
}

static bool is_type(const std::string& w)
{
    static const std::set<std::string> t = {
        "int", "char", "short", "long", "void", "unsigned", "float", "double", "bool"};
    return t.count(w) != 0;
}

// draw one code line with light token coloring, monospace assumed
static void draw_line(ImDrawList* dl, ImVec2 pos, const std::string& text)
{
    float x = pos.x;
    size_t i = 0, n = text.size();
    auto put = [&](const std::string& s, ImU32 col) {
        dl->AddText(ImVec2(x, pos.y), col, s.c_str(), s.c_str() + s.size());
        x += ImGui::CalcTextSize(s.c_str()).x;
    };
    while (i < n) {
        char c = text[i];
        if (c == '/' && i + 1 < n && text[i + 1] == '/') {
            put(text.substr(i), theme::auto_comment);
            break;
        }
        if (c == '"') {
            size_t j = i + 1;
            while (j < n && text[j] != '"')
                j++;
            if (j < n)
                j++;
            put(text.substr(i, j - i), theme::string);
            i = j;
            continue;
        }
        if (std::isalpha((unsigned char)c) || c == '_') {
            size_t j = i;
            while (j < n && (std::isalnum((unsigned char)text[j]) || text[j] == '_'))
                j++;
            std::string w = text.substr(i, j - i);
            ImU32 col = theme::text;
            if (is_keyword(w))
                col = theme::kw;
            else if (is_type(w))
                col = theme::ctype;
            // a following '(' means it's a call
            else if (j < n && text[j] == '(')
                col = theme::call;
            put(w, col);
            i = j;
            continue;
        }
        if (std::isdigit((unsigned char)c)) {
            size_t j = i;
            while (j < n && (std::isalnum((unsigned char)text[j]) || text[j] == 'x'))
                j++;
            put(text.substr(i, j - i), theme::number);
            i = j;
            continue;
        }
        // a run of punctuation / spaces
        size_t j = i;
        while (j < n && !std::isalnum((unsigned char)text[j]) && text[j] != '_' && text[j] != '"' &&
               !(text[j] == '/' && j + 1 < n && text[j + 1] == '/'))
            j++;
        put(text.substr(i, j - i), theme::punct);
        i = j;
    }
}

void draw(app_state& s)
{
    static cache c;
    database& db = *s.db;
    const function* fn = db.an.func_containing(s.cursor);
    uint64_t func = fn ? fn->start : 0;

    if (func == 0) {
        ImGui::BeginChild("##pseudo", ImVec2(0, 0));
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(theme::nop),
                           "  put the cursor inside a function to decompile it");
        ImGui::EndChild();
        return;
    }

    if (c.db != &db || c.func != func || c.version != s.version) {
        c.db = &db;
        c.func = func;
        c.version = s.version;
        c.result = decompile(db, func);
    }

    // toolbar
    ImGui::TextDisabled("pseudocode");
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(theme::func), "%s", c.result.name.c_str());
    ImGui::SameLine(ImGui::GetWindowWidth() - ImGui::CalcTextSize("Copy").x -
                    ImGui::GetStyle().FramePadding.x * 2 - ImGui::GetStyle().WindowPadding.x);
    if (ImGui::SmallButton("Copy"))
        ImGui::SetClipboardText(decompile_text(db, func).c_str());

    ImGui::BeginChild("##pseudo", ImVec2(0, 0), ImGuiChildFlags_None, ImGuiWindowFlags_NoNav);
    if (!c.result.ok) {
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(theme::log_error), "  %s",
                           c.result.error.c_str());
        ImGui::EndChild();
        return;
    }

    ImDrawList* dl = ImGui::GetWindowDrawList();
    float lh = ImGui::GetTextLineHeightWithSpacing();
    float cw = ImGui::CalcTextSize(" ").x;
    float pad = ImGui::GetStyle().WindowPadding.x;

    ImGuiListClipper clip;
    clip.Begin((int)c.result.lines.size(), lh);
    while (clip.Step()) {
        for (int i = clip.DisplayStart; i < clip.DisplayEnd; i++) {
            const decomp_line& l = c.result.lines[(size_t)i];
            ImVec2 p = ImGui::GetCursorScreenPos();
            float w = ImGui::GetContentRegionAvail().x;
            ImGui::PushID(i);
            ImGui::Selectable("##pl", false, ImGuiSelectableFlags_AllowOverlap, ImVec2(w, lh));
            bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
            ImGui::PopID();

            if (l.addr && l.addr == s.cursor)
                dl->AddRectFilled(p, ImVec2(p.x + w, p.y + lh), theme::row_selected);

            float x = p.x + pad + (float)l.indent * cw * 4.0f;
            draw_line(dl, ImVec2(x, p.y), l.text);

            if (clicked && l.addr)
                app_jump(s, l.addr);
        }
    }
    ImGui::EndChild();
}

} // namespace pseudo_view
