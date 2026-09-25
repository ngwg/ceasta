#include "ui/pseudo_view.h"

#include "core/decompiler.h"
#include "core/kuna.h"
#include "core/os.h"
#include "core/util.h"
#include "ui/dialogs.h"
#include "imgui.h"
#include "theme.h"

#include <atomic>
#include <cctype>
#include <cstdio>
#include <map>
#include <set>
#include <string>
#include <thread>

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
        "int", "char", "short", "long", "void", "unsigned", "signed", "float", "double", "bool", "const", "struct",
        "BOOL", "BYTE", "WORD", "DWORD", "QWORD", "HANDLE", "LPVOID", "LPCVOID", "LPSTR", "LPCSTR", "LPWSTR",
        "LPCWSTR", "SIZE_T", "UINT", "ULONG", "LONG", "HMODULE", "HWND", "NTSTATUS", "PVOID", "FILE", "wchar_t"};
    return t.count(w) != 0 || (w.size() > 2 && w.compare(w.size() - 2, 2, "_t") == 0);
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

// the last decompiled function, so it isn't decompiled again every frame
static cache g_cache;

// kuna, the optional second decompiler: its output for the same function. it's another program,
// so it runs in the background, and what it made is kept per function
struct kuna_entry {
    kuna_result r;
    std::vector<decomp_line> lines; // r's lines the way the view draws them
};

struct kuna_state {
    const database* db = nullptr; // what the results are for
    std::map<uint64_t, kuna_entry> done;
    uint64_t running = 0;         // the function kuna is working on, 0 when none
    uint64_t started_ms = 0;
    std::thread worker;
    std::atomic<bool> finished{false};
    std::atomic<bool> cancel{false};
    kuna_result result;           // the worker's, read once finished is set

    ~kuna_state() { stop(); }
    void stop()
    {
        if (worker.joinable()) {
            cancel = true;
            worker.join();
        }
        running = 0;
        cancel = false;
        finished = false;
    }
};
static kuna_state g_kuna;
static bool g_showing_kuna = false; // the view shows kuna's this frame: renaming doesn't apply there
static std::string g_kuna_code;

void shutdown() { g_kuna.stop(); }

static bool ident_char(char c) { return std::isalnum((unsigned char)c) || c == '_'; }

// the identifier at column col of text, "" when there's none (numbers don't count)
static std::string word_at(const std::string& text, int col)
{
    if (col < 0 || (size_t)col >= text.size() || !ident_char(text[(size_t)col]))
        return std::string();
    size_t a = (size_t)col, b = (size_t)col;
    while (a > 0 && ident_char(text[a - 1]))
        a--;
    while (b < text.size() && ident_char(text[b]))
        b++;
    std::string w = text.substr(a, b - a);
    return std::isdigit((unsigned char)w[0]) ? std::string() : w;
}

static const decomp_var* var_named(const std::string& w)
{
    for (const decomp_var& v : g_cache.result.vars)
        if (v.name == w)
            return &v;
    return nullptr;
}

// what a word names in the file: a function, a global. 0 when it's nothing there
static uint64_t address_of(app_state& s, const std::string& w)
{
    uint64_t a = 0;
    if (w.empty() || (!g_showing_kuna && var_named(w)) || is_keyword(w) || is_type(w))
        return 0;
    if (s.db->resolve(w, a) && s.db->bin.is_mapped(a))
        return a;
    // kuna's own names carry the address: sub_58d0, dat_2e298, FUN_00401000 (not local_10: a variable)
    size_t us = w.find('_');
    if (!g_showing_kuna || us == std::string::npos || us + 1 >= w.size())
        return 0;
    std::string prefix = w.substr(0, us);
    for (char& ch : prefix)
        ch = (char)std::tolower((unsigned char)ch);
    static const std::set<std::string> address_names = {"sub", "fun", "dat", "lab", "ptr", "off", "unk", "loc", "thunk"};
    if (address_names.count(prefix) && util::parse_hex(w.substr(us + 1), a) && s.db->bin.is_mapped(a))
        return a;
    return 0;
}

bool rename_selected(app_state& s)
{
    if (!s.db || s.pseudo_word.empty() || g_cache.func == 0 || g_showing_kuna)
        return false;
    if (const decomp_var* v = var_named(s.pseudo_word)) {
        std::string key = v->key, name = v->name;
        dialogs::open(s, dialog_kind::lvar_name, g_cache.func);
        s.dialog.key = key;
        snprintf(s.dialog.buf, sizeof(s.dialog.buf), "%s", name.c_str());
        return true;
    }
    uint64_t a = address_of(s, s.pseudo_word);
    if (!a)
        return false;
    dialogs::open(s, dialog_kind::rename, a);
    return true;
}

bool retype_selected(app_state& s)
{
    if (!s.db || g_cache.func == 0 || g_showing_kuna)
        return false;
    if (const decomp_var* v = var_named(s.pseudo_word)) {
        std::string key = v->key, type = v->type;
        dialogs::open(s, dialog_kind::lvar_type, g_cache.func);
        s.dialog.key = key;
        s.dialog.error.clear();
        snprintf(s.dialog.buf, sizeof(s.dialog.buf), "%s", type.c_str());
        return true;
    }
    // the function's own name, the signature line, or a function it calls: its prototype
    uint64_t a = address_of(s, s.pseudo_word);
    const function* f = a ? s.db->an.func_containing(a) : nullptr;
    uint64_t func = f && f->start == a ? a : (s.pseudo_line == 0 || s.pseudo_word.empty()) ? g_cache.func : 0;
    if (!func)
        return false;
    dialogs::open(s, dialog_kind::proto, func);
    return true;
}

bool follow_selected(app_state& s)
{
    uint64_t a = s.db ? address_of(s, s.pseudo_word) : 0;
    if (!a)
        return false;
    app_jump(s, a);
    return true;
}

static void word_menu(app_state& s)
{
    uint64_t a = address_of(s, s.pseudo_word);
    if (!s.pseudo_word.empty())
        ImGui::TextDisabled("%s", s.pseudo_word.c_str());
    if (g_showing_kuna) {
        // kuna's names are its own: this view reads, the ceasta view is where things get named
        if (ImGui::MenuItem("Jump to it", "Enter", false, a != 0))
            follow_selected(s);
        if (ImGui::MenuItem("Copy", nullptr, false, !s.pseudo_word.empty()))
            ImGui::SetClipboardText(s.pseudo_word.c_str());
        ImGui::Separator();
        if (ImGui::MenuItem("Copy the function"))
            ImGui::SetClipboardText(g_kuna_code.c_str());
        return;
    }
    const decomp_var* v = var_named(s.pseudo_word);
    const function* f = a ? s.db->an.func_containing(a) : nullptr;
    bool is_func = f && f->start == a;
    if (ImGui::MenuItem(v ? "Rename variable..." : "Rename...", "N", false, v || a))
        rename_selected(s);
    if (ImGui::MenuItem(v ? "Set type..." : "Edit prototype...", "Y", false, v || is_func || s.pseudo_line == 0))
        retype_selected(s);
    if (ImGui::MenuItem("Jump to it", "Enter", false, a != 0))
        follow_selected(s);
    if (ImGui::MenuItem("Copy", nullptr, false, !s.pseudo_word.empty()))
        ImGui::SetClipboardText(s.pseudo_word.c_str());
    ImGui::Separator();
    if (ImGui::MenuItem("Copy the function"))
        ImGui::SetClipboardText(decompile_text(*s.db, g_cache.func).c_str());
}

// one of the two small switches in the toolbar
static bool switch_button(const char* label, bool on)
{
    ImGui::PushStyleColor(ImGuiCol_Button, on ? ImGui::GetStyleColorVec4(ImGuiCol_ButtonActive) : ImVec4(0, 0, 0, 0));
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetStyleColorVec4(on ? ImGuiCol_Text : ImGuiCol_TextDisabled));
    bool pressed = ImGui::SmallButton(label);
    ImGui::PopStyleColor(2);
    return pressed;
}

// the lines, with the listing's line marked, the clicked word lit up, clicks moving the listing
static void draw_lines(app_state& s, const std::vector<decomp_line>& lines)
{
    ImDrawList* dl = ImGui::GetWindowDrawList();
    float lh = ImGui::GetTextLineHeightWithSpacing();
    float pitch = lh + ImGui::GetStyle().ItemSpacing.y;
    float cw = ImGui::CalcTextSize(" ").x;
    float pad = ImGui::GetStyle().WindowPadding.x;

    // the line the listing cursor is on: the last one at or before it (a line carries the
    // address of the instruction it starts at). when the cursor moved elsewhere, it scrolls there
    int here = -1;
    uint64_t best = 0;
    for (size_t i = 0; i < lines.size(); i++) {
        uint64_t a = lines[i].addr;
        if (a && a <= s.cursor && a >= best && i > 0) {
            best = a;
            here = (int)i;
        }
    }
    static uint64_t seen_cursor = ~0ull;
    bool scroll_here = seen_cursor != s.cursor && here >= 0 && !ImGui::IsWindowFocused();
    seen_cursor = s.cursor;

    ImGuiListClipper clip;
    clip.Begin((int)lines.size(), pitch);
    if (scroll_here)
        clip.IncludeItemByIndex(here);
    while (clip.Step()) {
        for (int i = clip.DisplayStart; i < clip.DisplayEnd; i++) {
            const decomp_line& l = lines[(size_t)i];
            ImVec2 p = ImGui::GetCursorScreenPos();
            float w = ImGui::GetContentRegionAvail().x;
            if (scroll_here && i == here) {
                float y = i * pitch;
                if (y < ImGui::GetScrollY() || y + lh > ImGui::GetScrollY() + ImGui::GetWindowHeight())
                    ImGui::SetScrollHereY(0.3f);
            }
            ImGui::PushID(i);
            ImGui::Selectable("##pl", false, ImGuiSelectableFlags_AllowOverlap | ImGuiSelectableFlags_AllowDoubleClick, ImVec2(w, lh));
            bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left) || ImGui::IsItemClicked(ImGuiMouseButton_Right);
            bool dbl = ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left);
            float x = p.x + pad + (float)l.indent * cw * 4.0f;
            if (clicked) {
                // the word under the mouse is selected: every place it's used lights up
                int col = (int)((ImGui::GetIO().MousePos.x - x) / cw);
                s.pseudo_word = word_at(l.text, col);
                s.pseudo_line = i;
                if (l.addr && ImGui::IsItemClicked(ImGuiMouseButton_Left)) {
                    seen_cursor = l.addr; // moved from here: no scrolling back
                    app_jump(s, l.addr);
                }
            }
            if (dbl)
                follow_selected(s);
            if (ImGui::BeginPopupContextItem("##pctx")) {
                word_menu(s);
                ImGui::EndPopup();
            }
            ImGui::PopID();

            if (i == here)
                dl->AddRectFilled(p, ImVec2(p.x + w, p.y + lh), theme::row_selected);
            // the selected word, wherever it is on this line
            if (!s.pseudo_word.empty())
                for (size_t at = l.text.find(s.pseudo_word); at != std::string::npos; at = l.text.find(s.pseudo_word, at + 1)) {
                    bool left = at == 0 || !ident_char(l.text[at - 1]);
                    size_t e = at + s.pseudo_word.size();
                    bool right = e >= l.text.size() || !ident_char(l.text[e]);
                    if (left && right)
                        dl->AddRectFilled(ImVec2(x + cw * (float)at - 1, p.y), ImVec2(x + cw * (float)e + 1, p.y + lh - 1),
                            theme::row_hover, 3.0f);
                }
            draw_line(dl, ImVec2(x, p.y), l.text);
        }
    }
}

// kuna's output for func: started in the background the first time, then kept
static const kuna_entry* kuna_for(app_state& s, uint64_t func)
{
    kuna_state& k = g_kuna;
    if (k.db != s.db.get()) {
        k.stop();
        k.done.clear();
        k.db = s.db.get();
    }
    if (k.running && k.finished) {
        k.worker.join();
        kuna_entry& e = k.done[k.running];
        e.r = std::move(k.result);
        for (const kuna_line& l : e.r.lines)
            e.lines.push_back({0, l.text, l.addr});
        k.running = 0;
        k.finished = false;
    }
    auto it = k.done.find(func);
    if (it != k.done.end())
        return &it->second;
    if (k.running && k.running != func)
        k.stop(); // moved on to another function: that one isn't wanted any more
    if (!k.running) {
        k.running = func;
        k.started_ms = os::now_ms();
        k.result = kuna_result();
        std::string exe = s.kuna_exe, file = s.db->bin.path;
        k.worker = std::thread([exe, file, func] {
            g_kuna.result = kuna_decompile(exe, file, func, 120000, &g_kuna.cancel);
            g_kuna.finished = true;
        });
    }
    return nullptr;
}

void draw(app_state& s)
{
    cache& c = g_cache;
    database& db = *s.db;
    const function* fn = db.an.func_containing(s.cursor);
    uint64_t func = fn ? fn->start : 0;
    s.pseudo_focus = false;
    bool have_kuna = !s.kuna_exe.empty();
    bool use_kuna = have_kuna && s.pseudo_kuna;
    g_showing_kuna = use_kuna;

    if (func == 0) {
        ImGui::BeginChild("##pseudo", ImVec2(0, 0));
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(theme::nop),
                           "  put the cursor inside a function to decompile it");
        ImGui::EndChild();
        return;
    }

    if (c.db != &db || c.func != func || c.version != s.version) {
        if (c.func != func)
            s.pseudo_word.clear();
        c.db = &db;
        c.func = func;
        c.version = s.version;
        c.result = use_kuna ? decompiled() : decompile(db, func);
        c.result.name = db.location(func);
        if (use_kuna)
            c.version = ~0ull; // the built-in one runs when it's switched back
    }

    // kuna's, when that's the one shown
    const kuna_entry* ke = nullptr;
    std::string kuna_why = use_kuna ? kuna_unsupported(db.bin) : std::string();
    if (use_kuna && kuna_why.empty())
        ke = kuna_for(s, func);
    const kuna_result* kr = ke ? &ke->r : nullptr;
    if (kr && kr->ok)
        g_kuna_code = kr->code;

    // toolbar
    ImGui::TextDisabled("pseudocode");
    ImGui::SameLine();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(theme::func), "%s", c.result.name.c_str());
    if (have_kuna) {
        // the second decompiler: only here when kuna is installed
        ImGui::SameLine(0, ImGui::GetFontSize());
        if (switch_button("ceasta", !use_kuna) && use_kuna) {
            s.pseudo_kuna = false;
            c.version = ~0ull;
        }
        ImGui::SetItemTooltip("ceasta's decompiler: your names, types and prototypes");
        ImGui::SameLine(0, 2);
        if (switch_button("kuna", use_kuna))
            s.pseudo_kuna = true;
        ImGui::SetItemTooltip("kuna, a decompiler ported from ghidra's (%s). it names things itself", s.kuna_exe.c_str());
    }
    ImGui::SameLine();
    if (use_kuna && kr && kr->ok)
        ImGui::TextDisabled("  kuna, %.1f s - reads only", kr->millis / 1000.0);
    else if (use_kuna)
        ImGui::TextDisabled("  kuna");
    else
        ImGui::TextDisabled("  click a name: N renames, Y sets its type");
    ImGui::SameLine(ImGui::GetWindowWidth() - ImGui::CalcTextSize("Copy").x -
                    ImGui::GetStyle().FramePadding.x * 2 - ImGui::GetStyle().WindowPadding.x);
    if (ImGui::SmallButton("Copy"))
        ImGui::SetClipboardText(use_kuna ? (kr && kr->ok ? kr->code.c_str() : "") : decompile_text(db, func).c_str());

    ImGui::BeginChild("##pseudo", ImVec2(0, 0), ImGuiChildFlags_None, ImGuiWindowFlags_NoNav);
    s.pseudo_focus = ImGui::IsWindowFocused();
    ImVec4 err_col = ImGui::ColorConvertU32ToFloat4(theme::log_error);
    if (use_kuna) {
        if (!kuna_why.empty())
            ImGui::TextColored(err_col, "  %s", kuna_why.c_str());
        else if (!kr)
            ImGui::TextDisabled("  kuna is decompiling %s... %.0f s", c.result.name.c_str(),
                (os::now_ms() - g_kuna.started_ms) / 1000.0);
        else if (!kr->ok)
            ImGui::TextColored(err_col, "  %s", kr->error.c_str());
        else
            draw_lines(s, ke->lines);
        ImGui::EndChild();
        return;
    }
    if (!c.result.ok) {
        ImGui::TextColored(err_col, "  %s", c.result.error.c_str());
        // ceasta's can't (arm64): kuna may
        if (have_kuna && kuna_unsupported(db.bin).empty()) {
            ImGui::Spacing();
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + ImGui::GetFontSize());
            if (ImGui::SmallButton("Show kuna's"))
                s.pseudo_kuna = true;
        }
        ImGui::EndChild();
        return;
    }
    draw_lines(s, c.result.lines);
    ImGui::EndChild();
}

} // namespace pseudo_view
