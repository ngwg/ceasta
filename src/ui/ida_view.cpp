#include "ui/ida_view.h"
#include "core/util.h"
#include "imgui.h"
#include "theme.h"
#include "ui/dialogs.h"
#include "ui/graph_view.h"
#include "ui/pseudo_view.h"
#include "widgets/nav_band.h"
#include <algorithm>

namespace ida_view {

static void centered_text(const char* text, ImU32 col)
{
    float w = ImGui::CalcTextSize(text).x;
    ImGui::SetCursorPosX(std::max(0.0f, (ImGui::GetWindowWidth() - w) * 0.5f));
    ImGui::PushStyleColor(ImGuiCol_Text, col);
    ImGui::TextUnformatted(text);
    ImGui::PopStyleColor();
}

static void welcome(app_state& s)
{
    float h = ImGui::GetContentRegionAvail().y;
    ImGui::Dummy(ImVec2(0, h * 0.18f));
    ImGui::PushFont(nullptr, ImGui::GetStyle().FontSizeBase * 2.2f);
    centered_text("ceasta", theme::func);
    ImGui::PopFont();
    centered_text("disassembler + debugger for windows and linux binaries", theme::addr);
    ImGui::Dummy(ImVec2(0, ImGui::GetTextLineHeight()));

    float bw = ImGui::CalcTextSize("Open as raw code...").x + ImGui::GetStyle().FramePadding.x * 2;
    ImGui::SetCursorPosX(std::max(0.0f, (ImGui::GetWindowWidth() - bw * 2 - ImGui::GetStyle().ItemSpacing.x) * 0.5f));
    if (ImGui::Button("Open a file...", ImVec2(bw, 0)))
        app_open_dialog(s);
    ImGui::SameLine();
    if (ImGui::Button("Open as raw code...", ImVec2(bw, 0)))
        dialogs::open(s, dialog_kind::open_raw, 0);
    ImGui::Dummy(ImVec2(0, ImGui::GetTextLineHeight() * 0.5f));
    centered_text("or drop a file on the window  -  .exe .dll .sys, elf binaries, raw shellcode", theme::nop);

    if (!s.recent.empty()) {
        ImGui::Dummy(ImVec2(0, ImGui::GetTextLineHeight()));
        centered_text("recent files", theme::addr);
        float w = std::min(ImGui::GetWindowWidth() - 20.0f, ImGui::CalcTextSize("0").x * 80);
        std::string pick;
        for (size_t i = 0; i < s.recent.size(); i++) {
            ImGui::SetCursorPosX(std::max(0.0f, (ImGui::GetWindowWidth() - w) * 0.5f));
            ImGui::PushID((int)i);
            if (ImGui::Selectable(s.recent[i].c_str(), false, 0, ImVec2(w, 0)))
                pick = s.recent[i];
            ImGui::PopID();
        }
        if (!pick.empty())
            app_open(s, pick);
    }
}

static void loading(app_state& s)
{
    float h = ImGui::GetContentRegionAvail().y;
    ImGui::Dummy(ImVec2(0, h * 0.3f));
    int pct = s.job->progress.percent.load();
    std::string msg = "analyzing " + s.job->path;
    centered_text(msg.c_str(), theme::text);
    float w = std::min(ImGui::GetWindowWidth() * 0.6f, 600.0f);
    ImGui::SetCursorPosX((ImGui::GetWindowWidth() - w) * 0.5f);
    std::string label = util::fmt("%d%%", pct);
    ImGui::ProgressBar(pct / 100.0f, ImVec2(w, 0), label.c_str());
    float bw = ImGui::CalcTextSize("Cancel").x + ImGui::GetStyle().FramePadding.x * 2;
    ImGui::SetCursorPosX((ImGui::GetWindowWidth() - bw) * 0.5f);
    if (ImGui::Button("Cancel"))
        s.job->progress.cancel.store(true);
}

// ---- listing ----

static void row_menu(app_state& s, uint64_t a)
{
    database& db = *s.db;
    if (ImGui::MenuItem("Follow", "Enter"))
        app_follow(s, a);
    if (ImGui::MenuItem("Rename...", "N"))
        dialogs::open(s, dialog_kind::rename, a);
    if (ImGui::MenuItem("Comment...", ";"))
        dialogs::open(s, dialog_kind::comment, a);
    if (ImGui::MenuItem("References...", "X"))
        dialogs::open(s, dialog_kind::xrefs, a);
    ImGui::Separator();
    if (ImGui::MenuItem("Toggle breakpoint", "F2"))
        app_toggle_bp(s, a);
    if (ImGui::MenuItem("Run to here", "F4", false, s.dbg.state() == dbg_state::stopped && s.dbg_mapped)) {
        s.cursor = a;
        dbg_run_to_cursor(s);
    }
    ImGui::Separator();
    if (ImGui::MenuItem("Copy address"))
        ImGui::SetClipboardText(db.fmt_addr(a).c_str());
    if (ImGui::MenuItem("Copy line")) {
        row r;
        r.addr = a;
        uint8_t f = db.an.flags_at(a);
        r.kind = (f & fl_code) ? row_kind::code : (f & fl_str) ? row_kind::string : (f & fl_data) ? row_kind::data : row_kind::unknown;
        r.size = db.an.item_size(a);
        line_text t;
        db.format(r, t);
        std::string line = t.addr + "  " + t.text + (t.comment.empty() ? "" : "  ; " + t.comment);
        ImGui::SetClipboardText(line.c_str());
    }
    if (ImGui::MenuItem("Show in hex")) {
        s.hex_addr = a;
        s.bottom_tab_request = 1;
        s.show_bottom = true;
    }
}

// the item row before / after the cursor row, skipping header rows that share an address
static uint64_t step_rows(database& db, uint64_t cursor, int delta)
{
    const std::vector<row>& rows = db.rows();
    if (rows.empty())
        return cursor;
    size_t i = db.row_of(cursor);
    while (delta < 0 && i > 0) {
        uint64_t here = rows[i].addr;
        while (i > 0 && rows[i].addr == here)
            i--;
        size_t j = db.row_of(rows[i].addr);
        i = j;
        delta++;
    }
    while (delta > 0 && i + 1 < rows.size()) {
        i++;
        i = db.row_of(rows[i].addr);
        delta--;
    }
    return rows[i].addr;
}

static void listing(app_state& s)
{
    database& db = *s.db;
    ImGui::BeginChild("##listing", ImVec2(0, 0), ImGuiChildFlags_None, ImGuiWindowFlags_NoNav);
    const std::vector<row>& rows = db.rows();
    float lh = ImGui::GetTextLineHeightWithSpacing();
    float cw = ImGui::CalcTextSize("0").x;
    size_t cur_row = db.row_of(s.cursor);

    // column layout from the widest segment name + address width
    size_t seg_len = 0;
    for (const segment& seg : db.bin.segments)
        seg_len = std::max(seg_len, seg.name.size());
    float x_gutter = ImGui::GetStyle().WindowPadding.x;
    float x_addr = x_gutter + cw * 2.5f;
    float x_bytes = x_addr + cw * (float)(seg_len + 1 + db.fmt_addr(0).size() + 2);
    float x_text = x_bytes + (s.show_bytes ? cw * 26 : 0.0f);

    uint64_t pc = 0;
    bool has_pc = app_pc_static(s, pc);
    bool focused = ImGui::IsWindowFocused();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    float visible_h = ImGui::GetWindowHeight();
    float scroll_y = ImGui::GetScrollY();
    line_text t;

    ImGuiListClipper clip;
    clip.Begin((int)rows.size(), lh);
    if (s.scroll_to_cursor)
        clip.IncludeItemByIndex((int)cur_row);
    while (clip.Step()) {
        for (int i = clip.DisplayStart; i < clip.DisplayEnd; i++) {
            const row& r = rows[(size_t)i];
            if (s.scroll_to_cursor && (size_t)i == cur_row) {
                float y = i * lh;
                if (y < scroll_y || y + lh > scroll_y + visible_h)
                    ImGui::SetScrollHereY(0.3f);
            }
            ImVec2 p = ImGui::GetCursorScreenPos();
            float w = ImGui::GetContentRegionAvail().x;
            ImGui::PushID(i);
            ImGui::Selectable("##row", false, ImGuiSelectableFlags_AllowDoubleClick | ImGuiSelectableFlags_AllowOverlap, ImVec2(w, lh));
            bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
            bool dbl = ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left);
            if (ImGui::BeginPopupContextItem("##row_ctx")) {
                s.cursor = r.addr;
                row_menu(s, r.addr);
                ImGui::EndPopup();
            }
            ImGui::PopID();

            bool item_row = r.kind == row_kind::code || r.kind == row_kind::data || r.kind == row_kind::string || r.kind == row_kind::unknown;
            if ((size_t)i == cur_row)
                dl->AddRectFilled(p, ImVec2(p.x + w, p.y + lh), theme::row_selected);
            if (has_pc && item_row && r.addr == pc)
                dl->AddRectFilled(p, ImVec2(p.x + w, p.y + lh), theme::row_pc);

            float mid = p.y + lh * 0.5f;
            float gx = p.x + x_gutter - ImGui::GetStyle().WindowPadding.x + cw * 0.9f;
            if (item_row && db.breakpoints.count(r.addr))
                dl->AddCircleFilled(ImVec2(gx, mid), lh * 0.28f, theme::bp);
            if (has_pc && item_row && r.addr == pc) {
                float ax = gx + cw * 0.9f;
                dl->AddTriangleFilled(ImVec2(ax - cw * 0.5f, mid - lh * 0.3f), ImVec2(ax - cw * 0.5f, mid + lh * 0.3f),
                    ImVec2(ax + cw * 0.4f, mid), theme::pc_arrow);
            }

            db.format(r, t);
            float base_x = p.x - ImGui::GetStyle().WindowPadding.x;
            if (!t.addr.empty())
                dl->AddText(ImVec2(base_x + x_addr, p.y), theme::addr, t.addr.c_str());
            if (s.show_bytes && !t.bytes.empty())
                dl->AddText(ImVec2(base_x + x_bytes, p.y), theme::bytes, t.bytes.c_str());
            float tx = base_x + x_text + ((r.kind == row_kind::func || r.kind == row_kind::label || r.kind == row_kind::seg) ? 0.0f : cw * 2);
            if (!t.text.empty())
                dl->AddText(ImVec2(tx, p.y), theme::style_color(t.style), t.text.c_str());
            float cx = std::max(tx + ImGui::CalcTextSize(t.text.c_str()).x + cw * 3, base_x + x_text + cw * 44);
            if (!t.comment.empty()) {
                std::string c = "; " + t.comment;
                size_t nl = c.find('\n');
                if (nl != std::string::npos)
                    c = c.substr(0, nl) + " ...";
                dl->AddText(ImVec2(cx, p.y), theme::comment, c.c_str());
                cx += ImGui::CalcTextSize(c.c_str()).x + cw * 2;
            }
            if (!t.auto_comment.empty()) {
                std::string c = "; " + t.auto_comment;
                dl->AddText(ImVec2(cx, p.y), theme::auto_comment, c.c_str());
            }

            if (clicked) {
                // a click in the gutter toggles a breakpoint
                if (item_row && ImGui::GetIO().MousePos.x < base_x + x_addr - cw * 0.3f)
                    app_toggle_bp(s, r.addr);
                s.cursor = r.addr;
                if (s.hex_follow)
                    s.hex_addr = r.addr;
            }
            if (dbl && !app_follow(s, r.addr) && r.kind == row_kind::func)
                dialogs::open(s, dialog_kind::rename, r.addr);
        }
    }
    s.scroll_to_cursor = false;

    // arrow keys move the cursor while the listing has focus
    if (focused && !ImGui::GetIO().WantTextInput) {
        int page = std::max(1, (int)(visible_h / lh) - 2);
        int delta = 0;
        if (ImGui::IsKeyPressed(ImGuiKey_UpArrow))
            delta = -1;
        if (ImGui::IsKeyPressed(ImGuiKey_DownArrow))
            delta = 1;
        if (ImGui::IsKeyPressed(ImGuiKey_PageUp))
            delta = -page;
        if (ImGui::IsKeyPressed(ImGuiKey_PageDown))
            delta = page;
        if (delta) {
            s.cursor = step_rows(db, s.cursor, delta);
            if (s.hex_follow)
                s.hex_addr = s.cursor;
            s.scroll_to_cursor = true;
        }
    }
    ImGui::EndChild();
}

static void header(app_state& s)
{
    database& db = *s.db;
    const function* f = db.an.func_containing(s.cursor);
    ImGui::AlignTextToFramePadding();
    if (f) {
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(theme::func), "%s", db.name_at(f->start).c_str());
        ImGui::SameLine();
        ImGui::TextDisabled("%s  size %llX  %u insns", db.fmt_addr(f->start).c_str(), (unsigned long long)(f->end - f->start), f->insns);
    } else {
        ImGui::TextDisabled("%s", db.location(s.cursor).c_str());
    }
    // the view switch: three small tabs on the right
    static const char* const names[] = {"Listing", "Graph", "Pseudocode"};
    static const char* const keys[] = {"Space switches listing / graph", "Space switches listing / graph", "F5"};
    static const center_view views[] = {center_view::listing, center_view::graph, center_view::pseudo};
    ImGuiStyle& st = ImGui::GetStyle();
    float bw = st.ItemSpacing.x * 2;
    for (const char* n : names)
        bw += ImGui::CalcTextSize(n).x + st.FramePadding.x * 2 + 2;
    float right = ImGui::GetWindowWidth() - st.WindowPadding.x;
    ImGui::SameLine(std::max(ImGui::GetCursorPosX(), right - bw));
    for (int i = 0; i < 3; i++) {
        bool on = s.view == views[i];
        ImGui::PushStyleColor(ImGuiCol_Button, on ? ImGui::GetStyleColorVec4(ImGuiCol_ButtonActive) : ImVec4(0, 0, 0, 0));
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetStyleColorVec4(on ? ImGuiCol_Text : ImGuiCol_TextDisabled));
        if (ImGui::Button(names[i]))
            s.view = views[i];
        ImGui::PopStyleColor(2);
        ImGui::SetItemTooltip("%s", keys[i]);
        if (i < 2)
            ImGui::SameLine(0, 2);
    }
}

void draw(app_state& s)
{
    widgets::nav_band(s);
    if (s.job) {
        loading(s);
        return;
    }
    if (!s.db) {
        welcome(s);
        return;
    }
    header(s);
    if (s.view == center_view::graph)
        graph_view::draw(s);
    else if (s.view == center_view::pseudo)
        pseudo_view::draw(s);
    else
        listing(s);
}

}
