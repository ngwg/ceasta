#include "ui/right_panel.h"
#include "core/util.h"
#include "imgui.h"
#include "theme.h"
#include "ui/dialogs.h"
#include <algorithm>

namespace right_panel {

// indexes of the rows that pass the filter, per tab, rebuilt when the inputs change
struct filtered {
    const database* db = nullptr;
    uint64_t version = ~0ull;
    std::string filter;
    std::vector<uint32_t> idx;

    template <typename F>
    const std::vector<uint32_t>& get(const database* d, uint64_t v, const std::string& f, size_t count, F match)
    {
        if (db != d || version != v || filter != f) {
            db = d;
            version = v;
            filter = f;
            idx.clear();
            for (size_t i = 0; i < count; i++)
                if (f.empty() || match(i))
                    idx.push_back((uint32_t)i);
        }
        return idx;
    }
};

static filtered f_imports, f_exports, f_strings;

static bool begin_table(const char* id, int cols)
{
    return ImGui::BeginTable(id, cols, ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable |
                                         ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_SizingFixedFit);
}

// compact addresses (no leading zeros) so names get the width
static float addr_w(database& db)
{
    return ImGui::CalcTextSize("0").x * (float)(util::hex(db.bin.max_addr()).size() + 1);
}

// the caller wraps each row in PushID/PopID so per row popups get their own id
static bool addr_cell(uint64_t a, bool enabled = true)
{
    return ImGui::Selectable(util::hex(a).c_str(), false, ImGuiSelectableFlags_SpanAllColumns | (enabled ? 0 : ImGuiSelectableFlags_Disabled));
}

static const std::vector<uint32_t>& imports_matching(app_state& s, const std::string& filter)
{
    const std::vector<import_entry>& imp = s.db->bin.imports;
    return f_imports.get(s.db.get(), s.version, filter, imp.size(), [&](size_t i) {
        return util::icontains(imp[i].name, filter) || util::icontains(imp[i].lib, filter);
    });
}

static const std::vector<uint32_t>& exports_matching(app_state& s, const std::string& filter)
{
    const std::vector<export_entry>& ex = s.db->bin.exports;
    return f_exports.get(s.db.get(), s.version, filter, ex.size(), [&](size_t i) {
        return util::icontains(ex[i].name, filter) || util::icontains(ex[i].forward, filter);
    });
}

static const std::vector<uint32_t>& strings_matching(app_state& s, const std::string& filter)
{
    const std::vector<string_item>& st = s.db->an.strings;
    return f_strings.get(s.db.get(), s.version, filter, st.size(), [&](size_t i) {
        return util::icontains(st[i].text, filter);
    });
}

static void imports(app_state& s, const std::vector<uint32_t>& idx)
{
    database& db = *s.db;
    const std::vector<import_entry>& imp = db.bin.imports;
    if (!begin_table("##imports", 3))
        return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("Address", 0, addr_w(db));
    ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
    ImGui::TableSetupColumn("Library", ImGuiTableColumnFlags_WidthStretch, 0.6f);
    ImGui::TableHeadersRow();
    ImGuiListClipper clip;
    clip.Begin((int)idx.size());
    while (clip.Step())
        for (int i = clip.DisplayStart; i < clip.DisplayEnd; i++) {
            const import_entry& e = imp[idx[(size_t)i]];
            ImGui::PushID(i);
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            if (addr_cell(e.slot))
                app_jump(s, e.slot);
            if (ImGui::BeginPopupContextItem("##imp_ctx")) {
                if (ImGui::MenuItem("Who calls this?", "X"))
                    dialogs::open(s, dialog_kind::xrefs, e.slot);
                ImGui::EndPopup();
            }
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(e.name.c_str());
            ImGui::TableNextColumn();
            ImGui::TextDisabled("%s", e.lib.c_str());
            ImGui::PopID();
        }
    ImGui::EndTable();
}

static void exports(app_state& s, const std::vector<uint32_t>& idx)
{
    database& db = *s.db;
    const std::vector<export_entry>& ex = db.bin.exports;
    if (!begin_table("##exports", 3))
        return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("Address", 0, addr_w(db));
    ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
    ImGui::TableSetupColumn("Ord");
    ImGui::TableHeadersRow();
    ImGuiListClipper clip;
    clip.Begin((int)idx.size());
    while (clip.Step())
        for (int i = clip.DisplayStart; i < clip.DisplayEnd; i++) {
            const export_entry& e = ex[idx[(size_t)i]];
            ImGui::PushID(i);
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            if (addr_cell(e.addr, e.addr != 0))
                app_jump(s, e.addr);
            ImGui::TableNextColumn();
            if (e.forward.empty())
                ImGui::TextUnformatted(e.name.c_str());
            else
                ImGui::Text("%s -> %s", e.name.c_str(), e.forward.c_str());
            ImGui::TableNextColumn();
            if (e.ordinal)
                ImGui::TextDisabled("%u", e.ordinal);
            ImGui::PopID();
        }
    ImGui::EndTable();
}

static void strings(app_state& s, const std::vector<uint32_t>& idx)
{
    database& db = *s.db;
    const std::vector<string_item>& st = db.an.strings;
    if (!begin_table("##strings", 2))
        return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("Address", 0, addr_w(db));
    ImGui::TableSetupColumn("String", ImGuiTableColumnFlags_WidthStretch);
    ImGui::TableHeadersRow();
    ImGuiListClipper clip;
    clip.Begin((int)idx.size());
    ImVec4 col = ImGui::ColorConvertU32ToFloat4(theme::string);
    while (clip.Step())
        for (int i = clip.DisplayStart; i < clip.DisplayEnd; i++) {
            const string_item& e = st[idx[(size_t)i]];
            ImGui::PushID(i);
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            if (addr_cell(e.addr))
                app_jump(s, e.addr);
            if (ImGui::BeginPopupContextItem("##str_ctx")) {
                if (ImGui::MenuItem("References...", "X"))
                    dialogs::open(s, dialog_kind::xrefs, e.addr);
                if (ImGui::MenuItem("Copy text"))
                    ImGui::SetClipboardText(e.text.c_str());
                ImGui::EndPopup();
            }
            ImGui::TableNextColumn();
            std::string t = util::escape(e.text, 160);
            ImGui::TextColored(col, "%s%s", e.wide ? "L" : "", t.c_str());
            ImGui::PopID();
        }
    ImGui::EndTable();
}

// what the file itself says: warnings first, hashes, headers, sections, resources, version
static void file_tab(app_state& s, const std::string& filter)
{
    database& db = *s.db;
    const file_info& fi = db.info;
    ImGui::BeginChild("##fileinfo", ImVec2(0, 0));
    for (const std::string& w : fi.warnings) {
        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(theme::log_warn));
        ImGui::TextWrapped("! %s", w.c_str());
        ImGui::PopStyleColor();
    }
    if (!fi.warnings.empty())
        ImGui::Spacing();
    auto copyable = [&](const char* label, const std::string& v) {
        if (v.empty())
            return;
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        ImGui::TextDisabled("%s", label);
        ImGui::TableNextColumn();
        ImGui::PushID(label);
        if (ImGui::Selectable(v.c_str()))
            ImGui::SetClipboardText(v.c_str());
        ImGui::SetItemTooltip("click to copy");
        ImGui::PopID();
    };
    if (ImGui::BeginTable("##hdr", 2, ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed);
        ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthStretch);
        for (const file_info::row& r : fi.header) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextDisabled("%s", r.label.c_str());
            ImGui::TableNextColumn();
            ImGui::TextWrapped("%s", r.value.c_str());
        }
        copyable("md5", fi.md5);
        copyable("sha256", fi.sha256);
        copyable("imphash", fi.imphash);
        for (const file_info::row& r : fi.version) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextDisabled("%s", r.label.c_str());
            ImGui::TableNextColumn();
            ImGui::TextWrapped("%s", r.value.c_str());
        }
        ImGui::EndTable();
    }
    ImGui::Spacing();
    ImGui::TextDisabled("sections - entropy near 8 is compressed or encrypted");
    if (ImGui::BeginTable("##secs", 5, ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV)) {
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Address", 0, addr_w(db));
        ImGui::TableSetupColumn("Size");
        ImGui::TableSetupColumn("Access");
        ImGui::TableSetupColumn("Entropy", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();
        int i = 0;
        for (const file_info::section& sec : fi.sections) {
            if (!util::icontains(sec.name, filter))
                continue;
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::PushID(i++);
            if (ImGui::Selectable(sec.name.c_str(), false, ImGuiSelectableFlags_SpanAllColumns) && db.bin.is_mapped(sec.addr))
                app_jump(s, sec.addr);
            ImGui::PopID();
            ImGui::TableNextColumn();
            ImGui::TextDisabled("%s", util::hex(sec.addr).c_str());
            ImGui::TableNextColumn();
            ImGui::TextDisabled("%llX", (unsigned long long)sec.size);
            ImGui::TableNextColumn();
            bool x = sec.perms.size() == 3 && sec.perms[2] == 'x', w = sec.perms.size() == 3 && sec.perms[1] == 'w';
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(x && w ? theme::log_error : theme::text), "%s", sec.perms.c_str());
            ImGui::TableNextColumn();
            // a small bar: how full of randomness it is
            ImVec2 p = ImGui::GetCursorScreenPos();
            float bw = ImGui::GetFontSize() * 4, h = ImGui::GetTextLineHeight();
            ImDrawList* dl = ImGui::GetWindowDrawList();
            dl->AddRectFilled(ImVec2(p.x, p.y + h * 0.3f), ImVec2(p.x + bw, p.y + h * 0.7f), theme::band_bg);
            dl->AddRectFilled(ImVec2(p.x, p.y + h * 0.3f), ImVec2(p.x + bw * (float)(sec.entropy / 8.0), p.y + h * 0.7f),
                sec.entropy > 7.2 ? theme::log_warn : theme::band_code);
            ImGui::Dummy(ImVec2(bw, h));
            ImGui::SameLine();
            ImGui::TextDisabled("%.2f", sec.entropy);
        }
        ImGui::EndTable();
    }
    if (!fi.resources.empty()) {
        ImGui::Spacing();
        ImGui::TextDisabled("resources - a click shows the bytes");
        if (ImGui::BeginTable("##res", 4, ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV)) {
            ImGui::TableSetupColumn("Type");
            ImGui::TableSetupColumn("Name");
            ImGui::TableSetupColumn("Size");
            ImGui::TableSetupColumn("What", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();
            int i = 0;
            for (const file_info::resource& r : fi.resources) {
                if (!util::icontains(r.type + " " + r.name, filter))
                    continue;
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::PushID(i++);
                if (ImGui::Selectable(r.type.c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
                    // the file offset back to where the section maps it
                    for (const file_info::section& sec : fi.sections)
                        if (r.file_off >= sec.file_off && r.file_off < sec.file_off + sec.file_size) {
                            s.hex_process = false;
                            s.hex_live = false;
                            s.hex_addr = sec.addr + (r.file_off - sec.file_off);
                            s.bottom_tab_request = 1;
                            s.show_bottom = true;
                        }
                }
                ImGui::PopID();
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(r.name.c_str());
                ImGui::TableNextColumn();
                ImGui::TextDisabled("%llu", (unsigned long long)r.size);
                ImGui::TableNextColumn();
                std::string what = r.note.empty() ? util::fmt("entropy %.2f", r.entropy) : r.note;
                ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(what.find("program") != std::string::npos ? theme::log_warn : theme::text),
                    "%s", what.c_str());
            }
            ImGui::EndTable();
        }
    }
    ImGui::EndChild();
}

static void xrefs(app_state& s)
{
    database& db = *s.db;
    // references to the item under the cursor, or to its function when the item has none
    uint64_t target = db.an.item_head(s.cursor);
    auto refs = db.an.refs_to(target);
    if (refs.first == refs.second) {
        const function* f = db.an.func_containing(s.cursor);
        if (f) {
            target = f->start;
            refs = db.an.refs_to(target);
        }
    }
    ImGui::TextDisabled("to %s: %d", db.location(target).c_str(), (int)(refs.second - refs.first));
    if (!begin_table("##xrefs", 3))
        return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("From", 0, addr_w(db));
    ImGui::TableSetupColumn("Type");
    ImGui::TableSetupColumn("Where", ImGuiTableColumnFlags_WidthStretch);
    ImGui::TableHeadersRow();
    static const char* const kinds[] = {"call", "jump", "read", "write", "offset"};
    int i = 0;
    for (const xref* x = refs.first; x != refs.second && i < 5000; x++, i++) {
        ImGui::PushID(i);
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        if (addr_cell(x->from))
            app_jump(s, x->from);
        ImGui::TableNextColumn();
        ImGui::TextDisabled("%s", kinds[(int)x->type]);
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(db.location(x->from).c_str());
        ImGui::PopID();
    }
    ImGui::EndTable();
}

void draw(app_state& s)
{
    if (!s.db) {
        ImGui::PushTextWrapPos(0);
        ImGui::TextDisabled("Imports, exports, strings, segments and references show up here once a file is open.");
        ImGui::PopTextWrapPos();
        return;
    }
    database& db = *s.db;
    // the search box filters every list; each tab then says how many of its rows match
    bool has_filter = s.info_filter[0] != 0;
    float clear_w = has_filter ? ImGui::GetFrameHeight() + ImGui::GetStyle().ItemSpacing.x : 0.0f;
    ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x - clear_w);
    ImGui::InputTextWithHint("##info_filter", "search imports, exports, strings", s.info_filter, sizeof(s.info_filter));
    if (has_filter) {
        ImGui::SameLine();
        if (ImGui::Button("x", ImVec2(ImGui::GetFrameHeight(), 0)))
            s.info_filter[0] = 0;
        ImGui::SetItemTooltip("clear the search");
    }
    std::string filter = util::trim(s.info_filter);
    const std::vector<uint32_t>& imp_idx = imports_matching(s, filter);
    const std::vector<uint32_t>& exp_idx = exports_matching(s, filter);
    const std::vector<uint32_t>& str_idx = strings_matching(s, filter);
    // while searching, the tabs count the matches
    auto count = [&](size_t shown, size_t total) { return util::fmt("%zu", filter.empty() ? total : shown); };
    if (ImGui::BeginTabBar("##info_tabs", ImGuiTabBarFlags_FittingPolicyScroll)) {
        auto tab = [&](const char* label, int index) {
            ImGuiTabItemFlags fl = s.right_tab_request == index ? ImGuiTabItemFlags_SetSelected : 0;
            return ImGui::BeginTabItem(label, nullptr, fl);
        };
        std::string imp = "Imports (" + count(imp_idx.size(), db.bin.imports.size()) + ")###imports";
        std::string exp = "Exports (" + count(exp_idx.size(), db.bin.exports.size()) + ")###exports";
        std::string str = "Strings (" + count(str_idx.size(), db.an.strings.size()) + ")###strings";
        if (tab(imp.c_str(), 0)) {
            imports(s, imp_idx);
            ImGui::EndTabItem();
        }
        if (tab(exp.c_str(), 1)) {
            exports(s, exp_idx);
            ImGui::EndTabItem();
        }
        if (tab(str.c_str(), 2)) {
            strings(s, str_idx);
            ImGui::EndTabItem();
        }
        std::string file_label = std::string(db.info.warnings.empty() ? "File" : "File (!)") + "###file";
        if (tab(file_label.c_str(), 3)) {
            file_tab(s, filter);
            ImGui::EndTabItem();
        }
        if (tab("Xrefs", 4)) {
            xrefs(s);
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
    s.right_tab_request = -1;
}

}
