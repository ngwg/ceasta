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

static void imports(app_state& s, const std::string& filter)
{
    database& db = *s.db;
    const std::vector<import_entry>& imp = db.bin.imports;
    const std::vector<uint32_t>& idx = f_imports.get(&db, s.version, filter, imp.size(), [&](size_t i) {
        return util::icontains(imp[i].name, filter) || util::icontains(imp[i].lib, filter);
    });
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

static void exports(app_state& s, const std::string& filter)
{
    database& db = *s.db;
    const std::vector<export_entry>& ex = db.bin.exports;
    const std::vector<uint32_t>& idx = f_exports.get(&db, s.version, filter, ex.size(), [&](size_t i) {
        return util::icontains(ex[i].name, filter);
    });
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

static void strings(app_state& s, const std::string& filter)
{
    database& db = *s.db;
    const std::vector<string_item>& st = db.an.strings;
    const std::vector<uint32_t>& idx = f_strings.get(&db, s.version, filter, st.size(), [&](size_t i) {
        return util::icontains(st[i].text, filter);
    });
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

static void segments(app_state& s)
{
    database& db = *s.db;
    if (!begin_table("##segments", 4))
        return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("Name");
    ImGui::TableSetupColumn("Start", 0, addr_w(db));
    ImGui::TableSetupColumn("Size");
    ImGui::TableSetupColumn("Access", ImGuiTableColumnFlags_WidthStretch);
    ImGui::TableHeadersRow();
    int i = 0;
    for (const segment& seg : db.bin.segments) {
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        ImGui::PushID(i++);
        if (ImGui::Selectable(seg.name.c_str(), false, ImGuiSelectableFlags_SpanAllColumns))
            app_jump(s, seg.start);
        ImGui::PopID();
        ImGui::TableNextColumn();
        ImGui::TextDisabled("%s", util::hex(seg.start).c_str());
        ImGui::TableNextColumn();
        ImGui::TextDisabled("%llX", (unsigned long long)seg.size());
        ImGui::TableNextColumn();
        ImGui::Text("%c%c%c", (seg.perms & perm_r) ? 'r' : '-', (seg.perms & perm_w) ? 'w' : '-', (seg.perms & perm_x) ? 'x' : '-');
    }
    ImGui::EndTable();
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
    ImGui::SetNextItemWidth(-FLT_MIN);
    ImGui::InputTextWithHint("##info_filter", "filter", s.info_filter, sizeof(s.info_filter));
    std::string filter = util::trim(s.info_filter);
    if (ImGui::BeginTabBar("##info_tabs", ImGuiTabBarFlags_FittingPolicyScroll)) {
        auto tab = [&](const char* label, int index) {
            ImGuiTabItemFlags fl = s.right_tab_request == index ? ImGuiTabItemFlags_SetSelected : 0;
            return ImGui::BeginTabItem(label, nullptr, fl);
        };
        std::string imp = util::fmt("Imports (%zu)###imports", db.bin.imports.size());
        std::string exp = util::fmt("Exports (%zu)###exports", db.bin.exports.size());
        std::string str = util::fmt("Strings (%zu)###strings", db.an.strings.size());
        if (tab(imp.c_str(), 0)) {
            imports(s, filter);
            ImGui::EndTabItem();
        }
        if (tab(exp.c_str(), 1)) {
            exports(s, filter);
            ImGui::EndTabItem();
        }
        if (tab(str.c_str(), 2)) {
            strings(s, filter);
            ImGui::EndTabItem();
        }
        if (tab("Segments", 3)) {
            segments(s);
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
