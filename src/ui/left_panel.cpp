#include "ui/left_panel.h"
#include "core/util.h"
#include "imgui.h"
#include "ui/dialogs.h"
#include <algorithm>

namespace left_panel {

struct entry {
    uint64_t addr;
    uint64_t size;
    std::string name;
};

// filtered + sorted view, rebuilt only when something it depends on changes
static struct {
    const database* db = nullptr;
    uint64_t version = ~0ull;
    std::string filter;
    int sort_col = -1;
    bool sort_desc = false;
    std::vector<entry> rows;
    size_t total = 0;
} cache;

void draw(app_state& s)
{
    if (!s.db) {
        ImGui::TextDisabled("Functions");
        ImGui::TextDisabled("(no file loaded)");
        return;
    }
    database& db = *s.db;
    ImGui::Text("Functions");
    ImGui::SameLine();
    ImGui::TextDisabled("%zu", cache.db == &db ? cache.rows.size() : db.an.funcs.size());
    ImGui::SetNextItemWidth(-FLT_MIN);
    ImGui::InputTextWithHint("##func_filter", "filter by name or address", s.func_filter, sizeof(s.func_filter));

    ImGuiTableFlags flags = ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_Sortable |
                            ImGuiTableFlags_Resizable | ImGuiTableFlags_Hideable | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_SizingFixedFit;
    if (!ImGui::BeginTable("##funcs", 3, flags))
        return;
    float cw = ImGui::CalcTextSize("0").x;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
    // compact addresses (no leading zeros) leave the name column room to breathe
    ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_DefaultSort, cw * (float)(util::hex(db.bin.max_addr()).size() + 1));
    ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_PreferSortDescending, cw * 7);
    ImGui::TableHeadersRow();

    int col = 1;
    bool desc = false;
    if (ImGuiTableSortSpecs* ss = ImGui::TableGetSortSpecs()) {
        if (ss->SpecsCount > 0) {
            col = ss->Specs[0].ColumnIndex;
            desc = ss->Specs[0].SortDirection == ImGuiSortDirection_Descending;
        }
        ss->SpecsDirty = false;
    }
    std::string filter = util::trim(s.func_filter);
    if (cache.db != &db || cache.version != s.version || cache.filter != filter || cache.sort_col != col || cache.sort_desc != desc) {
        cache.db = &db;
        cache.version = s.version;
        cache.filter = filter;
        cache.sort_col = col;
        cache.sort_desc = desc;
        cache.rows.clear();
        uint64_t want = 0;
        bool hex = util::parse_hex(filter, want);
        for (const function& f : db.an.funcs) {
            std::string n = db.name_at(f.start);
            if (!filter.empty() && !util::icontains(n, filter) && !(hex && util::icontains(util::hex(f.start), filter)))
                continue;
            cache.rows.push_back({f.start, f.end - f.start, n});
        }
        std::sort(cache.rows.begin(), cache.rows.end(), [&](const entry& a, const entry& b) {
            if (col == 0 && a.name != b.name)
                return desc ? b.name < a.name : a.name < b.name;
            if (col == 2 && a.size != b.size)
                return desc ? b.size < a.size : a.size < b.size;
            return desc ? b.addr < a.addr : a.addr < b.addr;
        });
    }

    const function* cur = db.an.func_containing(s.cursor);
    ImGuiListClipper clip;
    clip.Begin((int)cache.rows.size());
    while (clip.Step()) {
        for (int i = clip.DisplayStart; i < clip.DisplayEnd; i++) {
            const entry& e = cache.rows[(size_t)i];
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::PushID(i);
            bool selected = cur && cur->start == e.addr;
            if (ImGui::Selectable(e.name.c_str(), selected, ImGuiSelectableFlags_SpanAllColumns))
                app_jump(s, e.addr);
            if (ImGui::BeginPopupContextItem("##fn_ctx")) {
                if (ImGui::MenuItem("Jump to", "Enter"))
                    app_jump(s, e.addr);
                if (ImGui::MenuItem("Rename...", "N"))
                    dialogs::open(s, dialog_kind::rename, e.addr);
                if (ImGui::MenuItem("References...", "X"))
                    dialogs::open(s, dialog_kind::xrefs, e.addr);
                if (ImGui::MenuItem("Show graph")) {
                    app_jump(s, e.addr);
                    s.view = center_view::graph;
                }
                if (ImGui::MenuItem("Toggle breakpoint", "F2"))
                    app_toggle_bp(s, e.addr);
                if (ImGui::MenuItem("Copy name"))
                    ImGui::SetClipboardText(e.name.c_str());
                ImGui::EndPopup();
            }
            ImGui::PopID();
            ImGui::TableNextColumn();
            ImGui::TextDisabled("%s", util::hex(e.addr).c_str());
            ImGui::TableNextColumn();
            ImGui::TextDisabled("%llX", (unsigned long long)e.size);
        }
    }
    ImGui::EndTable();
}

}
