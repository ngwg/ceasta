#pragma once
#include "app.h"
#include "imgui.h"
#include "theme.h"
#include <algorithm>
#include <vector>

namespace widgets {

// maps a position along all segments laid end to end to an address, and back
inline bool band_addr(const binary& b, uint64_t off, uint64_t& out)
{
    for (const segment& s : b.segments) {
        if (off < s.size()) {
            out = s.start + off;
            return true;
        }
        off -= s.size();
    }
    return false;
}

inline bool band_offset(const binary& b, uint64_t a, uint64_t& out)
{
    uint64_t off = 0;
    for (const segment& s : b.segments) {
        if (s.contains(a)) {
            out = off + (a - s.start);
            return true;
        }
        off += s.size();
    }
    return false;
}

// overview of the whole file, one color per pixel column. click or drag to jump
inline void nav_band(app_state& s)
{
    float h = std::max(8.0f, ImGui::GetTextLineHeight() * 0.8f);
    ImVec2 pos = ImGui::GetCursorScreenPos();
    float w = std::max(ImGui::GetContentRegionAvail().x, 1.0f);
    ImGui::InvisibleButton("##navband", ImVec2(w, h));
    bool hovered = ImGui::IsItemHovered();
    bool active = ImGui::IsItemActive();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    dl->AddRectFilled(pos, ImVec2(pos.x + w, pos.y + h), theme::band_bg);
    if (!s.db)
        return;
    database& db = *s.db;
    uint64_t total = 0;
    for (const segment& seg : db.bin.segments)
        total += seg.size();
    if (!total)
        return;

    static struct {
        const database* db = nullptr;
        uint64_t version = ~0ull;
        int width = 0;
        std::vector<ImU32> cols;
    } cache;
    int px = (int)w;
    if (cache.db != &db || cache.version != s.version || cache.width != px) {
        cache.db = &db;
        cache.version = s.version;
        cache.width = px;
        cache.cols.assign((size_t)px, theme::band_unknown);
        for (int x = 0; x < px; x++) {
            uint64_t lo = total * (uint64_t)x / (uint64_t)px, hi = total * (uint64_t)(x + 1) / (uint64_t)px;
            int counts[4] = {0, 0, 0, 0}; // code, data, string, unknown
            uint64_t span = std::max<uint64_t>(hi - lo, 1);
            int samples = (int)std::min<uint64_t>(span, 24);
            for (int k = 0; k < samples; k++) {
                uint64_t a;
                if (!band_addr(db.bin, lo + span * (uint64_t)k / (uint64_t)samples, a))
                    continue;
                uint8_t f = db.an.flags_at(db.an.item_head(a));
                counts[(f & fl_code) ? 0 : (f & fl_data) ? 1 : (f & fl_str) ? 2 : 3]++;
            }
            int best = (int)(std::max_element(counts, counts + 4) - counts);
            static const ImU32 palette[4] = {theme::band_code, theme::band_data, theme::band_string, theme::band_unknown};
            cache.cols[(size_t)x] = palette[best];
        }
    }
    // runs of the same color as one rect
    for (int x = 0; x < px;) {
        int e = x + 1;
        while (e < px && cache.cols[(size_t)e] == cache.cols[(size_t)x])
            e++;
        dl->AddRectFilled(ImVec2(pos.x + x, pos.y + 1), ImVec2(pos.x + e, pos.y + h - 1), cache.cols[(size_t)x]);
        x = e;
    }
    auto mark = [&](uint64_t a, ImU32 col) {
        uint64_t off;
        if (band_offset(db.bin, a, off)) {
            float x = pos.x + (float)((double)off / (double)total * w);
            dl->AddRectFilled(ImVec2(x - 1, pos.y), ImVec2(x + 2, pos.y + h), col);
        }
    };
    uint64_t pc;
    if (app_pc_static(s, pc))
        mark(pc, theme::pc_arrow);
    mark(s.cursor, theme::band_cursor);

    if (hovered || active) {
        float mx = std::min(std::max(ImGui::GetIO().MousePos.x - pos.x, 0.0f), w - 1);
        uint64_t a;
        if (band_addr(db.bin, (uint64_t)((double)mx / w * (double)total), a)) {
            if (hovered && !active)
                ImGui::SetTooltip("%s  %s", db.fmt_addr(a).c_str(), db.location(db.an.item_head(a)).c_str());
            if (ImGui::IsItemClicked())
                app_jump(s, db.an.item_head(a), true);
            else if (active && ImGui::IsMouseDragging(ImGuiMouseButton_Left))
                app_jump(s, db.an.item_head(a), false);
        }
    }
}

}
