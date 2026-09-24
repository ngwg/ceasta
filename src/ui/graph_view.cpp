#include "ui/graph_view.h"
#include "core/util.h"
#include "imgui.h"
#include "theme.h"
#include "ui/dialogs.h"
#include <algorithm>
#include <functional>

namespace graph_view {

struct gline {
    uint64_t addr = 0; // 0 for the label line
    std::string text;
    ImU32 col = theme::text;
};

struct gnode {
    float x = 0, y = 0, w = 0, h = 0;
    int rank = 0;
    std::vector<gline> lines;
};

// layout in "unit" coordinates (zoom 1 at the current font size)
static struct {
    const database* db = nullptr;
    uint64_t func = ~0ull;
    uint64_t version = ~0ull;
    float font = 0;
    cfg g;
    std::vector<gnode> nodes;
    float width = 0, height = 0;
    float zoom = 1.0f;
    bool center_on_cursor = true;
} L;

static void build(app_state& s, uint64_t fstart)
{
    database& db = *s.db;
    L.db = &db;
    L.func = fstart;
    L.version = s.version;
    L.font = ImGui::GetFontSize();
    L.nodes.clear();
    L.width = L.height = 0;
    if (!build_cfg(db.bin, db.an, fstart, L.g))
        return;

    const float lh = ImGui::GetTextLineHeight();
    const float pad = lh * 0.5f;
    const size_t n = L.g.blocks.size();
    L.nodes.resize(n);
    for (size_t i = 0; i < n; i++) {
        const cfg_block& b = L.g.blocks[i];
        gnode& nd = L.nodes[i];
        std::string label = db.name_at(b.start);
        if (!label.empty())
            nd.lines.push_back({0, label + ":", i == 0 ? theme::func : theme::label});
        for (uint64_t a : b.insns) {
            insn in;
            if (!db.decode(a, in))
                continue;
            std::string text = util::hex(a) + "  " + db.insn_text(in);
            std::string c = db.comment_at(a);
            if (!c.empty())
                text += "  ; " + c.substr(0, c.find('\n'));
            ImU32 col = in.kind == flow::call ? theme::call : (in.kind == flow::jump || in.kind == flow::cond) ? theme::jump :
                        (in.kind == flow::ret || in.kind == flow::stop) ? theme::ret : theme::text;
            nd.lines.push_back({a, text, col});
        }
        float w = 0;
        for (const gline& l : nd.lines)
            w = std::max(w, ImGui::CalcTextSize(l.text.c_str()).x);
        nd.w = w + pad * 2;
        nd.h = nd.lines.size() * lh + pad * 2;
    }

    // back edges: edges into a block that's still on the dfs stack
    std::vector<int> state(n, 0); // 0 new, 1 on stack, 2 done
    std::vector<std::vector<bool>> back(n);
    for (size_t i = 0; i < n; i++)
        back[i].assign(L.g.blocks[i].succ.size(), false);
    std::vector<std::pair<size_t, size_t>> stack; // node, next edge
    stack.push_back({0, 0});
    state[0] = 1;
    std::vector<size_t> topo; // post order
    while (!stack.empty()) {
        size_t v = stack.back().first;
        size_t& ei = stack.back().second;
        if (ei < L.g.blocks[v].succ.size()) {
            size_t e = ei++;
            size_t t = L.g.blocks[v].succ[e].to;
            if (state[t] == 1)
                back[v][e] = true;
            else if (state[t] == 0) {
                state[t] = 1;
                stack.push_back({t, 0});
            }
        } else {
            state[v] = 2;
            topo.push_back(v);
            stack.pop_back();
        }
    }
    // longest path ranks over forward edges, in reverse post order (a topological order)
    std::vector<int> rank(n, 0);
    for (auto it = topo.rbegin(); it != topo.rend(); ++it) {
        size_t v = *it;
        for (size_t e = 0; e < L.g.blocks[v].succ.size(); e++)
            if (!back[v][e]) {
                size_t t = L.g.blocks[v].succ[e].to;
                rank[t] = std::max(rank[t], rank[v] + 1);
            }
    }
    int max_rank = 0;
    for (size_t i = 0; i < n; i++) {
        if (state[i] == 0) // unreachable from the entry (truncated graphs)
            rank[i] = -1;
        max_rank = std::max(max_rank, rank[i]);
    }
    for (size_t i = 0; i < n; i++) {
        if (rank[i] < 0)
            rank[i] = max_rank + 1;
        L.nodes[i].rank = rank[i];
    }
    max_rank = 0;
    for (size_t i = 0; i < n; i++)
        max_rank = std::max(max_rank, rank[i]);

    // rows, top to bottom. each node goes under the average of its parents, then overlaps are pushed right
    std::vector<std::vector<size_t>> preds(n);
    for (size_t v = 0; v < n; v++)
        for (size_t e = 0; e < L.g.blocks[v].succ.size(); e++)
            if (!back[v][e])
                preds[L.g.blocks[v].succ[e].to].push_back(v);
    const float gap_x = lh * 2.0f, gap_y = lh * 3.0f;
    float y = 0;
    for (int r = 0; r <= max_rank; r++) {
        std::vector<std::pair<float, size_t>> row;
        float row_h = 0;
        for (size_t i = 0; i < n; i++) {
            if (L.nodes[i].rank != r)
                continue;
            float want = 0;
            if (preds[i].empty()) {
                want = (float)L.g.blocks[i].start; // keeps address order for roots
            } else {
                for (size_t p : preds[i])
                    want += L.nodes[p].x + L.nodes[p].w * 0.5f;
                want /= (float)preds[i].size();
            }
            row.push_back({want, i});
            row_h = std::max(row_h, L.nodes[i].h);
        }
        std::stable_sort(row.begin(), row.end(), [](const std::pair<float, size_t>& a, const std::pair<float, size_t>& b) { return a.first < b.first; });
        float right = -1e30f;
        bool roots_only = true;
        for (const auto& it : row)
            if (!preds[it.second].empty())
                roots_only = false;
        for (const auto& it : row) {
            gnode& nd = L.nodes[it.second];
            float x = roots_only ? (right < -1e29f ? 0.0f : right + gap_x) : it.first - nd.w * 0.5f;
            if (right > -1e29f)
                x = std::max(x, right + gap_x);
            nd.x = x;
            nd.y = y;
            right = x + nd.w;
        }
        y += row_h + gap_y;
    }
    float minx = 1e30f, maxx = -1e30f, maxy = 0;
    for (const gnode& nd : L.nodes) {
        minx = std::min(minx, nd.x);
        maxx = std::max(maxx, nd.x + nd.w);
        maxy = std::max(maxy, nd.y + nd.h);
    }
    float margin = lh * 2;
    for (gnode& nd : L.nodes) {
        nd.x += margin - minx;
        nd.y += margin;
    }
    L.width = maxx - minx + margin * 2 + lh * 4; // room for back edges on the right
    L.height = maxy + margin * 2;
    L.center_on_cursor = true;
}

static ImU32 edge_color(edge_kind k)
{
    switch (k) {
    case edge_kind::taken: return IM_COL32(100, 200, 120, 255);
    case edge_kind::not_taken: return IM_COL32(220, 110, 110, 255);
    case edge_kind::table: return IM_COL32(190, 140, 230, 255);
    default: return IM_COL32(110, 160, 230, 255);
    }
}

void draw(app_state& s)
{
    database& db = *s.db;
    const function* f = db.an.func_containing(s.cursor);
    if (!f) {
        ImGui::Spacing();
        ImGui::TextDisabled("the cursor isn't inside a function.");
        ImGui::TextDisabled("pick one in the functions list, or press Space to go back to the listing.");
        return;
    }
    if (L.db != &db || L.func != f->start || L.version != s.version || L.font != ImGui::GetFontSize())
        build(s, f->start);
    if (L.nodes.empty()) {
        ImGui::TextDisabled("couldn't build a graph for this function");
        return;
    }

    ImGuiIO& io = ImGui::GetIO();
    ImGuiWindowFlags wf = ImGuiWindowFlags_HorizontalScrollbar | ImGuiWindowFlags_NoNav;
    if (io.KeyCtrl)
        wf |= ImGuiWindowFlags_NoScrollWithMouse; // ctrl + wheel zooms instead
    ImGui::BeginChild("##graph", ImVec2(0, 0), ImGuiChildFlags_None, wf);
    float z = L.zoom;
    ImVec2 origin = ImGui::GetCursorScreenPos();
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImFont* font = ImGui::GetFont();
    float fs = ImGui::GetFontSize() * z;
    float lh = ImGui::GetTextLineHeight() * z;
    float pad = ImGui::GetTextLineHeight() * 0.5f * z;
    ImVec2 clip_min = ImGui::GetWindowPos(), clip_max = ImVec2(clip_min.x + ImGui::GetWindowWidth(), clip_min.y + ImGui::GetWindowHeight());
    uint64_t pc = 0;
    bool has_pc = app_pc_static(s, pc);

    auto P = [&](float x, float y) { return ImVec2(origin.x + x * z, origin.y + y * z); };

    // edges first so blocks draw over them
    for (size_t v = 0; v < L.nodes.size(); v++) {
        const gnode& a = L.nodes[v];
        const std::vector<cfg_edge>& succ = L.g.blocks[v].succ;
        for (size_t e = 0; e < succ.size(); e++) {
            const gnode& b = L.nodes[succ[e].to];
            ImU32 col = edge_color(succ[e].kind);
            float sx = a.x + a.w * (succ.size() > 1 ? (e + 1.0f) / (succ.size() + 1.0f) : 0.5f);
            float sy = a.y + a.h;
            float tx = b.x + b.w * 0.5f, ty = b.y;
            float g = ImGui::GetTextLineHeight();
            if (b.rank > a.rank) {
                float dy = (ty - sy) * 0.5f;
                dl->AddBezierCubic(P(sx, sy), P(sx, sy + dy), P(tx, ty - dy), P(tx, ty), col, 1.5f);
            } else {
                // back edge: out the bottom, around the right side, in from the top
                float rx = std::max(a.x + a.w, b.x + b.w) + g * (1.0f + (float)(v % 3));
                ImVec2 pts[6] = {P(sx, sy), P(sx, sy + g), P(rx, sy + g), P(rx, ty - g), P(tx, ty - g), P(tx, ty)};
                dl->AddPolyline(pts, 6, col, ImDrawFlags_None, 1.5f);
            }
            ImVec2 tip = P(tx, ty);
            float ah = g * 0.45f * z;
            dl->AddTriangleFilled(ImVec2(tip.x - ah * 0.6f, tip.y - ah), ImVec2(tip.x + ah * 0.6f, tip.y - ah), tip, col);
        }
    }

    int cursor_block = L.g.block_of(s.cursor);
    bool clicked_line = false;
    for (size_t i = 0; i < L.nodes.size(); i++) {
        const gnode& nd = L.nodes[i];
        ImVec2 a = P(nd.x, nd.y), b = P(nd.x + nd.w, nd.y + nd.h);
        if (b.x < clip_min.x || a.x > clip_max.x || b.y < clip_min.y || a.y > clip_max.y)
            continue;
        bool cur = (int)i == cursor_block;
        dl->AddRectFilled(a, b, IM_COL32(24, 27, 34, 255), 4.0f * z);
        dl->AddRect(a, b, cur ? IM_COL32(120, 160, 240, 255) : IM_COL32(70, 84, 110, 255), 4.0f * z, 0, cur ? 2.0f : 1.0f);
        float ly = a.y + pad;
        for (const gline& l : nd.lines) {
            if (l.addr && l.addr == s.cursor)
                dl->AddRectFilled(ImVec2(a.x + 1, ly), ImVec2(b.x - 1, ly + lh), theme::row_selected);
            if (has_pc && l.addr && l.addr == pc)
                dl->AddRectFilled(ImVec2(a.x + 1, ly), ImVec2(b.x - 1, ly + lh), theme::row_pc);
            if (l.addr && db.breakpoints.count(l.addr))
                dl->AddCircleFilled(ImVec2(a.x + pad * 0.5f, ly + lh * 0.5f), lh * 0.2f, theme::bp);
            if (fs >= 4.0f)
                dl->AddText(font, fs, ImVec2(a.x + pad, ly), l.col, l.text.c_str());
            // clicks pick the line under the mouse
            if (l.addr && ImGui::IsWindowHovered() && io.MousePos.x >= a.x && io.MousePos.x < b.x && io.MousePos.y >= ly && io.MousePos.y < ly + lh) {
                if (ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
                    s.cursor = l.addr;
                    if (s.hex_follow)
                        s.hex_addr = l.addr;
                    clicked_line = true;
                }
                if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left))
                    app_follow(s, l.addr);
                if (ImGui::IsMouseClicked(ImGuiMouseButton_Right)) {
                    s.cursor = l.addr;
                    ImGui::OpenPopup("##graph_ctx");
                }
            }
            ly += lh;
        }
    }
    if (ImGui::BeginPopup("##graph_ctx")) {
        if (ImGui::MenuItem("Follow", "Enter"))
            app_follow(s, s.cursor);
        if (ImGui::MenuItem("Rename...", "N"))
            dialogs::open(s, dialog_kind::rename, s.cursor);
        if (ImGui::MenuItem("Comment...", ";"))
            dialogs::open(s, dialog_kind::comment, s.cursor);
        if (ImGui::MenuItem("References...", "X"))
            dialogs::open(s, dialog_kind::xrefs, s.cursor);
        if (ImGui::MenuItem("Toggle breakpoint", "F2"))
            app_toggle_bp(s, s.cursor);
        ImGui::EndPopup();
    }

    // content size for the scrollbars
    ImGui::SetCursorScreenPos(origin);
    ImGui::Dummy(ImVec2(L.width * z, L.height * z));

    // pan with the right / middle mouse button or with left drag on empty space
    if (ImGui::IsWindowHovered() && !clicked_line) {
        bool drag = ImGui::IsMouseDragging(ImGuiMouseButton_Right) || ImGui::IsMouseDragging(ImGuiMouseButton_Middle) ||
                    ImGui::IsMouseDragging(ImGuiMouseButton_Left);
        if (drag) {
            ImGui::SetScrollX(ImGui::GetScrollX() - io.MouseDelta.x);
            ImGui::SetScrollY(ImGui::GetScrollY() - io.MouseDelta.y);
        }
        if (io.KeyCtrl && io.MouseWheel != 0.0f) {
            float old = L.zoom;
            L.zoom = std::min(2.5f, std::max(0.2f, L.zoom * (io.MouseWheel > 0 ? 1.15f : 1.0f / 1.15f)));
            // keep the point under the mouse still
            ImVec2 m = ImVec2(io.MousePos.x - origin.x, io.MousePos.y - origin.y);
            ImGui::SetScrollX(ImGui::GetScrollX() + m.x * (L.zoom / old - 1.0f));
            ImGui::SetScrollY(ImGui::GetScrollY() + m.y * (L.zoom / old - 1.0f));
        }
    }
    // bring the cursor's block into view after a jump or a rebuild
    if ((L.center_on_cursor || s.scroll_to_cursor) && cursor_block >= 0) {
        const gnode& nd = L.nodes[(size_t)cursor_block];
        float vw = ImGui::GetWindowWidth(), vh = ImGui::GetWindowHeight();
        ImGui::SetScrollX(std::max(0.0f, (nd.x + nd.w * 0.5f) * z - vw * 0.5f));
        ImGui::SetScrollY(std::max(0.0f, nd.y * z - vh * 0.25f));
        L.center_on_cursor = false;
        s.scroll_to_cursor = false;
    }
    if (L.g.truncated) {
        ImGui::SetCursorScreenPos(ImVec2(clip_min.x + 8, clip_min.y + 8));
        ImGui::TextColored(ImVec4(1, 0.8f, 0.4f, 1), "graph truncated (function too large)");
    }
    ImGui::EndChild();
}

}
