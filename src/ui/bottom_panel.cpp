#include "ui/bottom_panel.h"
#include "core/dbg_stack.h"
#include "core/util.h"
#include "imgui.h"
#include "theme.h"
#include "ui/dialogs.h"
#include <algorithm>
#include <cstring>

namespace bottom_panel {

static int history_cb(ImGuiInputTextCallbackData* data)
{
    app_state& s = *(app_state*)data->UserData;
    if (data->EventFlag != ImGuiInputTextFlags_CallbackHistory || s.console_history.empty())
        return 0;
    int n = (int)s.console_history.size();
    if (data->EventKey == ImGuiKey_UpArrow)
        s.history_pos = s.history_pos < 0 ? n - 1 : std::max(0, s.history_pos - 1);
    else if (data->EventKey == ImGuiKey_DownArrow)
        s.history_pos = s.history_pos < 0 ? -1 : (s.history_pos + 1 >= n ? -1 : s.history_pos + 1);
    data->DeleteChars(0, data->BufTextLen);
    if (s.history_pos >= 0)
        data->InsertChars(0, s.console_history[(size_t)s.history_pos].c_str());
    return 0;
}

static void output(app_state& s)
{
    float input_h = ImGui::GetFrameHeightWithSpacing();
    ImGui::BeginChild("##log", ImVec2(0, -input_h), ImGuiChildFlags_None, ImGuiWindowFlags_HorizontalScrollbar);
    ImGuiListClipper clip;
    clip.Begin((int)s.log.size());
    while (clip.Step())
        for (int i = clip.DisplayStart; i < clip.DisplayEnd; i++) {
            const log_line& l = s.log[(size_t)i];
            ImGui::PushStyleColor(ImGuiCol_Text, ImGui::ColorConvertU32ToFloat4(theme::log_color(l.level)));
            ImGui::TextUnformatted(l.text.c_str());
            ImGui::PopStyleColor();
        }
    if (s.log_to_bottom) {
        ImGui::SetScrollHereY(1.0f);
        s.log_to_bottom = false;
    }
    if (ImGui::BeginPopupContextWindow("##log_ctx")) {
        if (ImGui::MenuItem("Copy all")) {
            std::string all;
            for (const log_line& l : s.log)
                all += l.text + "\n";
            ImGui::SetClipboardText(all.c_str());
        }
        if (ImGui::MenuItem("Clear"))
            s.log.clear();
        ImGui::EndPopup();
    }
    ImGui::EndChild();

    ImGui::AlignTextToFramePadding();
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(theme::log_echo), "Lua>");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(-ImGui::CalcTextSize("Clear").x - ImGui::GetStyle().FramePadding.x * 2 - ImGui::GetStyle().ItemSpacing.x);
    if (s.focus_console) {
        ImGui::SetKeyboardFocusHere();
        s.focus_console = false;
    }
    ImGuiInputTextFlags fl = ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_CallbackHistory;
    if (ImGui::InputTextWithHint("##console", "type lua and press enter, e.g.  ceasta.name(ceasta.here())", s.console,
            sizeof(s.console), fl, history_cb, &s)) {
        std::string code = util::trim(s.console);
        if (!code.empty()) {
            app_log(s, "> " + code, 3);
            s.console_history.push_back(code);
            if (s.console_history.size() > 200)
                s.console_history.erase(s.console_history.begin());
            s.history_pos = -1;
            s.lua.run_console(code);
            app_names_changed(s);
        }
        s.console[0] = '\0';
        ImGui::SetKeyboardFocusHere(-1);
    }
    ImGui::SameLine();
    if (ImGui::Button("Clear"))
        s.log.clear();
}

// the memory map of this stop (read once per stop)
static const std::vector<dbg_region>& regions(app_state& s)
{
    static std::vector<dbg_region> cache;
    static uint64_t seq = ~0ull;
    static uint32_t pid = 0;
    if (seq != s.stop_seq || pid != s.dbg.pid()) {
        cache = s.dbg.state() == dbg_state::stopped ? s.dbg.regions() : std::vector<dbg_region>();
        seq = s.stop_seq;
        pid = s.dbg.pid();
    }
    return cache;
}

static const dbg_region* region_at(app_state& s, uint64_t a)
{
    for (const dbg_region& r : regions(s))
        if (a >= r.base && a - r.base < r.size)
            return &r;
    return nullptr;
}

static std::string base_name(const std::string& p)
{
    size_t at = p.find_last_of("/\\");
    return at == std::string::npos || p.empty() || p[0] == '[' ? p : p.substr(at + 1);
}

// the hex view on the process's memory: the heap, a stack, a library's data
static void process_hex(app_state& s)
{
    if (ImGui::SmallButton("Back to the file"))
        s.hex_process = false;
    if (s.dbg.state() != dbg_state::stopped) {
        ImGui::SameLine();
        ImGui::TextDisabled(s.dbg.state() == dbg_state::none ? "the program has ended" : "running - pause it to read its memory");
        return;
    }
    const dbg_region* reg = region_at(s, s.hex_rt);
    ImGui::SameLine();
    if (!reg) {
        ImGui::TextDisabled("%s isn't mapped in the process", util::hex(s.hex_rt).c_str());
        return;
    }
    ImGui::TextDisabled("process memory  %s  %s - %s  %s", reg->what.empty() ? "(anonymous)" : base_name(reg->what).c_str(),
        util::hex(reg->base).c_str(), util::hex(reg->base + reg->size).c_str(), reg->perms.c_str());
    // a window of 2 MB around the address: regions can be huge
    uint64_t lo = std::max(reg->base, s.hex_rt > (1u << 20) ? s.hex_rt - (1u << 20) : 0) & ~15ull;
    uint64_t hi = std::min(reg->base + reg->size, s.hex_rt + (1u << 20));
    uint64_t rows = (hi - lo + 15) / 16;
    float cw = ImGui::CalcTextSize("0").x;
    float lh = ImGui::GetTextLineHeightWithSpacing();
    float pitch = lh + ImGui::GetStyle().ItemSpacing.y;
    ImGui::BeginChild("##phex", ImVec2(0, 0), ImGuiChildFlags_None, ImGuiWindowFlags_NoNav);
    ImDrawList* dl = ImGui::GetWindowDrawList();
    int target_row = (int)((s.hex_rt - lo) / 16);
    static uint64_t last_scrolled = ~0ull;
    ImGuiListClipper clip;
    clip.Begin((int)rows, pitch);
    if (last_scrolled != s.hex_rt)
        clip.IncludeItemByIndex(target_row);
    while (clip.Step()) {
        for (int r = clip.DisplayStart; r < clip.DisplayEnd; r++) {
            uint64_t a = lo + (uint64_t)r * 16;
            if (r == target_row && last_scrolled != s.hex_rt) {
                ImGui::SetScrollHereY(0.3f);
                last_scrolled = s.hex_rt;
            }
            uint8_t buf[16] = {};
            size_t got = s.dbg.read(a, buf, 16);
            ImVec2 p = ImGui::GetCursorScreenPos();
            std::string addr = util::hex(a);
            dl->AddText(p, theme::addr, addr.c_str());
            float hx = p.x + cw * (float)(addr.size() + 2);
            float ax = hx + cw * 50;
            for (int i = 0; i < 16; i++) {
                float x = hx + cw * (float)(i * 3 + (i >= 8 ? 1 : 0));
                if (a + (uint64_t)i == s.hex_rt) {
                    dl->AddRectFilled(ImVec2(x - 1, p.y), ImVec2(x + cw * 2 + 1, p.y + lh - 1), theme::row_selected);
                    dl->AddRectFilled(ImVec2(ax + cw * i, p.y), ImVec2(ax + cw * (i + 1), p.y + lh - 1), theme::row_selected);
                }
                if ((size_t)i >= got) {
                    dl->AddText(ImVec2(x, p.y), theme::nop, "..");
                    continue;
                }
                char hx2[3];
                snprintf(hx2, sizeof(hx2), "%02X", buf[i]);
                dl->AddText(ImVec2(x, p.y), buf[i] ? theme::text : theme::nop, hx2);
                char c[2] = {(buf[i] >= 32 && buf[i] < 127) ? (char)buf[i] : '.', 0};
                dl->AddText(ImVec2(ax + cw * i, p.y), theme::string, c);
            }
            ImGui::PushID(r);
            ImGui::InvisibleButton("##prow", ImVec2(std::max(ax + cw * 17 - p.x, 1.0f), lh));
            if (ImGui::IsItemClicked() || ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
                float mx = ImGui::GetIO().MousePos.x;
                int col = -1;
                if (mx >= hx && mx < hx + cw * 48)
                    col = std::min(15, (int)((mx - hx) / (cw * 3)));
                else if (mx >= ax && mx < ax + cw * 16)
                    col = (int)((mx - ax) / cw);
                if (col >= 0) {
                    s.hex_rt = a + (uint64_t)col;
                    last_scrolled = s.hex_rt; // it's on screen already
                }
            }
            if (ImGui::BeginPopupContextItem("##phex_ctx")) {
                if (ImGui::MenuItem("Watch (stop when it's written)..."))
                    dialogs::open(s, dialog_kind::watch, s.hex_rt);
                if (ImGui::MenuItem("Copy address"))
                    ImGui::SetClipboardText(util::hex(s.hex_rt).c_str());
                ImGui::EndPopup();
            }
            ImGui::PopID();
        }
    }
    ImGui::EndChild();
}

static void hex(app_state& s)
{
    if (!s.db) {
        ImGui::TextDisabled("no file loaded");
        return;
    }
    if (s.hex_process) {
        process_hex(s);
        return;
    }
    database& db = *s.db;
    ImGui::Checkbox("follow cursor", &s.hex_follow);
    ImGui::SameLine();
    bool live_ok = s.dbg.state() == dbg_state::stopped && s.dbg_mapped;
    ImGui::BeginDisabled(!live_ok);
    ImGui::Checkbox("live memory", &s.hex_live);
    ImGui::EndDisabled();
    ImGui::SetItemTooltip("show the debugged process's memory instead of the file");
    bool live = live_ok && s.hex_live;

    const segment* seg = db.bin.seg_at(s.hex_addr);
    if (!seg)
        seg = db.bin.seg_at(s.cursor);
    if (!seg) {
        ImGui::TextDisabled("nothing mapped here");
        return;
    }
    ImGui::SameLine();
    ImGui::TextDisabled("%s  %s - %s", seg->name.c_str(), db.fmt_addr(seg->start).c_str(), db.fmt_addr(seg->end).c_str());

    uint64_t first = seg->start & ~15ull;
    uint64_t rows = (seg->end - first + 15) / 16;
    uint64_t sel = s.hex_addr;
    uint32_t sel_len = std::max<uint32_t>(1, db.an.item_size(db.an.item_head(sel)));
    uint64_t sel_head = db.an.item_head(sel);
    float cw = ImGui::CalcTextSize("0").x;
    float lh = ImGui::GetTextLineHeightWithSpacing();

    ImGui::BeginChild("##hex", ImVec2(0, 0), ImGuiChildFlags_None, ImGuiWindowFlags_NoNav);
    ImDrawList* dl = ImGui::GetWindowDrawList();
    int target_row = (int)((sel_head - first) / 16);
    float pitch = lh + ImGui::GetStyle().ItemSpacing.y; // a row and the spacing after it
    ImGuiListClipper clip;
    clip.Begin((int)std::min<uint64_t>(rows, 0x7fffffff), pitch);
    if (s.hex_follow)
        clip.IncludeItemByIndex(target_row);
    static uint64_t last_scrolled = ~0ull;
    while (clip.Step()) {
        for (int r = clip.DisplayStart; r < clip.DisplayEnd; r++) {
            uint64_t a = first + (uint64_t)r * 16;
            if (r == target_row && last_scrolled != sel_head) {
                float y = r * pitch;
                if (y < ImGui::GetScrollY() || y + lh > ImGui::GetScrollY() + ImGui::GetWindowHeight())
                    ImGui::SetScrollHereY(0.4f);
                last_scrolled = sel_head;
            }
            uint8_t buf[16] = {};
            bool have[16] = {};
            if (live) {
                size_t got = s.dbg.read(app_to_runtime(s, a), buf, 16);
                for (size_t i = 0; i < 16; i++)
                    have[i] = i < got && seg->contains(a + i);
            } else {
                for (int i = 0; i < 16; i++)
                    have[i] = seg->contains(a + (uint64_t)i) && db.bin.read_u8(a + (uint64_t)i, buf[i]);
            }
            ImVec2 p = ImGui::GetCursorScreenPos();
            std::string addr = db.fmt_addr(a);
            dl->AddText(p, theme::addr, addr.c_str());
            float hx = p.x + cw * (float)(addr.size() + 2);
            float ax = hx + cw * 50;
            for (int i = 0; i < 16; i++) {
                float x = hx + cw * (float)(i * 3 + (i >= 8 ? 1 : 0));
                uint64_t ba = a + (uint64_t)i;
                bool in_sel = ba >= sel_head && ba < sel_head + sel_len;
                if (in_sel) {
                    dl->AddRectFilled(ImVec2(x - 1, p.y), ImVec2(x + cw * 2 + 1, p.y + lh - 1), theme::row_selected);
                    dl->AddRectFilled(ImVec2(ax + cw * i, p.y), ImVec2(ax + cw * (i + 1), p.y + lh - 1), theme::row_selected);
                }
                if (!have[i]) {
                    dl->AddText(ImVec2(x, p.y), theme::nop, "..");
                    continue;
                }
                char hx2[3];
                snprintf(hx2, sizeof(hx2), "%02X", buf[i]);
                dl->AddText(ImVec2(x, p.y), buf[i] ? theme::text : theme::nop, hx2);
                char c[2] = {(buf[i] >= 32 && buf[i] < 127) ? (char)buf[i] : '.', 0};
                dl->AddText(ImVec2(ax + cw * i, p.y), theme::string, c);
            }
            // clicks select the byte under the mouse, a right click also offers a watch on it
            ImGui::PushID(r);
            ImGui::InvisibleButton("##hexrow", ImVec2(std::max(ax + cw * 17 - p.x, 1.0f), lh));
            if (ImGui::IsItemClicked() || ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
                float mx = ImGui::GetIO().MousePos.x;
                int col = -1;
                if (mx >= hx && mx < hx + cw * 48)
                    col = std::min(15, (int)((mx - hx) / (cw * 3)));
                else if (mx >= ax && mx < ax + cw * 16)
                    col = (int)((mx - ax) / cw);
                if (col >= 0 && seg->contains(a + (uint64_t)col)) {
                    s.hex_addr = a + (uint64_t)col;
                    bool follow = s.hex_follow;
                    s.hex_follow = false; // don't bounce back to the listing cursor
                    app_jump(s, db.an.item_head(s.hex_addr));
                    s.hex_follow = follow;
                }
            }
            if (ImGui::BeginPopupContextItem("##hex_ctx")) {
                if (ImGui::MenuItem("Watch (stop when it's written)...", nullptr, false, s.dbg.state() != dbg_state::none))
                    dialogs::open(s, dialog_kind::watch, s.hex_addr);
                if (ImGui::MenuItem("Copy address"))
                    ImGui::SetClipboardText(db.fmt_addr(s.hex_addr).c_str());
                ImGui::EndPopup();
            }
            ImGui::PopID();
        }
    }
    ImGui::EndChild();
}

// the watchpoints of this run, above the breakpoints
static void watches(app_state& s)
{
    std::vector<debugger::watch> ws = s.dbg.watches();
    if (ws.empty())
        return;
    uint64_t remove = 0;
    bool none = false;
    if (ImGui::BeginTable("##watches", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_BordersInnerV)) {
        ImGui::TableSetupColumn("Watching");
        ImGui::TableSetupColumn("Bytes");
        ImGui::TableSetupColumn("Stops when", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();
        int i = 0;
        for (const debugger::watch& w : ws) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::PushID(i++);
            uint64_t st = 0;
            bool here = app_to_static(s, w.addr, st);
            if (ImGui::Selectable(app_where_runtime(s, w.addr).c_str(), false, ImGuiSelectableFlags_SpanAllColumns) && here)
                app_jump(s, st);
            if (ImGui::BeginPopupContextItem("##w_ctx")) {
                if (ImGui::MenuItem("Remove"))
                    remove = w.addr;
                if (ImGui::MenuItem("Remove all watches"))
                    none = true;
                ImGui::EndPopup();
            }
            ImGui::SetItemTooltip("%s  (right-click to remove)", util::hex(w.addr).c_str());
            ImGui::PopID();
            ImGui::TableNextColumn();
            ImGui::Text("%d", w.size);
            ImGui::TableNextColumn();
            uint64_t v = 0;
            bool have = s.dbg.state() == dbg_state::stopped && s.dbg.read(w.addr, &v, (size_t)w.size) == (size_t)w.size;
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(theme::call), "%s", w.access ? "read or written" : "written");
            if (have) {
                ImGui::SameLine();
                ImGui::TextDisabled("(now %s)", util::hex(v).c_str());
            }
        }
        ImGui::EndTable();
    }
    if (remove)
        app_del_watch(s, remove);
    if (none)
        for (const debugger::watch& w : ws)
            app_del_watch(s, w.addr);
    ImGui::Spacing();
}

static void breakpoints(app_state& s)
{
    if (!s.db) {
        ImGui::TextDisabled("no file loaded");
        return;
    }
    database& db = *s.db;
    watches(s);
    if (db.breakpoints.empty()) {
        ImGui::TextDisabled(s.dbg.watches().empty() ? "no breakpoints. select a line and press F2 (on a variable, F2 watches it)."
                                                    : "no breakpoints. select a line and press F2.");
        return;
    }
    uint64_t remove = 0;
    bool clear = ImGui::Button("Remove all");
    if (ImGui::BeginTable("##bps", 4, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_BordersInnerV)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Address");
        ImGui::TableSetupColumn("Where");
        ImGui::TableSetupColumn("Instruction", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Stops when", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();
        int i = 0;
        for (uint64_t a : db.breakpoints) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::PushID(i++);
            if (ImGui::Selectable(db.fmt_addr(a).c_str(), false, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick)) {
                app_jump(s, a);
                if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left))
                    dialogs::open(s, dialog_kind::bp_condition, a);
            }
            if (ImGui::BeginPopupContextItem("##bp_ctx")) {
                if (ImGui::MenuItem("Condition...", "Shift+F2"))
                    dialogs::open(s, dialog_kind::bp_condition, a);
                if (ImGui::MenuItem("Remove"))
                    remove = a;
                ImGui::EndPopup();
            }
            ImGui::PopID();
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(db.location(a).c_str());
            ImGui::TableNextColumn();
            insn in;
            if (db.decode(a, in))
                ImGui::TextDisabled("%s", db.insn_text(in).c_str());
            ImGui::TableNextColumn();
            auto c = db.bp_conditions.find(a);
            if (c != db.bp_conditions.end()) {
                auto h = s.bp_hits.find(a);
                ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(theme::call), "%s", c->second.c_str());
                if (h != s.bp_hits.end()) {
                    ImGui::SameLine();
                    ImGui::TextDisabled("(%d hits)", h->second);
                }
            } else {
                ImGui::TextDisabled("always");
            }
        }
        ImGui::EndTable();
    }
    if (remove)
        app_toggle_bp(s, remove);
    if (clear) {
        std::vector<uint64_t> all(db.breakpoints.begin(), db.breakpoints.end());
        for (uint64_t a : all)
            app_toggle_bp(s, a);
    }
}

static bool need_stop(app_state& s)
{
    if (s.dbg.state() == dbg_state::stopped)
        return true;
    ImGui::TextDisabled(s.dbg.state() == dbg_state::running ? "running - pause it (F12) to look" : "not debugging");
    return false;
}

// how the program got here: a click shows the frame in the listing (the call that made it)
static void call_stack(app_state& s)
{
    if (!need_stop(s))
        return;
    static std::vector<stack_frame> frames;
    static uint64_t seq = ~0ull;
    if (seq != s.stop_seq) {
        frames = dbg_call_stack(s.dbg, 64, [&s](uint64_t a) { return app_func_start_runtime(s, a); });
        seq = s.stop_seq;
    }
    if (!ImGui::BeginTable("##calls", 4, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_BordersInnerV))
        return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("#");
    ImGui::TableSetupColumn("Function");
    ImGui::TableSetupColumn("Returns to");
    ImGui::TableSetupColumn("Stack slot", ImGuiTableColumnFlags_WidthStretch);
    ImGui::TableHeadersRow();
    for (size_t i = 0; i < frames.size(); i++) {
        const stack_frame& f = frames[i];
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        ImGui::PushID((int)i);
        uint64_t show = i ? f.call : f.pc, st = 0;
        bool in_file = app_to_static(s, show, st);
        if (ImGui::Selectable(util::fmt("%zu", i).c_str(), false, ImGuiSelectableFlags_SpanAllColumns) && in_file)
            app_jump(s, st);
        if (ImGui::BeginPopupContextItem("##cs_ctx")) {
            if (ImGui::MenuItem("Show in the listing", nullptr, false, in_file))
                app_jump(s, st);
            if (ImGui::MenuItem("Show the stack slot in hex", nullptr, false, f.slot != 0))
                app_show_memory(s, f.slot);
            if (ImGui::MenuItem("Copy address"))
                ImGui::SetClipboardText(util::hex(f.pc).c_str());
            ImGui::EndPopup();
        }
        ImGui::PopID();
        ImGui::TableNextColumn();
        std::string w = app_where_runtime(s, i ? f.call : f.pc);
        if (in_file)
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(theme::func), "%s", w.c_str());
        else
            ImGui::TextUnformatted(w.c_str());
        ImGui::TableNextColumn();
        ImGui::TextDisabled("%s", i ? util::hex(f.pc).c_str() : "(here)");
        ImGui::TableNextColumn();
        ImGui::TextDisabled("%s", f.slot ? util::hex(f.slot).c_str() : "");
    }
    ImGui::EndTable();
}

// the process's memory: what's mapped where. a click shows it (the listing for the file, the
// hex view for the rest)
static void memory_map(app_state& s)
{
    if (!need_stop(s))
        return;
    static char filter[64] = {};
    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 16);
    ImGui::InputTextWithHint("##mfilter", "filter: libc, heap, stack, rwx...", filter, sizeof(filter));
    std::string f = util::lower(util::trim(filter));
    const std::vector<dbg_region>& regs = regions(s);
    ImGui::SameLine();
    ImGui::TextDisabled("%zu regions", regs.size());
    if (!ImGui::BeginTable("##maps", 4, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_BordersInnerV))
        return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("Address");
    ImGui::TableSetupColumn("Size");
    ImGui::TableSetupColumn("Access");
    ImGui::TableSetupColumn("What", ImGuiTableColumnFlags_WidthStretch);
    ImGui::TableHeadersRow();
    uint64_t pc = s.dbg.pc(), sp = s.dbg.sp();
    int i = 0;
    for (const dbg_region& r : regs) {
        std::string what = r.what.empty() ? std::string() : base_name(r.what);
        bool has_pc = pc >= r.base && pc - r.base < r.size, has_sp = sp >= r.base && sp - r.base < r.size;
        if (!f.empty() && util::lower(what + " " + r.perms + " " + r.what).find(f) == std::string::npos)
            continue;
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        ImGui::PushID(i++);
        if (ImGui::Selectable(util::hex(r.base).c_str(), false, ImGuiSelectableFlags_SpanAllColumns))
            app_show_memory(s, r.base);
        if (ImGui::BeginPopupContextItem("##map_ctx")) {
            if (ImGui::MenuItem("Show in hex"))
                app_show_memory(s, r.base);
            if (ImGui::MenuItem("Copy address"))
                ImGui::SetClipboardText(util::hex(r.base).c_str());
            ImGui::EndPopup();
        }
        if (!r.what.empty())
            ImGui::SetItemTooltip("%s", r.what.c_str());
        ImGui::PopID();
        ImGui::TableNextColumn();
        ImGui::TextDisabled("%s", util::hex(r.size).c_str());
        ImGui::TableNextColumn();
        bool x = r.perms.size() == 3 && r.perms[2] == 'x', w = r.perms.size() == 3 && r.perms[1] == 'w';
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(x && w ? theme::log_error : x ? theme::func : theme::text), "%s", r.perms.c_str());
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(what.c_str());
        if (has_pc || has_sp) {
            ImGui::SameLine();
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(theme::pc_arrow), "%s", has_pc && has_sp ? "(pc, sp)" : has_pc ? "(pc)" : "(sp)");
        }
    }
    ImGui::EndTable();
}

void draw(app_state& s)
{
    if (ImGui::BeginTabBar("##bottom_tabs")) {
        auto tab = [&](const char* label, int index) {
            ImGuiTabItemFlags fl = s.bottom_tab_request == index ? ImGuiTabItemFlags_SetSelected : 0;
            return ImGui::BeginTabItem(label, nullptr, fl);
        };
        if (tab("Output", 0)) {
            output(s);
            ImGui::EndTabItem();
        }
        if (tab("Hex", 1)) {
            hex(s);
            ImGui::EndTabItem();
        }
        size_t n_bps = (s.db ? s.db->breakpoints.size() : 0) + s.dbg.watches().size();
        std::string bp_label = util::fmt("Breakpoints (%zu)###bps", n_bps);
        if (tab(bp_label.c_str(), 2)) {
            breakpoints(s);
            ImGui::EndTabItem();
        }
        // while debugging: how it got here, and what's in memory
        if (s.dbg.state() != dbg_state::none) {
            if (tab("Call stack", 3)) {
                call_stack(s);
                ImGui::EndTabItem();
            }
            if (tab("Memory", 4)) {
                memory_map(s);
                ImGui::EndTabItem();
            }
        }
        ImGui::EndTabBar();
    }
    s.bottom_tab_request = -1;
}

}
