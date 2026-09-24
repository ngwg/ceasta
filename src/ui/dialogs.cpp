#include "ui/dialogs.h"
#include "core/util.h"
#include "imgui.h"
#include "theme.h"
#include "version.h"
#include <cstring>

namespace dialogs {

static const char* title(dialog_kind k)
{
    switch (k) {
    case dialog_kind::jump: return "Jump to address###dlg";
    case dialog_kind::rename: return "Rename###dlg";
    case dialog_kind::comment: return "Comment###dlg";
    case dialog_kind::xrefs: return "References###dlg";
    case dialog_kind::search: return "Search bytes###dlg";
    case dialog_kind::open_raw: return "Open as raw code###dlg";
    case dialog_kind::attach: return "Attach to process###dlg";
    case dialog_kind::run_args: return "Program arguments###dlg";
    case dialog_kind::about: return "About ceasta###dlg";
    case dialog_kind::shortcuts: return "Keyboard shortcuts###dlg";
    default: return "###dlg";
    }
}

void open(app_state& s, dialog_kind kind, uint64_t addr)
{
    bool needs_file = kind == dialog_kind::jump || kind == dialog_kind::rename || kind == dialog_kind::comment ||
                      kind == dialog_kind::xrefs || kind == dialog_kind::search;
    if (needs_file && !s.db)
        return;
    dialog_state& d = s.dialog;
    d = dialog_state();
    d.kind = kind;
    d.addr = addr;
    d.just_opened = true;
    if (!s.db)
        return;
    database& db = *s.db;
    if (kind == dialog_kind::rename) {
        // rename works on the item head, and on the function start when the cursor is inside one
        uint64_t head = db.an.item_head(addr);
        d.addr = head;
        std::string n = db.name_at(head);
        if (db.user_names.count(head) || !n.empty())
            snprintf(d.buf, sizeof(d.buf), "%s", n.c_str());
    } else if (kind == dialog_kind::comment) {
        d.addr = db.an.item_head(addr);
        snprintf(d.buf, sizeof(d.buf), "%s", db.comment_at(d.addr).c_str());
    } else if (kind == dialog_kind::xrefs) {
        d.addr = db.an.item_head(addr);
        auto refs = db.an.refs_to(d.addr);
        if (refs.first == refs.second) {
            const function* f = db.an.func_containing(addr);
            if (f)
                d.addr = f->start;
        }
    } else if (kind == dialog_kind::run_args) {
        snprintf(d.buf, sizeof(d.buf), "%s", s.debug_args.c_str());
    } else if (kind == dialog_kind::attach) {
        d.procs = list_processes();
    }
}

static bool ok_cancel(bool can_ok = true)
{
    ImGui::Spacing();
    ImGui::BeginDisabled(!can_ok);
    bool ok = ImGui::Button("OK", ImVec2(ImGui::GetFontSize() * 6, 0));
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button("Cancel", ImVec2(ImGui::GetFontSize() * 6, 0)))
        ImGui::CloseCurrentPopup();
    return ok;
}

static void focus_first()
{
    if (ImGui::IsWindowAppearing())
        ImGui::SetKeyboardFocusHere();
}

static void jump(app_state& s, dialog_state& d)
{
    ImGui::TextDisabled("address in hex, or any name (sub_401000, main, start, CreateFileW)");
    focus_first();
    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 28);
    bool enter = ImGui::InputText("##where", d.buf, sizeof(d.buf), ImGuiInputTextFlags_EnterReturnsTrue);
    if (!d.error.empty())
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(theme::log_error), "%s", d.error.c_str());
    if (ok_cancel() || enter) {
        uint64_t a;
        if (!s.db->resolve(d.buf, a))
            d.error = "no such address or name";
        else if (!s.db->bin.is_mapped(a))
            d.error = "that address isn't part of the file";
        else {
            app_jump(s, a);
            ImGui::CloseCurrentPopup();
        }
    }
}

static void rename(app_state& s, dialog_state& d)
{
    ImGui::Text("new name for %s", s.db->fmt_addr(d.addr).c_str());
    ImGui::TextDisabled("leave it empty to go back to the automatic name");
    focus_first();
    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 28);
    bool enter = ImGui::InputText("##name", d.buf, sizeof(d.buf), ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_AutoSelectAll);
    if (!d.error.empty())
        ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(theme::log_error), "%s", d.error.c_str());
    if (ok_cancel() || enter) {
        std::string err;
        if (s.db->set_name(d.addr, d.buf, err)) {
            app_names_changed(s);
            ImGui::CloseCurrentPopup();
        } else {
            d.error = err;
        }
    }
}

static void comment(app_state& s, dialog_state& d)
{
    ImGui::Text("comment at %s", s.db->location(d.addr).c_str());
    ImGui::TextDisabled("enter saves, ctrl+enter starts a new line. empty removes the comment");
    focus_first();
    bool save = ImGui::InputTextMultiline("##comment", d.buf, sizeof(d.buf), ImVec2(ImGui::GetFontSize() * 32, ImGui::GetTextLineHeight() * 6),
        ImGuiInputTextFlags_CtrlEnterForNewLine | ImGuiInputTextFlags_EnterReturnsTrue);
    if (ok_cancel() || save) {
        s.db->set_comment(d.addr, util::trim(d.buf));
        app_names_changed(s);
        ImGui::CloseCurrentPopup();
    }
}

static void xrefs(app_state& s, dialog_state& d)
{
    database& db = *s.db;
    auto refs = db.an.refs_to(d.addr);
    ImGui::Text("references to %s (%d)", db.location(d.addr).c_str(), (int)(refs.second - refs.first));
    static const char* const kinds[] = {"call", "jump", "read", "write", "offset"};
    ImVec2 size(ImGui::GetFontSize() * 44, ImGui::GetTextLineHeightWithSpacing() * 14);
    if (ImGui::BeginTable("##xr", 4, ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_BordersInnerV, size)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("From");
        ImGui::TableSetupColumn("Type");
        ImGui::TableSetupColumn("Where");
        ImGui::TableSetupColumn("Code", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();
        int i = 0;
        uint64_t go = 0;
        for (const xref* x = refs.first; x != refs.second && i < 10000; x++, i++) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::PushID(i);
            if (ImGui::Selectable(db.fmt_addr(x->from).c_str(), false, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick))
                go = x->from;
            ImGui::PopID();
            ImGui::TableNextColumn();
            ImGui::TextDisabled("%s", kinds[(int)x->type]);
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(db.location(x->from).c_str());
            ImGui::TableNextColumn();
            insn in;
            if ((db.an.flags_at(x->from) & fl_code) && db.decode(x->from, in))
                ImGui::TextDisabled("%s", db.insn_text(in).c_str());
        }
        ImGui::EndTable();
        if (go) {
            app_jump(s, go);
            ImGui::CloseCurrentPopup();
        }
    }
    if (ImGui::Button("Close", ImVec2(ImGui::GetFontSize() * 6, 0)))
        ImGui::CloseCurrentPopup();
}

static void search(app_state& s, dialog_state& d)
{
    ImGui::TextDisabled("hex bytes, ?? for any byte:  48 8B ?? 24 08");
    focus_first();
    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 30);
    bool enter = ImGui::InputText("##pattern", d.buf, sizeof(d.buf), ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();
    if (ImGui::Button("Search") || enter) {
        d.results = s.db->find_bytes(d.buf, 0, 2000);
        d.error = d.results.empty() ? "no matches (or the pattern isn't valid hex)" : util::fmt("%zu matches%s", d.results.size(), d.results.size() >= 2000 ? " (first 2000)" : "");
    }
    if (!d.error.empty())
        ImGui::TextDisabled("%s", d.error.c_str());
    if (!d.results.empty()) {
        ImVec2 size(ImGui::GetFontSize() * 36, ImGui::GetTextLineHeightWithSpacing() * 12);
        ImGui::BeginChild("##results", size, ImGuiChildFlags_Borders);
        ImGuiListClipper clip;
        clip.Begin((int)d.results.size());
        uint64_t go = 0;
        while (clip.Step())
            for (int i = clip.DisplayStart; i < clip.DisplayEnd; i++) {
                uint64_t a = d.results[(size_t)i];
                std::string line = s.db->fmt_addr(a) + "  " + s.db->location(a);
                ImGui::PushID(i);
                if (ImGui::Selectable(line.c_str()))
                    go = a;
                ImGui::PopID();
            }
        ImGui::EndChild();
        if (go) {
            app_jump(s, s.db->an.item_head(go));
            ImGui::CloseCurrentPopup();
        }
    }
    if (ImGui::Button("Close", ImVec2(ImGui::GetFontSize() * 6, 0)))
        ImGui::CloseCurrentPopup();
}

static void open_raw(app_state& s, dialog_state& d)
{
    ImGui::TextDisabled("for shellcode, firmware and memory dumps");
    ImGui::RadioButton("32 bit (x86)", &d.raw_arch, 0);
    ImGui::SameLine();
    ImGui::RadioButton("64 bit (x64)", &d.raw_arch, 1);
    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 14);
    ImGui::InputText("base address (hex)", d.raw_base, sizeof(d.raw_base), ImGuiInputTextFlags_CharsHexadecimal);
    if (ok_cancel()) {
        load_options o;
        o.force_raw = true;
        o.raw_arch = d.raw_arch ? bin_arch::x64 : bin_arch::x86;
        util::parse_hex(d.raw_base, o.raw_base);
        ImGui::CloseCurrentPopup();
        if (s.platform.open_file_dialog) {
            std::string path = s.platform.open_file_dialog("Open raw code");
            if (!path.empty())
                app_open(s, path, o);
        }
    }
}

static void attach(app_state& s, dialog_state& d)
{
    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 20);
    focus_first();
    ImGui::InputTextWithHint("##pfilter", "filter by name or pid", d.filter, sizeof(d.filter));
    ImGui::SameLine();
    if (ImGui::Button("Refresh"))
        d.procs = list_processes();
    ImVec2 size(ImGui::GetFontSize() * 30, ImGui::GetTextLineHeightWithSpacing() * 14);
    uint32_t pick = 0;
    if (ImGui::BeginTable("##procs", 2, ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingFixedFit, size)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("PID");
        ImGui::TableSetupColumn("Process", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();
        std::string f = util::trim(d.filter);
        for (const process_info& p : d.procs) {
            std::string pid = std::to_string(p.pid);
            if (!f.empty() && !util::icontains(p.name, f) && pid.find(f) == std::string::npos)
                continue;
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::PushID((int)p.pid);
            if (ImGui::Selectable(pid.c_str(), d.addr == p.pid, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick)) {
                d.addr = p.pid;
                if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left))
                    pick = p.pid;
            }
            ImGui::PopID();
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(p.name.c_str());
        }
        ImGui::EndTable();
    }
    if (d.procs.empty())
        ImGui::TextDisabled("no processes (attaching needs the windows build)");
    if (ok_cancel(d.addr != 0))
        pick = (uint32_t)d.addr;
    if (pick) {
        ImGui::CloseCurrentPopup();
        dbg_attach(s, pick);
    }
}

static void run_args(app_state& s, dialog_state& d)
{
    ImGui::TextDisabled("command line passed to the program when debugging starts");
    focus_first();
    ImGui::SetNextItemWidth(ImGui::GetFontSize() * 30);
    bool enter = ImGui::InputText("##args", d.buf, sizeof(d.buf), ImGuiInputTextFlags_EnterReturnsTrue);
    if (ok_cancel() || enter) {
        s.debug_args = d.buf;
        ImGui::CloseCurrentPopup();
    }
}

static void about(app_state&, dialog_state&)
{
    ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(theme::func), "ceasta %s", CEASTA_VERSION);
    ImGui::Text("disassembler + debugger with lua plugins");
    ImGui::Spacing();
    ImGui::TextDisabled("built with:");
    ImGui::BulletText("Dear ImGui %s (MIT)", IMGUI_VERSION);
    ImGui::BulletText("Capstone 5 disassembly engine (BSD)");
    ImGui::BulletText("Lua 5.4 (MIT)");
    ImGui::TextDisabled("see THIRD_PARTY_NOTICES.md for the license texts");
    ImGui::Spacing();
    if (ImGui::Button("Close", ImVec2(ImGui::GetFontSize() * 6, 0)))
        ImGui::CloseCurrentPopup();
}

static void shortcuts(app_state&, dialog_state&)
{
    static const char* const keys[][2] = {
        {"Ctrl+O", "open a file"},          {"Ctrl+S", "save names and comments"},
        {"G", "jump to address / name"},    {"Enter / double click", "follow the operand"},
        {"Esc / Alt+Left", "back"},         {"Ctrl+Enter / Alt+Right", "forward"},
        {"N", "rename"},                    {";", "comment"},
        {"X", "references to here"},        {"Space", "listing / graph"},
        {"Alt+B", "search bytes"},          {"Up / Down / PgUp / PgDn", "move in the listing"},
        {"F9", "start debugging / continue"}, {"F7", "step into"},
        {"F8", "step over"},                {"F4", "run to cursor"},
        {"F2", "toggle breakpoint"},        {"F12", "pause"},
        {"Ctrl+F2", "stop debugging"},      {"Ctrl+= / Ctrl+- / Ctrl+0", "text size"},
        {"Ctrl+wheel (graph)", "zoom"},     {"drag (graph)", "pan"},
    };
    if (ImGui::BeginTable("##keys", 2, ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingFixedFit)) {
        for (const auto& k : keys) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::TextColored(ImGui::ColorConvertU32ToFloat4(theme::call), "%s", k[0]);
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(k[1]);
        }
        ImGui::EndTable();
    }
    if (ImGui::Button("Close", ImVec2(ImGui::GetFontSize() * 6, 0)))
        ImGui::CloseCurrentPopup();
}

void draw(app_state& s)
{
    dialog_state& d = s.dialog;
    if (d.kind == dialog_kind::none)
        return;
    const char* t = title(d.kind);
    if (d.just_opened) {
        ImGui::OpenPopup(t);
        d.just_opened = false;
    }
    ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(ImVec2(vp->WorkPos.x + vp->WorkSize.x * 0.5f, vp->WorkPos.y + vp->WorkSize.y * 0.4f), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    bool open = true;
    if (!ImGui::BeginPopupModal(t, &open, ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoSavedSettings)) {
        d.kind = dialog_kind::none; // closed with esc or the x
        return;
    }
    // dialogs that need a file close themselves when the file goes away
    bool needs_file = d.kind == dialog_kind::jump || d.kind == dialog_kind::rename || d.kind == dialog_kind::comment ||
                      d.kind == dialog_kind::xrefs || d.kind == dialog_kind::search;
    if (needs_file && !s.db) {
        ImGui::CloseCurrentPopup();
    } else {
        switch (d.kind) {
        case dialog_kind::jump: jump(s, d); break;
        case dialog_kind::rename: rename(s, d); break;
        case dialog_kind::comment: comment(s, d); break;
        case dialog_kind::xrefs: xrefs(s, d); break;
        case dialog_kind::search: search(s, d); break;
        case dialog_kind::open_raw: open_raw(s, d); break;
        case dialog_kind::attach: attach(s, d); break;
        case dialog_kind::run_args: run_args(s, d); break;
        case dialog_kind::about: about(s, d); break;
        case dialog_kind::shortcuts: shortcuts(s, d); break;
        default: ImGui::CloseCurrentPopup(); break;
        }
    }
    if (ImGui::IsKeyPressed(ImGuiKey_Escape, false))
        ImGui::CloseCurrentPopup();
    ImGui::EndPopup();
}

}
