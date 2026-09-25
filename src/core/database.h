#pragma once
#include "core/analysis.h"
#include "core/binary.h"
#include "core/disasm.h"
#include <map>
#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

// a loaded file + its analysis + everything the user added (names, comments, breakpoints).
// built on a worker thread, then only touched from the main thread.

enum class row_kind : uint8_t { seg, blank, func, label, code, string, data, unknown };

struct row {
    uint64_t addr = 0;
    uint32_t size = 0;
    row_kind kind = row_kind::blank;
};

enum line_style : uint8_t {
    ls_normal,
    ls_jump,
    ls_call,
    ls_ret,
    ls_nop,
    ls_data,
    ls_string,
    ls_label,
    ls_func,
    ls_segment,
    ls_unknown,
};

// one formatted listing line
struct line_text {
    std::string addr;
    std::string bytes;
    std::string text;
    std::string comment;       // user comment
    std::string auto_comment;  // string literals, switch info, ...
    uint64_t target = 0;       // where following this line goes (0 = nowhere)
    line_style style = ls_normal;
};

struct load_options {
    bool force_raw = false;
    bin_arch raw_arch = bin_arch::x64;
    uint64_t raw_base = 0;
    std::string project; // a project file to read names / comments from (and save to)
};

class database {
public:
    binary bin;
    analysis an;
    std::map<uint64_t, std::string> user_names;
    std::map<uint64_t, std::string> user_comments;
    std::set<uint64_t> breakpoints; // static addresses
    std::vector<xref> extra_xrefs;  // learned at runtime (indirect call / jump targets)
    uint32_t crc = 0;

    // record a cross-reference the static analysis couldn't see (an indirect branch resolved
    // while debugging). merges into refs_to / refs_from and the listing. returns false if it
    // already existed or an address isn't in the file.
    bool add_xref(uint64_t from, uint64_t to, xref_type type);

    // call once after bin + an are filled
    void build();

    std::string name_at(uint64_t a) const;      // "" when the address has no name
    std::string location(uint64_t a) const;     // name, or func+off, or plain address
    bool set_name(uint64_t a, const std::string& name, std::string& err);
    std::string comment_at(uint64_t a) const;
    void set_comment(uint64_t a, const std::string& text);
    // accepts hex ("401000", "0x401000") or any name
    bool resolve(const std::string& text, uint64_t& out) const;
    std::string fmt_addr(uint64_t a) const;
    std::string seg_name(uint64_t a) const;
    bool uninit(uint64_t a) const; // past the initialized bytes of its segment (.bss)

    const std::vector<row>& rows();
    size_t row_of(uint64_t a);                  // row of the item holding a
    void format(const row& r, line_text& out);
    // instruction text with names in place of addresses
    std::string insn_text(const insn& in) const;
    bool decode(uint64_t a, insn& out) const { return dis_.decode(bin, a, out); }
    const char* reg_name(unsigned reg) const { return dis_.reg_name(reg); }

    // "48 8b ?? 05" style patterns
    std::vector<uint64_t> find_bytes(const std::string& pattern, uint64_t from, size_t max_results) const;

    std::string db_path() const;
    std::string project_file;                      // the project / database this session saves to
    bool project_has_program = false;              // it carries a copy of the program (like an ida .i64)
    std::string project_path() const;              // project_file, else "<binary>.ceasta" next to the file
    std::string annotations_path() const;          // what loading reads: the project if it exists, else db_path
    // the annotations file text (sorted, diffable); with_program appends the program's bytes
    std::string serialize(bool with_program = false) const;
    // the private copy in the user folder, and the project file when there is one
    bool save(std::string& err) const;
    bool save_project(std::string& err) const;     // write the project file (creating it)
    bool write_annotations(const std::string& path, std::string& err, bool with_program = false) const;
    bool load_annotations(std::string& err);
    bool dirty = false; // unsaved user changes
    // where you were, kept in the project (the app sets them before saving, reads them after loading)
    uint64_t saved_cursor = 0;
    int saved_view = 0;

    // bookmarks: address -> a note (may be empty)
    std::map<uint64_t, std::string> bookmarks;
    void set_bookmark(uint64_t a, bool on, const std::string& note = std::string());

    // undo / redo of your edits: names, comments, bookmarks. edits in the same group (the app
    // uses one per frame, so a plugin or the ai renaming many things is one step) go together
    enum class edit_kind : uint8_t { name, comment, bookmark };
    struct edit {
        edit_kind kind;
        uint64_t addr;
        std::string before, after; // "" = nothing there
        uint64_t group;
    };
    bool record_edits = false; // on once the file is loaded, so loading isn't an edit
    uint64_t edit_group = 0;
    bool can_undo() const { return !undo_log_.empty(); }
    bool can_redo() const { return !redo_log_.empty(); }
    std::string undo(); // what it undid, "" when there was nothing
    std::string redo();

private:
    void record(edit_kind k, uint64_t a, const std::string& before, const std::string& after);
    std::string apply(const edit& e, bool forward);
    std::vector<edit> undo_log_, redo_log_;
    bool applying_ = false;

    std::string auto_name(uint64_t a) const;
    void build_names();
    void build_rows();
    void claim_name(uint64_t a, const std::string& base);
    std::string item_text(uint64_t a, uint32_t size, line_text& out) const;

    std::vector<row> rows_;
    bool rows_dirty_ = true;
    std::unordered_map<uint64_t, std::string> names_;   // symbols, imports, exports, strings, thunks
    std::unordered_map<std::string, uint64_t> by_name_;
    mutable disassembler dis_;
    int digits_ = 8;
};

// load + analyze, safe to run on a worker thread
std::unique_ptr<database> open_database(const std::string& path, const load_options& opts,
    analysis_progress* progress, std::string& err);

// true for a ceasta project file name ("*.ceasta")
bool is_project_file(const std::string& path);

// what a project / database file says about the program it belongs to
struct project_info {
    std::string name;          // the program's file name
    uint32_t crc = 0;          // of the program, when recorded
    bool has_crc = false;
    bool has_program = false;  // a copy of the program is inside
    load_options opts;         // raw loads keep their arch and base
};
bool read_project_info(const std::string& project, project_info& out, std::string& err);

// the program to open for a project: the file next to it ("<x>.ceasta" -> "<x>") or the recorded
// name in the same folder, when its crc matches; else the copy inside the project, written out to
// the user folder. "" when there's none. note says what was picked when it isn't the obvious file.
std::string project_program(const std::string& project, const project_info& info, std::string& note);

// open_database for a path the user gave: a .ceasta project / database opens its program (see
// project_program) with the project's annotations. note, when set, says which copy was used.
std::unique_ptr<database> open_any(const std::string& path, load_options opts, analysis_progress* progress,
    std::string& err, std::string* note = nullptr);
