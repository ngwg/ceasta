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
};

class database {
public:
    binary bin;
    analysis an;
    std::map<uint64_t, std::string> user_names;
    std::map<uint64_t, std::string> user_comments;
    std::set<uint64_t> breakpoints; // static addresses
    uint32_t crc = 0;

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
    bool save(std::string& err) const;
    bool load_annotations(std::string& err);
    bool dirty = false; // unsaved user changes

private:
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
