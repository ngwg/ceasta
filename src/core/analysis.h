#pragma once
#include "core/binary.h"
#include <atomic>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

// auto analysis: finds code, functions, xrefs, strings and switch tables.
// one flag byte per mapped byte, like ida.

enum : uint8_t {
    fl_code = 1,    // instruction head
    fl_tail = 2,    // inside an item, not its first byte
    fl_func = 4,    // function start
    fl_str = 8,     // string head
    fl_data = 16,   // data item head
    fl_label = 32,  // referenced from somewhere
};

enum class xref_type : uint8_t { call, jump, read, write, offset };

struct xref {
    uint64_t from = 0;
    uint64_t to = 0;
    xref_type type = xref_type::jump;
};

struct function {
    uint64_t start = 0;
    uint64_t end = 0;           // one past the highest instruction byte
    uint32_t insns = 0;
    bool thunk = false;         // body is a single jump to an import or another function
    uint64_t thunk_target = 0;
};

struct string_item {
    uint64_t addr = 0;
    uint32_t len = 0;           // bytes including the terminator
    bool wide = false;          // utf-16le
    std::string text;
};

struct jump_table {
    uint64_t jmp = 0;           // the indirect jump
    uint64_t table = 0;         // first entry
    uint32_t entry_size = 0;
    uint32_t entries = 0;
    std::vector<uint64_t> targets; // unique case targets
    std::vector<uint64_t> cases;   // target of each entry, by index
    unsigned index_reg = 0;        // capstone reg id of the switch index, 0 if unknown
};

struct insn;

struct analysis_progress {
    std::atomic<int> percent{0};
    std::atomic<bool> cancel{false};
};

struct analysis {
    std::vector<uint64_t> seg_start;               // parallel to flags
    std::vector<std::vector<uint8_t>> flags;       // one vector per binary segment
    std::vector<function> funcs;                   // sorted by start
    std::vector<xref> xto;                         // sorted by (to, from)
    std::vector<xref> xfrom;                       // sorted by (from, to)
    std::vector<string_item> strings;              // sorted by addr
    std::unordered_map<uint64_t, uint8_t> data_sizes;     // data item head -> size
    std::unordered_map<uint64_t, uint32_t> slot_import;   // import slot -> index in binary.imports
    std::unordered_map<uint64_t, uint32_t> thunk_import;  // thunk start -> index in binary.imports
    std::unordered_map<uint64_t, jump_table> tables;      // by jump address
    std::unordered_set<uint64_t> noret_calls;             // calls that never return
    // arm64 builds addresses in two steps (adrp x0, page; add x0, x0, #off). what the add, load,
    // store or branch at an address ends up using, and for an adrp, the first use of its page
    std::unordered_map<uint64_t, uint64_t> pc_refs;
    std::unordered_map<uint64_t, uint64_t> page_refs;
    uint64_t insn_count = 0;

    // fills in has_mem / mem from pc_refs, so an arm64 add or load reads like x86's [rip + x]
    void resolve(insn& in) const;

    uint8_t flags_at(uint64_t a) const;
    void add_flags(uint64_t a, uint8_t f);
    void clear_flags(uint64_t a, uint8_t f);
    bool mapped(uint64_t a) const { return seg_index(a) >= 0; }
    // size of the item starting at a (head + tail bytes), 1 for unknown bytes
    uint32_t item_size(uint64_t a) const;
    // head of the item that contains a
    uint64_t item_head(uint64_t a) const;

    const function* func_at(uint64_t start) const;
    const function* func_containing(uint64_t a) const;
    std::pair<const xref*, const xref*> refs_to(uint64_t a) const;
    std::pair<const xref*, const xref*> refs_from(uint64_t a) const;
    const string_item* string_at(uint64_t a) const;
    int seg_index(uint64_t a) const;
};

// runs the full analysis. progress may be null. returns false if cancelled
bool analyze(const binary& b, analysis& out, analysis_progress* progress = nullptr);

// control flow graph of one function, built on demand for the graph view

enum class edge_kind : uint8_t { next, taken, not_taken, jump, table };

struct cfg_edge {
    uint32_t to = 0;
    edge_kind kind = edge_kind::next;
};

struct cfg_block {
    uint64_t start = 0;
    uint64_t end = 0;
    std::vector<uint64_t> insns;
    std::vector<cfg_edge> succ;
};

struct cfg {
    uint64_t func = 0;
    std::vector<cfg_block> blocks;  // blocks[0] is the entry
    bool truncated = false;
    int block_of(uint64_t a) const;
};

bool build_cfg(const binary& b, const analysis& a, uint64_t func_start, cfg& out, size_t max_blocks = 1500);

bool is_noreturn_name(const std::string& name);

// a slot of the got (.got, __got, __auth_got) that holds the address of code in the file, not an
// import: rust and -fno-plt code call other crates' functions through these (call [rip + slot]).
// v is the function it points at
bool got_target(const binary& b, const analysis& an, uint64_t slot, uint64_t& v);
