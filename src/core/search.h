#pragma once
#include <cstdint>
#include <string>
#include <vector>

class database;

// "search everything": one text query over functions, names, imports, exports, strings,
// comments and segments. used by the gui's search dialog (ctrl+f) and `ceasta-cli search`.

enum class hit_kind : uint8_t { address, function, name, import, export_, string, comment, segment };

struct search_hit {
    hit_kind kind = hit_kind::address;
    uint64_t addr = 0;   // 0 for a forwarded export (nothing to jump to)
    std::string text;    // what matched, ready to show
    std::string extra;   // the library of an import, where a comment sits, ...
};

// which kinds to look in
enum : unsigned {
    sk_functions = 1u << 0,
    sk_names = 1u << 1,     // named items that aren't function starts (renamed, or the file's data symbols)
    sk_imports = 1u << 2,
    sk_exports = 1u << 3,
    sk_strings = 1u << 4,
    sk_comments = 1u << 5,
    sk_segments = 1u << 6,
    sk_all = (1u << 7) - 1,
};

const char* hit_kind_name(hit_kind k);

// case-insensitive substring match. within a kind, exact matches come first, then prefix
// matches, then the rest by address. a query that reads as a hex address in the file also
// yields an address hit at the top. at most max_per_kind hits per kind; truncated is set when
// a kind had more.
std::vector<search_hit> search_everything(const database& db, const std::string& query, unsigned kinds,
                                          size_t max_per_kind, bool* truncated = nullptr);
