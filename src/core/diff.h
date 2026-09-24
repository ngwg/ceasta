#pragma once
#include <cstdint>
#include <string>
#include <vector>

// compare two analyzed binaries at the function level: which functions match, which changed,
// which were added or removed. matching is position independent (it ignores load addresses),
// so it works across builds with aslr / pie.

class database;

struct diff_pair {
    uint64_t a = 0, b = 0;     // function addresses in each file
    std::string name;          // the name it matched by, or the a-side location
    double similarity = 1.0;   // 1.0 identical, lower = changed
    bool by_name = false;      // matched by name (vs by content)
};

struct diff_result {
    std::vector<diff_pair> identical; // same content
    std::vector<diff_pair> changed;   // matched but different
    std::vector<uint64_t> removed;    // only in a
    std::vector<uint64_t> added;      // only in b
    size_t funcs_a = 0, funcs_b = 0;
};

// match every function in a against b. cheap: one pass over each function's instructions.
diff_result diff_databases(database& a, database& b);
