#pragma once
#include <cstdint>
#include <string>
#include <vector>

// simple library-function signatures, like ida's FLIRT but small. a signature is a function's
// byte pattern with the parts that move between builds (relative call / jump displacements)
// wildcarded, so the same routine can be recognized in another binary - naming library
// functions in a stripped target. matching is exact on the fixed bytes, so it never mis-names
// (a changed function just won't match); the trade is that some functions won't be recognized.

class database;

struct signature {
    std::string name;
    uint32_t length = 0;          // function length in bytes
    uint64_t hash = 0;            // over the fixed (non-wildcarded) bytes + the mask
};

// build a signature for every named function in a binary that has symbols
std::vector<signature> make_signatures(database& db);

// text format, one signature per line: "<hash> <length> <name>"
std::string signatures_to_text(const std::vector<signature>& sigs);
std::vector<signature> signatures_from_text(const std::string& text);

// name the unnamed functions of db that uniquely match a signature. returns how many were
// named. if apply is false, nothing is renamed and it just counts what would match.
struct sig_match {
    uint64_t addr = 0;
    std::string name;
};
std::vector<sig_match> match_signatures(database& db, const std::vector<signature>& sigs, bool apply);
