#pragma once
#include <cstdint>
#include <string>
#include <vector>

// a small pseudo-c decompiler. it lifts one function's instructions to
// expressions, recovers conditions from the flags, structures the control flow
// (if / else / while / switch, gotos only where it has to) and prints c-like
// code. not a full decompiler - it is meant to read a routine quickly, the
// listing is still the source of truth.

class database;

struct decomp_line {
    int indent = 0;       // nesting level, one step = a pair of spaces
    std::string text;
    uint64_t addr = 0;    // instruction this line came from, 0 if none (braces, blanks)
};

// a variable of the function: a parameter, a slot of its stack frame, or a register the code
// keeps a value in. the database keeps your name and type for it under key
struct decomp_var {
    std::string key;   // the decompiler's own name: "rdi", "eax", "local_1c", "arg_4"
    std::string name;  // as shown (yours, the prototype's, or key)
    std::string type;  // as declared ("" for a register nobody gave a type)
    bool param = false;
    bool stack = false;
};

struct decompiled {
    bool ok = false;
    std::string error;
    uint64_t func = 0;
    std::string name;
    std::vector<decomp_line> lines;   // lines[0] is the signature
    std::vector<decomp_var> vars;
    bool truncated = false;   // the function was too big, output is partial
};

// decompiles the function that starts at func_start. safe on the main thread,
// uses the database's analysis and its disassembler.
decompiled decompile(database& db, uint64_t func_start);

// the whole thing as plain text (used by the cli and the clipboard)
std::string decompile_text(database& db, uint64_t func_start);

// same, but mark the line that the address `here` (a static address, usually the debuggee's pc
// mapped back into the listing) falls on, so you can read where execution is stopped
std::string decompile_text_marked(database& db, uint64_t func_start, uint64_t here);
