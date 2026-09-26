#pragma once
#include <string>

class database;

// your names, comments, prototypes and breakpoints, to and from other tools. addresses travel as
// offsets from the image base, so a rebased program (pie, aslr in the other tool) still lines up.
//
// out: an idapython script (ida: File > Script file), a ghidra script (Script Manager), and an
// x64dbg database (.dd64 / .dd32, x64dbg: File > Import database).
// in: an x64dbg database, a .map file (ida, msvc's linker), the json that
// scripts/ida_to_ceasta.py and scripts/ghidra_to_ceasta.py write, or a c header (its types).

std::string export_ida(const database& db);
std::string export_ghidra(const database& db);
std::string export_x64dbg(const database& db);

struct import_result {
    int names = 0, comments = 0, bookmarks = 0, breakpoints = 0, prototypes = 0, types = 0;
    int skipped = 0;          // automatic names (sub_401000, FUN_00401000) and ones that didn't fit
    std::string format;       // what the file was
    std::string error;        // set when nothing could be read
    std::string note;         // what was left out (a header's declarations that didn't read)
    std::string summary() const;
};

// works out the format from the contents
import_result import_names(database& db, const std::string& path);
