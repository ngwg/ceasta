#pragma once
#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

struct binary;
class database;

// kuna (github.com/Noelo-Lab/kuna), a decompiler ported from ghidra's, as an optional second
// one. ceasta runs its command line tool when it's installed - nothing of it is built in - and
// reads its json. kuna's addresses are the file's own, the same ones ceasta shows. it names
// things itself: the names you gave them here go over as --define-function arguments, so the
// pseudocode speaks the same vocabulary as the listing.

struct kuna_line {
    std::string text;
    uint64_t addr = 0; // the first instruction the line comes from, 0 for none (braces, blanks)
};

struct kuna_result {
    bool ok = false;
    std::string error;
    std::string name;             // kuna's name for the function
    std::string code;             // the c
    std::vector<kuna_line> lines; // the same, by line
    uint64_t millis = 0;          // how long it took
};

// the kuna program: the configured path when one is set (it has to exist then), else kuna on
// PATH. "" when there isn't one
std::string kuna_find(const std::string& configured = std::string());

// why kuna can't read this file ("" when it can): it takes pe, elf and mach-o files from
// disk, and raw mips dumps
std::string kuna_unsupported(const binary& b);

// how to load b in kuna when it isn't a pe / elf / mach-o (a raw mips dump: --raw-image with
// the sleigh target and base). "" ends the list
std::vector<std::string> kuna_format_args(const binary& b);

// the file to give kuna for b: the program itself, or for a universal mach-o file the part
// ceasta shows (so the addresses are the same), written out once to the user folder.
// "" when that can't be written (err says why)
std::string kuna_input(const binary& b, std::string& err);

// --define-function arguments carrying the database's named functions over to kuna
std::vector<std::string> kuna_define_args(const database& db);

// decompiles the function at addr of the program file with kuna, waiting up to timeout_ms.
// a set cancel stops it. extra args go on the command line after the file
kuna_result kuna_decompile(const std::string& kuna, const std::string& file, uint64_t addr,
    uint32_t timeout_ms = 120000, const std::atomic<bool>* cancel = nullptr,
    const std::vector<std::string>& extra_args = std::vector<std::string>());
