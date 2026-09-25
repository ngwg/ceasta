#pragma once
#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

struct binary;

// kuna (github.com/Noelo-Lab/kuna), a decompiler ported from ghidra's, as an optional second
// one. ceasta runs its command line tool when it's installed - nothing of it is built in - and
// reads its json. kuna's addresses are the file's own, the same ones ceasta shows. it names
// things itself: it doesn't know the names you gave them here.

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

// why kuna can't read this file ("" when it can): it takes pe and elf files from disk
std::string kuna_unsupported(const binary& b);

// decompiles the function at addr of the program file with kuna, waiting up to timeout_ms.
// a set cancel stops it
kuna_result kuna_decompile(const std::string& kuna, const std::string& file, uint64_t addr,
    uint32_t timeout_ms = 120000, const std::atomic<bool>* cancel = nullptr);
