#pragma once
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

// running another program and reading what it prints (an external decompiler like kuna).
// there's no shell in between: argv goes to the program as it is, so nothing in a file name or
// an argument is ever interpreted. stdin is empty, and ceasta's own files and sockets stay behind.

namespace os {

struct process_result {
    bool started = false;   // false when it couldn't be run at all (error says why)
    bool timed_out = false; // stopped because it took too long
    bool cancelled = false; // stopped because cancel was set
    int exit_code = -1;
    std::string out;        // what it printed on stdout / stderr (each capped at max_output)
    std::string err;
    std::string error;
};

// runs argv[0] (a path) with the arguments after it and waits for it, up to timeout_ms. a set
// cancel stops it early
process_result run_process(const std::vector<std::string>& argv, uint32_t timeout_ms,
    const std::atomic<bool>* cancel = nullptr, size_t max_output = 64u << 20);

// the full path of a program: a path as it is when that file exists, else the name looked up on
// PATH (on windows with .exe added). "" when it isn't anywhere
std::string find_program(const std::string& name);

}
