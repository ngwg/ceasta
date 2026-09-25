#pragma once
#include "core/binary.h"
#include <cstdint>
#include <string>
#include <vector>

// what the file itself says, beyond the code: headers, security flags, sections with their
// entropy, resources and version info (pe), and warnings worth knowing before reading the code
// (packed, an embedded program, an overlay, .net). re-reads the headers from the file bytes.

struct file_info {
    struct row {
        std::string label, value;
    };
    std::vector<row> header;
    struct section {
        std::string name;
        uint64_t addr = 0, size = 0, file_off = 0, file_size = 0;
        std::string perms;
        double entropy = 0;
    };
    std::vector<section> sections;
    struct resource {
        std::string type, name;
        uint32_t lang = 0;
        uint64_t file_off = 0, size = 0;
        double entropy = 0;
        std::string note; // "a windows program", "a png image", ...
    };
    std::vector<resource> resources;
    std::vector<row> version;          // pe version info: CompanyName, FileDescription, ...
    std::vector<std::string> warnings; // the ones worth knowing first
    std::string md5, sha256, imphash;
    double entropy = 0;
};

file_info inspect(const binary& b);

std::string md5_hex(const void* data, size_t n);
std::string sha256_hex(const void* data, size_t n);
double entropy(const uint8_t* p, size_t n); // bits per byte, 0 to 8
