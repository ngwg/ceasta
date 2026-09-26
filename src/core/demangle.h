#pragma once
#include <string>

// turns a compiler-mangled symbol into a readable name. four schemes:
//   _ZN4core3fmt5write17h..E           rust, legacy     core::fmt::write
//   _RNvNtCs..._4core3fmt5write        rust, v0         core::fmt::write
//   _ZNSt6vectorIiSaIiEE9push_backEOi  c++, gcc/clang   std::vector<int, std::allocator<int>>::push_back(int&&)
//   ?Load@Config@@QEAA_NXZ             c++, msvc        Config::Load(void)
// each parser is strict: a symbol it doesn't fully understand comes back unchanged (ok is false),
// so a name is either right or left mangled. the output matches what llvm-cxxfilt, llvm-undname
// and rustc-demangle print.

namespace demangle {

struct result {
    bool ok = false;
    std::string display; // what the listing shows: the name, with its parameters for a c++ function
    std::string name;    // the name alone, for calls in pseudocode: std::vector<int>::push_back
};

result run(const std::string& s);

// the name alone, "" if s isn't mangled (or not understood)
std::string name(const std::string& s);

// exactly what the reference tool prints (llvm-cxxfilt, llvm-undname with its --no-* flags,
// rustc-demangle's alternate form), "" if not demangled. for the tests
std::string full(const std::string& s);

// starts like a mangled name (_Z, __Z, ___Z, _R, ?): a cheap check before run()
bool is_mangled(const std::string& s);

} // namespace demangle
