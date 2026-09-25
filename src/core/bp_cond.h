#pragma once
#include <map>
#include <string>

class debugger;
struct lua_State;

// breakpoint conditions: a lua expression over the stopped program, like "rax == 5" or
// "u32(rsp + 8) > 100 and str(rdi) == 'admin'". it runs in a sandbox of its own that only has
// the registers (rax, eax, ...), memory readers u8 / u16 / u32 / u64 / str / wstr, the hit count
// (hits), math and string - no files, no os - so a condition from anyone is safe to evaluate.
class bp_conditions {
public:
    bp_conditions();
    ~bp_conditions();
    bp_conditions(const bp_conditions&) = delete;
    bp_conditions& operator=(const bp_conditions&) = delete;

    // true: stop here. an expression that doesn't work stops too, with err saying why
    bool check(debugger& d, const std::string& expr, int hits, std::string& err);
    // is the expression valid lua? (err says why not)
    bool valid(const std::string& expr, std::string& err);

private:
    lua_State* L_ = nullptr;
    std::map<std::string, int> compiled_; // expression -> registry ref of its function
};
