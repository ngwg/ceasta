#pragma once
#include <string>
#include <vector>

// function prototypes: parsed from c-like text ("int f(char* s, int n)"), and a table of
// well-known ones (the windows api, the c library, posix) so a call shows the right
// arguments and the listing can say which instruction sets which argument.

struct proto_param {
    std::string type;
    std::string name;
};

struct prototype {
    std::string ret = "int";
    std::string name;
    std::vector<proto_param> params;
    bool variadic = false;
    bool stdcall = false; // the callee takes its arguments off the stack (32-bit windows api)
};

// "int f(char* s, int n)", "HANDLE WINAPI CreateFileW(LPCWSTR lpFileName, ...)", "void f(void)".
// parameters without a name get a1, a2, ...
bool parse_prototype(const std::string& text, prototype& out, std::string& err);
std::string format_prototype(const prototype& p);

// a well-known function by the name a call shows: "CreateFileW", "__imp_CreateFileW",
// "j_printf", "printf@plt", "_Sleep@4". null when it isn't in the table
const prototype* known_prototype(const std::string& name);

bool is_identifier(const std::string& s);
bool is_reserved_word(const std::string& s); // c keywords and type words: not a variable name
