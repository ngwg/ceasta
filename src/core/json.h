#pragma once
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

// small json value, parser and writer - enough for json-rpc (the mcp server)

namespace json {

struct value;
using array = std::vector<value>;
using object = std::vector<std::pair<std::string, value>>; // keeps insertion order

struct value {
    enum class kind { null, boolean, number, string, array, object };
    kind k = kind::null;
    bool b = false;
    double n = 0;
    std::string s;
    std::shared_ptr<json::array> a;
    std::shared_ptr<json::object> o;

    value() = default;
    value(std::nullptr_t) {}
    value(bool v) : k(kind::boolean), b(v) {}
    value(int v) : k(kind::number), n(v) {}
    value(int64_t v) : k(kind::number), n((double)v) {}
    value(uint64_t v) : k(kind::number), n((double)v) {}
    value(double v) : k(kind::number), n(v) {}
    value(const char* v) : k(kind::string), s(v) {}
    value(std::string v) : k(kind::string), s(std::move(v)) {}

    static value make_array() { value v; v.k = kind::array; v.a = std::make_shared<json::array>(); return v; }
    static value make_object() { value v; v.k = kind::object; v.o = std::make_shared<json::object>(); return v; }

    bool is_null() const { return k == kind::null; }
    bool is_bool() const { return k == kind::boolean; }
    bool is_number() const { return k == kind::number; }
    bool is_string() const { return k == kind::string; }
    bool is_array() const { return k == kind::array; }
    bool is_object() const { return k == kind::object; }

    // object member, null when missing (or not an object)
    const value* get(const std::string& key) const;
    // object member for building, added when missing (turns null into an object)
    value& operator[](const std::string& key);
    // array append (turns null into an array)
    value& push(value v);

    std::string str(const std::string& fallback = std::string()) const { return k == kind::string ? s : fallback; }
    double num(double fallback = 0) const { return k == kind::number ? n : fallback; }
    bool boolean(bool fallback = false) const { return k == kind::boolean ? b : fallback; }
    size_t size() const { return a ? a->size() : o ? o->size() : 0; }
};

bool parse(const std::string& text, value& out, std::string& err);
// compact, one line (json-rpc over stdio needs no raw newlines). invalid utf-8 in strings
// is replaced, so the output is always valid json
std::string dump(const value& v);

} // namespace json
