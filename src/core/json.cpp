#include "core/json.h"

#include <cmath>
#include <cstdio>
#include <cstdlib>

namespace json {

const value* value::get(const std::string& key) const
{
    if (k != kind::object || !o)
        return nullptr;
    for (const auto& kv : *o)
        if (kv.first == key)
            return &kv.second;
    return nullptr;
}

value& value::operator[](const std::string& key)
{
    if (k != kind::object || !o) {
        k = kind::object;
        o = std::make_shared<json::object>();
    }
    for (auto& kv : *o)
        if (kv.first == key)
            return kv.second;
    o->emplace_back(key, value());
    return o->back().second;
}

value& value::push(value v)
{
    if (k != kind::array || !a) {
        k = kind::array;
        a = std::make_shared<json::array>();
    }
    a->push_back(std::move(v));
    return a->back();
}

// ------------------------------------------------------------------ parser

namespace {

struct parser {
    const std::string& t;
    size_t i = 0;
    std::string err;

    explicit parser(const std::string& text) : t(text) {}

    void ws()
    {
        while (i < t.size() && (t[i] == ' ' || t[i] == '\t' || t[i] == '\n' || t[i] == '\r'))
            i++;
    }
    bool fail(const char* what)
    {
        if (err.empty())
            err = std::string(what) + " at offset " + std::to_string(i);
        return false;
    }

    static void put_utf8(std::string& out, uint32_t cp)
    {
        if (cp < 0x80) {
            out += (char)cp;
        } else if (cp < 0x800) {
            out += (char)(0xC0 | (cp >> 6));
            out += (char)(0x80 | (cp & 0x3F));
        } else if (cp < 0x10000) {
            out += (char)(0xE0 | (cp >> 12));
            out += (char)(0x80 | ((cp >> 6) & 0x3F));
            out += (char)(0x80 | (cp & 0x3F));
        } else {
            out += (char)(0xF0 | (cp >> 18));
            out += (char)(0x80 | ((cp >> 12) & 0x3F));
            out += (char)(0x80 | ((cp >> 6) & 0x3F));
            out += (char)(0x80 | (cp & 0x3F));
        }
    }

    bool hex4(uint32_t& out)
    {
        if (i + 4 > t.size())
            return fail("short \\u escape");
        out = 0;
        for (int k = 0; k < 4; k++) {
            char c = t[i++];
            out <<= 4;
            if (c >= '0' && c <= '9')
                out |= (uint32_t)(c - '0');
            else if (c >= 'a' && c <= 'f')
                out |= (uint32_t)(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F')
                out |= (uint32_t)(c - 'A' + 10);
            else
                return fail("bad \\u escape");
        }
        return true;
    }

    bool string(std::string& out)
    {
        if (i >= t.size() || t[i] != '"')
            return fail("expected a string");
        i++;
        while (i < t.size()) {
            char c = t[i++];
            if (c == '"')
                return true;
            if ((unsigned char)c < 0x20)
                return fail("control character in string");
            if (c != '\\') {
                out += c;
                continue;
            }
            if (i >= t.size())
                break;
            char e = t[i++];
            switch (e) {
            case '"': out += '"'; break;
            case '\\': out += '\\'; break;
            case '/': out += '/'; break;
            case 'b': out += '\b'; break;
            case 'f': out += '\f'; break;
            case 'n': out += '\n'; break;
            case 'r': out += '\r'; break;
            case 't': out += '\t'; break;
            case 'u': {
                uint32_t cp;
                if (!hex4(cp))
                    return false;
                if (cp >= 0xD800 && cp < 0xDC00 && i + 6 <= t.size() && t[i] == '\\' && t[i + 1] == 'u') {
                    i += 2;
                    uint32_t lo;
                    if (!hex4(lo))
                        return false;
                    if (lo >= 0xDC00 && lo < 0xE000)
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    else
                        cp = 0xFFFD;
                } else if (cp >= 0xD800 && cp < 0xE000) {
                    cp = 0xFFFD;
                }
                put_utf8(out, cp);
                break;
            }
            default:
                return fail("bad escape");
            }
        }
        return fail("unterminated string");
    }

    bool val(value& out, int depth)
    {
        if (depth > 200)
            return fail("nested too deep");
        ws();
        if (i >= t.size())
            return fail("unexpected end");
        char c = t[i];
        if (c == '{') {
            i++;
            out = value::make_object();
            ws();
            if (i < t.size() && t[i] == '}') {
                i++;
                return true;
            }
            for (;;) {
                ws();
                std::string key;
                if (!string(key))
                    return false;
                ws();
                if (i >= t.size() || t[i] != ':')
                    return fail("expected ':'");
                i++;
                value v;
                if (!val(v, depth + 1))
                    return false;
                out.o->emplace_back(std::move(key), std::move(v));
                ws();
                if (i < t.size() && t[i] == ',') {
                    i++;
                    continue;
                }
                if (i < t.size() && t[i] == '}') {
                    i++;
                    return true;
                }
                return fail("expected ',' or '}'");
            }
        }
        if (c == '[') {
            i++;
            out = value::make_array();
            ws();
            if (i < t.size() && t[i] == ']') {
                i++;
                return true;
            }
            for (;;) {
                value v;
                if (!val(v, depth + 1))
                    return false;
                out.a->push_back(std::move(v));
                ws();
                if (i < t.size() && t[i] == ',') {
                    i++;
                    continue;
                }
                if (i < t.size() && t[i] == ']') {
                    i++;
                    return true;
                }
                return fail("expected ',' or ']'");
            }
        }
        if (c == '"') {
            out = value(std::string());
            return string(out.s);
        }
        if (t.compare(i, 4, "true") == 0) {
            i += 4;
            out = value(true);
            return true;
        }
        if (t.compare(i, 5, "false") == 0) {
            i += 5;
            out = value(false);
            return true;
        }
        if (t.compare(i, 4, "null") == 0) {
            i += 4;
            out = value();
            return true;
        }
        if (c == '-' || (c >= '0' && c <= '9')) {
            size_t start = i;
            if (t[i] == '-')
                i++;
            while (i < t.size() && ((t[i] >= '0' && t[i] <= '9') || t[i] == '.' || t[i] == 'e' || t[i] == 'E' ||
                                    t[i] == '+' || t[i] == '-'))
                i++;
            std::string num = t.substr(start, i - start);
            char* end = nullptr;
            double d = std::strtod(num.c_str(), &end);
            if (!end || *end != '\0' || num == "-")
                return fail("bad number");
            out = value(d);
            return true;
        }
        return fail("unexpected character");
    }
};

void put_string(std::string& out, const std::string& s)
{
    static const char* hexd = "0123456789abcdef";
    out += '"';
    size_t i = 0;
    while (i < s.size()) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x80) {
            switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            default:
                if (c < 0x20 || c == 0x7F) {
                    out += "\\u00";
                    out += hexd[c >> 4];
                    out += hexd[c & 15];
                } else {
                    out += (char)c;
                }
            }
            i++;
            continue;
        }
        // copy a well formed utf-8 sequence, replace anything else
        int len = c >= 0xF0 && c < 0xF5 ? 4 : c >= 0xE0 ? 3 : c >= 0xC2 && c < 0xE0 ? 2 : 0;
        bool ok = len > 0 && i + (size_t)len <= s.size();
        for (int k = 1; ok && k < len; k++)
            ok = ((unsigned char)s[i + (size_t)k] & 0xC0) == 0x80;
        if (ok && len == 3) {
            unsigned char c1 = (unsigned char)s[i + 1];
            ok = !(c == 0xE0 && c1 < 0xA0) && !(c == 0xED && c1 >= 0xA0); // overlong / surrogates
        }
        if (ok && len == 4) {
            unsigned char c1 = (unsigned char)s[i + 1];
            ok = !(c == 0xF0 && c1 < 0x90) && !(c == 0xF4 && c1 >= 0x90);
        }
        if (ok) {
            out.append(s, i, (size_t)len);
            i += (size_t)len;
        } else {
            out += "\\ufffd";
            i++;
        }
    }
    out += '"';
}

void put(std::string& out, const value& v)
{
    switch (v.k) {
    case value::kind::null: out += "null"; break;
    case value::kind::boolean: out += v.b ? "true" : "false"; break;
    case value::kind::number: {
        char buf[40];
        if (!std::isfinite(v.n))
            std::snprintf(buf, sizeof(buf), "null");
        else if (std::fabs(v.n) < 9007199254740992.0 && v.n == std::floor(v.n))
            std::snprintf(buf, sizeof(buf), "%lld", (long long)v.n);
        else
            std::snprintf(buf, sizeof(buf), "%.17g", v.n);
        out += buf;
        break;
    }
    case value::kind::string: put_string(out, v.s); break;
    case value::kind::array: {
        out += '[';
        bool first = true;
        if (v.a)
            for (const value& x : *v.a) {
                if (!first)
                    out += ',';
                first = false;
                put(out, x);
            }
        out += ']';
        break;
    }
    case value::kind::object: {
        out += '{';
        bool first = true;
        if (v.o)
            for (const auto& kv : *v.o) {
                if (!first)
                    out += ',';
                first = false;
                put_string(out, kv.first);
                out += ':';
                put(out, kv.second);
            }
        out += '}';
        break;
    }
    }
}

} // namespace

bool parse(const std::string& text, value& out, std::string& err)
{
    parser p(text);
    if (!p.val(out, 0)) {
        err = p.err;
        return false;
    }
    p.ws();
    if (p.i != text.size()) {
        err = "trailing characters at offset " + std::to_string(p.i);
        return false;
    }
    return true;
}

std::string dump(const value& v)
{
    std::string out;
    put(out, v);
    return out;
}

} // namespace json
