#include "core/search.h"

#include "core/database.h"
#include "core/util.h"

#include <algorithm>
#include <cctype>

namespace {

std::string lower_copy(const std::string& s)
{
    std::string o = s;
    for (char& c : o)
        c = (char)std::tolower((unsigned char)c);
    return o;
}

// 0 = the whole text, 1 = a prefix, 2 = somewhere inside, -1 = no match. the needle is lower
// case and not empty
int score(const std::string& hay, const std::string& needle)
{
    if (needle.size() > hay.size())
        return -1;
    auto it = std::search(hay.begin(), hay.end(), needle.begin(), needle.end(),
                          [](char a, char b) { return std::tolower((unsigned char)a) == b; });
    if (it == hay.end())
        return -1;
    if (it != hay.begin())
        return 2;
    return hay.size() == needle.size() ? 0 : 1;
}

struct cand {
    int score;
    uint64_t addr;
    size_t index; // into the kind's own list
};

// best matches first, capped, then turned into hits
template <typename Make>
void emit(std::vector<cand>& c, size_t cap, bool& cut, std::vector<search_hit>& out, Make make)
{
    std::stable_sort(c.begin(), c.end(), [](const cand& a, const cand& b) {
        return a.score != b.score ? a.score < b.score : a.addr < b.addr;
    });
    if (c.size() > cap) {
        c.resize(cap);
        cut = true;
    }
    for (const cand& x : c)
        out.push_back(make(x));
}

std::string first_line(const std::string& s, size_t max_len)
{
    size_t nl = s.find('\n');
    return util::escape(nl == std::string::npos ? s : s.substr(0, nl), max_len);
}

// where a string is used: the first reference, and how many more there are
std::string used_in(const database& db, uint64_t a)
{
    auto refs = db.an.refs_to(a);
    size_t n = (size_t)(refs.second - refs.first);
    if (n == 0)
        return std::string();
    std::string s = "used in " + db.location(refs.first->from);
    if (n > 1)
        s += util::fmt(" (+%zu more)", n - 1);
    return s;
}

} // namespace

const char* hit_kind_name(hit_kind k)
{
    switch (k) {
    case hit_kind::address: return "address";
    case hit_kind::function: return "function";
    case hit_kind::name: return "name";
    case hit_kind::import: return "import";
    case hit_kind::export_: return "export";
    case hit_kind::string: return "string";
    case hit_kind::comment: return "comment";
    case hit_kind::segment: return "segment";
    }
    return "";
}

std::vector<search_hit> search_everything(const database& db, const std::string& query, unsigned kinds,
                                          size_t max_per_kind, bool* truncated)
{
    std::vector<search_hit> out;
    bool cut = false;
    if (truncated)
        *truncated = false;
    std::string q = util::trim(query);
    if (q.empty())
        return out;
    std::string needle = lower_copy(q);
    size_t cap = max_per_kind ? max_per_kind : 1;
    std::vector<cand> c;

    uint64_t a = 0;
    if (util::parse_hex(q, a) && db.bin.is_mapped(a))
        out.push_back({hit_kind::address, a, db.location(a), std::string()});

    if (kinds & sk_functions) {
        c.clear();
        const std::vector<function>& fs = db.an.funcs;
        for (size_t i = 0; i < fs.size(); i++) {
            int s = score(db.name_at(fs[i].start), needle);
            if (s >= 0)
                c.push_back({s, fs[i].start, i});
        }
        emit(c, cap, cut, out, [&](const cand& x) {
            return search_hit{hit_kind::function, x.addr, db.name_at(x.addr), std::string()};
        });
    }
    if (kinds & sk_names) {
        // renamed data and labels; renamed functions already came up as functions
        c.clear();
        std::vector<const std::pair<const uint64_t, std::string>*> src;
        for (const auto& n : db.user_names)
            if (!(db.an.flags_at(n.first) & fl_func))
                src.push_back(&n);
        for (size_t i = 0; i < src.size(); i++) {
            int s = score(src[i]->second, needle);
            if (s >= 0)
                c.push_back({s, src[i]->first, i});
        }
        emit(c, cap, cut, out, [&](const cand& x) {
            return search_hit{hit_kind::name, x.addr, src[x.index]->second, db.location(x.addr)};
        });
    }
    if (kinds & sk_imports) {
        c.clear();
        const std::vector<import_entry>& im = db.bin.imports;
        for (size_t i = 0; i < im.size(); i++) {
            int s = score(im[i].name, needle);
            if (s < 0 && score(im[i].lib, needle) >= 0)
                s = 3; // only the library matched: after the name matches
            if (s >= 0)
                c.push_back({s, im[i].slot, i});
        }
        emit(c, cap, cut, out, [&](const cand& x) {
            return search_hit{hit_kind::import, x.addr, im[x.index].name, im[x.index].lib};
        });
    }
    if (kinds & sk_exports) {
        c.clear();
        const std::vector<export_entry>& ex = db.bin.exports;
        for (size_t i = 0; i < ex.size(); i++) {
            int s = score(ex[i].name, needle);
            if (s < 0 && !ex[i].forward.empty() && score(ex[i].forward, needle) >= 0)
                s = 3;
            if (s >= 0)
                c.push_back({s, ex[i].addr, i});
        }
        emit(c, cap, cut, out, [&](const cand& x) {
            const export_entry& e = ex[x.index];
            return search_hit{hit_kind::export_, e.addr, e.name, e.forward.empty() ? std::string() : "-> " + e.forward};
        });
    }
    if (kinds & sk_strings) {
        c.clear();
        const std::vector<string_item>& st = db.an.strings;
        for (size_t i = 0; i < st.size(); i++) {
            int s = score(st[i].text, needle);
            if (s >= 0)
                c.push_back({s, st[i].addr, i});
        }
        emit(c, cap, cut, out, [&](const cand& x) {
            const string_item& e = st[x.index];
            return search_hit{hit_kind::string, e.addr, std::string(e.wide ? "L\"" : "\"") + util::escape(e.text, 200) + "\"",
                              used_in(db, e.addr)};
        });
    }
    if (kinds & sk_comments) {
        c.clear();
        std::vector<const std::pair<const uint64_t, std::string>*> src;
        for (const auto& n : db.user_comments)
            src.push_back(&n);
        for (size_t i = 0; i < src.size(); i++) {
            int s = score(src[i]->second, needle);
            if (s >= 0)
                c.push_back({s, src[i]->first, i});
        }
        emit(c, cap, cut, out, [&](const cand& x) {
            return search_hit{hit_kind::comment, x.addr, first_line(src[x.index]->second, 160), db.location(x.addr)};
        });
    }
    if (kinds & sk_segments) {
        c.clear();
        const std::vector<segment>& sg = db.bin.segments;
        for (size_t i = 0; i < sg.size(); i++) {
            int s = score(sg[i].name, needle);
            if (s >= 0)
                c.push_back({s, sg[i].start, i});
        }
        emit(c, cap, cut, out, [&](const cand& x) {
            return search_hit{hit_kind::segment, x.addr, sg[x.index].name, std::string()};
        });
    }
    if (truncated)
        *truncated = cut;
    return out;
}
