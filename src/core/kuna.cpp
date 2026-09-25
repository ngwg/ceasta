#include "core/kuna.h"
#include "core/binary.h"
#include "core/json.h"
#include "core/os.h"
#include "core/process.h"
#include "core/util.h"
#include <algorithm>

std::string kuna_find(const std::string& configured)
{
    std::string c = util::trim(configured);
    if (!c.empty())
        return os::find_program(c);
    return os::find_program("kuna");
}

std::string kuna_unsupported(const binary& b)
{
    if (b.format != bin_format::pe && b.format != bin_format::elf && b.format != bin_format::macho)
        return "kuna reads pe, elf and mach-o files; this one was opened as raw code";
    if (b.path.empty() || !os::exists(b.path))
        return "the program isn't on disk for kuna to read";
    return std::string();
}

std::string kuna_input(const binary& b, std::string& err)
{
    if (!b.slice_size)
        return b.path;
    if (b.slice_off > b.file.size() || b.slice_size > b.file.size() - b.slice_off) {
        err = "the universal file's part is out of range";
        return std::string();
    }
    const uint8_t* p = b.file.data() + b.slice_off;
    uint32_t crc = util::crc32(p, (size_t)b.slice_size);
    std::string dir = os::join(os::user_dir(), "kuna");
    std::string out = os::join(dir, util::fmt("%08X-%s-%s", crc, arch_name(b.arch), b.name.c_str()));
    if (os::exists(out))
        return out;
    os::make_dirs(dir);
    if (!os::write_file(out, std::string((const char*)p, (size_t)b.slice_size), err))
        return std::string();
    return out;
}

namespace {

// the first few lines of what a program said, for an error message
std::string first_lines(const std::string& text, int n)
{
    std::string out;
    for (const std::string& raw : util::split(util::trim(text), "\n")) {
        std::string l = util::trim(raw);
        if (l.empty())
            continue;
        if (!out.empty())
            out += " / ";
        out += l;
        if (--n == 0)
            break;
    }
    return out;
}

} // namespace

kuna_result kuna_decompile(const std::string& kuna, const std::string& file, uint64_t addr, uint32_t timeout_ms,
    const std::atomic<bool>* cancel)
{
    kuna_result r;
    if (kuna.empty()) {
        r.error = "kuna isn't installed (put it on PATH, or set where it is)";
        return r;
    }
    uint64_t t0 = os::now_ms();
    os::process_result p = os::run_process(
        {kuna, "decompile", file, util::fmt("0x%llx", (unsigned long long)addr), "--addr", "--json"}, timeout_ms, cancel);
    r.millis = os::now_ms() - t0;
    if (!p.started) {
        r.error = "couldn't run kuna: " + p.error;
        return r;
    }
    if (p.cancelled) {
        r.error = "cancelled";
        return r;
    }
    if (p.timed_out) {
        r.error = util::fmt("kuna took longer than %u seconds and was stopped", timeout_ms / 1000);
        return r;
    }

    json::value v;
    std::string err;
    if (!json::parse(p.out, v, err) || !v.is_object()) {
        std::string said = first_lines(p.err, 3);
        r.error = "kuna failed" + (said.empty() ? util::fmt(" (exit code %d)", p.exit_code) : ": " + said);
        return r;
    }
    const json::value* run_err = v.get("error");
    if (run_err && run_err->is_string() && !run_err->s.empty()) {
        r.error = "kuna: " + run_err->s;
        return r;
    }
    const json::value* fns = v.get("functions");
    if (!fns || !fns->is_array() || fns->size() == 0) {
        std::string said = first_lines(p.err, 2);
        r.error = util::fmt("kuna found no function at 0x%llx", (unsigned long long)addr) +
                  (said.empty() ? std::string() : " (" + said + ")");
        return r;
    }
    const json::value& f = (*fns->a)[0];
    r.name = f.get("name") ? f.get("name")->str() : std::string();
    r.code = f.get("code") ? f.get("code")->str() : std::string();
    const json::value* fn_err = f.get("error");
    if (r.code.empty()) {
        r.error = "kuna: " + (fn_err && fn_err->is_string() && !fn_err->s.empty() ? fn_err->s : std::string("no code"));
        return r;
    }

    // every line, blank ones too: kuna's line numbers count them
    for (size_t at = 0; at <= r.code.size();) {
        size_t nl = r.code.find('\n', at);
        if (nl == std::string::npos)
            nl = r.code.size();
        std::string line = r.code.substr(at, nl - at);
        at = nl + 1;
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        std::string t;
        for (char c : line)
            if (c == '\t')
                t.append(4 - t.size() % 4, ' ');
            else
                t.push_back(c);
        r.lines.push_back({t, 0});
    }
    while (!r.lines.empty() && util::trim(r.lines.back().text).empty())
        r.lines.pop_back();
    // line_number (from 1) -> the instructions it came from; a line points at its first one
    if (const json::value* maps = f.get("line_mappings"); maps && maps->is_array())
        for (const json::value& m : *maps->a) {
            const json::value* ln = m.get("line_number");
            const json::value* addrs = m.get("addresses");
            if (!ln || !ln->is_number() || !addrs || !addrs->is_array())
                continue;
            size_t i = (size_t)ln->n;
            if (i == 0 || i > r.lines.size())
                continue;
            for (const json::value& a : *addrs->a) {
                if (!a.is_number() || a.n <= 0)
                    continue;
                uint64_t at = (uint64_t)a.n;
                uint64_t& dst = r.lines[i - 1].addr;
                if (!dst || at < dst)
                    dst = at;
            }
        }
    r.ok = true;
    return r;
}
