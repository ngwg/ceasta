// the ai server, started from the gui (ai menu): an mcp client on this machine talks to it over
// http. the server runs on its own thread, but the database and the debugger belong to the ui
// thread, so each tool call is queued and run there between frames.
#include "app.h"
#include "core/mcp.h"
#include "core/mcp_transport.h"
#include "core/util.h"
#include <algorithm>
#include <condition_variable>
#include <deque>
#include <mutex>

struct app_mcp {
    mcp_server server;
    std::thread worker;
    std::atomic<bool> stop{false};

    // a piece of a tool call waiting for the ui thread. it lives on the server thread's stack
    // until done (or dropped while stopping, before the ui thread took it)
    struct job {
        const std::function<void()>* fn = nullptr;
        bool taken = false;
        bool done = false;
    };
    std::mutex m;
    std::condition_variable cv;
    std::deque<job*> queue;
    std::vector<std::string> activity; // tool calls, logged by the ui thread
    std::string url;                   // set once it listens
    std::string error;                 // why it couldn't
    bool finished = false;             // the server thread returned

    // ui thread only
    int calls = 0;
    bool announced = false;
    bool reported = false;
    bool restore_entry = false; // debug_start forced a stop at the entry point...
    bool entry_setting = false; // ...and this was the user's setting

    // the server thread: hand fn to the ui thread and wait for it
    void run_on_ui(const std::function<void()>& fn)
    {
        job j;
        j.fn = &fn;
        std::unique_lock<std::mutex> l(m);
        if (stop)
            return;
        queue.push_back(&j);
        cv.wait(l, [&] { return j.done || (stop && !j.taken); });
        if (!j.done)
            queue.erase(std::remove(queue.begin(), queue.end(), &j), queue.end());
    }
};

namespace {

// the debugger as the ai reaches it: the same one the window shows. addresses coming in are
// static (the listing's), like everywhere in the app
void fill_debug_link(app_state& s, app_mcp& m)
{
    mcp_debug_link& d = m.server.debug;
    d.get = [&s] { return &s.dbg; };
    d.pump = [&s] {
        if (s.dbg.state() == dbg_state::running)
            s.dbg.poll(0);
    };
    d.to_runtime = [&s](uint64_t a) { return app_to_runtime(s, a); };
    d.to_static = [&s](uint64_t rt, uint64_t& out) { return app_to_static(s, rt, out); };
    d.start = [&s, &m](const std::string& args, std::string& err) {
        if (!app_can_debug(s, &err))
            return false;
        // an ai session starts stopped at the entry point; the user's setting comes back after
        m.entry_setting = s.dbg.break_on_entry;
        m.restore_entry = true;
        s.dbg.break_on_entry = true;
        if (!s.dbg.start(s.db->bin.path, args.empty() ? s.debug_args : args, "", err)) {
            s.dbg.break_on_entry = m.entry_setting;
            m.restore_entry = false;
            return false;
        }
        app_log(s, "[ai] debugging " + s.db->bin.path);
        return true;
    };
    d.cont = [&s](std::string& err) { return s.dbg.cont(err); };
    d.step_into = [&s](std::string& err) { return s.dbg.step_into(err); };
    d.step_over = [&s](std::string& err) { return s.dbg.step_over(err); };
    d.pause = [&s](std::string& err) { return s.dbg.pause(err); };
    d.run_to = [&s](uint64_t a, std::string& err) {
        if (!s.dbg_mapped) {
            err = "the process isn't the open file, so its addresses aren't known";
            return false;
        }
        return s.dbg.run_to(app_to_runtime(s, a), err);
    };
    d.kill = [&s] { dbg_stop(s); };
    d.add_bp = [&s](uint64_t a, std::string& err) {
        if (!s.db || !s.db->bin.is_mapped(a)) {
            err = "that address isn't part of the file";
            return false;
        }
        if (!s.db->breakpoints.insert(a).second)
            return true; // already there
        s.db->dirty = true;
        s.version++;
        if (s.dbg.state() != dbg_state::none && s.dbg_mapped)
            return s.dbg.add_bp(app_to_runtime(s, a), err);
        return true; // placed when the program starts
    };
    d.del_bp = [&s](uint64_t a) {
        if (!s.db || !s.db->breakpoints.erase(a))
            return false;
        s.db->dirty = true;
        s.version++;
        if (s.dbg.state() != dbg_state::none && s.dbg_mapped)
            s.dbg.del_bp(app_to_runtime(s, a));
        return true;
    };
    d.bps = [&s] {
        return s.db ? std::vector<uint64_t>(s.db->breakpoints.begin(), s.db->breakpoints.end()) : std::vector<uint64_t>();
    };
}

} // namespace

bool app_mcp_start(app_state& s)
{
    if (s.mcp && !s.mcp->finished)
        return true;
    app_mcp_stop(s); // a server that failed to listen: start over
    std::shared_ptr<app_mcp> m = std::make_shared<app_mcp>();
    app_mcp* raw = m.get();
    mcp_server& srv = m->server;
    srv.opts.allow_debug = s.mcp_allow_debug && debugger::supported() && !s.sandboxed;
    srv.opts.allow_lua = s.mcp_allow_lua;
    srv.opts.autosave = false; // the ai's edits wait for the user's save
    srv.get_db = [&s] { return s.db.get(); };
    if (srv.opts.allow_lua)
        srv.get_lua = [&s] { return &s.lua; };
    if (srv.opts.allow_debug)
        fill_debug_link(s, *raw);
    srv.on_owner = [raw](const std::function<void()>& fn) { raw->run_on_ui(fn); };
    srv.on_changed = [&s] { app_names_changed(s); };
    srv.on_activity = [raw](const std::string& what) {
        std::lock_guard<std::mutex> l(raw->m);
        raw->activity.push_back(what);
    };
    int port = s.mcp_port;
    m->worker = std::thread([raw, port] {
        std::string err;
        int rc = mcp_serve_http(raw->server, port, "127.0.0.1", [raw] { return raw->stop.load(); }, err,
            [raw](const std::string& url) {
                std::lock_guard<std::mutex> l(raw->m);
                raw->url = url;
            });
        std::lock_guard<std::mutex> l(raw->m);
        if (rc != 0)
            raw->error = err;
        raw->finished = true;
    });
    s.mcp = m;
    return true;
}

void app_mcp_stop(app_state& s)
{
    if (!s.mcp)
        return;
    std::shared_ptr<app_mcp> m = std::move(s.mcp);
    m->server.stopping = true;
    {
        std::lock_guard<std::mutex> l(m->m);
        m->stop = true;
    }
    m->cv.notify_all();
    if (m->worker.joinable())
        m->worker.join();
    if (m->restore_entry)
        s.dbg.break_on_entry = m->entry_setting;
    if (m->announced)
        app_log(s, "ai server stopped");
}

bool app_mcp_running(const app_state& s)
{
    if (!s.mcp)
        return false;
    std::lock_guard<std::mutex> l(s.mcp->m);
    return !s.mcp->finished;
}

std::string app_mcp_url(const app_state& s)
{
    if (!s.mcp)
        return std::string();
    std::lock_guard<std::mutex> l(s.mcp->m);
    return s.mcp->finished ? std::string() : s.mcp->url;
}

std::string app_mcp_error(const app_state& s)
{
    if (!s.mcp)
        return std::string();
    std::lock_guard<std::mutex> l(s.mcp->m);
    return s.mcp->error;
}

int app_mcp_calls(const app_state& s)
{
    return s.mcp ? s.mcp->calls : 0;
}

void app_mcp_pump(app_state& s)
{
    if (!s.mcp)
        return;
    app_mcp& m = *s.mcp;
    // the waiting tool calls, one after another; each is short (a lookup, a decompile, a step)
    for (int i = 0; i < 64; i++) {
        app_mcp::job* j = nullptr;
        {
            std::lock_guard<std::mutex> l(m.m);
            if (m.queue.empty())
                break;
            j = m.queue.front();
            m.queue.pop_front();
            j->taken = true;
        }
        try {
            (*j->fn)();
        } catch (const std::exception& e) {
            app_log(s, std::string("[ai] tool error: ") + e.what(), 2);
        } catch (...) {
            app_log(s, "[ai] tool error", 2);
        }
        {
            std::lock_guard<std::mutex> l(m.m);
            j->done = true;
        }
        m.cv.notify_all();
    }
    // the entry point setting an ai session overrode is back once the program first stops
    if (m.restore_entry && s.dbg.state() != dbg_state::running) {
        s.dbg.break_on_entry = m.entry_setting;
        m.restore_entry = false;
    }
    std::vector<std::string> acts;
    std::string url, err;
    {
        std::lock_guard<std::mutex> l(m.m);
        acts.swap(m.activity);
        url = m.url;
        err = m.error;
    }
    for (const std::string& a : acts) {
        m.calls++;
        app_log(s, "[ai] " + a);
    }
    if (!url.empty() && !m.announced) {
        m.announced = true;
        app_log(s, "ai server listening on " + url + (m.server.opts.allow_debug ? " (debugger allowed)" : "") +
            (m.server.opts.allow_lua ? " (lua allowed)" : ""));
    }
    if (!err.empty() && !m.reported) {
        m.reported = true;
        app_log(s, "ai server: " + err, 2);
    }
}
