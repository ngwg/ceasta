#include "core/debugger_remote.h"

#ifdef CEASTA_LINUX_DEBUGGER

#include "core/os.h"
#include "core/process.h"
#include "core/util.h"

#include <algorithm>
#include <cstring>
#include <map>
#include <set>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

// a gdb remote serial protocol client, made for qemu-user's stub. packets are $data#xx with
// a two hex digit checksum, acked with +. mips o32: 32 general registers, then sr, lo, hi,
// badvaddr, cause, pc, each 4 bytes in the target's byte order (little endian here).
//
// flow: qemu-mipsel -g port starts the program stopped; we read qOffsets for the load bias,
// set a breakpoint on the entry, continue, and from there it's the usual stop / resume loop.
// the socket is non blocking so poll() fits the debugger's calling pattern; an interrupt is
// a raw 0x03 byte.

struct remote_state {
    int fd = -1;
    pid_t child = 0;
    dbg_state st = dbg_state::none;
    std::string reason;
    int exit_code = 0;
    bool killing = false;
    bool pause_requested = false;
    bool cont_sent = false;      // a c / s is in flight: the stub replies when it stops
    bool over_bp = false;        // this resume stepped off an armed breakpoint at its pc
    bool over_bp_step = false;   // ... and the resume was a single step, not a continue
    uint64_t reinsert_bp = 0;    // the breakpoint lifted for that step, to put back
    uint64_t temp_bp = 0;        // a run to / step over breakpoint to lift on the hit
    std::string temp_why;
    bool have_regs = false;      // regs reflects the registers at the current stop
    bool noack = false;          // QStartNoAckMode agreed: no +/- either way
    uint64_t bias = 0;           // the load bias (qOffsets Text)
    uint64_t entry = 0;          // runtime
    std::string exe_path;
    uint64_t exe_low = 0, exe_high = 0; // linked span of the loaded segments
    std::set<uint64_t> bps;
    std::vector<debugger::watch> installed;
    std::string inbuf;
    std::vector<reg_value> regs;
    std::function<void(const std::string&)> log;
};

namespace {

void logit(remote_state* r, const std::string& s)
{
    if (r && r->log)
        r->log(s);
}

uint8_t checksum(const std::string& s)
{
    unsigned c = 0;
    for (char ch : s)
        c = (c + (uint8_t)ch) & 0xff;
    return (uint8_t)c;
}

bool send_raw(remote_state* r, const std::string& s)
{
    size_t done = 0;
    while (done < s.size()) {
        ssize_t n = ::send(r->fd, s.data() + done, s.size() - done, MSG_NOSIGNAL);
        if (n <= 0)
            return false;
        done += (size_t)n;
    }
    return true;
}

bool send_packet(remote_state* r, const std::string& payload)
{
    if (getenv("CEASTA_REMOTE_DBG"))
        fprintf(stderr, "remote: => %s\n", payload.substr(0, 120).c_str());
    if (!send_raw(r, "$" + payload + "#" + util::fmt("%02x", checksum(payload))))
        return false;
    // the ack (the socket is non blocking: wait for it)
    uint64_t deadline = os::now_ms() + 4000;
    for (;;) {
        char ack = 0;
        ssize_t n = ::recv(r->fd, &ack, 1, MSG_DONTWAIT);
        if (n == 1)
            return ack == '+';
        if (os::now_ms() >= deadline)
            return false;
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(r->fd, &fds);
        timeval tv{0, 2000};
        select(r->fd + 1, &fds, nullptr, nullptr, &tv);
    }
}

// pull bytes from the socket without blocking, return false when the connection died
bool pump_socket(remote_state* r)
{
    char buf[4096];
    for (;;) {
        ssize_t n = ::recv(r->fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (n > 0) {
            r->inbuf.append(buf, (size_t)n);
            continue;
        }
        return n != 0; // 0: closed, -1 EAGAIN: fine
    }
}

// a complete $...#xx in the buffer, acked
bool take_packet(remote_state* r, std::string& payload)
{
    size_t dollar = r->inbuf.find('$');
    if (dollar == std::string::npos) {
        r->inbuf.clear(); // acks and stray bytes: nothing to parse yet
        return false;
    }
    r->inbuf.erase(0, dollar);
    size_t hash = r->inbuf.find('#');
    if (hash == std::string::npos || hash + 2 >= r->inbuf.size())
        return false;
    payload = r->inbuf.substr(1, hash - 1);
    r->inbuf.erase(0, hash + 3);
    if (!r->noack)
        send_raw(r, "+");
    if (getenv("CEASTA_REMOTE_DBG"))
        fprintf(stderr, "remote: <= %s\n", payload.substr(0, 700).c_str());
    return true;
}

// blocking packet read with a deadline; only used during start
bool read_packet(remote_state* r, std::string& payload, uint32_t timeout_ms)
{
    uint64_t deadline = os::now_ms() + timeout_ms;
    for (;;) {
        if (take_packet(r, payload))
            return true;
        if (os::now_ms() >= deadline)
            return false;
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(r->fd, &fds);
        timeval tv{0, 10 * 1000};
        if (select(r->fd + 1, &fds, nullptr, nullptr, &tv) <= 0)
            continue;
        if (!pump_socket(r))
            return false;
    }
}

// a register field of the g packet: 8 hex chars, little endian
uint64_t reg_at(const std::string& hex, size_t slot)
{
    size_t at = slot * 8;
    if (at + 8 > hex.size())
        return 0;
    uint64_t v = 0;
    for (int i = 3; i >= 0; i--) {
        char c1 = hex[at + (size_t)i * 2], c2 = hex[at + (size_t)i * 2 + 1];
        int hi = c1 >= '0' && c1 <= '9' ? c1 - '0' : c1 - 'a' + 10;
        int lo = c2 >= '0' && c2 <= '9' ? c2 - '0' : c2 - 'a' + 10;
        v = (v << 8) | (uint64_t)((hi << 4) | lo);
    }
    return v;
}

std::string hex32(uint32_t v)
{
    char out[9];
    for (int i = 0; i < 8; i++)
        out[i] = "0123456789abcdef"[(v >> ((7 - i) * 4)) & 0xf];
    return std::string(out, 8);
}

const char* const gpr_names[32] = {
    "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
    "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "t8", "t9", "k0", "k1", "gp", "sp", "fp", "ra",
};

void parse_regs(remote_state* r, const std::string& hex)
{
    std::vector<reg_value> out;
    for (int i = 0; i < 32; i++)
        out.push_back({gpr_names[i], reg_at(hex, (size_t)i)});
    if (hex.size() >= 38 * 8) {
        out.push_back({"sr", reg_at(hex, 32)});
        out.push_back({"lo", reg_at(hex, 33)});
        out.push_back({"hi", reg_at(hex, 34)});
        out.push_back({"badvaddr", reg_at(hex, 35)});
        out.push_back({"cause", reg_at(hex, 36)});
        out.push_back({"pc", reg_at(hex, 37)});
    }
    r->regs = std::move(out);
    r->have_regs = true;
}

// the linked extent of the program's loadable segments, from its headers
void read_exe_layout(remote_state* r, const std::string& path)
{
    FILE* f = fopen(path.c_str(), "rb");
    if (!f)
        return;
    uint8_t h[52];
    size_t n = fread(h, 1, sizeof(h), f);
    uint64_t low = ~0ull, high = 0;
    if (n == sizeof(h) && !memcmp(h, "\x7f" "ELF", 4) && h[4] == 1) { // elf32
        uint16_t phentsize = (uint16_t)(h[42] | h[43] << 8);
        uint16_t phnum = (uint16_t)(h[44] | h[45] << 8);
        uint32_t phoff;
        memcpy(&phoff, h + 28, 4);
        for (uint16_t i = 0; i < phnum && phentsize >= 32; i++) {
            uint8_t p[32];
            if (fseek(f, (long)(phoff + (uint64_t)i * phentsize), SEEK_SET) != 0 ||
                fread(p, 1, sizeof(p), f) != sizeof(p))
                break;
            uint32_t type;
            memcpy(&type, p, 4);
            if (type != 1) // pt_load
                continue;
            uint32_t vaddr, memsz;
            memcpy(&vaddr, p + 8, 4);
            memcpy(&memsz, p + 20, 4);
            if (memsz) {
                low = std::min<uint64_t>(low, vaddr);
                high = std::max<uint64_t>(high, vaddr + memsz);
            }
        }
    }
    fclose(f);
    if (low != ~0ull) {
        r->exe_low = low;
        r->exe_high = high;
    }
}

std::string stop_text(const std::string& pkt, remote_state* r)
{
    // T05watch:0x...;T02...;W01;X0f
    if (!pkt.empty() && (pkt[0] == 'T' || pkt[0] == 'S')) {
        int sig = 0;
        if (pkt.size() >= 3) {
            unsigned v = 0;
            for (int i = 0; i < 2; i++) {
                char c = pkt[1 + (size_t)i];
                v = v * 16 + (unsigned)(c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10);
            }
            sig = (int)v;
        }
        switch (sig) {
        case 5: {
            // a trap: our entry / user breakpoint, a step, or the program's own int3.
            // thread: pcthread=...; the reply also carries the thread id
            size_t th = pkt.find("thread:");
            if (r->cont_sent) {
                r->cont_sent = false;
            }
            uint64_t pc = 0;
            for (const reg_value& reg : r->regs)
                if (reg.name == "pc")
                    pc = reg.value;
            if (r->bps.count(pc))
                return "breakpoint";
            return "trap";
        }
        case 2: return "interrupted (ctrl+c)";
        case 19: return "stopped";
        default:
            return util::fmt("signal %d", sig);
        }
    }
    return "trap";
}

} // namespace

namespace remote {

bool available()
{
    return !os::find_program("qemu-mipsel").empty();
}

bool start(remote_state*& r, const std::string& exe, const std::string& args, const std::string& cwd,
    bool break_on_entry, const std::function<void(const std::string&)>& log, std::string& err)
{
    std::string qemu = os::find_program("qemu-mipsel");
    if (qemu.empty()) {
        err = "mips programs run under qemu-mipsel, which isn't installed (apt install qemu-user)";
        return false;
    }
    const char* rootfs = getenv("CEASTA_ROOTFS");

    // a port for the stub: qemu-mipsel -g listens on it (gdb is the client, qemu the server),
    // so we only reserve something free and hand it over
    int port = 0;
    int pick = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(0x7f000001);
    for (int attempt = 0; attempt < 16 && !port; attempt++) {
        addr.sin_port = htons(0);
        if (::bind(pick, (sockaddr*)&addr, sizeof(addr)) != 0)
            continue;
        socklen_t len = sizeof(addr);
        getsockname(pick, (sockaddr*)&addr, &len);
        port = ntohs(addr.sin_port);
    }
    close(pick);
    if (!port) {
        err = "couldn't find a local port for the qemu connection";
        return false;
    }

    std::vector<std::string> argv{qemu, "-g", util::fmt("%d", port)};
    if (rootfs && *rootfs)
        argv.push_back("-L"), argv.push_back(rootfs);
    argv.push_back(exe);
    for (const std::string& a : util::split(args, " "))
        if (!a.empty())
            argv.push_back(a);

    r = new remote_state();
    r->exe_path = exe;
    r->log = log;
    read_exe_layout(r, exe);

    pid_t child = fork();
    if (child < 0) {
        err = "fork failed";
        delete r;
        r = nullptr;
        return false;
    }
    if (child == 0) {
        long max_fd = sysconf(_SC_OPEN_MAX);
        if (max_fd < 0 || max_fd > 65536)
            max_fd = 65536;
        for (long fd = 3; fd < max_fd; fd++)
            close((int)fd);
        if (!cwd.empty())
            chdir(cwd.c_str());
        std::vector<char*> cargv;
        for (auto& s : argv)
            cargv.push_back(const_cast<char*>(s.c_str()));
        cargv.push_back(nullptr);
        execv(qemu.c_str(), cargv.data());
        _exit(127);
    }

    // qemu listens on the port; connect with retries while it comes up
    int conn = -1;
    uint64_t deadline = os::now_ms() + 8000;
    while (os::now_ms() < deadline) {
        int st = 0;
        pid_t gone = waitpid(child, &st, WNOHANG);
        if (gone == child) {
            err = "the program failed to start under qemu (missing interpreter? set CEASTA_ROOTFS to the extracted firmware root)";
            delete r;
            r = nullptr;
            return false;
        }
        conn = socket(AF_INET, SOCK_STREAM, 0);
        if (conn >= 0 && ::connect(conn, (sockaddr*)&addr, sizeof(addr)) == 0)
            break;
        if (conn >= 0)
            close(conn);
        conn = -1;
        usleep(20 * 1000);
    }
    if (conn < 0) {
        ::kill(child, SIGKILL);
        waitpid(child, nullptr, 0);
        err = "qemu didn't open its gdb connection";
        delete r;
        r = nullptr;
        return false;
    }
    r->fd = conn;
    r->child = child;
    int flags = fcntl(conn, F_GETFL, 0);
    fcntl(conn, F_SETFL, flags | O_NONBLOCK);

    // the stub answers ? with the first stop (the program hasn't started yet)
    std::string reply;
    if (!send_packet(r, "?") || !read_packet(r, reply, 5000)) {
        err = "the gdb connection to qemu didn't answer";
        remote::destroy(r);
        r = nullptr;
        return false;
    }
    // drop the +/- acks: one less thing to drift out of sync
    if (send_packet(r, "QStartNoAckMode")) {
        std::string ok;
        if (read_packet(r, ok, 3000) && ok == "OK")
            r->noack = true;
    }

    // the load bias, then the runtime entry
    if (send_packet(r, "qOffsets") && read_packet(r, reply, 5000)) {
        size_t t = reply.find("Text=");
        if (t != std::string::npos)
            r->bias = strtoull(reply.c_str() + t + 5, nullptr, 16);
    }
    // the static entry, straight from the file
    FILE* f = fopen(exe.c_str(), "rb");
    if (f) {
        uint8_t h[32];
        if (fread(h, 1, sizeof(h), f) == sizeof(h) && !memcmp(h, "\x7f" "ELF", 4) && h[4] == 1) {
            uint32_t e;
            memcpy(&e, h + 24, 4);
            r->entry = e + (uint32_t)r->bias;
        }
        fclose(f);
    }
    r->st = dbg_state::stopped;
    r->reason = "start";

    // run to the entry like the native debugger does, and stop there
    if (break_on_entry && r->entry) {
        if (set_bp(r, r->entry, true, err)) {
            if (cont(r, false, err)) {
                return true; // poll() picks the entry stop up
            }
        }
        err = err.empty() ? "can't run to the entry point" : err;
        remote::destroy(r);
        r = nullptr;
        return false;
    }
    return true;
}

void destroy(remote_state* r)
{
    if (!r)
        return;
    if (r->fd >= 0) {
        send_packet(r, "k");
        close(r->fd);
    }
    if (r->child) {
        ::kill(r->child, SIGKILL);
        waitpid(r->child, nullptr, 0);
    }
    delete r;
}

void poll(remote_state* r, uint32_t timeout_ms)
{
    if (!r || r->st != dbg_state::running)
        return;
    uint64_t deadline = os::now_ms() + timeout_ms;
    for (;;) {
        if (!pump_socket(r)) {
            // the connection died: the program (or qemu) ended
            r->st = dbg_state::none;
            return;
        }
        std::string pkt;
        while (take_packet(r, pkt)) {
            if (!pkt.empty() && (pkt[0] == 'W' || pkt[0] == 'X')) {
                r->exit_code = (int)strtoul(pkt.c_str() + 1, nullptr, 16);
                logit(r, util::fmt("process exited with code %d", r->exit_code));
                r->st = dbg_state::none;
                return;
            }
            if (!pkt.empty() && (pkt[0] == 'T' || pkt[0] == 'S')) {
                // registers at the stop, for the pc and everything else
                if (send_packet(r, "g")) {
                    std::string g;
                    uint64_t dl = os::now_ms() + 2000;
                    while (os::now_ms() < dl) {
                        if (take_packet(r, g)) {
                            if (!g.empty() && g[0] != 'E')
                                parse_regs(r, g);
                            break;
                        }
                        pump_socket(r);
                        usleep(200);
                    }
                }
                r->cont_sent = false;
                r->st = dbg_state::stopped;
                r->reason = stop_text(pkt, r);
                for (const char* mark : {"watch:", "rwatch:", "awatch:"}) {
                    size_t at = pkt.find(mark);
                    if (at == std::string::npos)
                        continue;
                    uint64_t wa = strtoull(pkt.c_str() + at + strlen(mark), nullptr, 16);
                    for (const debugger::watch& w : r->installed)
                        if (w.addr == wa) {
                            r->reason = debugger::watch_text(w);
                            break;
                        }
                    if (r->reason.find("watchpoint") == 0)
                        break;
                }
                if (r->over_bp) {
                    // that stop was our step over the breakpoint at the old pc: keep running
                    r->over_bp = false;
                    if (send_packet(r, "c")) {
                        r->cont_sent = true;
                        r->have_regs = false;
                        r->st = dbg_state::running;
                        return;
                    }
                    return; // the continue failed: report the stop we have
                }
                uint64_t at = pc(r);
                if (r->temp_bp && at == r->temp_bp) {
                    char p[48];
                    snprintf(p, sizeof(p), "z0,%llx,1", (unsigned long long)r->temp_bp);
                    send_packet(r, p);
                    r->bps.erase(r->temp_bp);
                    r->reason = r->temp_why;
                    r->temp_bp = 0;
                }
                return;
            }
            // anything else (stop replies we didn't ask for): drop
        }
        if (os::now_ms() >= deadline)
            return;
        usleep(500);
    }
}

dbg_state state(remote_state* r) { return r ? r->st : dbg_state::none; }

bool cont(remote_state* r, bool step, std::string& err)
{
    if (!r || r->st != dbg_state::stopped) {
        err = "the process isn't stopped";
        return false;
    }
    // like an int3 on x86: stopped on our own breakpoint, a single step walks over it
    // (qemu's single step runs the instruction under the breakpoint and stops after)
    r->over_bp = !step && r->bps.count(pc(r)) != 0;
    r->over_bp_step = step;
    if (!send_packet(r, step || r->over_bp ? "s" : "c")) {
        err = "the gdb connection to qemu died";
        return false;
    }
    r->cont_sent = true;
    r->have_regs = false;
    r->st = dbg_state::running;
    r->reason.clear();
    return true;
}

bool step_over(remote_state* r, std::string& err)
{
    // a call: break after its delay slot (the return address), like the native backend
    uint64_t at = pc(r);
    uint8_t buf[4];
    uint32_t w = 0;
    if (at && read(r, at, buf, 4)) {
        for (int i = 0; i < 4; i++)
            w |= (uint32_t)buf[i] << (8 * i);
        bool call = (w >> 26) == 3;                      // jal
        if ((w >> 26) == 0 && (w & 0x3f) == 9) {         // jalr
            unsigned rs = (w >> 21) & 0x1f;
            call = rs != 31; // jalr ra is a tail-ish return, step into it
        }
        if ((w >> 26) == 1) {                            // bal / bltzal / bgezal link too
            unsigned rt = (w >> 16) & 0x1f;
            call = rt >= 0x10 && rt <= 0x13;
        }
        if (call) {
            if (!set_bp(r, at + 8, true, err))
                return false;
            r->temp_bp = at + 8;
            r->temp_why = "step over";
            return cont(r, false, err);
        }
    }
    // not a call: one instruction
    return cont(r, true, err);
}

bool run_to(remote_state* r, uint64_t addr, std::string& err)
{
    if (!set_bp(r, addr, true, err))
        return false;
    r->temp_bp = addr;
    r->temp_why = "run to cursor";
    return cont(r, false, err);
}

bool pause(remote_state* r, std::string& err)
{
    if (!r || r->st != dbg_state::running) {
        err = "the process isn't running";
        return false;
    }
    char brk = 3;
    if (!send_raw(r, std::string(1, brk))) {
        err = "can't interrupt the program";
        return false;
    }
    r->pause_requested = true;
    return true;
}

bool set_bp(remote_state* r, uint64_t addr, bool on, std::string& err)
{
    char p[64];
    snprintf(p, sizeof(p), "%c0,%llx,1", on ? 'Z' : 'z', (unsigned long long)addr);
    if (!send_packet(r, p)) {
        err = "the gdb connection to qemu died";
        return false;
    }
    // the stub's OK / E reply comes as a packet: read it right away (we're stopped)
    std::string reply;
    read_packet(r, reply, 2000);
    if (!reply.empty() && reply[0] == 'E') {
        err = util::fmt("qemu refused a breakpoint at %llx", (unsigned long long)addr);
        return false;
    }
    if (on)
        r->bps.insert(addr);
    else
        r->bps.erase(addr);
    return true;
}

bool has_bp(remote_state* r, uint64_t addr) { return r && r->bps.count(addr) != 0; }

std::vector<uint64_t> bps(remote_state* r)
{
    std::vector<uint64_t> out;
    if (r)
        for (uint64_t b : r->bps)
            out.push_back(b);
    return out;
}

bool read(remote_state* r, uint64_t addr, void* out, size_t n)
{
    if (!r || r->fd < 0 || n == 0)
        return false;
    // one packet per chunk: the stub caps lengths, stay well under
    size_t done = 0;
    uint8_t* dst = (uint8_t*)out;
    while (done < n) {
        size_t chunk = std::min<size_t>(n - done, 1024);
        char p[64];
        snprintf(p, sizeof(p), "m%llx,%zx", (unsigned long long)(addr + done), chunk);
        if (!send_packet(r, p))
            return false;
        std::string reply;
        if (!read_packet(r, reply, 3000) || reply.empty() || reply[0] == 'E')
            return false;
        if (reply.size() < chunk * 2)
            return false;
        for (size_t i = 0; i < chunk; i++) {
            char c1 = reply[i * 2], c2 = reply[i * 2 + 1];
            int hi = c1 >= '0' && c1 <= '9' ? c1 - '0' : c1 - 'a' + 10;
            int lo = c2 >= '0' && c2 <= '9' ? c2 - '0' : c2 - 'a' + 10;
            dst[done + i] = (uint8_t)((hi << 4) | lo);
        }
        done += chunk;
    }
    return true;
}

bool write(remote_state* r, uint64_t addr, const void* in, size_t n)
{
    if (!r || r->fd < 0 || n == 0)
        return false;
    const uint8_t* src = (const uint8_t*)in;
    size_t done = 0;
    while (done < n) {
        size_t chunk = std::min<size_t>(n - done, 1024);
        std::string hex;
        hex.reserve(chunk * 2);
        for (size_t i = 0; i < chunk; i++)
            hex += util::fmt("%02x", src[done + i]);
        char p[32];
        snprintf(p, sizeof(p), "M%llx,%zx:", (unsigned long long)(addr + done), chunk);
        if (!send_packet(r, p + hex))
            return false;
        std::string reply;
        if (!read_packet(r, reply, 3000) || (!reply.empty() && reply[0] == 'E'))
            return false;
        done += chunk;
    }
    return true;
}

std::vector<reg_value> registers(remote_state* r)
{
    if (!r || r->st != dbg_state::stopped)
        return {};
    if (!r->have_regs) {
        if (send_packet(r, "g")) {
            std::string g;
            if (read_packet(r, g, 3000) && !g.empty() && g[0] != 'E')
                parse_regs(r, g);
        }
    }
    return r->regs;
}

bool set_register(remote_state* r, const std::string& name, uint64_t v, std::string& err)
{
    std::vector<reg_value> regs = registers(r);
    int slot = -1;
    for (size_t i = 0; i < regs.size() && i < 38; i++)
        if (regs[i].name == util::lower(name))
            slot = (int)i;
    if (slot < 0) {
        err = "unknown register " + name;
        return false;
    }
    // rebuild the g packet with the one register changed
    std::string hex;
    for (int i = 0; i < 38; i++) {
        uint32_t val = i == slot ? (uint32_t)v : (uint32_t)reg_at(
            [&] {
                std::string h;
                for (const reg_value& reg : regs) {
                    uint32_t x = (uint32_t)reg.value;
                    for (int b = 0; b < 8; b++)
                        h += util::fmt("%02x", (x >> (b * 8)) & 0xff);
                }
                return h;
            }(),
            (size_t)i);
        hex += hex32(val);
    }
    if (!send_packet(r, "G" + hex)) {
        err = "the gdb connection to qemu died";
        return false;
    }
    std::string reply;
    read_packet(r, reply, 2000);
    r->have_regs = false;
    return true;
}

uint64_t pc(remote_state* r)
{
    for (const reg_value& reg : registers(r))
        if (reg.name == "pc")
            return reg.value;
    if (getenv("CEASTA_REMOTE_DBG")) {
        fprintf(stderr, "remote: pc not found (%zu regs, st=%d):", r ? r->regs.size() : 0, (int)(r ? (int)r->st : -1));
        for (const reg_value& reg : (r ? r->regs : std::vector<reg_value>{}))
            fprintf(stderr, " %s", reg.name.c_str());
        fprintf(stderr, "\n");
    }
    return 0;
}

uint64_t image_base(remote_state* r) { return r ? r->exe_low + r->bias : 0; }

uint32_t pid(remote_state* r) { return r ? (uint32_t)r->child : 0; }

int exit_code(remote_state* r) { return r ? r->exit_code : 0; }

std::string stop_reason(remote_state* r) { return r ? r->reason : std::string(); }

std::vector<dbg_region> regions(remote_state* r)
{
    std::vector<dbg_region> out;
    if (!r || !r->exe_low)
        return out;
    dbg_region rx;
    rx.base = r->exe_low + r->bias;
    rx.size = r->exe_high - r->exe_low;
    rx.perms = "r-x";
    rx.what = r->exe_path;
    out.push_back(rx);
    return out;
}

std::vector<dbg_module> modules(remote_state* r)
{
    std::vector<dbg_module> out;
    if (!r || !r->exe_low)
        return out;
    size_t slash = r->exe_path.find_last_of('/');
    dbg_module m;
    m.name = slash == std::string::npos ? r->exe_path : r->exe_path.substr(slash + 1);
    m.path = r->exe_path;
    m.base = r->exe_low + r->bias;
    m.size = r->exe_high - r->exe_low;
    out.push_back(m);
    return out;
}

// z2 watches writes, z3 reads, z4 both; the stub reports the hit in the stop reply
bool apply_watches(remote_state* r, const std::vector<debugger::watch>& watches, std::string& err)
{
    if (!r)
        return false;
    for (const debugger::watch& w : r->installed) {
        char p[64];
        snprintf(p, sizeof(p), "z%d,%llx,%d", w.access ? 4 : 2, (unsigned long long)w.addr, w.size);
        if (!send_packet(r, p)) {
            err = "the gdb connection to qemu died";
            return false;
        }
        std::string reply;
        read_packet(r, reply, 2000);
    }
    r->installed.clear();
    for (const debugger::watch& w : watches) {
        char p[64];
        snprintf(p, sizeof(p), "Z%d,%llx,%d", w.access ? 4 : 2, (unsigned long long)w.addr, w.size);
        if (!send_packet(r, p)) {
            err = "the gdb connection to qemu died";
            return false;
        }
        std::string reply;
        if (!read_packet(r, reply, 2000) || reply.empty() || reply[0] == 'E') {
            // an empty reply: the mips stub has no watchpoints. say so instead of a silent no-op
            err = reply.empty() ? "the emulator doesn't support watchpoints for mips programs"
                                : util::fmt("qemu refused a watchpoint at %llx", (unsigned long long)w.addr);
            return false;
        }
        r->installed.push_back(w);
    }
    return true;
}

} // namespace remote

#endif
