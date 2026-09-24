#include "core/mcp_transport.h"

#include "core/mcp.h"
#include "core/util.h"

#include <cstdio>
#include <cstring>
#include <string>

#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#define DUP _dup
#define DUP2 _dup2
#define FILENO _fileno
#else
#include <unistd.h>
#define DUP dup
#define DUP2 dup2
#define FILENO fileno
#endif

// ------------------------------------------------------------------ stdio

namespace {

// read one message from stdin. handles "Content-Length: N\r\n\r\n<body>" framing and, when the
// first bytes aren't that header, one json value per line. sets framed to the framing seen.
// returns false at end of input.
bool read_message(std::string& out, bool& framed)
{
    int c = getchar();
    while (c == '\r' || c == '\n') // skip blank lines between messages
        c = getchar();
    if (c == EOF)
        return false;

    if (c == 'C') { // "Content-Length" header
        framed = true;
        std::string header(1, (char)c);
        while ((c = getchar()) != EOF) {
            header += (char)c;
            size_t n = header.size();
            if ((n >= 4 && header.compare(n - 4, 4, "\r\n\r\n") == 0) ||
                (n >= 2 && header.compare(n - 2, 2, "\n\n") == 0))
                break;
        }
        size_t len = 0;
        size_t p = util::lower(header).find("content-length:");
        if (p != std::string::npos)
            len = (size_t)strtoull(header.c_str() + p + 15, nullptr, 10);
        out.assign(len, '\0');
        size_t got = len ? fread(&out[0], 1, len, stdin) : 0;
        out.resize(got);
        return true;
    }

    framed = false; // line-delimited json
    out.assign(1, (char)c);
    while ((c = getchar()) != EOF && c != '\n')
        if (c != '\r')
            out += (char)c;
    return true;
}

void write_message(FILE* out, const std::string& reply, bool framed)
{
    if (reply.empty())
        return;
    if (framed)
        fprintf(out, "Content-Length: %zu\r\n\r\n", reply.size());
    fwrite(reply.data(), 1, reply.size(), out);
    if (!framed)
        fputc('\n', out);
    fflush(out);
}

} // namespace

int mcp_serve_stdio(mcp_server& server)
{
    // Keep the json-rpc channel clean: save the real stdout, then point fd 1 at stderr so a
    // debugged child process (or a stray printf) can't corrupt the protocol. Replies go to the
    // saved handle only.
    FILE* out = stdout;
    int saved = DUP(FILENO(stdout));
    if (saved >= 0) {
        fflush(stdout);
        DUP2(FILENO(stderr), FILENO(stdout));
        FILE* f = fdopen(saved, "wb");
        if (f)
            out = f;
    }

    std::string message;
    bool framed = false;
    while (read_message(message, framed)) {
        if (message.empty())
            continue;
        write_message(out, server.handle(message), framed);
    }
    if (out != stdout)
        fclose(out);
    return 0;
}

// ------------------------------------------------------------------ http (localhost)

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
using socket_t = SOCKET;
static const socket_t bad_socket = INVALID_SOCKET;
static int close_socket(socket_t s) { return closesocket(s); }
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
using socket_t = int;
static const socket_t bad_socket = -1;
static int close_socket(socket_t s) { return close(s); }
#endif

#include "core/os.h"

namespace {

struct net_init {
    bool ok = true;
    net_init()
    {
#ifdef _WIN32
        WSADATA w;
        ok = WSAStartup(MAKEWORD(2, 2), &w) == 0;
#endif
    }
    ~net_init()
    {
#ifdef _WIN32
        if (ok)
            WSACleanup();
#endif
    }
};

void set_nonblocking(socket_t s)
{
#ifdef _WIN32
    u_long mode = 1;
    ioctlsocket(s, FIONBIO, &mode);
#else
    int fl = fcntl(s, F_GETFL, 0);
    fcntl(s, F_SETFL, fl | O_NONBLOCK);
#endif
}

bool would_block()
{
#ifdef _WIN32
    return WSAGetLastError() == WSAEWOULDBLOCK;
#else
    return errno == EAGAIN || errno == EWOULDBLOCK;
#endif
}

// read an http request (headers + body by Content-Length) from a blocking-ish socket. returns
// false on disconnect or a request with no proper end of headers within the size cap.
bool read_http_request(socket_t c, std::string& method, std::string& path, std::string& body)
{
    std::string buf;
    char tmp[4096];
    size_t header_end = std::string::npos;
    while (header_end == std::string::npos) {
        int n = (int)recv(c, tmp, sizeof(tmp), 0);
        if (n <= 0) {
            if (n < 0 && would_block()) {
                os::sleep_ms(2);
                continue;
            }
            return false;
        }
        buf.append(tmp, (size_t)n);
        header_end = buf.find("\r\n\r\n");
        if (buf.size() > 8 * 1024 * 1024)
            return false;
    }
    std::string head = buf.substr(0, header_end);
    size_t sp1 = head.find(' ');
    size_t sp2 = sp1 == std::string::npos ? std::string::npos : head.find(' ', sp1 + 1);
    if (sp1 == std::string::npos || sp2 == std::string::npos)
        return false;
    method = head.substr(0, sp1);
    path = head.substr(sp1 + 1, sp2 - sp1 - 1);

    size_t len = 0;
    size_t cl = util::lower(head).find("content-length:");
    if (cl != std::string::npos)
        len = (size_t)strtoull(head.c_str() + cl + 15, nullptr, 10);
    body = buf.substr(header_end + 4);
    while (body.size() < len) {
        int n = (int)recv(c, tmp, sizeof(tmp), 0);
        if (n <= 0) {
            if (n < 0 && would_block()) {
                os::sleep_ms(2);
                continue;
            }
            return false;
        }
        body.append(tmp, (size_t)n);
    }
    body.resize(len ? len : body.size());
    return true;
}

void send_all(socket_t c, const std::string& s)
{
    size_t sent = 0;
    while (sent < s.size()) {
        int n = (int)send(c, s.data() + sent, (int)(s.size() - sent), 0);
        if (n <= 0) {
            if (n < 0 && would_block()) {
                os::sleep_ms(2);
                continue;
            }
            return;
        }
        sent += (size_t)n;
    }
}

void http_reply(socket_t c, int status, const char* status_text, const std::string& ctype, const std::string& body)
{
    std::string r = util::fmt("HTTP/1.1 %d %s\r\n", status, status_text);
    r += "Content-Type: " + ctype + "\r\n";
    r += util::fmt("Content-Length: %zu\r\n", body.size());
    r += "Access-Control-Allow-Origin: *\r\n";
    r += "Access-Control-Allow-Headers: Content-Type, Mcp-Session-Id, Mcp-Protocol-Version\r\n";
    r += "Access-Control-Allow-Methods: POST, GET, OPTIONS\r\n";
    r += "Connection: close\r\n\r\n";
    r += body;
    send_all(c, r);
}

} // namespace

int mcp_serve_http(mcp_server& server, int port, const std::string& bind_addr, std::function<bool()> should_stop,
                   std::string& err, std::function<void(const std::string&)> on_listen)
{
    net_init net;
    if (!net.ok) {
        err = "network startup failed";
        return 1;
    }
    socket_t srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv == bad_socket) {
        err = "couldn't create a socket";
        return 1;
    }
    int yes = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof(yes));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    std::string host = bind_addr.empty() ? "127.0.0.1" : bind_addr;
    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1)
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(srv, (sockaddr*)&addr, sizeof(addr)) != 0 || listen(srv, 8) != 0) {
        err = util::fmt("couldn't listen on %s:%d (is the port taken?)", host.c_str(), port);
        close_socket(srv);
        return 1;
    }
    set_nonblocking(srv);
    if (on_listen)
        on_listen(util::fmt("http://%s:%d/mcp", host.c_str(), port));

    while (!(should_stop && should_stop())) {
        socket_t c = accept(srv, nullptr, nullptr);
        if (c == bad_socket) {
            os::sleep_ms(15);
            continue;
        }
        std::string method, path, body;
        if (read_http_request(c, method, path, body)) {
            if (method == "OPTIONS") {
                http_reply(c, 204, "No Content", "text/plain", "");
            } else if (method == "GET" && (path == "/health" || path == "/")) {
                http_reply(c, 200, "OK", "text/plain", "ceasta mcp\n");
            } else if (method == "POST") {
                std::string reply = server.handle(body);
                http_reply(c, 200, "OK", "application/json", reply.empty() ? std::string("{}") : reply);
            } else {
                http_reply(c, 405, "Method Not Allowed", "text/plain", "use POST\n");
            }
        }
        close_socket(c);
    }
    close_socket(srv);
    return 0;
}
