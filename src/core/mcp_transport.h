#pragma once
#include <atomic>
#include <cstdint>
#include <functional>
#include <string>

// transports for the mcp server. each reads a json-rpc message, calls handle, writes the reply.

class mcp_server;

// stdio: reads requests from stdin, writes replies to stdout. accepts both framings a client
// might use - LSP style "Content-Length:" headers, or one json object per line - and answers in
// kind. blocks until stdin closes. this is what claude desktop / claude code / cursor launch.
int mcp_serve_stdio(mcp_server& server);

// localhost http on 127.0.0.1:<port>. one request per POST (the "streamable http" shape without
// server-sent events), plus GET /health. loops until should_stop returns true. returns 0, or
// non-zero if the socket couldn't be opened (err is set).
int mcp_serve_http(mcp_server& server, int port, const std::string& bind_addr,
                   std::function<bool()> should_stop, std::string& err,
                   std::function<void(const std::string&)> on_listen = {});
