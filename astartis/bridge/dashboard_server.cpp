// dashboard_server.cpp — Minimal HTTP server implementation for Astartis Dashboard

// Windows headers must be first
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")

#include "dashboard_server.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <string>

namespace astartis {
namespace dashboard {

namespace {

bool ascii_iequals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        char x = a[i], y = b[i];
        if (x >= 'A' && x <= 'Z') x = static_cast<char>(x - 'A' + 'a');
        if (y >= 'A' && y <= 'Z') y = static_cast<char>(y - 'A' + 'a');
        if (x != y) return false;
    }
    return true;
}

// Value of the first header called `name` (case-insensitive), trimmed;
// empty if absent.  `headers_start` is the offset just past the request line.
std::string header_value(const std::string& req, size_t headers_start, const std::string& name) {
    size_t pos = headers_start;
    while (pos < req.size()) {
        size_t eol = req.find("\r\n", pos);
        if (eol == std::string::npos || eol == pos) break;  // end of headers
        std::string line = req.substr(pos, eol - pos);
        pos = eol + 2;
        size_t colon = line.find(':');
        if (colon == std::string::npos || !ascii_iequals(line.substr(0, colon), name)) continue;
        size_t first = line.find_first_not_of(" \t", colon + 1);
        if (first == std::string::npos) return "";
        size_t last = line.find_last_not_of(" \t");
        return line.substr(first, last - first + 1);
    }
    return "";
}

} // namespace

DashboardServer::DashboardServer(const std::string& static_dir,
                                 const std::string& json_path,
                                 uint16_t port)
    : static_dir_(static_dir), json_path_(json_path), port_(port)
    , listen_sock_((uintptr_t)INVALID_SOCKET) {}

DashboardServer::~DashboardServer() { stop(); }

void DashboardServer::start() {
    running_ = true;
    thread_ = std::thread([this]() { run(); });
}

void DashboardServer::stop() {
    running_ = false;
    if (listen_sock_ != (uintptr_t)INVALID_SOCKET) {
        closesocket((SOCKET)listen_sock_);
        listen_sock_ = (uintptr_t)INVALID_SOCKET;
    }
    if (thread_.joinable()) thread_.join();
}

void DashboardServer::run() {
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::cerr << "[DashboardServer] WSAStartup failed\n"; return;
    }

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        std::cerr << "[DashboardServer] socket() failed\n"; WSACleanup(); return;
    }
    listen_sock_ = (uintptr_t)sock;

    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse));

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port_);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(sock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        std::cerr << "[DashboardServer] bind() failed on port " << port_ << "\n";
        closesocket(sock); WSACleanup(); return;
    }
    if (listen(sock, 10) == SOCKET_ERROR) {
        std::cerr << "[DashboardServer] listen() failed\n";
        closesocket(sock); WSACleanup(); return;
    }

    std::cerr << "[DashboardServer] Running on http://127.0.0.1:" << port_ << "/\n";

    while (running_) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(sock, &fds);
        timeval tv{0, 100000}; // 100 ms poll
        if (select(0, &fds, nullptr, nullptr, &tv) <= 0) continue;

        SOCKET client = accept(sock, nullptr, nullptr);
        if (client == INVALID_SOCKET) continue;
        handle_client((uintptr_t)client);
        closesocket(client);
    }

    closesocket(sock);
    listen_sock_ = (uintptr_t)INVALID_SOCKET;
    WSACleanup();
}

void DashboardServer::handle_client(uintptr_t client) {
    char buf[16384]{};
    int received = recv((SOCKET)client, buf, (int)sizeof(buf) - 1, 0);
    if (received <= 0) return;
    buf[received] = '\0';

    std::string req(buf);
    size_t eol = req.find("\r\n");
    if (eol == std::string::npos) return;
    std::string first_line = req.substr(0, eol);

    // Request line: METHOD SP request-target SP HTTP-version
    size_t sp1 = first_line.find(' ');
    size_t sp2 = (sp1 == std::string::npos) ? std::string::npos : first_line.find(' ', sp1 + 1);
    if (sp2 == std::string::npos) {
        send_response(client, "400 Bad Request", "Bad request", "text/plain"); return;
    }
    std::string method = first_line.substr(0, sp1);
    std::string target = first_line.substr(sp1 + 1, sp2 - sp1 - 1);

    // Read-only: the dashboard only loads its own files and polls JSON.
    // There is deliberately no CORS support and no command endpoint.
    if (method != "GET") {
        send_response(client, "405 Method Not Allowed", "Method not allowed", "text/plain",
                      "Allow: GET\r\n");
        return;
    }

    // Only answer requests addressed to this loopback listener, so a page on
    // another domain cannot reach it through DNS rebinding.
    if (!is_allowed_host(header_value(req, eol + 2, "Host"))) {
        send_response(client, "403 Forbidden", "Forbidden", "text/plain"); return;
    }

    std::string path = target.substr(0, target.find('?'));
    if (path == "/dashboard_data.json") {
        serve_file(client, json_path_, "application/json"); return;
    }
    if (path == "/" || path == "/index.html") {
        serve_file(client, static_dir_ + "/index.html", "text/html"); return;
    }
    if (path == "/style.css") {
        serve_file(client, static_dir_ + "/style.css", "text/css"); return;
    }
    if (path == "/script.js") {
        serve_file(client, static_dir_ + "/script.js", "application/javascript"); return;
    }

    send_response(client, "404 Not Found", "Not found", "text/plain");
}

bool DashboardServer::is_allowed_host(const std::string& host) const {
    const std::string port = ":" + std::to_string(port_);
    return ascii_iequals(host, "127.0.0.1" + port) || ascii_iequals(host, "localhost" + port);
}

void DashboardServer::serve_file(uintptr_t client, const std::string& path,
                                  const std::string& content_type) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        send_response(client, "404 Not Found", "File not found", "text/plain"); return;
    }
    std::string content((std::istreambuf_iterator<char>(f)),
                         std::istreambuf_iterator<char>());
    send_response(client, "200 OK", content, content_type);
}

void DashboardServer::send_response(uintptr_t client, const std::string& status,
                                     const std::string& body,
                                     const std::string& content_type,
                                     const std::string& extra_headers) {
    std::string resp;
    resp.reserve(512 + body.size());
    resp  = "HTTP/1.1 " + status + "\r\n";
    resp += "Content-Type: "   + content_type + "; charset=utf-8\r\n";
    resp += extra_headers;
    resp += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    resp += "Connection: close\r\n\r\n";
    resp += body;
    send((SOCKET)client, resp.c_str(), (int)resp.size(), 0);
}

} // namespace dashboard
} // namespace astartis

