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
#include <vector>
#include <string>
#include <cstdio>

namespace astartis {
namespace dashboard {

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

    // CORS preflight
    if (first_line.find("OPTIONS") == 0) {
        send_response(client, "204 No Content", "", "text/plain"); return;
    }

    if (first_line.find("GET /dashboard_data.json") != std::string::npos) {
        serve_file(client, json_path_, "application/json"); return;
    }
    if (first_line.find("GET / ") == 0 ||
        first_line.find("GET /index.html") != std::string::npos) {
        serve_file(client, static_dir_ + "/index.html", "text/html"); return;
    }
    if (first_line.find("GET /style.css") != std::string::npos) {
        serve_file(client, static_dir_ + "/style.css", "text/css"); return;
    }
    if (first_line.find("GET /script.js") != std::string::npos) {
        serve_file(client, static_dir_ + "/script.js", "application/javascript"); return;
    }
    if (first_line.find("POST /exec") != std::string::npos) {
        handle_exec(client, req); return;
    }

    send_response(client, "404 Not Found", "Not found", "text/plain");
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

void DashboardServer::handle_exec(uintptr_t client, const std::string& req) {
    size_t body_start = req.find("\r\n\r\n");
    if (body_start == std::string::npos) {
        send_response(client, "400 Bad Request", "Missing body", "text/plain"); return;
    }
    body_start += 4;
    std::string body = req.substr(body_start);

    // Simple "cmd":"..." extractor — no external JSON lib needed
    size_t ck = body.find("\"cmd\"");
    if (ck == std::string::npos) {
        send_response(client, "400 Bad Request", "Missing cmd", "text/plain"); return;
    }
    size_t q1 = body.find('"', ck + 5);
    if (q1 == std::string::npos) { send_response(client, "400 Bad Request", "Malformed", "text/plain"); return; }
    size_t q2 = body.find('"', q1 + 1);
    if (q2 == std::string::npos) { send_response(client, "400 Bad Request", "Malformed", "text/plain"); return; }
    std::string cmd = body.substr(q1 + 1, q2 - q1 - 1);

    // Whitelist — only these prefixes are executable
    static const std::vector<std::string> whitelist = {
        "ipconfig", "tasklist", "netstat", "systeminfo", "getmac",
        "whoami", "hostname", "ver", "netsh", "Get-", "get-", "ping",
        "sc ", "sc\t",        // service control (sc query, sc start, etc.)
        "arp",               // arp -a
        "route",             // route print
        "nslookup",          // DNS lookup
        "tracert",           // traceroute
        "pathping",          // path ping
        "wmic",              // WMI queries
        "powercfg",          // power config
        "bcdedit",           // boot config
        "net ",  "net\t",    // net use, net view, net user
        "dir",               // directory listing
        "date /t",           // system date
        "time /t",           // system time
        "set",               // environment variables
        "echo",              // echo
        "type",              // file contents
        "where",             // find executable paths
    };
    bool allowed = false;
    for (const auto& w : whitelist) {
        if (cmd.find(w) == 0) { allowed = true; break; }
    }

    std::string output;
    if (allowed) {
        if (cmd.find("Get-") == 0 || cmd.find("get-") == 0) {
            output = exec_shell("powershell -NoProfile -Command \"" + cmd + "\" 2>&1");
        } else {
            output = exec_shell("cmd /c " + cmd + " 2>&1");
        }
    } else {
        output = "Error: Command not in whitelist.\n"
                 "Allowed: ipconfig, tasklist, netstat, systeminfo, getmac, whoami,\n"
                 "         hostname, ver, netsh, ping, arp, route, nslookup, tracert,\n"
                 "         pathping, wmic, net, sc, dir, date /t, time /t, set,\n"
                 "         Get-Process, Get-Service, Get-NetAdapter, Get-NetIPAddress, ...";
    }

    // JSON-escape the output
    std::string escaped;
    escaped.reserve(output.size() * 2);
    for (char c : output) {
        switch (c) {
            case '"':  escaped += "\\\""; break;
            case '\\': escaped += "\\\\"; break;
            case '\n': escaped += "\\n";  break;
            case '\r': escaped += "\\r";  break;
            case '\t': escaped += "\\t";  break;
            default:
                if ((unsigned char)c < 32) escaped += ' ';
                else escaped += c;
        }
    }
    // Truncate at 20 KB
    if (escaped.size() > 20000) {
        escaped = escaped.substr(0, 20000) + "\\n... (truncated at 20KB)";
    }

    std::string json_body = "{\"output\":\"" + escaped + "\"}";
    send_response(client, "200 OK", json_body, "application/json");
}

std::string DashboardServer::exec_shell(const std::string& cmd) {
    FILE* pipe = _popen(cmd.c_str(), "r");
    if (!pipe) return "Error: failed to execute command";
    char buffer[4096];
    std::string result;
    while (fgets(buffer, (int)sizeof(buffer), pipe) != nullptr) {
        result += buffer;
    }
    _pclose(pipe);
    return result;
}

void DashboardServer::send_response(uintptr_t client, const std::string& status,
                                     const std::string& body,
                                     const std::string& content_type) {
    std::string resp;
    resp.reserve(512 + body.size());
    resp  = "HTTP/1.1 " + status + "\r\n";
    resp += "Content-Type: "   + content_type + "; charset=utf-8\r\n";
    resp += "Access-Control-Allow-Origin: *\r\n";
    resp += "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n";
    resp += "Access-Control-Allow-Headers: Content-Type\r\n";
    resp += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    resp += "Connection: close\r\n\r\n";
    resp += body;
    send((SOCKET)client, resp.c_str(), (int)resp.size(), 0);
}

} // namespace dashboard
} // namespace astartis

