// dashboard_server.h — Minimal HTTP server for Astartis Dashboard
//
// Read-only by design: it serves the static dashboard files and
// dashboard_data.json over GET on 127.0.0.1, and nothing else.  It never
// executes commands; host diagnostics belong to the bridge's stdio
// `terminal_execute` allowlist, which the Phoenix dashboard uses.
#ifndef DASHBOARD_SERVER_H
#define DASHBOARD_SERVER_H

#include <string>
#include <thread>
#include <atomic>

namespace astartis {
namespace dashboard {

class DashboardServer {
public:
    explicit DashboardServer(const std::string& static_dir,
                             const std::string& json_path,
                             uint16_t port = 9876);
    ~DashboardServer();

    DashboardServer(const DashboardServer&) = delete;
    DashboardServer& operator=(const DashboardServer&) = delete;

    void start();
    void stop();
    bool is_running() const { return running_.load(); }

private:
    void run();
    void handle_client(uintptr_t client);
    void serve_file(uintptr_t client, const std::string& path, const std::string& content_type);
    bool is_allowed_host(const std::string& host) const;
    void send_response(uintptr_t client, const std::string& status,
                       const std::string& body, const std::string& content_type,
                       const std::string& extra_headers = "");

    std::string static_dir_;
    std::string json_path_;
    uint16_t port_;
    std::atomic<bool> running_{false};
    std::thread thread_;
    uintptr_t listen_sock_{(uintptr_t)~0};
};

} // namespace dashboard
} // namespace astartis

#endif // DASHBOARD_SERVER_H

