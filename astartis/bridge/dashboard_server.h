// dashboard_server.h — Minimal HTTP server for Astartis Dashboard
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
    void handle_exec(uintptr_t client, const std::string& req);
    void send_response(uintptr_t client, const std::string& status,
                       const std::string& body, const std::string& content_type);
    std::string exec_shell(const std::string& cmd);

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

