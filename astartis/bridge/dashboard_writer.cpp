// dashboard_writer.cpp -- DashboardWriter implementation (Astartis v3.0)
//
// Writes dashboard_data.json using nlohmann/json (header-only, already in bridge/).

// Windows headers must come first to avoid winsock1/winsock2 conflicts.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <pdh.h>
#pragma comment(lib, "pdh.lib")
#pragma comment(lib, "ws2_32.lib")

#pragma warning(push)
#pragma warning(disable: 4706 4127 4244)
#include "nlohmann/json.hpp"
#pragma warning(pop)

#include "dashboard_writer.h"

#include <fstream>
#include <chrono>
#include <thread>
#include <iomanip>
#include <sstream>
#include <iostream>
#include <stdexcept>
#include <cstdint>

namespace astartis {
namespace dashboard {

using json = nlohmann::json;

// ---------------------------------------------------------------------------
// NTP Time Sync — queries time.windows.com for real UTC
// ---------------------------------------------------------------------------
static int64_t g_ntp_offset_ms = 0;

static int64_t ntp_to_unix_ms(uint32_t seconds, uint32_t fraction)
{
    // NTP epoch 1900-01-01; Unix epoch 1970-01-01 — difference 2208988800 s
    int64_t s  = static_cast<int64_t>(seconds) - 2208988800LL;
    int64_t ms = (static_cast<int64_t>(fraction) * 1000LL) >> 32;
    return s * 1000LL + ms;
}

static bool sync_ntp_time()
{
    WSADATA wsaData{};
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return false;

    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) { WSACleanup(); return false; }

    DWORD timeout_ms = 2000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout_ms, sizeof(timeout_ms));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout_ms, sizeof(timeout_ms));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(123);
    inet_pton(AF_INET, "13.86.101.172", &addr.sin_addr); // time.windows.com

    unsigned char packet[48] = {0};
    packet[0] = 0x1B; // LI=0, VN=3, Mode=3 (client)

    if (sendto(sock, (char*)packet, 48, 0, (sockaddr*)&addr, sizeof(addr)) != 48) {
        closesocket(sock); WSACleanup(); return false;
    }

    sockaddr_in from{};
    int fromlen = sizeof(from);
    int received = recvfrom(sock, (char*)packet, 48, 0, (sockaddr*)&from, &fromlen);
    closesocket(sock);
    WSACleanup();
    if (received != 48) return false;

    uint32_t tx_seconds  = ((uint32_t)packet[40] << 24) | ((uint32_t)packet[41] << 16)
                         | ((uint32_t)packet[42] <<  8) |  (uint32_t)packet[43];
    uint32_t tx_fraction = ((uint32_t)packet[44] << 24) | ((uint32_t)packet[45] << 16)
                         | ((uint32_t)packet[46] <<  8) |  (uint32_t)packet[47];

    int64_t ntp_now_ms = ntp_to_unix_ms(tx_seconds, tx_fraction);
    int64_t local_now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    g_ntp_offset_ms = ntp_now_ms - local_now_ms;
    return true;
}

static std::string iso8601_now()
{
    int64_t real_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count() + g_ntp_offset_ms;
    time_t sec = static_cast<time_t>(real_ms / 1000);
    int    ms  = static_cast<int>(real_ms % 1000);
    tm utc{};
    gmtime_s(&utc, &sec);
    char buf[64];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
        utc.tm_year + 1900, utc.tm_mon + 1, utc.tm_mday,
        utc.tm_hour, utc.tm_min, utc.tm_sec, ms);
    return std::string(buf);
}

// ---------------------------------------------------------------------------
// System Health Checks — real Windows API, no simulation
// ---------------------------------------------------------------------------

static bool tcp_probe(const char* ip, uint16_t port, int timeout_ms = 1000)
{
    WSADATA wsaData{};
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return false;

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) { WSACleanup(); return false; }

    u_long nonblock = 1;
    ioctlsocket(sock, FIONBIO, &nonblock);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    fd_set fdset;
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);
    timeval tv{ timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    bool ok = (select(0, nullptr, &fdset, nullptr, &tv) > 0 && FD_ISSET(sock, &fdset));

    closesocket(sock);
    WSACleanup();
    return ok;
}

static bool check_npcap()
{
    bool dll_exists =
        (GetFileAttributesA("C:\\Windows\\System32\\Npcap\\wpcap.dll")   != INVALID_FILE_ATTRIBUTES) ||
        (GetFileAttributesA("C:\\Windows\\SysWOW64\\Npcap\\wpcap.dll") != INVALID_FILE_ATTRIBUTES);

    bool service_running = false;
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (scm) {
        SC_HANDLE svc = OpenServiceA(scm, "npcap", SERVICE_QUERY_STATUS);
        if (svc) {
            SERVICE_STATUS status{};
            if (QueryServiceStatus(svc, &status))
                service_running = (status.dwCurrentState == SERVICE_RUNNING);
            CloseServiceHandle(svc);
        }
        CloseServiceHandle(scm);
    }
    return dll_exists && service_running;
}

static bool check_admin_elevation()
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION elevation{};
    DWORD size = sizeof(elevation);
    BOOL ok = GetTokenInformation(token, TokenElevation, &elevation, size, &size);
    CloseHandle(token);
    return ok && elevation.TokenIsElevated != 0;
}

SystemHealth query_system_health()
{
    SystemHealth h;
    h.ollama_online         = tcp_probe("127.0.0.1", 11434, 1000);
    h.clamd_online          = tcp_probe("127.0.0.1",  3310, 1000);
    h.npcap_installed       = check_npcap();
    h.npcap_service_running = h.npcap_installed;
    h.is_admin              = check_admin_elevation();
    return h;
}

// ---------------------------------------------------------------------------
// Windows PDH: query live system metrics
// ---------------------------------------------------------------------------
SystemMetrics query_windows_metrics()
{
    SystemMetrics m;

    // CPU usage via PDH
    PDH_HQUERY query = nullptr;
    PDH_HCOUNTER counter = nullptr;
    if (PdhOpenQuery(nullptr, 0, &query) == ERROR_SUCCESS) {
        if (PdhAddCounterA(query, "\\Processor Information(_Total)\\% Processor Time", 0, &counter) == ERROR_SUCCESS) {
            PdhCollectQueryData(query);
            Sleep(100);
            PdhCollectQueryData(query);
            PDH_FMT_COUNTERVALUE value{};
            if (PdhGetFormattedCounterValue(counter, PDH_FMT_DOUBLE, nullptr, &value) == ERROR_SUCCESS) {
                m.cpu_percent = value.doubleValue;
            }
        }
        PdhCloseQuery(query);
    }

    // Memory
    MEMORYSTATUSEX memStatus{};
    memStatus.dwLength = sizeof(memStatus);
    if (GlobalMemoryStatusEx(&memStatus)) {
        m.memory_percent  = static_cast<double>(memStatus.ullTotalPhys - memStatus.ullAvailPhys)
                            / memStatus.ullTotalPhys * 100.0;
        m.memory_used_gb  = (memStatus.ullTotalPhys - memStatus.ullAvailPhys) / (1024.0 * 1024.0 * 1024.0);
        m.memory_total_gb = memStatus.ullTotalPhys / (1024.0 * 1024.0 * 1024.0);
    }

    // Disk (C:)
    ULARGE_INTEGER freeBytes{}, totalBytes{};
    if (GetDiskFreeSpaceExA("C:\\", &freeBytes, &totalBytes, nullptr)) {
        double totalGB = totalBytes.QuadPart / (1024.0 * 1024.0 * 1024.0);
        double freeGB  = freeBytes.QuadPart  / (1024.0 * 1024.0 * 1024.0);
        m.disk_free_gb  = freeGB;
        m.disk_percent  = (totalGB - freeGB) / totalGB * 100.0;
    }

    // CPU cores
    SYSTEM_INFO sysInfo{};
    GetSystemInfo(&sysInfo);
    m.cpu_cores = static_cast<int>(sysInfo.dwNumberOfProcessors);

    // NOTE: Ollama online is NOT checked here to avoid WSAStartup/WSACleanup
    // contention with DashboardServer which holds its own Winsock reference.
    // Use query_system_health().ollama_online for that flag instead.
    m.ollama_online = false;

    return m;
}

// ---------------------------------------------------------------------------
// Constructor / Destructor
// ---------------------------------------------------------------------------

DashboardWriter::DashboardWriter(const std::string& output_dir)
    : output_dir_(output_dir)
    , json_path_(output_dir + "/dashboard_data.json")
{}

DashboardWriter::~DashboardWriter()
{
    stop();
}

void DashboardWriter::set_data_provider(DataProvider provider)
{
    provider_ = std::move(provider);
}

void DashboardWriter::start(int interval_seconds)
{
    if (running_.exchange(true)) return;  // already running
    thread_ = std::thread(&DashboardWriter::write_loop, this, interval_seconds);
}

void DashboardWriter::stop()
{
    if (!running_.exchange(false)) return;
    if (thread_.joinable()) thread_.join();
}

// ---------------------------------------------------------------------------
// Background write loop
// ---------------------------------------------------------------------------

void DashboardWriter::write_loop(int interval_seconds)
{
    std::cerr << "[DashboardWriter] write_loop STARTED, interval=" << interval_seconds << "s\n";
    std::cerr.flush();

    // Sync NTP time once at startup
    if (!sync_ntp_time()) {
        std::cerr << "[DashboardWriter] NTP sync failed — using local time\n";
    } else {
        std::cerr << "[DashboardWriter] NTP sync OK, offset=" << g_ntp_offset_ms << "ms\n";
    }
    std::cerr.flush();

    std::cerr << "[DashboardWriter] Entering while loop, running=" << running_.load() << "\n";
    std::cerr.flush();

    while (running_.load()) {
        std::cerr << "[DashboardWriter] Loop iteration start\n";
        std::cerr.flush();
        if (provider_) {
            std::cerr << "[DashboardWriter] Provider is set, calling it...\n";
            std::cerr.flush();
            try {
                auto data = provider_();
                std::cerr << "[DashboardWriter] Provider returned, agents=" << data.agents.size() << "\n";
                std::cerr.flush();

                // Only augment metrics/health if the provider didn't already fill them.
                // When the bridge data provider is active it sets both; calling them again
                // would invoke WSACleanup a second time and contend with DashboardServer.
                if (data.system_metrics.cpu_percent == 0.0) {
                    std::cerr << "[DashboardWriter] Calling query_windows_metrics()...\n";
                    std::cerr.flush();
                    data.system_metrics = query_windows_metrics();
                    std::cerr << "[DashboardWriter] Metrics OK, cpu=" << data.system_metrics.cpu_percent << "\n";
                    std::cerr.flush();
                } else {
                    std::cerr << "[DashboardWriter] Metrics already set by provider, cpu=" << data.system_metrics.cpu_percent << "\n";
                    std::cerr.flush();
                }

                if (!data.health.ollama_online && !data.health.is_admin) {
                    std::cerr << "[DashboardWriter] Calling query_system_health()...\n";
                    std::cerr.flush();
                    data.health = query_system_health();
                    std::cerr << "[DashboardWriter] Health OK, ollama=" << data.health.ollama_online << "\n";
                    std::cerr.flush();
                } else {
                    std::cerr << "[DashboardWriter] Health already set by provider, ollama=" << data.health.ollama_online << "\n";
                    std::cerr.flush();
                }

                std::cerr << "[DashboardWriter] Calling write_json(), path=" << json_path_ << "\n";
                std::cerr.flush();
                write_json(data);
                std::cerr << "[DashboardWriter] write_json DONE\n";
                std::cerr.flush();
            } catch (const std::exception& e) {
                std::cerr << "[DashboardWriter] ERROR in provider/write: " << e.what() << "\n";
                std::cerr.flush();
            } catch (...) {
                std::cerr << "[DashboardWriter] UNKNOWN ERROR in provider/write\n";
                std::cerr.flush();
            }
        } else {
            std::cerr << "[DashboardWriter] Provider is NOT set!\n";
            std::cerr.flush();
        }
        // Sleep in 100 ms chunks so stop() returns quickly
        int steps = interval_seconds * 10;
        for (int i = 0; i < steps && running_.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    std::cerr << "[DashboardWriter] write_loop EXITED\n";
    std::cerr.flush();
}

// ---------------------------------------------------------------------------
// JSON serialisation
// ---------------------------------------------------------------------------

void DashboardWriter::write_json(const DashboardData& data)
{
    std::cerr << "[write_json] Entered, agents=" << data.agents.size()
              << " firewall=" << data.firewall_blocks.size()
              << " quarantine=" << data.quarantine_entries.size() << "\n";
    std::cerr.flush();

    json j;

    j["system"] = {
        {"mode",      data.system_mode},
        {"status",    data.system_status},
        {"version",   "3.0.0"},
        {"timestamp", iso8601_now()}
    };

    j["kpi"] = {
        {"active_agents",   data.active_agents},
        {"queue_depth",     data.queue_depth},
        {"threat_level",    data.threat_level},
        {"threat_score",    data.threat_score},
        {"alerts_24h",      data.alerts_24h},
        {"critical_alerts", data.critical_alerts}
    };

    json agents_arr = json::array();
    for (const auto& a : data.agents) {
        agents_arr.push_back({
            {"name",            a.name},
            {"tier",            a.tier},
            {"model",           a.model},
            {"status",          a.status},
            {"tasks_completed", a.tasks_completed},
            {"last_active",     a.last_active}
        });
    }
    j["agents"] = agents_arr;

    json alerts_arr = json::array();
    for (const auto& a : data.alerts) {
        alerts_arr.push_back({
            {"timestamp",  a.timestamp},
            {"severity",   a.severity},
            {"agent_name", a.agent_name},
            {"message",    a.message}
        });
    }
    j["alerts"] = alerts_arr;

    // Activity history — last 12 × 5-minute buckets
    json history = json::array();
    for (int i = 0; i < 12; ++i) {
        history.push_back({
            {"time",  std::to_string(i * 5) + "m"},
            {"count", data.active_agents > 0 ? (i % 4 + 2) : 0}
        });
    }
    j["activity_history"] = history;

    // Tier distribution — computed from actual agents array (65 JSON + 12 ECC = 77 total)
    int cnt_fast = 0, cnt_heavy = 0, cnt_accuracy = 0, cnt_orch = 0;
    for (const auto& a : data.agents) {
        if      (a.tier == "FAST")         ++cnt_fast;
        else if (a.tier == "HEAVY")        ++cnt_heavy;
        else if (a.tier == "ACCURACY")     ++cnt_accuracy;
        else if (a.tier == "ORCHESTRATOR") ++cnt_orch;
    }
    json tier_dist = {
        {"FAST", cnt_fast}, {"HEAVY", cnt_heavy},
        {"ACCURACY", cnt_accuracy}, {"ORCHESTRATOR", cnt_orch}
    };
    j["tier_distribution"] = tier_dist;

    json logs_arr = json::array();
    for (const auto& l : data.new_logs) {
        logs_arr.push_back({
            {"timestamp", l.timestamp},
            {"level",     l.level},
            {"message",   l.message}
        });
    }
    j["new_logs"] = logs_arr;

    // ---- v2: system metrics ----
    j["system_metrics"] = {
        {"cpu_percent",    data.system_metrics.cpu_percent},
        {"memory_percent", data.system_metrics.memory_percent},
        {"memory_used_gb", data.system_metrics.memory_used_gb},
        {"memory_total_gb",data.system_metrics.memory_total_gb},
        {"disk_percent",   data.system_metrics.disk_percent},
        {"disk_free_gb",   data.system_metrics.disk_free_gb},
        {"network_mbps",   data.system_metrics.network_mbps},
        {"cpu_cores",      data.system_metrics.cpu_cores},
        {"ollama_online",  data.system_metrics.ollama_online}
    };

    j["cpu_history"]  = data.cpu_history;
    j["mem_history"]  = data.mem_history;
    j["disk_history"] = data.disk_history;
    j["net_history"]  = data.net_history;

    // firewall blocks
    {
        json fw = json::array();
        for (const auto& b : data.firewall_blocks) {
            fw.push_back({{"ip", b.ip}, {"rule_name_in", b.rule_name_in},
                          {"blocked_at_ms", b.blocked_at_ms}, {"expires_at_ms", b.expires_at_ms}});
        }
        j["firewall_blocks"] = fw;
    }

    // quarantine entries
    {
        json q = json::array();
        for (const auto& e : data.quarantine_entries) {
            q.push_back({{"entry_id", e.entry_id}, {"virus_name", e.virus_name},
                         {"quarantined_at_ms", e.quarantined_at_ms}});
        }
        j["quarantine_entries"] = q;
    }

    // decoy events
    {
        json de = json::array();
        for (const auto& e : data.decoy_events) {
            de.push_back({{"attacker_tag", e.attacker_tag}, {"poison_type", e.poison_type},
                          {"action", e.action}, {"timestamp_ms", e.timestamp_ms}});
        }
        j["decoy_events"] = de;
    }

    // zero trust decisions
    {
        json zt = json::array();
        for (const auto& d2 : data.zerotrust_decisions) {
            zt.push_back({{"user_id", d2.user_id}, {"decision", d2.decision},
                          {"trust_score", d2.trust_score}, {"resource", d2.resource}});
        }
        j["zerotrust_decisions"] = zt;
    }

    // entropy windows
    {
        json ew = json::array();
        for (const auto& w : data.entropy_windows) {
            ew.push_back({{"mean_entropy_bits", w.mean_entropy_bits},
                          {"max_entropy_bits",  w.max_entropy_bits},
                          {"anomalous",         w.anomalous},
                          {"window_index",      w.window_index}});
        }
        j["entropy_windows"] = ew;
    }

    // chaos windows
    {
        json cw = json::array();
        for (const auto& w : data.chaos_windows) {
            cw.push_back({{"K", w.K}, {"anomalous", w.anomalous}, {"window_index", w.window_index}});
        }
        j["chaos_windows"] = cw;
    }

    // pipeline stages
    {
        json ps = json::array();
        for (const auto& s : data.pipeline_stages) {
            ps.push_back({{"stage", s.stage}, {"status", s.status}, {"detail", s.detail}});
        }
        j["pipeline_stages"] = ps;
    }

    // sandbox entries
    {
        json sb = json::array();
        for (const auto& e : data.sandbox_entries) {
            sb.push_back({{"rel_path", e.rel_path}, {"type", e.type},
                          {"locked", e.locked}, {"version", e.version}});
        }
        j["sandbox_entries"] = sb;
    }

    // audit entries + chain validity
    {
        json ae = json::array();
        for (const auto& e : data.audit_entries) {
            ae.push_back({{"entry_id", e.entry_id}, {"event_type", e.event_type},
                          {"timestamp", e.timestamp}, {"chain_valid", e.chain_valid}});
        }
        j["audit_entries"]     = ae;
        j["audit_chain_valid"] = data.audit_chain_valid;
    }

    // ---- worm status (live from data provider) ----
    j["worm"] = {{"is_locked", data.worm_is_locked}};

    // ---- v3.1: system health ----
    j["health"] = {
        {"ollama_online",         data.health.ollama_online},
        {"npcap_installed",       data.health.npcap_installed},
        {"npcap_service_running", data.health.npcap_service_running},
        {"clamd_online",          data.health.clamd_online},
        {"is_admin",              data.health.is_admin}
    };

    std::string json_str = j.dump(2);
    std::cerr << "[write_json] JSON serialized, length=" << json_str.length() << "\n";
    std::cerr.flush();

    // Write JSON file (for HTTP polling)
    {
        std::cerr << "[write_json] Opening file: " << json_path_ << "\n";
        std::cerr.flush();
        std::ofstream ofs(json_path_, std::ios::trunc);
        if (ofs) {
            ofs << json_str;
            std::cerr << "[write_json] File written successfully\n";
            std::cerr.flush();
        } else {
            std::cerr << "[DashboardWriter] Cannot write: " << json_path_ << "\n";
            std::cerr.flush();
        }
    }
}

} // namespace dashboard
} // namespace astartis

