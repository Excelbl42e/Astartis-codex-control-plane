// demo_dashboard_data.cpp -- Standalone demo data generator for Astartis dashboard (v3.0)
//
// Writes dashboard/dashboard_data.json every 5 seconds with realistic simulated data.
// Run this to preview the dashboard without the full C++ system running.
//
// Usage: demo_dashboard_data.exe [output_dir]
//        default output_dir = "dashboard"

// Windows headers must come first — required for GetModuleFileNameA, GetFileAttributesA, etc.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "dashboard_writer.h"
#include "dashboard_server.h"

#include <iostream>
#include <thread>
#include <chrono>
#include <random>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <string>
#include <vector>
#include <cstdlib>

using namespace astartis::dashboard;

// Forward declaration — query_system_health() is defined in dashboard_writer.cpp
// (static linkage removed for this symbol so it is visible across TUs)
namespace astartis { namespace dashboard { SystemHealth query_system_health(); } }

static std::string iso_now()
{
    auto now = std::chrono::system_clock::now();
    auto t   = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    gmtime_s(&tm, &t);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

// -----------------------------------------------------------------------
// Agent catalogue — mirrors the real 65 JSON + 12 ECC = 77 agents
// -----------------------------------------------------------------------
static const char* FAST_AGENTS[] = {
    "alert_triage","log_parser","status_checker","ping_monitor",
    "port_scanner_fast","dns_checker","arp_monitor","heartbeat_agent"
};
static const char* HEAVY_AGENTS[] = {
    "siem_analyst","threat_hunter","compliance_monitor","vulnerability_mgr",
    "ioc_manager","security_reporter","threat_intel","forensics_investigator",
    "incident_responder_soc","patch_manager","identity_auditor","network_monitor",
    "access_reviewer","config_auditor","anomaly_detector","phishing_analyst",
    "malware_analyst","api_tester","blue_team_def","cloud_sec_tester",
    "container_sec","crypto_analyst","forensics_agent","ics_scada_tester",
    "mobile_app_tester","osint_gatherer","physical_security","recon_agent",
    "social_engineer","vuln_scanner","web_app_tester","wireless_tester",
    "code_reviewer","security_reviewer","report_generator"
};
static const char* ACCURACY_AGENTS[] = {
    "zero_trust_engineer","ransomware_hunter","quantum_crypto_analyst",
    "api_security_guru","cloud_native_defender","threat_modeler_acc",
    "exploit_dev","risk_quantifier","supply_chain_auditor","deception_specialist",
    "attribution_analyst","malware_reverser","firmware_auditor","ai_red_teamer",
    "ot_security_analyst","identity_architect"
};
static const char* ORCHESTRATOR_AGENTS[] = {
    "incident_responder","breach_simulator","red_team_coord",
    "purple_team","chief_orchestrator","threat_modeler"
};
static const char* ECC_AGENTS[] = {
    "cpp_security_reviewer","code_security_auditor","ai_model_security_evaluator",
    "autonomous_response_operator","security_e2e_tester","build_security_analyzer",
    "runtime_threat_monitor","memory_forensics_agent","kernel_security_auditor",
    "supply_chain_scanner","zero_day_researcher","exploit_chain_analyst"
};

int main(int argc, char* argv[])
{
    // Resolve output directory relative to the executable, not the working directory
    std::string output_dir;
    if (argc > 1) {
        output_dir = argv[1];
    } else {
        // Get the directory containing this executable
        char exe_path[MAX_PATH];
        DWORD len = GetModuleFileNameA(nullptr, exe_path, MAX_PATH);
        if (len > 0 && len < MAX_PATH) {
            std::string exe_dir(exe_path);
            size_t last_slash = exe_dir.find_last_of("\\/");
            if (last_slash != std::string::npos) exe_dir = exe_dir.substr(0, last_slash);

            // Walk up the tree looking for a directory that contains 'dashboard/'
            std::string search_dir = exe_dir;
            for (int up = 0; up < 6; ++up) {
                std::string candidate = search_dir + "\\dashboard";
                DWORD attr = GetFileAttributesA(candidate.c_str());
                if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)) {
                    output_dir = candidate;
                    break;
                }
                size_t slash = search_dir.find_last_of("\\/");
                if (slash == std::string::npos || slash < 3) break;
                search_dir = search_dir.substr(0, slash);
            }

            // Fallback: resolve relative path via GetFullPathNameA
            if (output_dir.empty()) {
                char resolved[MAX_PATH];
                std::string rel = exe_dir + "\\..\\..\\..\\dashboard";
                if (GetFullPathNameA(rel.c_str(), MAX_PATH, resolved, nullptr)) {
                    output_dir = resolved;
                } else {
                    output_dir = exe_dir + "\\..\\..\\..\\dashboard";
                }
            }
        }
    }
    if (output_dir.empty()) output_dir = "dashboard";

    // Create the output directory if it doesn't exist
    DWORD attr = GetFileAttributesA(output_dir.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
        if (!CreateDirectoryA(output_dir.c_str(), nullptr)) {
            std::cerr << "[Demo] ERROR: Cannot create directory: " << output_dir << "\n";
            std::cerr << "[Demo] GetLastError: " << GetLastError() << "\n";
            return 1;
        }
    }
    std::cout << "[Demo] Starting Astartis dashboard data generator\n";
    std::cout << "[Demo] Output: " << output_dir << "/dashboard_data.json\n";
    std::cout << "[Demo] Interval: 5 seconds\n";
    std::cout << "[Demo] Press Ctrl+C to stop.\n\n";

    std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<int> d100(0, 99);

    DashboardWriter writer(output_dir);

    writer.set_data_provider([&]() -> DashboardData {
        DashboardData d;
        d.system_mode   = "FULL";
        d.system_status = "online";
        d.queue_depth   = d100(rng) % 8;

        const char* threat_levels[] = {"LOW","LOW","LOW","MEDIUM","HIGH","CRITICAL"};
        int threat_roll = d100(rng);
        d.threat_level  = threat_levels[threat_roll / 20];  // mostly LOW/MEDIUM
        d.threat_score  = d100(rng) % 60;
        d.alerts_24h    = d100(rng) % 15;
        d.critical_alerts = (d100(rng) > 85) ? (d100(rng) % 3) : 0;

        // Build 77 agents
        const char* statuses[] = {"online","online","online","online","busy","offline"};
        auto add_agents = [&](const char** names, int count, const char* tier, const char* model) {
            for (int i = 0; i < count; ++i) {
                AgentStatus a;
                a.name            = names[i];
                a.tier            = tier;
                a.model           = model;
                a.status          = statuses[d100(rng) % 6];
                a.tasks_completed = d100(rng);
                a.last_active     = iso_now();
                d.agents.push_back(a);
            }
        };
        add_agents(FAST_AGENTS,        8,  "FAST",         "granite4.0-h-micro");
        add_agents(HEAVY_AGENTS,       35, "HEAVY",        "granite4.1-8b");
        add_agents(ACCURACY_AGENTS,    16, "ACCURACY",     "granite4.1-8b");
        add_agents(ORCHESTRATOR_AGENTS, 6, "ORCHESTRATOR", "granite4.1-8b");
        add_agents(ECC_AGENTS,         12, "ACCURACY",     "granite4.1-8b");

        d.active_agents = 0;
        for (const auto& a : d.agents)
            if (a.status == "online" || a.status == "busy") ++d.active_agents;

        // Generate alerts
        const char* sevs[]       = {"CRITICAL","HIGH","MEDIUM","LOW","LOW","LOW"};
        const char* alert_msgs[] = {
            "Brute-force SSH from 185.220.101.1 (Tor exit node)",
            "Port scan detected — 10.0.0.55 scanned 1024 ports",
            "Malware signature match: Ransomware.WannaCry variant",
            "Anomalous outbound DNS query to C2 domain",
            "Failed login attempt — admin account (5× in 60s)",
            "Lateral movement: SMB relay from 10.0.1.12",
            "File encryption behaviour detected — monitoring",
            "Decoy credential accessed — honeypot triggered",
        };
        for (int i = 0; i < 8; ++i) {
            Alert a;
            a.timestamp  = iso_now();
            a.severity   = sevs[d100(rng) % 6];
            a.agent_name = d.agents[d100(rng) % (int)d.agents.size()].name;
            a.message    = alert_msgs[i % 8];
            d.alerts.push_back(a);
        }

        // Log entry for this tick
        const char* log_msgs[] = {
            "Dashboard data updated",
            "Threat feed synchronised (65 IOCs)",
            "Agent health check passed — 77/77 responsive",
            "Queue depth nominal",
            "Keep-alive pings sent to granite4.0-h-micro, granite4.1-8b",
        };
        LogEntry l;
        l.timestamp = iso_now();
        l.level     = "INFO";
        l.message   = log_msgs[d100(rng) % 5];
        d.new_logs.push_back(l);

        // ---- v2: system metrics (simulated — real values come from query_windows_metrics in write_loop) ----
        d.system_metrics.cpu_percent      = 15.0 + (d100(rng) % 60);
        d.system_metrics.memory_percent   = 30.0 + (d100(rng) % 40);
        d.system_metrics.memory_used_gb   = 8.0  + (d100(rng) % 8);
        d.system_metrics.memory_total_gb  = 32.0;
        d.system_metrics.disk_percent     = 45.0 + (d100(rng) % 30);
        d.system_metrics.disk_free_gb     = 120.0 + (d100(rng) % 50);
        d.system_metrics.cpu_cores        = 8;
        d.system_metrics.network_mbps     = static_cast<double>(d100(rng) % 100);
        d.system_metrics.ollama_online    = (d100(rng) > 20);

        // History arrays (20 samples each)
        for (int i = 0; i < 20; ++i) {
            d.cpu_history.push_back(10.0 + (d100(rng) % 70));
            d.mem_history.push_back(25.0 + (d100(rng) % 50));
            d.disk_history.push_back(40.0 + (d100(rng) % 30));
            d.net_history.push_back(static_cast<double>(d100(rng) % 100));
        }

        // Get now in ms
        auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        // Firewall blocks
        for (int i = 0; i < 3; ++i) {
            FirewallBlockData b;
            b.ip           = "192.168.1." + std::to_string(100 + i);
            b.rule_name_in = "Astartis-Block-" + b.ip + "-in";
            b.blocked_at_ms = now_ms - 300000;
            b.expires_at_ms = now_ms + 600000;
            d.firewall_blocks.push_back(b);
        }

        // Quarantine entries
        for (int i = 0; i < 2; ++i) {
            QuarantineEntryData e;
            e.entry_id           = "Q-" + std::to_string(i + 1);
            e.virus_name         = "Trojan.FakeAV-" + std::to_string(i + 1);
            e.quarantined_at_ms  = now_ms - 3600000;
            d.quarantine_entries.push_back(e);
        }

        // Decoy events
        const char* poison_types[] = {"DATA_VALUATION", "CREDENTIAL", "LATERAL_MOVEMENT"};
        const char* decoy_actions[] = {"read", "write_attempt"};
        for (int i = 0; i < 5; ++i) {
            DecoyEventData e;
            e.attacker_tag = "attacker_001";
            e.poison_type  = poison_types[i % 3];
            e.action       = decoy_actions[i % 2];
            e.timestamp_ms = now_ms - i * 60000LL;
            d.decoy_events.push_back(e);
        }

        // Zero Trust decisions
        const char* zt_decisions[] = {"ALLOW", "DENY", "QUARANTINE", "MFA_REQUIRED"};
        for (int i = 0; i < 4; ++i) {
            ZeroTrustDecisionData z;
            z.user_id     = "user_" + std::to_string(i + 1);
            z.decision    = zt_decisions[i % 4];
            z.trust_score = 20 + (d100(rng) % 80);
            z.resource    = "/api/sensitive-" + std::to_string(i + 1);
            d.zerotrust_decisions.push_back(z);
        }

        // Entropy windows (30 samples)
        for (int i = 0; i < 30; ++i) {
            EntropyWindowData w;
            w.mean_entropy_bits = 3.0 + (d100(rng) % 50) / 10.0;
            w.max_entropy_bits  = w.mean_entropy_bits + 1.0 + (d100(rng) % 20) / 10.0;
            w.anomalous         = (w.mean_entropy_bits > 7.2);
            w.window_index      = static_cast<uint64_t>(i);
            d.entropy_windows.push_back(w);
        }

        // Chaos windows (30 samples)
        for (int i = 0; i < 30; ++i) {
            ChaosWindowData w;
            w.K            = (d100(rng) % 70) / 100.0;
            w.anomalous    = (w.K > 0.7);
            w.window_index = static_cast<uint64_t>(i);
            d.chaos_windows.push_back(w);
        }

        // Pipeline stages
        const char* stage_names[] = {
            "CODE_COMMIT","STATIC_ANALYSIS","UNIT_TESTS","INTEGRATION_TESTS",
            "SECURITY_SCAN","BUILD","DEPLOY_STAGING","E2E_TESTS","DEPLOY_PRODUCTION","MONITOR"
        };
        const char* stage_statuses[] = {"PASSED","PASSED","PASSED","FAILED","AUTO_FIXED"};
        for (int i = 0; i < 10; ++i) {
            PipelineStageData s;
            s.stage  = stage_names[i];
            s.status = stage_statuses[d100(rng) % 5];
            s.detail = (s.status == std::string("FAILED"))    ? "Build timeout"    :
                       (s.status == std::string("AUTO_FIXED"))? "Agent fixed lint"  : "OK";
            d.pipeline_stages.push_back(s);
        }

        // Sandbox entries
        for (int i = 0; i < 8; ++i) {
            SandboxEntryData e;
            e.rel_path = (i % 2 == 0)
                ? "etc/config-" + std::to_string(i) + ".conf"
                : "var/log/app-" + std::to_string(i) + ".log";
            e.type    = (i % 2 == 0) ? "FILE" : "DIRECTORY";
            e.locked  = (d100(rng) > 70);
            e.version = static_cast<uint64_t>(1 + (d100(rng) % 5));
            d.sandbox_entries.push_back(e);
        }

        // Audit entries
        const char* audit_types[] = {
            "firewall_block","agent_task_completed","worm_lock_engaged",
            "decoy_event","quarantine","rule_fired"
        };
        for (int i = 0; i < 6; ++i) {
            AuditEntryData e;
            e.entry_id   = "AE-" + std::to_string(i + 1);
            e.event_type = audit_types[i % 6];
            e.timestamp  = iso_now();
            e.chain_valid = true;
            d.audit_entries.push_back(e);
        }
        d.audit_chain_valid = true;

        // v3.1 — real health checks (query_system_health defined in dashboard_writer.cpp)
        d.health = query_system_health();

        return d;
    });

    // Write once immediately before starting background thread
    writer.start(5);

    // Start HTTP server — serves dashboard files + terminal command execution
    DashboardServer server(output_dir, output_dir + "/dashboard_data.json", 9876);
    server.start();
    std::cerr << "[Demo] Open http://127.0.0.1:9876/ in your browser\n";

    // Run until Ctrl+C
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    server.stop();
    writer.stop();
    return 0;
}

