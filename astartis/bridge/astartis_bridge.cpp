// astartis_bridge.cpp -- Port target for the Elixir orchestration layer (Step 15)
//
// Communicates over stdio using newline-delimited JSON:
//   stdin  : {"cmd":"...", "args":{...}}
//   stdout : {"event":"...", "data":{...}}
//
// Stdout is always flushed immediately.
// Step 16: elevation is the Port supervisor's responsibility, not ours.
// --dashboard flag: launches the browser and starts the DashboardWriter.

// Winsock2 must precede windows.h
#include <winsock2.h>
#include <windows.h>
#include <shellapi.h>

// MUST come after winsock2.h; use nlohmann BEFORE any other Windows includes
// so WIN32_LEAN_AND_MEAN doesn't strip anything nlohmann needs.
#pragma warning(push)
#pragma warning(disable: 4706 4127 4244)
#include "nlohmann/json.hpp"
#pragma warning(pop)

// Now include the core headers. The core headers use WIN32_LEAN_AND_MEAN
// themselves; nlohmann is already fully compiled above so there's no conflict.
#include "audit_chain/audit_chain.h"
#include "worm_lock/worm_lock.h"
#include "sandbox/sandbox.h"
#include "threat_level/threat_level.h"
#include "rule_engine/rule_engine.h"
#include "chaos_detector/chaos_detector.h"
#include "decoy/decoy.h"
#include "active_response/active_response.h"
#include "attribution/attribution_report.h"
#include "clamd/clamd_scanner.h"
#include "quarantine/quarantine.h"
#include "firewall/firewall_blocker.h"
#include "unlock_protocol/unlock_protocol.h"
#include "access_token/access_token.h"
#include "ai_triage/ai_triage.h"
#include "veeam_interface/veeam_interface.h"
#include "packet_sensor/packet_sensor.h"

#include <iostream>
#include <fstream>
#include <string>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <functional>
#include <filesystem>
#include <sstream>
#include <vector>
#include <algorithm>
#include <cstdint>
#include <cmath>
#include <memory>
#include <limits>

// v2.0 agent swarm
#include "agents/controller/agent_controller.h"

// Dashboard writer (Phase UX)
#include "dashboard_writer.h"
#include "dashboard_server.h"

// v2.1 network architecture — Zero Trust simulation
#include "network_arch/segmentation/ssid_config.h"
#include "network_arch/zerotrust/nac_workflow.h"
#include "network_arch/zerotrust/zerotrust_engine.h"

using json = nlohmann::json;
namespace fs = std::filesystem;

// Correct namespace aliases for each module
using AuditChain   = astartis::audit::AuditChain;
using WormLock     = astartis::worm::WormLock;
using Sandbox      = astartis::sandbox::Sandbox;
using EntryType    = astartis::sandbox::EntryType;
using ThreatSM     = astartis::threat::ThreatStateMachine;
using ThreatTier   = astartis::threat::ThreatTier;
using RuleEngine   = astartis::rules::RuleEngine;
using ChaosDetect  = astartis::chaos::ChaosDetector;
using ChaosWindow  = astartis::chaos::ChaosWindow;
using DecoyEnv     = astartis::decoy::DecoyEnvironment;
using ActiveResp   = astartis::active_response::ActiveResponse;
using Attribution  = astartis::attribution::AttributionReporter;
using ClamdScan    = astartis::clamd::ClamdScanner;
using Quarantine      = astartis::quarantine::Quarantine;
using FwBlocker       = astartis::firewall::FirewallBlocker;
using TokenStore      = astartis::access::TokenStore;
using UnlockProtocol  = astartis::unlock::UnlockProtocol;
using ApproverSide    = astartis::unlock::ApproverSide;
using AiTriage        = astartis::ai::AiTriage;
using VeeamIface      = astartis::backup::VeeamInterface;
using BackupLockState = astartis::backup::BackupLockState;
using PacketSensor = astartis::sensor::PacketSensor;
using EntropyWindow = astartis::sensor::EntropyWindow;

// ---------------------------------------------------------------------------
// Global objects (all share a single audit chain)
// ---------------------------------------------------------------------------

static AuditChain g_audit;

// WormLock, ThreatSM, RuleEngine constructed in main (need audit_adder lambda)
// All heap objects held as unique_ptr for RAII / exception safety (P0 fix)
static std::unique_ptr<WormLock>       g_worm;
static std::unique_ptr<Sandbox>        g_sandbox;
static std::unique_ptr<ThreatSM>       g_threat;
static std::unique_ptr<RuleEngine>     g_rules;
static std::unique_ptr<ChaosDetect>    g_chaos;
static std::unique_ptr<DecoyEnv>       g_decoy;
static std::unique_ptr<ActiveResp>     g_ar;
static std::unique_ptr<ClamdScan>      g_clamd;
static std::unique_ptr<Quarantine>     g_qtn;
static std::unique_ptr<FwBlocker>      g_firewall;
static std::unique_ptr<TokenStore>     g_tokens;
static std::unique_ptr<UnlockProtocol> g_unlock;
static std::unique_ptr<AiTriage>       g_ai_triage;
static std::unique_ptr<VeeamIface>     g_veeam;
// v2.0 agent swarm controller
static std::unique_ptr<astartis::agents::AgentController> g_agents;
// Live capture is deliberately opt-in. It reads packet bytes locally through
// Npcap and exports only aggregate entropy windows to the dashboard/audit log.
static std::unique_ptr<PacketSensor> g_packet_sensor;
static std::mutex g_packet_sensor_mutex;
static std::atomic<uint64_t> g_packet_windows{0};
static std::atomic<int> g_packet_threat_score{0};
static std::atomic<bool> g_packet_anomalous{false};
static std::string g_packet_adapter;
static bool g_packet_synthetic = false;

// Step 18: last triage snapshot (written by triage_event handler, read by build_snapshot)
static std::mutex         g_triage_snap_mutex;
static nlohmann::json     g_last_triage_snap = nullptr;

// Step 17: approver identities keyed by name (bridge holds private keys for demo)
static std::map<std::string, std::unique_ptr<astartis::crypto::Identity>> g_approver_identities;

static std::string g_sandbox_root;
static std::unique_ptr<astartis::dashboard::DashboardWriter> g_dashboard_writer;
static std::unique_ptr<astartis::dashboard::DashboardServer> g_dashboard_server;

// Rolling history buffers for sparkline charts (20 samples each)
static std::mutex              g_metrics_hist_mutex;
static std::vector<double>     g_cpu_history;
static std::vector<double>     g_mem_history;
static std::vector<double>     g_disk_history;
static std::vector<double>     g_net_history;

static std::mutex        g_write_mutex;
static std::atomic<bool> g_running{true};

// Elevation status — set once in main() before any threads start
static bool g_is_elevated = false;

// ---------------------------------------------------------------------------
// Elevation check (Windows-specific)
// ---------------------------------------------------------------------------

static bool check_elevation()
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;
    TOKEN_ELEVATION elevation{};
    DWORD size = sizeof(elevation);
    BOOL ok = GetTokenInformation(token, TokenElevation, &elevation, size, &size);
    CloseHandle(token);
    return ok && elevation.TokenIsElevated != 0;
}

// Chaos K rolling history (max 100 windows)
static std::mutex          g_hist_mutex;
static std::vector<double> g_chaos_history;

// Latest chaos window values for the tick snapshot
static std::atomic<double> g_latest_K{0.0};
static std::atomic<bool>   g_latest_anomalous{false};
static std::atomic<uint64_t> g_latest_chaos_windows{0};

// ---------------------------------------------------------------------------
// Audit adder
// ---------------------------------------------------------------------------

static std::function<std::string(const std::string&, const std::string&)>
make_audit_adder()
{
    return [](const std::string& evt, const std::string& payload) -> std::string {
        return g_audit.add_entry(evt, payload);
    };
}

// ---------------------------------------------------------------------------
// Serialised stdout writer
// ---------------------------------------------------------------------------

static void emit(const json& obj)
{
    std::lock_guard<std::mutex> lk(g_write_mutex);
    std::cout << obj.dump() << "\n";
    std::cout.flush();
}

// ---------------------------------------------------------------------------
// Safe local diagnostic terminal
// ---------------------------------------------------------------------------
//
// The dashboard may ask the bridge for a small set of machine diagnostics.
// This deliberately is NOT a general terminal: the caller cannot supply an
// executable, arguments, shell metacharacters, or a PowerShell script.  Each
// accepted display command maps to fixed, read-only program arguments below.
//
// If the bridge itself was started elevated, diagnostics use the UAC linked
// (medium-integrity) token.  If that token is not available, the request is
// rejected rather than falling back to an elevated child process.

namespace {

constexpr DWORD kDiagnosticTimeoutMs = 12'000;
constexpr size_t kDiagnosticOutputLimit = 64 * 1024;

enum class DiagnosticOutputEncoding {
    Oem,
    Utf8
};

struct TerminalDiagnosticSpec {
    const char* canonical_command;
    const wchar_t* executable_relative_to_system32;
    const wchar_t* fixed_arguments;
    DiagnosticOutputEncoding output_encoding;
};

struct TerminalDiagnosticResult {
    std::string command;
    std::string stdout_text;
    std::string stderr_text;
    std::string status = "error";
    int exit_code = -1;
    int64_t duration_ms = 0;
    bool allowed = false;
    bool executed = false;
    bool rejected = false;
    bool timed_out = false;
    bool stdout_truncated = false;
    bool stderr_truncated = false;
    bool elevated = false;
};

class ScopedHandle {
public:
    ScopedHandle() = default;
    explicit ScopedHandle(HANDLE handle) : handle_(handle) {}
    ~ScopedHandle() { reset(); }

    ScopedHandle(const ScopedHandle&) = delete;
    ScopedHandle& operator=(const ScopedHandle&) = delete;

    HANDLE get() const { return handle_; }
    bool valid() const { return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE; }

    void reset(HANDLE handle = nullptr) {
        if (valid()) CloseHandle(handle_);
        handle_ = handle;
    }

private:
    HANDLE handle_ = nullptr;
};

static char ascii_lower(char ch)
{
    return (ch >= 'A' && ch <= 'Z') ? static_cast<char>(ch - 'A' + 'a') : ch;
}

static std::string trim_ascii_whitespace(const std::string& value)
{
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

static bool ascii_iequals(const std::string& left, const char* right)
{
    const std::string rhs(right);
    if (left.size() != rhs.size()) return false;
    for (size_t i = 0; i < left.size(); ++i) {
        if (ascii_lower(left[i]) != ascii_lower(rhs[i])) return false;
    }
    return true;
}

static std::string safe_diagnostic_label(const std::string& value)
{
    constexpr size_t kMaxLabel = 160;
    std::string safe;
    safe.reserve(std::min(value.size(), kMaxLabel));
    for (unsigned char ch : value) {
        if (safe.size() >= kMaxLabel) break;
        safe.push_back((ch >= 0x20 && ch <= 0x7e) ? static_cast<char>(ch) : '?');
    }
    if (value.size() > kMaxLabel) safe += "...";
    return safe;
}

static std::string utf16_to_utf8(const std::wstring& value)
{
    if (value.empty()) return "";
    const int needed = WideCharToMultiByte(
        CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return "";
    std::string converted(static_cast<size_t>(needed), '\0');
    const int written = WideCharToMultiByte(
        CP_UTF8, 0, value.data(), static_cast<int>(value.size()), converted.data(), needed, nullptr, nullptr);
    if (written != needed) return "";
    return converted;
}

static std::string safe_ascii_output(const std::string& bytes)
{
    std::string safe;
    safe.reserve(bytes.size());
    for (unsigned char ch : bytes) {
        if (ch == '\r' || ch == '\n' || ch == '\t' || (ch >= 0x20 && ch <= 0x7e)) {
            safe.push_back(static_cast<char>(ch));
        } else {
            safe.push_back('?');
        }
    }
    return safe;
}

static std::string output_bytes_to_utf8(const std::string& bytes, DiagnosticOutputEncoding encoding)
{
    if (bytes.empty()) return "";
    const UINT code_page = encoding == DiagnosticOutputEncoding::Utf8 ? CP_UTF8 : GetOEMCP();
    const DWORD flags = encoding == DiagnosticOutputEncoding::Utf8 ? MB_ERR_INVALID_CHARS : 0;
    const int wide_length = MultiByteToWideChar(
        code_page, flags, bytes.data(), static_cast<int>(bytes.size()), nullptr, 0);
    if (wide_length <= 0) return safe_ascii_output(bytes);

    std::wstring wide(static_cast<size_t>(wide_length), L'\0');
    if (MultiByteToWideChar(code_page, flags, bytes.data(), static_cast<int>(bytes.size()),
                            wide.data(), wide_length) != wide_length) {
        return safe_ascii_output(bytes);
    }

    const std::string utf8 = utf16_to_utf8(wide);
    return utf8.empty() && !bytes.empty() ? safe_ascii_output(bytes) : utf8;
}

static std::string windows_error_message(DWORD code)
{
    LPWSTR raw = nullptr;
    const DWORD length = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, code, 0, reinterpret_cast<LPWSTR>(&raw), 0, nullptr);
    std::wstring text;
    if (length > 0 && raw != nullptr) text.assign(raw, length);
    if (raw != nullptr) LocalFree(raw);
    const std::string message = trim_ascii_whitespace(utf16_to_utf8(text));
    return message.empty() ? "Windows error " + std::to_string(code) : message;
}

static std::wstring system_program_path(const wchar_t* relative_name)
{
    wchar_t system_dir[MAX_PATH + 1] = {};
    const UINT length = GetSystemDirectoryW(system_dir, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) return L"";
    std::wstring path(system_dir, length);
    path += L"\\";
    path += relative_name;
    return path;
}

static bool token_is_elevated(HANDLE token)
{
    TOKEN_ELEVATION elevation{};
    DWORD size = sizeof(elevation);
    return GetTokenInformation(token, TokenElevation, &elevation, size, &size) &&
           elevation.TokenIsElevated != 0;
}

// Returns a non-null token only when the bridge itself is elevated.  On a
// normal dashboard launch, CreateProcessW inherits the already non-elevated
// process token.
static bool create_non_elevated_child_token(ScopedHandle& child_token, std::string& error)
{
    if (!check_elevation()) return true;

    ScopedHandle current_token;
    HANDLE opened_token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &opened_token)) {
        error = "Unable to inspect the elevated bridge token: " + windows_error_message(GetLastError());
        return false;
    }
    current_token.reset(opened_token);

    TOKEN_LINKED_TOKEN linked{};
    DWORD returned = 0;
    if (!GetTokenInformation(current_token.get(), TokenLinkedToken, &linked, sizeof(linked), &returned) ||
        linked.LinkedToken == nullptr) {
        error = "A non-elevated linked token is unavailable; diagnostic was not run elevated.";
        return false;
    }
    ScopedHandle linked_token(linked.LinkedToken);

    if (token_is_elevated(linked_token.get())) {
        error = "The linked token is elevated; diagnostic was not run.";
        return false;
    }

    HANDLE duplicated = nullptr;
    const DWORD desired_access = TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY |
                                 TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID;
    if (!DuplicateTokenEx(linked_token.get(), desired_access, nullptr, SecurityImpersonation,
                          TokenPrimary, &duplicated)) {
        error = "Unable to create a non-elevated diagnostic token: " + windows_error_message(GetLastError());
        return false;
    }
    child_token.reset(duplicated);

    if (token_is_elevated(child_token.get())) {
        error = "The diagnostic token remained elevated; diagnostic was not run.";
        child_token.reset();
        return false;
    }
    return true;
}

static const TerminalDiagnosticSpec* find_terminal_diagnostic(const std::string& requested_command)
{
    static const TerminalDiagnosticSpec kAllowedDiagnostics[] = {
        {"ipconfig /all", L"ipconfig.exe", L"/all", DiagnosticOutputEncoding::Oem},
        {"whoami", L"whoami.exe", L"", DiagnosticOutputEncoding::Oem},
        {"hostname", L"hostname.exe", L"", DiagnosticOutputEncoding::Oem},
        {"systeminfo", L"systeminfo.exe", L"", DiagnosticOutputEncoding::Oem},
        {"netstat -ano", L"netstat.exe", L"-ano", DiagnosticOutputEncoding::Oem},
        // This is a fixed PowerShell command, not caller-supplied script text.
        {"Get-NetAdapter", L"WindowsPowerShell\\v1.0\\powershell.exe",
         L"-NoLogo -NoProfile -NonInteractive -Command \"[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); Get-NetAdapter | Select-Object Name,Status,MacAddress,LinkSpeed,InterfaceDescription | Format-Table -AutoSize\"",
         DiagnosticOutputEncoding::Utf8},
    };

    const std::string normalized = trim_ascii_whitespace(requested_command);
    for (const auto& candidate : kAllowedDiagnostics) {
        if (ascii_iequals(normalized, candidate.canonical_command)) return &candidate;
    }
    return nullptr;
}

static void drain_terminal_pipe(HANDLE pipe, bool& pipe_open, std::string& output,
                                size_t& remaining_capacity, bool& truncated)
{
    while (pipe_open) {
        DWORD available = 0;
        if (!PeekNamedPipe(pipe, nullptr, 0, nullptr, &available, nullptr)) {
            const DWORD error = GetLastError();
            if (error == ERROR_BROKEN_PIPE || error == ERROR_PIPE_NOT_CONNECTED) pipe_open = false;
            return;
        }
        if (available == 0) return;

        char buffer[4096];
        const DWORD to_read = std::min<DWORD>(available, static_cast<DWORD>(sizeof(buffer)));
        DWORD read = 0;
        if (!ReadFile(pipe, buffer, to_read, &read, nullptr) || read == 0) {
            const DWORD error = GetLastError();
            if (error == ERROR_BROKEN_PIPE || error == ERROR_PIPE_NOT_CONNECTED) pipe_open = false;
            return;
        }

        const size_t accepted = std::min<size_t>(remaining_capacity, read);
        if (accepted > 0) output.append(buffer, accepted);
        if (accepted < read) truncated = true;
        remaining_capacity -= accepted;
    }
}

static void emit_terminal_execute_result(const TerminalDiagnosticResult& result)
{
    emit({{"event", "terminal_execute_result"}, {"data", {
        {"command", result.command},
        {"stdout", result.stdout_text},
        {"stderr", result.stderr_text},
        {"exit_code", result.exit_code},
        {"duration_ms", result.duration_ms},
        {"mode", "live_local"},
        {"status", result.status},
        {"allowed", result.allowed},
        {"executed", result.executed},
        {"rejected", result.rejected},
        {"timed_out", result.timed_out},
        {"stdout_truncated", result.stdout_truncated},
        {"stderr_truncated", result.stderr_truncated},
        {"elevated", result.elevated}
    }}});
}

static TerminalDiagnosticResult run_terminal_diagnostic(const TerminalDiagnosticSpec& spec)
{
    TerminalDiagnosticResult result;
    result.command = spec.canonical_command;
    result.allowed = true;

    const auto started = std::chrono::steady_clock::now();
    const std::wstring application = system_program_path(spec.executable_relative_to_system32);
    if (application.empty()) {
        result.stderr_text = "Windows system directory could not be resolved.";
        result.duration_ms = 0;
        return result;
    }

    std::wstring command_line = L"\"" + application + L"\"";
    if (spec.fixed_arguments[0] != L'\0') {
        command_line += L" ";
        command_line += spec.fixed_arguments;
    }
    std::vector<wchar_t> mutable_command_line(command_line.begin(), command_line.end());
    mutable_command_line.push_back(L'\0');

    ScopedHandle child_token;
    std::string token_error;
    if (!create_non_elevated_child_token(child_token, token_error)) {
        result.stderr_text = token_error;
        result.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started).count();
        return result;
    }

    SECURITY_ATTRIBUTES security{};
    security.nLength = sizeof(security);
    security.bInheritHandle = TRUE;

    ScopedHandle stdout_read, stdout_write, stderr_read, stderr_write, null_input;
    HANDLE raw_read = nullptr;
    HANDLE raw_write = nullptr;
    if (!CreatePipe(&raw_read, &raw_write, &security, 0)) {
        result.stderr_text = "Could not create diagnostic stdout pipe: " + windows_error_message(GetLastError());
        result.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started).count();
        return result;
    }
    stdout_read.reset(raw_read);
    stdout_write.reset(raw_write);
    if (!SetHandleInformation(stdout_read.get(), HANDLE_FLAG_INHERIT, 0)) {
        result.stderr_text = "Could not secure diagnostic stdout pipe: " + windows_error_message(GetLastError());
        result.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started).count();
        return result;
    }

    raw_read = nullptr;
    raw_write = nullptr;
    if (!CreatePipe(&raw_read, &raw_write, &security, 0)) {
        result.stderr_text = "Could not create diagnostic stderr pipe: " + windows_error_message(GetLastError());
        result.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started).count();
        return result;
    }
    stderr_read.reset(raw_read);
    stderr_write.reset(raw_write);
    if (!SetHandleInformation(stderr_read.get(), HANDLE_FLAG_INHERIT, 0)) {
        result.stderr_text = "Could not secure diagnostic stderr pipe: " + windows_error_message(GetLastError());
        result.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started).count();
        return result;
    }

    HANDLE raw_null = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                  &security, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (raw_null == INVALID_HANDLE_VALUE) {
        result.stderr_text = "Could not create diagnostic stdin handle: " + windows_error_message(GetLastError());
        result.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started).count();
        return result;
    }
    null_input.reset(raw_null);

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = null_input.get();
    startup.hStdOutput = stdout_write.get();
    startup.hStdError = stderr_write.get();

    PROCESS_INFORMATION process_info{};
    BOOL created = FALSE;
    if (child_token.valid()) {
        created = CreateProcessAsUserW(child_token.get(), application.c_str(), mutable_command_line.data(),
                                       nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr,
                                       &startup, &process_info);
    } else {
        created = CreateProcessW(application.c_str(), mutable_command_line.data(), nullptr, nullptr, TRUE,
                                 CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process_info);
    }

    // The child owns the inherited ends after CreateProcess*.  Closing our
    // copies is required so pipe EOF accurately tracks child completion.
    stdout_write.reset();
    stderr_write.reset();
    null_input.reset();

    if (!created) {
        result.stderr_text = "Diagnostic launch failed: " + windows_error_message(GetLastError());
        result.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started).count();
        return result;
    }

    ScopedHandle child_process(process_info.hProcess);
    ScopedHandle child_thread(process_info.hThread);
    result.executed = true;
    result.elevated = false;

    bool stdout_open = true;
    bool stderr_open = true;
    size_t remaining_capacity = kDiagnosticOutputLimit;
    std::string raw_stdout;
    std::string raw_stderr;

    while (true) {
        drain_terminal_pipe(stdout_read.get(), stdout_open, raw_stdout, remaining_capacity, result.stdout_truncated);
        drain_terminal_pipe(stderr_read.get(), stderr_open, raw_stderr, remaining_capacity, result.stderr_truncated);

        const DWORD wait_status = WaitForSingleObject(child_process.get(), 25);
        if (wait_status == WAIT_OBJECT_0) break;
        if (wait_status == WAIT_FAILED) {
            result.stderr_text = "Diagnostic wait failed: " + windows_error_message(GetLastError());
            break;
        }

        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started).count();
        if (elapsed >= static_cast<int64_t>(kDiagnosticTimeoutMs)) {
            result.timed_out = true;
            TerminateProcess(child_process.get(), 1);
            WaitForSingleObject(child_process.get(), 2'000);
            break;
        }
    }

    // Give the now-closed child handles a short chance to flush their last
    // buffered bytes without ever allowing an unbounded read.
    for (int i = 0; i < 8 && (stdout_open || stderr_open); ++i) {
        drain_terminal_pipe(stdout_read.get(), stdout_open, raw_stdout, remaining_capacity, result.stdout_truncated);
        drain_terminal_pipe(stderr_read.get(), stderr_open, raw_stderr, remaining_capacity, result.stderr_truncated);
        if (stdout_open || stderr_open) Sleep(5);
    }

    DWORD exit_code = static_cast<DWORD>(-1);
    if (GetExitCodeProcess(child_process.get(), &exit_code)) {
        result.exit_code = static_cast<int>(exit_code);
    }
    result.stdout_text = output_bytes_to_utf8(raw_stdout, spec.output_encoding);
    const std::string captured_stderr = output_bytes_to_utf8(raw_stderr, spec.output_encoding);
    if (result.stderr_text.empty()) result.stderr_text = captured_stderr;
    else if (!captured_stderr.empty()) result.stderr_text += "\n" + captured_stderr;
    result.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started).count();

    if (result.timed_out) result.status = "timed_out";
    else if (result.exit_code == 0) result.status = "completed";
    else result.status = "completed_with_errors";
    return result;
}

static std::string terminal_audit_payload(const TerminalDiagnosticResult& result)
{
    std::ostringstream payload;
    payload << "command=" << result.command
            << " status=" << result.status
            << " exit_code=" << result.exit_code
            << " duration_ms=" << result.duration_ms
            << " timed_out=" << (result.timed_out ? "true" : "false")
            << " stdout_bytes=" << result.stdout_text.size()
            << " stderr_bytes=" << result.stderr_text.size()
            << " truncated=" << ((result.stdout_truncated || result.stderr_truncated) ? "true" : "false")
            << " elevated=false";
    return payload.str();
}

} // namespace

// ---------------------------------------------------------------------------
// Snapshot for the 500 ms tick
// ---------------------------------------------------------------------------

static json build_snapshot()
{
    json snap;

    // Threat tier
    ThreatTier tier = g_threat->current_tier();
    snap["threat_tier"] = static_cast<int>(tier);
    switch (tier) {
        case ThreatTier::LOW:      snap["threat_tier_name"] = "LOW";      break;
        case ThreatTier::MEDIUM:   snap["threat_tier_name"] = "MEDIUM";   break;
        case ThreatTier::HIGH:     snap["threat_tier_name"] = "HIGH";     break;
        case ThreatTier::CRITICAL: snap["threat_tier_name"] = "CRITICAL"; break;
        default:                   snap["threat_tier_name"] = "LOW";      break;
    }
    snap["threat_transitions"] = g_threat->transition_count();

    // WORM
    snap["worm_locked"]     = g_worm->is_locked();
    snap["worm_reason"]     = g_worm->lock_reason();
    snap["worm_lock_count"] = g_worm->lockdown_count();

    // Audit chain
    auto vr = g_audit.verify_chain();
    snap["chain_length"] = g_audit.get_chain_length();
    snap["chain_valid"]  = vr.is_valid;
    {
        auto h = g_audit.get_chain_head_hash();
        snap["chain_head"] = h.size() >= 12 ? h.substr(0, 12) : h;
    }

    // Chaos
    snap["chaos_K"]         = g_latest_K.load();
    snap["chaos_anomalous"] = g_latest_anomalous.load();
    snap["chaos_windows"]   = g_latest_chaos_windows.load();
    {
        std::lock_guard<std::mutex> lk(g_hist_mutex);
        snap["chaos_history"] = g_chaos_history;
    }

    // Rule engine
    snap["rule_fires"]    = g_rules->total_fires();
    snap["worm_triggers"] = g_rules->worm_trigger_count();

    // Decoy
    snap["decoy_events"] = g_decoy->event_count();

    // Sandbox file tree
    json entries = json::array();
    for (const auto& e : g_sandbox->get_tree()) {
        entries.push_back({
            {"rel_path",      e.rel_path},
            {"type",          e.type == EntryType::FILE ? "file" : "dir"},
            {"size_bytes",    e.size_bytes},
            {"version",       e.version},
            {"locked",        e.locked},
            {"last_modified", e.last_modified}
        });
    }
    snap["sandbox_entries"] = entries;
    snap["sandbox_root"]    = g_sandbox_root;
    snap["elevated"]        = g_is_elevated;

    // Npcap sensor status. This is absent until the operator explicitly starts
    // capture; no network traffic is collected merely by launching Astartis.
    {
        std::lock_guard<std::mutex> lk(g_packet_sensor_mutex);
        const bool running = g_packet_sensor && g_packet_sensor->is_running();
        snap["packet_capture_running"] = running;
        snap["packet_capture_mode"] = running ? (g_packet_synthetic ? "synthetic" : "live") : "stopped";
        snap["packet_capture_adapter"] = g_packet_adapter;
        snap["packet_windows"] = g_packet_windows.load();
        snap["packet_threat_score"] = g_packet_threat_score.load();
        snap["packet_anomalous"] = g_packet_anomalous.load();
    }

    // Step 16 ST-5: quarantine + firewall counts
    snap["quarantine_count"] = g_qtn ? static_cast<int>(g_qtn->list().size()) : 0;
    {
        json fw_blocks = json::array();
        if (g_firewall) {
            for (const auto& ab : g_firewall->active_blocks()) {
                fw_blocks.push_back({
                    {"ip",             ab.ip},
                    {"rule_name_in",   ab.rule_name_in},
                    {"expires_at_ms",  ab.expires_at_ms}
                });
            }
        }
        snap["active_firewall_blocks"] = fw_blocks;
    }

    // Step 17: unlock protocol status
    if (g_unlock) {
        auto ust = g_unlock->status();
        snap["unlock_votes_collected"] = ust.votes_collected;
        snap["unlock_threshold"]       = ust.threshold;
        snap["unlock_state"] = [&]() -> std::string {
            switch (ust.state) {
                case astartis::unlock::ProtocolState::COLLECTING: return "COLLECTING";
                case astartis::unlock::ProtocolState::GRANTED:    return "GRANTED";
                default:                                           return "IDLE";
            }
        }();
        json approver_arr = json::array();
        for (const auto& ap : ust.approvers) {
            approver_arr.push_back({
                {"name",  ap.name},
                {"side",  ap.side == ApproverSide::ASTARTIS ? "ASTARTIS" : "CLIENT"},
                {"voted", ap.voted}
            });
        }
        snap["unlock_approvers"] = approver_arr;
    } else {
        snap["unlock_votes_collected"] = 0;
        snap["unlock_threshold"]       = UnlockProtocol::DEMO_THRESHOLD;
        snap["unlock_state"]           = "IDLE";
        snap["unlock_approvers"]       = json::array();
    }

    // Step 18: last triage result (populated after first triage_event call)
    {
        std::lock_guard<std::mutex> lk(g_triage_snap_mutex);
        snap["last_triage"] = g_last_triage_snap;
    }

    // Step 19: Veeam / IBM Storage backup repo status
    if (g_veeam) {
        auto vs = g_veeam->status();
        snap["veeam_lock_state"]       = VeeamIface::lock_state_str(vs.lock_state);
        snap["veeam_backup_count"]     = vs.backup_count;
        snap["veeam_locked_at_ms"]     = vs.locked_at_ms;
        snap["veeam_integrity_checks"] = vs.integrity_check_count;
        snap["veeam_locked_by_reason"] = vs.locked_by_reason;
    } else {
        snap["veeam_lock_state"]       = "UNLOCKED";
        snap["veeam_backup_count"]     = 0;
        snap["veeam_locked_at_ms"]     = 0;
        snap["veeam_integrity_checks"] = 0;
        snap["veeam_locked_by_reason"] = "";
    }

    // v2.0: agent swarm status — included in every tick so dashboard stays live
    if (g_agents) {
        auto statuses = g_agents->get_statuses();
        json status_arr = json::array();
        for (const auto& s : statuses) {
            std::string state_str;
            switch (s.state) {
                case astartis::agents::AgentState::IDLE:      state_str = "IDLE";      break;
                case astartis::agents::AgentState::RUNNING:   state_str = "RUNNING";   break;
                case astartis::agents::AgentState::COMPLETED: state_str = "COMPLETED"; break;
                case astartis::agents::AgentState::FAILED:    state_str = "FAILED";    break;
                default:                                       state_str = "IDLE";      break;
            }
            status_arr.push_back({
                {"name",                s.name},
                {"category",            s.category},
                {"state",               state_str},
                {"last_task_id",        s.last_task_id},
                {"last_result_snippet", s.last_result_snippet},
                {"last_run_at_ms",      s.last_run_at_ms},
                {"tasks_completed",     s.tasks_completed},
                {"tasks_failed",        s.tasks_failed}
            });
        }
        snap["agent_statuses"]    = status_arr;
        snap["agent_queue_depth"] = static_cast<int>(g_agents->queue_depth());
    } else {
        snap["agent_statuses"]    = json::array();
        snap["agent_queue_depth"] = 0;
    }

    return snap;
}

// ---------------------------------------------------------------------------
// Command dispatcher
// ---------------------------------------------------------------------------

static void dispatch(const json& msg)
{
    auto audit_adder = make_audit_adder();
    std::string cmd = msg.value("cmd", "");
    json args = msg.value("args", json::object());

    if (cmd == "ping") {
        emit({{"event", "pong"}});
        return;
    }

    if (cmd == "get_snapshot") {
        emit({{"event", "snapshot"}, {"data", build_snapshot()}});
        return;
    }

    // Local runtime evidence for the Astartis x Codex workspace.  This is a
    // bounded, read-only point-in-time sample rather than a 500 ms tick: PDH
    // and local service probes are intentionally not added to the hot path.
    if (cmd == "runtime_status") {
        namespace dash = astartis::dashboard;
        const auto metrics = dash::query_windows_metrics();
        const auto health = dash::query_system_health();

        int agents_loaded = 0;
        int agents_running = 0;
        int agents_completed_tasks = 0;
        int agents_failed_tasks = 0;
        int agent_queue_depth = 0;

        if (g_agents) {
            const auto statuses = g_agents->get_statuses();
            agents_loaded = static_cast<int>(statuses.size());
            agent_queue_depth = static_cast<int>(g_agents->queue_depth());
            for (const auto& status : statuses) {
                if (status.state == astartis::agents::AgentState::RUNNING) ++agents_running;
                agents_completed_tasks += status.tasks_completed;
                agents_failed_tasks += status.tasks_failed;
            }
        }

        const auto sampled_at_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        emit({{"event", "runtime_status"}, {"data", {
            {"sampled_at_ms",          sampled_at_ms},
            {"mode",                   "live_local"},
            {"cpu_percent",            metrics.cpu_percent},
            {"memory_percent",         metrics.memory_percent},
            {"memory_used_gb",         metrics.memory_used_gb},
            {"memory_total_gb",        metrics.memory_total_gb},
            {"disk_percent",           metrics.disk_percent},
            {"disk_free_gb",           metrics.disk_free_gb},
            {"network_mbps",           metrics.network_mbps},
            {"cpu_cores",              metrics.cpu_cores},
            {"ollama_online",          health.ollama_online},
            {"clamd_online",           health.clamd_online},
            {"npcap_installed",        health.npcap_installed},
            {"npcap_service_running",  health.npcap_service_running},
            {"bridge_elevated",        g_is_elevated},
            {"agents_loaded",          agents_loaded},
            {"agents_running",         agents_running},
            {"agent_completed_tasks",  agents_completed_tasks},
            {"agent_failed_tasks",     agents_failed_tasks},
            {"agent_queue_depth",      agent_queue_depth},
            {"rule_fires",             g_rules ? g_rules->total_fires() : 0},
            {"audit_chain_length",     g_audit.get_chain_length()}
        }}});
        return;
    }

    // Local diagnostic terminal: explicit allowlist only.  Do not add a
    // generic executable/argument path here; see the fixed command map above.
    if (cmd == "terminal_execute") {
        const std::string requested = args.is_object() ? args.value("command", "") : "";
        const TerminalDiagnosticSpec* spec = find_terminal_diagnostic(requested);
        if (spec == nullptr) {
            TerminalDiagnosticResult rejected;
            rejected.command = safe_diagnostic_label(trim_ascii_whitespace(requested));
            rejected.stderr_text = "Rejected: command is not in Astartis' read-only diagnostic allowlist.";
            rejected.status = "rejected";
            rejected.rejected = true;
            audit_adder("terminal_execute_rejected",
                        "requested=" + rejected.command + " reason=not_allowlisted");
            emit_terminal_execute_result(rejected);
            return;
        }

        TerminalDiagnosticResult result = run_terminal_diagnostic(*spec);
        const char* audit_event = result.executed ? "terminal_execute" : "terminal_execute_failed";
        audit_adder(audit_event, terminal_audit_payload(result));
        emit_terminal_execute_result(result);
        return;
    }

    if (cmd == "packet_capture_list_adapters") {
        json adapters = json::array();
        for (const auto& adapter : PacketSensor::list_adapters()) {
            adapters.push_back({
                {"name", adapter.name},
                {"description", adapter.description},
                {"up", adapter.up},
                {"loopback", adapter.loopback}
            });
        }
        emit({{"event", "packet_capture_adapters"}, {"data", {{"adapters", adapters}}}});
        return;
    }

    if (cmd == "packet_capture_start") {
        const std::string adapter_hint = args.value("adapter_hint", "");
        bool already_running = false;
        std::string error;
        {
            std::lock_guard<std::mutex> lk(g_packet_sensor_mutex);
            already_running = g_packet_sensor && g_packet_sensor->is_running();
            if (!already_running) try {
                g_packet_sensor = std::make_unique<PacketSensor>(
                [](const EntropyWindow& window) {
                    auto result = g_rules->evaluate_packet_window(window);
                    g_packet_windows.store(window.window_index + 1);
                    g_packet_threat_score.store(window.threat_score);
                    g_packet_anomalous.store(window.anomalous);
                    {
                        std::lock_guard<std::mutex> status_lk(g_packet_sensor_mutex);
                        g_packet_adapter = window.adapter_name;
                        g_packet_synthetic = window.synthetic;
                    }
                    emit({{"event", "packet_entropy_window"}, {"data", {
                        {"window_index", window.window_index},
                        {"packet_count", window.packet_count},
                        {"mean_entropy_bits", window.mean_entropy_bits},
                        {"threat_score", window.threat_score},
                        {"anomalous", window.anomalous},
                        {"adapter", window.adapter_name},
                        {"mode", window.synthetic ? "synthetic" : "live"},
                        {"rule_id", result.rule_id},
                        {"rule_fired", result.fired}
                    }}});
                }, audit_adder, adapter_hint);
                const bool live = g_packet_sensor->start();
                g_packet_adapter = g_packet_sensor->adapter_name();
                g_packet_synthetic = !live;
                audit_adder("packet_capture_started", "mode=" + std::string(live ? "live" : "synthetic") + " adapter=" + g_packet_adapter);
            } catch (const std::exception& ex) {
                g_packet_sensor.reset();
                error = ex.what();
            }
        }
        if (!error.empty()) emit({{"event", "packet_capture_error"}, {"data", {{"message", error}}}});
        else emit({{"event", "packet_capture_status"}, {"data", build_snapshot()}});
        return;
    }

    if (cmd == "packet_capture_stop") {
        // Never join the sensor thread while holding its status mutex: its
        // entropy callback also updates that status and could otherwise block
        // shutdown forever.
        std::unique_ptr<PacketSensor> sensor_to_stop;
        {
            std::lock_guard<std::mutex> lk(g_packet_sensor_mutex);
            sensor_to_stop = std::move(g_packet_sensor);
            g_packet_adapter.clear();
            g_packet_synthetic = false;
        }
        if (sensor_to_stop) sensor_to_stop->stop();
        audit_adder("packet_capture_stopped", "operator_requested=true");
        emit({{"event", "packet_capture_status"}, {"data", build_snapshot()}});
        return;
    }

    if (cmd == "observe_signal") {
        int score = args.value("score", 0);
        std::string source = args.value("source", "elixir");
        auto result = g_threat->observe_signal(score, source);
        auto rule_r = g_rules->evaluate_threat_score(score, source);
        bool worm_fired = result.worm_triggered || rule_r.worm_triggered;
        if (worm_fired)
            g_worm->trigger_lockdown("threat_signal score=" + std::to_string(score));
        emit({{"event", "signal_result"}, {"data", {
            {"tier",           static_cast<int>(result.current_tier)},
            {"tier_changed",   result.tier_changed},
            {"worm_triggered", worm_fired},
            {"action",         result.response_description}
        }}});
        return;
    }

    if (cmd == "push_chaos") {
        double value     = args.value("value", 0.0);
        bool   synthetic = args.value("synthetic", true);
        g_chaos->push(value, synthetic);
        emit({{"event", "chaos_pushed"}, {"data", {{"value", value}}}});
        return;
    }

    if (cmd == "push_chaos_batch") {
        // Accept a JSON array of doubles, push all at once.
        // {"cmd":"push_chaos_batch","args":{"values":[0.5,0.76,...],"synthetic":true}}
        bool synthetic = args.value("synthetic", true);
        auto vals = args.value("values", json::array());
        int pushed = 0;
        for (const auto& v : vals) {
            if (v.is_number()) {
                g_chaos->push(v.get<double>(), synthetic);
                ++pushed;
            }
        }
        emit({{"event", "chaos_batch_pushed"}, {"data", {{"count", pushed}}}});
        return;
    }

    if (cmd == "worm_trigger") {
        std::string reason = args.value("reason", "manual");
        bool changed = g_worm->trigger_lockdown(reason);
        if (changed) {
            g_sandbox->lock_all("worm_lockdown");
            audit_adder("worm_trigger", "reason=" + reason);
            // Step 17: open a fresh voting session whenever lockdown is engaged
            if (g_unlock) g_unlock->begin_session();
            // Step 19: mirror lockdown to backup repo
            if (g_veeam) g_veeam->lock_backups(reason);
        }
        emit({{"event", "worm_status"}, {"data", {
            {"locked", g_worm->is_locked()},
            {"reason", g_worm->lock_reason()}
        }}});
        return;
    }

    // worm_unlock direct command is DISABLED (P0 security fix).
    // All unlock operations MUST go through the UnlockProtocol (unlock_vote).
    // This prevents a single actor bypassing the multi-party threshold check.
    if (cmd == "worm_unlock") {
        audit_adder("worm_unlock_rejected",
                    "reason=direct_unlock_disabled use_unlock_vote_instead");
        emit({{"event", "worm_status"}, {"data", {
            {"locked",  g_worm->is_locked()},
            {"reason",  g_worm->lock_reason()},
            {"error",   "Direct unlock disabled. Use unlock_vote with all required approvers."},
            {"hint",    "POST cmd=unlock_vote for each approver to reach threshold"}
        }}});
        return;
    }

    // -------------------------------------------------------------------
    // Step 19: veeam_integrity_check
    // {"cmd":"veeam_integrity_check"}
    // -------------------------------------------------------------------
    if (cmd == "veeam_integrity_check") {
        if (!g_veeam) {
            emit({{"event", "veeam_check_result"}, {"data", {
                {"error", "veeam_not_initialised"}
            }}});
            return;
        }
        auto r = g_veeam->integrity_check();
        emit({{"event", "veeam_check_result"}, {"data", {
            {"passed",          r.passed},
            {"checked_count",   r.checked_count},
            {"violations_found",r.violations_found},
            {"checked_at_ms",   r.checked_at_ms},
            {"audit_entry_id",  r.audit_entry_id}
        }}});
        return;
    }

    // -------------------------------------------------------------------
    // Step 19: veeam_status
    // {"cmd":"veeam_status"}
    // -------------------------------------------------------------------
    if (cmd == "veeam_status") {
        if (!g_veeam) {
            emit({{"event", "veeam_status"}, {"data", {
                {"error", "veeam_not_initialised"}
            }}});
            return;
        }
        auto vs = g_veeam->status();
        emit({{"event", "veeam_status"}, {"data", {
            {"lock_state",            VeeamIface::lock_state_str(vs.lock_state)},
            {"backup_count",          vs.backup_count},
            {"locked_at_ms",          vs.locked_at_ms},
            {"locked_by_reason",      vs.locked_by_reason},
            {"integrity_check_count", vs.integrity_check_count},
            {"last_check_ms",         vs.last_integrity_check_ms}
        }}});
        return;
    }

    if (cmd == "sandbox_get_tree") {
        json entries = json::array();
        for (const auto& e : g_sandbox->get_tree()) {
            entries.push_back({
                {"rel_path",      e.rel_path},
                {"type",          e.type == EntryType::FILE ? "file" : "dir"},
                {"size_bytes",    e.size_bytes},
                {"version",       e.version},
                {"locked",        e.locked},
                {"last_modified", e.last_modified}
            });
        }
        emit({{"event", "sandbox_tree"}, {"data", entries}});
        return;
    }

    if (cmd == "decoy_plant") {
        size_t count = g_decoy->plant();
        emit({{"event", "decoy_planted"}, {"data", {{"count", count}}}});
        return;
    }

    if (cmd == "decoy_touch") {
        std::string path    = args.value("path", "");
        std::string action  = args.value("action", "read");
        std::string session = args.value("session", "demo");
        std::string detail  = args.value("detail", "");
        bool hit = g_decoy->touch(path, action, session, detail);
        emit({{"event", "decoy_touch"}, {"data", {{"hit", hit}, {"path", path}}}});
        return;
    }

    if (cmd == "active_response_serve") {
        std::string session  = args.value("session", "demo");
        std::string resource = args.value("resource", "");
        std::string ioc_hint = args.value("ioc_hint", "");
        auto ev = g_ar->serve(session, resource, ioc_hint);
        emit({{"event", "ar_serve"}, {"data", {
            {"response_tier", ev.response_tier},
            {"ioc_match",     ev.ioc_match},
            {"ioc_indicator", ev.ioc_indicator}
        }}});
        return;
    }

    if (cmd == "run_demo") {
        // P1 fix: run_demo used to block the stdin thread for 3+ seconds.
        // Now it spawns a detached thread so the stdin loop stays responsive.
        audit_adder("demo_started", "pass=1");
        std::thread demo_thread([audit_adder]() {
            // Start the incident at MEDIUM/HIGH. Do not reach CRITICAL yet:
            // ThreatStateMachine locks WORM immediately at CRITICAL, and the
            // local decoy files must be planted before the sandbox is frozen.
            for (int score : {30, 60}) {
                g_threat->observe_signal(score, "demo");
                g_rules->evaluate_threat_score(score, "demo");
                std::this_thread::sleep_for(std::chrono::milliseconds(800));
            }

            // Simulate and record the local decoy session while the sandbox is
            // still writable. These entries are the source of the MITRE report.
            g_decoy->plant();
            g_decoy->touch("decoy/credentials/.aws/credentials",
                            "read", "demo-atk", "demo");
            g_decoy->touch("decoy/assets/financial-projections-2024.xlsx",
                            "exfil_attempt", "demo-atk", "demo");
            g_ar->serve("demo-atk", "decoy/credentials/.aws/credentials", "185.220.101.1");

            // Complete the escalation. Score 85 reaches CRITICAL and engages
            // WORM only after the decoy evidence is already immutable-ready.
            for (int score : {85, 95}) {
                g_threat->observe_signal(score, "demo");
                g_rules->evaluate_threat_score(score, "demo");
                std::this_thread::sleep_for(std::chrono::milliseconds(800));
            }

            // Push 64 logistic-map values (r=4, chaotic)
            double x = 0.7;
            for (int i = 0; i < 64; ++i) {
                x = 4.0 * x * (1.0 - x);
                g_chaos->push(x - 0.5, true);
                std::this_thread::sleep_for(std::chrono::milliseconds(25));
            }

            // WORM lockdown
            g_worm->trigger_lockdown("demo_script");
            g_sandbox->lock_all("demo_worm");
            audit_adder("demo_completed", "pass=1");

            emit({{"event", "demo_done"}, {"data", {{"pass", 1}}}});
        });
        demo_thread.detach();
        emit({{"event", "demo_started_async"}, {"data", {{"pass", 1}}}});
        return;
    }

    if (cmd == "get_attribution") {
        std::string session = args.value("session", "demo-atk");
        Attribution reporter(g_sandbox_root, audit_adder);
        auto artifact = reporter.generate(
            session,
            g_decoy->forensic_log(),
            g_ar->forensic_log()
        );
        json techs = json::array();
        for (const auto& t : artifact.techniques) {
            techs.push_back({
                {"technique_id", t.technique_id},
                {"name",         t.name},
                {"tactic",       t.tactic},
                {"evidence",     t.evidence}
            });
        }
        emit({{"event", "attribution_report"}, {"data", {
            {"session_id",         artifact.session_id},
            {"total_interactions", artifact.total_interactions},
            {"summary",            artifact.summary},
            {"techniques",         techs}
        }}});
        return;
    }

    // -------------------------------------------------------------------
    // Step 16 ST-5: scan_and_quarantine
    // Scan a real file via clamd; if INFECTED quarantine it immediately.
    // {"cmd":"scan_and_quarantine","args":{"path":"C:\\..."}}
    // -------------------------------------------------------------------
    if (cmd == "scan_and_quarantine") {
        std::string path = args.value("path", "");
        if (path.empty()) {
            emit({{"event", "scan_quarantine_result"}, {"data", {
                {"status",      "error"},
                {"error",       "no path provided"}
            }}});
            return;
        }
        auto result = g_clamd->scan_file(path);
        bool quarantined = false;
        std::string qtn_path;
        std::string qtn_entry_id;

        if (result.status == astartis::clamd::ScanStatus::SCAN_INFECTED) {
            auto qe = g_qtn->quarantine_file(path, result.virus_name);
            quarantined  = !qe.entry_id.empty();
            qtn_path     = qe.quarantine_path;
            qtn_entry_id = qe.entry_id;
        }

        std::string status_str;
        switch (result.status) {
            case astartis::clamd::ScanStatus::SCAN_CLEAN:    status_str = "clean";    break;
            case astartis::clamd::ScanStatus::SCAN_INFECTED: status_str = "infected"; break;
            default:                                         status_str = "error";    break;
        }

        emit({{"event", "scan_quarantine_result"}, {"data", {
            {"status",         status_str},
            {"virus_name",     result.virus_name},
            {"quarantined",    quarantined},
            {"quarantine_path",qtn_path},
            {"entry_id",       qtn_entry_id},
            {"audit_entry_id", result.audit_entry_id}
        }}});
        return;
    }

    // -------------------------------------------------------------------
    // Step 16 ST-5: block_ip
    // {"cmd":"block_ip","args":{"ip":"240.0.0.1","ttl_s":900}}
    // -------------------------------------------------------------------
    if (cmd == "block_ip") {
        std::string ip  = args.value("ip", "");
        int         ttl = args.value("ttl_s", 0);
        if (ip.empty()) {
            emit({{"event", "block_ip_result"}, {"data", {
                {"blocked", false}, {"reason", "no ip provided"}
            }}});
            return;
        }
        auto br = g_firewall->block(ip, ttl);
        emit({{"event", "block_ip_result"}, {"data", {
            {"blocked",       br.blocked},
            {"reason",        br.reason},
            {"rule_name_in",  br.rule_name_in},
            {"rule_name_out", br.rule_name_out}
        }}});
        return;
    }

    // -------------------------------------------------------------------
    // Step 16 ST-5: unblock_ip
    // {"cmd":"unblock_ip","args":{"ip":"240.0.0.1"}}
    // -------------------------------------------------------------------
    if (cmd == "unblock_ip") {
        std::string ip = args.value("ip", "");
        bool ok = !ip.empty() && g_firewall->unblock(ip);
        emit({{"event", "unblock_ip_result"}, {"data", {
            {"unblocked", ok},
            {"ip",        ip}
        }}});
        return;
    }

    // -------------------------------------------------------------------
    // Step 17: unlock_vote
    // {"cmd":"unlock_vote","args":{"approver":"client-rep-1"}}
    // The bridge holds the Identity objects and calls make_signed_request
    // internally — the dashboard only needs to name the approver.
    // -------------------------------------------------------------------
    if (cmd == "unlock_vote") {
        std::string approver = args.value("approver", "");
        if (approver.empty() || !g_unlock) {
            emit({{"event", "unlock_vote_result"}, {"data", {
                {"accepted", false}, {"reason", "no_approver_or_protocol_not_ready"}
            }}});
            return;
        }
        // Look up the Identity for this approver name and sign the challenge.
        // Identities are stored in g_approver_identities (keyed by name).
        auto it = g_approver_identities.find(approver);
        if (it == g_approver_identities.end()) {
            emit({{"event", "unlock_vote_result"}, {"data", {
                    {"accepted", false}, {"reason", "unknown_approver_identity"}
            }}});
            return;
        }
        auto challenge = g_unlock->get_challenge(approver);
        if (challenge.empty()) {
            emit({{"event", "unlock_vote_result"}, {"data", {
                {"accepted", false}, {"reason", "no_challenge_or_already_voted"}
            }}});
            return;
        }
        auto signed_req = astartis::crypto::make_signed_request(*it->second.get(), challenge);
        auto vr = g_unlock->cast_vote(approver, signed_req);
        emit({{"event", "unlock_vote_result"}, {"data", {
            {"accepted",       vr.accepted},
            {"reason",         vr.reason},
            {"votes_now",      vr.votes_now},
            {"threshold",      vr.threshold},
            {"unlocked",       vr.unlocked}
        }}});
        return;
    }

    // -------------------------------------------------------------------
    // Step 17: get_unlock_status
    // -------------------------------------------------------------------
    if (cmd == "get_unlock_status") {
        auto snap = build_snapshot();
        emit({{"event", "unlock_status"}, {"data", {
            {"unlock_state",           snap["unlock_state"]},
            {"unlock_votes_collected", snap["unlock_votes_collected"]},
            {"unlock_threshold",       snap["unlock_threshold"]},
            {"unlock_approvers",       snap["unlock_approvers"]}
        }}});
        return;
    }

    // -------------------------------------------------------------------
    // Step 18: triage_event
    // {"cmd":"triage_event","args":{"event_type":"...","source":"...","score":N,"detail":"..."}}
    // Runs AI triage (fast tier + optional heavy tier) and returns result.
    // Exit code 2 pattern applies at the test level, not here.
    // -------------------------------------------------------------------
    if (cmd == "triage_event") {
        if (!g_ai_triage) {
            emit({{"event", "triage_result"}, {"data", {
                {"error", "ai_triage_not_initialised"}
            }}});
            return;
        }
        astartis::ai::TriageInput tin;
        tin.event_type = args.value("event_type", "unknown");
        tin.source     = args.value("source",     "bridge");
        tin.score      = args.value("score",       0);
        tin.raw_detail = args.value("detail",      "");
        // Truncate raw_detail to 200 chars as per spec
        if (tin.raw_detail.size() > 200)
            tin.raw_detail = tin.raw_detail.substr(0, 200);

        auto r = g_ai_triage->triage(tin);

        // Build a JSON snapshot of this result for the tick snapshot
        json rs;
        rs["event_type"]           = r.input.event_type;
        rs["score"]                = r.input.score;
        rs["fast_route"]           = r.fast.route;
        rs["fast_severity_hint"]   = r.fast.severity_hint;
        rs["fast_confidence"]      = r.fast.confidence;
        rs["fast_model"]           = r.fast.model_used;
        rs["fast_timed_out"]       = r.fast.timed_out;
        rs["model_suggested_tier"] = static_cast<int>(r.model_suggested_tier);
        rs["final_tier"]           = static_cast<int>(r.final_tier);
        rs["rule_engine_overrode"] = r.rule_engine_overrode;
        rs["audit_entry_id"]       = r.audit_entry_id;
        if (r.heavy.has_value()) {
            rs["heavy_severity"]   = r.heavy->severity;
            rs["heavy_rationale"]  = r.heavy->rationale;
            rs["heavy_mitre"]      = r.heavy->mitre_technique;
            rs["heavy_model"]      = r.heavy->model_used;
            rs["heavy_timed_out"]  = r.heavy->timed_out;
        }

        {
            std::lock_guard<std::mutex> lk(g_triage_snap_mutex);
            g_last_triage_snap = rs;
        }

        emit({{"event", "triage_result"}, {"data", rs}});
        return;
    }

    // -------------------------------------------------------------------
    // v2.0: agent_submit
    // Submit a task to a named agent persona.
    // {"cmd":"agent_submit","args":{"agent_name":"alert_triage","input":"...","priority":"normal"}}
    // priority: "high" | "normal" | "low"   (default: "normal")
    // Returns: {"event":"agent_submitted","data":{"task_id":"..."}} immediately.
    // Result arrives later as {"event":"agent_task_result","data":{...}}
    // -------------------------------------------------------------------
    if (cmd == "agent_submit") {
        if (!g_agents) {
            emit({{"event", "agent_submitted"}, {"data", {
                {"error", "agent_controller_not_initialised"}
            }}});
            return;
        }
        std::string agent_name = args.value("agent_name", "");
        std::string input      = args.value("input",      "");
        std::string prio_str   = args.value("priority",   "normal");

        if (agent_name.empty() || input.empty()) {
            emit({{"event", "agent_submitted"}, {"data", {
                {"error", "agent_name and input are required"}
            }}});
            return;
        }

        astartis::agents::Priority prio = astartis::agents::Priority::NORMAL;
        if (prio_str == "high") prio = astartis::agents::Priority::HIGH;
        if (prio_str == "low")  prio = astartis::agents::Priority::LOW;

        std::string task_id = g_agents->submit_task(agent_name, input, prio);
        if (task_id.empty()) {
            emit({{"event", "agent_submitted"}, {"data", {
                {"error", "unknown_agent"},
                {"agent_name", agent_name}
            }}});
        } else {
            audit_adder("agent_submit", "agent=" + agent_name + " task=" + task_id);
            emit({{"event", "agent_submitted"}, {"data", {
                {"task_id",    task_id},
                {"agent_name", agent_name},
                {"priority",   prio_str}
            }}});
        }
        return;
    }

    // -------------------------------------------------------------------
    // v2.0: agent_status
    // Get live status of all loaded agents.
    // {"cmd":"agent_status"}
    // Returns: {"event":"agent_status_update","data":{"agent_statuses":[...],"agent_queue_depth":N}}
    // -------------------------------------------------------------------
    if (cmd == "agent_status") {
        if (!g_agents) {
            emit({{"event", "agent_status_update"}, {"data", {
                {"agent_statuses",    json::array()},
                {"agent_queue_depth", 0},
                {"error",             "agent_controller_not_initialised"}
            }}});
            return;
        }
        auto statuses = g_agents->get_statuses();
        json status_arr = json::array();
        for (const auto& s : statuses) {
            std::string state_str;
            switch (s.state) {
                case astartis::agents::AgentState::IDLE:      state_str = "IDLE";      break;
                case astartis::agents::AgentState::RUNNING:   state_str = "RUNNING";   break;
                case astartis::agents::AgentState::COMPLETED: state_str = "COMPLETED"; break;
                case astartis::agents::AgentState::FAILED:    state_str = "FAILED";    break;
                default:                                       state_str = "IDLE";      break;
            }
            status_arr.push_back({
                {"name",                s.name},
                {"category",            s.category},
                {"state",               state_str},
                {"last_task_id",        s.last_task_id},
                {"last_result_snippet", s.last_result_snippet},
                {"last_run_at_ms",      s.last_run_at_ms},
                {"tasks_completed",     s.tasks_completed},
                {"tasks_failed",        s.tasks_failed}
            });
        }
        emit({{"event", "agent_status_update"}, {"data", {
            {"agent_statuses",    status_arr},
            {"agent_queue_depth", static_cast<int>(g_agents->queue_depth())}
        }}});
        return;
    }

    // -------------------------------------------------------------------
    // v2.1: network_get_ssids
    // Returns the three defined SSID configurations as JSON.
    // {"cmd":"network_get_ssids"}
    // -------------------------------------------------------------------
    if (cmd == "network_get_ssids") {
        using namespace astartis::network;
        auto pub  = make_public_ssid();
        auto ent  = make_enterprise_ssid();
        auto mgmt = make_management_ssid();

        auto ssid_to_json = [](const SSIDConfig& s) -> json {
            std::string posture_str;
            switch (s.posture) {
                case SecurityPosture::FILTERED_INTERNET: posture_str = "FILTERED_INTERNET"; break;
                case SecurityPosture::ZERO_TRUST:        posture_str = "ZERO_TRUST";        break;
                case SecurityPosture::MANAGEMENT:        posture_str = "MANAGEMENT";        break;
            }
            return json{
                {"ssid_name",               s.ssid_name},
                {"vlan_id",                 s.vlan_id},
                {"ip_subnet",               s.ip_subnet},
                {"gateway",                 s.gateway},
                {"posture",                 posture_str},
                {"client_isolation",        s.client_isolation},
                {"requires_8021x",          s.requires_8021x},
                {"captive_portal_url",      s.captive_portal_url},
                {"bandwidth_limit_mbps",    s.bandwidth_limit_mbps},
                {"session_timeout_minutes", s.session_timeout_minutes}
            };
        };

        emit({{"event", "network_ssids"}, {"data", {
            {"ssids", json::array({ssid_to_json(pub), ssid_to_json(ent), ssid_to_json(mgmt)})}
        }}});
        return;
    }

    // -------------------------------------------------------------------
    // v2.1: nac_simulate_device
    // Runs the 8-step NAC workflow simulation for a device + returns verbose steps.
    // {"cmd":"nac_simulate_device","args":{
    //     "device_mac":"11:22:33:44:55:66",
    //     "device_name":"IT-Laptop-001",
    //     "ssid_name":"eGov",
    //     "username":"kgosi.blanda",
    //     "domain":"egov.gov.bw",
    //     "os_updated":true,
    //     "antivirus_running":true,
    //     "disk_encrypted":true,
    //     "firewall_enabled":true
    // }}
    // -------------------------------------------------------------------
    if (cmd == "nac_simulate_device") {
        using namespace astartis::zerotrust;
        AccessRequest req;
        req.device_mac              = args.value("device_mac",  "00:00:00:00:00:00");
        req.device_name             = args.value("device_name", "Unknown-Device");
        req.ssid_name               = args.value("ssid_name",   "SmartBots");
        req.identity.username       = args.value("username",    "");
        req.identity.domain         = args.value("domain",      "");
        req.posture.os_updated      = args.value("os_updated",      false);
        req.posture.antivirus_running = args.value("antivirus_running", false);
        req.posture.disk_encrypted  = args.value("disk_encrypted",  false);
        req.posture.firewall_enabled= args.value("firewall_enabled", false);

        NACWorkflow nac;
        auto steps   = nac.process_verbose(req);
        auto decision= nac.process(req);

        // Map result enum to string
        auto result_str = [](NACDecision::Result r) -> std::string {
            switch (r) {
                case NACDecision::Result::ALLOW_FULL:    return "ALLOW_FULL";
                case NACDecision::Result::ALLOW_LIMITED: return "ALLOW_LIMITED";
                case NACDecision::Result::MFA_REQUIRED:  return "MFA_REQUIRED";
                case NACDecision::Result::QUARANTINE:    return "QUARANTINE";
                case NACDecision::Result::DENY:          return "DENY";
                default:                                  return "DENY";
            }
        };

        json steps_arr = json::array();
        int idx = 0;
        for (const auto& step : steps) {
            steps_arr.push_back({
                {"step",        idx + 1},
                {"passed",      step.passed},
                {"detail",      step.detail},
                {"duration_ms", step.duration_ms.count()}
            });
            ++idx;
        }

        json resources_arr = json::array();
        for (const auto& r : decision.accessible_resources)
            resources_arr.push_back(r);

        audit_adder("nac_simulate",
            "device=" + req.device_name +
            " ssid="  + req.ssid_name  +
            " user="  + req.identity.username +
            " result="+ result_str(decision.result));

        emit({{"event", "nac_result"}, {"data", {
            {"device_mac",           req.device_mac},
            {"device_name",          req.device_name},
            {"ssid_name",            req.ssid_name},
            {"result",               result_str(decision.result)},
            {"assigned_vlan",        decision.assigned_vlan},
            {"assigned_role",        decision.assigned_role},
            {"accessible_resources", resources_arr},
            {"remediation_reason",   decision.remediation_reason},
            {"reauth_interval_s",    decision.reauth_interval.count()},
            {"steps",                steps_arr}
        }}});
        return;
    }

    // -------------------------------------------------------------------
    // v2.1: zerotrust_evaluate
    // Evaluate a single access request through the Zero Trust engine.
    // {"cmd":"zerotrust_evaluate","args":{
    //     "user_id":"kgosi.blanda",
    //     "device_id":"IT-Laptop-001",
    //     "source_ip":"10.0.200.50",
    //     "destination_ip":"10.0.200.10",
    //     "requested_resource":"file-server",
    //     "ssid_name":"eGov"
    // }}
    // -------------------------------------------------------------------
    if (cmd == "zerotrust_evaluate") {
        using namespace astartis::zerotrust;
        AccessContext ctx;
        ctx.user_id            = args.value("user_id",            "unknown");
        ctx.device_id          = args.value("device_id",          "unknown");
        ctx.source_ip          = args.value("source_ip",          "0.0.0.0");
        ctx.destination_ip     = args.value("destination_ip",     "0.0.0.0");
        ctx.requested_resource = args.value("requested_resource", "");
        ctx.ssid_name          = args.value("ssid_name",          "SmartBots");

        // ZeroTrustEngine constructor requires audit_adder — wire through the bridge's lambda
        ZeroTrustEngine engine(
            [](const std::string& k, const std::string& v) -> std::string {
                // Forward to bridge audit system
                return k + ":" + v;
            }
        );

        int   score    = engine.calculate_trust_score(ctx);
        ctx.trust_score = score;
        auto  decision = engine.evaluate(ctx);

        audit_adder("zerotrust_evaluate",
            "user="     + ctx.user_id +
            " src="     + ctx.source_ip +
            " dst="     + ctx.destination_ip +
            " resource="+ ctx.requested_resource +
            " decision="+ ZeroTrustEngine::decision_str(decision));

        emit({{"event", "zerotrust_result"}, {"data", {
            {"user_id",            ctx.user_id},
            {"device_id",          ctx.device_id},
            {"source_ip",          ctx.source_ip},
            {"destination_ip",     ctx.destination_ip},
            {"requested_resource", ctx.requested_resource},
            {"ssid_name",          ctx.ssid_name},
            {"trust_score",        score},
            {"decision",           ZeroTrustEngine::decision_str(decision)}
        }}});
        return;
    }

    emit({{"event", "unknown_cmd"}, {"data", {{"cmd", cmd}}}});
}

// ---------------------------------------------------------------------------
// Chaos window callback
// ---------------------------------------------------------------------------

static void on_chaos_window(const ChaosWindow& w)
{
    // Feed into rule engine
    auto rr = g_rules->evaluate_chaos_window(w);
    if (rr.worm_triggered)
        g_worm->trigger_lockdown("RULE-05 chaos K=" + std::to_string(w.K));

    // Step 16 ST-5: emit firewall candidate when RULE-05 fires on real data.
    // Elixir calls block_ip after receiving this — rule engine keeps authority.
    if (rr.worm_triggered && !w.synthetic) {
        emit({{"event", "rule05_firewall_candidate"}, {"data", {
            {"K",         w.K},
            {"anomalous", w.anomalous},
            {"source_ip", ""}   // populated by packet sensor in a live capture
        }}});
    }

    // Update latest values for tick snapshot
    g_latest_K.store(w.K);
    g_latest_anomalous.store(w.anomalous);
    g_latest_chaos_windows.store(w.window_index + 1);

    // Maintain rolling history
    {
        std::lock_guard<std::mutex> lk(g_hist_mutex);
        g_chaos_history.push_back(w.K);
        if (g_chaos_history.size() > 100)
            g_chaos_history.erase(g_chaos_history.begin());
    }

    // Emit immediate chaos_window event
    emit({{"event", "chaos_window"}, {"data", {
        {"K",            w.K},
        {"anomalous",    w.anomalous},
        {"window_index", w.window_index},
        {"lambda1",      std::isnan(w.lambda1) ? json(nullptr) : json(w.lambda1)}
    }}});
}

// ---------------------------------------------------------------------------
// Tick thread
// ---------------------------------------------------------------------------

static void tick_loop()
{
    while (g_running.load()) {
        emit({{"event", "tick"}, {"data", build_snapshot()}});
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

// ---------------------------------------------------------------------------
// stdin reader thread
// ---------------------------------------------------------------------------

static void stdin_loop()
{
    std::string line;
    while (g_running.load() && std::getline(std::cin, line)) {
        // Strip trailing \r from Windows line endings (\r\n -> \n -> \r left by getline)
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        try {
            dispatch(json::parse(line));
        } catch (const std::exception& ex) {
            emit({{"event", "parse_error"}, {"data", {{"msg", ex.what()}}}});
        }
    }
    g_running.store(false);
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Daemon mode helper
// ---------------------------------------------------------------------------
// When --daemon is passed, the process writes its PID to a file and redirects
// stderr to a log file so it can run detached from the console.
// Stdout stays connected to the Elixir port pipe — do NOT redirect it.
// ---------------------------------------------------------------------------

static bool g_daemon_mode = false;

static void enter_daemon_mode(const std::string& pid_file_path,
                               const std::string& log_file_path)
{
    // Write PID file
    try {
        std::ofstream pid_file(pid_file_path);
        if (pid_file) {
            pid_file << GetCurrentProcessId() << "\n";
        }
    } catch (...) { /* non-fatal */ }

    // Redirect stderr to log file (stdout stays on the port pipe)
    try {
        FILE* dummy = nullptr;
        freopen_s(&dummy, log_file_path.c_str(), "a", stderr);
        // If freopen_s fails, stderr stays on the console — not fatal
        (void)dummy;
    } catch (...) { /* non-fatal */ }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main(int argc, char* argv[])
{
    bool launch_dashboard = false;

    // Parse CLI flags
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--daemon")    g_daemon_mode    = true;
        if (arg == "--dashboard") launch_dashboard = true;
    }

    // Unbuffered stdout so each JSON line arrives at Elixir immediately
    setvbuf(stdout, nullptr, _IONBF, 0);

    if (g_daemon_mode) {
        auto tmp = fs::temp_directory_path();
        enter_daemon_mode(
            (tmp / "astartis_bridge.pid").string(),
            (tmp / "astartis_bridge.log").string()
        );
    }

    // Check elevation before any threads start (ST-2 gate)
    g_is_elevated = check_elevation();

    // Sandbox in system temp
    g_sandbox_root = (fs::temp_directory_path() / "astartis_demo").string();
    fs::create_directories(g_sandbox_root);

    auto audit_adder = make_audit_adder();

    // -----------------------------------------------------------------------
    // Graceful degradation (P2 fix): wrap each subsystem in try/catch.
    // If a subsystem fails to construct, log the failure and continue in
    // degraded mode — the bridge still serves other subsystems.
    // The "ready" event lists which subsystems are available.
    // -----------------------------------------------------------------------

    std::vector<std::string> degraded_subsystems;

    auto try_init = [&](const char* name, std::function<void()> init_fn) {
        try {
            init_fn();
        } catch (const std::exception& ex) {
            std::string msg = std::string(name) + " init failed: " + ex.what();
            degraded_subsystems.push_back(msg);
            emit({{"event", "subsystem_degraded"}, {"data", {
                {"subsystem", name},
                {"reason",    ex.what()}
            }}});
        } catch (...) {
            degraded_subsystems.push_back(std::string(name) + " init failed: unknown exception");
            emit({{"event", "subsystem_degraded"}, {"data", {
                {"subsystem", name},
                {"reason",    "unknown exception"}
            }}});
        }
    };

    // Core WORM + Sandbox — most critical; if these fail, emit a hard error
    try_init("worm_lock", [&]() {
        g_worm = std::make_unique<WormLock>(audit_adder);
    });

    if (!g_worm) {
        emit({{"event", "fatal_error"}, {"data", {
            {"msg", "WormLock failed to initialise — bridge cannot start"}
        }}});
        return 1;
    }

    try_init("sandbox", [&]() {
        g_sandbox = std::make_unique<Sandbox>(
            g_sandbox_root, audit_adder,
            [&]() { return g_worm->is_locked(); }
        );
        g_sandbox->populate();
    });

    auto worm_trigger_fn = [&](const std::string& reason) {
        g_worm->trigger_lockdown(reason);
    };

    try_init("threat_level", [&]() {
        g_threat = std::make_unique<ThreatSM>(audit_adder, worm_trigger_fn);
    });

    // RuleEngine depends on ThreatSM — only init if threat is available
    if (g_threat) {
        try_init("rule_engine", [&]() {
            g_rules = std::make_unique<RuleEngine>(
                audit_adder,
                *g_threat,
                worm_trigger_fn,
                [&]() { return g_worm->is_locked(); }
            );
        });
    } else {
        degraded_subsystems.push_back("rule_engine skipped: threat_level unavailable");
    }

    try_init("chaos_detector", [&]() {
        g_chaos = std::make_unique<ChaosDetect>(
            on_chaos_window, audit_adder,
            16   // 16-sample window for demo: 40 pushes guarantees 2+ windows fire
        );
    });

    if (g_sandbox) {
        try_init("decoy", [&]() {
            g_decoy = std::make_unique<DecoyEnv>(*g_sandbox, audit_adder);
        });
    } else {
        degraded_subsystems.push_back("decoy skipped: sandbox unavailable");
    }

    try_init("active_response", [&]() {
        g_ar = std::make_unique<ActiveResp>(audit_adder);
    });

    try_init("clamd", [&]() {
        g_clamd = std::make_unique<ClamdScan>(audit_adder, "127.0.0.1", 3310);
    });

    try_init("quarantine", [&]() {
        std::string qtn_dir = g_is_elevated
            ? Quarantine::DEFAULT_DIR
            : (fs::temp_directory_path() / "astartis_quarantine").string();
        g_qtn = std::make_unique<Quarantine>(qtn_dir, audit_adder);
    });

    try_init("firewall", [&]() {
        g_firewall = std::make_unique<FwBlocker>(audit_adder);
    });

    // Step 17: 12-eye unlock protocol (DEMO-SCALE: 3 approvers stand in for 12)
    try_init("unlock_protocol", [&]() {
        g_tokens = std::make_unique<TokenStore>(audit_adder);

        constexpr int64_t TTL_24H = 24LL * 60 * 60 * 1000;
        g_approver_identities["astartis-admin-1"] =
            std::make_unique<astartis::crypto::Identity>("astartis-admin-1");
        g_approver_identities["client-rep-1"] =
            std::make_unique<astartis::crypto::Identity>("client-rep-1");
        g_approver_identities["client-rep-2"] =
            std::make_unique<astartis::crypto::Identity>("client-rep-2");

        auto t_ast = g_tokens->grant("astartis-admin-1", "worm_unlock_vote", TTL_24H);
        auto t_cl1 = g_tokens->grant("client-rep-1",     "worm_unlock_vote", TTL_24H);
        auto t_cl2 = g_tokens->grant("client-rep-2",     "worm_unlock_vote", TTL_24H);

        g_unlock = std::make_unique<UnlockProtocol>(
            audit_adder,
            *g_tokens,
            [&](const std::string& authority){ g_worm->unlock(authority); },
            UnlockProtocol::DEMO_THRESHOLD   // 3 — DEMO-SCALE STAND-IN for 12
        );
        g_unlock->register_approver("astartis-admin-1", ApproverSide::ASTARTIS,
            g_approver_identities["astartis-admin-1"]->public_key_der(), t_ast.token_id);
        g_unlock->register_approver("client-rep-1", ApproverSide::CLIENT,
            g_approver_identities["client-rep-1"]->public_key_der(), t_cl1.token_id);
        g_unlock->register_approver("client-rep-2", ApproverSide::CLIENT,
            g_approver_identities["client-rep-2"]->public_key_der(), t_cl2.token_id);
    });

    // Step 18: AI triage (advisory — rule engine retains final authority)
    if (g_rules) {
        try_init("ai_triage", [&]() {
            g_ai_triage = std::make_unique<AiTriage>(audit_adder, *g_rules);
        });
    } else {
        degraded_subsystems.push_back("ai_triage skipped: rule_engine unavailable");
    }

    // Step 19: Veeam / IBM Storage backup interface (stubbed for demo)
    try_init("veeam", [&]() {
        g_veeam = std::make_unique<VeeamIface>(audit_adder);
    });

    // v2.0: Agent swarm controller — loads all personas from agents/definitions/
    // Runs on local IBM Granite only; zero cloud API cost.
    try_init("agent_controller", [&]() {
        g_agents = std::make_unique<astartis::agents::AgentController>(audit_adder);
        std::vector<fs::path> json_candidates = {
            fs::path("agents/definitions"),
            fs::path("../astartis/agents/definitions"),
            fs::path("../agents/definitions"),
            fs::path("../../agents/definitions")
        };
        int json_loaded = 0;
        for (const auto& candidate : json_candidates) {
            if (fs::exists(candidate)) {
                json_loaded = g_agents->load_all_personas(candidate);
                if (json_loaded > 0) break;
            }
        }
        std::vector<fs::path> ecc_candidates = {
            fs::path("agents/ecc/agents"),
            fs::path("../astartis/agents/ecc/agents"),
            fs::path("../agents/ecc/agents"),
            fs::path("../../agents/ecc/agents")
        };
        int ecc_loaded = 0;
        for (const auto& candidate : ecc_candidates) {
            if (fs::exists(candidate)) {
                ecc_loaded = g_agents->load_ecc_personas(candidate);
                if (ecc_loaded > 0) break;
            }
        }
        const int loaded = json_loaded + ecc_loaded;
        audit_adder("agent_controller_ready",
                    "personas_loaded=" + std::to_string(loaded) +
                    " json=" + std::to_string(json_loaded) +
                    " ecc=" + std::to_string(ecc_loaded));
        auto statuses = g_agents->get_statuses();
        json status_arr = json::array();
        for (const auto& s : statuses) {
            status_arr.push_back({
                {"name",     s.name},
                {"category", s.category},
                {"state",    "IDLE"},
                {"tasks_completed", 0},
                {"tasks_failed",    0},
                {"last_result_snippet", ""}
            });
        }
        emit({{"event", "agent_status_update"}, {"data", {
            {"agent_statuses",    status_arr},
            {"agent_queue_depth", 0},
            {"personas_loaded",   loaded}
        }}});
        g_agents->start();
    });

    // Build degraded list for the ready event
    json degraded_arr = json::array();
    for (const auto& msg : degraded_subsystems) degraded_arr.push_back(msg);

    // Announce readiness (includes elevation status — ST-2 gate)
    emit({{"event", "ready"}, {"data", {
        {"sandbox_root",        g_sandbox_root},
        {"chain_length",        g_audit.get_chain_length()},
        {"elevated",            g_is_elevated},
        {"daemon_mode",         g_daemon_mode},
        {"degraded_subsystems", degraded_arr}
    }}});

    // --dashboard: start the JSON writer and launch the browser
    if (launch_dashboard) {
        // Robustly locate dashboard/ by walking up from the exe, then falling
        // back to CWD. Works regardless of how/where the binary was invoked.
        fs::path exe_path = fs::absolute(argv[0]);
        std::cerr << "[Bridge] argv[0]=" << (argv[0] ? argv[0] : "NULL") << "\n";
        std::cerr << "[Bridge] exe_path=" << exe_path.string() << "\n";

        fs::path exe_dir  = exe_path.parent_path();
        fs::path dash_dir;
        for (int up = 0; up < 5; ++up) {
            fs::path candidate = exe_dir / "dashboard";
            if (fs::exists(candidate) && fs::is_directory(candidate)) {
                dash_dir = candidate;
                break;
            }
            fs::path parent = exe_dir.parent_path();
            if (parent == exe_dir) break;   // reached filesystem root
            exe_dir = parent;
        }
        if (dash_dir.empty()) {
            // Last resort: CWD / dashboard
            dash_dir = fs::current_path() / "dashboard";
        }
        std::string out_dir = dash_dir.string();
        std::cerr << "[Bridge] dash_dir=" << out_dir << "\n";

        g_dashboard_writer = std::make_unique<astartis::dashboard::DashboardWriter>(out_dir);

        g_dashboard_writer->set_data_provider([&]() -> astartis::dashboard::DashboardData {
            namespace dash = astartis::dashboard;
            dash::DashboardData d;
            d.system_mode   = "FULL";
            d.system_status = "online";

            // ---- Threat level ----
            if (g_threat) {
                auto tier = g_threat->current_tier();
                switch (tier) {
                    case ThreatTier::CRITICAL: d.threat_level = "CRITICAL"; d.threat_score = 95; break;
                    case ThreatTier::HIGH:     d.threat_level = "HIGH";     d.threat_score = 75; break;
                    case ThreatTier::MEDIUM:   d.threat_level = "MEDIUM";   d.threat_score = 45; break;
                    default:                   d.threat_level = "LOW";      d.threat_score = 15; break;
                }
            }

            // ---- Agents ----
            if (g_agents) {
                d.queue_depth = static_cast<int>(g_agents->queue_depth());
                auto statuses = g_agents->get_statuses();
                d.active_agents = 0;
                for (const auto& s : statuses) {
                    dash::AgentStatus a;
                    a.name  = s.name;
                    a.tier  = s.tier;   // real tier from persona JSON
                    a.model = (a.tier == "FAST") ? "granite3.1-moe:3b" : "granite4.1-8b";
                    a.last_active = s.last_active;
                    switch (s.state) {
                        case astartis::agents::AgentState::RUNNING:
                            a.status = "busy";    ++d.active_agents; break;
                        case astartis::agents::AgentState::IDLE:
                            a.status = "online";  ++d.active_agents; break;
                        default:
                            a.status = "offline"; break;
                    }
                    a.tasks_completed = s.tasks_completed;
                    d.agents.push_back(a);
                }
            }

            // ---- Alerts (approx from audit chain length) ----
            d.alerts_24h     = static_cast<int>(g_audit.get_chain_length());
            d.critical_alerts = (d.threat_level == "CRITICAL") ? 1 : 0;

            // ---- WORM status ----
            d.worm_is_locked = g_worm ? g_worm->is_locked() : false;

            // ---- System metrics (real Windows PDH) ----
            d.system_metrics = dash::query_windows_metrics();

            // ---- Update rolling history (cap at 20 samples) ----
            {
                std::lock_guard<std::mutex> lk(g_metrics_hist_mutex);
                auto push_history = [](std::vector<double>& h, double v) {
                    if (h.size() >= 20) h.erase(h.begin());
                    h.push_back(v);
                };
                push_history(g_cpu_history,  d.system_metrics.cpu_percent);
                push_history(g_mem_history,  d.system_metrics.memory_percent);
                push_history(g_disk_history, d.system_metrics.disk_percent);
                push_history(g_net_history,  d.system_metrics.network_mbps);
                d.cpu_history  = g_cpu_history;
                d.mem_history  = g_mem_history;
                d.disk_history = g_disk_history;
                d.net_history  = g_net_history;
            }

            // ---- System health (Ollama / Npcap / ClamAV / Admin) ----
            d.health = dash::query_system_health();

            // ---- Firewall blocks ----
            if (g_firewall) {
                for (const auto& b : g_firewall->active_blocks()) {
                    dash::FirewallBlockData fb;
                    fb.ip            = b.ip;
                    fb.rule_name_in  = b.rule_name_in;
                    fb.blocked_at_ms = b.blocked_at_ms;
                    fb.expires_at_ms = b.expires_at_ms;
                    d.firewall_blocks.push_back(fb);
                }
            }

            // ---- Quarantine entries ----
            if (g_qtn) {
                for (const auto& e : g_qtn->list()) {
                    dash::QuarantineEntryData q;
                    q.entry_id           = e.entry_id;
                    q.virus_name         = e.virus_name;
                    q.quarantined_at_ms  = e.quarantined_at_ms;
                    d.quarantine_entries.push_back(q);
                }
            }

            // ---- Decoy events ----
            if (g_decoy) {
                for (const auto& ev : g_decoy->forensic_log()) {
                    dash::DecoyEventData de;
                    de.attacker_tag  = ev.attacker_tag;
                    de.poison_type   = astartis::decoy::poison_type_name(ev.poison_type);
                    de.action        = ev.action;
                    de.timestamp_ms  = ev.timestamp_ms;
                    d.decoy_events.push_back(de);
                }
            }

            // ---- Sandbox entries ----
            if (g_sandbox) {
                for (const auto& e : g_sandbox->get_tree()) {
                    dash::SandboxEntryData se;
                    se.rel_path = e.rel_path;
                    se.type     = (e.type == astartis::sandbox::EntryType::DIRECTORY)
                                  ? "DIRECTORY" : "FILE";
                    se.locked   = e.locked;
                    se.version  = e.version;
                    d.sandbox_entries.push_back(se);
                }
            }

            // ---- Audit chain ----
            {
                auto vr = g_audit.verify_chain();
                d.audit_chain_valid = vr.is_valid;
                auto all = g_audit.get_all_entries();
                size_t start = (all.size() > 10) ? all.size() - 10 : 0;
                for (size_t i = start; i < all.size(); ++i) {
                    dash::AuditEntryData ae;
                    ae.entry_id   = all[i].entry_id;
                    ae.event_type = all[i].event_type;
                    ae.timestamp  = std::to_string(all[i].timestamp);
                    ae.chain_valid = vr.is_valid;
                    d.audit_entries.push_back(ae);
                }
            }

            // ---- Log entry ----
            dash::LogEntry log;
            log.level   = "INFO";
            log.message = "Bridge tick — agents=" + std::to_string(d.active_agents) +
                          " queue=" + std::to_string(d.queue_depth) +
                          " threat=" + d.threat_level +
                          " worm=" + (d.worm_is_locked ? "LOCKED" : "NORMAL");
            d.new_logs.push_back(log);

            return d;
        });

        g_dashboard_writer->start(5);

        // Start HTTP server for dashboard (serves static files + /dashboard_data.json + /exec)
        g_dashboard_server = std::make_unique<astartis::dashboard::DashboardServer>(
            out_dir, out_dir + "/dashboard_data.json", 9876);
        g_dashboard_server->start();

        // Open browser to HTTP URL (not file:///) so fetch() is not blocked by CORS
        std::string url = "http://127.0.0.1:9876/";
        ShellExecuteA(nullptr, "open", url.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
        std::cerr << "[Dashboard] Writer started. Launched: " << url << "\n";
    }

    // Start threads
    std::thread tick_th(tick_loop);
    std::thread stdin_th(stdin_loop);

    stdin_th.join();
    g_running.store(false);
    tick_th.join();
    if (g_dashboard_server) g_dashboard_server->stop();
    if (g_dashboard_writer) g_dashboard_writer->stop();
    // All unique_ptr globals are destroyed automatically at program exit.
    // No manual delete needed — that's the whole point of RAII.
    return 0;
}

