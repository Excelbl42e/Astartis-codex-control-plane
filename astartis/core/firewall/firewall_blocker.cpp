// Step 16 ST-4 -- FirewallBlocker implementation
//
// See firewall_blocker.h for API documentation.

// Winsock2 before windows.h
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

#include "firewall/firewall_blocker.h"

#include <chrono>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <stdexcept>
#include <cstring>
#include <cctype>

namespace astartis {
namespace firewall {

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

static int64_t now_ms()
{
    using namespace std::chrono;
    return duration_cast<milliseconds>(
               system_clock::now().time_since_epoch()).count();
}

// Parse text as exactly one IPv4 or IPv6 address literal. On success fill
// addr (first 4 bytes for IPv4, all 16 for IPv6), set is_v4 and write the
// canonical inet_ntop form. IPv4-mapped IPv6 (::ffff:a.b.c.d) is unmapped to
// plain IPv4 so it compares equal to IPv4 allowlist entries.
static bool parse_ip_literal(const std::string& text,
                             std::string& canonical,
                             unsigned char (&addr)[16],
                             bool& is_v4)
{
    // INET6_ADDRSTRLEN covers the longest address text plus its NUL.
    if (text.empty() || text.size() >= INET6_ADDRSTRLEN) return false;

    // Address literals use only hex digits, '.' and ':'. Rejecting everything
    // else up front keeps whitespace, quotes, '/', '-', '%' and keywords such
    // as "any" away from inet_pton, whose leniency varies by platform.
    for (unsigned char c : text) {
        if (!std::isxdigit(c) && c != '.' && c != ':') return false;
    }

    std::memset(addr, 0, sizeof(addr));
    int family = AF_INET;
    if (inet_pton(AF_INET, text.c_str(), addr) != 1) {
        if (inet_pton(AF_INET6, text.c_str(), addr) != 1) return false;
        static const unsigned char v4_mapped_prefix[12] =
            {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
        if (std::memcmp(addr, v4_mapped_prefix, sizeof(v4_mapped_prefix)) == 0) {
            std::memmove(addr, addr + 12, 4);
            std::memset(addr + 4, 0, 12);
        } else {
            family = AF_INET6;
        }
    }
    is_v4 = (family == AF_INET);

    char buf[INET6_ADDRSTRLEN] = {};
    if (!inet_ntop(family, addr, buf, sizeof(buf))) return false;
    canonical = buf;
    return true;
}

bool FirewallBlocker::canonicalize_ip(const std::string& ip,
                                      std::string& canonical,
                                      std::string& reason)
{
    canonical.clear();
    unsigned char addr[16];
    bool is_v4 = false;
    std::string parsed;
    if (!parse_ip_literal(ip, parsed, addr, is_v4)) {
        // ip is deliberately not echoed: it is untrusted and the reason ends
        // up in bridge events and audit payloads.
        reason = "invalid ip: expected a single IPv4 or IPv6 address "
                 "(no hostnames, keywords, CIDR, ranges or whitespace)";
        return false;
    }

    const unsigned char* first = addr;
    const unsigned char* last  = addr + (is_v4 ? 4 : 16);
    const bool unspecified =
        std::all_of(first, last, [](unsigned char b) { return b == 0; });
    const bool broadcast =
        is_v4 && std::all_of(first, last, [](unsigned char b) { return b == 0xff; });
    const bool multicast =
        is_v4 ? (addr[0] & 0xf0) == 0xe0   // 224.0.0.0/4
              : addr[0] == 0xff;           // ff00::/8
    const char* kind = unspecified ? "unspecified"
                     : broadcast   ? "broadcast"
                     : multicast   ? "multicast"
                     :               nullptr;
    if (kind) {
        reason = "ip " + parsed + " is " + (unspecified ? "an " : "a ") + kind +
                 " address — not blocked";
        return false;
    }

    canonical = parsed;
    return true;
}

// Run "netsh <args>" via CreateProcess; return exit code.
// stdout/stderr are discarded.
int FirewallBlocker::run_netsh(const std::string& args)
{
    std::string cmd = "netsh " + args;

    STARTUPINFOA si{};
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESTDHANDLES;
    // Discard all output — open NUL device
    HANDLE nul = CreateFileA("NUL", GENERIC_WRITE, FILE_SHARE_WRITE,
                             nullptr, OPEN_EXISTING, 0, nullptr);
    si.hStdOutput = nul;
    si.hStdError  = nul;
    si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION pi{};
    // CreateProcess needs a mutable buffer
    std::vector<char> buf(cmd.begin(), cmd.end());
    buf.push_back('\0');

    BOOL ok = CreateProcessA(
        nullptr, buf.data(),
        nullptr, nullptr,
        TRUE,                          // bInheritHandles — pass NUL handles
        CREATE_NO_WINDOW,
        nullptr, nullptr,
        &si, &pi
    );

    if (nul != INVALID_HANDLE_VALUE) CloseHandle(nul);
    if (!ok) return -1;

    WaitForSingleObject(pi.hProcess, 30000); // 30 s timeout
    DWORD exit_code = 1;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return static_cast<int>(exit_code);
}

bool FirewallBlocker::add_rule(const std::string& name,
                                const std::string& ip,
                                const std::string& dir)
{
    // Defence in depth: only an already-canonical single address may become
    // a netsh argument, whatever the caller passed.
    std::string canonical, reason;
    if (!canonicalize_ip(ip, canonical, reason) || canonical != ip) return false;

    // netsh advfirewall firewall add rule
    //   name="..." protocol=any dir=in|out action=block remoteip=<ip>
    std::string args =
        "advfirewall firewall add rule"
        " name=\"" + name + "\""
        " protocol=any"
        " dir="    + dir  +
        " action=block"
        " remoteip=" + ip;
    return netsh_(args) == 0;
}

bool FirewallBlocker::delete_rule(const std::string& name)
{
    std::string args =
        "advfirewall firewall delete rule"
        " name=\"" + name + "\"";
    return netsh_(args) == 0;
}

bool FirewallBlocker::ping_elevation_check()
{
    // Read-only, harmless — just proves we can run netsh advfirewall at all
    return run_netsh("advfirewall show currentprofile") == 0;
}

std::string FirewallBlocker::make_rule_stem(const std::string& ip)
{
    // Replace dots with hyphens for readability in netsh output
    std::string safe_ip = ip;
    std::replace(safe_ip.begin(), safe_ip.end(), '.', '-');
    std::replace(safe_ip.begin(), safe_ip.end(), ':', '-');
    return "Astartis-Block-" + safe_ip + "-" + std::to_string(now_ms());
}

// ---------------------------------------------------------------------------
// Allowlist construction
// ---------------------------------------------------------------------------

void FirewallBlocker::build_allowlist(const std::vector<std::string>& extra)
{
    // Static entries that must never be blocked
    allowlist_ = {"127.0.0.1", "::1", "0.0.0.0"};

    // Attempt to detect default gateway and DNS IPs via GetAdaptersInfo
    ULONG buf_size = 16384;
    std::vector<BYTE> buf(buf_size);
    auto* info = reinterpret_cast<IP_ADAPTER_INFO*>(buf.data());
    DWORD rc = GetAdaptersInfo(info, &buf_size);
    if (rc == ERROR_BUFFER_OVERFLOW) {
        buf.resize(buf_size);
        info = reinterpret_cast<IP_ADAPTER_INFO*>(buf.data());
        rc = GetAdaptersInfo(info, &buf_size);
    }
    if (rc == NO_ERROR) {
        for (auto* p = info; p; p = p->Next) {
            // Gateway
            for (auto* gw = &p->GatewayList; gw; gw = gw->Next) {
                std::string gw_ip = gw->IpAddress.String;
                if (!gw_ip.empty() && gw_ip != "0.0.0.0")
                    allowlist_.push_back(gw_ip);
            }
        }
    }

    // DNS servers via GetNetworkParams
    FIXED_INFO fi{};
    ULONG fi_size = sizeof(fi);
    if (GetNetworkParams(&fi, &fi_size) == ERROR_SUCCESS) {
        for (auto* dns = &fi.DnsServerList; dns; dns = dns->Next) {
            std::string dns_ip = dns->IpAddress.String;
            if (!dns_ip.empty() && dns_ip != "0.0.0.0")
                allowlist_.push_back(dns_ip);
        }
    }

    // Merge caller extras
    for (const auto& ip : extra)
        allowlist_.push_back(ip);

    // Canonicalize so entries compare equal to canonicalized block targets
    // (e.g. an extra "2001:DB8::1" must match a request for "2001:db8::1").
    for (auto& entry : allowlist_) {
        std::string canonical;
        unsigned char addr[16];
        bool is_v4 = false;
        if (parse_ip_literal(entry, canonical, addr, is_v4)) entry = canonical;
    }

    // Deduplicate
    std::sort(allowlist_.begin(), allowlist_.end());
    allowlist_.erase(std::unique(allowlist_.begin(), allowlist_.end()),
                     allowlist_.end());
}

// ---------------------------------------------------------------------------
// Constructor / destructor
// ---------------------------------------------------------------------------

FirewallBlocker::FirewallBlocker(
    std::function<std::string(const std::string&, const std::string&)> audit_adder,
    int default_ttl_s,
    std::vector<std::string> extra_allowlist,
    NetshRunner netsh_runner
)
    : audit_adder_(std::move(audit_adder))
    , default_ttl_s_(default_ttl_s > 0 ? default_ttl_s : DEFAULT_TTL_SECONDS)
    , netsh_(netsh_runner ? std::move(netsh_runner)
                          : NetshRunner(&FirewallBlocker::run_netsh))
{
    build_allowlist(extra_allowlist);
    expiry_thread_ = std::thread(&FirewallBlocker::expiry_loop, this);
}

FirewallBlocker::~FirewallBlocker()
{
    running_.store(false);
    if (expiry_thread_.joinable()) expiry_thread_.join();

    // Remove all remaining rules on shutdown
    std::lock_guard<std::mutex> lk(mutex_);
    for (auto& kv : blocks_) {
        delete_rule(kv.second.rule_name_in);
        delete_rule(kv.second.rule_name_out);
    }
    blocks_.clear();
}

// ---------------------------------------------------------------------------
// block
// ---------------------------------------------------------------------------

BlockResult FirewallBlocker::block(const std::string& raw_ip, int ttl_s)
{
    // 1. Parse + canonicalize — only a single address goes any further
    std::string ip, reason;
    if (!canonicalize_ip(raw_ip, ip, reason))
        return BlockResult{false, reason, "", ""};

    // 2. Allowlist check (canonical form) — BEFORE any netsh call
    {
        auto it = std::find(allowlist_.begin(), allowlist_.end(), ip);
        if (it != allowlist_.end()) {
            return BlockResult{false,
                "ip " + ip + " is in the allowlist (loopback/gateway/DNS) — not blocked",
                "", ""};
        }
    }

    std::lock_guard<std::mutex> lk(mutex_);

    // 3. Already blocked?
    if (blocks_.count(ip)) {
        return BlockResult{false, "ip " + ip + " is already blocked", "", ""};
    }

    // 4. Build rule names
    std::string stem    = make_rule_stem(ip);
    std::string name_in  = stem + "-in";
    std::string name_out = stem + "-out";

    // 5. Add the two netsh rules
    bool ok_in  = add_rule(name_in,  ip, "in");
    bool ok_out = add_rule(name_out, ip, "out");

    if (!ok_in && !ok_out) {
        return BlockResult{false,
            "netsh add rule failed for " + ip + " (not elevated?)",
            "", ""};
    }

    // 6. Record the block
    int effective_ttl = (ttl_s > 0) ? ttl_s : default_ttl_s_;
    int64_t now = now_ms();
    ActiveBlock ab{
        ip, name_in, name_out,
        now,
        now + static_cast<int64_t>(effective_ttl) * 1000,
        ""
    };

    // 7. Audit entry
    std::ostringstream pl;
    pl << "ip=" << ip
       << " rule_in="  << name_in
       << " rule_out=" << name_out
       << " ttl_s=" << effective_ttl
       << " expires_at_ms=" << ab.expires_at_ms;
    ab.audit_entry_id = audit_adder_("firewall_block", pl.str());

    blocks_[ip] = ab;

    return BlockResult{true, "blocked", name_in, name_out};
}

// ---------------------------------------------------------------------------
// unblock (public)
// ---------------------------------------------------------------------------

bool FirewallBlocker::unblock(const std::string& raw_ip)
{
    std::string ip, reason;
    if (!canonicalize_ip(raw_ip, ip, reason)) return false;

    std::lock_guard<std::mutex> lk(mutex_);
    auto it = blocks_.find(ip);
    if (it == blocks_.end()) return false;
    do_unblock_locked(it);
    return true;
}

// ---------------------------------------------------------------------------
// do_unblock_locked — caller must hold mutex_
// ---------------------------------------------------------------------------

void FirewallBlocker::do_unblock_locked(
    std::map<std::string, ActiveBlock>::iterator it)
{
    const ActiveBlock& ab = it->second;
    delete_rule(ab.rule_name_in);
    delete_rule(ab.rule_name_out);

    std::ostringstream pl;
    pl << "ip=" << ab.ip
       << " rule_in="  << ab.rule_name_in
       << " rule_out=" << ab.rule_name_out
       << " blocked_at_ms=" << ab.blocked_at_ms
       << " unblocked_at_ms=" << now_ms();
    audit_adder_("firewall_unblock", pl.str());

    blocks_.erase(it);
}

// ---------------------------------------------------------------------------
// is_blocked / active_blocks
// ---------------------------------------------------------------------------

bool FirewallBlocker::is_blocked(const std::string& raw_ip) const
{
    std::string ip, reason;
    if (!canonicalize_ip(raw_ip, ip, reason)) return false;

    std::lock_guard<std::mutex> lk(mutex_);
    return blocks_.count(ip) > 0;
}

std::vector<ActiveBlock> FirewallBlocker::active_blocks() const
{
    std::lock_guard<std::mutex> lk(mutex_);
    std::vector<ActiveBlock> out;
    out.reserve(blocks_.size());
    for (const auto& kv : blocks_) out.push_back(kv.second);
    return out;
}

// ---------------------------------------------------------------------------
// expiry_loop — background thread
// ---------------------------------------------------------------------------

void FirewallBlocker::expiry_loop()
{
    // Check-then-sleep so an already-expired block is caught on the very
    // first iteration, and the maximum latency between TTL expiry and rule
    // removal is one sleep interval (1 second).
    while (running_.load()) {
        {
            int64_t now = now_ms();
            std::lock_guard<std::mutex> lk(mutex_);
            for (auto it = blocks_.begin(); it != blocks_.end(); ) {
                if (it->second.expires_at_ms <= now) {
                    auto next = std::next(it);
                    do_unblock_locked(it);
                    it = next;
                } else {
                    ++it;
                }
            }
        }
        // Sleep 1 second per tick; re-check running_ each tick so shutdown
        // is responsive without a 30-second stall.
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

} // namespace firewall
} // namespace astartis

