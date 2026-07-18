#!/usr/bin/env node
/**
 * Astartis Control Plane MCP server.
 *
 * This adapter deliberately exposes evidence and simulation tools only. It
 * does not expose firewall, quarantine, WORM unlock, or arbitrary agent
 * execution. Astartis remains the deterministic enforcement authority.
 */
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const pluginRoot = resolve(scriptDirectory, "..");
const repositoryRoot = resolve(pluginRoot, "..", "..");
const astartisRoot = resolve(repositoryRoot, "astartis");

const toolDefinitions = [
  {
    name: "astartis_get_security_posture",
    description: "Read the current local Astartis bridge state: threat, WORM, audit-chain, sandbox, agent health, and Npcap mode. Packet telemetry is live only when the returned capture mode is live.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false }
  },
  {
    name: "astartis_list_network_zones",
    description: "List Astartis's configured public, enterprise, and management SSID/VLAN policy zones. This does not discover a physical LAN.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false }
  },
  {
    name: "astartis_simulate_nac_admission",
    description: "Safely simulate the 8-step NAC admission workflow for a device. No real network is changed.",
    inputSchema: {
      type: "object",
      properties: {
        device_mac: { type: "string", description: "Simulated MAC address." },
        device_name: { type: "string", description: "Device label shown in evidence." },
        ssid_name: { type: "string", enum: ["SmartBots", "eGov", "Astartis-Admin"] },
        username: { type: "string" },
        domain: { type: "string" },
        os_updated: { type: "boolean" },
        antivirus_running: { type: "boolean" },
        disk_encrypted: { type: "boolean" },
        firewall_enabled: { type: "boolean" }
      },
      additionalProperties: false
    }
  },
  {
    name: "astartis_evaluate_zero_trust_access",
    description: "Evaluate a simulated resource request with Astartis Zero Trust policy. No real access is changed.",
    inputSchema: {
      type: "object",
      properties: {
        user_id: { type: "string" },
        device_id: { type: "string" },
        source_ip: { type: "string" },
        destination_ip: { type: "string" },
        requested_resource: { type: "string" },
        ssid_name: { type: "string", enum: ["SmartBots", "eGov", "Astartis-Admin"] }
      },
      required: ["user_id", "device_id", "source_ip", "destination_ip", "requested_resource", "ssid_name"],
      additionalProperties: false
    }
  },
  {
    name: "astartis_get_agent_health",
    description: "Read local Astartis persona-status records and queue depth. Loaded personas are not synonymous with simultaneous model inference.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false }
  },
  {
    name: "astartis_get_attack_attribution",
    description: "Retrieve local sandbox/decoy forensic evidence and MITRE attribution for a session. It may be empty until a local scenario produces an interaction.",
    inputSchema: {
      type: "object",
      properties: { session_id: { type: "string", description: "Defaults to demo-atk." } },
      additionalProperties: false
    }
  },
  {
    name: "astartis_run_proof_mode",
    description: "Run deterministic local Proof Mode: policy denial, decoy interaction, WORM protection, and attribution. It changes only this MCP bridge's local demo session; restart MCP for a fresh session.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false }
  }
];

function bridgePath() {
  const candidates = [
    process.env.ASTARTIS_BRIDGE_PATH,
    resolve(astartisRoot, "build-vs18-pathfix", "Release", "astartis_bridge.exe"),
    resolve(astartisRoot, "build", "Release", "astartis_bridge.exe"),
    resolve(astartisRoot, "build", "astartis_bridge.exe")
  ].filter(Boolean);
  return candidates.find((candidate) => existsSync(candidate));
}

class BridgeSession {
  constructor() {
    this.child = null;
    this.pending = [];
    this.eventLog = [];
  }

  start() {
    if (this.child && !this.child.killed) return;
    const executable = bridgePath();
    if (!executable) {
      throw new Error(
        "Astartis bridge was not found. Build Astartis first or set ASTARTIS_BRIDGE_PATH to astartis_bridge.exe."
      );
    }

    this.child = spawn(executable, [], {
      cwd: astartisRoot,
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true
    });
    this.child.stderr.on("data", (data) => process.stderr.write(`[astartis] ${data}`));
    createInterface({ input: this.child.stdout }).on("line", (line) => this.handleLine(line));
    this.child.on("error", (error) => this.rejectPending(error));
    this.child.on("exit", (code) => {
      this.child = null;
      this.rejectPending(new Error(`Astartis bridge stopped with exit code ${code}.`));
    });
  }

  handleLine(line) {
    let message;
    try {
      message = JSON.parse(line);
    } catch {
      process.stderr.write(`[astartis] Ignored non-JSON bridge output: ${line}\n`);
      return;
    }
    this.eventLog.push(message);
    if (this.eventLog.length > 100) this.eventLog.shift();
    const pendingIndex = this.pending.findIndex((pending) => pending.events.includes(message.event));
    if (pendingIndex >= 0) {
      const [pending] = this.pending.splice(pendingIndex, 1);
      clearTimeout(pending.timer);
      pending.resolve(message.data ?? {});
    }
  }

  request(command, args, events, timeoutMs = 10_000) {
    this.start();
    return new Promise((resolvePromise, rejectPromise) => {
      const timer = setTimeout(() => {
        const index = this.pending.findIndex((pending) => pending.timer === timer);
        if (index >= 0) this.pending.splice(index, 1);
        rejectPromise(new Error(`Timed out waiting for Astartis ${events.join(" or ")}.`));
      }, timeoutMs);
      this.pending.push({ events, resolve: resolvePromise, reject: rejectPromise, timer });
      this.child.stdin.write(`${JSON.stringify({ cmd: command, args })}\n`);
    });
  }

  waitFor(events, timeoutMs = 15_000) {
    return new Promise((resolvePromise, rejectPromise) => {
      const timer = setTimeout(() => {
        const index = this.pending.findIndex((pending) => pending.timer === timer);
        if (index >= 0) this.pending.splice(index, 1);
        rejectPromise(new Error(`Timed out waiting for Astartis ${events.join(" or ")}.`));
      }, timeoutMs);
      this.pending.push({ events, resolve: resolvePromise, reject: rejectPromise, timer });
    });
  }

  rejectPending(error) {
    for (const pending of this.pending.splice(0)) {
      clearTimeout(pending.timer);
      pending.reject(error);
    }
  }
}

const bridge = new BridgeSession();

function stopBridge() {
  if (bridge.child && !bridge.child.killed) {
    bridge.child.kill();
  }
}

process.on("SIGTERM", () => {
  stopBridge();
  process.exit(0);
});

process.on("SIGINT", () => {
  stopBridge();
  process.exit(0);
});

process.on("exit", stopBridge);

function textResult(value) {
  return { content: [{ type: "text", text: JSON.stringify(value, null, 2) }] };
}

async function callTool(name, args = {}) {
  switch (name) {
    case "astartis_get_security_posture": {
      const posture = await bridge.request("get_snapshot", {}, ["snapshot"]);
      return {
        ...posture,
        evidence_scope:
          posture.packet_capture_mode === "live"
            ? "current local bridge state with live local Npcap metadata"
            : `current local bridge state; Npcap capture mode is ${posture.packet_capture_mode || "stopped"}`,
        simulation: false
      };
    }
    case "astartis_list_network_zones": {
      const zones = await bridge.request("network_get_ssids", {}, ["network_ssids"]);
      return {
        ...zones,
        source: "configured Astartis demo policy zones; not a physical-network discovery result",
        simulation: true
      };
    }
    case "astartis_simulate_nac_admission":
      return bridge.request("nac_simulate_device", args, ["nac_result"]);
    case "astartis_evaluate_zero_trust_access":
      return bridge.request("zerotrust_evaluate", args, ["zerotrust_result"]);
    case "astartis_get_agent_health": {
      const health = await bridge.request("agent_status", {}, ["agent_status_update"]);
      return {
        ...health,
        evidence_scope: "local persona status and queue records; not a claim of concurrent model inference",
        simulation: false
      };
    }
    case "astartis_get_attack_attribution": {
      const attribution = await bridge.request("get_attribution", { session: args.session_id || "demo-atk" }, ["attribution_report"]);
      return {
        ...attribution,
        evidence_scope: "local sandbox/decoy forensic evidence; empty techniques mean this bridge session has no matching interaction",
        simulation: true
      };
    }
    case "astartis_run_proof_mode": {
      const scenario = {
        device_mac: "02:42:ac:11:00:09",
        device_name: "unpatched-demo-laptop",
        ssid_name: "eGov",
        username: "demo.contractor",
        domain: "egov.local",
        os_updated: false,
        antivirus_running: false,
        disk_encrypted: false,
        firewall_enabled: false
      };
      const zeroTrustRequest = {
        user_id: scenario.username,
        device_id: scenario.device_mac,
        source_ip: "10.200.0.25",
        destination_ip: "10.200.0.10",
        requested_resource: "citizen-records",
        ssid_name: scenario.ssid_name
      };
      const nacAdmission = await bridge.request("nac_simulate_device", scenario, ["nac_result"]);
      const zeroTrustDecision = await bridge.request("zerotrust_evaluate", zeroTrustRequest, ["zerotrust_result"]);
      await bridge.request("run_demo", {}, ["demo_started_async"]);
      await bridge.waitFor(["demo_done"], 20_000);
      const attribution = await bridge.request("get_attribution", { session: "demo-atk" }, ["attribution_report"]);
      const posture = await bridge.request("get_snapshot", {}, ["snapshot"]);
      return {
        mode: "Astartis Proof Mode",
        safety_disclosure: "This is a deterministic local simulation. It does not change a real network, firewall, identity provider, or production data.",
        session_scope: "The scenario, audit evidence, and WORM state belong to this local MCP bridge process. Restart the MCP server for a fresh Proof Mode session.",
        scenario: {
          title: "Non-compliant contractor requests protected citizen records",
          device: scenario.device_name,
          network_zone: scenario.ssid_name,
          failed_posture_controls: ["OS updates", "antivirus", "disk encryption", "firewall"]
        },
        nac_admission: nacAdmission,
        zero_trust_decision: zeroTrustDecision,
        incident_evidence: attribution,
        verification: {
          audit_chain_valid: posture.chain_valid,
          worm_protected: posture.worm_locked,
          threat_level: posture.threat_tier_name || posture.threat_level || "unknown"
        },
        codex_handoff: [
          "Explain the NAC and Zero Trust denials using the returned evidence.",
          "Propose a minimal remediation plan; do not claim a real device or network was changed.",
          "Ask the developer to make and test the code/configuration fix, then re-run the simulation to verify the expected decision."
        ]
      };
    }
    default:
      throw new Error(`Unknown Astartis tool: ${name}`);
  }
}

function send(message) {
  process.stdout.write(`${JSON.stringify(message)}\n`);
}

async function handleRequest(request) {
  if (request.method === "notifications/initialized") return;
  if (request.method === "initialize") {
    send({
      jsonrpc: "2.0",
      id: request.id,
      result: {
        protocolVersion: request.params?.protocolVersion || "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: { name: "astartis-control-plane", version: "0.1.0" }
      }
    });
    return;
  }
  if (request.method === "tools/list") {
    send({ jsonrpc: "2.0", id: request.id, result: { tools: toolDefinitions } });
    return;
  }
  if (request.method === "tools/call") {
    try {
      const result = await callTool(request.params?.name, request.params?.arguments || {});
      send({ jsonrpc: "2.0", id: request.id, result: textResult(result) });
    } catch (error) {
      send({
        jsonrpc: "2.0",
        id: request.id,
        result: { content: [{ type: "text", text: error.message }], isError: true }
      });
    }
    return;
  }
  if (request.id !== undefined) {
    send({ jsonrpc: "2.0", id: request.id, error: { code: -32601, message: "Method not found" } });
  }
}

const input = createInterface({ input: process.stdin, crlfDelay: Infinity });
input.on("line", (line) => {
  try {
    handleRequest(JSON.parse(line));
  } catch {
    send({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } });
  }
});
