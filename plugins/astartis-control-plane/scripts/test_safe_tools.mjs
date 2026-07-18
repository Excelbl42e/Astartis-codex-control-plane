#!/usr/bin/env node
/**
 * Integration check for every safe Astartis Control Plane tool.
 * Uses only deterministic local simulations and read-only evidence queries.
 */
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const serverPath = resolve(here, "astartis_mcp_server.mjs");
const server = spawn(process.execPath, [serverPath], {
  stdio: ["pipe", "pipe", "pipe"],
  windowsHide: true
});

const pending = new Map();
const output = createInterface({ input: server.stdout });
let sequence = 1;
let finished = false;
const timeout = setTimeout(() => finish(1, new Error("safe-tool smoke test timed out after 45 seconds.")), 45_000);

function finish(code = 0, error) {
  if (finished) return;
  finished = true;
  clearTimeout(timeout);
  if (error) console.error(error.stack || error.message);
  server.kill("SIGTERM");
  process.exitCode = code;
}

function request(method, params) {
  const id = sequence++;
  server.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
  return new Promise((resolvePromise, rejectPromise) => {
    pending.set(id, { resolve: resolvePromise, reject: rejectPromise });
  });
}

server.stderr.on("data", (data) => process.stderr.write(data));
server.on("error", (error) => finish(1, error));
output.on("line", (line) => {
  try {
    const message = JSON.parse(line);
    const waiting = pending.get(message.id);
    if (waiting) {
      pending.delete(message.id);
      waiting.resolve(message);
    }
  } catch (error) {
    finish(1, error);
  }
});

function toolResult(response, name) {
  if (response.result?.isError) {
    throw new Error(`${name} returned an MCP error: ${response.result.content?.[0]?.text || "unknown"}`);
  }
  return JSON.parse(response.result?.content?.[0]?.text || "{}");
}

try {
  const initialized = await request("initialize", {
    protocolVersion: "2025-03-26",
    capabilities: {},
    clientInfo: { name: "astartis-safe-tool-test", version: "1.0.0" }
  });
  if (!initialized.result?.serverInfo?.name) throw new Error("MCP initialization failed.");

  const listed = await request("tools/list", {});
  const tools = listed.result?.tools || [];
  if (tools.length !== 7) throw new Error(`Expected 7 safe tools, found ${tools.length}.`);

  const posture = toolResult(await request("tools/call", {
    name: "astartis_get_security_posture", arguments: {}
  }), "posture");
  if (posture.chain_valid !== true) throw new Error("Posture query did not report a valid audit chain.");

  const zones = toolResult(await request("tools/call", {
    name: "astartis_list_network_zones", arguments: {}
  }), "zones");
  if (!Array.isArray(zones.ssids) || zones.ssids.length < 3) throw new Error("Expected three network zones.");

  const nac = toolResult(await request("tools/call", {
    name: "astartis_simulate_nac_admission",
    arguments: {
      device_mac: "02:42:ac:11:00:09", device_name: "smoke-laptop", ssid_name: "eGov",
      username: "demo.contractor", domain: "egov.local", os_updated: false,
      antivirus_running: false, disk_encrypted: false, firewall_enabled: false
    }
  }), "nac");
  if (nac.result !== "DENY") throw new Error("Expected non-compliant NAC simulation to deny.");

  const zt = toolResult(await request("tools/call", {
    name: "astartis_evaluate_zero_trust_access",
    arguments: {
      user_id: "demo.contractor", device_id: "02:42:ac:11:00:09", source_ip: "10.200.0.25",
      destination_ip: "10.200.0.10", requested_resource: "citizen-records", ssid_name: "eGov"
    }
  }), "zero trust");
  if (zt.decision !== "DENY") throw new Error("Expected Zero Trust simulation to deny.");

  const health = toolResult(await request("tools/call", {
    name: "astartis_get_agent_health", arguments: {}
  }), "agent health");
  if (!Array.isArray(health.agent_statuses) || health.agent_statuses.length !== 77) {
    throw new Error(`Agent health expected the complete 77-persona catalogue, found ${health.agent_statuses?.length || 0}.`);
  }

  const proof = toolResult(await request("tools/call", {
    name: "astartis_run_proof_mode", arguments: {}
  }), "proof mode");
  if (proof.verification?.audit_chain_valid !== true || proof.verification?.worm_protected !== true) {
    throw new Error("Proof Mode verification evidence was incomplete.");
  }
  if (!Array.isArray(proof.incident_evidence?.techniques) || proof.incident_evidence.techniques.length === 0) {
    throw new Error("Proof Mode did not return local decoy/MITRE attribution evidence.");
  }

  const attribution = toolResult(await request("tools/call", {
    name: "astartis_get_attack_attribution", arguments: { session_id: "demo-atk" }
  }), "attribution");
  if (!attribution.session_id || !Array.isArray(attribution.techniques) || attribution.techniques.length === 0) {
    throw new Error("Attribution query did not return MITRE evidence after Proof Mode.");
  }

  console.log(`Safe-tool smoke test passed: ${tools.length} tools, ${health.agent_statuses.length} loaded personas, NAC/ZT denials, attribution, and Proof Mode.`);
  finish();
} catch (error) {
  finish(1, error);
}
