#!/usr/bin/env node
/**
 * End-to-end smoke test for the local MCP server and Astartis Proof Mode.
 *
 * This invokes only the deterministic local demo. It does not target a real
 * network, firewall, identity provider, or production data.
 */
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const serverPath = resolve(scriptDirectory, "astartis_mcp_server.mjs");
const server = spawn(process.execPath, [serverPath], {
  stdio: ["pipe", "pipe", "pipe"],
  windowsHide: true
});

const pending = new Map();
const output = createInterface({ input: server.stdout });
let sequence = 1;
let finished = false;

function stop(exitCode = 0, error) {
  if (finished) return;
  finished = true;
  clearTimeout(timeout);
  server.kill("SIGTERM");
  if (error) console.error(error.stack || error.message);
  process.exitCode = exitCode;
}

function request(method, params) {
  const id = sequence++;
  server.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
  return new Promise((resolvePromise, rejectPromise) => pending.set(id, { resolve: resolvePromise, reject: rejectPromise }));
}

const timeout = setTimeout(() => stop(1, new Error("Proof Mode smoke test timed out after 35 seconds.")), 35_000);

server.stderr.on("data", (data) => process.stderr.write(data));
server.on("error", (error) => stop(1, error));
output.on("line", (line) => {
  try {
    const message = JSON.parse(line);
    const waiting = pending.get(message.id);
    if (waiting) {
      pending.delete(message.id);
      waiting.resolve(message);
    }
  } catch (error) {
    stop(1, error);
  }
});

try {
  const initialized = await request("initialize", {
    protocolVersion: "2025-03-26",
    capabilities: {},
    clientInfo: { name: "astartis-proof-mode-test", version: "1.0.0" }
  });

  if (!initialized.result?.serverInfo?.name) {
    throw new Error("The MCP server did not initialize.");
  }

  const response = await request("tools/call", {
    name: "astartis_run_proof_mode",
    arguments: {}
  });
  if (response.result?.isError) {
    throw new Error(response.result.content?.[0]?.text || "Proof Mode returned an MCP error.");
  }

  const proof = JSON.parse(response.result?.content?.[0]?.text || "{}");
  if (proof.nac_admission?.result !== "DENY") {
    throw new Error("Expected the non-compliant test device to be denied by NAC.");
  }
  if (proof.zero_trust_decision?.decision !== "DENY") {
    throw new Error("Expected the protected resource request to be denied by Zero Trust.");
  }
  if (proof.verification?.audit_chain_valid !== true) {
    throw new Error("Expected Astartis audit-chain verification to succeed.");
  }
  if (proof.verification?.worm_protected !== true) {
    throw new Error("Expected Proof Mode to leave its simulated evidence WORM-protected.");
  }
  if (!Array.isArray(proof.incident_evidence?.techniques) || proof.incident_evidence.techniques.length === 0) {
    throw new Error("Expected Proof Mode to return MITRE attribution from its simulated decoy evidence.");
  }

  console.log("Proof Mode passed: NAC denial, Zero Trust denial, WORM/audit verification, and MITRE attribution are present.");
  stop();
} catch (error) {
  stop(1, error);
}
