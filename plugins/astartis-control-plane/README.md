# Astartis Control Plane for Codex

**Astartis Control Plane** is a local Codex plugin that turns Astartis security evidence into a developer workflow: investigate an access decision, propose the smallest secure fix, test it, and verify the result.

It is intentionally evidence and simulation only. Astartis remains the deterministic authority for policy-gated security actions; this plugin does not expose firewall changes, quarantine, WORM unlocks, or arbitrary agent execution.

## Developer workflow

1. Codex reads the current Astartis posture, audit-chain state, agent health, and network zones.
2. A developer runs a safe NAC or Zero Trust simulation and asks Codex to explain the decision from the returned evidence.
3. Codex proposes a narrow code or configuration remediation, then helps create and test it in the developer's repository.
4. The developer reruns the simulation and records the resulting evidence.

This makes Astartis a security control plane for developer decisions, rather than a dashboard that only reports alerts.

## Included MCP tools

| Tool | Purpose | Safety boundary |
| --- | --- | --- |
| `astartis_get_security_posture` | Read threat, WORM, audit-chain, sandbox, and agent-health evidence. | Read-only |
| `astartis_list_network_zones` | Read the public, enterprise, and management SSID/VLAN zones. | Read-only |
| `astartis_simulate_nac_admission` | Run Astartis's 8-step admission workflow for a supplied test device. | Local simulation only |
| `astartis_evaluate_zero_trust_access` | Evaluate a supplied test resource request. | Local simulation only |
| `astartis_get_agent_health` | Read the Astartis agent-swarm status. | Read-only |
| `astartis_get_attack_attribution` | Retrieve local decoy-session MITRE evidence. | Read-only |
| `astartis_run_proof_mode` | Run the fixed end-to-end demo and return its evidence bundle. | Deterministic local demo only |

## Install and run locally

1. Build Astartis so `astartis/build/Release/astartis_bridge.exe` exists, or set `ASTARTIS_BRIDGE_PATH` to that executable's absolute path.
2. In Codex, add this folder as a local plugin: `plugins/astartis-control-plane`.
3. Start a Codex task and use a prompt such as:

   ```text
   Run Astartis Proof Mode. Explain why the device and resource request were denied,
   propose the smallest remediation plan, and tell me how to verify the fix.
   ```

The plugin's `.mcp.json` starts the local Node MCP server. It has no cloud dependency and no network listener.

## Proof Mode

Proof Mode is the demo spine. It always performs the same local scenario:

```text
Non-compliant contractor laptop
  -> NAC evaluates identity + four posture controls and denies admission
  -> Zero Trust denies access to citizen-records (trust score 20)
  -> Astartis runs the local threat/decoy/WORM demonstration
  -> Codex receives attribution plus audit-chain and WORM verification
```

Every result includes an explicit disclosure that it is a deterministic local simulation, not a live network action. Restart the MCP server before replaying Proof Mode to receive a fresh in-memory Astartis session.

## Verify the integration

With Node.js 20 or newer available, run:

```powershell
node scripts/test_proof_mode.mjs
node scripts/test_safe_tools.mjs
```

The first test starts the actual local MCP adapter and bridge, then asserts the NAC denial, Zero Trust denial, and valid audit chain. The second exercises all seven safe tools and verifies the loaded persona catalogue. Set `ASTARTIS_BRIDGE_PATH` when testing a source-built bridge. Both tests clean up their bridge process on completion.

The root [README](../../README.md) contains the judge setup, dashboard launch, and verification instructions.
