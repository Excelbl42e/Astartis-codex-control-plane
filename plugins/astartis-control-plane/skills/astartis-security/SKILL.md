---
name: astartis-security
description: Investigate and verify developer-security events with the local Astartis Control Plane. Use when a developer asks to inspect Astartis posture, simulate NAC/Zero Trust, explain audit evidence, or run Proof Mode.
---

# Astartis Security Control Plane

Use Astartis as the evidence and enforcement system; use Codex to explain evidence, create a reviewed remediation, and verify the outcome. Never describe a simulation as a live production-network action.

## Safe workflow

1. Start with `astartis_get_security_posture` to establish threat tier, audit-chain validity, WORM state, and agent health.
2. For network questions, use `astartis_list_network_zones`, then simulate NAC admission or evaluate a Zero Trust access request.
3. Explain the result using the returned evidence: NAC steps, assigned VLAN/role, trust score, decision, and audit status.
4. Propose a minimal, reviewable developer remediation. Include a regression test or configuration verification where appropriate.
5. Run a second safe simulation to verify the intended posture. State whether the fix was actually verified or merely proposed.

## Proof Mode

`astartis_run_proof_mode` is a deterministic local demo. It performs a simulated escalation, decoy interaction, WORM protection event, and MITRE attribution. It does not touch a real network or malware sample.

After Proof Mode, retrieve the returned attribution and explain the security narrative in this order:

- entry condition and detection;
- containment/deception;
- WORM protection;
- audit/attribution evidence;
- developer remediation and verification.

## Safety boundaries

- Do not request firewall blocking, file quarantine, direct WORM unlock, or arbitrary agent execution through this plugin.
- Do not claim that optional local-inference agent output overrides Astartis policy. PolicyEngine and Zero Trust controls retain enforcement authority.
- Label confidence and distinguish source evidence from recommended next steps.
