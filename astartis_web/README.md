# Astartis x Codex dashboard

This Phoenix LiveView application is the local operations dashboard for Astartis x Codex. It presents posture, network/capture state, rules, NAC and Zero Trust decisions, agent-catalogue health, WORM/audit evidence, recovery posture, Proof Mode, and a safe diagnostic terminal.

For the full judge setup and product explanation, see the [repository README](../README.md).

## Start on Windows

From the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\setup-judge-demo.ps1
.\astartis_web\start-dashboard.bat
```

Open [http://127.0.0.1:4000](http://127.0.0.1:4000). The launcher starts the included native bridge automatically.

For a normal Phoenix development session, run `mix setup` once and then `mix phx.server` from this directory. The dashboard is a local evaluation surface; it does not expose an Internet-facing service by default.
