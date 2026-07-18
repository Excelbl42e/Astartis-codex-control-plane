# Astartis native security engine

This directory contains the Windows-first C++ security engine used by Astartis x Codex. The engine is the deterministic policy authority behind the local bridge, Phoenix dashboard, and Codex MCP plugin.

For the complete project story, judge quick start, Codex integration, and Vercel-ready interactive lab, see the [repository README](../README.md).

## What is in this component

- Deterministic rule engine and entropy/chaos analysis
- Audit-chain verification and WORM evidence controls
- NAC admission and Zero Trust policy evaluation
- Opt-in local Npcap metadata capture support
- Safe, allowlisted diagnostic-terminal execution
- Local bridge that communicates through newline-delimited JSON
- 77 agent definitions used as a routed catalogue, not 77 simultaneous model processes
- Optional local inference routing for agent-assisted analysis

## Two ways to run it

### Recommended evaluation path — use the included bridge

The project includes a Windows build of `astartis_bridge.exe`. Judges do not need a native build to evaluate the dashboard, Proof Mode, MCP plugin, or safe terminal.

From the repository root, run:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\setup-judge-demo.ps1
.\astartis_web\start-dashboard.bat
```

The dashboard launches at [http://127.0.0.1:4000](http://127.0.0.1:4000).

### Native source build — optional

Use this route when you want to compile the bridge yourself. Install:

- Windows 10/11 x64
- Visual Studio 2022 C++ Build Tools with Desktop development with C++
- CMake 3.20 or later
- OpenSSL for Windows (the supplied script defaults to `C:\Program Files\OpenSSL-Win64`)
- Npcap SDK (the supplied CMake configuration defaults to `C:\npcap-sdk`)

Then run:

```powershell
Set-Location .\astartis
.\build.bat
```

The build script creates the bridge and native test executables. Point the dashboard or MCP plugin at a rebuilt bridge by setting `ASTARTIS_BRIDGE_PATH` to its absolute path.

## Safety boundaries

The engine is designed for evidence and deterministic policy evaluation. The included Codex plugin can retrieve permitted local evidence and run clearly-labelled simulations; it does not expose firewall enforcement, quarantine, WORM unlock, identity-provider changes, or arbitrary agent execution.

Proof Mode is a repeatable local scenario. It demonstrates a non-compliant device denied by NAC, a protected-resource request denied by Zero Trust, protected WORM/audit evidence, and a bounded attribution record. It does not contact or alter a real network, endpoint, directory, firewall, or backup system.

## Tests

After a source build, native test executables are created in the configured build directory. For the judge-ready checks that use the included bridge, run the commands in the [root README](../README.md#test-the-codex-integration).

Npcap and a local inference runtime are optional capabilities. They are not required for the dashboard, local MCP test suite, Proof Mode, NAC/Zero Trust simulation, audit verification, or safe-terminal test.
