@echo off
REM Starts the Astartis Phoenix dashboard with the project's local dependencies.
REM Close any older `mix phx.server` window before using this launcher.
setlocal
set "MIX_DEPS_PATH="
set "MIX_BUILD_PATH="
set "HEX_HOME="
set "ELIXIR_MAKE_CACHE_DIR="
set "ASTARTIS_BRIDGE_PATH=%~dp0..\astartis\build-vs18-pathfix\Release\astartis_bridge.exe"
cd /d "%~dp0"
echo Starting Astartis dashboard at http://127.0.0.1:4000
mix phx.server
