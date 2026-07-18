[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$webRoot = Join-Path $repoRoot "astartis_web"
$bridge = Join-Path $repoRoot "astartis\build-vs18-pathfix\Release\astartis_bridge.exe"

function Require-Command([string]$name, [string]$help) {
  if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
    throw "$name is required. $help"
  }
}

Require-Command "node" "Install Node.js 20 or newer, then run this script again."
Require-Command "mix" "Install Elixir/Erlang, then run this script again."

if (-not (Test-Path -LiteralPath $bridge)) {
  throw "The bundled bridge is missing: $bridge"
}

Write-Host "Preparing Astartis × Codex judge demo..." -ForegroundColor Cyan
Push-Location $webRoot
try {
  mix deps.get
  mix assets.setup
} finally {
  Pop-Location
}

Write-Host "`nSetup complete." -ForegroundColor Green
Write-Host "Start the dashboard with: .\astartis_web\start-dashboard.bat"
Write-Host "Then open: http://127.0.0.1:4000"
Write-Host "Optional MCP verification: node .\plugins\astartis-control-plane\scripts\test_safe_tools.mjs"
