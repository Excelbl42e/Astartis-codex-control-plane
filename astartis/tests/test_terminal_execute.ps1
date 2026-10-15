[CmdletBinding()]
param(
    [string]$BridgePath
)

# Focused bridge-level validation for the safe local diagnostic terminal.
# It deliberately runs only `hostname` and `ipconfig /all`, then proves that
# shell chaining, redirection, and unlisted commands are rejected before any
# process is started.  It also checks that the bridge binary no longer carries
# the legacy dashboard HTTP `/exec` shell endpoint, so a stale build fails.

if ([string]::IsNullOrWhiteSpace($BridgePath)) {
    $BridgePath = Join-Path $PSScriptRoot '..\build-vs18-pathfix\Release\astartis_bridge.exe'
}
$BridgePath = (Resolve-Path -LiteralPath $BridgePath -ErrorAction Stop).Path
$workingDirectory = Split-Path -Parent $BridgePath

# The removed HTTP endpoint ran `cmd /c <cmd>` behind a prefix whitelist and
# answered with `Access-Control-Allow-Origin: *`.  None of these strings exist
# in the current source, so finding one means the binary predates the fix.
$bridgeText = [System.Text.Encoding]::ASCII.GetString([System.IO.File]::ReadAllBytes($BridgePath))
foreach ($marker in @('POST /exec', 'cmd /c ', 'Access-Control-Allow-Origin')) {
    if ($bridgeText.Contains($marker)) {
        throw "Bridge binary still contains the legacy dashboard shell endpoint ('$marker'). Rebuild it from source with astartis\build.bat: $BridgePath"
    }
}

$startInfo = [System.Diagnostics.ProcessStartInfo]::new()
$startInfo.FileName = $BridgePath
$startInfo.WorkingDirectory = $workingDirectory
$startInfo.UseShellExecute = $false
$startInfo.CreateNoWindow = $true
$startInfo.RedirectStandardInput = $true
$startInfo.RedirectStandardOutput = $true
$startInfo.RedirectStandardError = $true

$process = [System.Diagnostics.Process]::new()
$process.StartInfo = $startInfo

function Send-BridgeCommand {
    param([hashtable]$Command)

    $process.StandardInput.WriteLine(($Command | ConvertTo-Json -Compress -Depth 4))
    $process.StandardInput.Flush()
}

function Receive-BridgeEvent {
    param(
        [Parameter(Mandatory)] [string]$Event,
        [int]$TimeoutMs = 20000
    )

    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
    $readTask = $process.StandardOutput.ReadLineAsync()

    while ([DateTime]::UtcNow -lt $deadline) {
        if ($readTask.Wait(250)) {
            $line = $readTask.Result
            if ($null -eq $line) {
                $stderr = $process.StandardError.ReadToEnd()
                throw "Bridge stdout closed before '$Event'. stderr: $stderr"
            }

            try {
                $message = $line | ConvertFrom-Json -ErrorAction Stop
                if ($message.event -eq $Event) {
                    return $message.data
                }
            } catch {
                # Ignore non-JSON diagnostics; the protocol itself is JSONL.
            }

            $readTask = $process.StandardOutput.ReadLineAsync()
        }
    }

    throw "Timed out waiting for bridge event '$Event'."
}

try {
    if (-not $process.Start()) {
        throw "Could not start bridge: $BridgePath"
    }

    $null = Receive-BridgeEvent -Event 'ready'

    Send-BridgeCommand @{ cmd = 'terminal_execute'; args = @{ command = 'hostname' } }
    $allowed = Receive-BridgeEvent -Event 'terminal_execute_result'
    if (-not $allowed.allowed -or -not $allowed.executed -or $allowed.rejected -or
        $allowed.mode -ne 'live_local' -or $allowed.status -ne 'completed' -or
        [string]::IsNullOrWhiteSpace([string]$allowed.stdout)) {
        throw "Allowed diagnostic result was invalid: $($allowed | ConvertTo-Json -Compress -Depth 4)"
    }

    # Required network diagnostic. Do not print its output: it can contain
    # local adapter and address metadata, but must be returned to the caller.
    Send-BridgeCommand @{ cmd = 'terminal_execute'; args = @{ command = 'ipconfig /all' } }
    $ipconfig = Receive-BridgeEvent -Event 'terminal_execute_result'
    if (-not $ipconfig.allowed -or -not $ipconfig.executed -or $ipconfig.rejected -or
        $ipconfig.command -ne 'ipconfig /all' -or $ipconfig.mode -ne 'live_local' -or
        $ipconfig.status -ne 'completed' -or [string]::IsNullOrWhiteSpace([string]$ipconfig.stdout)) {
        throw "ipconfig /all result was invalid: $($ipconfig | ConvertTo-Json -Compress -Depth 4)"
    }

    # Every payload here must be refused without starting a process.  Each
    # chained form starts with an allowlisted command, so a prefix match or a
    # shell hand-off would let it through.  Payloads are harmless if a
    # regression ever did run them.
    $unsafeCommands = @(
        # Shell chaining, piping, and redirection
        'whoami & hostname',
        'hostname && whoami',
        'hostname || whoami',
        'hostname | whoami',
        'hostname; whoami',
        'ipconfig /all & whoami',
        'Get-NetAdapter; Get-Process',
        'Get-NetAdapter | Out-String',
        'hostname > NUL',
        "hostname`nwhoami",
        # Commands outside the fixed allowlist
        'tasklist',
        'echo astartis',
        'cmd /c hostname',
        'powershell -Command hostname',
        'Get-Process',
        'hostname.exe',
        'whoami /all',
        'ipconfig',
        ''
    )
    foreach ($unsafe in $unsafeCommands) {
        Send-BridgeCommand @{ cmd = 'terminal_execute'; args = @{ command = $unsafe } }
        $rejected = Receive-BridgeEvent -Event 'terminal_execute_result'
        if (-not $rejected.rejected -or $rejected.allowed -or $rejected.executed -or
            $rejected.status -ne 'rejected' -or $rejected.exit_code -ne -1 -or
            -not [string]::IsNullOrEmpty([string]$rejected.stdout)) {
            throw "Unsafe command was not rejected: $($rejected | ConvertTo-Json -Compress -Depth 4)"
        }
    }

    Write-Host "terminal_execute validation passed: hostname and ipconfig /all completed; $($unsafeCommands.Count) chained or unlisted commands rejected; no legacy HTTP exec endpoint in the bridge binary."
}
finally {
    if ($process -and -not $process.HasExited) {
        $process.StandardInput.Close()
        if (-not $process.WaitForExit(1500)) {
            $process.Kill()
            $process.WaitForExit()
        }
    }
    if ($process) { $process.Dispose() }
}
