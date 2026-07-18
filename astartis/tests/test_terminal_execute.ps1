[CmdletBinding()]
param(
    [string]$BridgePath
)

# Focused bridge-level validation for the safe local diagnostic terminal.
# It deliberately runs only `hostname`, then proves a shell-injection-shaped
# request is rejected before any process is started.

if ([string]::IsNullOrWhiteSpace($BridgePath)) {
    $BridgePath = Join-Path $PSScriptRoot '..\build-vs18-pathfix\Release\astartis_bridge.exe'
}
$BridgePath = (Resolve-Path -LiteralPath $BridgePath -ErrorAction Stop).Path
$workingDirectory = Split-Path -Parent $BridgePath

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

    Send-BridgeCommand @{ cmd = 'terminal_execute'; args = @{ command = 'whoami & hostname' } }
    $rejected = Receive-BridgeEvent -Event 'terminal_execute_result'
    if (-not $rejected.rejected -or $rejected.allowed -or $rejected.executed -or
        $rejected.status -ne 'rejected' -or $rejected.exit_code -ne -1) {
        throw "Unsafe command was not rejected: $($rejected | ConvertTo-Json -Compress -Depth 4)"
    }

    Write-Host 'terminal_execute validation passed: hostname and ipconfig /all completed; shell-shaped input rejected.'
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
