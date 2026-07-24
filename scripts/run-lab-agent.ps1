# Launch Noirlycan agent via subprocess helper (Windows VM, run as Administrator).
param(
    [string]$Server = "172.16.239.1:8888",
    [string]$AgentId = "vm01",
    [string]$Token = "",
    [string]$Config = "",
    [switch]$NoWatchSysmon,
    [switch]$NoAutoAttach,
    [switch]$NewConsole
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root

$Python = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $Python)) {
    $Python = "python"
}

$Args = @("$Root\scripts\lab_stack.py", "agent", "--server", $Server, "--agent-id", $AgentId)
if ($Config) {
    $Args += @("--config", $Config)
} elseif ($Token) {
    $Args += @("--token", $Token)
} else {
    Write-Host "[!] Set -Token or -Config (from dashboard Agents tab)."
    exit 1
}
if ($NoWatchSysmon) { $Args += "--no-watch-sysmon" }
if ($NoAutoAttach) { $Args += "--no-auto-attach" }
if ($NewConsole) { $Args += "--new-console" }

Write-Host "[+] $($Args -join ' ')"
& $Python @Args
