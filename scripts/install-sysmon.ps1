# Install Sysmon with Noirlycan lab config (Windows VM, run as Administrator)
param(
    [string]$SysmonDir = ""
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root

$binDir = if ($SysmonDir) { $SysmonDir } else { Join-Path $Root "Sysmon" }
$sysmon = Join-Path $binDir "Sysmon64.exe"
$config = Join-Path $Root "configs\sysmon-noirlycan.xml"

if (-not (Test-Path $sysmon)) {
    Write-Host "[!] Missing $sysmon"
    Write-Host "    Download Sysmon from:"
    Write-Host "    https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon"
    Write-Host "    Extract Sysmon64.exe into: $binDir"
    exit 1
}

if (-not (Test-Path $config)) {
    Write-Host "[!] Missing config: $config"
    exit 1
}

Write-Host "[+] Installing Sysmon with configs\sysmon-noirlycan.xml ..."
& $sysmon -accepteula -i $config

Write-Host ""
Write-Host "[+] Verify channel:"
Write-Host "    Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 1"
Write-Host ""
Write-Host "[+] Run agent (Admin PowerShell recommended):"
Write-Host "    noirlycan-agent run --config .\noirlycan-agent.toml --watch-sysmon --auto-attach-new-processes"
