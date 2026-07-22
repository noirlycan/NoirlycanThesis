# Install Noirlycan agent only (Windows VM)
param(
    [string]$Python = "py -3.11"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root

Write-Host "[+] Creating venv..."
Invoke-Expression "$Python -m venv .venv"
& .\.venv\Scripts\python.exe -m pip install --upgrade pip
& .\.venv\Scripts\pip.exe install -e ".[agent]"

Write-Host ""
Write-Host "[+] Agent installed (no backend/dashboard deps)."
Write-Host "    1. Register agent on dashboard -> Copy config -> save as noirlycan-agent.toml"
Write-Host "    2. Run:"
Write-Host "       .\.venv\Scripts\activate"
Write-Host "       noirlycan-agent run --config .\noirlycan-agent.toml --watch-sysmon"
