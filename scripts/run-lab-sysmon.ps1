# Install Sysmon via subprocess helper (Windows Admin).
param(
    [switch]$NewConsole
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root

$Python = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $Python)) {
    $Python = "python"
}

$Args = @("$Root\scripts\lab_stack.py", "sysmon")
if ($NewConsole) { $Args += "--new-console" }

Write-Host "[+] $($Args -join ' ')"
& $Python @Args
