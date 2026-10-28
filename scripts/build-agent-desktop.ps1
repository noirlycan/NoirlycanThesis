# Build on Windows x64 with Python 3.11. The target machine needs no Python.
param([string]$Python = "py", [string]$PythonVersion = "-3.11", [switch]$Installer)
$ErrorActionPreference = "Stop"
if ($env:OS -ne "Windows_NT") { throw "Build the Windows EXE on Windows." }
$ProjectRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Push-Location $ProjectRoot
try {
    $VersionArguments = @()
    if ($PythonVersion) { $VersionArguments += $PythonVersion }
    & $Python @VersionArguments -m venv .venv-agent-build
    if ($LASTEXITCODE -ne 0) { throw "Could not create build environment." }
    $BuildPython = Join-Path $ProjectRoot ".venv-agent-build\Scripts\python.exe"
    & $BuildPython -m pip install --upgrade pip
    if ($LASTEXITCODE -ne 0) { throw "pip upgrade failed." }
    & $BuildPython -m pip install ".[agent]" "pyinstaller>=6,<7"
    if ($LASTEXITCODE -ne 0) { throw "Dependency installation failed." }
    & $BuildPython -m PyInstaller --noconfirm --onefile --windowed --uac-admin `
        --name NoirlycanAgent --paths src --collect-all frida `
        --collect-data noirlycan_agent --hidden-import win32evtlog `
        --distpath dist --workpath build/agent-desktop --specpath build `
        scripts/agent_desktop_entry.py
    if ($LASTEXITCODE -ne 0) { throw "EXE build failed." }
    & $BuildPython scripts/verify-agent-desktop.py dist/NoirlycanAgent.exe
    if ($LASTEXITCODE -ne 0) { throw "EXE verification failed." }
    Write-Host "Built: $ProjectRoot\dist\NoirlycanAgent.exe"
    if ($Installer) {
        $CompilerCommand = Get-Command ISCC.exe -ErrorAction SilentlyContinue
        $CompilerPath = if ($CompilerCommand) { $CompilerCommand.Source } else {
            Join-Path ${env:ProgramFiles(x86)} "Inno Setup 6\ISCC.exe"
        }
        if (-not (Test-Path -LiteralPath $CompilerPath)) {
            throw "Install Inno Setup 6.3+ from https://jrsoftware.org/isdl.php to build the installer."
        }
        & $CompilerPath deploy/agent/NoirlycanAgent.iss
        if ($LASTEXITCODE -ne 0) { throw "Windows installer build failed." }
        & $BuildPython -c "from pathlib import Path; from noirlycan_backend.domain.agent_deploy import validate_agent_release; validate_agent_release(Path('dist/NoirlycanAgentSetup.exe'), 'installer')"
        if ($LASTEXITCODE -ne 0) { throw "Installer PE/Administrator manifest verification failed." }
        Write-Host "Built: $ProjectRoot\dist\NoirlycanAgentSetup.exe"
    }
} finally {
    Pop-Location
}
