# Minimal Windows agent install (no backend/dashboard/npm)

## Desktop EXE (Windows x64)

Build once on Windows with Python 3.11 x64, from the repository root:

```powershell
.\scripts\build-agent-desktop.ps1
```

For a normal Windows installer, install Inno Setup 6.3+ on the build machine,
then run:

```powershell
.\scripts\build-agent-desktop.ps1 -Installer
```

This also produces `dist\NoirlycanAgentSetup.exe`. It installs the Agent into
Program Files, creates a Start Menu shortcut (and optionally a desktop shortcut),
and registers an uninstaller. Both Setup and the installed Agent request UAC
Administrator rights. There is no automatic startup or Windows service.

On the dashboard, an Admin opens **Agents → Desktop Agent (Windows)** and selects
**Publish installer** for `NoirlycanAgentSetup.exe`, or **Publish portable release** for
`NoirlycanAgent.exe`. The server checks the Windows PE header and Administrator
manifest, then atomically publishes the file. This verifies packaging, not code
signing or whether the binary is trusted; publish only your verified build.
Clients log into the dashboard on their Windows machine, choose **Download Windows
installer**, install it, then copy the server address and their workstation's token
into the app. The **Copy server** button uses the API origin reached by the
browser, so a client is not given the server's loopback address by mistake.

The output is `dist\NoirlycanAgent.exe`. Copy this single file to the Windows
machine; Python and pip are not required there. Opening the EXE requests
Administrator rights through Windows UAC. Accept the prompt, enter the backend
server (`http://IP:port` or `https://host`) and the agent enrollment token from
**Agents → Register workstation**, then click **Connect and start**. The backend
resolves the Agent ID from that token; the global server token is not accepted.
Deploy the updated backend before using the desktop app.

The build script also verifies the x64/windowed PE header, Administrator
manifest, GUI startup, Frida hooks, signing, and DPAPI round-trip in the packaged
EXE. Accept UAC if Windows prompts during that verification.

The interface shows connectivity, Agent ID, and live runtime messages. **Stop
Agent** stops collection and sends goodbye; closing the window waits for cleanup.
The app does not install itself as a Windows service or start automatically at
login. Data lives under `%LOCALAPPDATA%\Noirlycan`, separately for each server.
The saved token is protected with Windows DPAPI for the elevated account; only
the server address is stored in `desktop.json`. Token protection failure prevents
startup rather than storing an unprotected token.

Sysmon remains a separate prerequisite for Sysmon telemetry. Its absence is
reported in the app log; Frida and the existing sensors still run where available.
The desktop app uses the same collection and sample-analysis behavior as `run`,
including automatic analysis of new files while connected to the console.

Alternatively, run the **Build Windows desktop Agent** workflow in GitHub Actions
and download the `NoirlycanAgent-windows-x64` artifact. The workflow must be present
in the remote repository before it can be started. Place the resulting EXE at
`dist/NoirlycanAgent.exe` on the backend host, or set `NOIRLYCAN_AGENT_EXE` to its
absolute path. **Agents → Download Agent .exe** then serves it to authenticated
console users with agent-management permission. For a containerized backend,
mount the file into the container and set that environment variable to the
mounted path. The download button stays disabled until the file is available.

The default publication directory is `deploy/agent-artifacts/`; override it
with `NOIRLYCAN_AGENT_ARTIFACTS_DIR`. `NOIRLYCAN_AGENT_SETUP` can override the setup
file's path. Docker Compose mounts that directory at `/app/agent-artifacts`, so
uploads survive backend/container restarts. Nginx allows release uploads up to
256 MiB. Publishing releases is restricted to the Admin role; downloads require
the existing agent-management permission.

For development from source:

```powershell
pip install -e ".[agent]"
noirlycan-agent-desktop
```

The source/CLI options below require **Python 3.10+** and **Frida** on the VM.
They do not install FastAPI, Django, or the React dashboard.

## Option A — from git (one folder)

```powershell
git clone https://github.com/noirlycan/NoirlycanThesis.git C:\Noirlycan\agent
cd C:\Noirlycan\agent
py -3.11 -m venv .venv
.\.venv\Scripts\activate
pip install -e ".[agent]"
```

## Option B — install script

From an already-cloned repo on the VM:

```powershell
.\scripts\install-agent.ps1
```

## Configure on dashboard

1. Open **Agents** → **Register workstation** (agent id + token).
2. **Copy config** → save as `C:\Noirlycan\noirlycan-agent.toml`.
3. On VM:

```powershell
noirlycan-agent run --config C:\Noirlycan\noirlycan-agent.toml --watch-sysmon
```

Credentials are stored in `logs\.agent_identity.json` next to the config working directory.

## What runs where

| Machine | Install | Runs |
|---------|---------|------|
| Mac / lab server | `pip install -e ".[backend]"` + dashboard UI | API + SQLite + React |
| Windows VM | `pip install -e ".[agent]"` only | Frida + Sysmon + file watch → push to API |

Optional on VM: **Sysmon** (separate MSI), not bundled in pip.

## Dependencies on VM

- Python 3.10+
- `frida`, `pywin32` (via `[agent]` extra)
- `pefile` (core)

Not installed on VM: FastAPI, uvicorn, Django, channels, pytest.
