# Minimal Windows agent install (no backend/dashboard/npm)

Requires **Python 3.10+** and **Frida** on the VM. Does not install FastAPI, Django, or the React dashboard.

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
