# Noirlycan Thesis Telemetry Prototype

Defensive lab prototype for Windows 10/11 that correlates **file drops → process lineage → process-injection primitives**, inspired by the ASIA CCS 2025 paper *Can You Run My Code?* Extended with file provenance, remote agents, and a web console for thesis experiments.

**Not for production.** No payloads, loaders, or exploit code are shipped.

## What it detects

The correlator scores chains with at least two of three injection primitives:

1. **Allocate** executable memory in a target process  
2. **Write / map** payload into that process  
3. **Execute** (thread context, resume, remote thread, …)

Enrichment adds Sysmon context (file create, process create, image load, process access, network) and Frida API telemetry. Typical lab flows:

```text
memory-only loader:  decrypt → section mapping → SetThreadContext → ResumeThread
file-dropping loader: FileCreate → ProcessCreate → cross-process write → execute
```

After **CRITICAL** findings, the agent watches the injected target PID for outbound connections (Sysmon EID 3) for 5 minutes.

## Architecture

Three deployable units (see [`deploy/README.md`](deploy/README.md)):

```text
┌─────────────────┐     HTTP ingest      ┌──────────────────┐
│  Windows VM     │ ───────────────────► │  noirlycan-backend│
│  noirlycan-agent│     :8765            │  FastAPI + SQLite │
│  Frida + Sysmon │                      └────────┬─────────┘
└─────────────────┘                               │
                                                  │ /api
┌─────────────────┐                               │
│  Analyst browser│ ◄──── dashboard-ui ───────────┘
│  React (Vite)   │      :5173 dev / :8080 prod
└─────────────────┘
```

| Package | Role |
|---------|------|
| `noirlycan_core` | Correlation, classification, JSONL storage |
| `noirlycan_agent` | Windows collector (Frida hooks, Sysmon, file watch) |
| `noirlycan_backend` | REST ingest, auth, rules, agents, findings API |
| `dashboard-ui/` | React console (Findings, Agents, Rules, File drops) |
| `noirlycan_dashboard` | Static file server for built UI (+ legacy Django) |

Deprecated shims (still work): `noirlycan-telemetry`, `noirlycan-console` → prefer `noirlycan-agent` / `noirlycan-backend`.

## Quick start — lab console (Mac / Linux server)

### 1. Install

```bash
git clone https://github.com/noirlycan/NoirlycanThesis.git
cd NoirlycanThesis
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[lab]"
# or: uv sync && uv pip install -e ".[lab]"
```

### 2. Backend API

```bash
noirlycan-backend api --host 0.0.0.0 --port 8765
```

Data defaults to `logs/` (JSONL sessions + `noirlycan.db`). Override with `NOIRLYCAN_LOGS_DIR`.

### 3. Dashboard (dev)

```bash
cd dashboard-ui && npm install && npm run dev
```

Open [http://127.0.0.1:5173](http://127.0.0.1:5173) — Vite proxies `/api` → `http://127.0.0.1:8765`.

**Demo login:** `admin@lab` / `admin` (change in production).

Production build + static serve:

```bash
cd dashboard-ui && npm run build && cd ..
noirlycan-dashboard serve --host 0.0.0.0 --port 8080
```

Or Docker:

```bash
docker compose up backend-api dashboard-ui
```

### One-command launcher (backend + dashboard)

`scripts/lab_stack.py` wraps steps 2–3 into a single process group (Ctrl+C stops both):

```bash
./scripts/run-lab.sh --host 0.0.0.0 --backend-port 8888
# or directly:
python scripts/lab_stack.py up --host 0.0.0.0 --backend-port 8888
```

Prints the backend health URL, dashboard URL, and the exact `noirlycan-agent`/`lab_stack.py agent` command to run on the Windows VM once you've copied its enrollment token from **Agents**. Individual pieces are also available: `lab_stack.py backend`, `lab_stack.py dashboard`, `lab_stack.py agent`, `lab_stack.py sysmon`.

## Quick start — Windows agent (VM)

Use a **disposable VM snapshot**. Isolate from production networks.

### 1. Install agent only

```powershell
git clone https://github.com/noirlycan/NoirlycanThesis.git C:\Noirlycan\agent
cd C:\Noirlycan\agent
.\scripts\install-agent.ps1
# or: py -3.11 -m venv .venv; .\.venv\Scripts\activate; pip install -e ".[agent]"
```

### 2. Register on dashboard

1. Open **Agents** → **Register workstation** (agent id + enrollment token).  
2. **Copy config** → save as `C:\Noirlycan\noirlycan-agent.toml`.  
3. On the VM:

```powershell
.\.venv\Scripts\activate
noirlycan-agent run --config C:\Noirlycan\noirlycan-agent.toml --watch-sysmon --auto-attach-new-processes
```

Or pass server/token directly:

```powershell
noirlycan-agent run --server 192.168.1.10:8765 --agent-id vm01 --token YOUR_TOKEN --watch-sysmon --auto-attach-new-processes
```

Or the launcher shortcut (same flags, wraps `lab_stack.py agent`):

```powershell
.\scripts\run-lab-agent.ps1 -Server 192.168.1.10:8765 -AgentId vm01 -Token YOUR_TOKEN
```

Credentials persist in `logs\.agent_identity.json` next to the working directory.

### 3. Agent dependencies (Frida + pywin32)

`--watch-sysmon` and Frida hooks need the **`[agent]`** extra. Install inside the venv:

```powershell
cd C:\Noirlycan\agent   # repo root on VM
.\.venv\Scripts\Activate.ps1
pip install -e ".[agent]"

python -c "import frida; import win32evtlog; print('OK', frida.__version__)"
```

If you see `Frida unavailable` or `pywin32 is required`, the agent was started outside `.venv` or without `[agent]`.

### 4. Sysmon configuration

Sysmon is **not** bundled in the repo (license). The lab ships **`configs/sysmon-noirlycan.xml`** and **`scripts/install-sysmon.ps1`**. You must download the binary separately.

#### Layout on the VM

```text
NoirlycanThesis/
  Sysmon/
    Sysmon64.exe          ← download from Microsoft Sysinternals (not in git)
  configs/
    sysmon-noirlycan.xml  ← lab rules (committed)
  scripts/
    install-sysmon.ps1
```

Download: [Sysmon for Windows](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) → extract **`Sysmon64.exe`** into `Sysmon\`.

#### What `configs/sysmon-noirlycan.xml` logs

| Sysmon EID | Rule in config | Used by Noirlycan for |
|------------|----------------|------------------------|
| **1** ProcessCreate | Log all (exclude none) | Parent/child lineage, **target process name**, auto-attach candidates |
| **3** NetworkConnect | Outbound, not localhost | Post-finding network watch (beacon hints) |
| **7** ImageLoad | `ntdll.dll`, `kernel32.dll` | Process/DLL context for correlation |
| **8** CreateRemoteThread | Log all (exclude none) | Remote-thread injection context |
| **10** ProcessAccess | Selected `GrantedAccess` masks | Cross-process open / injection staging |
| **11** FileCreate | `.exe`, `.dll`, `.ps1`, `.vbs`, … | File-drop provenance (with agent file watch) |

Rules intentionally broad for **isolated lab VMs** — expect volume on busy hosts. Tune `configs/sysmon-noirlycan.xml` for your experiment; reload with `-c` (below).

Full config path: [`configs/sysmon-noirlycan.xml`](configs/sysmon-noirlycan.xml).

#### Install (Admin PowerShell)

From repo root:

```powershell
.\scripts\install-sysmon.ps1
# or: .\scripts\run-lab-sysmon.ps1
```

Equivalent manual install:

```powershell
.\Sysmon\Sysmon64.exe -accepteula -i .\configs\sysmon-noirlycan.xml
```

#### Update config after `git pull`

```powershell
.\Sysmon\Sysmon64.exe -c .\configs\sysmon-noirlycan.xml
```

#### Reinstall (broken or old config)

```powershell
.\Sysmon\Sysmon64.exe -u force
.\Sysmon\Sysmon64.exe -accepteula -i .\configs\sysmon-noirlycan.xml
```

#### Permissions

The agent reads **`Microsoft-Windows-Sysmon/Operational`** via pywin32. Either:

- Run the agent in **Administrator** PowerShell, **or**
- Add the VM user to local group **Event Log Readers**, then **sign out and sign in** (or reboot).

Verify the channel exists:

```powershell
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 3
```

#### Troubleshooting

| Agent message | Fix |
|---------------|-----|
| `pywin32 is required on Windows` | `pip install -e ".[agent]"` in activated `.venv` |
| `Install Sysmon first` / winerror **4201** | Install Sysmon with `install-sysmon.ps1`; channel missing |
| `Access denied reading ... Operational` | Admin shell or **Event Log Readers** + re-login |
| Target process shows `unknown (pid N)` | Sysmon EID 1 not ingested — complete install + `--watch-sysmon` |
| Terminal slow after CRITICAL finding | Expected with broad EID 3 rules; agent throttles Sysmon ingest |

#### Run agent with Sysmon

```powershell
.\.venv\Scripts\Activate.ps1
noirlycan-agent run --config .\noirlycan-agent.toml --watch-sysmon --auto-attach-new-processes
```

Successful startup has **no** `[!] Sysmon unavailable` line.

### 5. File-drop experiment

`run` watches common folders by default (Downloads, Desktop, `D:\`, repo root). Drop a **new** executable name:

```powershell
Copy-Item "C:\Lab\loader.exe" "C:\Users\Public\Downloads\drop_$(Get-Random).exe"
```

Console: **File drops** tab → **Analyze APIs** (optional) → findings appear under **Findings**.

## Standalone mode (no console)

Local JSONL only — useful for quick tests without backend:

```powershell
# Spawn sample under Frida from the first instruction (best for loaders)
noirlycan-agent spawn --watch-sysmon -- C:\Lab\loader.exe

# Long-running loop + file watch
noirlycan-agent run --watch-sysmon --auto-attach-new-processes

# Attach to PID
noirlycan-agent run --watch-sysmon --attach-pid 1337

# Static triage
noirlycan-agent triage C:\Lab\loader.exe
```

Default log: `logs/session-<timestamp>.jsonl` (override with `--jsonl`).

## Console features

- **Findings** — grouped by actor → target process / injection chain; kill process from dashboard  
- **Agents** — register VMs, copy run command, auto-kill policy per agent  
- **Rules** — scoring weights, hook policy, capture window, network watch duration  
- **File drops** — pending drops + triage metadata  
- **Access** — RBAC (admin / analyst / viewer)

UI spec: [`design_handoff_noirlycan_console/`](design_handoff_noirlycan_console/).

Legacy Django dashboard (upload tab, Jet admin):

```powershell
pip install -e ".[dashboard]"
noirlycan-dashboard legacy
```

## Repository layout

```text
configs/sysmon-noirlycan.xml    Sysmon lab config
dashboard-ui/                   React + Vite frontend
deploy/                         nginx, 3-service deploy notes
docs/                           architecture, threat model, thesis notes
scripts/
  install-agent.ps1             Agent-only Windows install
  install-sysmon.ps1            Sysmon + repo config
  lab_stack.py                  Launch backend/dashboard/agent (up/backend/dashboard/agent/sysmon)
  run-lab.sh                    Mac/Linux: lab_stack.py up
  run-lab-agent.ps1             Windows VM: lab_stack.py agent
  run-lab-sysmon.ps1            Windows VM: lab_stack.py sysmon
src/
  noirlycan_core/               correlation, storage, classification
  noirlycan_agent/              collector + Frida hooks
  noirlycan_backend/            FastAPI console backend
  noirlycan_dashboard/          UI static server + legacy Django
tests/
thesis/                         thesis chapters (Vietnamese / HTW)
docker-compose.yml
```

## Environment variables

| Variable | Description |
|----------|-------------|
| `NOIRLYCAN_LOGS_DIR` | Logs + SQLite directory (default: `./logs`) |
| `NOIRLYCAN_CORS_ORIGINS` | Comma-separated dashboard origins for CORS |
| `NOIRLYCAN_CONSOLE_JWT_SECRET` | JWT signing secret (set in production) |
| `NOIRLYCAN_DASHBOARD_UI` | Path to built `dashboard-ui/dist` (optional) |

## CLI reference

| Command | Purpose |
|---------|---------|
| `noirlycan-backend api` | Start FastAPI console backend |
| `noirlycan-backend seed-demo` | Seed demo agent sessions |
| `noirlycan-dashboard serve` | Serve built React UI |
| `noirlycan-agent run` | Collector loop (local and/or remote ingest) |
| `noirlycan-agent spawn` | Frida-spawn a sample |
| `noirlycan-agent triage` | Static PE/hash triage |
| `noirlycan-telemetry …` | Deprecated alias → `noirlycan-agent` |

## Development

```bash
pip install -e ".[dev]"
python -m pytest
```

Key docs:

- [`docs/clean-architecture-plan.md`](docs/clean-architecture-plan.md) — service boundaries  
- [`docs/architecture-diagrams.md`](docs/architecture-diagrams.md) — diagrams  
- [`configs/sysmon-noirlycan.xml`](configs/sysmon-noirlycan.xml) — Sysmon lab rules (see **Sysmon configuration** above)  
- [`deploy/agent/README.md`](deploy/agent/README.md) — minimal VM install  

## Limitations

- Frida and Sysmon are lab instrumentation; evasive malware can bypass user-mode hooks.  
- Direct syscalls / kernel techniques are out of scope.  
- Sysmon config is broad for experiments and can be noisy.  
- Target process names depend on Sysmon ProcessCreate and/or Frida spawn metadata; install Sysmon on the VM for best results.  
- Prototype for measurement and thesis work — not an EDR product.
