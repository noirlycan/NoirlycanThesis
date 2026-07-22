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

Credentials persist in `logs\.agent_identity.json` next to the working directory.

### 3. Install Sysmon (strongly recommended)

Sysmon supplies process names, lineage, and network events. Without it, target process names may show as `unknown (pid N)`.

Download [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon), place `Sysmon64.exe` in `Sysmon\`, then **Admin PowerShell**:

```powershell
.\scripts\install-sysmon.ps1
```

Add the VM user to **Event Log Readers**, then sign out/in. Update config after git pull:

```powershell
.\Sysmon\Sysmon64.exe -c .\configs\sysmon-noirlycan.xml
```

Relevant event IDs: **1** process create, **3** network, **7** image load, **8** remote thread, **10** process access, **11** file create.

### 4. File-drop experiment

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
- [`deploy/agent/README.md`](deploy/agent/README.md) — minimal VM install  

## Limitations

- Frida and Sysmon are lab instrumentation; evasive malware can bypass user-mode hooks.  
- Direct syscalls / kernel techniques are out of scope.  
- Sysmon config is broad for experiments and can be noisy.  
- Target process names depend on Sysmon ProcessCreate and/or Frida spawn metadata; install Sysmon on the VM for best results.  
- Prototype for measurement and thesis work — not an EDR product.
