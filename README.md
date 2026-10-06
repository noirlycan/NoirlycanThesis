# Noirlycan Thesis Telemetry Prototype

Defensive lab prototype for Windows 10/11 that correlates **file drops → process lineage → process-injection primitives**, inspired by the ASIA CCS 2025 paper *Can You Run My Code?* Extended with file provenance, remote agents, and a web console for thesis experiments.

**Not for production.** No payloads, loaders, or exploit code are shipped.

## What it detects

The correlator scores chains with at least two of three injection primitives:

1. **Allocate** executable memory in a target process  
2. **Write / map** payload into that process  
3. **Execute** (thread context, resume, remote thread, …)

Two sensors feed the detector. **Frida** hooks give API-level detail (addresses, sizes, protections). **Sysmon** kernel callbacks still see remote-thread creation (EID 8, as an EXECUTE primitive) and cross-process handle opens with their call stack (EID 10) when a sample bypasses the user-mode hooks with direct syscalls or unhooking; the call stack is checked for direct syscalls and unbacked callers, and a remote thread the kernel saw but Frida missed is flagged as a hook bypass. See [`docs/code-map.md`](docs/code-map.md) for how the code maps to the paper. Typical lab flows:

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
| `noirlycan_core` | Analysis module: paper rules (`detection/`), technique classification, trace parsers, storage |
| `noirlycan_agent` | Monitoring module on the VM: sensors (Frida, Sysmon, file watch, network), runtime, lab studies |
| `noirlycan_backend` | FastAPI console: auth/RBAC, agent channel (signed commands), samples, rules, findings |
| `dashboard-ui/` | React console (Findings, Activity, Network, Rules, Samples, Agents, Access) |
| `noirlycan_dashboard` | Static file server for the built UI |

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

**Login:** on first start the backend creates `admin@lab` with the password in `NOIRLYCAN_ADMIN_PASSWORD`, or prints a random one to the console. For demos, `NOIRLYCAN_DEMO_USERS=1` seeds `admin@lab`/`admin`, `analyst@lab`/`analyst`, `viewer@lab`/`viewer` instead.

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

For the desktop version, build on Windows with `.\scripts\build-agent-desktop.ps1`
and copy `dist\NoirlycanAgent.exe` to the VM. Open it, accept Administrator UAC,
and enter the server and agent enrollment token from the dashboard. No Python is
needed on the target VM. See [desktop build and usage](deploy/agent/README.md).

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

Credentials persist in `logs\.agent_identity.json` next to the working directory. On Windows the token is encrypted with DPAPI. The file also pins the console's command-signing key (from `command_key` in the exported config): the agent only runs commands signed with that key, addressed to itself, unexpired and not replayed.

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
| **8** CreateRemoteThread | Log all (exclude none) | EXECUTE primitive from the kernel (start address used for congruence when unbacked) |
| **10** ProcessAccess | Selected `GrantedAccess` masks | Handle-access evidence; `CallTrace` checked for direct syscalls / unbacked callers |
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
- **Samples** — upload an `.exe`/`.dll`, send it to a lab agent (SHA-256 verified on the VM, run under Frida), view the report; `.jsonl` uploads are imported for offline analysis  
- **Agents** — register VMs, copy config, auto-kill policy per agent  
- **Rules** — scoring weights, hook policy, capture window, network watch duration  
- **Activity** — live events, pending file drops + triage metadata  
- **Access** — RBAC (admin / analyst / viewer)

Classifier rules (built-in catalog, per-rule gates, custom rules) are served at `/api/classifier`; offline corpus stats and re-correlation at `/api/analysis/*`.

UI spec: [`design_handoff_noirlycan_console/`](design_handoff_noirlycan_console/).

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
  noirlycan_core/               detection (paper rules), classification, trace parsers, storage
  noirlycan_agent/              sensors (Frida, Sysmon, file/network watch), runtime, lab studies
  noirlycan_backend/            FastAPI console backend
  noirlycan_dashboard/          static server for the built UI
tests/
thesis/                         thesis chapters (Vietnamese / HTW)
docker-compose.yml
```

## Environment variables

| Variable | Description |
|----------|-------------|
| `NOIRLYCAN_LOGS_DIR` | Logs + SQLite directory (default: `./logs`) |
| `NOIRLYCAN_CORS_ORIGINS` | Comma-separated dashboard origins for CORS |
| `NOIRLYCAN_CONSOLE_JWT_SECRET` | JWT signing secret (default: random, stored in `logs/.jwt_secret`) |
| `NOIRLYCAN_ADMIN_PASSWORD` | Password for `admin@lab` on first start (default: random, printed once) |
| `NOIRLYCAN_DEMO_USERS` | `1` seeds the three well-known demo accounts instead |
| `NOIRLYCAN_DASHBOARD_UI` | Path to built `dashboard-ui/dist` (optional) |

## CLI reference

| Command | Purpose |
|---------|---------|
| `noirlycan-backend api` | Start FastAPI console backend |
| `noirlycan-backend corpus` | Corpus statistics over stored sessions |
| `noirlycan-backend reclassify` | Replay a session through the current detector/classifier |
| `noirlycan-backend seed-demo` | Seed demo agent sessions |
| `noirlycan-dashboard serve` | Serve built React UI |
| `noirlycan-agent run` | Collector loop (local and/or remote ingest) |
| `noirlycan-agent spawn` | Frida-spawn a sample |
| `noirlycan-agent triage` | Static PE/hash triage |
| `noirlycan-agent batch` | Run every EXE in a folder (mini-corpus study) |
| `noirlycan-agent compare` | Compare with Defender / VirusTotal |

## Development

```bash
pip install -e ".[dev]"
python -m pytest
```

Key docs:

- [`docs/code-map.md`](docs/code-map.md) — code ↔ paper map and module layout  
- [`docs/proposal-kernel-telemetry.md`](docs/proposal-kernel-telemetry.md) — sensor roadmap (ETW-TI, Sysmon)  
- [`docs/proposal-platform-architecture.md`](docs/proposal-platform-architecture.md) — agent management and security design  
- [`docs/architecture-diagrams.md`](docs/architecture-diagrams.md) — diagrams  
- [`configs/sysmon-noirlycan.xml`](configs/sysmon-noirlycan.xml) — Sysmon lab rules (see **Sysmon configuration** above)  
- [`deploy/agent/README.md`](deploy/agent/README.md) — minimal VM install  

## Limitations

- Frida hooks can be bypassed (direct/indirect syscalls, unhooking, anti-Frida). Sysmon keeps kernel-side signal (remote threads, handle opens + call stacks) but has no allocate/write events; restoring full syscall-level primitives needs the ETW Threat-Intelligence sensor described in the kernel-telemetry proposal (not implemented: it requires a PPL/ELAM-signed native sensor).  
- While Frida is attached, its own trampolines appear as unbacked frames in Sysmon call stacks; that heuristic is only scored for actors Frida did not instrument.  
- Kernel-mode adversaries are out of scope, as in the paper.  
- Sysmon config is broad for experiments and can be noisy.  
- Target process names depend on Sysmon ProcessCreate and/or Frida spawn metadata; install Sysmon on the VM for best results.  
- Prototype for measurement and thesis work — not an EDR product.
