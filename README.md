# Noirlycan Thesis Telemetry Prototype

Prototype for a Windows 10/11 thesis lab that correlates:

```text
new file on disk -> process lineage -> process injection primitives
```

The implementation combines:

- **Sysmon** for file creation, process creation, image load, process access,
  and remote-thread context.
- **Frida** for user-mode API telemetry around process injection primitives.
- A Python **correlation engine** inspired by the ASIA CCS 2025 paper
  "Can You Run My Code? A Close Look at Process Injection in Windows Malware",
  extended with file provenance and process lineage.

This is a defensive analysis prototype for isolated lab use. It does not ship
payloads, loaders, or exploit code.

## What it detects

The correlator looks for at least two of the three process-injection primitives:

1. allocate or prepare executable memory in a target process,
2. write/map payload into that target process,
3. initiate execution in that target process.

It then enriches the runtime primitive chain with Sysmon context:

- which file was newly created,
- which process executed that file,
- the parent/child process lineage,
- whether the injected target is cross-process,
- whether the flow used section mapping or suspended process execution.

This is useful for comparing:

```text
memory-only loader:
  embedded/encrypted payload -> section mapping -> ResumeThread

file-dropping loader:
  FileCreate -> ProcessCreate -> injection primitives
```

## Repository layout

```text
configs/
  sysmon-noirlycan.xml              Minimal Sysmon config for the lab
src/noirlycan_telemetry/
  cli.py                            Composition root (monolith mode)
  kernel/                           Domain layer (shared)
    entities/models.py              Finding, MemoryPrimitive, …
    analysis/primitives.py          operational_kind_count, analyze_execution
    classification/
      api_manifest.py               PAPER_API_CLASSES (ASIA CCS 2025)
      technique_classifier.py       Rule-based technique detection
  services/
    collector/                      Sysmon, Frida, file watch, triage
    analysis/domain/                correlation.py, reclassify, session_analytics
    storage/infrastructure/         log_store, analysis_db
    dashboard/                      Django REST + WebSocket UI
  frida_hooks/windows_injection_hooks.js
  contracts/events.py               Inter-service wire format
tests/
  test_correlation.py               Synthetic correlation tests
docs/
  clean-architecture-plan.md        Clean Architecture + microservices
  architecture-diagrams.md          Thesis diagrams
docker-compose.yml                  Optional microservices deployment
```

See [`docs/clean-architecture-plan.md`](docs/clean-architecture-plan.md) for service boundaries and deployment modes.

## Windows 10/11 lab setup

Use a disposable VM snapshot. If you test real malware, keep the VM isolated
from production networks and do not use personal credentials or shared folders
containing sensitive files.

### 1. Install Python dependencies

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e .[dev]
```

### 2. Install Sysmon

Sysmon binaries live in `.\Sysmon\`. From the repo root, install the included config:

```powershell
cd D:\thesis\NoirlycanThesis
.\Sysmon\Sysmon64.exe -accepteula -i .\configs\sysmon-noirlycan.xml
```

If Sysmon is already installed but broken or you need to refresh the config:

```powershell
.\Sysmon\Sysmon64.exe -u force
.\Sysmon\Sysmon64.exe -accepteula -i .\configs\sysmon-noirlycan.xml
```

To update config only on a healthy install:

```powershell
.\Sysmon\Sysmon64.exe -c .\configs\sysmon-noirlycan.xml
```

Relevant Sysmon events:

- Event ID 1: process creation and parent/child lineage
- Event ID 7: `ntdll.dll` / `kernel32.dll` image loads
- Event ID 8: remote thread creation
- Event ID 10: process access
- Event ID 11: executable/script file creation
- Event ID 15: alternate data stream hash

Sysmon does **not** see all NT-level operations used by section-mapping loaders,
so Frida provides the API-level telemetry.

### 3. Run a sample under Frida from process start

This is the preferred mode for a loader because injection may happen quickly:

```powershell
noirlycan-telemetry spawn --watch-sysmon -- C:\Lab\loader.exe
```

By default, telemetry is written to `logs/session-<timestamp>.jsonl`. Override the
path with `--jsonl` or disable file logging with `--no-jsonl`.

The `spawn` command starts the process suspended via Frida, loads the hook
script, then resumes it. This gives the prototype the best chance to observe
early calls such as:

- `NtCreateSection`
- `NtMapViewOfSection`
- `SetThreadContext`
- `ResumeThread`

### 4. Attach to an already running process

```powershell
noirlycan-telemetry run --watch-sysmon --attach-pid 1337
```

### 5. Watch Sysmon and auto-attach to new interesting processes

```powershell
noirlycan-telemetry run --watch-sysmon --auto-attach-new-processes
```

Auto-attach is useful for file-dropping experiments, but it can miss very early
injection activity if the process injects before Frida attaches. Use `spawn`
for controlled tests where possible.

### 6. Open the web dashboard (Django)

After collecting one or more sessions in `logs/`, launch the statistics UI:

```powershell
noirlycan-telemetry dashboard
```

Then open [http://127.0.0.1:8765](http://127.0.0.1:8765). The dashboard is a **Django** app with drag-and-drop upload (tab **Upload**), SQLite persistence for parsed logs (`logs/noirlycan.db`), and the same REST API paths as before (`/api/overview`, `/api/upload`, …). It includes:

- tabs for **Overview**, **Findings**, **Network**, **Primitives**, **Event stream**, and **Sessions**,
- filters by severity, target PID, event type, and free-text search,
- click a finding to open a detail modal (evidence, API chain, primitives, related network),
- click a session row or network row to drill into that PID,
- auto-refresh toggle and JSONL export for the active session,
- charts for severity, primitives, timeline, top APIs, and top actors.

After a finding reaches **HIGH** or **CRITICAL**, the correlator watches the
injected target PID for 5 minutes. Outbound connections are captured from
Sysmon Event ID 3 and surfaced as `[NETWORK:BEACON?]` when the destination is
outside private/local ranges.

Reload Sysmon config after pulling updates:

```powershell
C:\Windows\System32\sysmon.exe -c .\configs\sysmon-noirlycan.xml
```

### 7. Watch for dropped files and auto-triage

`run` polls watched folders **by default** (repo root, `D:\`, `D:\thesis`,
Downloads, Desktop). Sysmon is optional but adds creator process metadata.

```powershell
python -m noirlycan_telemetry run
# or with Sysmon (Admin PowerShell recommended):
python -m noirlycan_telemetry run --watch-sysmon
```

Test with a **new filename** (files already on disk at startup are baselined):

```powershell
Copy-Item "D:\thesis\aes_decrypt_loader.exe" "D:\drop_test_$(Get-Random).exe"
```

You should see `[FILE:DROP] Detected ...` immediately, then a
`===== FILE DROP DETECTED =====` banner when static triage finishes. Open the
dashboard **File drops** tab for the active session.

Disable folder polling with `--no-watch-files` (locks the dashboard toggle off).
Add paths with `--watch-path C:\Lab`.

While `run` is active, open the dashboard **File drops** tab:

- **Watch folders** — detect new executables without restarting the collector
- **Auto API analysis on drop** — spawn every new EXE under Frida injection hooks (off by default)
- **Analyze APIs** button — spawn a pending drop under Frida hooks (`NtMapViewOfSection`, `ResumeThread`, …)
- Primitives and findings appear in the **Primitives** / **Findings** tabs of the same session

### 8. Static triage a file

```powershell
noirlycan-telemetry triage C:\Lab\loader.exe
```

The triage step computes SHA-256, PE header presence, entropy, Authenticode
status, and suspicious imports when available.

## Loader flow coverage

For a section-mapping loader like:

```text
resource payload -> AES decrypt in heap
CreateProcess(msedge.exe, CREATE_SUSPENDED)
NtCreateSection(PAGE_EXECUTE_READWRITE, SEC_COMMIT)
NtMapViewOfSection(local)
RtlCopyMemory(payload into local view)
NtMapViewOfSection(remote msedge.exe)
SetThreadContext
ResumeThread
```

Expected telemetry:

```text
Sysmon:
  ProcessCreate loader.exe
  ProcessCreate msedge.exe with suspicious parent/command line
  ProcessAccess loader.exe -> msedge.exe

Frida:
  allocate primitive: NtCreateSection
  write primitive: NtMapViewOfSection(remote)
  execute primitive: SetThreadContext / ResumeThread

Correlator:
  Probable process injection chain
  section_mapping=true
  cross_process=true
```

For a file-dropping loader, the output should additionally include a related
file from Sysmon Event ID 11 and static triage metadata.

## Current limitations

- Frida is a lab instrumentation backend and can be detected or bypassed by
  evasive malware.
- Direct syscalls, unhooking, or kernel-mode techniques can bypass user-mode
  hooks.
- The hook script currently logs `SetThreadContext`/`ResumeThread` as execution
  primitives without decoding every architecture-specific register field.
- Sysmon filtering is intentionally broad enough for experiments and may be too
  noisy for production hosts.
- The prototype is for measurement and thesis experiments, not a production EDR.

## Development

Run tests:

```bash
python -m pytest
```
