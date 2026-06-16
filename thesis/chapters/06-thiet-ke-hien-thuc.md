# CHƯƠNG 5. THIẾT KẾ VÀ HIỆN THỰC HỆ THỐNG NOIRLYCAN

Chương này mô tả kiến trúc và hiện thực artifact **Noirlycan Telemetry** — prototype phục vụ phòng lab Windows 10/11 cô lập, triển khai phương pháp Chương 4. Hệ thống được tổ chức theo mô hình phân lớp: thu thập (collectors), xử lý (correlator, triage, classifier), lưu trữ (JSONL, SQLite), và trình bày (dashboard Django). Mọi thiết kế bám sát paper [4] ở tầng correlator; các module provenance và dashboard là đóng góp engineering của luận văn. **Module anti-evasion (E5) của [4] không được hiện thực** — file `kernel/analysis/evasion.py` chỉ ghi nhận tín hiệu, không patch timing hay môi trường sandbox.

---

## 5.1. Kiến trúc tổng thể

Sau giai đoạn refactor, codebase Noirlycan tổ chức theo **Clean Architecture** (Uncle Bob) và có thể triển khai **monolith** (mặc định lab) hoặc **microservices** (Docker). **Lõi correlator 2-of-3 của [4] không đổi** — chỉ tách boundary module cho dễ kiểm soát, test và mở rộng. Chi tiết: `docs/clean-architecture-plan.md`.

### 5.1.1. Sơ đồ Clean Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  Presentation                                                    │
│  cli.py · services/dashboard/ (Django REST + WebSocket)          │
│  services/storage/api.py · services/analysis/api.py              │
├──────────────────────────────────────────────────────────────────┤
│  Application                                                     │
│  collector_runtime · analysis_queue · reclassify · upload_finalize│
├──────────────────────────────────────────────────────────────────┤
│  Domain (kernel/) — không phụ thuộc framework/I/O               │
│  entities/models · analysis/primitives · analysis/injection_graph│
│  classification/technique_classifier · classification/api_manifest│
├──────────────────────────────────────────────────────────────────┤
│  Infrastructure                                                  │
│  collector: sysmon · frida_manager · file_watch · triage         │
│  storage: log_store · analysis_db · atomic_io                    │
│  analysis/domain: correlation · session_analytics · batch_runner  │
└──────────────────────────────────────────────────────────────────┘
```

**Quy tắc phụ thuộc:** Presentation → Application → Domain ← Infrastructure. Layer `kernel/` không import Django, Frida hay win32evtlog.

### 5.1.2. Bốn microservice và chế độ triển khai

**Bảng 5.1.** Service boundary

| Service | Vai trò | Port | Entry point |
|---------|---------|------|-------------|
| **collector** | Sysmon + Frida + file-drop trên Windows VM | 8782 (health) | `noirlycan-telemetry run` |
| **storage** | Ghi/đọc JSONL, SQLite uploads | 8780 | `noirlycan-storage` |
| **analysis** | Correlator, reclassify, corpus | 8781 | `noirlycan-analysis` |
| **dashboard** | UI analyst | 8765 | `noirlycan-telemetry dashboard` |

| Mode | Mô tả | Khi dùng |
|------|-------|----------|
| **Monolith** | `run` + `dashboard` in-process, ghi trực tiếp `logs/` | Dev lab, demo luận văn |
| **Microservices** | `docker compose up` — storage + analysis + dashboard; collector native trên VM | Tách scale, kiểm soát từng service |

Wire format giữa service: `contracts/events.py` (`TelemetryEnvelope`) — tương thích JSONL session.

### 5.1.3. Luồng runtime monolith (`noirlycan-telemetry run`)

1. `cli.py` (composition root) khởi tạo `Correlator`, `JsonlWriter`, `SysmonPoller`, `FridaInjectionMonitor`, `FileDropWatcher`.
2. Vòng lặp: Sysmon batch → correlator; file watcher → triage → correlator; drain Frida → correlator.
3. `Finding` ghi `logs/session-*.jsonl`; dashboard tail cùng volume.

### 5.1.4. Module map (đường dẫn sau refactor)

**Bảng 5.2.** Ánh xạ module — trách nhiệm

| Thành phần | Đường dẫn trong repo | Vai trò |
|------------|----------------------|---------|
| CLI | `cli.py` | Composition root, subcommand |
| Correlator | `services/analysis/domain/correlation.py` | 2-of-3, scoring, network watch |
| Primitives | `kernel/analysis/primitives.py` | `operational_kind_count`, `analyze_execution` |
| Classifier | `kernel/classification/technique_classifier.py` | Rule → `InjectionTechnique` |
| API manifest | `kernel/classification/api_manifest.py` | `PAPER_API_CLASSES` [4] |
| Models | `kernel/entities/models.py` | `Finding`, `MemoryPrimitive`, … |
| Collector loop | `services/collector/application/collector_runtime.py` | JsonlWriter, drain |
| Frida | `services/collector/infrastructure/frida_manager.py` | Attach/spawn, bridge |
| Hooks | `frida_hooks/windows_injection_hooks.js` | Interceptor user-mode |
| Sysmon | `services/collector/infrastructure/sysmon.py` | Kernel event poll |
| File watch | `services/collector/infrastructure/file_watch.py` | Drop scanner |
| Triage | `services/collector/infrastructure/triage.py` | Static analysis |
| Log store | `services/storage/infrastructure/log_store.py` | JSONL I/O |
| Analysis DB | `services/storage/infrastructure/analysis_db.py` | SQLite cache |
| Dashboard | `services/dashboard/` | Django + Daphne + WebSocket |
| Evasion log | `kernel/analysis/evasion.py` | Ghi signal E5/E6 (không patch) |

Package: `src/noirlycan_telemetry/`, cài `pip install -e .[dev]`.

---

## 5.2. Giao diện dòng lệnh (`cli.py`)

### 5.2.1. Subcommand

`build_parser()` định nghĩa:

| Lệnh | Mục đích |
|------|----------|
| `run` | Vòng lặp collector đầy đủ (Sysmon + file watch + Frida) |
| `spawn` | Spawn mẫu dưới Frida từ entry (giảm miss E6/E4 attach trễ) |
| `triage` | Static triage một file |
| `dashboard` | Khởi Django server |
| `batch` | Chạy nhiều mẫu tuần tự, báo cáo JSON |
| `compare` | So sánh với VirusTotal (tùy chọn API key) |
| `corpus` | Thống kê aggregate trên nhiều session JSONL |
| `reclassify` | Chạy lại classifier trên log cũ |

### 5.2.2. `command_run` — orchestration

Tham số quan trọng:

- `--watch-sysmon`: bật `SysmonPoller` (cần quyền đọc Event Log).
- `--watch-path`: thêm thư mục file drop (mặc định: repo root, `D:\`, `D:\thesis`, Downloads, Desktop).
- `--attach-pid` / `--auto-attach-new-processes`: Frida attach thủ công hoặc theo Sysmon E1.
- `--minimum-score`: ngưỡng finding (mặc định 50).
- `--jsonl`: đường dẫn session log.

Luồng xử lý file mới:

1. `FileDropWatcher.drain()` → `FileEvent`.
2. Thread pool `_TRiage_EXECUTOR` gọi `triage_file` → làm giàu SHA256, PE, entropy, signature.
3. `correlator.add_file(enriched)`.
4. Nếu PE executable: `enqueue_analysis` spawn dưới Frida (hàng đợi `analysis_queue.py`).

Heartbeat collector ghi `logs/.runtime.json` để dashboard biết trạng thái online.

### 5.2.3. Tích hợp classifier config

`ensure_classifier_config()` tạo `.classifier_rules.json` — cho phép chỉnh `minimum_score`, `minimum_operational_kinds`, custom rules mà không sửa code. `Correlator.reload_rules_config()` hot-reload khi file thay đổi.

---

## 5.3. Vòng lặp collector (`services/collector/application/collector_runtime.py`)

### 5.3.1. JsonlWriter

Ghi từng dòng JSON `{"type": event_type, "value": ...}` — type gồm: `file`, `sysmon`, `primitive`, `finding`, `network`, `frida_raw`, `evasion`. Flush mỗi 32 dòng giảm I/O. Dashboard và `reclassify` đọc cùng format.

### 5.3.2. Xử lý Sysmon batch

`process_sysmon_batch()`:

- `FileEvent` → handler tùy chỉnh hoặc `correlator.add_file`.
- `ProcessEvent` → `correlator.add_process`; nếu `auto_attach` và `should_auto_attach()` → `safe_attach(monitor, pid)`.
- `NetworkConnectionEvent` → `handle_network_event` (chỉ lưu nếu PID trong network watch).
- `TelemetryEvent` generic (E8/E10 raw) → ghi JSONL cho phân tích sau.

`should_auto_attach`: bỏ qua binary system32 không có parent lạ; chấp nhận `.exe/.dll/.scr/.com` từ nguồn đáng ngờ.

### 5.3.3. Drain Frida

`drain_frida()` xử lý queue không blocking:

1. `evasion` signal → in cảnh báo, **không** correlate (E5/E6 awareness only).
2. `frida_process` → `add_process`, auto-attach con.
3. `memory_primitive` → `add_primitive` → findings.

`print_finding()` in severity, technique, execution_confirmed, recursive chain, network watch — phục vụ lab không cần dashboard.

---

## 5.4. Lớp Frida (`services/collector/infrastructure/frida_manager.py` + hooks)

### 5.4.1. FridaInjectionMonitor

- `load_default_hook_script()`: đọc `windows_injection_hooks.js` qua `importlib.resources`.
- `attach(pid)`: `frida.attach` → `create_script` → `script.load`; một session/script mỗi PID.
- `_on_message`: parse JSON payload, đẩy `FridaRuntimeEvent` vào `queue.Queue`.

Chuyển đổi:

- `runtime_event_to_primitive()`: map `allocate|write|execute|context_read` → `MemoryPrimitive`.
- `runtime_event_to_process()`: spawn notification từ hook.
- Observation-only (`remote_read`, TXF hint) → `api_observation`, không vào 2-of-3.

### 5.4.2. Thiết kế hook JavaScript

File `windows_injection_hooks.js` (~1900 dòng) cấu trúc:

1. **Helper:** `ptrToNumber`, `ntSuccess`, `readAnsiString`, `protectionToString`.
2. **Dynamic resolve:** hook `GetProcAddress` / `LdrGetProcedureAddress` — khi target ∈ `DYNAMIC_INJECTION_APIS`, attach lazy hook.
3. **Per-API handler:** đọc args/retval, trích `baseAddress`, `NumberOfBytes`, `lpStartAddress`, `CONTEXT.Rip`.
4. **Emit:** `send({type: "memory_primitive", kind, api, actor_pid, target_pid, address, size, details})`.

**Fix D1:** `readInstructionPointerFromContext` cho `SetThreadContext` / `NtSetContextThread` — đặt `address = Rip` trên primitive EXECUTE.

**Alias Zw*:** manifest và hook dùng tên canonical; stub Zw chuyển tiếp tới Nt.

Coverage test: `test_hook_manifest_coverage.py`, `test_api_coverage.py` đối chiếu manifest ↔ hook.

### 5.4.3. Hạn chế hiện thực

Frida chạy **user-mode** trong target — malware E4/E6 có thể né. Luận văn bổ sung Sysmon (mục 5.6) và khuyến nghị `spawn` mode; **không** có anti-Frida countermeasure.

---

## 5.5. Correlation engine (`services/analysis/domain/correlation.py`)

### 5.5.1. Cấu trúc trạng thái

Lớp `Correlator` duy trì:

| Trường | Kiểu | Mục đích |
|--------|------|----------|
| `files_by_path` | `dict[str, FileEvent]` | Provenance E3 |
| `processes_by_pid` | `dict[int, ProcessEvent]` | Lineage, CREATE_SUSPENDED |
| `primitives` | `deque[MemoryPrimitive]` | Expiration FIFO |
| `_chain_buckets` | `dict[(actor, target), list]` | Nhóm primitive theo chuỗi |
| `_reported_chain_scores` | `dict` | Chỉ báo cáo khi score tăng |
| `_network_watch_until` | `dict[pid, datetime]` | Hậu injection 300s |
| `_injection_graph` | `InjectionGraph` | Recursive chain |

Cửa sổ mặc định **300 giây** — đồ bộ với paper batch window và network watch.

### 5.5.2. State machine đánh giá chuỗi

```
                    add_primitive
                         │
                         ▼
              ┌─────────────────────┐
              │  enrich + bucket    │
              └──────────┬──────────┘
                         │
                         ▼
              ┌─────────────────────┐
     no ──────│ |K| ≥ 2 operational?│──────► (idle)
              └──────────┬──────────┘
                         │ yes
                         ▼
              ┌─────────────────────┐
     no ──────│  temporal OK?       │──────► discard
              └──────────┬──────────┘
                         │ yes
                         ▼
              ┌─────────────────────┐
     no ──────│  congruence OK?     │──────► discard
              └──────────┬──────────┘
                         │ yes
                         ▼
              ┌─────────────────────┐
     no ──────│  score ≥ min?       │──────► discard
              └──────────┬──────────┘
                         │ yes
                         ▼
              ┌─────────────────────┐
     no ──────│  score > previous?  │──────► discard (duplicate)
              └──────────┬──────────┘
                         │ yes
                         ▼
              apply_classification
              injection_graph.add_finding
              emit Finding
              [score≥70 → network_watch]
```

### 5.5.3. Execution analysis

Module `kernel/analysis/primitives.py` (`analyze_execution`) tách **execution transfer** (`ResumeThread`, `CreateRemoteThread`, …) khỏi **context read** (`GetThreadContext`). Finding có W+A nhưng không có transfer API → title *"Probable injection staging chain"*, `execution_confirmed = false`, score cap 75 nếu `missing_execution_transfer`.

### 5.5.4. Injection graph

`kernel/analysis/injection_graph.py` — `InjectionGraph.add_finding()` nối finding theo quan hệ actor(target trước) → target mới, set `is_recursive`, `chain_depth`. Chưa có metric prevalence 2% như [4] — chỉ hiển thị dashboard.

---

## 5.6. Sysmon, file watch, triage

### 5.6.1. `services/collector/infrastructure/sysmon.py`

- Channel: `Microsoft-Windows-Sysmon/Operational`.
- `SysmonPoller.poll_once()`: đọc event mới qua `win32evtlog` (Windows only).
- Parser XML → model: E1 ProcessCreate, E3 NetworkConnect, E11 FileCreate, E15 FileCreateStreamHash, E8/E10 → TelemetryEvent.

Config lab: `configs/sysmon-noirlycan.xml` — bật ImageLoad, ProcessAccess, CreateRemoteThread, FileCreate, NetworkConnect với filter phù hợp lab.

Graceful degradation: nếu Sysmon unavailable, CLI in hint cài đặt/quyền và tiếp tục Frida-only.

### 5.6.2. `services/collector/infrastructure/file_watch.py`

`FileDropWatcher` poll không đệ quy (recursive reserved):

- Bootstrap: snapshot mtime toàn file interesting trong watch paths.
- `drain()`: file mới hoặc modified → `FileEvent(creator_image="file-scanner")`.
- `is_interesting_path`: suffix `.exe`, `.dll`, `.ps1`, `.js`, …

Bổ sung Sysmon E11 khi process tạo file; watcher bắt drop ngoài event (copy thủ công, mount nhanh).

### 5.6.3. `services/collector/infrastructure/triage.py`

`FileTriage` dataclass + `triage_file()`:

- SHA256 streaming 1 MB chunks;
- Entropy Shannon;
- PE detection, optional `pefile` imports;
- Authenticode qua subprocess;
- Rule scoring: unsigned + temp path + high entropy → `suspicious_reasons`.

Kết quả merge vào `FileEvent` trước `add_file` — feeding scoring provenance (+10/+5/+10/+5).

---

## 5.7. Technique classifier (`kernel/classification/technique_classifier.py`)

### 5.7.1. Enum và pipeline

`InjectionTechnique` — 21+ giá trị từ `section_mapping_injection` tới `poolparty`, `mockingjay`, `process_ghosting`, …

`classify_finding()`:

1. Load `ClassifierRulesConfig` (gates, confidence override).
2. `evaluate_custom_rules` (phase `before_builtin`).
3. Chuỗi if-rule theo specificity giảm dần (instrumentation callback, ghosting, doppelgänging, …).
4. `_confidence_from_kinds`: HIGH nếu 3 primitive + execution confirmed.

`apply_classification()` gắn `finding.technique`, `technique_confidence`, `technique_rationale`.

### 5.7.2. Custom rules

Dashboard và `.classifier_rules.json` cho phép analyst thêm rule JSON — `kernel/classification/custom_rule_engine.py` parse điều kiện API/kind/evidence. Phục vụ lab mà không rebuild code.

---

## 5.8. Dashboard analyst (`services/dashboard/`)

### 5.8.1. Kiến trúc Django

- `server.py` / `run_dashboard`: khởi ASGI (HTTP + WebSocket).
- `views.py`: REST-like endpoints — sessions list, session detail, uploads, classifier config, collector start/stop.
- `consumers.py` + `live_hub.py`: WebSocket broadcast finding mới (`ws_broadcast`).
- `jet_dashboard.py`: tích hợp Django Jet (nếu bật) cho admin-style UI.

Static assets: `dashboard.js`, `dashboard.css`, `i18n.js` (Vi/En).

### 5.8.2. Tính năng chính

| Tab / chức năng | Mô tả |
|-----------------|-------|
| Overview | Số finding, severity, session metadata |
| Findings | Bảng finding, filter score/technique, drill-down primitive |
| Network | Kết nối Sysmon E3 trong network watch window |
| Primitives | Timeline API theo PID |
| Sessions | Chọn JSONL, export, reclassify |
| Uploads | Upload sample → queue → spawn Frida → báo cáo |
| Classifier rules | Sửa JSON rules live |
| Collector control | Start/stop `run` subprocess, heartbeat |

`AnalysisDatabase` (SQLite) lưu upload metadata, trạng thái queue, liên kết session report.

### 5.8.3. Live sync

Khi collector ghi finding mới, `live_sync` tail JSONL hoặc nhận signal → `broadcast_refresh` tới WebSocket clients — analyst không cần reload trang.

---

## 5.9. Mô hình dữ liệu (`kernel/entities/models.py`)

Các dataclass immutable (frozen):

- `MemoryPrimitive`: kind, actor/target PID+image, address, size, api, details dict.
- `FileEvent`, `ProcessEvent`, `NetworkConnectionEvent`.
- `Finding`: primitives tuple, score, evidence, technique fields, `related_file`, injection chain.

Enum `PrimitiveKind`: ALLOCATE, WRITE, EXECUTE, CONTEXT_READ.

JSON serialization qua `collector_runtime.jsonable()` — datetime ISO8601.

---

## 5.10. Tái lập thí nghiệm (reproducibility)

### 5.10.1. Artifact công bố

Theo Phụ lục C:

1. Clone repo NoirlycanThesis.
2. VM Windows 10/11, Python 3.11+, `uv sync` hoặc `pip install -e .`.
3. Cài Sysmon với `configs/sysmon-noirlycan.xml`.
4. Cài Frida (`pip install frida frida-tools`).
5. Chạy `noirlycan-telemetry run --watch-sysmon --auto-attach-new-processes`.
6. Dashboard: `noirlycan-telemetry dashboard`.

### 5.10.2. Microservices (Docker Compose)

`docker-compose.yml` khởi động `storage-api` (:8780), `analysis-api` (:8781), `dashboard-api` (:8765) với volume chung `./logs`. Collector (Frida/Sysmon) **vẫn chạy native trên Windows VM** — không container hóa vì phụ thuộc kernel hook và Frida attach.

```bash
docker compose up --build
# Dashboard: http://127.0.0.1:8765
```

Biến môi trường: `NOIRLYCAN_STORAGE_URL`, `NOIRLYCAN_ANALYSIS_URL` cho dashboard proxy tới storage/analysis khi tách service.

### 5.10.3. Test tự động

```bash
uv run pytest tests/test_correlation.py tests/test_ired_team_classifier.py
```

31 test xác nhận methodology + classifier (Chương 6). Toàn bộ suite `tests/` gồm thêm dashboard, sysmon parser, log_store (~80 test).

### 5.10.4. Deviation đã biết (audit)

| ID | Mô tả | Trạng thái repo |
|----|-------|-----------------|
| D1 | Execute address | Đã fix SetThreadContext Rip; ResumeThread vẫn thiếu |
| D2 | Read ∈ write | Đã tách `remote_read` |
| D3 | Temporal | Đã fix write-after-execute |
| D4 | Anti-evasion E5 | **Chưa** — `kernel/analysis/evasion.py` log only |
| D5 | Ghosting enum | Đã thêm, phụ thuộc hook precursor |

---

## 5.11. Hàng đợi phân tích và batch

Module: `services/collector/application/analysis_queue.py`, `services/analysis/domain/batch_runner.py`.

### 5.11.1. Analysis queue

Khi file drop được triage là PE executable, `enqueue_analysis(logs_dir, path)` thêm vào `analysis_queue.json` (atomic write qua `atomic_io.py`). Collector `drain_analysis_queue()`:

1. Pop pending entry.
2. `FridaInjectionMonitor` spawn process (`frida.spawn` + `resume`) thay vì attach muộn.
3. Ghi session riêng hoặc merge JSONL tùy cấu hình.

Cơ chế này giảm **miss primitive đầu** (E6) so với chỉ `--auto-attach` sau Sysmon E1.

### 5.11.2. Batch runner

`noirlycan-telemetry batch --manifest samples.jsonl`:

- Đọc danh sách đường dẫn mẫu + metadata expected technique.
- Với mỗi mẫu: spawn dưới Frida, timeout, thu JSONL.
- `write_batch_report()` tổng hợp finding count, max score, technique — phục vụ PoC-Bench tương lai.

## 5.12. Chi tiết hook Frida theo nhóm API

**Bảng 5.2.** Hook handler — trích `windows_injection_hooks.js`

| Nhóm API | Handler chính | Trường extract |
|----------|---------------|----------------|
| VirtualAlloc(Ex) | onEnter/onLeave | baseAddress, regionSize, flProtect |
| NtAllocateVirtualMemory | onLeave NT success | *BaseAddress, RegionSize |
| WriteProcessMemory | onEnter | lpBaseAddress, nSize |
| NtMapViewOfSection | onEnter | BaseAddress, ViewSize, InheritDisposition |
| CreateRemoteThread(Ex) | onEnter | lpStartAddress, lpParameter |
| NtCreateThreadEx | onEnter | StartRoutine, Argument |
| SetThreadContext | onEnter | lpContext → Rip | 
| GetThreadContext | onEnter | lpContext pointer → details |
| QueueUserAPC / NtQueueApcThread* | onEnter | ApcRoutine, ApcArgument |
| ResumeThread / NtResumeThread | onEnter | hThread → target PID resolve |
| LoadLibrary* / LdrLoadDll | onEnter | lpLibFileName |
| OpenProcess / NtOpenProcess | observation | access mask flags |
| NtCreateSection | onLeave | SectionHandle |
| Dynamic GetProcAddress | onLeave | attach lazy hook |

Mỗi handler gọi `emitObservation` cho API phụ trợ (OpenProcess) hoặc `emitPrimitive` cho operational kind. `hookedAddresses` Set tránh double-hook cùng địa chỉ export.

### 5.12.1. Resolve PID victim

Cross-process injection cần `target_pid` chính xác:

- Tham số `hProcess` / `ProcessHandle` → `GetProcessId`.
- Fallback: thread handle → `GetProcessIdOfThread`.
- Self: `Process.id` Frida khi handle pseudo current process.

Sai PID làm lệch bucket correlator — test `test_resolves_target_image_from_child_process` kiểm tra enrich từ ProcessEvent khi hook thiếu image.

## 5.13. Sysmon — ánh xạ Event ID

**Bảng 5.3.** Event ID dùng trong Noirlycan

| EID | Tên | Model output | Vai trò E3/E4 |
|-----|-----|--------------|---------------|
| 1 | ProcessCreate | ProcessEvent | Lineage, CREATE_SUSPENDED flags |
| 3 | NetworkConnect | NetworkConnectionEvent | Network watch post-finding |
| 7 | ImageLoad | TelemetryEvent | Module stomping context (raw) |
| 8 | CreateRemoteThread | TelemetryEvent | E4 fallback — thread create kernel |
| 10 | ProcessAccess | TelemetryEvent | E4 — OpenProcess cross-process |
| 11 | FileCreate | FileEvent | Provenance E3 |
| 15 | FileCreateStreamHash | FileEvent | Alternate data stream drop |

Parser `parse_sysmon_xml` tách namespace XML Sysmon chuẩn Microsoft. Unit test `test_sysmon_files.py` dùng fixture XML — không cần Windows khi CI.

## 5.14. Dashboard — endpoint và luồng upload

### 5.14.1. API chính (`views.py`)

| Route | Method | Chức năng |
|-------|--------|-----------|
| `/` | GET | SPA index.html |
| `/api/sessions` | GET | Liệt kê JSONL sessions |
| `/api/sessions/<id>` | GET | Chi tiết finding + primitive |
| `/api/uploads` | GET/POST | Quản lý upload sample |
| `/api/collector/start` | POST | Spawn `noirlycan-telemetry run` |
| `/api/collector/status` | GET | Heartbeat `.runtime.json` |
| `/api/classifier/rules` | GET/PUT | CRUD `.classifier_rules.json` |
| `/api/corpus` | GET | `analyze_corpus()` aggregate |
| `/ws/live` | WebSocket | Push refresh |

### 5.14.2. Luồng upload mẫu

```
Analyst upload EXE → SHA256 dedupe (AnalysisDatabase)
  → stored_path → enqueue_analysis
  → collector spawn Frida
  → JSONL findings
  → build_upload_report → dashboard "done — view report"
```

Upload không thực thi payload trên host analyst — chỉ trên VM lab có collector.

## 5.15. Lưu trữ và tái phân loại

- `log_store.py`: `new_session_log_path()`, `aggregate_logs()`, `session_detail()`.
- `reclassify.py`: đọc JSONL cũ, chạy lại `apply_classification` + scoring rules mới — hữu ích khi cập nhật classifier không cần re-run mẫu.
- `analysis_db.py`: SQLite `uploads`, `sessions` — dashboard query nhanh.

## 5.16. Cấu hình và phụ thuộc

| Thành phần | Phụ thuộc | Ghi chú |
|------------|-----------|---------|
| Core | Python 3.11+, stdlib | |
| Frida | `frida`, `frida-tools` | Windows lab |
| Sysmon | pywin32, Sysmon driver | Optional graceful degrade |
| Triage PE | `pefile` optional | Import API scan |
| Dashboard | Django 4+, channels | ASGI WebSocket |
| Test | pytest | 31+ methodology tests |

File `pyproject.toml` khai báo entry point `noirlycan-telemetry = noirlycan_telemetry.cli:main`.

## 5.17. Sequence: một vòng poll collector

```
CLI run loop:
  1. file_watcher.drain() → triage async → correlator.add_file
  2. process_sysmon_batch() → add_process / add_file / network
  3. drain_frida() → add_primitive → findings → jsonl
  4. drain_analysis_queue() → spawn pending samples
  5. touch_collector_heartbeat()
  6. sleep(poll_interval)
```

Đồng bộ single-threaded cho correlator; triage dùng `ThreadPoolExecutor` tránh block poll Sysmon.

## 5.19. Module phụ trợ

| Module | Vai trò |
|--------|---------|
| `process_resolve.py` | Windows API PID → image path khi Sysmon/Frida thiếu |
| `injection_graph.py` | Đồ thị finding nối actor→target, recursive chain |
| `payload_classifier.py` | Shellcode vs PE trong buffer (entropy, MZ header) |
| `kernel/analysis/evasion.py` | **Chỉ log** signal E5/E6 — không bypass |
| `sandbox_compare.py` | So sánh VT (optional) — ngoài core |
| `session_analytics.py` | Corpus stats trên nhiều JSONL |
| `classifier_config.py` | Load/save `.classifier_rules.json` |
| `custom_rule_engine.py` | DSL rule tùy chỉnh dashboard |
| `collector_launcher.py` | PID file, start/stop subprocess từ dashboard |

Các module này không thay đổi quy tắc 2-of-3; chúng enrich finding và vận hành lab.

## 5.20. Bảo mật và đạo đức triển khai

- Mẫu phân tích **chỉ** trong VM cô lập — không phát tán payload thật.
- Dashboard upload lưu local SQLite — không cloud mặc định.
- PoC loader (Phụ lục D) chỉ MessageBox — không weaponized exploit.
- JSONL có thể chứa path nhạy cảm — analyst tự bảo vệ log.

## 5.21. Tóm tắt chương

Chương 5 trình bày hiện thực Noirlycan: kiến trúc phân lớp từ hook Frida và Sysmon kernel tới correlator 2-of-3, scoring, classifier; CLI và collector runtime điều phối pipeline real-time; file watch và triage mở rộng provenance chống E3; dashboard Django hỗ trợ điều tra. Hệ thống **không** tích hợp anti-sandbox [4] (E5). Chương 6 đánh giá hiệu quả trên bộ test và case study section-mapping.
