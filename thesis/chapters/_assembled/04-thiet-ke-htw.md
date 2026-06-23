# CHƯƠNG 3. THIẾT KẾ VÀ HIỆN THỰC HỆ THỐNG NOIRLYCAN

Chương cụ thể hóa phương pháp Chương 2 thành artifact phần mềm — theo định hướng ứng dụng công nghệ trong hướng dẫn HTW: phân tích, thiết kế (Clean Architecture), cài đặt (Python, Frida, Sysmon, Django dashboard). Mục tiêu là tái tạo được (*reproducible*) trên VM Windows lab.

---

Chương này mô tả artifact **Noirlycan Telemetry** — prototype cho phòng lab Windows 10/11 cô lập, triển khai phương pháp ở Chương 4. Hệ thống tổ chức bốn miền: thu thập (collectors), xử lý (correlator, triage, classifier), lưu trữ (JSONL, SQLite), trình bày (dashboard Django). Tầng correlator bám sát [4]; module provenance và dashboard là đóng góp engineering. **Module anti-evasion (E5) của [4] không được hiện thực** — `kernel/analysis/evasion.py` chỉ ghi nhận tín hiệu sandbox, không patch timing; giới hạn tuyên bố ở 5.10.4.

---

## 3.1. Kiến trúc tổng thể

Codebase tổ chức theo **Clean Architecture**, triển khai dạng **monolith** (mặc định) hoặc **microservices** (Docker Compose). Tách miền nghiệp vụ khỏi framework cho phép thay tầng I/O mà không động vào quy tắc 2-of-3. **Lõi correlator 2-of-3 của [4] không đổi** — chỉ tách boundary module. Chi tiết refactor: `docs/clean-architecture-plan.md`.

### 3.1.1. Sơ đồ Clean Architecture

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

**Quy tắc phụ thuộc:** Presentation → Application → Domain ← Infrastructure. Layer `kernel/` không import Django, Frida, `win32evtlog`; I/O tiêm vào qua dataclass thuần Python. Nhờ vậy test unit của classifier và correlator chạy trên CI Linux mà không cần Windows hay Frida.

### 3.1.2. Bốn microservice và chế độ triển khai

**Bảng 3.1.** Service boundary

| Service | Vai trò | Port | Entry point |
|---------|---------|------|-------------|
| **collector** | Sysmon + Frida + file-drop trên Windows VM | 8782 (health) | `noirlycan-telemetry run` |
| **storage** | Ghi/đọc JSONL, SQLite uploads | 8780 | `noirlycan-storage` |
| **analysis** | Correlator, reclassify, corpus | 8781 | `noirlycan-analysis` |
| **dashboard** | UI analyst | 8765 | `noirlycan-telemetry dashboard` |

Bốn service là bốn ranh giới logic, không bắt buộc bốn process. Monolith dùng một process Python; microservices đóng gói từng service thành image Docker, giao tiếp qua HTTP/JSONL trên volume chung.

| Mode | Mô tả | Khi dùng |
|------|-------|----------|
| **Monolith** | `run` + `dashboard` in-process, ghi trực tiếp `logs/` | Dev lab, demo luận văn |
| **Microservices** | `docker compose up` — storage + analysis + dashboard; collector native trên VM | Tách scale, kiểm soát từng service |

Wire format giữa các service là `contracts/events.py` (`TelemetryEnvelope`) — dataclass JSON-serializable tương thích JSONL session.

### 3.1.3. Luồng runtime monolith (`noirlycan-telemetry run`)

1. `cli.py` là composition root, khởi tạo `Correlator`, `JsonlWriter`, `SysmonPoller`, `FridaInjectionMonitor`, `FileDropWatcher`.
2. Vòng lặp: Sysmon batch → correlator; file watcher → triage → correlator; drain queue Frida xử lý primitive bộ nhớ.
3. Mỗi `Finding` ghi vào `logs/session-*.jsonl`; dashboard tail cùng volume.

### 3.1.4. Module map

**Bảng 3.2.** Ánh xạ module — trách nhiệm

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

Package tập trung tại `src/noirlycan_telemetry/`, cài qua `pip install -e .[dev]`.

---

## 3.2. Giao diện dòng lệnh (`cli.py`)

### 3.2.1. Subcommand

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

Tách `spawn` riêng vì nhiều mẫu inject ngay trong `DllMain`, attach sau Sysmon E1 là quá muộn.

### 3.2.2. `command_run` — orchestration

Tham số chính: `--watch-sysmon`, `--watch-path`, `--attach-pid`/`--auto-attach-new-processes`, `--minimum-score` (mặc định 50), `--jsonl`.

Luồng file mới: `FileDropWatcher.drain()` → `FileEvent` → `_TRIAGE_EXECUTOR` chạy `triage_file` (SHA256, layout PE, entropy, chữ ký) → `correlator.add_file`. Nếu là PE, `enqueue_analysis` đẩy vào hàng đợi spawn Frida.

Heartbeat ghi `logs/.runtime.json` (PID, last-tick) để dashboard biết trạng thái online.

### 3.2.3. Tích hợp classifier config

`ensure_classifier_config()` tạo `.classifier_rules.json` nếu chưa có. Khi file thay đổi, `Correlator.reload_rules_config()` hot-reload — FP tuning chỉ là chỉnh JSON.

---

## 3.3. Vòng lặp collector (`collector_runtime.py`)

### 3.3.1. JsonlWriter

`JsonlWriter` ghi mỗi sự kiện dạng `{"type": event_type, "value": ...}`, `type` ∈ {`file`, `sysmon`, `primitive`, `finding`, `network`, `frida_raw`, `evasion`}. Flush mỗi 32 dòng. Dashboard tail và `reclassify` dùng chung format.

### 3.3.2. Xử lý Sysmon batch

`process_sysmon_batch()` điều phối: `FileEvent` → `correlator.add_file`; `ProcessEvent` → `correlator.add_process`, nếu `auto_attach` và `should_auto_attach()` true thì gọi `safe_attach`; `NetworkConnectionEvent` → `handle_network_event` chỉ lưu khi PID trong network watch window; `TelemetryEvent` (E8/E10 raw) ghi xuống JSONL.

`should_auto_attach` áp dụng heuristic: bỏ qua binary trong `system32` không có parent lạ, chấp nhận `.exe/.dll/.scr/.com` từ thư mục bị triage nghi vấn.

### 3.3.3. Drain Frida

`drain_frida()` xử lý queue non-blocking: tín hiệu `evasion` chỉ in cảnh báo, **không** correlate; `frida_process` → `add_process`; `memory_primitive` → `add_primitive` chạy 2-of-3.

`print_finding()` xuất severity, kỹ thuật, `execution_confirmed`, chuỗi đệ quy và network watch.

---

## 3.4. Lớp Frida (`frida_manager.py` + hooks)

### 3.4.1. FridaInjectionMonitor

`FridaInjectionMonitor` quản lý vòng đời session: `load_default_hook_script()` đọc `windows_injection_hooks.js` qua `importlib.resources`; `attach(pid)` gọi `frida.attach` → `create_script` → `script.load`, mỗi PID một session riêng để tránh leak handler; `_on_message` parse payload và đẩy `FridaRuntimeEvent` vào `queue.Queue`.

Bộ chuyển đổi: `runtime_event_to_primitive()` map `allocate|write|execute|context_read` sang `MemoryPrimitive`; `runtime_event_to_process()` xử lý spawn notification; quan sát observation-only (`remote_read`, gợi ý TXF) phát ra dạng `api_observation` không tham gia 2-of-3.

### 3.4.2. Thiết kế hook JavaScript

`windows_injection_hooks.js` (~1900 dòng) gồm bốn tầng:

1. **Helper:** `ptrToNumber`, `ntSuccess`, `readAnsiString`, `protectionToString` chuẩn hoá địa chỉ, NTSTATUS, bit-flag `PAGE_*`.
2. **Dynamic resolve:** hook `GetProcAddress`/`LdrGetProcedureAddress`; khi target rơi vào `DYNAMIC_INJECTION_APIS`, một lazy hook được attach tại địa chỉ vừa resolve để bắt binding muộn.
3. **Per-API handler:** trích args/retval lấy `baseAddress`, `NumberOfBytes`, `lpStartAddress`, `CONTEXT.Rip`.
4. **Emit:** `send({type: "memory_primitive", kind, api, actor_pid, target_pid, address, size, details})`.

**Fix D1:** `readInstructionPointerFromContext` áp dụng cho `SetThreadContext` và `NtSetContextThread` để gán `address = Rip`, sửa sai sót nêu trong audit Chương 4.

**Alias Zw\*:** manifest và hook dùng tên canonical Nt-prefix; stub Zw chuyển tiếp tới Nt để tránh đếm trùng primitive.

Coverage test `test_hook_manifest_coverage.py` và `test_api_coverage.py` đối chiếu manifest với hook JS, phát hiện sớm API bị bỏ quên.

### 3.4.3. Hạn chế hiện thực

Frida vận hành **user-mode** trong target process, nên E4/E6 dạng direct/indirect syscall có thể né hoàn toàn. Luận văn bù bằng kênh Sysmon kernel (5.6) và khuyến nghị `spawn` mode. Không có anti-Frida countermeasure — mẫu chủ động dò Frida có thể terminate; trade-off chấp nhận.

---

## 3.5. Correlation engine (`correlation.py`)

### 3.5.1. Cấu trúc trạng thái

| Trường | Kiểu | Mục đích |
|--------|------|----------|
| `files_by_path` | `dict[str, FileEvent]` | Provenance E3 |
| `processes_by_pid` | `dict[int, ProcessEvent]` | Lineage, CREATE_SUSPENDED |
| `primitives` | `deque[MemoryPrimitive]` | Expiration FIFO |
| `_chain_buckets` | `dict[(actor, target), list]` | Nhóm primitive theo chuỗi |
| `_reported_chain_scores` | `dict` | Chỉ báo cáo khi score tăng |
| `_network_watch_until` | `dict[pid, datetime]` | Hậu injection 300s |
| `_injection_graph` | `InjectionGraph` | Recursive chain |

Cửa sổ trượt mặc định **300 giây** đồng bộ với batch window [4] và độ dài network watch — một hằng số thời gian thống nhất cho toàn pipeline.

### 3.5.2. State machine đánh giá chuỗi

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

Vượt 2-of-3 chưa đủ phát finding: còn cần ràng buộc thời gian, đồng quy địa chỉ, ngưỡng điểm, `score > previous` để tránh phát lặp.

### 3.5.3. Execution analysis

`analyze_execution` (trong `primitives.py`) tách **execution transfer** (`ResumeThread`, `CreateRemoteThread`, `NtQueueApcThread`…) khỏi **context read** (`GetThreadContext`). `GetThreadContext` chỉ đọc state. Khi finding có W+A nhưng thiếu API transfer: title *"Probable injection staging chain"*, `execution_confirmed = false`, score giới hạn 75 qua nhãn `missing_execution_transfer`.

### 3.5.4. Injection graph

`injection_graph.py` cài `InjectionGraph`: `add_finding()` nối actor→target, cờ `is_recursive` khi A→B→C, tăng `chain_depth`. Chưa tính metric prevalence 2% như [4] do corpus chưa đủ; đồ thị phục vụ trực quan hoá.

---

## 3.6. Sysmon, file watch, triage

### 3.6.1. `sysmon.py`

Bộ poll đọc channel `Microsoft-Windows-Sysmon/Operational` qua `win32evtlog`. Parser XML chuyển E1, E3, E11, E15 sang model nghiệp vụ; E8/E10 giữ dạng `TelemetryEvent` raw. Lab dùng `configs/sysmon-noirlycan.xml`. Khi Sysmon không khả dụng, CLI chạy Frida-only.

### 3.6.2. `file_watch.py`

`FileDropWatcher` poll không đệ quy: bootstrap snapshot mtime; `drain()` so sánh để phát `FileEvent(creator_image="file-scanner")`; `is_interesting_path` lọc suffix `.exe`, `.dll`, `.ps1`, `.js`…

Bổ sung cho Sysmon E11 ở các kịch bản không có tiến trình Windows nào ghi file (copy qua RDP clipboard, mount ổ ảo).

### 3.6.3. `triage.py`

`FileTriage` dataclass và `triage_file()` thực hiện:

- Hash SHA256 streaming 1 MB/chunk.
- Entropy Shannon toàn file (chỉ báo packing).
- Phát hiện PE qua magic `MZ`/`PE`; nếu có `pefile` thì liệt kê import.
- Xác minh Authenticode qua `signtool`/`Get-AuthenticodeSignature`.
- Rule heuristic: unsigned + `%TEMP%` + entropy cao → `suspicious_reasons`.

Kết quả merge vào `FileEvent` trước `add_file`, đóng góp vào scoring provenance với trọng số +10/+5/+10/+5.

---

## 3.7. Technique classifier (`technique_classifier.py`)

### 3.7.1. Enum và pipeline

`InjectionTechnique` định nghĩa hơn 21 giá trị, từ `section_mapping_injection` tới `poolparty`, `mockingjay`, `process_ghosting`. Enum tập trung giúp dashboard và export Word/PDF dùng chung danh mục.

`classify_finding()` bốn bước: nạp `ClassifierRulesConfig`; gọi `evaluate_custom_rules` ở phase `before_builtin`; chuỗi if-rule theo specificity giảm dần (instrumentation callback, ghosting, doppelgänging trước classic DLL injection); `_confidence_from_kinds` gán HIGH khi đủ ba primitive operational và `execution_confirmed = true`, MEDIUM/LOW các trường hợp khác.

`apply_classification()` gắn `technique`, `technique_confidence`, `technique_rationale` lên `Finding`.

### 3.7.2. Custom rules

Dashboard và `.classifier_rules.json` cho phép thêm rule JSON; `custom_rule_engine.py` parse điều kiện API, kind, evidence với AND/OR phẳng — hữu ích khi gắn nhãn nhanh cho biến thể mới chưa vào codebase chính.

---

## 3.8. Dashboard analyst (`services/dashboard/`)

### 3.8.1. Kiến trúc Django

Django + Channels: `server.py`/`run_dashboard` khởi ASGI; `views.py` cung cấp endpoint REST cho sessions, uploads, classifier config, collector start/stop; `consumers.py` + `live_hub.py` quản WebSocket, `ws_broadcast` đẩy finding tới client; `jet_dashboard.py` tích hợp Django Jet (tuỳ chọn).

Static: `dashboard.js`, `dashboard.css`, `i18n.js` (Vi/En) — đa ngôn ngữ ở client.

### 3.8.2. Tính năng chính

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

`AnalysisDatabase` (SQLite) lưu metadata upload và liên kết session report; SQLite được chọn để giữ artifact dạng file đơn, thuận lợi đóng gói VM lab.

### 3.8.3. Live sync

Khi collector ghi finding, `live_sync` tail JSONL hoặc nhận signal và gọi `broadcast_refresh` tới WebSocket. Độ trễ chỉ phụ thuộc flush JSONL (32 dòng) cộng chi phí WebSocket.

---

## 3.9. Mô hình dữ liệu (`models.py`)

Các dataclass nghiệp vụ đều `frozen=True` để thread-safe:

- `MemoryPrimitive`: `kind`, PID/image actor & target, địa chỉ, kích thước, API, dict `details`.
- `FileEvent`, `ProcessEvent`, `NetworkConnectionEvent` cho ba kênh thu thập.
- `Finding`: tuple primitive, score, evidence, trường technique, liên kết file gốc, chuỗi injection.

`PrimitiveKind` ∈ {`ALLOCATE`, `WRITE`, `EXECUTE`, `CONTEXT_READ`}. Serialize qua `collector_runtime.jsonable()`, chuẩn hoá datetime ISO8601, đệ quy dataclass lồng.

---

## 3.10. Tái lập thí nghiệm

### 3.10.1. Artifact công bố

Theo Phụ lục C, sáu bước: (1) Clone repo; (2) VM Windows 10/11, Python 3.11+, `uv sync` hoặc `pip install -e .`; (3) Cài Sysmon kèm `configs/sysmon-noirlycan.xml`; (4) `pip install frida frida-tools`; (5) `noirlycan-telemetry run --watch-sysmon --auto-attach-new-processes`; (6) `noirlycan-telemetry dashboard` ở terminal thứ hai.

### 3.10.2. Microservices (Docker Compose)

`docker-compose.yml` khởi ba container `storage-api` (:8780), `analysis-api` (:8781), `dashboard-api` (:8765) chia sẻ volume `./logs`. Collector **vẫn chạy native trên Windows VM** vì phụ thuộc kernel hook và Frida runtime.

```bash
docker compose up --build
# Dashboard: http://127.0.0.1:8765
```

`NOIRLYCAN_STORAGE_URL` và `NOIRLYCAN_ANALYSIS_URL` cho phép dashboard proxy sang storage/analysis ở host khác.

### 3.10.3. Test tự động

```bash
uv run pytest tests/test_correlation.py tests/test_ired_team_classifier.py
```

31 test xác nhận methodology và classifier. Suite `tests/` mở rộng tới ~80 test gồm dashboard view, parser Sysmon, log_store.

### 3.10.4. Deviation đã biết (audit)

| ID | Mô tả | Trạng thái repo |
|----|-------|-----------------|
| D1 | Execute address | Đã fix SetThreadContext Rip; ResumeThread vẫn thiếu |
| D2 | Read ∈ write | Đã tách `remote_read` |
| D3 | Temporal | Đã fix write-after-execute |
| D4 | Anti-evasion E5 | **Chưa** — `evasion.py` log only |
| D5 | Ghosting enum | Đã thêm, phụ thuộc hook precursor |

---

## 3.11. Hàng đợi phân tích và batch

### 3.11.1. Analysis queue

Khi file drop được triage là PE, `enqueue_analysis(logs_dir, path)` thêm entry vào `analysis_queue.json` bằng atomic write của `atomic_io.py`. `drain_analysis_queue()`: pop entry pending; `FridaInjectionMonitor` `spawn` + `resume` thay vì attach muộn; ghi session riêng hoặc merge JSONL.

Cơ chế spawn-from-entry giảm **miss primitive đầu** (E6) — điểm yếu cố hữu khi chỉ dùng `--auto-attach` sau Sysmon E1.

### 3.11.2. Batch runner

`noirlycan-telemetry batch --manifest samples.jsonl`: đọc danh sách mẫu + expected technique; mỗi mẫu spawn Frida với timeout, thu JSONL riêng; `write_batch_report()` tổng hợp finding count, max score, technique — phục vụ PoC-Bench tương lai.

## 3.12. Chi tiết hook Frida theo nhóm API

**Bảng 3.3.** Hook handler — trích `windows_injection_hooks.js`

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

Mỗi handler gọi `emitObservation` cho API phụ trợ hoặc `emitPrimitive` cho operational kind. Set `hookedAddresses` tránh double-hook khi cùng symbol resolve nhiều lần.

### 3.12.1. Resolve PID victim

Sai `target_pid` làm primitive rơi vào bucket sai và phá vỡ 2-of-3. Hook áp dụng fallback: có `hProcess`/`ProcessHandle` → `GetProcessId`; chỉ có thread handle → `GetProcessIdOfThread`; self-injection → `Process.id` của Frida (pseudo-handle).

Test `test_resolves_target_image_from_child_process` kiểm chứng enrich image từ `ProcessEvent` khi hook thiếu module path.

## 3.13. Sysmon — ánh xạ Event ID

**Bảng 3.4.** Event ID dùng trong Noirlycan

| EID | Tên | Model output | Vai trò E3/E4 |
|-----|-----|--------------|---------------|
| 1 | ProcessCreate | ProcessEvent | Lineage, CREATE_SUSPENDED flags |
| 3 | NetworkConnect | NetworkConnectionEvent | Network watch post-finding |
| 7 | ImageLoad | TelemetryEvent | Module stomping context (raw) |
| 8 | CreateRemoteThread | TelemetryEvent | E4 fallback — thread create kernel |
| 10 | ProcessAccess | TelemetryEvent | E4 — OpenProcess cross-process |
| 11 | FileCreate | FileEvent | Provenance E3 |
| 15 | FileCreateStreamHash | FileEvent | Alternate data stream drop |

`parse_sysmon_xml` xử lý namespace XML Sysmon, tách `Data Name="..."` thành dict. Test `test_sysmon_files.py` dùng fixture XML nên chạy được trên CI Linux.

## 3.14. Dashboard — endpoint và luồng upload

### 3.14.1. API chính (`views.py`)

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

### 3.14.2. Luồng upload mẫu

```
Analyst upload EXE → SHA256 dedupe (AnalysisDatabase)
  → stored_path → enqueue_analysis
  → collector spawn Frida
  → JSONL findings
  → build_upload_report → dashboard "done — view report"
```

Dashboard chỉ lưu trữ payload; thực thi diễn ra trên VM lab cô lập. Host analyst không bao giờ chạy mẫu.

## 3.15. Lưu trữ và tái phân loại

`log_store.py` cung cấp `new_session_log_path()`, `aggregate_logs()`, `session_detail()` chuẩn hoá I/O JSONL theo phiên. `reclassify.py` mở session cũ, chạy lại `apply_classification` với scoring đã cập nhật — hữu ích khi tinh chỉnh classifier mà không cần chạy lại mẫu. `analysis_db.py` quản SQLite gồm `uploads` và `sessions`.

## 3.16. Cấu hình và phụ thuộc

| Thành phần | Phụ thuộc | Ghi chú |
|------------|-----------|---------|
| Core | Python 3.11+, stdlib | |
| Frida | `frida`, `frida-tools` | Windows lab |
| Sysmon | pywin32, Sysmon driver | Optional graceful degrade |
| Triage PE | `pefile` optional | Import API scan |
| Dashboard | Django 4+, channels | ASGI WebSocket |
| Test | pytest | 31+ methodology tests |

`pyproject.toml` khai báo entry point `noirlycan-telemetry = noirlycan_telemetry.cli:main`.

## 3.17. Sequence: một vòng poll collector

```
CLI run loop:
  1. file_watcher.drain() → triage async → correlator.add_file
  2. process_sysmon_batch() → add_process / add_file / network
  3. drain_frida() → add_primitive → findings → jsonl
  4. drain_analysis_queue() → spawn pending samples
  5. touch_collector_heartbeat()
  6. sleep(poll_interval)
```

Correlator single-threaded để loại race condition trên bucket; triage tách `ThreadPoolExecutor` riêng tránh block poll Sysmon trong I/O nặng (hash, Authenticode).

## 3.19. Module phụ trợ

| Module | Vai trò |
|--------|---------|
| `process_resolve.py` | Windows API PID → image path khi Sysmon/Frida thiếu |
| `injection_graph.py` | Đồ thị finding actor→target, recursive chain |
| `payload_classifier.py` | Shellcode vs PE trong buffer (entropy, MZ header) |
| `kernel/analysis/evasion.py` | **Chỉ log** signal E5/E6 — không bypass |
| `sandbox_compare.py` | So sánh VT (optional) — ngoài core |
| `session_analytics.py` | Corpus stats trên nhiều JSONL |
| `classifier_config.py` | Load/save `.classifier_rules.json` |
| `custom_rule_engine.py` | DSL rule tùy chỉnh dashboard |
| `collector_launcher.py` | PID file, start/stop subprocess từ dashboard |

Các module phụ trợ không can thiệp 2-of-3; chỉ làm giàu finding và điều phối vận hành lab.

## 3.20. Bảo mật và đạo đức triển khai

- Mẫu **chỉ** thực thi trong VM cô lập, không có route mạng tới hạ tầng SSI.
- Dashboard upload lưu SQLite local, không sync cloud mặc định.
- PoC loader (Phụ lục D) chỉ gọi `MessageBox`, không weaponized.
- JSONL có thể chứa đường dẫn nhạy cảm; analyst tự redact khi chia sẻ.

## 3.21. Tóm tắt chương

Chương 3 đã trình bày hiện thực Noirlycan: hook Frida user-mode và kênh Sysmon kernel ở tầng thu thập; correlator 2-of-3 cùng scoring và classifier ở tầng phân tích; CLI và collector runtime điều phối pipeline thời gian thực. File watch và triage mở rộng chiều provenance cho các kịch bản E3 mà Sysmon bỏ sót; dashboard Django phục vụ điều tra trực quan. Giới hạn được tuyên bố: **không** tích hợp anti-sandbox theo nghĩa [4] (E5), chỉ ghi nhận tín hiệu. Chương 6 chuyển sang đánh giá định lượng và case study section-mapping.