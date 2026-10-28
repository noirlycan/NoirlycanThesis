# CHƯƠNG 5. THIẾT KẾ VÀ HIỆN THỰC HỆ THỐNG NOIRLYCAN

Chương này mô tả artifact **Noirlycan** — prototype cho phòng lab Windows 10/11 cô lập, triển khai phương pháp ở Chương 4. Thiết kế đi theo đúng hai module của [7] (Figure 1, §3.3): **monitoring module** thu trace API trên máy chạy mẫu và **analysis module** phát hiện rồi phân loại injection. [7] hiện thực monitoring module bằng BluePill trên Intel Pin và khẳng định phương pháp *"can be integrated into any dynamic analysis system that intercepts API calls"*; Noirlycan thay monitoring module bằng hai sensor (Frida user-mode, Sysmon kernel-mode) và **giữ nguyên** analysis module. Module provenance, console và kênh agent là đóng góp engineering. **Anti-evasion (E5) của [7] không được hiện thực** — `extensions/evasion.py` chỉ ghi nhận tín hiệu; giới hạn tuyên bố ở 5.10.4.

---

## 5.1. Kiến trúc tổng thể

### 5.1.1. Ba đơn vị triển khai

```
┌──────────────── Windows lab VM ────────────────┐        ┌──────── Máy analyst ────────┐
│ noirlycan-agent  (MONITORING MODULE)           │  HTTP  │ noirlycan-backend (FastAPI) │
│  sensors/  Frida · Sysmon · file watch · mạng  │ ─────► │  ingest · samples · rules   │
│  runtime/  pipeline → Correlator (lõi [7])     │ ◄───── │  findings · auth/RBAC       │
│            sink JSONL + upload batch           │  lệnh  │  SQLite + JSONL theo agent  │
│            lệnh đã ký Ed25519                  │  ký số │                             │
└────────────────────────────────────────────────┘        │ dashboard-ui (React)        │
                                                          └─────────────────────────────┘
          noirlycan_core (ANALYSIS MODULE, thuần Python, dùng chung cả hai phía)
```

Agent chạy bản `Correlator` ngay trên VM để báo finding thời gian thực; backend dùng cùng lõi để replay (`reclassify`) và thống kê corpus. Lõi `noirlycan_core` không import Frida, `win32evtlog`, FastAPI hay bất kỳ thứ gì của agent — nên toàn bộ test của detector và classifier chạy trên CI macOS/Linux.

Backend là *modular monolith*, không tách microservice: lab chỉ có vài VM, tách service chỉ thêm chi phí vận hành mà không phục vụ câu hỏi nghiên cứu (lập luận chi tiết ở `docs/proposal-platform-architecture.md`).

### 5.1.2. Ánh xạ paper → module

**Bảng 5.1.** Thành phần của [7] và vị trí trong repo

| Khái niệm [7] | Module | Ghi chú |
|---------------|--------|---------|
| Monitoring module (BluePill/Pin) | `noirlycan_agent/sensors/` | Frida + Sysmon thay cho DBI |
| Trace format | `noirlycan_core/trace/frida.py`, `trace/sysmon.py` | Message sensor → `MemoryPrimitive` |
| Ba primitive (§3.1) | `noirlycan_core/models.py` `PrimitiveKind` | + `CONTEXT_READ` (không tính 2/3) |
| Lớp tương đương API (§3.1, App. B) | `detection/api_classes.py` `PAPER_API_CLASSES` | 67 API của paper |
| 2/3 · congruence · temporal (§3.2) | `detection/rules.py` | Hàm thuần, docstring trích mục paper |
| Gom chuỗi (actor, victim) | `detection/correlator.py` | Cửa sổ trượt 300 s |
| Chuỗi đệ quy (§3.1) | `detection/injection_graph.py` | `is_recursive`, `chain_depth` |
| Phân loại kỹ thuật | `noirlycan_core/classification/` | 36 kỹ thuật |
| *[mở rộng]* điểm, provenance, network watch | `detection/scoring.py`, `provenance.py`, `network_watch.py` | Không đổi quyết định của rules |
| *[mở rộng]* bằng chứng kernel | `extensions/kernel_evidence.py` | Call stack, đối chiếu sensor |

Quy ước bất biến: phần **[mở rộng]** chỉ thêm điểm và evidence cho chuỗi **đã qua** quy tắc của paper, không bao giờ biến một chuỗi bị loại thành finding.

### 5.1.3. Cấu trúc thư mục

```
src/
  noirlycan_core/        models · trace/ · detection/ · classification/ · extensions/
                         analysis/ (replay, corpus) · storage/ (JSONL, SQLite) · runtime/
  noirlycan_agent/       cli.py · sensors/ · runtime/ · lab/ (batch, so sánh AV) · frida_hooks/
  noirlycan_backend/     api/routes/ · domain/ · infrastructure/console_db.py
  noirlycan_dashboard/   server tĩnh cho dashboard-ui/dist
dashboard-ui/            React + Vite
```

---

## 5.2. Agent: giao diện dòng lệnh và vòng lặp

### 5.2.1. Subcommand

| Lệnh | Mục đích |
|------|----------|
| `noirlycan-agent run` | Vòng lặp collector (Sysmon + file watch + Frida), tùy chọn nối console |
| `noirlycan-agent spawn -- <cmd>` | Spawn mẫu dưới Frida từ lệnh đầu tiên (không lỡ primitive trong `DllMain`) |
| `noirlycan-agent triage <file>` | Triage tĩnh một file |
| `noirlycan-agent batch` / `compare` | Chạy cả thư mục mẫu; so sánh với Defender/VirusTotal |
| `noirlycan-backend corpus` / `reclassify` | Thống kê corpus; replay session qua detector hiện tại |

Tách `spawn` riêng vì nhiều mẫu inject ngay trong `DllMain`; attach sau Sysmon EID 1 là quá muộn.

### 5.2.2. Vòng lặp collector (`runtime/collector.py`)

Mỗi tick:

1. `read_tick()` đọc policy (console/`.agent_policy.json`) và runtime config **một lần**, đóng gói thành `Tick` (bật file watch, auto API analysis, auto attach, thư mục theo dõi).
2. `apply()` đẩy policy vào `Correlator` và script Frida (hot reload khi version đổi).
3. File watcher → `FileIntake.on_file`; hàng đợi phân tích → `SampleRunner.process_queue`.
4. `poll_sensors()`: Sysmon batch, drain Frida, TCP/WFP cho PID đang được network watch; nhận và dispatch lệnh console.
5. Heartbeat; ngủ `poll_interval` (0,2 s khi đang network watch).

Correlator đơn luồng để không có race trên bucket; triage tĩnh chạy trong `ThreadPoolExecutor` riêng (hash, Authenticode chậm) và ghi qua `JsonlWriter` có khóa.

### 5.2.3. Ghi sự kiện (`runtime/event_sink.py`)

`JsonlWriter` ghi mỗi sự kiện `{"type", "value"}` vào `logs/session-*.jsonl` — định dạng chung cho dashboard, `reclassify` và import. Khi nối console, `MirroredWriter` ghi cục bộ trước rồi đẩy sự kiện vào `BatchUploader`: một thread nền gom tối đa 200 sự kiện hoặc 0,5 s rồi `POST /api/ingest/batch`. Vòng lặp thu thập không bao giờ chờ mạng; console mất kết nối thì log cục bộ vẫn đầy đủ.

---

## 5.3. Pipeline sensor → detector (`runtime/pipeline.py`)

`process_sysmon_batch()` điều phối Sysmon: `FileEvent` → `FileIntake`; `ProcessEvent` → `add_process` (và auto-attach Frida khi bật); `NetworkConnectionEvent` chỉ giữ khi PID đang network watch; EID 8 → `primitive_from_remote_thread` → `feed_primitive`; EID 10 → `access_from_process_access` → `add_process_access`.

`drain_frida()` xử lý queue Frida không chặn: `process_create` → gợi ý lineage; tín hiệu evasion chỉ in cảnh báo; `memory_primitive`/`api_observation` → `feed_primitive`.

`feed_primitive()` là điểm vào chung cho mọi sensor: ghi primitive, gọi `Correlator.add_primitive`, ghi và in finding.

---

## 5.4. Sensor Frida (`sensors/frida_monitor.py` + `frida_hooks/`)

### 5.4.1. FridaInjectionMonitor

Mỗi PID một session Frida riêng (`frida.attach` → `create_script` → `load`) để tránh leak handler. Script ghép từ `runtime.js` (helper, resolve PID, emit) và `handlers.js` (handler theo API) — tổng khoảng 2.270 dòng — kèm cấu hình hook sinh từ policy (`frida_hook_catalog.build_runtime_config`). Khi bật auto-attach, child gating gắn hook vào tiến trình con trước khi resume. `_on_message` đẩy `FridaRuntimeEvent` vào queue; `trace/frida.py` chuyển thành `MemoryPrimitive(source="frida")`.

### 5.4.2. Thiết kế hook JavaScript

1. **Helper:** chuẩn hoá con trỏ, NTSTATUS, cờ `PAGE_*`.
2. **Dynamic resolve:** hook `GetProcAddress`/`LdrGetProcedureAddress`; khi tên rơi vào tập API injection, gắn hook lười tại địa chỉ vừa resolve để bắt binding muộn. Tập `hookedAddresses` tránh hook trùng.
3. **Handler theo API:** trích `BaseAddress`, `RegionSize`, `lpStartAddress`, `lpParameter` (→ `thread_parameter`), con trỏ `CONTEXT` (→ `context_pointer`, `Rip`).
4. **Emit:** `send({type: "memory_primitive" | "api_observation", …})`.

**Fix D1:** `readInstructionPointerFromContext` gán `address = Rip` cho `SetThreadContext`/`NtSetContextThread`, giữ được memory congruence cho thread hijack. Stub `Zw*` được chuẩn hoá về tên `Nt*` để không đếm trùng primitive. `test_hook_manifest_coverage.py` và `test_api_coverage.py` đối chiếu manifest với hook.

### 5.4.3. Hạn chế

Frida đặt điểm quan sát trong tiến trình được gắn công cụ, nên độ đầy đủ của trace phụ thuộc vào vị trí hook và việc mẫu có tiếp tục thực thi như bình thường hay không. Một lời gọi hệ thống trực tiếp hoặc việc thay đổi mã ở `ntdll` có thể bỏ qua những điểm hook đang dùng. Sysmon cung cấp thêm loại sự kiện ở mức hệ điều hành, song không khôi phục được toàn bộ đối số API còn thiếu. Hướng bổ sung nguồn telemetry khác, chẳng hạn ETW Threat Intelligence, mới là đề xuất thiết kế và chưa được đánh giá trong hiện thực này.

---

## 5.5. Analysis module: detector (`noirlycan_core/detection/`)

### 5.5.1. Ba quy tắc của paper (`rules.py`)

| Hàm | Quy tắc [7] §3.2 | Hiện thực |
|-----|------------------|-----------|
| `has_minimal_core_operations` | ≥2 trong 3 primitive khác loại | Đếm ALLOCATE/WRITE/EXECUTE; CONTEXT_READ không tính |
| `has_temporal_consistency` | allocate → write → execute | Loại ALLOCATE/WRITE xuất hiện sau bước muộn hơn; **đổi quyền vùng nhớ** (`VirtualProtect(Ex)`, `NtProtectVirtualMemory`) được miễn |
| `has_memory_congruence` | Các bước thao tác trên vùng nhớ đồng quy | Hai primitive khác loại có khoảng địa chỉ giao nhau; `thread_parameter`/`context_pointer` cũng là liên kết |

Miễn trừ đổi quyền là bản sửa phát hiện khi viết test cho từng quy tắc: chuỗi shellcode kinh điển `VirtualAllocEx(RW) → WriteProcessMemory → VirtualProtectEx(RX) → CreateRemoteThread` trước đó chỉ dừng ở finding "staging" vì bước RW→RX bị coi là đảo thứ tự. Đổi quyền một vùng đã cấp phát không tạo buffer mới nên không thuộc ràng buộc *allocate trước write*.

### 5.5.2. Correlator (`correlator.py`)

```
add_primitive ─► provenance.enrich ─► bucket (actor, victim) trong cửa sổ 300 s
     │
     ▼
 rules: 2/3 ─► temporal ─► congruence ─► (trượt → bỏ)
     │
     ▼
 scope gate (tùy chọn: bỏ self-inject / chỉ cross-process)
     │
     ▼
 score_chain + kernel_evidence ─► score ≥ ngưỡng?
     │
     ▼
 chuỗi có tiến triển so với lần báo trước?  (điểm tăng HOẶC thêm loại primitive
     │                                       HOẶC execute vừa được xác nhận)
     ▼
 apply_classification ─► injection_graph ─► Finding  [score ≥ 70 → network watch]
```

Điều kiện "tiến triển" thay cho điều kiện cũ "điểm tăng": điểm bị chặn ở 100 nên một chuỗi có thể chạm trần trước khi bước cuối (thường là bước cho phép phân loại chính xác nhất) xuất hiện, và finding đó từng bị nuốt.

Console có thể nâng ngưỡng 2/3 lên 3/3 hoặc tắt temporal/congruence qua policy — dùng cho ablation từng quy tắc.

### 5.5.3. Execution analysis và scoring

`primitives.analyze_execution` tách **execution transfer** (`ResumeThread`, `CreateRemoteThread`, `NtQueueApcThread`…) khỏi **context read** (`GetThreadContext`). Thiếu execution transfer: finding có tiêu đề *"Probable injection staging chain"*, `execution_confirmed = false`, điểm chặn ở 75.

`scoring.score_chain` cộng điểm cho W+E đã xác nhận, đủ ba primitive, cross-process, section mapping, quyền thực thi, `CREATE_SUSPENDED`, file thả xuống chưa ký/entropy cao; giảm điểm chuỗi chỉ có `ResumeThread` vào `Program Files` (installer). Severity theo ngưỡng của policy.

### 5.5.4. Provenance và injection graph

`provenance.ProvenanceTracker` giữ file thả xuống, bảng tiến trình, cache PID→image và gợi ý spawn chưa biết PID; resolver hệ điều hành được tiêm vào nên test không phụ thuộc Windows. `injection_graph.InjectionGraph` nối actor→victim, đánh dấu `is_recursive` cho A→B→C.

---

## 5.6. Sensor Sysmon và bằng chứng kernel

### 5.6.1. Ánh xạ Event ID

**Bảng 5.2.** Sysmon trong Noirlycan

| EID | Tên | Model | Vai trò |
|-----|-----|-------|---------|
| 1 | ProcessCreate | `ProcessEvent` | Lineage, `CREATE_SUSPENDED` |
| 3 | NetworkConnect | `NetworkConnectionEvent` | Network watch sau finding |
| 7 | ImageLoad | `TelemetryEvent` | Ngữ cảnh module |
| 8 | CreateRemoteThread | `MemoryPrimitive(EXECUTE, source="sysmon")` | Bằng chứng về tạo luồng từ xa khi Sysmon ghi nhận được sự kiện |
| 10 | ProcessAccess | `ProcessAccessEvent` | Quyền handle + call stack |
| 11 / 15 | FileCreate / StreamHash | `FileEvent` | Provenance |

EID 8 dùng `StartAddress` làm địa chỉ cho congruence **chỉ khi** thread bắt đầu ở vùng nhớ không thuộc module nào (`StartModule` rỗng): khi đó nó trỏ vào buffer bị inject. Thread bắt đầu tại `kernel32!LoadLibraryW` không mang địa chỉ buffer nên không được dùng để so khoảng.

### 5.6.2. Bằng chứng kernel (`extensions/kernel_evidence.py`)

[7] lọc call theo return address và tự nhận rủi ro gadget, gợi ý *"verifying the legitimacy of the return address"* (§3.3). Call stack của EID 10 do kernel chụp cho phép kiểm đúng điều đó:

- frame trong cùng không phải `ntdll.dll`/`win32u.dll` → **direct syscall**;
- frame `UNKNOWN` → caller chạy từ **vùng nhớ unbacked** (shellcode, image nạp reflective);
- kernel thấy remote thread nhưng Frida — đang gắn vào actor — không thấy → **hook bypass**.

**Observer effect:** trampoline của Frida Interceptor nằm ở vùng nhớ unbacked, nên khi Frida gắn vào actor, chính Frida xuất hiện như frame `UNKNOWN` (quan sát trên log thật: loader → `msedge.exe`, call stack `ntdll.dll+161a74|UNKNOWN(00007FFF8B23372F)`). Vì vậy dấu hiệu unbacked chỉ được tính điểm khi actor **không** bị Frida instrument — đúng kịch bản hook bị né. Kiểm tra frame trong cùng không bị ảnh hưởng.

Các bằng chứng này chỉ cộng điểm (+10 mỗi loại) cho chuỗi đã qua quy tắc của paper.

### 5.6.3. File watch và triage

`FileDropWatcher` poll thư mục (bootstrap snapshot mtime), bổ sung cho EID 11 khi không có tiến trình Windows nào ghi file (copy qua clipboard RDP, mount ổ ảo). `runtime/triage.py`: SHA-256 theo khối 1 MB, entropy Shannon, nhận diện PE và import (`pefile`), Authenticode, lý do nghi vấn. `FileIntake` triage mỗi nội dung một lần mỗi phiên, rồi tùy policy đưa vào hàng đợi chạy dưới Frida hoặc chỉ triage.

---

## 5.7. Phân loại kỹ thuật (`noirlycan_core/classification/`)

`InjectionTechnique` gồm 36 kỹ thuật, từ `section_mapping_injection` tới `poolparty`, `process_ghosting`. `classify_finding()`: nạp `ClassifierRulesConfig`; chạy custom rule pha `before_builtin`; chuỗi rule built-in theo độ đặc hiệu giảm dần; gán confidence (HIGH khi đủ ba primitive và execution đã xác nhận). Analyst sửa rule qua `/api/classifier` (bật/tắt, ngưỡng từng rule, custom rule JSON); logic kiểm hợp lệ nằm ở `classification/config.py`, route chỉ là lớp mỏng.

---

## 5.8. Console (`noirlycan_backend` + `dashboard-ui`)

### 5.8.1. Kênh agent

| Route | Chức năng |
|-------|-----------|
| `POST /api/ingest/hello · heartbeat · goodbye` | Vòng đời agent; phản hồi kèm policy, lệnh chờ, public key ký lệnh |
| `POST /api/ingest/batch` | Nhận lô sự kiện, ghi vào session của **chính agent** (agent không chọn tên file) |
| `GET /api/agents/{id}/commands` | Lấy lệnh đã ký |
| `GET /api/agents/{id}/samples/{n}` | Tải sample — chỉ khi lệnh `sample.run` cho sample đó đã gửi tới đúng agent |
| `POST /api/agents/{id}/samples/{n}/status` | Báo spawned/failed kèm đường dẫn phía agent |

Mọi call agent bắt buộc token enrollment riêng + `X-Agent-Id`; token dùng chung toàn server không còn được chấp nhận.

### 5.8.2. Kênh analyst

| Route | Chức năng |
|-------|-----------|
| `/api/findings`, `/api/sessions`, `/api/overview` | Finding gom theo victim, session, KPI |
| `/api/samples` | Upload `.exe/.dll` (lưu theo SHA-256), gửi tới agent, báo cáo; `.jsonl` được import để phân tích offline |
| `/api/rules`, `/api/classifier` | Ruleset phát hiện (policy agent) và rule phân loại |
| `/api/analysis/corpus`, `/api/analysis/reclassify/{session}` | Thống kê corpus, replay |
| `/api/agents`, `/api/users`, `/api/auth` | Đăng ký agent, RBAC (Admin/Analyst/Viewer) |

React console có các tab Overview, Findings, Activity, Network, Rules, Samples, Agents, Account, Access; WebSocket đẩy refresh khi có sự kiện mới.

### 5.8.3. Luồng sample

```
Analyst upload EXE ─► backend lưu, tính SHA-256 ─► Run (chọn agent)
  ─► lệnh sample.run (ký Ed25519: upload_id, sha256, tên, argv)
  ─► agent verify chữ ký ─► tải sample ─► so SHA-256 ─► hàng đợi ─► spawn dưới Frida
  ─► báo spawned/failed ─► finding về session của agent ─► báo cáo theo sample
```

Host analyst không bao giờ thực thi mẫu; mẫu chỉ chạy trên VM.

---

## 5.9. Mô hình dữ liệu (`models.py`)

Dataclass nghiệp vụ đều `frozen=True`: `MemoryPrimitive` (kind, PID/image actor & victim, địa chỉ, kích thước, API, `details`, `source` = sensor), `ProcessAccessEvent`, `FileEvent`, `ProcessEvent`, `NetworkConnectionEvent`, `Finding` (primitive, score, evidence, kỹ thuật, file gốc, chuỗi injection). `PrimitiveKind` ∈ {`ALLOCATE`, `WRITE`, `EXECUTE`, `CONTEXT_READ`}.

---

## 5.10. Tái lập thí nghiệm

### 5.10.1. Cài đặt

1. Máy analyst: `pip install -e ".[backend]"`, `noirlycan-backend api`; build `dashboard-ui` (hoặc `docker compose up backend-api dashboard-ui`).
2. VM Windows 10/11: `pip install -e ".[agent]"`, cài Sysmon với `configs/sysmon-noirlycan.xml`.
3. Console → Agents → Register → tải file config (chứa endpoint, agent id, token và `command_key`).
4. VM: `noirlycan-agent run --config noirlycan-agent.toml --watch-sysmon`.

### 5.10.2. Test tự động

```bash
uv run --extra full pytest
```

127 test, chạy không cần Windows/Frida, gồm: từng quy tắc của paper (`test_paper_rules.py`), correlator và các case của [7] (`test_correlation.py`), sensor Sysmon và call stack (`test_kernel_sensors.py`), classifier, kênh agent (batch upload, lệnh ký, sample) và an toàn đường dẫn. Ngoài ra, mỗi lần refactor được kiểm bằng replay 20 session thật trong `logs/` qua code cũ và mới.

### 5.10.3. Deviation đã biết (audit)

| ID | Mô tả | Trạng thái |
|----|-------|-----------|
| D1 | Execute mang địa chỉ | `SetThreadContext` → Rip; CRT → `thread_parameter`; Sysmon EID 8 → start address nếu unbacked; `ResumeThread` vẫn không có |
| D2 | Read ∉ write | Đã tách `remote_read` |
| D3 | Temporal | Đã sửa write-after-execute; miễn đổi quyền vùng nhớ |
| D4 | Anti-evasion E5 | **Chưa** — chỉ ghi tín hiệu |
| D5 | Ghosting/Herpaderping | Có enum, phụ thuộc hook precursor |

### 5.10.4. Giới hạn hiện thực

- Không có anti-evasion (E5); kết quả không so trực tiếp với prevalence của [7].
- Sysmon không có sự kiện allocate/write; khi Frida bị né hoàn toàn, chuỗi chỉ còn EXECUTE từ kernel — chưa đủ 2/3. Cần sensor ETW-TI (yêu cầu PPL/ELAM) để phục hồi.
- Đối thủ kernel-mode nằm ngoài phạm vi, như [7].

---

## 5.11. Bảo mật triển khai

Agent chạy trên chính máy đang nhiễm mẫu, nên thiết kế coi agent và dữ liệu của nó là **không tin cậy**:

- **Dữ liệu agent:** giới hạn kích thước lô/sự kiện; tên file session do backend quyết định; đường dẫn session từ request bị giới hạn trong `logs/` và đuôi `.jsonl`.
- **Lệnh console → agent:** ký Ed25519, kèm `agent_id`, hạn 10 phút, nonce chống replay; agent pin public key từ file config và từ chối mọi lệnh khác. Allowlist chỉ có `kill` và `sample.run`; `kill` từ chối PID hệ thống/của agent và kiểm image hiện tại của PID (chống PID reuse); `sample.run` chỉ nhận `.exe/.dll`, SHA-256 hợp lệ, argv là PID.
- **Bí mật:** JWT secret và mật khẩu admin sinh ngẫu nhiên lần chạy đầu (tài khoản demo chỉ khi bật `NOIRLYCAN_DEMO_USERS=1`); token agent mã hóa DPAPI trên Windows.
- **Lab:** mẫu chỉ thực thi trong VM cô lập; PoC loader (Phụ lục D) không weaponized; JSONL có thể chứa đường dẫn nhạy cảm, cần redact khi chia sẻ.

## 5.12. Tóm tắt chương

Chương 5 trình bày Noirlycan theo hai module của [7]: monitoring module gồm sensor Frida (user-mode, giàu đối số) và Sysmon (kernel, còn tín hiệu khi hook bị né), analysis module giữ nguyên ba quy tắc của paper trong `detection/rules.py`. Phần mở rộng — provenance từ file thả xuống, bằng chứng call stack kernel với xử lý observer effect của Frida, console và kênh agent có ký lệnh — được tách rõ khỏi lõi paper. Giới hạn: không có anti-evasion E5, chưa có sensor ETW-TI. Chương 6 chuyển sang đánh giá định lượng và case study section-mapping.
