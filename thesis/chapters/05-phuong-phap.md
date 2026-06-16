# CHƯƠNG 4. PHƯƠNG PHÁP TĂNG CƯỜNG PHÁT HIỆN

Chương này trình bày phương pháp luận của luận văn *Tăng cường phát hiện mã độc dưới các hình thức né tránh*, căn cứ chính thức vào công trình Di Pietro, D'Elia và Querzoni tại ASIA CCS 2025 [4]. Phương pháp [4] được thiết kế để phát hiện process injection khi malware **né signature API** (nhóm né tránh E1) hoặc **gộp/ẩn bước operational** (E2). Luận văn kế thừa lõi phương pháp đó — ba *operational primitive*, lớp tương đương API (*equivalence class*), quy tắc *2-of-3*, đồng nhất vùng nhớ (*memory congruence*) và ràng buộc thứ tự thời gian (*temporal ordering*) — rồi mở rộng hai tầng bổ sung nhằm đối phó **né attribution** (E3) và **né hook user-mode** (E4). Các hình thức né tránh E5 (phát hiện sandbox/VM) và E6 (anti-instrumentation) được khai báo rõ trong Chương 3; **module anti-evasion của [4] tương ứng E5 không được hiện thực** trong artifact Noirlycan và không nằm trong phạm vi claim khoa học của luận văn.

---

## 4.1. Tổng quan pipeline phương pháp

### 4.1.1. Hai tầng tăng cường

Phương pháp luận văn gồm **hai tầng** bổ trợ lẫn nhau:

1. **Tầng phát hiện chống biến thể (E1, E2)** — kế thừa trực tiếp [4]: mọi lời gọi Windows API liên quan injection được ánh xạ vào một trong ba primitive *allocate*, *write*, *execute*; một chuỗi injection được kết luận khi quan sát **ít nhất hai primitive khác loại** trên cùng cặp `(actor_pid, target_pid)` và thỏa congruence + temporal.
2. **Tầng ngữ cảnh và phòng thủ sâu (E3, E4)** — đóng góp của luận văn: (a) pipeline *file provenance* gắn nguồn gốc file với chuỗi injection; (b) *telemetry kép* Sysmon (kernel) ∪ Frida (user-mode) để giảm false negative khi hook bị né.

Hình 4.1 (tham chiếu `docs/architecture-diagrams.md`) so sánh pipeline batch của [4] (QEMU sandbox → trace API → analyzer offline) với pipeline Noirlycan (lab Windows real-time: file/process events → Frida primitives → correlator → finding → dashboard).

### 4.1.2. Luồng dữ liệu end-to-end

Pipeline Noirlycan được mô tả bằng các giai đoạn sau:

```
[Giai đoạn 1 — Thu thập]
  FileDropWatcher / Sysmon E11,E15  →  FileEvent
  Sysmon E1                         →  ProcessEvent
  Frida hooks (windows_injection_hooks.js) → MemoryPrimitive
  Sysmon E3 (tùy chọn)              →  NetworkConnectionEvent

[Giai đoạn 2 — Tiền xử lý]
  FileTriage (SHA256, PE, entropy, Authenticode) → làm giàu FileEvent
  runtime_event_to_primitive / runtime_event_to_process → chuẩn hóa Frida

[Giai đoạn 3 — Tương quan]
  Correlator.add_file / add_process / add_primitive
    → kiểm 2-of-3 + temporal + congruence
    → scoring + technique_classifier
    → Finding

[Giai đoạn 4 — Đầu ra]
  JSONL session log  →  Dashboard analyst  →  export / reclassify
```

Khác với [4] — nơi phân tích chạy *post-mortem* trên trace tĩnh — Noirlycan duy trì **cửa sổ trượt 300 giây** (`Correlator.window_seconds = 300`) và đánh giá lại chuỗi `(actor_pid, target_pid)` mỗi khi có primitive mới, cho phép phát hiện real-time trong phòng lab.

### 4.1.3. Định nghĩa đối tượng quan sát

Ký hiệu dùng xuyên suốt chương:

| Ký hiệu | Ý nghĩa |
|---------|---------|
| $\mathcal{P}$ | Tập tiến trình trên host |
| $\pi \in \{\texttt{allocate}, \texttt{write}, \texttt{execute}\}$ | Operational primitive theo [4], [7] |
| $\mathrm{obs}(t, a, v, \pi, r)$ | Quan sát primitive $\pi$ lúc $t$, actor $a$, victim $v$, vùng nhớ $r = [addr, addr+size)$ |
| $K \subseteq \{\texttt{A}, \texttt{W}, \texttt{E}\}$ | Tập loại primitive đã quan sát trên một chuỗi |
| $\mathrm{score}(K, ctx)$ | Điểm tin cậy 0–100 sau khi thỏa quy tắc phát hiện |

Một **Finding** là bản ghi có cấu trúc gồm: timestamp, actor/target PID và image, danh sách primitive, điểm số, evidence, kỹ thuật injection suy luận (nếu có), và `related_file` khi pipeline provenance khớp.

---

## 4.2. Operational primitive và equivalence class (chống E1)

### 4.2.1. Ba primitive theo [4]

Theo Klein et al. [7] và formal hóa của [4], process injection user-mode có thể mô hình hóa bằng ba thao tác operational trên vùng nhớ victim:

1. **Allocate ($\texttt{A}$)** — chuẩn bị vùng nhớ (cấp phát, map section, đổi protection sang executable).
2. **Write ($\texttt{W}$)** — đặt payload (shellcode, PE, đường dẫn DLL) vào vùng đó.
3. **Execute ($\texttt{E}$)** — chuyển luồng thực thi tới vùng đó (remote thread, APC, resume, set context, load library, …).

**E1 (biến thể API):** malware thay `CreateRemoteThread` bằng `NtCreateThreadEx`, hoặc Win32 bằng NT/Zw export tương đương. Phương pháp [4] không khớp chuỗi API cố định mà khớp **lớp tương đương** — mọi API cùng ngữ nghĩa operational được gom vào một primitive.

### 4.2.2. Bảng equivalence class

Manifest `PAPER_API_CLASSES` trong `kernel/classification/api_manifest.py` liệt kê ánh xạ chính thức (Phụ lục A). Tóm tắt Bảng 4.1:

**Bảng 4.1.** Lớp tương đương API theo [4] (trích)

| Lớp | Primitive | Ví dụ API |
|-----|-----------|-----------|
| allocate | A | `VirtualAllocEx`, `NtAllocateVirtualMemory`, `VirtualProtectEx`, `NtCreateSection`, `CreateFileMapping*`, `MapViewOfFile*` |
| write | W | `WriteProcessMemory`, `NtWriteVirtualMemory`, `NtMapViewOfSection`, `NtUnmapViewOfSection`, `RtlCopyMemory` |
| execute | E | `CreateRemoteThread*`, `NtCreateThreadEx`, `QueueUserAPC`, `SetThreadContext`, `ResumeThread`, `LoadLibrary*`, `SetWindowsHookEx*`, `NtAddAtom` |
| remote_read | *(quan sát)* | `ReadProcessMemory`, `NtReadVirtualMemory` — **không** tính vào 2-of-3 (deviation D2 đã sửa) |
| context_read | *(lab)* | `GetThreadContext`, `NtGetContextThread` — chỉ báo hijack-prep, không tính 2-of-3 |

Mở rộng lab: `IRED_TEAM_API_CLASSES` bổ sung fiber, threadpool, window memory, TXF — phục vụ classifier iRed.team mà không thay đổi quy tắc 2-of-3 cốt lõi.

### 4.2.3. Cơ chế hook chống E1

Frida `Interceptor.attach` trên export của `kernel32.dll`, `ntdll.dll`, … Alias `Zw*` được resolve cùng stub với `Nt*`. Tập `DYNAMIC_INJECTION_APIS` trong `windows_injection_hooks.js` bao phủ API resolve động qua `GetProcAddress`. Mỗi lần gọi thành công phát sinh sự kiện `memory_primitive` hoặc `api_observation` với trường `kind` đã ánh xạ.

---

## 4.3. Quy tắc 2-of-3 (chống E2)

### 4.3.1. Động cơ né tránh E2

Malware thường **gộp hoặc ẩn bước** để né detector dựa trên chuỗi A→W→E đầy đủ:

- **Section mapping:** `NtCreateSection` + `NtMapViewOfSection` (remote) vừa map vừa ghi — chỉ cần W+E.
- **Mockingjay / RWX sẵn có:** payload copy vào vùng executable có sẵn — W+E hoặc chỉ E.
- **Process Hollowing (section variant):** allocate+write gộp trong map; execute qua `SetThreadContext` + `ResumeThread`.

Paper [4] chứng minh trên dataset lớn rằng yêu cầu **đủ ba bước** gây false negative đáng kể; quy tắc **ít nhất 2 trong 3 primitive khác loại** tăng recall mà vẫn giữ precision nhờ congruence và temporal.

### 4.3.2. Phát biểu hình thức

Cho cặp actor $a$ và victim $v$, tập quan sát trong cửa sổ thời gian $T$:

$$\mathcal{O}_{a,v,T} = \{\, \mathrm{obs}(t_i, a, v, \pi_i, r_i) \mid t_i \in T \,\}$$

Định nghĩa tập loại primitive:

$$K = \{\, \pi \mid \exists\, \mathrm{obs}(\cdot, a, v, \pi, \cdot) \in \mathcal{O}_{a,v,T} \,\}$$

**Quy tắc 2-of-3** (Công thức 4.1):

$$|K \cap \{\texttt{A}, \texttt{W}, \texttt{E}\}| \geq 2 \tag{4.1}$$

**Điều kiện bổ sung** (theo [4] §3.3–3.4), chuỗi chỉ được chấp nhận nếu:

$$\mathrm{Congruence}(\mathcal{O}_{a,v,T}) \land \mathrm{Temporal}(\mathcal{O}_{a,v,T}) \tag{4.2}$$

Implementation: `operational_kind_count(kinds) >= 2` trong `_evaluate_chain`, loại trừ `CONTEXT_READ` khỏi đếm (`kernel.analysis.primitives.operational_kind_count`).

### 4.3.3. Ví dụ minh họa E2

| Kịch bản | Primitive quan sát | $|K|$ | Kết luận |
|----------|-------------------|-------|----------|
| Classic DLL injection | A + W + E | 3 | Finding (cao điểm) |
| Section-mapping (*neurevt*) | W (`NtMapViewOfSection`) + E (`ResumeThread`) | 2 | Finding (test `test_detects_section_mapping_write_execute_chain`) |
| Chỉ `WriteProcessMemory` | W | 1 | **Không** finding (`test_requires_two_distinct_primitives`) |
| Debugger remote read | A + read-only | 1 | **Không** (D2: read không tính W) |

---

## 4.4. Memory range congruence

### 4.4.1. Định nghĩa

Hai quan sát $\mathrm{obs}_1, \mathrm{obs}_2$ **đồng nhất vùng nhớ** nếu khoảng nửa mở $r_1 = [addr_1, addr_1 + size_1)$ và $r_2 = [addr_2, addr_2 + size_2)$ **giao nhau**:

$$\mathrm{overlap}(r_1, r_2) \iff addr_1 < addr_2 + size_2 \;\land\; addr_2 < addr_1 + size_1 \tag{4.3}$$

Starink et al. [12] dùng ý tưởng tương tự trong behavior graph; [4] áp dụng để loại false positive khi cùng process thực hiện nhiều thao tác heap độc lập.

### 4.4.2. Thuật toán trong Noirlycan

Hàm `_has_memory_congruence` xây dựng tập khoảng từ mỗi primitive qua `_memory_link_ranges`:

- `address` + `size` chính;
- `thread_parameter` trên EXECUTE (DLL path buffer cho `CreateRemoteThread`);
- `context_pointer` liên kết `GetThreadContext` ↔ `SetThreadContext`;
- `address == 0` coi như thiếu (hook không đọc được base — thường gặp với `NtAllocateVirtualMemory`).

Congruence yêu cầu **ít nhất một cặp primitive khác loại** có khoảng overlap. Ngoại lệ thực dụng: khi `NtAllocateVirtualMemory` không trả address nhưng có nhiều WRITE + EXECUTE cross-process, chuỗi vẫn được chấp nhận nếu `operational_kind_count >= 2` và chỉ một loại có range (`services/analysis/domain/correlation.py` dòng 454–458).

### 4.4.3. Deviation D1 (khai báo trung thực)

Execute-level API (`ResumeThread`, …) lịch sử không mang `address`. Fix D1: hook đọc `Rip` từ `CONTEXT` cho `SetThreadContext`, `lpStartAddress` cho `CreateRemoteThread` — test `test_set_thread_context_with_rip_overlaps_write_buffer` xác nhận. Khi execute vẫn thiếu address, congruence có thể suy yếu; luận văn **không claim** precision tương đương paper trên mọi biến thể execute-only.

---

## 4.5. Temporal ordering

### 4.5.1. Quy tắc [4]

Thứ tự canonical: **allocate → write → execute**, với hai ngoại lệ được paper cho phép:

1. **Allocate lặp** — resize, đổi protection RWX→RX.
2. **Gộp bước** — section mapping có thể phát sinh W đồng thời với map (allocate ngữ nghĩa đã xảy ra trước hoặc trong cùng API).

### 4.5.2. Formal hóa implementation

Gán bậc:

$$\mathrm{rank}(\texttt{A}) = 0,\; \mathrm{rank}(\texttt{W}) = 1,\; \mathrm{rank}(\texttt{E}) = 3$$

(`CONTEXT_READ` = 2, không gây reject.)

Sắp xếp primitive theo timestamp; duyệt tuần tự, với mỗi $\pi \in \{\texttt{A}, \texttt{W}, \texttt{E}\}$:

$$\text{nếu } \mathrm{rank}(\pi) < \mathrm{last\_rank} \text{ và } \pi \in \{\texttt{A}, \texttt{W}\} \Rightarrow \text{reject} \tag{4.4}$$

Fix D3: từ chối WRITE sau EXECUTE (`test_rejects_write_after_execute_temporal_order`). Cho phép allocate sau write (re-protect) vì rank A = 0 < last chỉ reject khi A xuất hiện **sau** W hoặc E đã nâng last_rank — logic trong `_has_temporal_consistency`.

---

## 4.6. Pipeline file provenance (chống E3)

### 4.6.1. Động cơ né tránh E3

Malware **né attribution** bằng cách inject vào tiến trình hợp pháp (`msedge.exe`, `explorer.exe`) thay vì giữ process tree bất thường. Signature chỉ nhìn injection trên victim sẽ **mất dấu loader gốc**. Paper [4] tập trung trace execution, không xây pipeline file→process end-to-end cho lab endpoint.

### 4.6.2. Luồng provenance

```
Sysmon E11/E15 (FileCreate)  ──┐
FileDropWatcher (poll)       ──┼→  FileEvent  →  FileTriage
                               │       ↓
Sysmon E1 (ProcessCreate)  ────┘  add_process: created_from_file = image path
                                         ↓
                              add_primitive → Finding.related_file
```

Hàm `_related_file_for_process` liên kết theo thứ tự ưu tiên: (1) `created_from_file`; (2) image path khớp `files_by_path`; (3) image của parent process.

### 4.6.3. Static triage

Module `triage.py` tính:

- SHA256, entropy Shannon (1 MB đầu);
- PE header (`pefile`), Authenticode (`signtool` / PowerShell);
- import injection API đáng ngờ;
- heuristic thư mục (`SUSPICIOUS_DIRECTORIES`).

Metadata làm giàu scoring (mục 4.9) và dashboard — hỗ trợ analyst **phá vỡ né attribution** bằng cách truy ngược file drop tới loader.

---

## 4.7. Telemetry kép (chống E4)

### 4.7.1. Động cơ né tránh E4

**Direct syscall** và **unhook ntdll** né Frida user-mode. Sysmon driver (`SysmonDrv.sys`) đăng ký kernel callback — Event ID 8 (CreateRemoteThread), 10 (ProcessAccess), 11 (FileCreate), 1 (ProcessCreate) — **không phụ thuộc** export hook trong process nạn nhân.

### 4.7.2. Ma trận bổ sung

| Tình huống E4 | Frida | Sysmon | Kết quả mong đợi |
|---------------|-------|--------|------------------|
| Win32/NT qua export | Có primitive + address | E8/E10 (context) | Finding đầy đủ |
| Syscall thuần, unhook | Miss primitive | E8/E10 vẫn log | Cảnh báo một phần; **thiếu congruence** |
| File drop + spawn | Miss nếu attach trễ | E11 + E1 | Provenance vẫn có |

Luận văn claim **giảm false negative một phần** dưới E4, không claim phát hiện injection đầy đủ khi chỉ có Sysmon (thiếu address/size cho congruence).

### 4.7.3. Chế độ spawn

`noirlycan-telemetry spawn` khởi chạy mẫu **dưới Frida từ đầu**, giảm rủi ro miss primitive đầu (liên quan E6). Đây là biện pháp methodology, không thay thế anti-evasion E5.

---

## 4.8. Phân loại kỹ thuật injection

Sau khi có Finding, `kernel/classification/technique_classifier.py` áp dụng **rule-based classifier** (21+ enum `InjectionTechnique`), căn cứ taxonomy §4 của [4] và mở rộng iRed.team:

| Rule (rút gọn) | Kỹ thuật | ATT&CK |
|----------------|----------|--------|
| W section + E resume + CREATE_SUSPENDED | `process_hollowing_section` | T1055.012 |
| CRT + thread_parameter trong write buffer | `dll_injection` | T1055.001 |
| APC + suspended child | `early_bird_apc_injection` | T1055.004 |
| Local A+W RWX, không transfer | `shellcode_injection` / staging | T1055.002 |
| TXF + section | `process_doppelganging` | T1055.013 |
| NtSetInformationFile + section | `process_ghosting` | T1055.012 |

`apply_classification` gọi sau scoring; confidence `high` khi đủ 3 primitive + execution_confirmed. Ghosting/Herpaderping có enum nhưng phụ thuộc precursor observation từ hook.

**E5:** classifier không chạy nếu malware **không inject** do phát hiện VM — out-of-scope; recall trên lab có thể thấp hơn [4].

---

## 4.9. Mô hình scoring

Điểm 0–100 (`Correlator._score`) **không** thay thế quy tắc 2-of-3 mà **xếp hạng** finding và lọc `minimum_score` (mặc định 50):

| Thành phần | Điểm | Điều kiện |
|------------|------|-----------|
| W + E + execution confirmed | +45 | Chuỗi mạnh nhất |
| ≥ 2 operational kinds | +35 | Thay thế khi chưa confirm execute |
| A + W + E + confirmed | +20 | Bonus đủ ba bước |
| Cross-process | +15 | `target_pid ≠ actor_pid` |
| Section mapping API | +10 | `NtMapViewOfSection`, … |
| Executable protection | +10 | PAGE_EXECUTE* trong details |
| CREATE_SUSPENDED | +15 | ProcessEvent flags |
| Related file | +10 | Provenance E3 |
| PE / unsigned / entropy ≥ 7 | +5 / +10 / +5 | Static triage |

Severity: CRITICAL ≥ 85, HIGH ≥ 70, MEDIUM ≥ 50. Score ≥ 70 kích hoạt **network watch** 300 giây trên `target_pid` (Sysmon E3).

Heuristic giảm false positive: `_resume_only_spawn_to_trusted_target` cap score ≤ 50 khi chỉ ResumeThread vào Program Files.

---

## 4.10. Thuật toán (pseudo-code)

### Thuật toán 4.1 — Ánh xạ API → primitive

```
function MAP_API(api_name):
    for class in PAPER_API_CLASSES ∪ IRED_TEAM_API_CLASSES:
        if api_name in class.apis:
            if class.primitive == "observation":
                return OBSERVATION_ONLY
            return class.primitive
    return UNKNOWN

function ON_API_CALL(api, args, retval):
    if not success(retval): return
    kind ← MAP_API(api)
    if kind == OBSERVATION_ONLY:
        emit api_observation(...)
        return
    range ← extract_memory_range(api, args, retval)
    emit memory_primitive(kind, actor_pid, target_pid, range, api, details)
```

### Thuật toán 4.2 — Correlator: đánh giá chuỗi

```
function ADD_PRIMITIVE(p):
    enrich p with actor_image, target_image
    bucket[(p.actor_pid, p.target_pid)].append(p)
    expire events older than WINDOW
    return EVALUATE_CHAIN(p.actor_pid, p.target_pid)

function EVALUATE_CHAIN(actor, target):
    P ← bucket[(actor, target)]
    K ← { p.kind | p ∈ P } \ { CONTEXT_READ }
    if |K ∩ {A,W,E}| < 2: return []
    if not TEMPORAL_OK(P): return []
    if not CONGRUENCE_OK(P): return []
    score, evidence ← SCORE(P, related_process, related_file)
    if score < minimum_score: return []
    if score ≤ previous_reported_score: return []  // chỉ upgrade
    finding ← Finding(..., apply_classification(...))
    if score ≥ 70: enable_network_watch(target)
    return [finding]
```

### Thuật toán 4.3 — Congruence

```
function CONGRUENCE_OK(P):
    ranges_by_kind ← group memory_link_ranges(p) for p in P
    if count_linked_primitives < 2: return TRUE  // không đủ dữ liệu
    for each pair (kind1, kind2) where kind1 ≠ kind2:
        for r1 in ranges_by_kind[kind1], r2 in ranges_by_kind[kind2]:
            if overlap(r1, r2): return TRUE
    if |operational_kinds| ≥ 2 and only WRITE has ranges:
        return TRUE  // NtAllocateVirtualMemory edge case
    return FALSE
```

### Thuật toán 4.4 — File provenance

```
function ADD_PROCESS(proc):
    path ← normalize(proc.image)
    if path in files_by_path:
        proc.created_from_file ← path
    processes_by_pid[proc.pid] ← proc

function RELATED_FILE(proc):
    if proc.created_from_file: return files[proc.created_from_file]
    if proc.image in files: return files[proc.image]
    if parent exists: return files[parent.image]
    return NULL
```

---

## 4.11. Ranh giới phương pháp so với [4]

| Khía cạnh | [4] | Luận văn (Noirlycan) |
|-----------|-----|----------------------|
| 2-of-3 + congruence + temporal | ✅ | ✅ (có test) |
| Equivalence class | Table 1 đầy đủ | `PAPER_API_CLASSES` + lab extension |
| Anti-evasion E5 | ✅ Tích hợp | ❌ **Không hiện thực** — chỉ ghi `kernel/analysis/evasion.py` signal |
| Dataset 56k + prevalence | ✅ | ❌ Ngoài phạm vi |
| File provenance E3 | ❌ | ✅ Đóng góp |
| Real-time endpoint | ❌ | ✅ Đóng góp |
| Recursive chain metric ~2% | ✅ | ⚠️ `InjectionGraph` một phần |

Luận văn **không** claim số liệu 16,5 % hay 21,2 % của [4]; các con số đó thuộc paper gốc và phụ thuộc module anti-evasion mà luận văn **chưa triển khai**.

---

## 4.12. Ví dụ đi sâu: phân tích chuỗi section-mapping

Để minh họa cách các thành phần phương pháp tương tác, xét chuỗi cross-process vào `msedge.exe` (case study *neurevt* [4], test `test_detects_section_mapping_write_execute_chain`):

**Bước 1 — Provenance (E3):** Sysmon E11 hoặc file watcher ghi nhận `loader.exe` trong `%TEMP%`. Static triage: PE=True, signed=False, entropy=7,2. Khi loader spawn (E1, flag `CREATE_SUSPENDED`), `add_process` gắn `created_from_file`.

**Bước 2 — Primitive W:** Hook bắt `NtMapViewOfSection` với `target_pid` = Edge, `address` = 0x200000, `protection` = EXECUTE_READWRITE. Một lần map remote vừa đóng vai trò write vừa expose vùng executable — **không cần** quan sát `VirtualAllocEx` riêng (E2).

**Bước 3 — Kiểm 2-of-3:** $K = \{\texttt{W}, \texttt{E}\}$, $|K| = 2$ — thỏa Công thức (4.1).

**Bước 4 — Temporal:** ResumeThread (E) sau MapView (W); không có A lùi sau E — thỏa (4.4).

**Bước 5 — Congruence:** Execute không mang address; với chỉ W+E có range, `_has_memory_congruence` chấp nhận khi đủ operational kinds và overlap implicit qua cùng target (edge case Resume-only đã được test acceptance).

**Bước 6 — Scoring:** W+E confirmed → +45; cross-process +15; section +10; CREATE_SUSPENDED +15; related_file +10; unsigned +10 → tổng ≥ 70 (HIGH).

**Bước 7 — Classifier:** Rule `process_hollowing_section` nếu thêm context read/set; với W+E resume → `section_mapping_injection` hoặc hollowing tùy evidence.

So với baseline signature `VirtualAllocEx → WriteProcessMemory → CreateRemoteThread`, chuỗi này **không match** — minh chứng trực tiếp giá trị phương pháp [4] dưới E2.

## 4.13. Ví dụ đi sâu: classic DLL injection (E1)

Malware E1 thay `CreateRemoteThread` bằng `NtCreateThreadEx`:

1. `VirtualAllocEx` → A, range $r_a$
2. `WriteProcessMemory` ghi đường dẫn DLL → W, $r_w$ overlap $r_a$
3. `NtCreateThreadEx` start = `LoadLibraryW`, parameter = $r_a$ → E, `thread_parameter` overlap $r_w$

Equivalence class map cả ba API vào $\{\texttt{A}, \texttt{W}, \texttt{E}\}$ dù tên export khác Win32 classic. Congruence liên kết qua `thread_parameter` (Thuật toán 4.3). Pattern `_dll_path_remote_thread_pattern` tăng +5 score và classifier → `dll_injection` (MITRE T1055.001).

## 4.14. Self-injection và local staging

Paper [4] tập trung cross-process; Noirlycan mở rộng `actor_pid == target_pid`:

- `VirtualAlloc` + `memcpy` local RWX → A+W, `local_staging` evidence, score ≥ 50.
- Config `.classifier_rules.json` có thể bật `ignore_same_process_findings` nếu lab muốn giảm FP installer.

Phương pháp vẫn áp dụng 2-of-3; scoring ưu tiên cross-process (+15) để phân biệt mối đe dọa attribution E3.

## 4.15. CONTEXT_READ — extension lab (không phải primitive [4])

`GetThreadContext` / `NtGetContextThread` được hook với kind `CONTEXT_READ`:

- **Không** đếm vào $|K|$ cho 2-of-3.
- Tăng +5 score khi có hijack prep mà chưa execution_confirmed.
- Classifier dùng context_read + SET_SUSPENDED → `thread_hijack`, `process_hollowing_classic`.

Phải khai báo rõ trong luận văn để tránh reviewer hiểu nhầm là primitive thứ tư của [4] (audit D7).

## 4.16. Chiến lược giảm false positive

Paper [4] dùng congruence + temporal; Noirlycan bổ sung heuristic scoring:

| Heuristic | Mục đích |
|-----------|----------|
| `minimum_score` ≥ 50 | Lọc chuỗi yếu |
| `_resume_only_spawn_to_trusted_target` | Cap 50 — installer resume Edge/Program Files |
| `missing_execution_transfer` cap 75 | Staging chưa execute |
| `require_cross_process_findings` (config) | Lab chỉ báo inject cross-process |
| Network watch chỉ khi score ≥ 70 | Tránh alert noise |

Các heuristic là **lab tuning**, không thay đổi định nghĩa 2-of-3 [4].

## 4.17. Liên hệ MITRE ATT&CK

Mỗi finding có thể map technique classifier → sub-technique T1055:

| Pattern primitive + evidence | ATT&CK (ví dụ) |
|------------------------------|----------------|
| CRT + LoadLibrary remote | T1055.001 DLL injection |
| APC + suspended | T1055.004 Asynchronous Procedure Call |
| Section + resume | T1055.012 Process Hollowing |
| SetWindowsHookEx | T1055.004 Hook injection |
| TxF + section | T1055.013 Process Doppelgänging |

Phân loại phục vụ analyst sau bước phát hiện primitive — tách biệt với quyết định 2-of-3.

## 4.19. So sánh pipeline [4] và Noirlycan

**Bảng 4.2.** Pipeline phân tích — paper vs luận văn

| Giai đoạn | [4] Sap4Sec | Noirlycan |
|-----------|-------------|-----------|
| Môi trường thực thi | QEMU sandbox batch | Windows 10/11 VM lab |
| Thu thập trace | API logger toàn process tree | Frida hook + Sysmon events |
| Anti-evasion E5 | Có — patch env/timing | **Không** |
| Phân tích | Offline analyzer Python | Online Correlator 300s window |
| Đầu ra | Label + technique + log | Finding JSONL + dashboard |
| Provenance file | Không | FileCreate + triage + lineage |
| Quy mô đánh giá | 56.340 mẫu | 31 unit test + case study |

Noirlycan **không** thay thế nghiên cứu thống kê [4]; nó **operationalize** phương pháp detection cho analyst endpoint và bổ sung lớp E3/E4.

## 4.20. Giả định phương pháp (M1–M5)

Phương pháp Chương 4 dựa trên giả định Chương 3:

| ID | Giả định | Ảnh hưởng phương pháp |
|----|----------|----------------------|
| M1 | Malware gọi API qua export hookable hoặc Sysmon-visible | E4 partial |
| M2 | Injection trong cửa sổ 300s | Expiration correlator |
| M3 | User-mode injection | Không kernel primitive |
| M4 | Lab cô lập | E5 không cần fake production |
| M5 | Frida fidelity chấp nhận được | RQ5 — cần đo |

Vi phạm M1 (syscall thuần + unhook hoàn toàn) → phương pháp 2-of-3 **không khả dụng**; chỉ còn telemetry Sysmon một phần.

## 4.21. Mở rộng tương lai phương pháp

Ba hướng mở rộng **ngoài phạm vi luận văn hiện tại** nhưng bám Chương 4:

1. **ETW Threat Intelligence provider** — thay/đi cùng Frida, giảm E4/E6; vẫn map về cùng equivalence class [4].
2. **ML trên chuỗi primitive** — embedding API sequence thay rule classifier; cần dataset gán nhãn lớn hơn 31 test.
3. **Anti-evasion E5 port** — tích hợp patch timing từ Sap4Sec artifact để so sánh công bằng recall với [4] trên Paper-Subset.

Các hướng này không invalidate phương pháp hiện tại — chúng bổ sung lớp vận hành và phạm vi đối thủ.

## 4.22. Giám sát mạng hậu injection

Sau khi finding đạt score ≥ 70, phương pháp kích hoạt **network watch** trên `target_pid` trong 300 giây (đồng bộ cửa sổ correlator). Sysmon E3 (NetworkConnect) được lọc: chỉ lưu connection khởi phát từ PID victim. Mục tiêu: bắt **beacon** sau khi payload chạy trong tiến trình hợp pháp — bổ sung giá trị điều tra cho analyst, không thay thế bước phát hiện 2-of-3.

Heuristic `is_external_beacon_candidate` đánh dấu IP/hostname ngoài RFC1918. Đây là extension lab, không có trong paper [4]. Module `network.py` và test `test_network_watch.py` xác nhận chỉ connection trong cửa sổ watch mới được correlate — tránh flood log từ toàn hệ thống.

## 4.23. Tóm tắt chương

Chương 4 trình bày phương pháp tăng cường phát hiện process injection: kế thừa lõi operational primitive và quy tắc 2-of-3 của [4] để chống né tránh biến thể API (E1) và gộp bước (E2); bổ sung memory congruence và temporal ordering dưới dạng phát biểu hình thức và pseudo-code; mở rộng pipeline provenance file (E3) và telemetry kép Sysmon–Frida (E4). Scoring và classifier rule-based xếp hạng finding cho analyst. Module anti-sandbox (E5) của [4] **không nằm trong phương pháp hiện thực** — hạn chế được thảo luận ở Chương 6 và 7. Chương 5 mô tả hiện thực các module tương ứng trong artifact Noirlycan.
