# CHƯƠNG 4. PHƯƠNG PHÁP TĂNG CƯỜNG PHÁT HIỆN

Chương này trình bày phương pháp luận, căn cứ công trình Di Pietro, D'Elia, Querzoni tại ASIA CCS 2025 [4], phát hiện process injection khi malware né signature API (E1) hoặc gộp/ẩn bước operational (E2). Luận văn kế thừa lõi — ba *operational primitive*, *equivalence class*, *2-of-3*, *memory congruence*, *temporal ordering* — và mở rộng hai tầng chống E3, E4. **Module anti-evasion E5 không được hiện thực** trong Noirlycan.

---

## 4.1. Tổng quan pipeline phương pháp

### 4.1.1. Hai tầng tăng cường

Phương pháp gồm hai tầng:

1. **Tầng chống biến thể (E1, E2)** — kế thừa [4]: mọi lời gọi API injection ánh xạ vào một trong ba primitive *allocate*, *write*, *execute*; chuỗi được kết luận khi có ≥2 primitive khác loại trên cùng cặp `(actor_pid, target_pid)` thỏa congruence + temporal.
2. **Tầng ngữ cảnh (E3, E4)** — đóng góp của luận văn: (a) pipeline *file provenance* phục hồi loader khi victim hợp pháp; (b) *telemetry kép* Sysmon ∪ Frida giảm FN khi user-mode hook bị né.

So với pipeline batch của [4] (QEMU sandbox → trace → analyzer offline), Noirlycan chạy trên Windows real-time: khác biệt then chốt là trục thời gian — Noirlycan dùng cửa sổ trượt và re-evaluation tăng dần.

### 4.1.2. Luồng dữ liệu end-to-end

```
[1. Thu thập] FileDropWatcher/Sysmon E11,E15→FileEvent; Sysmon E1→ProcessEvent;
              Frida hooks→MemoryPrimitive; Sysmon E3→NetworkConnectionEvent
[2. Tiền xử lý] FileTriage (SHA256, PE, entropy, Authenticode);
                runtime_event_to_primitive / runtime_event_to_process
[3. Tương quan] Correlator.add_file/add_process/add_primitive
                → 2-of-3 + temporal + congruence → scoring → Finding
[4. Đầu ra] JSONL → Dashboard → export/reclassify
```

Noirlycan duy trì **cửa sổ trượt 300s** (`Correlator.window_seconds=300`), đánh giá lại chuỗi mỗi khi có primitive mới. Giá trị 300s dự phòng *delayed execution* mà không bùng nổ bộ nhớ.

### 4.1.3. Định nghĩa đối tượng quan sát

Ký hiệu:

| Ký hiệu | Ý nghĩa |
|---------|---------|
| $\mathcal{P}$ | Tập tiến trình trên host |
| $\pi \in \{\texttt{allocate}, \texttt{write}, \texttt{execute}\}$ | Operational primitive theo [4], [7] |
| $\mathrm{obs}(t, a, v, \pi, r)$ | Quan sát primitive $\pi$ lúc $t$, actor $a$, victim $v$, vùng nhớ $r = [addr, addr+size)$ |
| $K \subseteq \{\texttt{A}, \texttt{W}, \texttt{E}\}$ | Tập loại primitive đã quan sát trên một chuỗi |
| $\mathrm{score}(K, ctx)$ | Điểm tin cậy 0–100 sau khi thỏa quy tắc phát hiện |

Một **Finding** gồm: timestamp, actor/target PID + image, danh sách primitive, score, evidence, kỹ thuật suy luận, `related_file`. Finding immutable; cập nhật chỉ *upgrade* score.

---

## 4.2. Giả thuyết, tính khả thi và tiêu chí kiểm chứng

Theo [14], chương này gắn với **H1–H5** (§1.3.3). Mỗi giả thuyết quy định biến độc lập, biến phụ thuộc, thí nghiệm, ngưỡng chấp nhận; neo vào thành phần code giúp phản nghiệm khả thi.

**Bảng 4.1.** Giả thuyết ↔ thành phần phương pháp ↔ tiêu chí

| Giả thuyết | Thành phần Noirlycan | Tiêu chí chấp nhận |
|------------|----------------------|-------------------|
| **H1** (E1) | `api_manifest.py`, correlator 2-of-3 | Test correlation pass; NT API thay Win32 vẫn ≥2 primitive |
| **H2** (E2) | Congruence + temporal + section-mapping rule | Score ≥ 70 trên case `section_mapping` |
| **H3** (E3) | `file_watch.py`, triage, `related_file` | Finding chứa path + hash file-drop |
| **H4** (E4) | Sysmon E8/E10 + Frida hooks | Case syscall: Sysmon bắt khi Frida miss (thiết kế; số liệu pending) |
| **H5** (E6/M5) | `frida-fidelity.md` protocol | Drop-rate < 1 % trên VM |

**Tính khả thi:** artifact [11] và paper [4] công khai; stack Sysmon/Frida/Python có sẵn. Rủi ro: benchmark VM Windows (H4, H5) phụ thuộc thời gian lab và ổn định Frida.

**Well-posed problem:** vấn đề là *tăng cường phát hiện dưới E1–E4 trên endpoint lab*, không phải giảm 21,2 % sandbox miss của [4] (phát biểu sau không kiểm chứng được trong phạm vi luận văn).

---

## 4.3. Operational primitive và equivalence class (chống E1)

### 4.3.1. Ba primitive theo [4]

Theo Klein et al. [7] và formal hóa của [4], process injection user-mode mô hình bằng ba thao tác độc lập với họ API:

1. **Allocate ($\texttt{A}$)** — chuẩn bị vùng nhớ qua `VirtualAllocEx`, `NtCreateSection` + `NtMapViewOfSection`, hoặc đổi protection sang `PAGE_EXECUTE_READWRITE` qua `VirtualProtectEx`.
2. **Write ($\texttt{W}$)** — đặt payload qua `WriteProcessMemory` hoặc ghi ngầm qua mapping.
3. **Execute ($\texttt{E}$)** — chuyển luồng thực thi qua `CreateRemoteThread`/`NtCreateThreadEx`, `QueueUserAPC`, `SetThreadContext` + `ResumeThread`, `LoadLibrary` remote, hoặc `SetWindowsHookEx`.

**E1:** malware thay `CreateRemoteThread` bằng `NtCreateThreadEx`, thay Win32 bằng NT/Zw, hoặc resolve API runtime qua `GetProcAddress`. [4] khớp **lớp tương đương** chứ không khớp chuỗi API cố định, nên tổ hợp NT thuần vẫn được phát hiện như A+W+E hợp lệ.

### 4.3.2. Bảng equivalence class

**Bảng 4.2.** Lớp tương đương API theo [4] (trích; manifest `PAPER_API_CLASSES`, Phụ lục A)

| Lớp | Primitive | Ví dụ API |
|-----|-----------|-----------|
| allocate | A | `VirtualAllocEx`, `NtAllocateVirtualMemory`, `VirtualProtectEx`, `NtCreateSection`, `CreateFileMapping*`, `MapViewOfFile*` |
| write | W | `WriteProcessMemory`, `NtWriteVirtualMemory`, `NtMapViewOfSection`, `NtUnmapViewOfSection`, `RtlCopyMemory` |
| execute | E | `CreateRemoteThread*`, `NtCreateThreadEx`, `QueueUserAPC`, `SetThreadContext`, `ResumeThread`, `LoadLibrary*`, `SetWindowsHookEx*`, `NtAddAtom` |
| remote_read | *(quan sát)* | `ReadProcessMemory`, `NtReadVirtualMemory` — **không** tính vào 2-of-3 (D2) |
| context_read | *(lab)* | `GetThreadContext`, `NtGetContextThread` — chỉ báo hijack-prep |

`remote_read` và `context_read` là *observation-only*: log phục vụ classifier nhưng không nâng $|K|$ vì đọc remote không cấu thành tấn công (debugger cũng làm). `IRED_TEAM_API_CLASSES` bổ sung fiber, threadpool, window memory, TXF — không thay quy tắc 2-of-3.

### 4.3.3. Cơ chế hook chống E1

Frida `Interceptor.attach` gắn trên export của `kernel32.dll`, `ntdll.dll`, `user32.dll`. Alias `Zw*` resolve cùng stub với `Nt*`. Tập `DYNAMIC_INJECTION_APIS` bao phủ API resolve động qua `GetProcAddress`: agent hook xen kẽ khi `GetProcAddress` trả về địa chỉ trong tập theo dõi. Mỗi lần gọi thành công phát sinh `memory_primitive` hoặc `api_observation` với `kind`, `address`, `size`, `protection`, và (nếu có) `thread_parameter` hoặc trích đoạn `CONTEXT`.

---

## 4.4. Quy tắc 2-of-3 (chống E2)

### 4.3.1. Động cơ né tránh E2

Malware gộp/ẩn bước để né chuỗi A→W→E đầy đủ: **section mapping** (`NtCreateSection`+`NtMapViewOfSection` remote — chỉ W+E); **Mockingjay/RWX sẵn có** (W+E hoặc E); **Process Hollowing section variant** (allocate+write gộp trong map, execute qua `SetThreadContext`+`ResumeThread`).

[4] chứng minh yêu cầu đủ ba bước gây FN; quy tắc **≥2 trong 3 primitive khác loại** tăng recall, giữ precision nhờ congruence + temporal.

### 4.3.2. Phát biểu hình thức

Cho cặp $(a, v)$ trong cửa sổ $T$:

$$\mathcal{O}_{a,v,T} = \{\, \mathrm{obs}(t_i, a, v, \pi_i, r_i) \mid t_i \in T \,\}$$

$$K = \{\, \pi \mid \exists\, \mathrm{obs}(\cdot, a, v, \pi, \cdot) \in \mathcal{O}_{a,v,T} \,\}$$

**Quy tắc 2-of-3** (phương trình 2.14):

$$|K \cap \{\texttt{A}, \texttt{W}, \texttt{E}\}| \geq 2$$ (2.14)

**Điều kiện bổ sung** ([4] §3.3–3.4):

$$\mathrm{Congruence}(\mathcal{O}_{a,v,T}) \land \mathrm{Temporal}(\mathcal{O}_{a,v,T})$$ (2.15)

Implementation: `operational_kind_count(kinds) >= 2` trong `_evaluate_chain`, loại `CONTEXT_READ` khỏi đếm. Độ trễ $O(|P|)$ trên bucket $(a, v)$, thực tế dưới 100 phần tử mỗi cặp.

### 4.3.3. Ví dụ minh họa E2

| Kịch bản | Primitive quan sát | $|K|$ | Kết luận |
|----------|-------------------|-------|----------|
| Classic DLL injection | A + W + E | 3 | Finding (cao điểm) |
| Section-mapping (*neurevt*) | W (`NtMapViewOfSection`) + E (`ResumeThread`) | 2 | Finding (test `test_detects_section_mapping_write_execute_chain`) |
| Chỉ `WriteProcessMemory` | W | 1 | **Không** finding (`test_requires_two_distinct_primitives`) |
| Debugger remote read | A + read-only | 1 | **Không** (D2: read không tính W) |

Ba dòng cuối thể hiện vai trò *gating*: không alarm hoạt động đơn lẻ, kích hoạt khi đủ hai trục tác vụ.

---

## 4.5. Memory range congruence

### 4.5.1. Định nghĩa

Hai quan sát đồng nhất vùng nhớ nếu $r_1 = [addr_1, addr_1 + size_1)$ và $r_2$ giao nhau:

$$\mathrm{overlap}(r_1, r_2) \iff addr_1 < addr_2 + size_2 \;\land\; addr_2 < addr_1 + size_1$$ (2.16)

Starink et al. [12] dùng ý tưởng tương tự; [4] áp dụng overlap để loại FP khi process có nhiều thao tác heap độc lập (allocate A, write B không overlap → không ghép).

### 4.5.2. Thuật toán trong Noirlycan

`_has_memory_congruence` xây tập khoảng từ mỗi primitive qua `_memory_link_ranges`:

- `address` + `size` lấy từ tham số API;
- `thread_parameter` trên EXECUTE — ví dụ tham số thứ hai của `CreateRemoteThread` trỏ buffer chứa đường dẫn DLL (pattern LoadLibrary remote thread);
- `context_pointer` liên kết `GetThreadContext` ↔ `SetThreadContext` qua trường `Rip` trong `CONTEXT` x86-64;
- `address == 0` coi như thiếu (thường gặp với `NtAllocateVirtualMemory` khi `*BaseAddress` chưa fill).

Congruence yêu cầu **ít nhất một cặp primitive khác loại** có overlap. Ngoại lệ: khi `NtAllocateVirtualMemory` không trả address nhưng có WRITE + EXECUTE cross-process, chuỗi vẫn chấp nhận nếu `operational_kind_count >= 2` và chỉ một loại có range — *safe relaxation*.

### 4.5.3. Deviation D1 (khai báo trung thực)

Execute-level API (`ResumeThread`, `NtCreateThreadEx` không kèm `lpStartAddress`) lịch sử không mang `address`. Fix D1: hook đọc `Rip` từ `CONTEXT` cho `SetThreadContext`, `lpStartAddress` cho `CreateRemoteThread`, `StartRoutine` cho `NtCreateThreadEx` (test `test_set_thread_context_with_rip_overlaps_write_buffer`). Khi execute vẫn thiếu address, congruence suy yếu; luận văn **không claim** precision tương đương paper trên mọi biến thể execute-only.

---

## 4.6. Temporal ordering

### 4.6.1. Quy tắc [4]

Thứ tự canonical **A → W → E**, với hai ngoại lệ: (1) allocate lặp (resize buffer, đổi protection RWX→RX sau khi ghi); (2) gộp bước (section mapping phát sinh W đồng thời với map; thứ tự A–W không xác định từ trace).

### 4.6.2. Formal hóa implementation

Gán bậc:

$$\mathrm{rank}(\texttt{A}) = 0,\; \mathrm{rank}(\texttt{W}) = 1,\; \mathrm{rank}(\texttt{E}) = 3$$

(`CONTEXT_READ` = 2, không gây reject.) Sắp xếp primitive theo timestamp; duyệt tuần tự, với mỗi $\pi \in \{\texttt{A}, \texttt{W}, \texttt{E}\}$:

$$\text{nếu } \mathrm{rank}(\pi) < \mathrm{last\_rank} \text{ và } \pi \in \{\texttt{A}, \texttt{W}\} \Rightarrow \text{reject}$$ (2.17)

Fix D3: từ chối WRITE sau EXECUTE (`test_rejects_write_after_execute_temporal_order`) vì write-sau-execute thường là cập nhật cấu hình hậu injection. Cho phép allocate sau write (re-protect). Gap rank W–E = 2 để chừa khe cho `CONTEXT_READ`.

---

## 4.7. Pipeline file provenance (chống E3)

### 4.7.1. Động cơ né tránh E3

Malware né attribution bằng cách inject vào tiến trình hợp pháp (`msedge.exe`, `explorer.exe`, `svchost.exe`). Detector chỉ nhìn victim sẽ **mất dấu loader gốc** — đặc biệt khi loader tự xoá sau spawn. Paper [4] không xây pipeline file→process cho lab endpoint; lớp provenance là đóng góp của luận văn.

### 4.7.2. Luồng provenance

```
Sysmon E11/E15 (FileCreate)  ──┐
FileDropWatcher (poll)       ──┼→  FileEvent  →  FileTriage
                               │       ↓
Sysmon E1 (ProcessCreate)  ────┘  add_process: created_from_file = image path
                                         ↓
                              add_primitive → Finding.related_file
```

`_related_file_for_process` liên kết theo ưu tiên: (1) `created_from_file` — khớp chính xác image path và file drop; (2) image khớp `files_by_path` (E11 đến sau ProcessCreate); (3) image của parent — fallback. Thứ tự phản ánh độ tin cậy giảm dần.

### 4.7.3. Static triage

Module `triage.py` tính thuộc tính tĩnh: SHA256, entropy Shannon (1 MB đầu — gần 8 gợi ý packed); PE header qua `pefile`, Authenticode qua `signtool`; import injection API đáng ngờ; heuristic thư mục (`%TEMP%`, `%APPDATA%\Local\Temp`, `C:\Windows\Tasks`).

Metadata làm giàu scoring (§4.10) và hỗ trợ analyst truy ngược file drop tới loader dù victim hợp pháp. Triage *lazy*, không quét đệ quy toàn ổ đĩa.

---

## 4.8. Telemetry kép (chống E4)

### 4.8.1. Động cơ né tránh E4

**Direct syscall** (stub `syscall` tự xây thay vì `Nt*` export) và **unhook ntdll** (đọc bản gốc từ đĩa, ghi đè bản hook) né Frida user-mode. Sysmon driver đăng ký kernel callback (`PsSetCreateThreadNotifyRoutine`, `ObRegisterCallbacks`) — Event ID 8/10/11/1 — không phụ thuộc export hook, vẫn hoạt động dưới direct syscall.

### 4.8.2. Ma trận bổ sung

| Tình huống E4 | Frida | Sysmon | Kết quả mong đợi |
|---------------|-------|--------|------------------|
| Win32/NT qua export | Có primitive + address | E8/E10 (context) | Finding đầy đủ |
| Syscall thuần, unhook | Miss primitive | E8/E10 vẫn log | Cảnh báo một phần; **thiếu congruence** |
| File drop + spawn | Miss nếu attach trễ | E11 + E1 | Provenance vẫn có |

Luận văn claim **giảm FN một phần** dưới E4, không claim phát hiện đầy đủ khi chỉ có Sysmon. Sysmon E10 báo mở handle với access mask nhưng không cung cấp `address`/`size`, nên congruence không đầy đủ; finding ở mức cảnh báo (severity giảm).

### 4.8.3. Chế độ spawn

`noirlycan-telemetry spawn` khởi chạy mẫu **dưới Frida từ đầu** (spawn-then-attach), giảm miss primitive đầu (liên quan E6: malware kiểm tra hook khi khởi động và self-terminate, attach-after-spawn bỏ lỡ). Đây là methodology bảo đảm fidelity, không thay anti-evasion E5.

---

## 4.9. Phân loại kỹ thuật injection

Sau khi có Finding, `technique_classifier.py` áp dụng **rule-based classifier** (21+ enum), căn cứ taxonomy §4 của [4] và mở rộng iRed.team:

| Rule (rút gọn) | Kỹ thuật | ATT&CK |
|----------------|----------|--------|
| W section + E resume + CREATE_SUSPENDED | `process_hollowing_section` | T1055.012 |
| CRT + thread_parameter trong write buffer | `dll_injection` | T1055.001 |
| APC + suspended child | `early_bird_apc_injection` | T1055.004 |
| Local A+W RWX, không transfer | `shellcode_injection` / staging | T1055.002 |
| TXF + section | `process_doppelganging` | T1055.013 |
| NtSetInformationFile + section | `process_ghosting` | T1055.012 |

`apply_classification` gọi sau scoring; confidence `high` khi đủ 3 primitive + `execution_confirmed`. Ghosting/Herpaderping phụ thuộc precursor (xoá image sau `NtCreateSection`, rewrite sau map); thiếu precursor, classifier rơi về nhãn tổng quát.

**E5:** classifier không chạy nếu malware không inject do phát hiện VM — out-of-scope; recall trên lab có thể thấp hơn [4] với họ malware có anti-VM mạnh.

---

## 4.10. Mô hình scoring

Điểm 0–100 (`Correlator._score`) **không** thay quy tắc 2-of-3 mà **xếp hạng** finding và lọc `minimum_score` (mặc định 50). Tách *gating logic* khỏi *ranking logic* cho phép tinh chỉnh ngưỡng mà không phá định nghĩa khoa học.

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

Severity: CRITICAL ≥ 85, HIGH ≥ 70, MEDIUM ≥ 50. Score ≥ 70 kích hoạt **network watch** 300s trên `target_pid` (Sysmon E3).

Heuristic giảm FP: `_resume_only_spawn_to_trusted_target` cap score ≤ 50 khi chỉ có ResumeThread vào Program Files mà không kèm write/context — pattern installer hợp pháp.

---

## 4.11. Thuật toán (pseudo-code)

### Thuật toán 4.1 — Ánh xạ API → primitive

```
function MAP_API(api):
    for class in PAPER_API_CLASSES ∪ IRED_TEAM_API_CLASSES:
        if api in class.apis:
            return OBSERVATION_ONLY if class.primitive=="observation" else class.primitive
    return UNKNOWN

function ON_API_CALL(api, args, retval):
    if not success(retval): return
    kind ← MAP_API(api)
    if kind == OBSERVATION_ONLY: emit api_observation(...); return
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
    P ← bucket[(actor, target)]; K ← {p.kind | p∈P} \ {CONTEXT_READ}
    if |K ∩ {A,W,E}| < 2 or not TEMPORAL_OK(P) or not CONGRUENCE_OK(P): return []
    score, evidence ← SCORE(P, related_process, related_file)
    if score < minimum_score or score ≤ previous_reported_score: return []
    finding ← Finding(..., apply_classification(...))
    if score ≥ 70: enable_network_watch(target)
    return [finding]
```

### Thuật toán 4.3 — Congruence

```
function CONGRUENCE_OK(P):
    ranges_by_kind ← group memory_link_ranges(p) for p in P
    if count_linked_primitives < 2: return TRUE
    for (kind1,kind2) with kind1≠kind2, r1∈ranges[kind1], r2∈ranges[kind2]:
        if overlap(r1, r2): return TRUE
    if |operational_kinds| ≥ 2 and only WRITE has ranges: return TRUE
    return FALSE
```

### Thuật toán 4.4 — File provenance

```
function ADD_PROCESS(proc):
    if normalize(proc.image) in files_by_path: proc.created_from_file ← path
    processes_by_pid[proc.pid] ← proc

function RELATED_FILE(proc):
    if proc.created_from_file: return files[proc.created_from_file]
    if proc.image in files: return files[proc.image]
    if parent exists: return files[parent.image]
    return NULL
```

---

## 4.12. Ranh giới phương pháp so với [4]

| Khía cạnh | [4] | Luận văn (Noirlycan) |
|-----------|-----|----------------------|
| 2-of-3 + congruence + temporal | ✅ | ✅ (có test) |
| Equivalence class | Table 1 đầy đủ | `PAPER_API_CLASSES` + lab extension |
| Anti-evasion E5 | ✅ Tích hợp | ❌ **Không hiện thực** — chỉ ghi `kernel/analysis/evasion.py` signal |
| Dataset 56k + prevalence | ✅ | ❌ Ngoài phạm vi |
| File provenance E3 | ❌ | ✅ Đóng góp |
| Real-time endpoint | ❌ | ✅ Đóng góp |
| Recursive chain metric ~2% | ✅ | ⚠️ `InjectionGraph` một phần |

Luận văn không claim số 16,5 % hay 21,2 % của [4]; các con số đó phụ thuộc module anti-evasion chưa triển khai. Mọi cải tiến trên lab phải được hiểu trong phạm vi E1–E4.

---

## 4.13. Ví dụ đi sâu: phân tích chuỗi section-mapping

Xét chuỗi cross-process vào `msedge.exe` (case study *neurevt* [4], test `test_detects_section_mapping_write_execute_chain`):

**B1 — Provenance:** Sysmon E11 ghi `loader.exe` trong `%TEMP%`. Triage: PE=True, signed=False, entropy=7,2. Khi loader spawn (E1, `CREATE_SUSPENDED`), `add_process` gắn `created_from_file`.

**B2 — W:** Hook bắt `NtMapViewOfSection` với `target_pid`=Edge, `address`=0x200000, `protection`=EXECUTE_READWRITE. Map remote vừa write vừa expose vùng executable — không cần `VirtualAllocEx` riêng.

**B3 — Gating:** $K=\{\texttt{W},\texttt{E}\}$, $|K|=2$ thỏa (4.1); ResumeThread sau MapView thỏa temporal; congruence chấp nhận khi đủ operational kinds.

**B4 — Scoring:** +45 (W+E confirmed) +15 (cross-process) +10 (section) +15 (SUSPENDED) +10 (related_file) +10 (unsigned) ≥ 70 (HIGH).

**B5 — Classifier:** W+E resume → `section_mapping_injection` (hoặc hollowing nếu thêm context).

Baseline `VirtualAllocEx→WriteProcessMemory→CreateRemoteThread` không match — minh chứng giá trị phương pháp [4] dưới E2.

## 4.14. Ví dụ đi sâu: classic DLL injection (E1)

Malware E1 thay `CreateRemoteThread` bằng `NtCreateThreadEx`:

1. `VirtualAllocEx` → A, range $r_a$
2. `WriteProcessMemory` ghi đường dẫn DLL → W, $r_w$ overlap $r_a$
3. `NtCreateThreadEx` với `StartRoutine = LoadLibraryW`, `Argument = r_a` → E, `thread_parameter` overlap $r_w$

Equivalence class map cả ba vào $\{\texttt{A},\texttt{W},\texttt{E}\}$ dù tên khác Win32. Congruence qua $r_a \cap r_w$ và $r_w \cap \text{thread\_parameter}$. Pattern `_dll_path_remote_thread_pattern` tăng +5 score; classifier kết luận `dll_injection` (T1055.001).

## 4.15. Self-injection và local staging

Paper [4] tập trung cross-process; Noirlycan mở rộng `actor_pid == target_pid` (self-injection, dùng để decode payload trước khi inject ra ngoài): `VirtualAlloc` + `memcpy` local RWX → A+W, evidence `local_staging`. Config `.classifier_rules.json` có thể bật `ignore_same_process_findings` để giảm FP từ installer/JIT. Phương pháp vẫn áp 2-of-3 nguyên vẹn; scoring ưu tiên cross-process (+15).

## 4.16. CONTEXT_READ — extension lab

`GetThreadContext`/`NtGetContextThread` hook với kind `CONTEXT_READ` để hỗ trợ classifier, không làm primitive thứ tư: không đếm vào $|K|$; +5 score khi hijack prep chưa confirmed; classifier dùng `context_read + SET_SUSPENDED` để nhãn `thread_hijack` hoặc `process_hollowing_classic`. Khai báo rõ để tránh hiểu nhầm là primitive thứ tư của [4] (deviation D7).

## 4.17. Chiến lược giảm false positive

| Heuristic | Mục đích |
|-----------|----------|
| `minimum_score` ≥ 50 | Lọc chuỗi yếu |
| `_resume_only_spawn_to_trusted_target` | Cap 50 — installer resume Edge/Program Files |
| `missing_execution_transfer` cap 75 | Staging chưa execute |
| `require_cross_process_findings` (config) | Lab chỉ báo inject cross-process |
| Network watch chỉ khi score ≥ 70 | Tránh alert noise |

Đây là **lab tuning**, không thay định nghĩa 2-of-3 [4]: chỉ điều chỉnh mức trình bày, không thêm/bớt điều kiện logic cốt lõi.

## 4.18. Liên hệ MITRE ATT&CK

Technique classifier ánh xạ finding sang sub-technique T1055 để tích hợp threat-informed defense:

| Pattern primitive + evidence | ATT&CK (ví dụ) |
|------------------------------|----------------|
| CRT + LoadLibrary remote | T1055.001 DLL injection |
| APC + suspended | T1055.004 Asynchronous Procedure Call |
| Section + resume | T1055.012 Process Hollowing |
| SetWindowsHookEx | T1055.004 Hook injection |
| TxF + section | T1055.013 Process Doppelgänging |

Phân loại tách biệt với 2-of-3; lỗi nhãn không làm mất finding.

## 4.20. So sánh pipeline [4] và Noirlycan

**Bảng 4.3.** Pipeline phân tích — paper vs luận văn

| Giai đoạn | [4] Sap4Sec | Noirlycan |
|-----------|-------------|-----------|
| Môi trường thực thi | QEMU sandbox batch | Windows 10/11 VM lab |
| Thu thập trace | API logger toàn process tree | Frida hook + Sysmon events |
| Anti-evasion E5 | Có — patch env/timing | **Không** |
| Phân tích | Offline analyzer Python | Online Correlator 300s window |
| Đầu ra | Label + technique + log | Finding JSONL + dashboard |
| Provenance file | Không | FileCreate + triage + lineage |
| Quy mô đánh giá | 56.340 mẫu | 31 unit test + case study |

Noirlycan **operationalize** phương pháp [4] cho analyst endpoint và bổ sung E3/E4; không thay thế nghiên cứu thống kê của paper.

## 4.21. Giả định phương pháp (M1–M5)

| ID | Giả định | Ảnh hưởng |
|----|----------|-----------|
| M1 | API qua export hookable hoặc Sysmon-visible | E4 partial |
| M2 | Injection trong cửa sổ 300s | Expiration |
| M3 | User-mode injection | Không kernel primitive |
| M4 | Lab cô lập | E5 không cần fake production |
| M5 | Frida fidelity chấp nhận | RQ5 — cần đo |

Vi phạm M1 (syscall thuần + unhook ntdll + tránh API có Sysmon callback) → 2-of-3 không khả dụng. Vi phạm M2 (*time bomb* > 300s) → correlator hết hạn primitive đầu.

## 4.22. Mở rộng tương lai phương pháp

Ba hướng ngoài phạm vi luận văn:

1. **ETW Threat Intelligence provider** — thay/đi cùng Frida, giảm E4/E6 vì ETW-TI cung cấp sự kiện kernel cho `VirtualAllocEx`, `WriteProcessMemory`, `SetThreadContext`; ánh xạ về cùng equivalence class [4].
2. **ML trên chuỗi primitive** — embedding API sequence thay rule classifier; yêu cầu dataset lớn và đánh giá robustness.
3. **Anti-evasion E5 port** — tích hợp module patch timing/CPUID/registry từ Sap4Sec [11] để so sánh recall trên Paper-Subset.

## 4.23. Giám sát mạng hậu injection

Sau khi finding đạt score ≥ 70, phương pháp kích hoạt **network watch** trên `target_pid` 300s. Sysmon E3 lọc theo PID, chỉ lưu connection từ PID victim. Mục tiêu: bắt beacon sau khi payload chạy trong tiến trình hợp pháp.

Heuristic `is_external_beacon_candidate` đánh dấu IP/hostname ngoài RFC1918; kết nối nội bộ giữ lại cho phân tích lateral movement nhưng không nâng severity. Module `network.py` và test `test_network_watch.py` xác nhận chỉ connection trong cửa sổ watch mới correlate với finding.

## 4.24. Tóm tắt chương

Chương 4 trình bày phương pháp phát hiện process injection: kế thừa operational primitive và 2-of-3 của [4] chống E1, E2; bổ sung memory congruence và temporal ordering dưới dạng phát biểu hình thức và pseudo-code; mở rộng pipeline provenance file (E3) để truy ngược loader từ victim hợp pháp; telemetry kép Sysmon–Frida (E4) duy trì khả năng phát hiện khi user-mode hook bị né. Module anti-sandbox (E5) **không hiện thực** — hạn chế thảo luận ở Chương 6 và 7. Chương 5 mô tả hiện thực các module trong artifact Noirlycan.
