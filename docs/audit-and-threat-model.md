# Audit code-vs-paper và Threat Model formal

**Phạm vi:** Đối chiếu implementation của `NoirlycanThesis` với phương pháp
phát hiện process injection trong:

> Di Pietro, G., D'Elia, D. C., & Querzoni, L. (2025).
> *Can You Run My Code? A Close Look at Process Injection in Windows Malware.*
> ASIA CCS '25, Hanoi. DOI: [10.1145/3708821.3736206](https://doi.org/10.1145/3708821.3736206).
> Artifact: [github.com/Sap4Sec/process-injection](https://github.com/Sap4Sec/process-injection).

Tài liệu này phục vụ chương *Methodology Validation* và chương *Threat Model*
của luận văn — đủ formal cho hội đồng.

---

## 1. Phương pháp audit

| Khía cạnh | Cách kiểm chứng |
|-----------|-----------------|
| Quy tắc phương pháp | Đọc paper §3 + artifact `Sap4Sec/process-injection` (analyzer rules) |
| Implementation repo | Đọc trực tiếp `correlation.py`, `execution_analysis.py`, `technique_classifier.py`, `injection_api_manifest.py`, `models.py` |
| API equivalence classes | Đối chiếu danh sách trong [injection_api_manifest.py](../src/noirlycan_telemetry/injection_api_manifest.py) `PAPER_API_CLASSES` với Table 1 của paper |
| Quy tắc 2/3 | Kiểm `_find_injection_chains()` + test `test_requires_two_distinct_primitives` |
| Memory congruence | Kiểm `_has_memory_congruence` + test `test_rejects_unrelated_memory_ranges` |
| Temporal ordering | Kiểm `_has_temporal_consistency` |
| Section mapping case | Kiểm test `test_detects_section_mapping_write_execute_chain` |
| Phân loại kỹ thuật | Đối chiếu [technique_classifier.py](../src/noirlycan_telemetry/technique_classifier.py) với taxonomy §4 của paper |

Ký hiệu kết luận:
- ✅ **Đúng phương pháp** — implementation trung thành với paper.
- ⚠️ **Lệch nhẹ / lab extension** — không sai về mặt khoa học, nhưng phải khai báo trong threat model.
- ❌ **Lệch nguy hiểm** — có thể gây false positive/negative hoặc sai diễn giải khoa học. Cần fix trước khi báo cáo kết quả.

---

## 2. Audit từng quy tắc

### 2.1. Ba operational primitive (Paper §3.1)

**Paper:** Process injection = ba thao tác *operational* trên cùng vùng nhớ của
victim — *allocate* (chuẩn bị vùng nhớ và quyền), *write* (đặt payload vào đó),
*execute* (khởi sự thực thi từ đó). Mỗi primitive ánh xạ một *lớp tương đương*
gồm các Windows API có ngữ nghĩa tương đương.

**Repo:** `PrimitiveKind` trong [models.py:16-21](../src/noirlycan_telemetry/models.py)
định nghĩa `ALLOCATE / WRITE / EXECUTE / CONTEXT_READ`.

| Mục | Trạng thái | Ghi chú |
|---|---|---|
| 3 primitive paper | ✅ | Khớp định nghĩa Klein et al. mà paper dựa vào. |
| Thêm `CONTEXT_READ` | ⚠️ Lab extension | `GetThreadContext` không phải primitive của paper. Repo dùng để đánh dấu giai đoạn *hijack-prep*. **Không tính** vào quy tắc 2/3 (xem [execution_analysis.py:108-111](../src/noirlycan_telemetry/execution_analysis.py)) — đúng cách. Phải khai báo rõ trong luận văn rằng đây là chỉ báo bổ trợ, không phải primitive thứ tư. |

### 2.2. API equivalence classes (Paper Table 1)

**Repo:** [`PAPER_API_CLASSES`](../src/noirlycan_telemetry/injection_api_manifest.py).

| Lớp | Khớp paper | Lệch |
|-----|-----------|------|
| allocate | `VirtualAllocEx`, `NtAllocateVirtualMemory`, `VirtualProtectEx`, `NtProtectVirtualMemory`, `NtCreateSection`, `CreateFileMappingA/W`, `MapViewOfFile(Ex)` | ⚠️ Paper xếp `NtCreateSection` thuộc *allocate* hay *write* tùy cách dùng. Repo cố định ở *allocate* — chấp nhận được nhưng ghi chú rõ. |
| write | `WriteProcessMemory`, `NtWriteVirtualMemory`, `NtMapViewOfSection`, `NtUnmapViewOfSection`, `RtlCopyMemory`, `CopyMemory` | ⚠️ Paper **không** coi `NtReadVirtualMemory`/`ReadProcessMemory` là write — repo gom vào để bắt remote read trong reflective patterns. Cần ghi rõ deviation, có thể gây inflation primitive count. ❌ **Khuyến nghị fix**: tách `READ` thành kind riêng hoặc bỏ khỏi class write. |
| execute | CRT/APC/Resume/SetContext/LoadLibrary/Hook/Atom/AddAtom | ✅ Bao phủ đầy đủ; mở rộng *fiber/threadpool/atom* lấy từ iRed.team đã tách lớp riêng. |
| process_spawn / process_access / dynamic_resolve | ⚠️ Phụ trợ, không phải primitive paper | Repo dùng làm context flag, đúng cách. |

**Deviation đáng chú ý**:
- `LoadLibrary*` được paper liệt kê là *execute* khi remote → ✅ giống repo.
- Repo thêm `VirtualProtect` (local) thông qua `IRED_TEAM_API_CLASSES` → ⚠️ lab-only, khai báo.

### 2.3. Quy tắc 2-of-3 (Paper §3.2)

**Paper:** Để giảm phụ thuộc vào việc quan sát đủ cả ba bước (malware thường che
giấu hoặc lùi việc write/execute), paper yêu cầu **quan sát ít nhất 2 trong 3
primitive trên cùng vùng nhớ trong cùng actor→target**.

**Repo:**
```python
# correlation.py:88-94
kinds = {primitive.kind for primitive in primitives}
if operational_kind_count(kinds) < 2:
    continue
if not _has_temporal_consistency(primitives):
    continue
if not _has_memory_congruence(primitives):
    continue
```
`operational_kind_count` chỉ đếm `ALLOCATE/WRITE/EXECUTE`, loại trừ `CONTEXT_READ`
([execution_analysis.py:108-111](../src/noirlycan_telemetry/execution_analysis.py)).

| Mục | Trạng thái |
|---|---|
| Yêu cầu ≥2 primitive **khác loại** | ✅ |
| Loại CONTEXT_READ khỏi đếm | ✅ |
| Nhóm theo `(actor_pid, target_pid)` | ✅ Đúng tinh thần paper. |
| Trường hợp `target_pid is None` (self-inject) | ⚠️ Repo gom riêng nhánh, đúng nhưng paper tập trung cross-process — phải nói rõ self-inject là mở rộng. |

### 2.4. Memory range congruence (Paper §3.3)

**Paper:** Hai primitive được coi là tương ứng *cùng vùng nhớ* nếu khoảng địa chỉ
của chúng giao nhau hoặc chứa nhau. Mục đích: chống false positive khi cùng
process thực hiện nhiều thao tác độc lập (vd. heap allocations song song).

**Repo:** [`_has_memory_congruence`](../src/noirlycan_telemetry/correlation.py)
+ `_ranges_overlap_or_contain`:
```python
left_end = left.address + left_size
right_end = right.address + right_size
return left_start < right_end and right_start < left_end
```

| Mục | Trạng thái | Ghi chú |
|---|---|---|
| Overlap / contain | ✅ | Toán tử khoảng mở chuẩn. |
| Primitive thiếu address (size=None → coi là 1 byte) | ⚠️ | Execute APIs (`ResumeThread`, `CreateRemoteThread`) **không có address** vì là thread-level. Code rẽ nhánh trả `True` nếu <2 primitive có address ([correlation.py:312-313](../src/noirlycan_telemetry/correlation.py)) → đồng nghĩa **bỏ qua kiểm congruence khi execute không gắn address**. Đây là **deviation thực dụng** so với paper (paper dùng tracking thread→start address). **Phải khai báo** trong luận văn; gợi ý: nếu `CreateRemoteThread`, gắn `lpStartAddress` làm `address` trong Frida hook để giữ đúng quy tắc paper. |
| Cross-kind only (`if left_kind == right_kind: continue`) | ⚠️ | Paper cho phép so vùng bất kỳ. Repo chỉ so giữa các kind khác nhau — đủ cho mục đích link allocate↔write↔execute, nhưng có thể bỏ sót *write→write* trên cùng vùng. Tài liệu hóa. |

❌ **Khuyến nghị fix nghiêm túc**: Trong Frida hook `windows_injection_hooks.js`,
khi hook `CreateRemoteThread/Ex` và `NtCreateThreadEx`, đọc `lpStartAddress`
(arg thứ 4 của `CreateRemoteThread`) và đính kèm làm `address` của primitive
`EXECUTE`. Hiện tại execute không có address → vô tình *bypass congruence*. Đây
là **deviation lớn nhất so với paper**.

### 2.5. Temporal ordering (Paper §3.4)

**Paper:** Yêu cầu thứ tự allocate → write → execute. Cho phép gộp bước (vd.
`NtCreateSection + NtMapViewOfSection` = allocate ∧ write đồng thời). Cho phép
allocate lặp (vd. resize, RWX→RX flip).

**Repo:** [`_has_temporal_consistency`](../src/noirlycan_telemetry/correlation.py:291-307)
gán bậc `ALLOCATE=0, WRITE=1, CONTEXT_READ=2, EXECUTE=3` và chỉ reject khi gặp
một ALLOCATE *sau khi* đã thấy bậc cao hơn.

| Mục | Trạng thái |
|---|---|
| Cho phép allocate lặp | ✅ |
| Cho phép write trước execute | ✅ |
| Reject execute → allocate → write (out of order) | ⚠️ Chỉ reject nếu chính ALLOCATE đi lùi. Paper thực ra cũng cho phép re-protect (allocate kind) đi sau write — đúng tinh thần. |
| Vị trí CONTEXT_READ giữa write và execute | ⚠️ Lab extension; trung tính. |

❌ **Lỗi nhỏ cần fix**: Hàm trả `True` ngay cả khi primitives **chỉ có
WRITE+EXECUTE không có ALLOCATE** và write đến sau execute. Test:
```
EXECUTE(t=1)  WRITE(t=2)   → trả True  # SAI
```
Vì chỉ ALLOCATE mới triggers reject. Đề xuất: ép thứ tự tăng đơn điệu cho mọi
kind paper (allocate/write/execute), CONTEXT_READ thì miễn trừ. Tham khảo:
```python
if current < last_seen and primitive.kind in {ALLOCATE, WRITE, EXECUTE}:
    return False
```

### 2.6. Section mapping case (Paper §3.5, case study *neurevt*)

**Paper:** `NtCreateSection + NtMapViewOfSection(remote)` thay cho cặp
allocate+write tách rời; sau đó `SetThreadContext + ResumeThread` đóng vai trò
execute. Paper coi đây là biến thể dominant của Process Hollowing.

**Repo:** Test `test_detects_section_mapping_write_execute_chain`
([test_correlation.py:14-69](../tests/test_correlation.py)) tạo đúng kịch bản
`NtMapViewOfSection + ResumeThread` cross-process vào `msedge.exe` và kỳ vọng
finding score ≥ 70. ✅ Khớp paper.

### 2.7. Recursive / multi-stage injection (Paper §5.3)

**Paper:** ~2% mẫu trong dataset thực hiện inject lồng (A→B→C). Paper theo dõi
chain bằng cách *re-trace* khi victim được resume.

**Repo:** [`injection_graph.py`](../src/noirlycan_telemetry/injection_graph.py)
ghi chuỗi và set `is_recursive`. Frida `--auto-attach-new-processes` cố attach
vào victim mới. ⚠️ **Một phần** — chưa có metric/báo cáo prevalence như paper.

### 2.8. Anti-evasion (Paper §6)

**Paper:** Có module anti-evasion tích hợp (bypass timing checks, env checks)
để tránh malware skip injection trong sandbox. Ablation: +21.2% mẫu phát hiện
được nhờ anti-evasion.

**Repo:** [`evasion.py`](../src/noirlycan_telemetry/evasion.py) ghi signal nhưng
không bypass. ❌ **Lệch lớn** với paper — cần khai báo rõ là **out of scope**
trong luận văn, hoặc tích hợp một subset (vd. timing patch).

### 2.9. Phân loại 12 kỹ thuật (Paper §4)

**Paper:** Liệt kê và phân loại các kỹ thuật chính: Classic Remote Thread,
APC, Early Bird APC, SetWindowsHookEx, Thread Hijacking, Process Hollowing
(classic + section variant), AtomBombing, Reflective DLL, Module Stomping,
Process Doppelgänging, Process Ghosting/Herpaderping (mới).

**Repo:** [`technique_classifier.py`](../src/noirlycan_telemetry/technique_classifier.py)
có 21 enum, bao gồm các kỹ thuật của paper + mở rộng (fiber, threadpool,
extra-window-memory, atom). ✅ Bao phủ đủ paper + hơn.

| Lỗi tiềm năng | Vị trí |
|---|---|
| ❌ Reflective DLL detector loại bỏ khi thấy `LoadLibrary*` — đúng heuristic, nhưng paper coi *manual map* + `LdrLoadDll` cũng là reflective. Cần xét. | [technique_classifier.py:365-380](../src/noirlycan_telemetry/technique_classifier.py) |
| ❌ Process Ghosting / Herpaderping **chưa có** trong enum. Paper có nhắc — bổ sung sẽ tăng độ phủ. | enum thiếu |
| ⚠️ Confidence dựa trên `len(kinds) >= 3` — không có ground-truth dataset đánh giá precision. | `_confidence_from_kinds` |

### 2.10. Bảng tổng hợp deviation

| # | Quy tắc paper | Repo | Mức |
|---|---|---|---|
| D1 | EXECUTE primitive gắn vùng nhớ (`lpStartAddress`) để check congruence | EXECUTE thường address=None → bỏ congruence | ❌ **Quan trọng** |
| D2 | `Read*VirtualMemory` không thuộc *write* | Repo gom vào *write* | ❌ |
| D3 | Temporal: reject mọi đảo bậc allocate/write/execute | Chỉ reject khi ALLOCATE lùi | ❌ Nhẹ |
| D4 | Anti-evasion tích hợp | Chỉ ghi signal | ❌ |
| D5 | Process Ghosting/Herpaderping trong taxonomy | Thiếu enum | ⚠️ |
| D6 | Recursive chain — báo cáo prevalence metric | Có graph, thiếu metric | ⚠️ |
| D7 | CONTEXT_READ là primitive thứ 4 | Có nhưng không tính 2/3 — đúng | ✅ (cần khai báo) |
| D8 | Section/CreateFileMapping xếp vào *allocate* hay *write* | Repo cố định *allocate* | ⚠️ (khai báo) |

---

## 3. Threat Model formal

> *Mục đích: định nghĩa rõ tài sản, đối thủ, năng lực, giả định, và phạm vi tin
> cậy — đủ để hội đồng đánh giá scope khoa học của luận văn.*

### 3.1. Hệ thống quan tâm (System Under Analysis)

Một host Windows 10/11 trong **lab cô lập**, có cài đặt:

| Thành phần | Privilege | Cơ chế |
|------------|-----------|--------|
| `SysmonDrv.sys` (kernel driver của Sysmon) | **kernel-mode (ring 0)** | `PsSetCreateProcessNotifyRoutineEx`, `PsSetLoadImageNotifyRoutine`, `ObRegisterCallbacks` (`PsProcessType`/`PsThreadType`), Minifilter `FltRegisterFilter`, ETW Threat Intelligence provider |
| `Sysmon.exe` service | user-mode (LocalSystem) | Đăng ký event với driver, ghi ra Windows Event Log |
| Frida instrumentation | **user-mode** (trong target process) | Interceptor.attach trên `kernel32.dll`/`ntdll.dll` exports |
| Python collector (`noirlycan-telemetry`) | user-mode | Đọc Sysmon Event Log + Frida message bus |
| Target process | user-mode | Mẫu loader: section-mapping / file-drop / ... |

**Hệ quả quan trọng cho threat model:** Hai lớp telemetry có *khả năng kháng bypass khác nhau*. Sysmon nhìn từ kernel callbacks ⇒ resistant với user-mode unhooking và direct syscall. Frida nhìn từ user-mode hook ⇒ có thể bị bypass. Xem §3.8 *Telemetry Layer Trust Matrix* để chi tiết.

### 3.2. Tài sản cần bảo vệ (Assets)

| ID | Tài sản | Mục đích |
|---|---|---|
| A1 | Tính toàn vẹn telemetry | Findings phải phản ánh thực tế host. |
| A2 | Tính sẵn sàng của collector | Không bị crash bởi mẫu phân tích. |
| A3 | Tính cô lập lab | Mẫu không vượt ra ngoài VM (không phải mục tiêu prototype, nhưng nêu để hội đồng rõ ranh giới). |

### 3.3. Đối thủ (Adversary Model)

**Loại đối thủ:** Tác giả malware Windows user-mode (Tier 2 theo phân loại
Microsoft SDL). Mục tiêu inject payload vào tiến trình khác để evasion/persistence.

**Năng lực giả định CÓ:**
- C1. Gọi mọi Win32 / NT API user-mode.
- C2. Dùng section mapping (`NtCreateSection + NtMapViewOfSection`) thay cho
  `VirtualAllocEx + WriteProcessMemory`.
- C3. `CreateProcess(CREATE_SUSPENDED)` + `SetThreadContext` + `ResumeThread`
  cho hollowing.
- C4. Tải DLL từ disk (`LoadLibrary*`) hoặc reflective.
- C5. Encrypt payload trong resource và giải mã runtime.
- C6. Drop file thực thi xuống đĩa rồi spawn.
- C7. Một mức evasion *thụ động*: kiểm tra debugger qua `IsDebuggerPresent`,
  `NtQueryInformationProcess`, timing checks.

**Năng lực giả định KHÔNG có (out of scope):**
- O1. Direct syscall stub bỏ qua *user-mode* hook — Frida sẽ miss API-arg
  granularity; nhưng kernel-side telemetry (Sysmon Event 8/10/1) **vẫn bắt
  được** ProcessAccess / CreateRemoteThread / ProcessCreate (xem §3.8).
- O2. Unhooking ntdll trước khi inject — cùng phạm vi như O1; Sysmon vẫn thấy
  cross-process artifact ở kernel callback.
- O3. **Đối thủ chạy kernel-mode** (kernel rootkit / signed-driver abuse /
  BYOVD): có thể tắt/lừa Sysmon driver, vô hiệu hóa cả hai lớp telemetry.
  Cả paper lẫn repo đều coi đây là out-of-scope; defender giả định Secure
  Boot + HVCI bật + chỉ ký driver hợp lệ được load.
- O4. Side-channel / TOCTOU exploit chống chính collector.
- O5. Anti-Frida cụ thể (kiểm `frida-agent`, gum, libffi).
- O6. ~~Process Ghosting / Herpaderping~~ — sau mở rộng iRed taxonomy đã cover.
- O7. Sandbox-aware evasion chủ động (D4).

### 3.4. Giả định môi trường (Environmental Assumptions)

| ID | Giả định | Tác động nếu vi phạm |
|---|---|---|
| E1 | Sysmon đang chạy với config repo cung cấp | Mất event 1/7/8/10/11 → giảm provenance, không ảnh hưởng phát hiện primitive. |
| E2 | Frida attach trước khi tiến trình target gọi API injection | Nếu late-attach, mất primitive đầu chuỗi → false negative. README đã cảnh báo. |
| E3 | Tiến trình target không direct-syscall | Vi phạm → tất cả hook miss → false negative toàn bộ. |
| E4 | Đồng hồ host monotonic trong window 300s | Vi phạm → temporal ordering có thể sai. |
| E5 | Không có process khác trong host gây nhiễu cùng (actor_pid, target_pid) | Vi phạm → có thể false positive (gom nhầm chain). |
| E6 | VM cô lập, không có dữ liệu/credentials thực | Vi phạm → rủi ro lab. |

### 3.5. Giả định khoa học (Methodological Assumptions)

| ID | Giả định | Nguồn |
|---|---|---|
| M1 | 3 primitive *allocate/write/execute* trên cùng vùng nhớ là đủ để mô tả injection user-mode | Klein et al. 2017; paper §3 |
| M2 | Quan sát ≥ 2/3 primitive đủ để kết luận injection với precision chấp nhận được | Paper §3.2 (claimed 16.5% prevalence; chưa đo lại trong repo) |
| M3 | API trong cùng equivalence class có ngữ nghĩa thay thế được | Paper Table 1 |
| M4 | Memory range overlap/contain là proxy hợp lý cho *same buffer* | Starink et al. 2023; paper §3.3 |
| M5 | Frida user-mode hook chính xác về argument và thứ tự gọi | Frida documentation; benchmark M5 protocol — xem [docs/experiments/frida-fidelity.md](experiments/frida-fidelity.md) |
| M6 | Sysmon kernel callbacks không bị attacker user-mode chỉnh sửa | Driver chạy ring 0, ETW TI provider chỉ ghi từ kernel; chỉ kernel rootkit (O3) phá được |

❌ **M5 cần justification**: luận văn nên có một thí nghiệm nhỏ chứng minh Frida
không drop event dưới load (vd. so output Frida vs ETW/`SilkETW` cho 1000 calls).

### 3.6. Phạm vi tin cậy (Trust Boundary)

```
┌────────────────────────────────────────────────────┐
│  Host Windows lab VM (UNTRUSTED — chứa malware)   │
│  ┌───────────────────────┐                         │
│  │  Target process       │  ←─ Frida injects agent │
│  │  (loader, msedge...)  │     (TRUSTED if E3 đúng)│
│  └───────────────────────┘                         │
│  ┌───────────────────────┐                         │
│  │  Sysmon driver        │  (TRUSTED — kernel)     │
│  └───────────────────────┘                         │
│  ┌───────────────────────┐                         │
│  │  Collector Python     │  (TRUSTED)              │
│  └───────────────────────┘                         │
└────────────────────────────────────────────────────┘
       │ JSONL session log (TRUSTED if file ACL đúng)
       ▼
   Analyst workstation (TRUSTED)
```

### 3.7. Threats & Mitigations

| ID | Threat | Mức | Mitigation hiện có | Mitigation đề xuất luận văn |
|---|---|---|---|---|
| T1 | Direct syscall bỏ qua Frida hook (API-arg layer) | Cao | **Sysmon kernel callbacks vẫn bắt được Event 1 (ProcessCreate), 8 (CreateRemoteThread), 10 (ProcessAccess), 11 (FileCreate)** — fallback một phần. Mất chi tiết argument (address/size). | Bổ sung **ETW Threat Intelligence** provider (kernel ETW, không bypass được bằng user-mode syscall stub) để lấy lại syscall-level granularity. |
| T2 | Late attach miss primitive đầu chuỗi | Cao | `spawn` mode | Khuyến nghị mặc định `spawn` cho thí nghiệm; auto-attach chỉ cho file-drop. |
| T3 | EXECUTE primitive không có address → bypass congruence (D1) | Trung | Không | Fix: hook đọc `lpStartAddress` cho `CreateRemoteThread*`/`NtCreateThreadEx`. |
| T4 | Frida agent bị detect → malware abort | Trung | Không | Out-of-Scope (O5); ghi nhận limitation. |
| T5 | Anti-evasion che injection (D4) | Cao | Chỉ ghi signal | Out-of-Scope; nêu rằng prevalence số liệu repo sẽ thấp hơn paper. |
| T6 | Read primitive lẫn vào write count (D2) | Trung | Không | Fix manifest. |
| T7 | Temporal ordering quá lỏng (D3) | Thấp | Không | Fix `_has_temporal_consistency`. |
| T8 | Concurrent process gây actor/target collision (E5) | Thấp | Window 300s + cặp PID | Đo trên dataset thực, báo cáo. |
| T9 | Kernel-mode injection (driver / APC kernel) | Cao | Không | Out-of-Scope (O3); paper cũng không phủ. |

### 3.8. Ma trận tin cậy theo lớp telemetry (Telemetry Layer Trust Matrix)

> Mục mới — bổ sung sau phản biện rằng Sysmon = kernel-mode, không cùng lớp với
> Frida = user-mode. Phân tách hai lớp giúp luận văn nêu chính xác cái gì bypass
> được cái gì.

| Telemetry source | Privilege | Cơ chế bắt | Bị bypass bởi | Phạm vi quan sát | Vai trò trong correlator |
|------------------|-----------|------------|----------------|------------------|--------------------------|
| **Sysmon Event 1** (ProcessCreate) | kernel | `PsSetCreateProcessNotifyRoutineEx` | Kernel rootkit (O3) | Mọi process create trong host | Lineage, `created_from_file`, `CREATE_SUSPENDED` flag |
| **Sysmon Event 7** (ImageLoad) | kernel | `PsSetLoadImageNotifyRoutine` | Kernel rootkit | Mọi DLL/PE map vào process | Phát hiện reflective vs `LoadLibrary` |
| **Sysmon Event 8** (CreateRemoteThread) | kernel | ETW Threat Intelligence | Kernel rootkit | Cross-process thread creation **kể cả direct syscall** | Fallback khi Frida miss `CreateRemoteThread*` |
| **Sysmon Event 10** (ProcessAccess) | kernel | `ObRegisterCallbacks(PsProcessType)` | Kernel rootkit | `OpenProcess` với `PROCESS_VM_WRITE` etc. **kể cả direct syscall** | Fallback cross-process handle acquisition |
| **Sysmon Event 11** (FileCreate) | kernel | Minifilter `FltRegisterFilter` | Kernel rootkit | File create executable / script | File provenance |
| **Sysmon Event 3** (Network) | kernel | ETW WFP layer | Kernel rootkit | TCP/UDP connections | Post-injection beacon |
| **Frida hooks** | **user** | `Interceptor.attach` vào export ntdll/kernel32 | **Direct syscall (O1), unhooking (O2), anti-Frida (O5)** | NT API args (address, size, protection) | Primitive-level detail, memory congruence input |
| **Static triage** | user | Đọc file trên đĩa | Encrypted/packed payload | SHA256, PE header, entropy, signature | Payload classification |

**Kết luận quan trọng cho thesis:** Khi đối thủ direct-syscall (O1), Noirlycan
**không mù hoàn toàn** như threat model phiên bản trước đã nói nhầm. Frida mất
granularity, nhưng Sysmon (kernel) vẫn báo *something happened cross-process*.
Hệ quả:

- **Detection vẫn khả thi** ở mức "có injection vào target X" với confidence
  giảm (chỉ còn 2 primitive: process_access + execute) — recall giảm nhưng
  không về 0.
- **Phân loại kỹ thuật** (`technique_classifier`) sẽ giảm precision vì không có
  API name + argument để phân biệt section_mapping vs shellcode chain.
- **Memory congruence** mất toàn bộ vì Sysmon không cung cấp address/size.

Đây là *graceful degradation* — luận văn nên trình bày như một điểm thiết kế,
không phải hạn chế ẩn.

### 3.9. Khẳng định khoa học (Scientific Claims) luận văn có thể bảo vệ

Sau audit, các claim sau **đủ căn cứ**:

1. **C-IMPL**: Lõi 2/3 primitive + memory congruence + temporal ordering của
   Di Pietro et al. (2025) đã được triển khai trên Frida + Sysmon trong môi
   trường lab Windows 10/11, với unit test che 3 case quan trọng.
2. **C-EXT**: Kiến trúc bổ sung *file provenance → process lineage → injection
   primitives* cung cấp ngữ cảnh nguồn gốc file mà paper gốc không mô hình hóa.
3. **C-CASE**: Repo phát hiện đúng kịch bản section-mapping (variant *neurevt*
   của paper) trong test `test_detects_section_mapping_write_execute_chain`.

Các claim sau **chưa đủ căn cứ, không được tuyên bố** trong luận văn nếu chưa
bổ sung evaluation:

- ❌ "Precision/recall ngang/hơn paper" — chưa có dataset, chưa có baseline.
- ❌ "Phát hiện được kỹ thuật injection X với độ chính xác Y%" — classifier
  chưa được đánh giá trên ground truth.
- ❌ "Frida user-mode đủ tin cậy cho production" — không phải scope, README đã
  nêu.

---

## 4. Khuyến nghị fix theo thứ tự ưu tiên

| Ưu tiên | Fix | File | Lý do |
|---|---|---|---|
| **P0** | Hook đọc `lpStartAddress` cho `CreateRemoteThread/Ex`, `NtCreateThreadEx`; gắn làm `address` của primitive EXECUTE | [frida_hooks/windows_injection_hooks.js](../src/noirlycan_telemetry/frida_hooks/windows_injection_hooks.js) | D1 — deviation lớn nhất với paper |
| **P0** | Tách `Read*VirtualMemory` khỏi class *write* trong `PAPER_API_CLASSES`; hoặc thêm `PrimitiveKind.READ` riêng và bỏ khỏi 2/3 count | [injection_api_manifest.py](../src/noirlycan_telemetry/injection_api_manifest.py) | D2 |
| **P0** | Sửa `_has_temporal_consistency` để reject mọi đảo bậc của primitive paper | [correlation.py:291-307](../src/noirlycan_telemetry/correlation.py) | D3 |
| **P1** | Thêm `PROCESS_GHOSTING`, `PROCESS_HERPADERPING` vào `InjectionTechnique` enum + rule classify | [technique_classifier.py](../src/noirlycan_telemetry/technique_classifier.py) | D5 |
| **P1** | Báo cáo metric recursive chain (đếm finding có `is_recursive=True` / tổng finding) | [injection_graph.py](../src/noirlycan_telemetry/injection_graph.py) + `session_analytics.py` | D6 |
| **P2** | Tài liệu hóa giả định M5 bằng benchmark Frida throughput | mới — `docs/experiments/frida-fidelity.md` | M5 |
| **P2** | Bổ sung mục Anti-evasion → ghi nhận Out-of-Scope một cách formal | luận văn chương 3 | D4 |

---

## 5. Tham chiếu

1. Di Pietro, D'Elia, Querzoni. *Can You Run My Code?* ASIA CCS '25.
   [DOI](https://doi.org/10.1145/3708821.3736206).
2. Sap4Sec/process-injection — paper artifact.
3. Klein, S., et al. *Process injection categorisation.* (paper cites).
4. Starink, T., et al. (2023) *Behavior-graph injection detection.*
5. Repo files: `correlation.py`, `execution_analysis.py`,
   `technique_classifier.py`, `injection_api_manifest.py`, `models.py`,
   `tests/test_correlation.py`, `frida_hooks/windows_injection_hooks.js`.

---

*Tài liệu phục vụ chương Methodology Validation + chương Threat Model của
luận văn Noirlycan. Audit trên revision repo tại commit `920077d`.*
