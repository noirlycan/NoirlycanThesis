# CHƯƠNG 1. CƠ SỞ LÝ THUYẾT

Chương này trình bày nền tảng lý thuyết: mô hình tiến trình và bộ nhớ ảo Windows; định nghĩa process injection; sáu nhóm né tránh E1–E6; phương pháp **operational primitive** và quy tắc **2-of-3** [4] — căn cứ khoa học chính của correlator Noirlycan; taxonomy kỹ thuật injection; và hai công cụ telemetry Sysmon (kernel) và Frida (user-mode). Chi tiết API ở Phụ lục A.

## 1.1. Mô hình tiến trình Windows và bối cảnh injection

### 1.1.1. Process, thread và không gian địa chỉ

Trên Windows, **process** là container cô lập gồm không gian địa chỉ ảo riêng, handle table, security context (token), và ít nhất một **thread**. Kernel đảm bảo cô lập qua phân trang phần cứng và chuyển **CR3** khi context switch; truy cập cross-process bắt buộc qua API kernel với handle hợp lệ. Mỗi thread có tập thanh ghi (`RIP`, `RSP`, …), stack riêng, và con trỏ tới **Thread Environment Block** (TEB). Process được mô tả bởi **Process Environment Block** (PEB) chứa loader data (`PEB_LDR_DATA`), command line, biến môi trường, cờ debug [7].

Kernel quản lý process qua **EPROCESS** và expose capability qua hai lớp: **Win32 API** (`kernel32.dll`, `kernelbase.dll`, `user32.dll`) là wrapper documented, và **Native API** (`ntdll.dll`) gồm `Nt*`/`Zw*` là syscall stub. Hầu hết injection đi qua Native API hoặc `syscall` trực tiếp với System Service Number (SSN), lách rule signature viết cho tên Win32 [4], [7].

**Bảng 1.1.** Thành phần mô hình tiến trình Windows liên quan injection

| Thành phần | Vai trò | Liên quan injection |
|------------|---------|---------------------|
| PEB | Metadata process, loader data | Reflective DLL, module stomping |
| TEB | Ngữ cảnh thread, stack | APC queue, thread hijack |
| VAD (Virtual Address Descriptor) | Mô tả vùng nhớ ảo | Allocate/map tạo VAD mới |
| Handle table | Quản lý handle process/thread | `OpenProcess` với `PROCESS_VM_WRITE` |
| Token / integrity level | Kiểm soát truy cập | UAC, cross-session injection |
| Section object | Shared memory kernel | `NtCreateSection`, `NtMapViewOfSection` |

**VAD** là vết kernel duy nhất cho mọi vùng nhớ ảo private — kể cả khi malware unhook user-mode, VAD vẫn forensic được qua Volatility. **Token** và integrity level quyết định một process Medium có thể inject sang process High hay không (cần `SeDebugPrivilege`).

### 1.1.2. Process injection như hành vi né tránh attribution

**Process injection** (MITRE T1055 [9]) là họ kỹ thuật đưa mã thực thi vào address space của tiến trình khác hoặc tự inject, kích hoạt thực thi mà không tạo image file hợp lệ trên đĩa. Mục tiêu là **né attribution**: tiến trình hiển thị vẫn là process hợp pháp (`msedge.exe`, `svchost.exe`, …), nhưng hành vi mạng/file/registry của payload bị quy cho nạn nhân. Rule dựa trên image path, signing certificate, hoặc reputation hash đều thất bại [4], [3].

Di Pietro và cộng sự [4] ước lượng **16,5 %** mẫu malware (dataset 2017–2023) có ít nhất một hành vi injection. Paper cũng chỉ ra xu hướng dịch chuyển từ classic remote thread sang **section-mapping** và **process hollowing** biến thể (E1, E2 ở mục 1.4), phản ánh áp lực từ EDR có hook user-mode.

### 1.1.3. Chuỗi hành vi điển hình: file-drop → spawn → inject

Loader thường kết hợp **file-drop** (E3): (1) ghi `.exe`/`.dll` xuống thư mục staging user-writable (`%TEMP%`, `%APPDATA%`, ProgramData); (2) `CreateProcess`/`ShellExecute` spawn — kèm `CREATE_SUSPENDED` cho Early Bird/hollowing; (3) `OpenProcess` nạn nhân với access mask `0x143a` (`PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD`) hoặc `PROCESS_ALL_ACCESS` (`0x1fffff`); (4) allocate → write → execute hoặc biến thể gộp (section mapping/Mockingjay, mục 1.6); (5) payload chạy dưới identity nạn nhân, file gốc bị xóa.

Luận văn mở rộng [4] bằng pipeline **provenance** bắt bước 1–2 (Sysmon Event 11, Event 1) để liên kết Finding với file nguồn — đối trọng cho E3.

## 1.2. Bộ nhớ ảo, section object và lớp API

### 1.2.1. Virtual memory và page protection

Windows dùng bộ nhớ ảo per-process với phân trang (4 KB hoặc 2 MB large page). Mỗi region có **protection** R/W/X: `PAGE_READWRITE` (RW), `PAGE_EXECUTE_READ` (RX), `PAGE_EXECUTE_READWRITE` (RWX). Để OPSEC, malware thực hiện chuỗi allocate RW → write → `VirtualProtectEx` đổi sang RX, tránh RWX vốn bị EDR coi là heuristic shellcode [7], [4].

Để né heuristic này, attacker có ba hướng: (a) **section mapping** với `SEC_IMAGE`/`PAGE_EXECUTE_READ` map trực tiếp ở RX; (b) **Mockingjay** — ghi đè vùng RWX có sẵn trong DLL hợp pháp (`libcef.dll`, `dbghelp.dll`) (E2); (c) **module stomping** — ghi đè `.text` của module đã RX.

### 1.2.2. Section object và shared mapping

**Section object** là abstraction kernel cho vùng nhớ map vào nhiều process. Chuỗi điển hình:

- `NtCreateSection` — tạo section từ file hoặc anonymous backing; `AllocationAttributes` (`SEC_COMMIT`, `SEC_IMAGE`, `SEC_RESERVE`) và `SectionPageProtection` quyết định ngữ nghĩa.
- `NtMapViewOfSection` — map view vào address space local hoặc **remote**, với `Win32Protect` xác định quyền.

Khi map remote, một lệnh có thể đồng thời **allocate** (VAD mới) và **write** (copy nội dung) — gộp bước điển hình của E2. Paper [4] xếp `NtCreateSection` vào *allocate* và `NtMapViewOfSection` vào *write*; luận văn tuân theo mapping artifact Noirlycan và khai báo deviation D8.

### 1.2.3. Win32 API và Native API

**Bảng 1.2.** Phân lớp API liên quan injection

| Lớp | Thư viện | Ví dụ | Ghi chú |
|-----|----------|-------|---------|
| Win32 | `kernel32.dll` | `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread` | Wrapper documented |
| Native | `ntdll.dll` | `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx` | Syscall stub |
| Direct syscall | Stub attacker | `syscall` với SSN tự resolve | E4 — bypass hook user-mode |
| Kernel | `ntoskrnl.exe` | (out-of-scope) | — |

Cùng thao tác cấp phát remote có thể qua ba lớp, mà chỉ Win32 có tên hàm “dễ nhận diện” trong Sigma/Yara. Malware E1 thay Win32 bằng Native API tương đương, hoặc tự resolve SSN gọi `syscall`. Paper [4] neutralize E1 bằng **equivalence class** — mọi API cùng ngữ nghĩa primitive gom thành một lớp; rule 2-of-3 chỉ phụ thuộc kind primitive (A/W/E) đã chuẩn hoá.

## 1.3. Process injection — định nghĩa và operational primitive

### 1.3.1. Ba bước cổ điển (Klein et al.)

Klein và cộng sự [7] phân loại injection thành ba thao tác **operational**, không phụ thuộc API:

1. **Allocate** — chuẩn bị vùng nhớ: `VirtualAllocEx`, `NtCreateSection`, hoặc `VirtualProtectEx` đổi protection.
2. **Write** — ghi payload: `WriteProcessMemory`, `NtWriteVirtualMemory`, hoặc map view section.
3. **Execute** — chuyển luồng CPU tới payload: remote thread, APC, resume thread, set context, `LoadLibrary` remote, hook window, thread pool.

Ba bước mô tả **ngữ nghĩa** chứ không ràng buộc API — nền tảng cho abstraction của [4].

### 1.3.2. Cùng vùng nhớ (Starink et al.)

Starink và cộng sự [12] dùng **behavior graph** với điều kiện các bước phải thao tác trên **cùng buffer**. Paper [4] formal hoá thành **memory range congruence**: hai primitive correlate nếu `[address, address+size)` giao nhau hoặc chứa nhau, giảm false positive khi actor có nhiều allocation độc lập [4], [12].

### 1.3.3. Giới hạn abstraction

Primitive **không** bao phủ credential dumping, lateral movement, kernel exploit. Phạm vi luận văn giới hạn ở **user-mode cross-process / self-inject** (Chương 3); ngoài ra out-of-scope. Static triage (entropy, signature, import table) bổ sung context payload cho E3.

## 1.4. Phân loại hình thức né tránh E1–E6

Luận văn nhóm các hình thức né tránh thành sáu lớp E1–E6 dựa trên đối tượng attacker nhắm (rule, sandbox, instrumentation, analyst). Một kỹ thuật có thể thuộc nhiều nhóm.

### 1.4.1. E1 — Né tránh bằng biến thể API

Attacker thay API Win32 bằng Native API hoặc biến thể ít bị rule hoá:

| API Win32 (dễ rule) | Thay thế Native |
|---------------------|-----------------|
| `CreateRemoteThread` | `NtCreateThreadEx`, `RtlCreateUserThread` |
| `VirtualAllocEx` | `NtAllocateVirtualMemory` |
| `WriteProcessMemory` | `NtWriteVirtualMemory` |
| `OpenProcess` | `NtOpenProcess` |

**Phát hiện [4]:** equivalence class — biến thể ánh xạ về cùng primitive nên rule fire bất kể lớp API. Noirlycan hiện thực manifest `PAPER_API_CLASSES` trong `kernel/classification/api_manifest.py` [11], [13]. Nếu attacker dùng direct syscall thì thuộc E4.

### 1.4.2. E2 — Né tránh bằng gộp hoặc ẩn bước

Attacker giảm số API observable bằng cách gộp allocate+write hoặc bỏ một bước:

- **Section mapping:** `NtCreateSection` + `NtMapViewOfSection` remote, map view đồng thời cấp phát và ghi.
- **Process hollowing (section variant):** process suspended, `NtUnmapViewOfSection` unmap image gốc, map section payload, set context, resume — chiếm tỉ lệ lớn trong dataset [4].
- **Mockingjay:** chỉ write + execute vào vùng RWX có sẵn (`libcef.dll`, `mshtml.dll`); bỏ allocate.
- **PoolParty:** lạm dụng thread pool wait callback / timer / IO completion thay cho `CreateRemoteThread`.

**Phát hiện [4]:** quy tắc **2-of-3** — chỉ cần ≥2 primitive khác kind trên cùng vùng nhớ. Mockingjay thoát rule yêu cầu allocate nhưng W+E vẫn đủ.

### 1.4.3. E3 — Né tránh bằng che attribution

Attacker chọn victim cẩn thận và xử lý dấu vết disk:

- Inject vào process tin cậy (`explorer.exe`, `svchost.exe`, `RuntimeBroker.exe`).
- File-drop tên giả mạo (`update.exe`, `svchost.exe` ngoài `System32`), staging trong thư mục user-writable, xóa file sau spawn.
- Parent PID spoofing qua `UpdateProcThreadAttribute` (ngoài phạm vi hiện thực đầy đủ).

**Phát hiện (extension):** Sysmon Event 1 (parent/child, command line) + Event 11 (file path, SHA-256) + static triage → pipeline provenance. Paper [4] dùng batch sandbox và không nhấn mạnh forensics file-drop endpoint — điểm mở rộng của luận văn.

### 1.4.4. E4 — Né tránh instrumentation user-mode

Attacker chủ động bypass hook user-mode:

- **Direct syscall:** stub assembly `mov r10, rcx; mov eax, <SSN>; syscall; ret`, không qua `ntdll`.
- **Unhooking:** đọc bản sạch `.text` của `ntdll.dll` từ disk hoặc `KnownDlls`, ghi đè vùng đã bị EDR vá.
- **Patch ETW/AMSI:** ghi đè entry function `EtwEventWrite`/`AmsiScanBuffer` bằng `ret`.

Khi E4 thành công, Frida miss toàn bộ — mất đối số address/size cho congruence. Tuy nhiên **Sysmon kernel** (Event 8, Event 10) vẫn ghi nhận cross-process vì callback đăng ký kernel qua `PsSetCreateProcessNotifyRoutineEx`, `ObRegisterCallbacks`, ETW Threat Intelligence [10]. E4 do đó trong phạm vi một phần: phát hiện được cross-process coarse-grained, có thể mất chi tiết congruence — khai báo trong RQ2/RQ4.

### 1.4.5. E5 — Né tránh sandbox và môi trường phân tích

Malware **không** inject khi phát hiện VM/sandbox/debugger:

- Timing: `RDTSC`, `GetTickCount`, sleep acceleration.
- Environment: thư mục Documents trống, registry key sandbox, MAC VM vendor, bit hypervisor trong CPUID.
- Human interaction: chờ click chuột, di chuyển con trỏ, số cửa sổ visible.

Paper [4] báo cáo **21,2 %** mẫu injection bị sandbox bỏ sót do E5; module anti-evasion của paper cải thiện recall trong ablation. Luận văn **không hiện thực** module này — **E5 ngoài phạm vi**. So sánh recall với [4] phải kèm disclaimer E5.

### 1.4.6. E6 — Né tránh instrumentation chủ động (anti-Frida)

Attacker quét bộ nhớ và process list tìm artifact Frida (`frida-agent`, pipe Frida, RWX shellcode gadget, INT3 Stalker, timing bất thường) rồi abort hoặc đổi code path. Luận văn giảm thiểu: ưu tiên **`spawn` mode**, khai báo limitation, dùng Sysmon làm fallback.

**Bảng 1.3.** Tóm tắt nhóm né tránh E1–E6

| Nhóm | Tấn công vào | Phát hiện chính | Phạm vi |
|------|--------------|-----------------|---------|
| E1 | Rule API cố định | Equivalence class [4] | Đầy đủ |
| E2 | Rule 3 bước tuần tự | 2-of-3 [4] | Đầy đủ |
| E3 | Analyst attribution | Provenance extension | Extension |
| E4 | Frida/EDR hook | Sysmon kernel fallback | Một phần |
| E5 | Sandbox/VM | Anti-evasion [4] | Out-of-scope |
| E6 | Frida agent | spawn; limitation | Hạn chế |

## 1.5. Operational primitive và quy tắc 2-of-3 theo Di Pietro et al. [4]

Phần này tóm tắt phương pháp [4] cùng artifact Sap4Sec/process-injection [11].

### 1.5.1. Ba primitive và lớp tương đương API

Mỗi primitive ánh xạ về tập API **thay thế được** về ngữ nghĩa operational, dựa trên hành vi kernel chứ không hình thức tên hàm.

**Bảng 1.4.** Lớp tương đương API (rút gọn từ [4], Table 1; đầy đủ Phụ lục A)

| Primitive | Ví dụ API (equivalence class) |
|-----------|-------------------------------|
| **Allocate (A)** | `VirtualAllocEx`, `NtAllocateVirtualMemory`, `VirtualProtectEx`, `NtProtectVirtualMemory`, `NtCreateSection`, `CreateFileMappingA/W`, `MapViewOfFile(Ex)` |
| **Write (W)** | `WriteProcessMemory`, `NtWriteVirtualMemory`, `NtMapViewOfSection`, `NtUnmapViewOfSection`, `RtlCopyMemory` |
| **Execute (E)** | `CreateRemoteThread(Ex)`, `NtCreateThreadEx`, `RtlCreateUserThread`, `QueueUserAPC`, `NtQueueApcThread(Ex)`, `SetThreadContext`, `ResumeThread`, `LoadLibraryA/W`, `LdrLoadDll`, `SetWindowsHookEx`, `GlobalAddAtom` |

`ReadProcessMemory`/`NtReadVirtualMemory` **không** tính write — dùng cho observation (reflective loader đọc PE headers). Noirlycan tách `remote_read` khỏi đếm 2-of-3 [13]. Class phụ trợ (`process_spawn`, `process_access`, `dynamic_resolve`, `context_read`) ghi nhận để hỗ trợ classifier và gắn evidence flag (`create_suspended`, `suspicious_access_mask`, `gpa_resolves_injection_api`).

### 1.5.2. Quy tắc 2-of-3

**Phát biểu:** Phát hiện injection khi tồn tại ≥ **hai primitive khác kind** trong {A, W, E} trên cùng cặp `(actor_pid, target_pid)` (hoặc `actor == target` cho self-inject), thoả memory congruence và temporal ordering [4].

**Lý do:** Malware E2 thường che một bước (section che A/W, Mockingjay che A, AtomBombing che W). Yêu cầu 3/3 gây false negative cao; ngưỡng 1/1 không đủ vì nhiều process hợp pháp gọi đơn lẻ `OpenProcess`/`VirtualAlloc`. Ngưỡng 2/3 là điểm cân bằng đánh giá thực nghiệm [4].

**Formal:**

- `P` — tập primitive trong cửa sổ thời gian `T` (Noirlycan: 300 giây).
- `kind(p) ∈ {A, W, E}`.
- Điều kiện: `|{kind(p) : p ∈ P}| ≥ 2` ∧ `congruent(P)` ∧ `temporal(P)`.

### 1.5.3. Memory range congruence

Với mỗi primitive `p`, `range(p) = [addr(p), addr(p)+size(p))`. Hai primitive **congruent** nếu `range(p) ∩ range(q) ≠ ∅` hoặc một chứa cái kia [4], [12].

Một số execute như `ResumeThread` không có address rõ ràng — paper [4] lấy `Rip` tại thời điểm thread bắt đầu chạy làm address đại diện. Frida đọc `lpStartAddress` từ tham số `CreateRemoteThread`/`NtCreateThreadEx`, hoặc `ThreadContext` trước resume (deviation D1).

Engine Noirlycan chỉ tính congruence giữa các kind khác nhau (A↔W, W↔E, A↔E), tránh gom nhầm hai write độc lập.

### 1.5.4. Temporal ordering

Thứ tự hợp lệ là **allocate → write → execute**, với ngoại lệ [4] công nhận:

- **Gộp bước:** A và W đồng thời (section map remote) — timestamp bằng nhau.
- **Allocate lặp:** `VirtualProtectEx` sau write để chuyển RW → RX vẫn là kind A, được phép sau write.
- **Reject:** allocate sau execute là out-of-order.

Noirlycan gán bậc `A=0, W=1, CONTEXT_READ=2, E=3` và reject khi primitive bậc thấp xuất hiện sau bậc cao trong cùng range. Engine chưa siết “write không sau execute” — deviation D3.

### 1.5.5. Phân loại kỹ thuật sau phát hiện

Sau 2-of-3, paper [4] dùng **tập API quan sát** + context (suspended, `SEC_IMAGE`, APC queue, …) gán nhãn: Classic Remote Thread, APC, Early Bird, Thread Hijacking, Hollowing (classic/section), Reflective DLL, Module Stomping, AtomBombing, Doppelgänging, Ghosting/Herpaderping. Noirlycan mở rộng lên **21+ enum** `InjectionTechnique`, thêm PoolParty, Mockingjay, fiber injection, thread pool variants [13].

### 1.5.6. Chuỗi injection đệ quy

Paper [4] báo cáo ~**2 %** mẫu có injection lồng nhiều tầng (A → B → C). Noirlycan có `injection_graph.py` mô hình hoá graph và auto-attach Frida cho process con; metric prevalence chưa tái lập do giới hạn dataset.

## 1.6. Taxonomy kỹ thuật process injection

Mỗi kỹ thuật trình bày ngắn theo cơ chế, primitive, và né tránh liên quan.

### 1.6.1. Classic Remote Thread Injection

**Cơ chế:** `OpenProcess` → `VirtualAllocEx` (A) → `WriteProcessMemory` (W) → `CreateRemoteThread` (E) với `lpStartAddress` trỏ tới shellcode.

**Né tránh:** E1 (`NtCreateThreadEx`); E3 (target `explorer.exe`); E4 (direct syscall).

**Phát hiện [4]:** A+W+E — case đơn giản nhất cho 2-of-3.

### 1.6.2. DLL Injection (LoadLibrary)

**Cơ chế:** `CreateRemoteThread` với `lpStartAddress = LoadLibraryA` và `lpParameter` trỏ tới đường dẫn DLL đã write sang remote memory.

**Né tránh:** E3 (DLL trên disk); E1 nếu chuyển `LdrLoadDll`.

**Phát hiện:** W+E; file provenance (Event 11) bổ sung cho E3.

### 1.6.3. APC Injection

**Cơ chế:** Allocate + write shellcode vào remote, `QueueUserAPC` (E) gắn vào APC queue thread victim. Khi thread alertable (`SleepEx`, `WaitForSingleObjectEx`), kernel dispatch APC.

**Né tránh:** E2 (Sysmon Event 8 không fire); E1 (`NtQueueApcThreadEx`).

**Phát hiện [4]:** W+E.

### 1.6.4. Early Bird APC Injection

**Cơ chế:** `CreateProcess(..., CREATE_SUSPENDED)`; allocate + write vào process con; `QueueUserAPC` lên thread chính; `ResumeThread` (E). Khi thread chính alertable trong init (`NtTestAlert`), APC chạy trước entrypoint.

**Né tránh:** E2; E3 (victim mới spawn “sạch”).

**Phát hiện:** Evidence `create_suspended` + APC + `ResumeThread`; classifier `EARLY_BIRD_APC_INJECTION`.

### 1.6.5. Thread Execution Hijacking

**Cơ chế:** `SuspendThread` → `GetThreadContext` → sửa `Rip`/`RSP` → `SetThreadContext` (E) → `ResumeThread`.

**Né tránh:** E2 (không tạo thread mới); E1 (`NtGetContextThread`/`NtSetContextThread`).

**Phát hiện [4]:** W + CONTEXT_READ + E; address congruence lấy từ `Rip` mới (extension D1).

### 1.6.6. Process Hollowing (classic)

**Cơ chế:** `CreateProcess` suspended → `NtUnmapViewOfSection` image gốc → allocate + write image độc hại vào cùng base → set context → `ResumeThread`.

**Né tránh:** E1, E2, E3.

**Phát hiện:** A+W+E hoặc unmap (W) + set context + resume; classifier `PROCESS_HOLLOWING_CLASSIC`.

### 1.6.7. Process Hollowing (section-mapping variant)

**Cơ chế:** Biến thể chiếm tỉ lệ lớn nhất trong [4]: `NtCreateSection` từ file payload → `NtMapViewOfSection` remote thay image gốc → `SetThreadContext` + `ResumeThread`. Case study **Neurevt** [4] §3.5.

**Né tránh:** E2 mạnh do gộp A và W.

**Phát hiện:** `NtMapViewOfSection` (W) + `ResumeThread` (E) = 2-of-3; testcase `test_detects_section_mapping_write_execute_chain`.

### 1.6.8. Reflective DLL Injection

**Cơ chế:** Loader trong shellcode manual-map PE DLL: parse PE headers, relocation, resolve import, gọi `DllMain` — không qua `LoadLibrary`.

**Né tránh:** E1, E3; E6 nếu loader có anti-analysis.

**Phát hiện [4]:** W+E; Sysmon Event 7 (ImageLoad) vắng mặt cho payload reflective.

### 1.6.9. Module Stomping / Overloading

**Cơ chế:** Load DLL hợp pháp; xác định section RX/RWX; ghi đè `.text` (W); execute qua export hoặc function pointer (E).

**Né tránh:** E2 (tái sử dụng mapping); E3 (DLL có chữ ký).

**Phát hiện:** W+E trên range module đã load; ImageLoad trước write là dấu hiệu phân loại.

### 1.6.10. Process Doppelgänging

**Cơ chế:** Lạm dụng **NTFS transaction**: tạo file transacted, ghi payload, `CreateProcess` từ transacted section, rollback transaction. Process chạy image “ma” không còn trên disk.

**Né tránh:** E1, E3.

**Phát hiện:** Transaction API + spawn + inject primitives; classifier `PROCESS_DOPPELGANGING`.

### 1.6.11. Process Ghosting và Herpaderping

**Ghosting:** File delete-pending, map section, ghi payload, tạo process, đóng handle — file bị xóa khi process payload đã chạy.

**Herpaderping:** Map file hợp lệ, ghi đè bằng payload, tạo process, “sửa” lại view trên disk thành file sạch.

**Né tránh:** E2, E3.

**Phát hiện:** Spawn + section + write thứ tự bất thường; classifier `PROCESS_GHOSTING`, `PROCESS_HERPADERPING`.

### 1.6.12. AtomBombing

**Cơ chế:** Ghi payload vào **global atom table** qua `GlobalAddAtom`; dùng `GlobalGetAtomName` ép kernel copy chuỗi sang memory victim; thực thi qua APC.

**Né tránh:** E2 (không có `VirtualAllocEx` cổ điển).

**Phát hiện:** `GlobalAddAtom` (execute class theo manifest paper) + APC + write.

### 1.6.13. SetWindowsHookEx Injection

**Cơ chế:** `SetWindowsHookEx` với hook type (`WH_KEYBOARD`, `WH_GETMESSAGE`, …) và handle module DLL độc hại. Kernel tự map DLL vào process có message loop tương ứng.

**Né tránh:** E3 (DLL có chữ ký); execute không qua `CreateRemoteThread`.

**Phát hiện:** `SetWindowsHookEx` (E) + W; classifier `HOOK_INJECTION`.

### 1.6.14. Mockingjay Injection

**Cơ chế:** Quét DLL signed đã load tìm section RWX có sẵn (`ssh.exe`, CEF, một số runtime); chỉ thực hiện `WriteProcessMemory` (W) + hijack execution (E) — **bỏ allocate** [7].

**Né tránh:** E2 mạnh — chỉ 2 primitive observable.

**Phát hiện [4]:** W+E đủ 2-of-3; classifier `MOCKINGJAY`.

### 1.6.15. PoolParty (Thread Pool)

**Cơ chế:** Lạm dụng Windows thread pool — queue work item, timer, hoặc wait callback trỏ tới shellcode — execute không cần `CreateRemoteThread`.

**Né tránh:** E2, E4.

**Phát hiện:** W + execute qua API thread pool; extension `POOLPARTY` trong Noirlycan; yêu cầu hook sâu hơn baseline.

**Bảng 1.5.** Tóm tắt kỹ thuật injection, primitive và né tránh

| # | Kỹ thuật | Primitive | E1 | E2 | E3 |
|---|----------|-----------|----|----|-----|
| 1 | Classic Remote Thread | A+W+E | ✓ | | ✓ |
| 2 | DLL Injection | W+E | ✓ | | ✓ |
| 3 | APC Injection | W+E | ✓ | ✓ | |
| 4 | Early Bird APC | W+E | | ✓ | ✓ |
| 5 | Thread Hijacking | W+E (+ctx) | ✓ | ✓ | |
| 6 | Hollowing classic | A+W+E | ✓ | | ✓ |
| 7 | Hollowing section | W+E | ✓ | ✓ | ✓ |
| 8 | Reflective DLL | W+E | ✓ | | ✓ |
| 9 | Module Stomping | W+E | | ✓ | ✓ |
| 10 | Doppelgänging | A+W+E | ✓ | ✓ | ✓ |
| 11 | Ghosting/Herpaderping | W+A+E | ✓ | ✓ | ✓ |
| 12 | AtomBombing | W+E | | ✓ | |
| 13 | SetWindowsHookEx | W+E | | | ✓ |
| 14 | Mockingjay | W+E | | ✓ | ✓ |
| 15 | PoolParty | W+E | | ✓ | |

## 1.7. Sysmon — telemetry kernel cho phát hiện injection

**Sysmon** ghi log qua driver kernel `SysmonDrv.sys` [10]. Trong luận văn, Sysmon là **lớp chống E4** — quan sát cross-process khi malware bypass user-mode hook, và là ground truth độc lập so với Frida cho RQ4.

### 1.7.1. Kiến trúc Sysmon

Sysmon.exe (LocalSystem) đăng ký với driver; driver cài callback kernel:

- `PsSetCreateProcessNotifyRoutineEx` — process create/exit.
- `PsSetLoadImageNotifyRoutine` — DLL/EXE map.
- `ObRegisterCallbacks` — handle operation (`OpenProcess`, `OpenThread`).
- Minifilter file system — file create/write.
- ETW Threat Intelligence — CreateRemoteThread kernel.

Log ghi vào `Microsoft-Windows-Sysmon/Operational`, collector Noirlycan đọc qua `EvtSubscribe`.

### 1.7.2. Sự kiện Sysmon trong phạm vi Noirlycan

**Bảng 1.6.** Sự kiện Sysmon và vai trò phát hiện

| Event | Tên | Cơ chế kernel | Chống né tránh | Vai trò |
|-------|-----|---------------|----------------|---------|
| **1** | ProcessCreate | Process notify | E3, E4 | Lineage, parent PID, command line |
| **3** | NetworkConnect | WFP ETW | — | Post-injection C2 |
| **7** | ImageLoad | Image notify | E4 (kernel) | Reflective vs LoadLibrary |
| **8** | CreateRemoteThread | ETW TI | **E4** | Fallback execute; `StartAddress` |
| **10** | ProcessAccess | ObRegisterCallbacks | **E4** | `GrantedAccess` suspicious (`0x1fffff`, `0x143a`) |
| **11** | FileCreate | Minifilter | E3 | File-drop provenance; SHA256 |
| **15** | FileCreateStreamHash | Minifilter | E3 alt | ADS |

Config `sysmon-noirlycan.xml` [13]: ProcessCreate broad; FileCreate filter `.exe/.dll/.ps1/.vbs/.js/.scr`; ProcessAccess filter `GrantedAccess` suspicious; CreateRemoteThread log toàn bộ; ImageLoad filter `ntdll.dll`, `kernel32.dll`.

### 1.7.3. Giới hạn Sysmon

- Thiếu chi tiết tham số NT API (size, protection flag) — Frida bổ sung cho memory congruence.
- Kernel rootkit (O3 threat model) có thể vô hiệu hoá driver — ngoài phạm vi luận văn.
- Event 8 không cover mọi execute vector — APC-only và thread pool không phát sinh CreateRemoteThread.
- Volume log tăng nhanh nếu config rộng — mức hiện tại chấp nhận được trong lab.

### 1.7.4. Sysmon và E4 — ma trận tin cậy

Khi malware direct-syscall `NtCreateThreadEx`, Frida miss hoàn toàn vì hook trên `ntdll!NtCreateThreadEx` không kích hoạt, nhưng Sysmon Event 8 vẫn fire qua ETW Threat Intelligence kernel. Correlator merge: Sysmon → primitive EXECUTE sơ cấp; Frida → W/A với address. Trong E4, congruence yếu hơn paper — khai báo trong RQ2/RQ4.

## 1.8. Frida — instrumentation user-mode và kiến trúc telemetry kép

### 1.8.1. Frida overview

**Frida** [5] inject agent JavaScript (V8/QuickJS) vào process target qua `frida-server` hoặc `frida-gadget`; hook function bằng `Interceptor.attach(address, { onEnter, onLeave })`. Noirlycan dùng Frida để:

- Hook export liên quan injection trong `kernel32.dll` và `ntdll.dll`.
- Trích xuất đối số: `lpBaseAddress`, `nSize`, `flAllocationType`, `flProtect`, `lpStartAddress`, handle.
- Emit **observation** sang collector Python qua JSON message bus.

Script `windows_injection_hooks.js` (~1900 dòng) [13] chuẩn hoá API (alias `Zw*` về `Nt*`), xử lý `CONTEXT` cho thread hijack, phân biệt `emit` (đếm 2-of-3) với `emitObservation` (không đếm).

### 1.8.2. Ưu điểm so với chỉ Sysmon

| Khía cạnh | Frida | Sysmon |
|-----------|-------|--------|
| Đối số API (addr, size, prot) | Chi tiết | Hạn chế |
| Memory congruence [4] | Trực tiếp | Một phần (StartAddress) |
| APC, MapView, Protect | Hook NT | Không log hết |
| Overhead | Cao hơn | Thấp hơn |
| E4 direct syscall | Miss | Event 8/10 |
| E6 anti-Frida | Risk | Không agent trong victim |

Hai công cụ bổ trợ: Frida cho chi tiết congruence [4], Sysmon cho tin cậy khi Frida bị vô hiệu hoá.

### 1.8.3. Chế độ attach và E6

- **`spawn`:** inject agent trước entrypoint — giảm cửa sổ race (T2).
- **`attach`:** gắn vào process đang chạy — rủi ro miss API ở init.
- **`auto-attach-new-processes`:** theo dõi process con cho injection đệ quy.

E6 không vô hiệu hoá hoàn toàn — luận văn khuyến nghị `spawn` mode cho thí nghiệm rủi ro E6 cao.

### 1.8.4. Kiến trúc kép Sysmon ∪ Frida

Luận văn kết hợp hai nguồn telemetry độc lập:

```
[Loader/Malware] 
    → API calls → Frida hooks → Primitives (detail)
    → Kernel path → Sysmon driver → Events 1/7/8/10/11
         ↓
    [Collector Python] → Correlator (2-of-3, congruence, temporal)
         ↓
    Finding + Technique label + Provenance
         ↓
    [Dashboard / JSONL]
```

Sơ đồ trên thể hiện trust boundary giữa Frida (user-mode, không tin cậy nếu E4/E6) và Sysmon (kernel, tin cậy nếu O3 không xảy ra); bản vẽ đầy đủ trình bày tại Chương 3. Correlator đặt ngoài agent — tránh mất logic phát hiện khi agent bị vô hiệu hoá.

### 1.8.5. Fidelity và giả định M5

Giả định Frida hook **trung thực** về thứ tự và đối số (M5 threat model); cần benchmark định kỳ (Phụ lục E) so với ETW/`SilkETW`. Overhead hook có thể thay đổi timing, do đó luận văn **không** claim đo lường E5 timing evasion từ Frida.

### 1.8.6. Hướng thay thế: ETW Threat Intelligence

**ETW Threat Intelligence** cung cấp event mức syscall kernel — không bypass bằng unhook user-mode. Đây là hướng tiềm năng thay thế Frida (Kết luận); hiện thực Noirlycan dùng Sysmon (đã tích hợp ETW TI cho Event 8) làm trung gian.

### 1.8.7. Tóm tắt chương

Chương 1 đã trình bày mô hình Windows, process injection (T1055, ~16,5 % [4]), sáu nhóm né tránh E1–E6, phương pháp [4] (primitive A/W/E, equivalence class, 2-of-3, congruence, temporal ordering), taxonomy 15+ kỹ thuật, Sysmon kernel chống E4/E3, Frida user-mode cho congruence, và kiến trúc kép Sysmon ∪ Frida. Chương 2 đặt [4] vào bức tranh công trình liên quan (Klein [7], Starink [12], sandbox evasion [6], [8]) và làm rõ vị trí đóng góp replication + extension so với 56.340 mẫu của tác giả gốc.
