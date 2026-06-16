# CHƯƠNG 1. CƠ SỞ LÝ THUYẾT

Chương này trình bày nền tảng lý thuyết phục vụ luận văn *Tăng cường phát hiện mã độc dưới các hình thức né tránh*. Nội dung bao gồm: mô hình tiến trình và bộ nhớ ảo Windows; định nghĩa process injection trong bối cảnh né tránh phát hiện; phân loại sáu nhóm né tránh E1–E6; phương pháp operational primitive và quy tắc 2-of-3 theo Di Pietro et al. [4]; taxonomy chi tiết hơn mười kỹ thuật injection; và hai công cụ telemetry trung tâm — Sysmon (kernel) và Frida (user-mode). Các khái niệm ở đây được tham chiếu xuyên suốt Chương 2 (công trình liên quan), Chương 3 (threat model), Chương 4 (phương pháp) và Chương 5 (hiện thực Noirlycan).

## 1.1. Mô hình tiến trình Windows và bối cảnh injection

### 1.1.1. Process, thread và không gian địa chỉ

Trên Windows, **process** (*tiến trình*) là container cô lập gồm không gian địa chỉ ảo riêng, handle table, security context (token), và ít nhất một **thread** (*luồng*) thực thi. Mỗi thread có ngữ cảnh riêng: thanh ghi CPU, stack, và con trỏ tới **Thread Environment Block** (TEB). Process được mô tả bởi **Process Environment Block** (PEB) — cấu trúc user-mode chứa thông tin loader, danh sách module đã map, và tham số command line [7].

Kernel quản lý process qua **EPROCESS** (kernel structure) và expose capability cho user-mode qua Win32 API (`kernel32.dll`, `kernelbase.dll`) và **Native API** (`ntdll.dll`). Hầu hết thao tác injection của malware đi qua Native API hoặc syscall tương ứng, vì lớp Win32 thường là wrapper mỏng gọi xuống `ntdll` [4], [7].

**Bảng 1.1.** Thành phần chính của mô hình tiến trình Windows liên quan injection

| Thành phần | Vai trò | Liên quan injection |
|------------|---------|---------------------|
| PEB | Metadata process, loader data | Reflective DLL, module stomping đọc/ghi PEB |
| TEB | Ngữ cảnh thread, stack | APC queue, thread hijack |
| VAD (Virtual Address Descriptor) | Mô tả vùng nhớ ảo | Allocate/map section tạo VAD mới |
| Handle table | Quản lý handle process/thread | `OpenProcess` với `PROCESS_VM_WRITE` |
| Token / integrity level | Kiểm soát truy cập | UAC, cross-session injection hạn chế |
| Section object | Shared memory kernel | `NtCreateSection`, `NtMapViewOfSection` |

### 1.1.2. Process injection như hành vi né tránh attribution

**Process injection** (MITRE T1055 [9]) là họ kỹ thuật đưa mã thực thi vào **address space của tiến trình khác** (cross-process) hoặc cùng tiến trình (self-inject), rồi kích hoạt thực thi mà không tạo image file hợp lệ trên đĩa cho payload. Mục tiêu của attacker không chỉ là thực thi code mà còn **né tránh phát hiện ở tầng attribution**: sau injection, tiến trình hiển thị trên Task Manager vẫn là nạn nhân hợp pháp (`msedge.exe`, `svchost.exe`, …), che giấu nguồn gốc thực sự của hành vi độc hại [4], [3].

Di Pietro et al. [4] ước lượng **16,5 %** mẫu malware trong dataset 2017–2023 có injection — con số đủ lớn để coi injection là vector then chốt, không phải edge case. Paper cũng chỉ ra xu hướng malware chuyển từ classic remote thread sang **section-mapping** và **process hollowing** biến thể — các kỹ thuật vừa inject vừa né rule signature cố định (E1, E2).

### 1.1.3. Chuỗi hành vi điển hình: file-drop → spawn → inject

Trong phòng lab Windows, loader thường không chỉ inject mà kết hợp **file-drop** (E3):

1. Malware (hoặc macro/script) ghi file `.exe`/`.dll` xuống thư mục staging (`%TEMP%`, `%APPDATA%`, …).
2. Gọi `CreateProcess` hoặc `ShellExecute` spawn tiến trình mới — có thể với `CREATE_SUSPENDED` cho Early Bird / hollowing.
3. `OpenProcess` nạn nhân (cùng process mới hoặc process hệ thống khác).
4. Thực hiện chuỗi allocate → write → execute (hoặc biến thể gộp bước).
5. Payload chạy dưới identity nạn nhân; file gốc có thể bị xóa.

Luận văn mở rộng paper [4] bằng pipeline **provenance** bắt sự kiện bước 1–2 (Sysmon Event 11, Event 1) để liên kết Finding injection với file nguồn — đối trọng trực tiếp cho E3.

## 1.2. Bộ nhớ ảo, section object và lớp API

### 1.2.1. Virtual memory và page protection

Windows sử dụng **bộ nhớ ảo per-process** với phân trang (typically 4 KB page). Mỗi vùng có **protection** quyết định quyền đọc/ghi/thực thi: `PAGE_READWRITE` (RW), `PAGE_EXECUTE_READ` (RX), `PAGE_EXECUTE_READWRITE` (RWX), v.v. Injection an toàn về mặt OPSEC thường: allocate RW → write payload → đổi protection sang RX (`VirtualProtectEx`) trước execute — tránh vùng RWX dễ bị heuristic EDR phát hiện [7], [4].

Malware né heuristic có thể: (a) dùng section mapping map trực tiếp RX; (b) **Mockingjay** — ghi vào vùng RWX có sẵn trong DLL signed (bỏ bước allocate riêng, E2); (c) **module stomping** — ghi đè section `.text` của module đã load.

### 1.2.2. Section object và shared mapping

**Section object** là abstraction kernel cho vùng nhớ có thể map vào nhiều process. Chuỗi:

- `NtCreateSection` — tạo section từ file hoặc anonymous (commit memory).
- `NtMapViewOfSection` — map view vào address space local hoặc **remote** (target process handle).

Khi map remote, một l lệnh có thể đồng thời **allocate** (reserve VAD) và **write** (copy content từ section) — điển hình E2 “gộp bước”. Paper [4] xếp `NtCreateSection` vào lớp *allocate*, `NtMapViewOfSection` vào *write*; thực tế ngữ nghĩa phụ thuộc tham số — luận văn theo artifact Noirlycan cố định mapping này và khai báo deviation D8 trong audit.

### 1.2.3. Win32 API và Native API

**Bảng 1.2.** Phân lớp API liên quan injection

| Lớp | Thư viện | Ví dụ | Ghi chú |
|-----|----------|-------|---------|
| Win32 | `kernel32.dll` | `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread` | Wrapper documented |
| Native | `ntdll.dll` | `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx` | Syscall stub nội bộ |
| Direct syscall | Stub attacker | `syscall` instruction với SSN tự resolve | E4 — bypass hook user-mode |
| Kernel | `ntoskrnl.exe` | (không gọi trực tiếp user malware thông thường) | Out-of-scope luận văn |

Malware E1 thay Win32 bằng Native API tương đương để lách rule Sigma/EDR viết cho tên hàm Win32. Phương pháp [4] neutralize E1 bằng **equivalence class** — mọi API cùng ngữ nghĩa primitive được gom một lớp, rule phát hiện không phụ thuộc tên export cụ thể.

## 1.3. Process injection — định nghĩa và operational primitive

### 1.3.1. Ba bước cổ điển (Klein et al.)

Klein et al. [7] phân loại process injection Windows thành ba thao tác **operational** trên bộ nhớ nạn nhân:

1. **Allocate** — dành/chuẩn bị vùng nhớ có thể thực thi (allocation, section creation, thay đổi protection).
2. **Write** — ghi payload (shellcode, PE image, DLL) vào vùng đó.
3. **Execute** — chuyển luồng CPU tới payload (remote thread, APC, resume, set context, load library, …).

Ba bước này mô tả **ngữ nghĩa** hành vi, không ràng buộc API cụ thể — nền tảng cho abstraction của [4].

### 1.3.2. Cùng vùng nhớ (Starink et al.)

Starink et al. [12] dùng **behavior graph** — đồ thị API — và yêu cầu các bước injection liên quan thao tác trên **cùng buffer** bộ nhớ. Paper [4] formal hóa thành **memory range congruence**: hai primitive được correlate nếu khoảng địa chỉ `[address, address+size)` giao nhau hoặc chứa nhau. Mục đích: giảm false positive khi cùng actor mở nhiều allocation độc lập trong nạn nhân [4], [12].

### 1.3.3. Giới hạn abstraction

Abstraction primitive **không** cover toàn bộ hành vi độc hại Windows: không mô tả credential dumping, lateral movement, kernel exploit. Phạm vi luận văn giới hạn **user-mode cross-process / self inject** theo threat model (Chương 3). Primitive cũng **không** thay thế phân tích tĩnh — static triage bổ sung context payload (entropy, signature) cho E3.

## 1.4. Phân loại hình thức né tránh E1–E6

Luận văn nhóm né tránh liên quan injection thành sáu lớp E1–E6. Phân loại thống nhất Mở đầu, threat model, và đánh giá.

### 1.4.1. E1 — Né tránh bằng biến thể API

Attacker thay API Win32 bằng Native API hoặc biến thể ít bị rule hóa:

| API Win32 (dễ rule) | Thay thế Native / khác |
|---------------------|------------------------|
| `CreateRemoteThread` | `NtCreateThreadEx`, `RtlCreateUserThread` |
| `VirtualAllocEx` | `NtAllocateVirtualMemory` |
| `WriteProcessMemory` | `NtWriteVirtualMemory` |
| `OpenProcess` | `NtOpenProcess` |

**Cơ chế phát hiện [4]:** equivalence class — mọi biến thể cùng primitive. Noirlycan manifest `PAPER_API_CLASSES` trong `kernel/classification/api_manifest.py` [11], [13].

### 1.4.2. E2 — Né tránh bằng gộp hoặc ẩn bước

Attacker giảm số API observable bằng cách gộp allocate+write hoặc bỏ allocate:

- **Section mapping:** `NtCreateSection` + `NtMapViewOfSection` remote.
- **Process hollowing (section variant):** tạo process suspended, unmap image gốc, map section payload, set context entrypoint — dominant variant trong dataset [4].
- **Mockingjay:** chỉ write+execute vào RWX có sẵn trong `libcef.dll`, `mshtml.dll`, …
- **PoolParty:** lạm dụng thread pool wait callback — execute không qua `CreateRemoteThread` cổ điển.

**Cơ chế phát hiện [4]:** quy tắc **2-of-3** — không yêu cầu đủ cả ba primitive; chỉ cần ≥2 primitive khác loại trên cùng vùng nhớ. Ví dụ Mockingjay: W + E đủ điều kiện.

### 1.4.3. E3 — Né tránh bằng che attribution

Attacker tránh tạo tiến trình “đáng ngờ”:

- Inject vào browser, shell, service signed.
- File-drop: executable tên giả mạo, thư mục staging, xóa file sau spawn.
- Parent PID spoofing (ngoài phạm vi đầy đủ luận văn nhưng liên quan lineage).

**Cơ chế phát hiện (extension luận văn):** Sysmon Event 1 (parent/child, command line, `CreationUtcTime`), Event 11 (file path hash), static triage — pipeline provenance Noirlycan. Paper [4] batch sandbox không nhấn mạnh forensics file-drop trên endpoint.

### 1.4.4. E4 — Né tránh instrumentation user-mode

Attacker bypass hook Frida/EDR user-mode:

- **Direct syscall:** stub assembly gọi `syscall` với System Service Number (SSN), không đi qua export `ntdll` đã hook.
- **Unhooking:** restore `.text` section `ntdll.dll` từ bản sạch (disk hoặc `KnownDlls`).
- **Patch ETW/AMSI:** giảm telemetry/logging (kỹ thuật riêng trong classifier Noirlycan).

Frida `Interceptor.attach` trên export **miss** toàn bộ khi E4 thành công — mất đối số address/size cho congruence. **Sysmon kernel** (Event 8 CreateRemoteThread, Event 10 ProcessAccess) vẫn ghi cross-process artifact vì callback đăng ký ở kernel, không phụ thuộc hook user-mode [10]. Luận văn coi E4 “trong phạm vi một phần”: phát hiện được hành vi cross-process nhưng có thể mất chi tiết memory congruence.

### 1.4.5. E5 — Né tránh sandbox và môi trường phân tích

Malware **không thực hiện** injection khi phát hiện VM/sandbox/debugger:

- Timing: `RDTSC`, `GetTickCount`, sleep acceleration.
- Environment: thiếu file user, registry sandbox, MAC address VM vendor, CPUID hypervisor bit.
- Human interaction: không click, không cửa sổ visible.

Paper [4] báo **21,2 %** mẫu injection bị sandbox bỏ sót vì evasion này; module **anti-evasion** paper (patch timing, fake env) cải thiện recall đáng kể trong ablation. Luận văn **không hiện thực** anti-evasion tương đương — **E5 ngoài phạm vi hiện thực**. Noirlycan ghi signal evasion nhưng không bypass. Mọi so sánh recall với paper phải nêu disclaimer E5.

### 1.4.6. E6 — Né tránh instrumentation chủ độch (anti-Frida)

Attacker quét memory/process để tìm `frida-agent`, pipe Frida, breakpoint INT3, timing bất thường do hook — rồi abort hoặc đổi code path. Luận văn:

- Ưu tiên **`spawn` mode** (Frida attach trước entrypoint) giảm cửa sổ race.
- Khai báo **limitation** — không claim chống anti-Frida.
- Sysmon fallback một phần khi malware vẫn inject sau khi không detect agent.

**Bảng 1.3.** Tóm tắt nhóm né tránh E1–E6

| Nhóm | Tấn công vào | Phát hiện chính | Phạm vi luận văn |
|------|--------------|-----------------|------------------|
| E1 | Rule API cố định | Equivalence class [4] | ✓ Đầy đủ |
| E2 | Rule 3 bước tuần tự | 2-of-3 [4] | ✓ Đầy đủ |
| E3 | Analyst attribution | Provenance extension | ✓ Extension |
| E4 | Frida/EDR hook | Sysmon kernel fallback | ✓ Một phần |
| E5 | Sandbox/VM | Anti-evasion [4] | ✗ Out-of-scope |
| E6 | Frida agent | spawn; limitation | △ Hạn chế |

## 1.5. Operational primitive và quy tắc 2-of-3 theo Di Pietro et al. [4]

Phần này trình bày phương pháp **căn cứ khoa học chính** của luận văn — tóm tắt và formal hóa theo paper [4] và artifact Sap4Sec/process-injection [11].

### 1.5.1. Ba primitive và lớp tương đương API

Mỗi primitive ánh xạ tập API **thay thế được** về mặt ngữ nghĩa operational:

**Bảng 1.4.** Lớp tương đương API (rút gọn từ [4], Table 1; đầy đủ Phụ lục A)

| Primitive | Ví dụ API (equivalence class) |
|-----------|-------------------------------|
| **Allocate (A)** | `VirtualAllocEx`, `NtAllocateVirtualMemory`, `VirtualProtectEx`, `NtProtectVirtualMemory`, `NtCreateSection`, `CreateFileMappingA/W`, `MapViewOfFile(Ex)` |
| **Write (W)** | `WriteProcessMemory`, `NtWriteVirtualMemory`, `NtMapViewOfSection`, `NtUnmapViewOfSection`, `RtlCopyMemory` |
| **Execute (E)** | `CreateRemoteThread(Ex)`, `NtCreateThreadEx`, `RtlCreateUserThread`, `QueueUserAPC`, `NtQueueApcThread(Ex)`, `SetThreadContext`, `ResumeThread`, `LoadLibraryA/W`, `LdrLoadDll`, `SetWindowsHookEx`, `GlobalAddAtom` |

**Lưu ý:** `ReadProcessMemory` / `NtReadVirtualMemory` **không** là write primitive trong paper — dùng cho observation (reflective loader đọc headers). Noirlycan tách class `remote_read` khỏi đếm 2-of-3 [13].

Các class phụ trợ không phải primitive paper: `process_spawn`, `process_access`, `dynamic_resolve`, `context_read` — hỗ trợ classifier và evidence flags.

### 1.5.2. Quy tắc 2-of-3

**Phát biểu:** Phát hiện injection khi tồn tại ít nhất **hai primitive khác loại** trong tập {A, W, E} quan sát trên cùng cặp `(actor_pid, target_pid)` (hoặc self-inject khi `actor == target`), thỏa memory congruence và temporal ordering [4].

**Lý do:** Malware E2 thường che một bước — section mapping che allocate/write tách rời; Mockingjay che allocate. Yêu cầu 3/3 gây false negative cao. Yêu cầu 1/1 không đủ (chỉ `OpenProcess` là access, không phải primitive). Ngưỡng 2/3 cân bằng recall/precision theo đánh giá paper trên dataset lớn [4].

**Formal (ký hiệu):**

- `P` — tập primitive quan sát trong cửa sổ thời gian `T` (Noirlycan: 300 giây).
- `kind(p) ∈ {A, W, E}` — loại primitive.
- Điều kiện: `|{kind(p) : p ∈ P}| ≥ 2` ∧ `congruent(P)` ∧ `temporal(P)`.

### 1.5.3. Memory range congruence

Với mỗi primitive `p`, ghi `range(p) = [addr(p), addr(p)+size(p))` (khoảng nửa mở). Hai primitive `p`, `q` **congruent** nếu `range(p) ∩ range(q) ≠ ∅` hoặc một range chứa range kia [4], [12].

**Thách thức thực thi:** Execute API như `ResumeThread` không có address — paper track thread start address (`Rip`/`RIP`). Frida hook nên đọc `lpStartAddress` từ `CreateRemoteThread` / `NtCreateThreadEx` để gắn address cho primitive E (deviation D1 trong audit Noirlycan).

**Cross-kind only:** Engine Noirlycan so congruence giữa các kind khác nhau (A↔W, W↔E, A↔E) — đủ link chuỗi injection; tránh gom nhầm hai write độc lập cùng kind.

### 1.5.4. Temporal ordering

Thứ tự hợp lệ: **allocate → write → execute**, với ngoại lệ:

- **Gộp bước:** A và W đồng thời (section map) — timestamp bằng nhau hoặc map ngay sau create section.
- **Allocate lặp:** `VirtualProtectEx` sau write để RW→RX — vẫn là allocate kind, được phép lặp sau write [4].
- **Reject:** allocate *sau* execute (out-of-order không hợp lý cho injection chuẩn).

Noirlycan gán bậc `A=0, W=1, CONTEXT_READ=2, E=3`; reject khi allocate xuất hiện sau bậc cao hơn (deviation D3: cần siết thêm write sau execute).

### 1.5.5. Phân loại kỹ thuật sau phát hiện

Sau khi 2-of-3 kết luận injection, paper [4] dùng **tập API quan sát** và context (suspended process, section flag, APC, …) để gán nhãn kỹ thuật: Classic Remote Thread, APC, Early Bird, Thread Hijacking, Process Hollowing (classic/section), Reflective DLL, Module Stomping, AtomBombing, Process Doppelgänging, Ghosting/Herpaderping, v.v. Noirlycan mở rộng **21+ enum** (`InjectionTechnique`) bao gồm PoolParty, Mockingjay, fiber, thread pool [13].

### 1.5.6. Chuỗi injection đệ quy

Paper [4] báo ~**2 %** mẫu có injection lồng: A inject B, B inject C. Framework theo dõi re-trace khi victim resume. Noirlycan `injection_graph.py` và auto-attach Frida hỗ trợ một phần — metric prevalence chưa tái lập đủ quy mô paper.

## 1.6. Taxonomy kỹ thuật process injection (chi tiết)

Phần này mô tả **mười hai kỹ thuật chính** theo paper [4] cộng biến thể mở rộng trong Noirlycan — mỗi kỹ thuật: cơ chế, primitive điển hình, né tránh liên quan.

### 1.6.1. Classic Remote Thread Injection

**Cơ chế:** `OpenProcess` → `VirtualAllocEx` (A) → `WriteProcessMemory` (W) → `CreateRemoteThread` (E) trỏ `lpStartAddress` tới shellcode.

**Né tránh:** E1 (`NtCreateThreadEx`); E3 (target `explorer.exe`); E4 (direct syscall).

**Phát hiện [4]:** A+W+E — case đơn giản nhất cho 2-of-3.

### 1.6.2. DLL Injection (LoadLibrary)

**Cơ chế:** Thay shellcode bằng đường dẫn DLL; `CreateRemoteThread` gọi `LoadLibraryA/W` (E) sau khi write path string (W) vào remote memory (A thường implicit).

**Né tránh:** E3 — DLL dropped disk; E1 — `LdrLoadDll`.

**Phát hiện:** W+E; file provenance bổ sung cho E3.

### 1.6.3. APC Injection

**Cơ chế:** `OpenProcess`/`OpenThread` → allocate/write shellcode → `QueueUserAPC` (E) — APC queue gắn thread alertable; execute khi thread vào trạng thái alertable.

**Né tránh:** E2 — thiếu remote thread rõ ràng; E1 — `NtQueueApcThreadEx`.

**Phát hiện [4]:** W+E phổ biến; cần thread alertable hoặc force alert.

### 1.6.4. Early Bird APC Injection

**Cơ chế:** `CreateProcess(..., CREATE_SUSPENDED)` → allocate/write vào process con suspended → `QueueUserAPC` trên thread chính → `ResumeThread` (E). APC chạy trước entrypoint chính.

**Né tránh:** E2, E3 — không cần inject process đang chạy; victim mới spawn trông “sạch”.

**Phát hiện:** Evidence `create_suspended` + APC + resume; classifier `EARLY_BIRD_APC_INJECTION`.

### 1.6.5. Thread Execution Hijacking

**Cơ chế:** Suspend thread nạn nhân → `GetThreadContext` (context read) → sửa `Rip`/`RSP` → `SetThreadContext` (E) → `ResumeThread`.

**Né tránh:** E2 — không tạo thread mới (khó Event 8); E1 — `NtGetContextThread`/`NtSetContextThread`.

**Phát hiện [4]:** W + CONTEXT_READ + E; memory congruence qua `Rip` (extension D1 Noirlycan).

### 1.6.6. Process Hollowing (classic)

**Cơ chế:** `CreateProcess` suspended → `NtUnmapViewOfSection` unmap image gốc → allocate/write image độc hại → set thread context entrypoint → resume.

**Né tránh:** E1, E2, E3 — victim là process hợp pháp (`svchost` pattern).

**Phát hiện:** A+W+E hoặc unmap (write kind) + set context + resume; `PROCESS_HOLLOWING_CLASSIC`.

### 1.6.7. Process Hollowing (section-mapping variant)

**Cơ chế:** Dominant trong dataset [4]: `NtCreateSection` từ file payload → `NtMapViewOfSection` remote thay image → `SetThreadContext` + `ResumeThread`. Case study **Neurevt** trong paper §3.5.

**Né tránh:** E2 mạnh — gộp allocate+write.

**Phát hiện:** `NtMapViewOfSection` (W) + `ResumeThread` (E) = 2-of-3; test Noirlycan `test_detects_section_mapping_write_execute_chain`.

### 1.6.8. Reflective DLL Injection

**Cơ chế:** Loader manual-map PE DLL vào memory: parse headers, relocations, imports — **không** gọi `LoadLibrary`. Execute qua export hoặc shellcode bootstrap.

**Né tránh:** E1, E3 — không file DLL load event rõ; E6 — anti-analysis trong loader.

**Phát hiện [4]:** W+E; heuristic loại `LoadLibrary` present; Sysmon Event 7 (ImageLoad) absent cho reflective.

### 1.6.9. Module Stomping / Overloading

**Cơ chế:** Load DLL hợp pháp (RWX section hoặc RW) → ghi đè `.text` (W) → execute trong export/function pointer (E).

**Né tránh:** E2 — tái sử dụng mapping có sẵn; E3 — DLL signed.

**Phát hiện:** W+E trên range module đã load; ImageLoad trước write.

### 1.6.10. Process Doppelgänging

**Cơ chế:** Lạm dụng **NTFS transaction**: tạo file transacted, ghi payload, `CreateProcess` từ transacted section, rollback transaction — process chạy image “ma” không tồn tại disk.

**Né tránh:** E1, E3 — forensics disk miss file.

**Phát hiện:** Transaction API + spawn + inject primitives; `PROCESS_DOPPELGANGING` enum.

### 1.6.11. Process Ghosting và Process Herpaderping

**Ghosting:** Tạo file delete-pending, map section, ghi payload, tạo process từ section, đóng handle file (file bị xóa khi handle hết).

**Herpaderping:** Map file legitimate, ghi đè payload, tạo process, sau đó mới “sửa” file view — lừa scanner đọc file sạch.

**Né tránh:** E2, E3 — file system forensics khó.

**Phát hiện:** Pattern spawn + section + write; enum `PROCESS_GHOSTING`, `PROCESS_HERPADERPING` trong Noirlycan.

### 1.6.12. AtomBombing

**Cơ chế:** Ghi payload vào **global atom table** → `GlobalGetAtomName`/`NtQueueApcThread` kết hợp trick copy từ atom sang memory nạn nhân — execute qua APC.

**Né tránh:** E2 — đường dẫn không classic VirtualAllocEx.

**Phát hiện:** `GlobalAddAtom` (execute class trong manifest) + APC + write.

### 1.6.13. SetWindowsHookEx Injection

**Cơ chế:** Cài hook (`SetWindowsHookEx`) trỏ tới DLL trong process nạn nhân (thường cần DLL trong shared memory hoặc inject DLL trước).

**Né tránh:** E3 — DLL hợp pháp; execute qua message loop.

**Phát hiện:** `SetWindowsHookEx` (E) + W; `HOOK_INJECTION`.

### 1.6.14. Mockingjay Injection

**Cơ chế:** Tìm section **RWX** trong DLL signed (ví dụ `ssh.exe`, Chromium Embedded) → chỉ `WriteProcessMemory` (W) + hijack execution (E) — **không allocate** [7].

**Né tránh:** E2 mạnh — chỉ 2 primitive.

**Phát hiện [4]:** W+E đủ 2-of-3; classifier `MOCKINGJAY`.

### 1.6.15. PoolParty (Thread Pool)

**Cơ chế:** Lạm dụng Windows thread pool: queue work item / timer / wait callback trỏ shellcode đã write — execute không qua remote thread API cổ điển.

**Né tránh:** E2, E4 — tránh CreateRemoteThread signature.

**Phát hiện:** W + execute qua pool API (extension `POOLPARTY`); cần hook sâu hơn.

**Bảng 1.5.** Tóm tắt kỹ thuật injection, primitive và né tránh

| # | Kỹ thuật | Primitive điển hình | E1 | E2 | E3 |
|---|----------|---------------------|----|----|-----|
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

**Sysmon** (System Monitor) là thành phần Sysinternals ghi log hành vi hệ thống qua driver kernel `SysmonDrv.sys` [10]. Trong luận văn, Sysmon đóng vai **lớp phòng thủ chống E4** — quan sát artifact cross-process mà không phụ thuộc hook user-mode.

### 1.7.1. Kiến trúc Sysmon

Sysmon.exe (service LocalSystem) đăng ký với driver; driver cài callback kernel:

- `PsSetCreateProcessNotifyRoutineEx` — process create/exit.
- `PsSetLoadImageNotifyRoutine` — DLL/EXE map.
- `ObRegisterCallbacks` — handle operation (OpenProcess).
- Minifilter — file create.
- ETW Threat Intelligence — CreateRemoteThread, …

Log ghi vào Windows Event Log (channel `Microsoft-Windows-Sysmon/Operational`).

### 1.7.2. Sự kiện Sysmon trong phạm vi Noirlycan

**Bảng 1.6.** Sự kiện Sysmon và vai trò phát hiện injection / né tránh

| Event ID | Tên | Cơ chế kernel | Chống né tránh | Vai trò Noirlycan |
|----------|-----|---------------|----------------|-------------------|
| **1** | ProcessCreate | Process notify | E3, E4 (syscall spawn vẫn log) | Lineage, parent PID, `CreationUtcTime`, command line, `CurrentDirectory` |
| **3** | NetworkConnect | WFP ETW | — | Post-injection C2 beacon watch |
| **7** | ImageLoad | Image notify | E4 (kernel) | Phân biệt reflective vs LoadLibrary |
| **8** | CreateRemoteThread | ETW TI | **E4** — kể cả direct syscall | Fallback execute primitive; `SourceImage`, `TargetImage`, `StartAddress` |
| **10** | ProcessAccess | ObRegisterCallbacks | **E4** | `OpenProcess` với `GrantedAccess` suspicious (`0x1fffff`, `0x143a`, …) |
| **11** | FileCreate | Minifilter | E3 | File-drop provenance; hash SHA256 (config Noirlycan) |
| **15** | FileCreateStreamHash | Minifilter | E3 alt | ADS (ít dùng trong config hiện tại) |

Config `sysmon-noirlycan.xml` [13]: ProcessCreate broad; FileCreate filter extension executable/script; ProcessAccess filter access mask; CreateRemoteThread exclude none (log all); ImageLoad filter `ntdll`, `kernel32`.

### 1.7.3. Giới hạn Sysmon

- **Không** có đối số đầy đủ mọi NT API (vd. size write, protection flags) — Frida bổ sung congruence.
- **Kernel rootkit** (O3 threat model) có thể blind driver — out-of-scope.
- Event 8 không cover mọi execute vector (APC-only, thread pool) — cần Frida.
- Volume log cao nếu config quá rộng — lab VM chấp nhận được.

### 1.7.4. Sysmon và E4 — ma trận tin cậy

Khi malware direct-syscall `NtCreateThreadEx`:

- Frida miss → không có primitive chi tiết từ hook export.
- Sysmon Event 8 vẫn fire (kernel ETW TI) → có `StartAddress`, `SourceImage`, `TargetImage`.

Correlator Noirlycan merge hai nguồn: Sysmon event chuyển thành primitive EXECUTE sơ cấp; Frida cung cập W/A với address. Congruence có thể yếu hơn paper — khai báo trong đánh giá RQ2/RQ4.

## 1.8. Frida — instrumentation user-mode và kiến trúc telemetry kép

### 1.8.1. Frida overview

**Frida** là toolkit dynamic instrumentation [5]: inject **agent** JavaScript (V8) vào process target qua `frida-server` hoặc `frida-gadget`; hook function bằng `Interceptor.attach(address, { onEnter, onLeave })`. Noirlycan dùng Frida để:

- Hook export `kernel32.dll` / `ntdll.dll` liên quan injection (manifest `PAPER_API_CLASSES` + extensions iRed.team).
- Trích xuất đối số: `lpBaseAddress`, `nSize`, `flAllocationType`, `lpStartAddress`, `lpBuffer`, process/thread handles.
- Emit **observation** tới collector Python qua message bus JSON.

Script `windows_injection_hooks.js` (~1900 dòng) [13] implement helper normalize API (`Zw*` alias `Nt*`), xử lý CONTEXT pointer cho thread hijack, và phân biệt `emit` vs `emitObservation` (read-only không đếm 2-of-3).

### 1.8.2. Ưu điểm so với chỉ Sysmon

| Khía cạnh | Frida | Sysmon |
|-----------|-------|--------|
| Đối số API (addr, size, prot) | ✓ Chi tiết | ✗ Hạn chế |
| Memory congruence [4] | ✓ Trực tiếp | △ Một phần (StartAddress) |
| APC, MapView, Protect | ✓ Hook NT | ✗ Không log hết |
| Overhead | Cao hơn | Thấp hơn |
| E4 direct syscall | ✗ Miss | ✓ Event 8/10 |
| E6 anti-Frida | ✗ Risk | ✓ Không agent trong victim hook path |

### 1.8.3. Chế độ attach và E6

- **`spawn`:** Frida tạo process suspended, inject agent trước entrypoint — giảm miss primitive đầu (T2 threat model); giảm cửa sổ malware chạy trước hook.
- **`attach`:** Gắn process đang chạy — phù hợp file-drop đã spawn; risk miss early API.
- **`auto-attach-new-processes`:** Theo dõi victim sau injection đệ quy [4].

E6: malware scan Frida artifact → luận văn **không** triển khai stealth agent; ghi limitation và khuyến nghị spawn cho thí nghiệm.

### 1.8.4. Kiến trúc kép Sysmon ∪ Frida (Hình 1.1)

Luận văn đề xuất kiến trúc **tăng cường phát hiện dưới né tránh** bằng cách kết hợp:

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

**Hình 1.1** (mô tả conceptual; bản đồ kiến trúc đầy đủ tại `docs/design/architecture-comparison-template.svg` và Chương 5) thể hiện trust boundary: Frida (user, untrusted nếu E4/E6) + Sysmon (kernel, trusted nếu O3 không xảy ra) → correlator (trusted).

### 1.8.5. Fidelity và giả định M5

Luận văn giả định Frida hook **trung thực** về thứ tự và đối số (M5 threat model) — cần benchmark Frida fidelity (Phụ lục E): so sánh N lần gọi API với ground truth ETW/`SilkETW` hoặc controlled PoC. Overhead hook có thể thay đổi timing — **không** claim đo lường E5 timing evasion.

### 1.8.6. Hướng thay thế: ETW Threat Intelligence

Microsoft **ETW Threat Intelligence** provider cung cấp syscall-level event kernel — không bypass bằng user-mode unhooking. Luận văn ghi nhận hướng phát triển thay/bổ sung Frida (Kết luận); hiện thực Noirlycan dùng Sysmon (đã tích hợp ETW TI cho Event 8) làm bước trung gian.

### 1.8.7. Tóm tắt chương

Chương 1 đã trình bày nền tảng lý thuyết cho luận văn *Tăng cường phát hiện mã độc dưới các hình thức né tránh*:

1. **Mô hình Windows** — process, thread, virtual memory, section object, và lớp Win32/NT API — bối cảnh mọi kỹ thuật injection.
2. **Process injection** — hành vi né attribution (T1055), prevalence ~16,5 % theo [4], chuỗi file-drop → spawn → inject trong lab.
3. **Sáu nhóm né tránh E1–E6** — từ biến thể API (E1) đến anti-sandbox (E5, **ngoài phạm vi hiện thực**) và anti-Frida (E6, hạn chế).
4. **Phương pháp [4]** — operational primitive (allocate, write, execute), equivalence class, quy tắc 2-of-3, memory congruence, temporal ordering — **căn cứ khoa học chính** của correlator Noirlycan.
5. **Taxonomy 15+ kỹ thuật** — từ classic remote thread đến PoolParty/Mockingjay, mỗi kỹ thuật gắn primitive và nhóm né tránh.
6. **Sysmon** — telemetry kernel (Event 1, 7, 8, 10, 11) fallback chống E4, provenance chống E3.
7. **Frida** — telemetry user-mode chi tiết cho congruence; kiến trúc kép Sysmon ∪ Frida tăng độ bền phát hiện dưới né tránh hook.

Chương 2 sẽ đặt phương pháp [4] trong bức tranh công trình liên quan (Klein [7], Starink [12], sandbox evasion [6], [8]) và làm rõ vị trí đóng góp replication + extension lab của luận văn so với nghiên cứu quy mô 56.340 mẫu của tác giả gốc.
