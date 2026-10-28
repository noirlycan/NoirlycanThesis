# Đề xuất: thay lớp monitoring Frida bằng telemetry phía kernel, giữ nguyên phương pháp của paper

**Mục tiêu:** Frida (hook user-mode trên export `ntdll`/`kernel32`) dễ bị bypass
bởi direct/indirect syscall, unhooking và anti-Frida. Tài liệu này đề xuất thay
**monitoring module** bằng telemetry phía kernel, còn **analysis module**
(ba primitive, quy tắc 2/3, memory congruence, temporal ordering) **giữ nguyên
đúng như paper**.

Mọi trích dẫn paper ở đây đều đối chiếu với bản PDF
(`diag.uniroma1.it/delia/papers/asiaccs25.pdf`). Những điểm về Windows internals
được đánh dấu **[verify]** thì phải kiểm lại trên đúng build Windows của lab
trước khi đưa vào luận văn.

---

## 1. Paper thực sự nói gì về lớp monitoring

| Điểm | Paper nói | Vị trí |
|------|-----------|--------|
| Công cụ tracing | **BluePill** (framework phân tích malware evasive) chạy trên **Intel Pin (DBI)**. Không phải QEMU, cũng không phải custom tracer. | §3.3 *Monitoring module* |
| Mức hook | "intercept functions at **both the library and system call levels**" | §3.3 |
| Số API | 74 API (101 nếu tính riêng biến thể A/W) | §3.3, Appendix B |
| Theo dõi đa tiến trình | Pin `-follow_execv` + mở rộng tracking sang tiến trình bị inject | §3.3 |
| Lọc nhiễu | Một call chỉ được tính khi **return address nằm trong code của mẫu**; dùng interval tree chứa code range của các DLL Windows hợp lệ | §3.3 |
| Rủi ro tự nhận của bộ lọc | Attacker đặt return address là gadget nằm trong DLL → có thể chặn bằng cách "verifying the legitimacy of the return address" | §3.3 |
| Ablation | Hiện thực lại trên **Microsoft Detours** (không có anti-evasion) để đo ảnh hưởng của evasion | §3.3, §5 |
| Giả định | "we assume the instrumentation framework is **trusted and resilient** to techniques designed to evade API call logging", có thể nới nếu có mitigation trực giao [3] (Assaiante et al., DIMVA 2024, *Evading Userland API Hooking, Again*) | §3 (threat model) |
| Tính pluggable | "The approach ... can be **integrated into any dynamic analysis system that intercepts API calls**" | §3.3 |
| Scope | Chỉ malware userspace; rootkit/kernel exploit nằm ngoài scope | §3 |

**Kết luận cho luận văn:**

1. Phương pháp của paper **không gắn với một tracer cụ thể** — nó chỉ cần
   *(API/operation, actor, victim, address, size, protection, thứ tự)*. Đổi sensor
   là việc paper cho phép một cách tường minh.
2. Frida ở chế độ hiện tại (`Interceptor.attach` vào export,
   `src/noirlycan_agent/frida_hooks/runtime.js:474`) **yếu hơn tracer của paper**:
   Pin quan sát được chính lệnh `syscall` dù nó chạy từ vùng nhớ nào, còn Frida
   chỉ thấy những call đi qua prologue của export đã bị hook. Như vậy repo hiện
   **vi phạm giả định "trusted and resilient"** của paper — nên sửa ngay chỗ này
   thay vì chỉ khai báo là out-of-scope.

---

## 2. Những điểm trong docs/thesis hiện tại cần sửa

| # | Hiện đang ghi | Thực tế | Chỗ cần sửa |
|---|---------------|---------|-------------|
| F1 | Paper dùng "custom tracer trong sandbox QEMU", "anti-evasion patch QEMU TCG"; "21,2 % = ablation anti-evasion"; RQ1–RQ3 diễn giải sai | BluePill/Pin (DBI), ablation bằng Detours (6,2 % vs 11,8 %); 21,2 % là tỷ lệ VirusTotal/CAPE bỏ sót; RQ theo nguyên văn §5 — **đã sửa** trong thesis và docs | `docs/paper-and-repo-analysis.md:106,191,194`, `docs/architecture-diagrams*.md`, `thesis/chapters/01-mo-dau.md:13`, `04-threat-model.md:164`, `07-danh-gia.md:336`, `08-thao-luan.md:21,100,108,143,206` |
| F2 | Trust matrix: "Sysmon Event 8 — cơ chế: ETW Threat Intelligence"; §3.1 liệt kê ETW TI dưới `SysmonDrv.sys` | **[verify]** Theo hiểu biết của mình, Event 8 lấy từ thread-creation notify callback (`PsSetCreateThreadNotifyRoutine`, so creator PID ≠ owner PID), và Sysmon **không** consume ETW TI (vì consumer phải chạy PPL-Antimalware) | `docs/audit-and-threat-model.md` §3.1, §3.8 |
| F3 | "Paper không cho phép đảo bậc" | Paper cho phép các thao tác phụ (vd. resolve `LoadLibrary`) xảy ra ngoài thứ tự chuẩn, miễn là trước execute; ràng buộc thứ tự chỉ áp lên tập thao tác cốt lõi | `docs/paper-and-repo-analysis.md` §2.3.4 |

F1 là lỗi nặng nhất: hội đồng có đọc paper sẽ thấy ngay, và nó làm sai luôn
lập luận "Frida vs tracer của paper" ở Chương 8.

---

## 3. Kiến trúc đề xuất

### 3.1. Nguyên tắc thiết kế (lấy từ chính paper)

Paper tách hai việc (§3.2): (a) **phát hiện** dựa trên *tập thao tác cốt lõi
tối thiểu*; (b) **phân loại** kỹ thuật dựa trên *mọi thông tin bổ sung còn lại*.
Đề xuất ánh xạ thẳng việc tách này vào hai nhóm sensor:

- **Detection** (2/3 + congruence + temporal) → chỉ dùng nguồn **sinh ra trong
  kernel**, malware user-mode không chặn được bằng syscall stub hay unhooking.
- **Classification** (phân biệt hollowing vs. shellcode vs. hook injection vs.
  atom bombing…) → được phép dùng nguồn user-mode (Frida) để lấy ngữ nghĩa
  Win32 chi tiết. Nếu nguồn này bị bypass thì chỉ mất độ chính xác phân loại,
  **không mất detection**.

### 3.2. Các lớp sensor

```
┌────────────────── Windows lab VM ──────────────────────────────────┐
│                                                                    │
│  K1  ETW Threat-Intelligence (kernel-emitted)                      │
│      noirlycan-ti-sensor.exe  [PPL-Antimalware-Light, native C++]  │──┐
│                                                                    │  │
│  K2  Sysmon EID 1/7/8/10/11 + Microsoft-Windows-Kernel-Process     │──┤
│      (thread start address, handle access + CallTrace)             │  │
│                                                                    │  │ JSONL / named pipe
│  U   Frida (giảm vai trò → enrichment cho classification)          │──┤
│                                                                    │  │
│  C   Kiểm tra call-stack / nguồn gốc syscall (mở rộng bộ lọc       │──┤
│      return-address của paper)                                     │  │
│                                                                    │  ▼
│  Python collector: chuẩn hóa → Primitive{kind, actor, victim,      │
│      addr, size, prot, ts, sensor} → detection/rules.py (GIỮ NGUYÊN)│
└────────────────────────────────────────────────────────────────────┘
```

#### K1 — ETW Threat Intelligence (sensor chính cho detection)

Provider `Microsoft-Windows-Threat-Intelligence` do kernel phát khi có thao tác
bộ nhớ/thread **cross-process**, bất kể userland gọi qua Win32, Nt*, direct hay
indirect syscall. Event có sẵn đúng các field paper cần (tiến trình gọi, tiến
trình đích, base address, region size, protection).

Ánh xạ sang primitive của paper (tên event lấy từ manifest; ID và field cụ
thể phải dump lại trên build của lab — **[verify]**):

| Primitive paper | Event ETW TI | Field dùng cho congruence |
|-----------------|--------------|---------------------------|
| **Allocate** | `ALLOCVM_REMOTE`, `PROTECTVM_REMOTE` | BaseAddress, RegionSize, Protection |
| **Allocate + Write** (gộp bước, case *neurevt*) | `MAPVIEW_REMOTE` | ViewBase, ViewSize, Protection |
| **Write** | `WRITEVM_REMOTE` | BaseAddress, BytesCopied |
| **Execute** | `SETTHREADCONTEXT_REMOTE`, `QUEUEUSERAPC_REMOTE`, `RESUME_THREAD` / `RESUME_PROCESS` | địa chỉ APC routine / context nếu có; nếu không có thì để address = None (giống xử lý hiện tại) |
| *(phụ trợ, không tính 2/3)* | `READVM_REMOTE`, `SUSPEND_THREAD` | — |

Thứ K1 **không** có: event tạo remote thread → lấy từ K2. Thực thi kiểu
threadless/callback (PoolParty, threadless inject, IAT hook) không sinh event
execute → đúng là tình huống quy tắc 2/3 của paper sinh ra để xử lý:
`PROTECTVM_REMOTE` + `WRITEVM_REMOTE` trên cùng vùng nhớ đã đủ để kết luận.

**Lưu ý [verify]:** Microsoft lọc bớt một số event TI để giảm volume (ví dụ có
event chỉ log khi protection có quyền execute, hoặc chỉ cho trường hợp remote).
Phải đo coverage thực tế cho từng kỹ thuật PoC và ghi vào chương Đánh giá —
đây đồng thời là một kết quả thực nghiệm.

**Ràng buộc triển khai:** consumer của TI phải chạy dưới dạng
**PPL Antimalware-Light**, tức là cần driver ELAM. Cách làm trong lab:

1. VM: tắt Secure Boot, `bcdedit /set testsigning on`.
2. Tạo cert test, ký một ELAM driver tối giản + ký luôn binary sensor bằng
   cùng cert đó.
3. Cài service với `SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT`.
   Tham khảo công khai: *PPLRunner* và *SealighterTI* của pathtofile
   (**[verify]** xem chúng còn chạy trên build Windows lab không).
4. Sensor viết bằng C++ (krabsetw) hoặc Rust (ferrisetw) — **không** dùng Python,
   vì tiến trình PPL chỉ load được image ký đúng signer, `python.exe` và các
   DLL của nó sẽ bị chặn. Sensor ghi JSONL / named pipe, Python collector đọc lại.

Phải khai báo đây là **lab deviation** (test-signing, Secure Boot tắt). Một
EDR thật dùng ELAM cert do Microsoft cấp, cơ chế y hệt.

#### K2 — Sysmon + Kernel-Process (không cần PPL, làm được ngay)

Repo đã thu Sysmon EID 8 và 10 nhưng mới lưu dạng `TelemetryEvent` thô
(`src/noirlycan_agent/collector/infrastructure/sysmon.py:131-139`), **chưa
chuyển thành primitive**. Có thể lấy thêm mà không cần driver:

| Nguồn | Field | Dùng làm gì |
|-------|-------|-------------|
| Sysmon EID 8 | `SourceProcessId`, `TargetProcessId`, **`StartAddress`**, `StartModule`, `StartFunction` | Primitive **Execute có address** → khôi phục memory congruence cho `CreateRemoteThread`/`NtCreateThreadEx`, kể cả khi bị direct syscall. Đây cũng là cách sửa D1 mà không phụ thuộc Frida. `StartModule` rỗng = thread start trong vùng nhớ không có file backing → tín hiệu rất mạnh. |
| Sysmon EID 10 | `GrantedAccess`, **`CallTrace`** | Lấy handle `PROCESS_VM_WRITE \| VM_OPERATION \| CREATE_THREAD` làm context actor→victim; `CallTrace` có frame `UNKNOWN` = lời gọi xuất phát từ shellcode/unbacked memory (input cho lớp C). |
| `Microsoft-Windows-Kernel-Process` (ETW thường) | ThreadStart (+ Win32StartAddress), ProcessStart, ImageLoad | Bản dự phòng cho EID 8, thời gian chính xác hơn so với poll Event Log |
| `Microsoft-Windows-Kernel-Audit-API-Calls` **[verify field]** | OpenProcess / OpenThread / SetContextThread | Context cho hollowing / thread hijack |

#### U — Frida (hạ vai trò thành enrichment)

Giữ Frida cho những gì kernel không cho: tên API Win32 chính xác, biến thể A/W,
`SetWindowsHookEx`, `SetProp`/`SendNotifyMessage` (PROPagate), atom table,
`NtSetInformationProcess` class 40… Các tín hiệu này chỉ đi vào
`technique_classifier.py`, không đi vào điều kiện 2/3.

#### C — Nguồn gốc lời gọi (mở rộng bộ lọc return-address của paper)

Paper lọc theo *return address* và tự nhận rủi ro bị gadget đánh lừa, kèm gợi ý
"verify the legitimacy of the return address". Đề xuất làm đúng gợi ý đó, nhưng
lấy dữ liệu từ kernel:

- Bật **stack walking** cho phiên ETW (cờ stack trace cho K1/K2) hoặc dùng
  `CallTrace` của Sysmon EID 10.
- Quy tắc: event K1/K2 mà **frame user-mode sâu nhất không nằm trong
  `ntdll.dll`** → *direct syscall*; frame trên ntdll **không** quay về module
  hợp lệ, hoặc có frame trong vùng unbacked → *indirect syscall / call-stack
  spoofing nghi vấn*.
- Kết quả là **evasion indicator** gắn vào finding (cộng điểm), **không** phải
  điều kiện bắt buộc để phát hiện — để phương pháp lõi vẫn y nguyên paper.

#### Cross-layer differential (đóng góp riêng của luận văn)

Cùng một thao tác (actor, victim, range khớp, Δt nhỏ) mà **K1 thấy nhưng Frida
không thấy** → bằng chứng trực tiếp là hook user-mode đã bị bypass. Biến chính
điểm yếu của Frida thành một detector: Frida càng bị né thì độ lệch càng lộ.

### 3.3. Thay đổi trong analysis module — tối thiểu, có chủ đích

| Thành phần | Thay đổi |
|------------|----------|
| `Primitive` (models) | Thêm field `sensor: kernel_ti \| sysmon \| kernel_etw \| frida` và `origin: ntdll \| direct \| unbacked \| unknown` |
| Dedupe | Gộp primitive cùng (actor, victim, kind, range overlap, \|Δt\| < ε) đến từ nhiều sensor; ưu tiên field của sensor kernel |
| `detection/rules.py` 2/3 / congruence / temporal | **Không đổi logic.** Đây là điểm bảo vệ "bám sát paper" trước hội đồng |
| Scoring | Tách `detection_basis` (sensor nào đã thỏa 2/3) khỏi `evasion_indicators` |

---

## 4. Cập nhật threat model

| Năng lực đối thủ | Trước (Frida + Sysmon) | Sau (K1 + K2 + U + C) |
|------------------|------------------------|-----------------------|
| O1 Direct syscall | Mất args, mất congruence | **In-scope**: K1 vẫn có args, congruence giữ nguyên; lớp C còn gắn cờ evasion |
| O2 Unhooking ntdll | Như O1 | **In-scope**: K1 không phụ thuộc hook; ImageLoad ntdll từ đường dẫn lạ (EID 7) là tín hiệu bổ sung |
| Indirect syscall | Không bàn | **In-scope một phần**: K1 bắt được thao tác; lớp C phát hiện tùy mức độ spoofing stack |
| O5 Anti-Frida | Mẫu dừng injection | Nếu mẫu chỉ dò Frida: chạy ở **chế độ không có Frida** (chỉ K1+K2) → mất classification chi tiết, không mất detection |
| Patch ETW ở user-mode (`EtwEventWrite`) | — | Không ảnh hưởng K1/K2 (event phát trong kernel); chỉ ảnh hưởng provider user-mode |
| O3 Đối thủ kernel / BYOVD | Out-of-scope | **Vẫn out-of-scope** — giống paper |
| O7 Anti-evasion (sandbox-aware) | Out-of-scope | Vẫn out-of-scope; K1/K2 không inject gì vào target nên bề mặt bị phát hiện **nhỏ hơn** Frida/Pin |

Giả định M5 ("Frida trung thực") được thay bằng M5' "ETW không làm rơi event
dưới tải" — đo bằng counter `EventsLost` / `BuffersLost` của phiên ETW, dễ hơn
và khách quan hơn benchmark Frida hiện tại.

---

## 5. Thiết kế đánh giá — ablation theo sensor, song song với ablation của paper

Paper làm ablation **BluePill vs Detours** để đo ảnh hưởng của evasion. Luận văn
làm ablation **theo sensor** để đo ảnh hưởng của việc bypass hook:

**Ma trận thí nghiệm:** với mỗi kỹ thuật PoC trong benchmark (shellcode,
section-mapping hollowing, APC/Early Bird, thread hijack, threadless/PoolParty…),
chạy các biến thể gọi:

| Biến thể | Mô tả |
|----------|-------|
| V1 | Win32 API (`VirtualAllocEx`…) |
| V2 | Native API (`Nt*` qua ntdll) |
| V3 | Direct syscall (stub nằm trong image của loader) |
| V4 | Indirect syscall (nhảy vào lệnh `syscall` trong ntdll) |
| V5 | Unhook ntdll trước rồi gọi V2 |

**Cấu hình sensor:** `Frida-only` · `Sysmon-only` · `K1+K2` · `K1+K2+U+C` ·
(tùy chọn) `BluePill/Pin` lấy từ artifact paper để làm baseline sát nhất với paper.

**Metric:** detection (thỏa 2/3), congruence hợp lệ (có địa chỉ thật, không phải
nhánh "bỏ qua vì thiếu address"), technique classification đúng, evasion
indicator đúng, overhead (theo đúng cách paper đo — so với baseline sensor
không có logic phân tích).

Kết quả kỳ vọng phải **đo ra rồi mới viết**, không điền trước: Frida-only rớt từ
V3 trở đi; K1+K2 giữ detection ở V1–V5; classification của K1+K2 thấp hơn khi
không có U.

---

## 6. Lộ trình triển khai trong repo

| Bước | Việc | File | Cần driver? |
|------|------|------|-------------|
| 1 | Parse Sysmon EID 8 → `Primitive(EXECUTE, address=StartAddress)`; EID 10 → context access + CallTrace | `collector/infrastructure/sysmon.py`, `core/detection/primitives.py` | Không |
| 2 | Thêm `sensor`/`origin` vào `Primitive` + dedupe đa sensor | `core/models.py`, `core/detection/correlator.py` | Không |
| 3 | Consumer `Microsoft-Windows-Kernel-Process` (ETW thường) | `collector/infrastructure/kernel_etw.py` (mới) | Không |
| 4 | `noirlycan-ti-sensor` (C++/krabsetw) + ELAM test-signed + service PPL | `sensors/ti/` (mới), `scripts/install-ti-sensor.ps1` | **Có** (test-signing) |
| 5 | Adapter đọc JSONL/pipe của TI sensor → primitive | `collector/infrastructure/etw_ti.py` (mới) | — |
| 6 | Lớp C: phân tích stack/CallTrace → `origin` + evasion indicator | `core/extensions/evasion.py` | Không |
| 7 | Chế độ chạy `--no-frida` (chỉ kernel sensor) | `agent/cli.py`, `collector_launcher.py` | Không |
| 8 | Benchmark V1–V5 × cấu hình sensor | `tests/manual/`, `docs/experiments/sensor-ablation.md` | — |
| 9 | Sửa F1–F3, cập nhật Chương 4/5/6/7/8 | `docs/`, `thesis/chapters/` | — |

Bước 1–3 và 6–7 làm được ngay, không cần kernel driver, và đã đủ giải quyết
một phần lớn câu hỏi "Frida bị bypass thì sao". Bước 4–5 là phần nặng nhất
nhưng cũng là phần mang lại giá trị khoa học rõ nhất.

---

## 7. Định khung claim sau khi đổi

**Được claim:**

- Hiện thực phương pháp Di Pietro et al. trên **monitoring module phía kernel**,
  đúng với tính pluggable mà paper khẳng định (§3.3), và thỏa giả định
  "instrumentation resilient" (§3) mà bản Frida-only vi phạm.
- Ablation theo sensor (V1–V5 × cấu hình) cho thấy detection có/không bền
  trước syscall evasion — **số liệu đo được**.
- Cross-layer differential và kiểm tra nguồn gốc syscall như phần mở rộng có
  kiểm chứng của bộ lọc return-address trong paper.

**Không được claim:**

- "Không thể bypass": đối thủ kernel (O3) vẫn tắt được TI; event TI bị lọc theo
  điều kiện; threadless execute không có event execute riêng.
- "Tương đương EDR thương mại": lab dùng test-signing chứ không có ELAM cert
  thật.
- Mọi con số coverage chưa đo trên build Windows của lab.

---

## 8. Hướng xa hơn (Future Work)

- **Out-of-guest / hypervisor** (DRAKVUF, VMI): không có gì chạy trong guest →
  minh bạch nhất trước anti-analysis, nhưng hạ tầng nặng (Xen). Rất hợp để
  nhắc đến như bước kế tiếp tự nhiên sau K1.
- **Hardware tracing** (Intel PT) cho control-flow tại thời điểm execute.
- Chạy lại một subset artifact `Sap4Sec/process-injection` dưới cả BluePill và
  K1+K2 để so trực tiếp với paper.
