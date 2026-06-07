# Phân tích paper ASIA CCS 2025 và repo Noirlycan: cơ sở cho luận văn thạc sĩ

**Tác giả phân tích:** Phan Vinh Co (copv@ssi.com.vn)
**Mục tiêu:** Bài viết hợp nhất phục vụ chương *Background — Related Work — Methodology Positioning* của luận văn thạc sĩ. Trình bày (a) phương pháp của paper gốc, (b) thiết kế repo Noirlycan, (c) mối quan hệ giữa hai, (d) định vị đóng góp luận văn.

---

## 1. Bối cảnh nghiên cứu

### 1.1. Vấn đề: Process injection trong malware Windows hiện đại

Process injection là kỹ thuật then chốt của malware Windows: chuyển payload vào không gian địa chỉ của tiến trình nạn nhân để thực thi dưới danh nghĩa tiến trình đó. Theo MITRE ATT&CK, T1055 (Process Injection) thuộc nhóm *base technique* với 12+ sub-technique đã được tài liệu hóa, từ Classic Remote Thread (1990s) đến Process Ghosting (2021), Mockingjay (2023), PoolParty (2023).

Lý do injection vẫn phổ biến:

1. **Né tránh attribution.** Mã độc chạy trong `explorer.exe` hoặc `msedge.exe` không sinh tiến trình mới đáng ngờ, không đổi parent lineage.
2. **Bypass policy.** Một tiến trình ký số sẵn (signed binary) có quyền truy cập tài nguyên mà malware tự do không có (ví dụ session token).
3. **Persistence linh hoạt.** Inject vào tiến trình hệ thống dài sống thay vì cần cơ chế persistence ổn định.
4. **Né EDR rule cứng.** Mỗi EDR có rule riêng cho từng kỹ thuật; biến thể nhỏ (ví dụ thay `CreateRemoteThread` bằng `NtCreateThreadEx`) đủ để bypass.

### 1.2. Bài toán phát hiện

Phương pháp phát hiện process injection có thể chia ba nhóm:

| Nhóm | Cơ chế | Ưu | Nhược |
|------|--------|-----|-------|
| **Signature API** | Khớp chính xác chuỗi API (vd. `VirtualAllocEx → WriteProcessMemory → CreateRemoteThread`) | Triển khai nhanh | Bị phá bởi biến thể (đổi API tương đương) |
| **Behavior graph** | Đồ thị quan hệ object handle / memory region | Tổng quát hơn signature | Chi phí cao, dễ false positive |
| **Memory forensic** | Dump RAM, scan executable region | Bắt được payload | Offline, không real-time, chi phí I/O lớn |

Không nhóm nào tự nó đủ. Cộng đồng nghiên cứu hai năm gần đây (Klein 2017, Barabosch 2017, Starink 2023, Korkin 2022) đẩy về hướng **operational primitive abstraction** — tách injection thành các "thao tác trên bộ nhớ" tối thiểu, độc lập với cách triển khai cụ thể.

Đây là bối cảnh sinh ra paper ASIA CCS 2025 của Di Pietro, D'Elia, Querzoni — paper trung tâm mà luận văn này tham chiếu.

---

## 2. Phân tích paper gốc

### 2.1. Thông tin định danh

> Di Pietro, G., D'Elia, D. C., & Querzoni, L. (2025).
> *Can You Run My Code? A Close Look at Process Injection in Windows Malware.*
> Proceedings of the 20th ACM Asia Conference on Computer and Communications Security (ASIA CCS '25), Hanoi, Vietnam, Aug 25–29, 2025.
> DOI: [10.1145/3708821.3736206](https://doi.org/10.1145/3708821.3736206).
> Artifact: [github.com/Sap4Sec/process-injection](https://github.com/Sap4Sec/process-injection).

Tác giả thuộc Sapienza University of Rome, có lịch sử nghiên cứu phân tích malware động (D'Elia là tác giả của framework Bluepill và một loạt paper về sandbox evasion).

### 2.2. Câu hỏi nghiên cứu của paper

Paper đặt ra ba câu hỏi:

- **RQ1.** Process injection thực sự phổ biến đến đâu trong malware Windows giai đoạn 2017–2023?
- **RQ2.** Có phương pháp nào tổng quát hơn signature API mà vẫn đủ rẻ để triển khai trên sandbox quy mô lớn không?
- **RQ3.** Sandbox công cộng (Cuckoo, Hatching Triage) bỏ sót bao nhiêu mẫu vì anti-evasion?

### 2.3. Phương pháp cốt lõi: ba operational primitive + quy tắc 2/3

Paper đề xuất khung lý thuyết gồm bốn thành tố:

#### 2.3.1. Ba operational primitive

Mọi process injection user-mode đều phải thực hiện ít nhất ba thao tác trên bộ nhớ của tiến trình nạn nhân (kế thừa và tinh chỉnh từ Klein et al. 2017):

1. **Allocate (A)** — cấp phát vùng nhớ hoặc thay đổi quyền vùng nhớ để chứa được mã thực thi.
2. **Write (W)** — đặt payload vào vùng nhớ đó.
3. **Execute (E)** — kích hoạt thực thi từ vùng nhớ đó.

Đóng góp của paper so với Klein không phải ở chỗ "phát hiện ra 3 bước này" — đó đã là kiến thức nền. Đóng góp là **lớp tương đương API** (*equivalence class*): mỗi primitive ánh xạ đến một tập API có ngữ nghĩa thay thế nhau.

Ví dụ:

- *Allocate*: `VirtualAllocEx`, `NtAllocateVirtualMemory`, `NtCreateSection`, `CreateFileMappingW`, `MapViewOfFile`, `VirtualProtectEx`, `NtProtectVirtualMemory`.
- *Write*: `WriteProcessMemory`, `NtWriteVirtualMemory`, `NtMapViewOfSection`, `RtlCopyMemory`.
- *Execute*: `CreateRemoteThread(Ex)`, `NtCreateThreadEx`, `RtlCreateUserThread`, `QueueUserAPC`, `SetThreadContext`, `ResumeThread`, `LoadLibrary*`, `SetWindowsHookEx*`.

Equivalence class cho phép phát hiện *ngữ nghĩa injection* thay vì *chuỗi API cụ thể* — đây là điểm robust với biến thể triển khai.

#### 2.3.2. Quy tắc 2-of-3

Trong thực tế, một số mẫu kết hợp hai thao tác trong một API (ví dụ `NtMapViewOfSection` vừa cấp phát section, vừa ánh xạ payload). Một số mẫu khác né bước nào đó (ví dụ Mockingjay không cần allocate vì tận dụng RWX section sẵn có trong DLL hợp pháp).

Paper kết luận: yêu cầu quan sát đủ cả ba primitive sẽ tạo false negative; yêu cầu chỉ một primitive sẽ tạo false positive. Cân bằng: **quan sát ít nhất 2/3 primitive khác loại trên cùng cặp (actor, victim)**.

#### 2.3.3. Memory range congruence

Yêu cầu các primitive được correlate phải thao tác trên *vùng nhớ chồng/chứa nhau*. Nếu actor X cấp phát vùng `[a, a+s)` ở target T rồi write vào vùng `[b, b+s')` không giao với `[a, a+s)`, đó là hai hoạt động độc lập — không phải injection chain.

Công thức (paraphrase): hai primitive `p1`, `p2` *congruent* khi
```
[p1.addr, p1.addr + p1.size) ∩ [p2.addr, p2.addr + p2.size) ≠ ∅
```

#### 2.3.4. Temporal consistency

Thứ tự tự nhiên là Allocate → Write → Execute. Paper cho phép:

- **Hợp nhất bước:** một API thực hiện đồng thời 2 primitive (`NtMapViewOfSection` = allocate + write).
- **Lặp:** allocate có thể xuất hiện nhiều lần (ví dụ resize, `VirtualProtect` đổi RW thành RX sau khi write).

Paper **không** cho phép đảo bậc — execute không thể xuất hiện trước write trên cùng vùng nhớ.

### 2.4. Đánh giá thực nghiệm của paper

- **Dataset:** Lọc 334 885 mẫu Windows malware từ VirusTotal Academic và VX Underground Bazaar (2017–2023) xuống 56 340 mẫu đại diện thuộc 2 667 family.
- **Hạ tầng:** Sandbox tùy biến trên QEMU + custom tracer + anti-evasion module.
- **Kết quả chính:**
  - 16,5 % mẫu thể hiện ít nhất một kỹ thuật injection (trung bình giai đoạn 2017–2023, xu hướng tăng theo năm).
  - 21,2 % các mẫu này bị Cuckoo / sandbox phổ biến bỏ sót do anti-evasion.
  - Biến thể *neurevt* (Process Hollowing dùng section mapping) chiếm tỷ trọng lớn nhất trong family đa kỹ thuật.
  - 2 % mẫu thực hiện chain đệ quy A → B → C (multi-stage injection).

### 2.5. Đóng góp khoa học của paper

| # | Đóng góp | Loại |
|---|----------|------|
| C1 | Framework 2/3 primitive + memory congruence + equivalence class | Methodology |
| C2 | Định lượng prevalence ở quy mô 56k mẫu | Empirical |
| C3 | So sánh với sandbox công cộng (21,2 % miss) | Comparative |
| C4 | Tích hợp anti-evasion → ablation cho thấy evasion che injection | Engineering + Empirical |
| C5 | Phát hiện biến thể dominant theo thời gian (section mapping) | Forensic |
| C6 | Artifact công khai (code + dataset + log) | Reproducibility |

### 2.6. Hạn chế tự nhận của paper

Paper tự công bố các giới hạn:

- **User-space only.** Kernel-mode injection (kernel APC, driver-based) không nằm trong scope. Paper coi đây là vấn đề riêng vì user-mode telemetry không thể quan sát.
- **Instrumentation có thể bị evade.** Direct syscall stub có thể bỏ qua user-mode hook. Paper khẳng định Cuckoo/Bluepill stack chống được phần lớn nhưng không phải tất cả.
- **Một số kỹ thuật mới hơn dataset:** Process Ghosting (2021), Mockingjay (2023), PoolParty (2023) — dataset paper kết thúc 2023 nên đại diện chưa đầy đủ.
- **Phụ thuộc API trace chất lượng cao.** Nếu tracer drop event, primitive count sai → 2/3 rule sai theo.

---

## 3. Phân tích repo Noirlycan

### 3.1. Mục tiêu và phạm vi

Noirlycan (repo cá nhân của tác giả luận văn) là **prototype telemetry phòng lab** cho Windows 10/11. Mục tiêu thiết kế:

> Phát hiện và phân loại process injection trong môi trường thí nghiệm khép kín, đồng thời gắn kết quả phát hiện với **nguồn gốc file** (file vừa được tạo trên đĩa và chuỗi tiến trình thực thi nó).

Phạm vi *cố tình hẹp hơn* paper:

- Không có dataset 56k mẫu. Thí nghiệm là PoC loader tự xây + một subset nhỏ từ artifact paper.
- Không phải sản phẩm production EDR. Là công cụ đo lường khoa học cho luận văn.

### 3.2. Kiến trúc

```
                ┌─── Sysmon driver (kernel-mode) ────┐
                │  • Event 1  ProcessCreate          │
                │  • Event 7  ImageLoad              │
                │  • Event 8  CreateRemoteThread     │
                │  • Event 10 ProcessAccess          │
                │  • Event 11 FileCreate             │
                │  • Event 3  NetworkConnect         │
                └────────────┬───────────────────────┘
                             │ (Windows Event Log)
                             ▼
   ┌─── Frida agent (user-mode, trong target) ───┐
   │  Hook 121 API: ntdll, kernel32, user32       │   ───► JSONL session log
   │  Emit primitive {kind, addr, size, target}   │              │
   └──────────────┬───────────────────────────────┘              │
                  │                                              ▼
                  ▼                                       Flask dashboard
       ┌── Correlator (Python) ──┐                       (overview / findings
       │ • 2/3 rule              │                        / primitives / network)
       │ • memory congruence     │
       │ • temporal ordering     │
       │ • file provenance link  │
       │ • technique classifier  │
       └─────────────────────────┘
```

Hai lớp telemetry trên hai privilege level khác nhau — đây là điểm thiết kế quan trọng, được thảo luận chi tiết ở §4.4.

### 3.3. Mapping với phương pháp paper

| Thành tố paper | Module trong repo | Vị trí |
|----------------|-------------------|--------|
| 3 operational primitive | `PrimitiveKind.ALLOCATE/WRITE/EXECUTE` | `models.py` |
| API equivalence class | `PAPER_API_CLASSES` (+ `IRED_TEAM_API_CLASSES` mở rộng) | `injection_api_manifest.py` |
| Quy tắc 2/3 | `operational_kind_count(kinds) >= 2` | `correlation.py`, `execution_analysis.py` |
| Memory range congruence | `_has_memory_congruence()` + `_ranges_overlap_or_contain()` | `correlation.py` |
| Temporal ordering | `_has_temporal_consistency()` | `correlation.py` |
| Phân loại kỹ thuật | `InjectionTechnique` (36 enum) + rule cascade | `technique_classifier.py` |

Lựa chọn instrumentation khác paper:

- **Paper:** custom tracer trong sandbox QEMU.
- **Repo:** Frida (user-mode) + Sysmon (kernel-mode).

Lý do: paper cần tracer của họ cho quy mô 56k mẫu trên QEMU; repo phục vụ thí nghiệm cá nhân trên VM thật, Frida + Sysmon là combination phổ biến và open-source.

### 3.4. Đóng góp riêng của repo so với paper

Sau quá trình audit (xem [audit-and-threat-model.md](audit-and-threat-model.md)) repo thể hiện ba đóng góp không trùng paper:

#### 3.4.1. File provenance pipeline

Paper bắt đầu từ thời điểm process đã chạy. Repo bắt đầu từ thời điểm **file xuất hiện trên đĩa**:

```
Sysmon Event 11 (FileCreate)
   → Static triage (SHA256, PE, entropy, Authenticode)
   → Liên kết với Sysmon Event 1 (ProcessCreate) qua image path
   → Khi process này gọi injection primitive, finding mang theo
     trường `related_file` + score bonus
```

Paper không xây pipeline end-to-end "file mới → triage → process → injection". Đây là extension thực dụng cho phân tích forensic trên endpoint.

#### 3.4.2. Mở rộng taxonomy ngoài paper

Paper tập trung vào tập kỹ thuật phổ biến trong dataset 2017–2023. Repo mở rộng taxonomy lên **36 kỹ thuật** (17 FULL coverage), bao gồm các kỹ thuật mới hơn hoặc đặc biệt mà paper chỉ đề cập sơ:

| Kỹ thuật | Tín hiệu phát hiện |
|----------|-------------------|
| Process Ghosting | `NtSetInformationFile` (delete-pending) + section + spawn |
| Process Herpaderping | Section captured + WriteFile overwrite + spawn |
| PROPagate | `SetPropA/W` + `SendNotifyMessageA/W` |
| Manual PE Mapping | ≥3 remote writes + `VirtualProtectEx` + thread, không `LoadLibrary` |
| IAT Hooking | Remote `VirtualProtectEx` + write ≤16 bytes, không allocate |
| Threadless Inject | Remote protect+write không có thread API |
| EnumXxx Callback Injection | `EnumSystemLocalesA/W`, `EnumWindows`, `EnumChildWindows`, ... |
| InstrumentationCallback | `NtSetInformationProcess` class 40, extract callback addr |
| GhostWriting | `OpenThread` + `SetThreadContext`, không cần remote write (sau D1 fix) |
| PoolParty | `TpAllocWork`, `TpPostWork`, `NtSetInformationWorkerFactory` |

#### 3.4.3. Defense in depth qua hai privilege level

Đây là điểm phản biện quan trọng. Paper dùng một lớp tracer duy nhất (custom). Repo dùng hai lớp khác privilege:

- **Frida (user-mode):** cho granularity API + argument.
- **Sysmon (kernel-mode, driver `SysmonDrv.sys`):** cho resilience trước user-mode unhooking và direct syscall.

Khi đối thủ direct-syscall bỏ qua Frida, Sysmon Event 8 (CreateRemoteThread) và Event 10 (ProcessAccess) vẫn fire vì chúng đến từ kernel callback (`PsSetCreateProcessNotifyRoutineEx`, `ObRegisterCallbacks`). Detection **graceful degradation** chứ không mù hoàn toàn.

Xem §4.4 để thấy hệ quả khoa học của điểm này.

### 3.5. Audit mức độ trung thành với paper

Audit chi tiết tại [docs/audit-and-threat-model.md](audit-and-threat-model.md). Tóm tắt:

| Mục paper | Repo | Trạng thái |
|-----------|------|-----------|
| 3 primitive | ✅ Đầy đủ | Có thêm `CONTEXT_READ` (informational, không tính 2/3) |
| API equivalence class | ✅ Đầy đủ | Có ghi nguồn paper trong manifest |
| Quy tắc 2/3 | ✅ Đầy đủ | Test `test_requires_two_distinct_primitives` |
| Memory congruence | ✅ Đầy đủ sau khi fix D1 (SetThreadContext extract Rip) |
| Temporal ordering | ✅ Đầy đủ sau khi fix D3 |
| Read vs Write primitive | ✅ Sau khi fix D2 (read APIs tách khỏi write class) |
| Recursive chain | ⚠️ Có graph, chưa có metric prevalence |
| Anti-evasion | ❌ Out of scope — khai báo formal |
| Direct syscall coverage | ⚠️ Graceful degradation qua Sysmon, chưa có ETW TI |
| Dataset 56k mẫu | ❌ Out of scope — luận văn là PoC + subset |

Ba deviation P0 ban đầu (D1/D2/D3) đã được fix và verify bằng test. Audit là tài liệu formal cho hội đồng, không phải tài liệu marketing.

---

## 4. Định vị luận văn

### 4.1. Câu chuyện luận văn ngắn gọn

> Một bài báo ASIA CCS 2025 đề xuất phương pháp phát hiện process injection dựa trên 2/3 primitive. Luận văn này (a) hiện thực hóa phương pháp đó trên Frida + Sysmon trong môi trường lab Windows, (b) audit độ trung thành với paper và sửa ba lệch lạc được phát hiện, (c) mở rộng taxonomy thêm 17 kỹ thuật chưa có trong paper, (d) bổ sung file-provenance pipeline mà paper không xây, (e) phân tích hệ quả của kiến trúc Sysmon ∪ Frida ở hai privilege level.

### 4.2. Định khung claim — quan trọng cho hội đồng

Luận văn **không được claim** những điều sau:

- ❌ "Phương pháp mới hơn paper" — sai. Phương pháp lõi là của paper.
- ❌ "Precision/recall ngang/hơn paper" — sai. Repo chưa đo trên dataset 56k.
- ❌ "Phát hiện được X% mẫu thực" — sai. Chưa có ground truth.
- ❌ "Production-ready EDR" — sai. Là prototype lab.

Luận văn **được phép claim** những điều sau:

- ✅ **Replication có kiểm chứng** lõi 2/3 primitive + memory congruence + temporal ordering của Di Pietro et al. trên Frida + Sysmon.
- ✅ **Phát hiện ba lệch lạc** (D1/D2/D3) trong implementation ban đầu, fix có test.
- ✅ **Mở rộng coverage** từ ~12 kỹ thuật của paper lên **36 kỹ thuật**, trong đó 17 đạt FULL coverage (hook + classifier + test).
- ✅ **Đóng góp kiến trúc**: file-provenance pipeline + telemetry layer trust matrix.
- ✅ **Bộ benchmark** (PoC loader 5 kỹ thuật) cho phép tái lập thí nghiệm.

### 4.3. Lựa chọn phương pháp luận

Luận văn nên định khung là *Replication + Extension Study*, không phải *Novel Detection Paper*. Định khung này:

1. **Phù hợp với scope master.** Master thesis hiếm khi đề xuất phương pháp mới có ý nghĩa lớn; thông thường là replication, ablation, hoặc extension.
2. **Defensible.** Mọi claim đều có evidence trong code/test/audit. Hội đồng không bắt bẻ được những điều đã được tài liệu hóa cẩn thận.
3. **Có novelty thực sự.** File-provenance pipeline và telemetry layer trust matrix là đóng góp riêng của luận văn, không trùng paper.

### 4.4. Điểm phản biện được dự kiến + phản hồi

| Câu hỏi tiềm năng từ hội đồng | Phản hồi đã chuẩn bị |
|------------------------------|----------------------|
| "Frida bị bypass bởi direct syscall, vậy phương pháp này có ý nghĩa gì?" | Trả lời graceful degradation: khi Frida miss, Sysmon kernel callback vẫn báo có cross-process event (Event 8, 10). Mất API-arg granularity nhưng không mất hoàn toàn signal. Xem audit §3.8 *Telemetry Layer Trust Matrix*. |
| "Bạn chưa đánh giá trên dataset thực, vậy số liệu của bạn có giá trị gì?" | Khai báo phạm vi rõ: đây là *replication + extension study*, không phải *prevalence study*. Có PoC benchmark 5 loader để chứng minh phương pháp chạy được trên các kỹ thuật khác nhau. |
| "Sao bạn lại tự sửa code paper artifact?" | Không sửa code paper. Repo Noirlycan là implementation độc lập. Ba fix D1/D2/D3 là sửa lệch lạc *trong implementation Noirlycan ban đầu*, không phải sửa paper. |
| "Anti-evasion là phần chính của paper, sao bạn bỏ?" | Khai báo formal là out-of-scope (O7 trong threat model). Hệ quả: prevalence repo đo sẽ thấp hơn paper. Đề xuất trong *Future Work*. |
| "Vì sao chọn Frida thay vì ETW?" | Frida open-source, dễ triển khai, cho phép sửa hook trong thí nghiệm. ETW Threat Intelligence là hướng mở rộng tương lai để chống direct syscall. |
| "Bạn có gì hơn Cuckoo Sandbox?" | Cuckoo không có file-provenance pipeline; Cuckoo dùng custom guest agent có thể bị detect dễ hơn Sysmon driver Microsoft-signed. Noirlycan tập trung phòng lab cá nhân, không cạnh tranh quy mô với Cuckoo. |

### 4.5. Cấu trúc đề xuất cho luận văn

| Chương | Trang | Nguồn tài liệu sẵn có |
|--------|-------|-----------------------|
| 1. Mở đầu | 5–7 | README, audit §1 |
| 2. Background (Windows mem model, injection taxonomy) | 8–10 | iRed-coverage doc |
| 3. Related Work (Klein 2017, Barabosch 2017, Starink 2023, Di Pietro 2025) | 6–8 | Cần viết, có outline |
| 4. **Methodology & Faithful Replication** | 8–10 | Bài này §2 + audit §2 |
| 5. **Threat Model & Assumptions** | 4–6 | Audit §3 |
| 6. **Implementation: Noirlycan Architecture** | 10–12 | Bài này §3 + code references |
| 7. Evaluation (PoC benchmark + Frida fidelity) | 8–10 | `docs/experiments/frida-fidelity.md` + PoC loader (cần xây) |
| 8. Discussion (limitations, telemetry trust) | 4–5 | Audit §3.8 |
| 9. Conclusion + Future Work | 2–3 | — |
| Appendix A — API equivalence classes | 4 | Sinh từ manifest |
| Appendix B — Sysmon config | 2 | `configs/` |
| Appendix C — Reproducibility | 4 | Frida fidelity protocol + PoC source |

Tổng ~70–80 trang — đúng chuẩn master thesis.

---

## 5. Kết luận của bài phân tích

### 5.1. Paper

Paper ASIA CCS 2025 đặt ra một framework đơn giản nhưng mạnh để hiểu process injection: ba operational primitive, quy tắc 2/3, memory congruence, equivalence class. Đóng góp khoa học bao gồm cả phương pháp (C1) và bằng chứng thực nghiệm quy mô lớn (C2–C5). Hạn chế chính: user-space only, không chống direct syscall, dataset đến 2023 nên thiếu kỹ thuật mới hơn.

### 5.2. Repo

Noirlycan là implementation độc lập của framework paper, áp dụng vào lab Windows 10/11 thông qua Frida (user-mode) ∪ Sysmon (kernel-mode). Sau audit và fix ba deviation, repo bám sát phương pháp paper ở các điểm cốt lõi. Đóng góp riêng tập trung ở (a) file-provenance pipeline end-to-end, (b) mở rộng taxonomy lên 36 kỹ thuật với 17 FULL coverage, (c) phân tích kiến trúc telemetry hai privilege level.

### 5.3. Luận văn

Luận văn nên định khung *Replication + Extension Study*. Claim được phép gồm: replication có kiểm chứng, audit ba deviation đã fix, mở rộng taxonomy +17 kỹ thuật, đóng góp kiến trúc (file provenance + telemetry trust matrix). Claim không được phép: phương pháp mới, precision/recall ngang paper, production-ready. Định khung này phù hợp scope master, defensible trước hội đồng, và có novelty thực sự ở chỗ extension chứ không phải ở chỗ phương pháp.

### 5.4. Việc tiếp theo

Theo lộ trình 12 tuần trong [thesis-outline.md](thesis-outline.md):

1. **Tuần 1–2:** đối chiếu outline với GVHD, viết Chương 2 + 3.
2. **Tuần 3–4:** chuyển audit-and-threat-model thành Chương 4 + 5.
3. **Tuần 5–6:** xây PoC benchmark 5 loader (section-mapping, shellcode, APC, reflective DLL, hollowing).
4. **Tuần 7–8:** chạy artifact paper trên subset, đối chiếu output.
5. **Tuần 9:** Frida fidelity benchmark (assumption M5).
6. **Tuần 10–11:** Chương 6, 7, 8, 9.
7. **Tuần 12:** format LaTeX, đóng gói reproducibility artifact.

---

## Tham khảo

1. Di Pietro, G., D'Elia, D. C., & Querzoni, L. (2025). *Can You Run My Code? A Close Look at Process Injection in Windows Malware.* ASIA CCS '25. https://doi.org/10.1145/3708821.3736206
2. Klein, S., et al. (2017). Process injection categorization.
3. Barabosch, T., & Gerhards-Padilla, E. (2017). *Quincy: Detecting host-based code injection attacks in memory dumps.*
4. Starink, T., et al. (2023). *Behavior-graph injection detection.* IEEE TIFS.
5. Korkin, I. (2022). *Anti-evasion techniques in modern Windows sandboxes.*
6. MITRE ATT&CK T1055 — Process Injection family.
7. iRed.team — Code & Process Injection labs.
8. Sap4Sec/process-injection — paper artifact.
9. NoirlycanThesis — repo cá nhân, `docs/audit-and-threat-model.md`, `docs/thesis-outline.md`, `docs/ired-team-injection-coverage.md`.

---

*Bài viết phục vụ luận văn thạc sĩ của Phan Vinh Co. Soạn dựa trên audit code thực tế tại commit hiện tại, không bịa số liệu hoặc claim không có evidence.*
