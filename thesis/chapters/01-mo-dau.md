# MỞ ĐẦU — ĐẶT VẤN ĐỀ

*(Cấu trúc theo Nguyễn Việt Hà — HTW: bối cảnh → nội dung nghiên cứu → bố cục; khuôn IMRAD [16].)*

## 1.1. Bối cảnh nghiên cứu

Mã độc Windows hiện đại chủ động **né tránh phát hiện** ở tầng hành vi động: thay thế API tương đương để lách rule EDR/AV; gộp các bước trong chuỗi tiêm mã; tiêm vào tiến trình hợp pháp để che attribution; phát hiện sandbox/debugger rồi ngừng hành vi; gọi syscall trực tiếp hoặc gỡ hook (unhooking) để bỏ qua instrumentation user-mode [4], [6], [8]. **Tiêm mã liên tiến trình** (process injection, MITRE ATT&CK T1055 [9]) đóng vai trò then chốt: malware thực thi payload dưới danh nghĩa tiến trình uy tín như `explorer.exe` hoặc binary đã ký số, khiến signature API đơn lẻ dễ bỏ sót [4], [9].

Công trình *Can You Run My Code?* tại ASIA CCS 2025 [4] — **căn cứ khoa học chính** — phân tích **56.340 mẫu** giai đoạn 2017–2023, ước lượng ~**16,5 %** thể hiện injection, và chỉ ra **21,2 %** bị sandbox bỏ sót do *evasion thụ động* (malware từ chối thực thi trong môi trường phân tích) [4], [6].

Paper [4] đề xuất abstraction **operational primitive** gồm ba thao tác: *allocate* (chuẩn bị vùng thực thi), *write* (đặt payload), *execute* (kích hoạt). Mỗi primitive ánh xạ vào **lớp tương đương API**: `VirtualAllocEx`, `NtAllocateVirtualMemory`, `NtCreateSection` thuộc *allocate*; `WriteProcessMemory`, `NtWriteVirtualMemory`, `NtMapViewOfSection` thuộc *write*; `CreateRemoteThread`, `NtCreateThreadEx`, `QueueUserAPC`, `SetThreadContext` thuộc *execute*. Quy tắc **2-of-3** kết hợp **memory range congruence** và **temporal ordering** (allocate → write → execute) cho phép phát hiện injection không phụ thuộc chuỗi API cụ thể, giảm false negative khi malware thay biến thể API [4], [7].

Tuy nhiên, [4] triển khai trên **sandbox QEMU batch**, chưa có pipeline cho **lab Windows endpoint** — nơi malware kết hợp **file-drop loader**, **direct syscall**/unhooking `ntdll`, **anti-instrumentation** nhắm Frida/debugger.

Từ đó, luận văn *Tăng cường phát hiện mã độc trước các kĩ thuật né tránh* nhằm: (1) **hiện thực hóa** phương pháp chống biến thể API [4] trên endpoint lab Windows 10/11 qua **Noirlycan Telemetry**; (2) **bổ sung lớp kernel** (Sysmon) khi Frida bị né; (3) **truy vết nguồn gốc** file → process → injection để đối phó inject vào tiến trình sạch; (4) **đánh giá có kiểm chứng** trên kịch bản biến thể (section-mapping, APC, reflective DLL, PoolParty) với ground truth tự xây.

Đề tài cung cấp công cụ mã nguồn mở, có threat model formal, giúp tái lập [4] không phụ thuộc sandbox đóng hay EDR thương mại. Luận văn cam kết **trung thực khoa học**: nhóm ngoài phạm vi (E5) khai báo rõ.

## 1.2. Nội dung nghiên cứu trong luận văn

### 1.2.1. Phân loại hình thức né tránh trong phạm vi đề tài

Luận văn tổ chức các hình thức né tránh thành **sáu nhóm E1–E6** (Bảng M.1), thống nhất với threat model (Chương 2).

**Bảng M.1.** Hình thức né tránh và cơ chế đối phó của luận văn

| Nhóm | Tên | Mô tả | Cơ chế tăng cường phát hiện | Phạm vi |
|------|-----|-------|----------------------------|---------|
| E1 | Biến thể API | `CreateRemoteThread` → `NtCreateThreadEx`; `VirtualAllocEx` → `NtAllocateVirtualMemory` | Lớp tương đương API + quy tắc 2-of-3 [4] | Trong phạm vi |
| E2 | Gộp/ẩn bước | Section mapping gộp allocate+write; Mockingjay khai thác RWX có sẵn | Quy tắc 2-of-3 (≥2 primitive); classifier section-mapping | Trong phạm vi |
| E3 | Né attribution | Inject vào tiến trình hợp pháp; file-drop loader che nguồn | Sysmon lineage (E1) + file provenance (E11) + static triage | Trong phạm vi (extension) |
| E4 | Né hook user-mode | Direct syscall stub, unhooking `ntdll`, patch ETW/AMSI | Sysmon kernel callback (E8, E10) fallback khi Frida miss | Trong phạm vi (một phần) |
| E5 | Né sandbox/VM | Timing check, env fingerprint, CPUID — malware *không chạy* injection | Paper [4] có anti-evasion; ablation +21,2 % | **Ngoài phạm vi hiện thực** |
| E6 | Né instrumentation | Anti-Frida, anti-debug, phát hiện agent rồi abort | `spawn` mode; khai báo limitation; ưu tiên Sysmon fallback | Hạn chế |

**E5**: rule 2-of-3 chỉ bắt khi malware *thực sự* phát primitive; nếu từ chối thực thi thì rule không có gì để đánh giá. Luận văn **không hiện thực** anti-evasion; Noirlycan chỉ *ghi nhận* tín hiệu (`kernel/analysis/evasion.py`). Hệ quả: prevalence/recall **không** so sánh trực tiếp với 16,5 %/21,2 % của paper.

**E4** trong phạm vi *một phần*: khi direct-syscall, Frida miss đối số API; Sysmon kernel-mode vẫn ghi **CreateRemoteThread** (Event 8) và **ProcessAccess** (Event 10) qua callback `PsSetCreateThreadNotifyRoutine`, `ObRegisterCallbacks`, không phụ thuộc hook `ntdll` [10].

**Bảng M.2.** Mối quan hệ giữa nhóm né tránh và kỹ thuật injection điển hình

| Kỹ thuật injection | E1 | E2 | E3 | E4 | E5 | E6 |
|--------------------|----|----|----|----|----|-----|
| Classic Remote Thread | ✓ | | ✓ | ✓ | | |
| Section-mapping / Hollowing | ✓ | ✓ | ✓ | ✓ | | |
| APC / Early Bird | | ✓ | ✓ | ✓ | | |
| Reflective DLL | ✓ | | ✓ | ✓ | | ✓ |
| Process Ghosting/Herpaderping | ✓ | ✓ | ✓ | ✓ | | |
| PoolParty / Mockingjay | | ✓ | ✓ | ✓ | | |

Hầu hết kỹ thuật injection hiện đại khai thác đồng thời nhiều nhóm né tránh, nên giải pháp đơn lớp khó đạt recall cao.

## 1.3. Mục tiêu nghiên cứu

### 1.3.1. Mục tiêu tổng quát

Tăng cường phát hiện mã độc Windows dùng process injection và né tránh E1–E4 trong lab Windows 10/11, căn cứ operational primitive và 2-of-3 [4], qua hiện thực và mở rộng có kiểm chứng trên Noirlycan.

### 1.3.2. Mục tiêu cụ thể

**RO1 — Hiện thực hóa lõi phương pháp [4].** Xây bộ quy tắc gồm: ba operational primitive; lớp tương đương API theo `PAPER_API_CLASSES` [11]; 2-of-3 trên cùng `(actor_pid, target_pid)`; memory range congruence; temporal ordering. Tiêu chí: unit test khớp case section-mapping (Neurevt) trong [4] §3.5.

**RO2 — Telemetry kép chống E4.** Pipeline **Sysmon ∪ Frida**: Frida cung cấp đối số API cho congruence; Sysmon kernel (Event 1, 7, 8, 10, 11) fallback khi user-mode hook bị bypass.

**RO3 — Pipeline provenance chống E3.** Mở rộng [4]: Sysmon Event 11 (FileCreate) → static triage (SHA256, PE header, entropy, Authenticode) → ProcessCreate lineage → Finding, giúp truy ngược về file nguồn.

**RO4 — Đánh giá trên benchmark biến thể.** Xây loader PoC (section-mapping, shellcode, APC, reflective DLL, hollowing precursor) và chạy trên subset Sap4Sec [11]. Đo precision, recall, F1 cho phát hiện chain; precision phân loại kỹ thuật.

**RO5 — Threat model và ranh giới claim.** Formal hóa đối thủ (C1–C7), out-of-scope (O1–O7), giả định (M1–M6), ma trận E1–E6 ↔ mitigation.

### 1.3.3. Giả thuyết nghiên cứu

Luận văn định vị là **nghiên cứu ứng dụng** — giả thuyết nhắm **kiểm chứng phạm vi mở rộng** và **giới hạn ứng dụng** của [4] [14], [15].

**Bảng M.3.** Giả thuyết nghiên cứu và cách kiểm chứng

| ID | Giả thuyết | Kiểm chứng | Kết quả sơ bộ |
|----|------------|------------|---------------|
| **H1** | 2-of-3 + equivalence class [4] phát hiện chain khi biến thể API (E1) | Unit test correlation | **Chấp nhận** (31 test) |
| **H2** | 2-of-3 phát hiện injection khi gộp bước (E2, section-mapping) | `test_detects_section_mapping_write_execute_chain` | **Chấp nhận** (score ≥ 70) |
| **H3** | Provenance file → process → finding tăng truy vết (E3) | Case study file-drop; `related_file` | **Chấp nhận một phần** |
| **H4** | Sysmon ∪ Frida giảm FN khi Frida bị né (E4) | Thiết kế E8/E10; benchmark syscall | **Chưa đủ số liệu** |
| **H5** | Frida hook trung thực ≥ 99 % call (M5) | `frida-fidelity.md` | **Chưa chạy trên VM** |

**Loại trừ:** anti-evasion E5 — out-of-scope hiện thực; chỉ trích dẫn 21,2 % làm động lực.

## 1.4. Đối tượng và phạm vi nghiên cứu

### 1.4.1. Đối tượng nghiên cứu

- **Mã độc/loader Windows user-mode** dùng process injection kèm né tránh E1–E4.
- **Phương pháp phát hiện** operational primitive, equivalence class, 2-of-3, memory congruence, temporal ordering [4].
- **Hệ thống Noirlycan Telemetry** [13]: collector, Frida hooks, Sysmon poller, correlator, classifier, dashboard.

### 1.4.2. Phạm vi trong luận văn

| Khía cạnh | Trong phạm vi |
|-----------|---------------|
| Hệ điều hành | Windows 10/11 (64-bit), lab VM cô lập |
| Chế độ malware | User-mode; cross-process và self-inject |
| Né tránh | E1, E2, E3 (extension), E4 (fallback Sysmon) |
| Telemetry | Sysmon (config `sysmon-noirlycan.xml`), Frida 16.x, static triage |
| Kỹ thuật injection | 21+ kỹ thuật (paper [4] + iRed.team + PoolParty/Mockingjay) |
| Đánh giá | PoC-Bench tự xây; subset Paper-Subset; Benign-Baseline; protocol Frida fidelity |

### 1.4.3. Phạm vi ngoài luận văn

| Khía cạnh | Ngoài phạm vi | Lý do |
|-----------|---------------|-------|
| E5 — Anti-sandbox/VM | Không hiện thực bypass | Paper [4] có module riêng; vượt phạm vi |
| E6 — Anti-Frida chủ động | Chỉ limitation + spawn | Không ship countermeasure |
| Injection kernel-mode | Không | Sysmon/Frida user-mode không đủ |
| Prevalence 56.340 mẫu | Không tái lập quy mô | Tập trung replication + extension lab |
| EDR thương mại | Không so sánh trực tiếp | Đóng source |
| Windows Server / ARM | Không | Chưa validate ngoài desktop lab |

Luận văn **không** tuyên bố Noirlycan thay thế sandbox [4] hay EDR production.

### 1.4.4. Đối tượng độc giả và động cơ

**Độc giả** [15]: hội đồng luận văn thạc sĩ CNTT/ATTT; nhà nghiên cứu và sinh viên lab malware; kỹ sư SOC/DFIR. Giả định đã biết Windows cơ bản, MITRE ATT&CK, process/thread.

**Động cơ:** khoảng cách giữa nghiên cứu injection quy mô lớn [4] và nhu cầu phòng lab cần công cụ mã nguồn mở, tái lập được trên Windows.

**Tính khả thi** [14]: artifact Sap4Sec [11], Noirlycan, VM Windows sẵn có; Sysmon/Frida miễn phí. Rủi ro Frida bị anti-instrumentation được kiểm soát qua fidelity protocol (RO5) và fallback Sysmon (RO2).

## 1.5. Phương pháp nghiên cứu

Luận văn kết hợp năm phương pháp:

**1. Nghiên cứu tài liệu.** Di Pietro et al. [4]; Klein et al. [7]; Starink et al. [12]; né tránh sandbox [6], anti-analysis [8]; MITRE T1055 [9]; Sysmon [10], Frida [5]; Sap4Sec [11].

**2. Phân tích threat model.** Chuyển `docs/audit-and-threat-model.md` thành threat model **Chương 2**: A1–A3, C1–C7, O1–O7, M1–M6, ma trận T1–T9.

**3. Thiết kế và hiện thực.** Áp dụng [4] vào Noirlycan (**Chương 3**): `kernel/classification/api_manifest.py`, `windows_injection_hooks.js`, `services/analysis/domain/correlation.py` (2-of-3 engine), `technique_classifier.py`, `file_watch.py` + static triage. Audit doc ghi deviation (D1–D8).

**4. Thực nghiệm và đánh giá** (**Chương 4**): unit test correlation (31+ case); PoC-Bench loader tự viết; subset 100 mẫu artifact paper; Benign-Baseline 50 chương trình hợp pháp; Frida fidelity protocol. Metrics: precision, recall, F1; drop-rate Frida.

**5. Thảo luận.** Hạn chế construct validity (Frida overhead), external validity (chỉ Windows 10/11 lab), deviation so với paper.

**Bảng M.4.** Ánh xạ phương pháp nghiên cứu với câu hỏi đánh giá (Chương 4)

| Phương pháp | Câu hỏi / Giả thuyết phục vụ |
|-------------|------------------------------|
| Audit code-vs-paper | RQ1 / H1, H2 |
| PoC-Bench + Paper-Subset | RQ2 |
| Provenance pipeline | RQ3 / H3 |
| Frida fidelity | RQ5 / H5 |
| Telemetry kép | RQ2 / H4 |

## 1.6. Những đóng góp của luận văn

**Đóng góp 1 — Chống biến thể API (E1) và gộp bước (E2).** Hiện thực có kiểm chứng lõi 2-of-3 + equivalence class [4] trên Frida/Sysmon, 31+ unit test bao phủ APC, section-mapping, PoolParty/Ghosting precursor, reflective DLL, thread hijack. Deviation (D1–D3) được audit; fix temporal ordering, `lpStartAddress` cải thiện fidelity.

**Đóng góp 2 — Chống né hook user-mode (E4).** Telemetry kép: Sysmon kernel callback bắt CreateRemoteThread/ProcessAccess khi Frida miss do direct syscall/unhooking. Ma trận tin cậy formal hóa ranh giới bypass.

**Đóng góp 3 — Chống né attribution (E3).** Pipeline `file → static triage → process lineage → Finding` — extension không có trong artifact batch [4]. Dashboard Flask hỗ trợ điều tra tương tác.

**Đóng góp 4 — Công cụ lab mã nguồn mở.** CLI collector, JSONL session log, reclassify, corpus analytics, config Sysmon tái lập, Dockerfile analyzer offline [13].

**Đóng góp 5 — Threat model và ranh giới claim.** Ma trận E1–E6 ↔ mitigation; **không** claim E5, prevalence 56k mẫu, hay thay thế EDR.

**Bảng M.5.** So sánh đóng góp luận văn với paper [4]

| Khía cạnh | Paper [4] | Luận văn (Noirlycan) |
|-----------|-----------|----------------------|
| Quy mô dataset | 56.340 mẫu, 2017–2023 | PoC-Bench + subset ~100 mẫu |
| Môi trường | QEMU sandbox batch | Windows 10/11 lab VM |
| Anti-evasion E5 | Có module tích hợp | **Out-of-scope** |
| File provenance | Không | Extension E3 |
| Telemetry | Trace nội bộ sandbox | Frida + Sysmon + dashboard |
| Phân loại kỹ thuật | 12 kỹ thuật chính | 21+ enum + rule catalog |
| Công khai | Sap4Sec/process-injection | NoirlycanThesis repo [13] |

Luận văn **bổ sung** chứ không cạnh tranh: paper mạnh về quy mô và anti-evasion, luận văn mạnh về provenance, telemetry kép và taxonomy mở rộng.

## 1.7. Bố cục luận văn

Luận văn tuân **IMRAD** và hướng dẫn HTW [16]; đáp ứng bố cục UET [2]. Với định hướng **ứng dụng công nghệ**, chương Phương pháp gộp threat model và pipeline detection; có chương riêng **Thiết kế và hiện thực**.

- **Mở đầu** — bối cảnh, E1–E6, RO1–RO5, H1–H5, phạm vi, đóng góp.
- **Chương 1 — Cơ sở lý thuyết** — Windows, injection, primitive, Sysmon, Frida.
- **Chương 2 — Phương pháp** — bài toán, threat model, pipeline 2-of-3 [4], provenance, telemetry kép.
- **Chương 3 — Thiết kế và hiện thực** — Clean Architecture, module Noirlycan, Frida hooks, correlator, dashboard.
- **Chương 4 — Thực nghiệm và so sánh** — môi trường, dữ liệu, kết quả (31 test), case section-mapping, so sánh [4], thảo luận.
- **Kết luận** — xuất xứ, phương pháp, kết quả, hạn chế, hướng tiếp theo [16].

Luận văn dùng trích dẫn `[n]` theo UET [2]. Bảng **M.x** trong Mở đầu; **Chương.x** trong các chương. [4] là nguồn trích dẫn nhiều nhất.
