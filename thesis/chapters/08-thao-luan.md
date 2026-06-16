# CHƯƠNG 7. THẢO LUẬN

Chương này tổng hợp ý nghĩa khoa học và thực tiễn của luận văn *Tăng cường phát hiện mã độc dưới các hình thức né tránh*, đặt kết quả Chương 6 trong bối cảnh công trình căn cứ Di Pietro et al. (ASIA CCS 2025) [4] và khảo sát Chương 2. Trọng tâm thảo luận là **phạm vi tăng cường thực sự đạt được** (E1–E4), **khoảng cách có chủ ý** so với paper (E5, quy mô 56.340 mẫu), và **ranh giới claim** phục vụ hội đồng bảo vệ. Luận văn không trình bày kết quả như phát minh phương pháp detection mới; định vị là *Replication + Extension Study* trên endpoint lab Windows.

---

## 7.1. Tổng hợp ý nghĩa khoa học đối với đề tài

### 7.1.1. Câu hỏi nghiên cứu và câu trả lời

Luận văn đặt câu hỏi trung tâm: *Trong phòng lab Windows, có thể tăng cường phát hiện process injection khi malware chủ động né rule cứng, né hook user-mode và che nguồn gốc hay không?* Kết quả Chương 6 trả lời **có, trong phạm vi E1–E4**, bằng cách kết hợp ba yếu tố:

1. **Phương pháp [4]** — abstraction *operational primitive* (allocate, write, execute) chịu biến thể API (E1) và gộp/ẩn bước (E2) nhờ quy tắc 2-of-3, memory congruence và temporal ordering.
2. **Kiến trúc telemetry kép** — Frida (chi tiết đối số user-mode) ∪ Sysmon (kernel callback) giảm false negative khi hook bị né (E4), với *graceful degradation* đã formal hóa ở Bảng 3.9 (Chương 3).
3. **Pipeline provenance** — liên kết Sysmon Event 11 (FileCreate) → static triage → ProcessCreate lineage → Finding injection, đối trọng né attribution (E3) mà paper [4] không mô hình hóa end-to-end trên endpoint.

Điểm then chốt: luận văn **không phát minh** thuật toán phát hiện mới thay [4]. Đóng góp nằm ở **tăng cường thực nghiện có kiểm chứng** (31 test pass), **mở rộng ngữ cảnh vận hành lab**, và **tài liệu hóa threat model formal** cho từng nhóm né tránh E1–E6.

### 7.1.2. Vị trí so với số liệu quy mô lớn của [4]

Hai con số **16,5 %** (prevalence injection) và **21,2 %** (sandbox miss do né tránh) thuộc **paper [4]**, đo trên corpus 56.340 mẫu với sandbox QEMU và module anti-evasion tích hợp. Luận văn **trích dẫn** hai con số làm động lực chọn đề tài và baseline tham chiếu (Chương Mở đầu, Chương 2 §2.6.4), **không claim** đã tái lập trên cùng điều kiện thí nghiệm.

**Bảng 7.1.** Phân tách vai trò số liệu [4] và kết quả luận văn

| Chỉ số | Nguồn | Vai trò trong luận văn | Claim luận văn |
|--------|-------|------------------------|----------------|
| ~16,5 % prevalence injection | [4], RQ1 | Chứng minh injection đáng nghiên cứu | Trích dẫn; không tái lập |
| 21,2 % sandbox miss | [4], RQ3 | Chứng minh E5 làm giảm recall | Trích dẫn; không so sánh recall Noirlycan |
| 2-of-3 framework | [4], RQ2 | Căn cứ phương pháp | **Replication** có test |
| Anti-evasion ablation | [4], §6 | Giải thích vì sao sandbox miss | **Out-of-scope** hiện thực |

Sự phân tách này là yêu cầu **trung thực khoa học** (Chương 3 §3.11): tránh inflation claim bằng số liệu không thuộc artifact luận văn.

### 7.1.3. Replication versus extension

**Bảng 7.2.** Phân loại đóng góp theo loại nghiên cứu

| Thành phần | Loại | Căn cứ |
|------------|------|--------|
| 2-of-3 + equivalence class + congruence + temporal | Replication [4] | `services/analysis/domain/correlation.py`, 11 test correlation |
| Section-mapping (*neurevt*-class) | Replication validation | `test_detects_section_mapping_write_execute_chain` |
| Audit D1/D2/D3 và fix | Methodology validation | `docs/audit-and-threat-model.md` |
| Sysmon ∪ Frida architecture | Extension (E4) | Bảng 3.9, config `sysmon-noirlycan.xml` |
| File provenance pipeline | Extension (E3) | `file_watch.py`, `test_detects_section_mapping_*` |
| Taxonomy 21+ enum | Extension (beyond paper §4) | `kernel/classification/technique_classifier.py`, 20 test |
| Dashboard + JSONL | Engineering artifact | `services/dashboard/`, reproducibility |
| Anti-evasion E5 | **Không có** | `kernel/analysis/evasion.py` ghi signal only |

---

## 7.2. Thảo luận theo từng nhóm né tránh

### 7.2.1. E1 — Biến thể API

E1 là hình thức né tránh **phổ biến nhất** trong thực tế vì chi phí triển khai thấp: thay `CreateRemoteThread` bằng `NtCreateThreadEx`, hoặc Win32 bằng Native export tương đương, đủ để rule Sigma/EDR viết cho tên hàm cụ thể thất bại.

Kết quả Chương 6 (31 test pass, case classic DLL injection với NT API) cho thấy **equivalence class** [4] giải quyết đúng vấn đề mà signature `VirtualAllocEx → WriteProcessMemory → CreateRemoteThread` không xử lý được. Baseline signature trong test (`test_signature_baseline_misses_nt_api_variant`) minh họa trực tiếp: rule khớp tên Win32 **miss** biến thể NT trong khi correlator 2-of-3 **detect**.

**Hạn chế còn lại:** malware có thể dùng API hiếm chưa có trong manifest `PAPER_API_CLASSES` hoặc `IRED_TEAM_API_CLASSES`. Cập nhật manifest định kỳ theo MITRE ATT&CK [9] và iRed.team là nhu cầu **vận hành**, không phải defect khoa học của phương pháp. Luận văn khai báo M3 (Chương 3): API ngoài class → FN có thể xảy ra.

**Liên hệ [4]:** paper đã chứng minh E1 trên quy mô dataset; luận văn **xác nhận hiện thực** trên Frida hooks, không mở rộng lý thuyết.

### 7.2.2. E2 — Gộp và ẩn bước

Quy tắc **2-of-3** là đóng góp trực tiếp của [4] cho E2: malware gộp allocate và write qua `NtCreateSection` + `NtMapViewOfSection`, hoặc bỏ allocate (Mockingjay — chỉ W+E vào vùng RWX có sẵn), vẫn đủ điều kiện phát hiện nếu còn ≥2 primitive khác loại trên cùng vùng nhớ.

Case study ***neurevt*** (paper §3.5) — biến thể **section-mapping hollowing** dominant trong family đa kỹ thuật của dataset [4] — được Noirlycan phát hiện trong test tổng hợp với score ≥ 70. Đây là bằng chứng mạnh nhất cho **validity construct** của replication: pattern W+E cross-process vào `msedge.exe` khớp mô tả paper, dù **không** chạy lại sample *neurevt* gốc từ corpus 56k.

**Mockingjay và PoolParty** — khai thác vùng RWX hoặc thread pool có sẵn — có rule classifier riêng; 20 test `test_ired_team_classifier.py` pass. Tuy nhiên, luận văn **chưa có đánh giá trên malware thật** cho hai kỹ thuật này; PoC-Bench (Phụ lục D) là hướng bổ sung bắt buộc trước bảo vệ nếu hội đồng hỏi precision thực tế.

**Temporal ordering (D3):** test `test_rejects_write_after_execute_temporal_order` xác nhận fix deviation — WRITE sau EXECUTE bị reject. Điều này củng cố tính nhất quán methodology so với paper §3.4.

### 7.2.3. E3 — Né attribution

E3 là đóng góp **độc lập** so với [4]. Trong điều tra sự cố, analyst thường thấy injection vào `msedge.exe` hoặc `explorer.exe` mà không biết file nào khởi động chuỗi. Paper batch sandbox bắt đầu từ process đã chạy; **file-drop → spawn → inject** — pattern phổ biến trên endpoint thật — không được mô hình hóa provenance end-to-end.

Pipeline Noirlycan:

```
Event 11 (FileCreate) → triage (SHA256, PE, entropy, Authenticode)
    → Event 1 (ProcessCreate, parent/child)
    → Frida primitives → Finding.related_file
```

Test `test_detects_section_mapping_write_execute_chain` và `test_resolves_target_image_from_child_process` xác nhận liên kết **định tính**. Giá trị forensic: giảm thời gian truy ngược từ Finding tới artifact trên đĩa — metric đề xuất trong outline (thời gian FileCreate → Finding) chưa điền số trên VM.

**Giới hạn E3:**

- Payload packed/encrypted (C5) che static triage — hash/entropy không đủ, runtime primitive vẫn cần.
- **Memory-only loader** (không ghi đĩa) không kích hoạt Event 11 — provenance file vô hiệu; phụ thuộc hoàn toàn Frida + Sysmon E1 lineage.
- Parent PID spoofing — Sysmon E1 có thể bị lừa; luận văn không claim chống spoofing đầy đủ.

### 7.2.4. E4 — Né hook user-mode

Ma trận tin cậy telemetry (Chương 3, Bảng 3.9) là điểm thảo luận quan trọng nhất về *tăng cường* so với single-layer Frida hoặc single-layer sandbox tracer của [4].

Khi malware **direct syscall** hoặc **unhook** `ntdll.dll` (O1/O2):

| Lớp | Trạng thái | Hệ quả |
|-----|------------|--------|
| Frida export hook | Miss toàn bộ | Mất address/size → congruence yếu |
| Sysmon Event 8 (CreateRemoteThread) | Vẫn fire (kernel ETW TI) | Fallback EXECUTE coarse |
| Sysmon Event 10 (ProcessAccess) | Vẫn fire | Fallback access pattern |
| Correlator | Degraded mode | Finding có thể đạt ngưỡng thấp hơn; classifier kém chi tiết |

Đây là **graceful degradation** — recall giảm, **không về zero** — và là đóng góp kiến trúc luận văn so với paper (một lớp tracer QEMU). Tuy nhiên, luận văn **thiếu benchmark định lượng E4**: chưa có session so sánh loader direct-syscall thuần với Frida on/off và đo tỷ lệ chain vẫn phát hiện. Hội đồng có thể hỏi *"bao nhiêu % chain vẫn detect khi Frida miss?"* — cần thí nghiệm bổ sung (Chương 6 §6.10, Kiến nghị Kết luận).

**ETW Threat Intelligence** (Chương 1 §1.8.6): Sysmon Event 8 đã tận dụng provider này; hướng phát triển là thu thập thêm syscall args từ kernel thay Frida — giảm phụ thuộc M5.

### 7.2.5. E5 — Né sandbox (hạn chế lớn nhất)

Paper [4] định lượng: **21,2 %** mẫu injection bị sandbox phổ biến bỏ sót khi thiếu anti-evasion — malware phát hiện VM/timing/env rồi **không thực hiện** injection, không phải né rule sau khi đã inject. Module anti-evasion paper (patch timing, fake environment) là thành phần **không thể tách rời** khi trả lời RQ3 [4].

Luận văn **không triển khai** module tương đương. `kernel/analysis/evasion.py` chỉ **ghi signal** (`IsDebuggerPresent`, `NtQueryInformationProcess`, …) — không bypass. Hệ quả:

1. Malware E5 trong lab VM có thể thoát sớm → log trống → zero finding.
2. Recall lab **không so sánh được** với recall paper trên cùng corpus.
3. Tên đề tài rộng (*"các hình thức né tránh"*) **rộng hơn** phạm vi hiện thực (E1–E4).

**Cách trình bày với hội đồng:** đề tài tập trung né tránh **ở tầng triển khai injection và instrumentation** (E1–E4), không phải né tránh **môi trường phân tích** (E5). Số liệu 21,2 % là **động lực** chọn [4] và **upper bound lý thuyết** cho recall nếu có anti-evasion, **không phải** kết quả Noirlycan. Đây là ranh giới đã formal hóa ở O7 (Chương 3) và claim cấm §3.11.2.

### 7.2.6. E6 — Anti-instrumentation

Frida inject **agent** vào process target — surface tấn công lớn hơn custom tracer trong QEMU của [4] (malware không “thấy” Frida trong cùng process space theo cách tương tự). E6 bao gồm: scan `frida-agent`, pipe, port 27042, timing do hook, INT3 breakpoint.

Luận văn mitigates **một phần** qua `spawn` mode (attach trước entrypoint — giảm T2 late attach) và auto-attach victim sau injection đệ quy. **Không** triển khai stealth agent hay anti-anti-Frida (O5 out-of-scope).

Recall trên malware anti-analysis thực tế có thể **thấp hơn đáng kể** so với 31 test synthetic. Giả định M5 (Frida fidelity) và protocol Phụ lục E là điều kiện cần trước khi claim kết luận phụ thuộc Frida granularity.

**Bảng 7.3.** Tóm tắt thảo luận E1–E6

| Nhóm | Mức tăng cường | Evidence chính | Hạn chế còn lại |
|------|----------------|----------------|-----------------|
| E1 | Cao | 31 test; NT API variant | API ngoài manifest |
| E2 | Cao | Section-mapping ≥70; classifier 20 test | Mockingjay/PoolParty chưa malware thật |
| E3 | Trung bình–cao | Provenance test; pipeline E11→E1 | Memory-only; packed file |
| E4 | Trung bình (thiết kế) | Bảng 3.9; Sysmon config | Thiếu benchmark syscall thuần |
| E5 | **Không** | Trích dẫn [4] 21,2 % | Không anti-evasion module |
| E6 | Thấp | spawn; limitation doc | Anti-Frida chủ động (O5) |

---

## 7.3. So sánh với các hướng tiếp cận khác

### 7.3.1. Signature và rule API (Sigma, YARA behavior)

**Ưu điểm:** triển khai nhanh trong SOC, latency thấp, giải thích dễ cho analyst junior.

**Nhược điểm:** thua E1 (đổi tên API) và E2 (gộp bước) — đúng kết luận paper [4] về false negative trên malware đa hình. Test baseline signature trong repo minh họa cụ thể.

**Vị trí Noirlycan:** không thay thế rule production — phục vụ **nghiên cứu, đào tạo, và audit** nơi cần hiểu *tại sao* rule fail và primitive abstraction hoạt động. Có thể export Finding sang Sigma rule thủ công sau analyst review.

### 7.3.2. Behavior graph (Starink et al. [12])

Starink dùng đồ thị hành vi đầy đủ với ràng buộc *same buffer* chặt hơn. Chi phí graph matching cao hơn; khó scale endpoint cá nhân. [4] đơn giản hóa thành stream rule 2-of-3 — lựa chọn luận văn bám [4] vì cân bằng tốt hơn giữa độ tổng quát và chi phí triển khai lab (Chương 2, Bảng 2.2).

### 7.3.3. EDR thương mại

Microsoft Defender, Elastic Defend, CrowdStrike Falcon kết hợp kernel driver, ML, cloud correlation — vượt xa phạm vi luận văn. Rule và model **đóng nguồn** — không audit equivalence class hay ablation E5 công khai.

**Giá trị Noirlycan:** mã nguồn mở, threat model minh bạch, tái lập [4] cho giảng dạy và thesis. Sysmon [10] được chọn vì driver ký Microsoft và schema event công khai — phổ biến trong forensic community Việt Nam và quốc tế.

### 7.3.4. Sandbox động (Cuckoo, Hatching Triage)

Paper [4] so sánh trực tiếp và chứng minh **21,2 % miss** trên injection khi thiếu anti-evasion. Sandbox cloud mạnh về quy mô batch nhưng yếu E5 nếu không có countermeasure tương đương Bluepill/paper.

Noirlycan bổ sung **quan sát endpoint real-time** trong lab cô lập — use case khác: điều tra sự cố có phạm vi hẹp, không cạnh tranh quy mô 56k mẫu. Hai hướng **bổ trợ** nhau: sandbox prevalence study [4] + endpoint lab replication/extension.

**Bảng 7.4.** So sánh tổng hợp hướng tiếp cận

| Tiêu chí | Signature | [4] QEMU batch | Sandbox cloud | EDR | Noirlycan |
|----------|-----------|----------------|---------------|-----|-----------|
| Chống E1 | Yếu | Mạnh | Yếu–TB | Khá–Mạnh | Mạnh (replication) |
| Chống E2 | Yếu | Mạnh | Yếu | Khá | Mạnh (replication) |
| Chống E3 provenance | TB | Yếu | TB | Khá | **Extension** |
| Chống E4 | Yếu | TB (tracer) | TB | Mạnh | TB (Sysmon fallback) |
| Chống E5 | TB | **Mạnh** (anti-evasion) | Yếu→21,2% miss | Khá | **Không** |
| Mở nguồn / audit | Có (Sigma) | Artifact [11] | Một phần | Không | **Có** |
| Real-time endpoint | Có | Không | Không | Có | **Có (lab)** |

---

## 7.4. Độ tin cậy của kết quả thực nghiệm

### 7.4.1. Internal validity

Ground truth trên 31 test do **tác giả luận văn gắn nhãn** — phù hợp kiểm chứng *specification* [4] (correlator implement đúng quy tắc paper), nhưng **yếu** về đại diện malware thật. Rủi ro bias: test có thể unconsciously favor implementation hiện tại.

**Giảm thiểu:** audit độc lập code-vs-paper phát hiện D1/D2/D3; test regression sau fix; hướng Paper-Subset 100 mẫu Sap4Sec [11] và PoC-Bench (Chương 6 §6.10).

### 7.4.2. External validity

Chỉ **Windows 10/11 client x64**, lab VM cô lập. Không Windows Server, ARM, enterprise fleet với EDR đa agent. Kết luận **không khái quát hóa** sang production deployment hay prevalence toàn cầu.

Malware dataset [4] giai đoạn 2017–2023 — kỹ thuật 2024+ (một số biến thể PoolParty phức tạp) có rule classifier nhưng **chưa evaluate** trên corpus.

### 7.4.3. Construct validity

- **M1 (ba primitive):** không cover kernel injection (O3) — construct đúng trong phạm vi user-mode đã khai báo.
- **M4 (memory congruence):** deviation D1 (execute thiếu address) đã fix một phần qua Rip/`lpStartAddress`; edge case `ResumeThread` không context vẫn suy yếu congruence.
- **M5 (Frida fidelity):** protocol `docs/experiments/frida-fidelity.md` có; **số liệu drop-rate chưa điền** — mọi claim phụ thuộc Frida args phải gắn nhãn *conditional on M5*.

Frida overhead thay đổi timing — có thể ảnh hưởng race APC hiếm; không đo đầy đủ trong luận văn hiện tại.

### 7.4.4. Conclusion validity

Luận văn **không** rút ra kết luận vượt evidence:

| Không claim | Có thể claim (Chương 6) |
|-------------|-------------------------|
| Prevalence 16,5 % / miss 21,2 % | 31 test pass; section-mapping ≥70 |
| Precision/recall trên corpus lớn | Vượt baseline signature trên E1/E2 (test) |
| Chống E5 toàn diện | Provenance + telemetry kép (thiết kế + test định tính) |
| Thay EDR/sandbox production | Replication [4] trên Windows lab |

---

## 7.5. Ý nghĩa thực tiễn

### 7.5.1. Phòng lab an ninh mạng giáo dục

Hệ thống Noirlycan phù hợp triển khai tại khoa CNTT — Trường Đại học Công nghệ (UET) và các đơn vị tương tự — với các use case:

- **Giảng dạy** MITRE T1055 [9]: sinh viên chạy loader PoC an toàn (MessageBox), quan sát primitive và so sánh với rule Sigma cứng.
- **Thực hành điều tra số:** correlate file drop với injection trong sự cố lab có phạm vi hẹp.
- **Thesis replication:** sinh viên sau có thể fork artifact, chạy subset Sap4Sec, mở rộng anti-evasion E5.

### 7.5.2. Giới hạn triển khai production

**Không khuyến nghị** deploy như EDR production thiếu: authentication dashboard, scale multi-host, signature update pipeline, hardening chống O4/O5, và SLA. Noirlycan là **research prototype** với JSONL export — analyst review bắt buộc trước hành động.

### 7.5.3. Tích hợp workflow SOC (tương lai)

Finding JSONL có thể ingest vào SIEM (Elasticsearch, Splunk) qua parser tùy chỉnh — ngoài phạm vi luận văn nhưng là hướng mở rộng thực tế cho lab chuyển dần sang vận hành.

---

## 7.6. Đạo đức nghiên cứu

Luận văn tuân thủ nguyên tắc nghiên cứu mã độc có trách nhiệm:

1. **Cô lập:** mẫu chỉ chạy trong VM **không kết nối** mạng sản xuất; snapshot revert sau session.
2. **PoC an toàn:** loader tự xây dùng MessageBox hoặc payload vô hại — không weaponized exploit.
3. **Không phát tán:** không redistribute hash/mẫu malware thật từ dataset [11] trong artifact công khai luận văn.
4. **Trích dẫn:** [4] và Sap4Sec/process-injection [11] đúng license và DOI công bố.
5. **Transparency:** threat model và limitation E5/E6 công khai — không che giấu recall gap so với paper.

---

## 7.7. Giải thích tên đề tài versus phạm vi hiện thực

Tên đề tài *Tăng cường phát hiện mã độc dưới các hình thức né tránh* mang nghĩa rộng — bao gồm cả E5 (sandbox/VM). Phạm vi hiện thực **cố ý thu hẹp** E1–E4 vì:

- Module anti-evasion [4] là engineering effort riêng (QEMU timing patch, env fingerprint) vượt phạm vi thesis thạc sĹ một năm.
- Replication lõi [4] + extension lab đã đủ đóng góp nếu trung thực về E5.

Luận văn coi E5 là **hướng phát triển bắt buộc** (Kết luận §4), không phải thất bại im lặng — paper đã chứng minh 21,2 % gap là real và measurable.

---

## 7.8. Hướng phát triển

**Bảng 7.5.** Lộ trình ưu tiên hướng phát triển

| Ưu tiên | Hướng | Đối phó | Nguồn / ghi chú |
|---------|-------|---------|-----------------|
| **Cao** | Anti-evasion subset | E5 | Artifact [11], paper §6 |
| **Cao** | Benchmark direct-syscall loader | E4 | PoC + session Frida on/off |
| **Cao** | Frida fidelity benchmark (M5) | E6, construct | `docs/experiments/frida-fidelity.md` |
| **Trung** | ETW TI provider trực tiếp | E4 | Thay/bổ sung Frida args |
| **Trung** | PoC-Bench + Paper-Subset 100 | E1, E2 validity | Sap4Sec [11] |
| **Trung** | Fix D1/D3 hoàn chỉnh | Congruence/temporal | Hooks + correlator |
| **Thấp** | ML classifier trên primitive sequence | E1 edge | Thay rule `technique_classifier` |
| **Thấp** | Cross-host correlation | Multi-stage | `injection_graph.py` mở rộng |

**Tương lai gần (6–12 tháng):** hoàn thiện M5 + PoC-Bench → claim conditional mạnh hơn trước publication follow-up.

**Trung hạn:** port subset anti-evasion → mới có thể nói “tăng cường dưới E5” với evidence.

**Dài hạn:** kernel ETW thay Frida hoàn toàn — giảm E6, tăng tin cậy E4.

---

## 7.9. Bài học cho nghiên cứu replication

Luận văn rút ra ba bài học cho các replication study an ninh mạng:

1. **Audit code-vs-paper trước khi claim** — D1/D2/D3 cho thấy implementation “gần đúng” vẫn có thể sai diễn giải khoa học (congruence bypass, read lẫn write).
2. **Tách số liệu paper và số liệu thesis** — prevalence 16,5 %/21,2 % là của [4], không của Noirlycan.
3. **Extension phải map threat model** — provenance và Sysmon fallback có giá trị khi gắn E3/E4 cụ thể, không marketing chung chung.

---

## 7.10. Tóm tắt chương

Chương 7 đã thảo luận ý nghĩa khoa học và thực tiễn của luận văn *Tăng cường phát hiện mã độc dưới các hình thức né tránh*: luận văn **tăng cường có căn cứ** phát hiện dưới **E1–E4** thông qua replication [4], kiến trúc Sysmon ∪ Frida, và pipeline provenance; **chưa** tăng cường dưới **E5** như paper khi có anti-evasion module. Số liệu 16,5 % và 21,2 % [4] là động lực và baseline tham chiếu, không phải kết quả luận văn. So với signature, behavior graph [12], sandbox và EDR, Noirlycan chiếm vị trí **công cụ lab mở, audit được, real-time endpoint**. Hạn chế internal/external/construct validity đã được khai báo; hướng phát triển ưu tiên anti-evasion E5, benchmark E4, và Frida fidelity M5. Luận văn định vị trung thực là **Replication + Extension Study** với Di Pietro et al. [4] là xương sống lý luận — phù hợp yêu cầu trung thực khoa học luận văn thạc sĩ UET.
