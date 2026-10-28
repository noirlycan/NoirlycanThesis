# CHƯƠNG 7. THẢO LUẬN

Chương này tổng hợp ý nghĩa khoa học và thực tiễn, đặt kết quả Chương 6 trong bối cảnh Di Pietro et al. (ASIA CCS 2025) [7]. Trọng tâm là **phạm vi tăng cường đạt được** (E1–E4), **khoảng cách có chủ ý** so với paper (E5), và **ranh giới claim**. Luận văn định vị là *Replication + Extension Study*.

---

## 7.1. Tổng hợp ý nghĩa khoa học đối với đề tài

### 7.1.1. Câu hỏi nghiên cứu và câu trả lời

Câu hỏi trung tâm: *Có thể tăng cường phát hiện process injection khi malware né rule cứng, né hook user-mode và che nguồn gốc?* Chương 6 (59 test methodology (quy tắc paper 15, correlator 12, execution 5, sensor kernel 7, classifier 20) trong tổng 129 test) trả lời **có, trong phạm vi E1–E4**, qua ba yếu tố:

1. **Phương pháp [7]** — abstraction *operational primitive* (allocate, write, execute) chịu E1 và E2 nhờ 2-of-3, memory congruence và temporal ordering. Correlator gom API cùng *semantic outcome* vào equivalence class.
2. **Telemetry kép** — Frida ∪ Sysmon giảm FN khi hook bị né (E4), *graceful degradation* ở Bảng 3.9.
3. **Pipeline provenance** — Event 11 → triage → ProcessCreate → Finding, đối trọng E3 mà [7] không mô hình hóa end-to-end.

Đóng góp ở **tăng cường thực nghiệm có kiểm chứng** và **threat model formal** cho E1–E6.

### 7.1.2. Vị trí so với số liệu quy mô lớn của [7]

**16,5 %** (prevalence) và **21,2 %** (tỷ lệ công cụ công khai bỏ sót) thuộc **[7]**, đo trên 56.340 mẫu bằng BluePill/Pin có anti-evasion. Luận văn **trích dẫn** làm động lực, **không claim** đã tái lập — dataset không công khai toàn bộ, và hạ tầng DBI + anti-evasion của paper vượt phạm vi thesis thạc sĩ.

**Bảng 7.1.** Phân tách vai trò số liệu [7] và kết quả luận văn

| Chỉ số | Nguồn | Vai trò | Claim |
|--------|-------|--------|-------|
| ~16,5% prevalence | [7], RQ1 | Động lực | Trích dẫn |
| 21,2% công cụ công khai bỏ sót | [7], RQ3 | Phương pháp primitive bổ sung cho sandbox | Trích dẫn |
| 2-of-3 framework | [7], RQ2 | Căn cứ phương pháp | **Replication** có test |
| Anti-evasion ablation | [7], §6 | Giải thích sandbox miss | **Out-of-scope** |

Phân tách này là yêu cầu **trung thực khoa học** (§3.11).

### 7.1.3. Replication versus extension

**Bảng 7.2.** Phân loại đóng góp theo loại nghiên cứu

| Thành phần | Loại | Căn cứ |
|------------|------|--------|
| 2-of-3 + equivalence class + congruence + temporal | Replication [7] | `detection/rules.py`, `detection/correlator.py`, `test_paper_rules.py` + `test_correlation.py` |
| Section-mapping (*neurevt*-class) | Replication validation | `test_detects_section_mapping_*` |
| Audit D1/D2/D3 và fix | Methodology validation | `docs/audit-and-threat-model.md` |
| Sysmon ∪ Frida | Extension (E4) | Bảng 3.9 |
| File provenance pipeline | Extension (E3) | `file_watch.py` |
| Taxonomy 36 enum | Extension | `technique_classifier.py`, 20 test |
| Console + JSONL | Engineering artifact | `noirlycan_backend/`, `dashboard-ui/` |
| Anti-evasion E5 | **Không có** | `evasion.py` ghi signal only |

---

## 7.2. Thảo luận theo từng nhóm né tránh

### 7.2.1. E1 — Biến thể API

E1 phổ biến nhất vì chi phí thấp: thay `CreateRemoteThread` bằng `NtCreateThreadEx` đủ để rule khớp tên hàm thất bại. Test `test_signature_baseline_misses_nt_api_variant`: rule Win32 **miss** biến thể NT trong khi correlator 2-of-3 **detect**. Manifest `PAPER_API_CLASSES` và `IRED_TEAM_API_CLASSES` ánh xạ cả hai họ vào cùng class ALLOCATE/WRITE/EXECUTE.

**Hạn chế:** API hiếm chưa có trong manifest (ví dụ `NtAllocateVirtualMemoryEx`) → FN có thể xảy ra (M3). Cập nhật manifest theo MITRE ATT&CK [12] là nhu cầu vận hành.

### 7.2.2. E2 — Gộp và ẩn bước

Quy tắc **2-of-3** xử lý E2: malware gộp allocate+write qua `NtCreateSection` + `NtMapViewOfSection`, hoặc bỏ allocate (Mockingjay — W+E vào RWX có sẵn), vẫn đủ nếu còn ≥2 primitive khác loại trên cùng vùng nhớ.

Case ***neurevt*** (paper §3.5) — **section-mapping hollowing** — được phát hiện với score ≥ 70. Pattern W+E cross-process vào `msedge.exe` khớp mô tả paper, dù **không** chạy lại sample gốc. Chuỗi: `NtCreateSection`, `NtMapViewOfSection`, EXECUTE (`NtQueueApcThread` hoặc `SetThreadContext`+`ResumeThread`).

**Mockingjay và PoolParty** có rule classifier; 20 test pass nhưng **chưa đánh giá trên malware thật**; PoC-Bench bắt buộc trước bảo vệ. **Temporal (D3):** `test_rejects_write_after_execute_temporal_order` — WRITE sau EXECUTE bị reject (tránh FP với JIT).

### 7.2.3. E3 — Né attribution

E3 là đóng góp **độc lập** so với [7]. Paper bắt đầu từ process đã chạy; **file-drop → spawn → inject** không được mô hình hóa end-to-end. Emotet, IcedID, Cobalt Strike thường drop file vào `%APPDATA%`/`%TEMP%`, spawn child, rồi inject từ child.

Pipeline Noirlycan:

```
Event 11 (FileCreate) → triage (SHA256, PE, entropy, Authenticode)
    → Event 1 (ProcessCreate, parent/child)
    → Frida primitives → Finding.related_file
```

Test `test_detects_section_mapping_write_execute_chain` và `test_resolves_target_image_from_child_process` xác nhận liên kết **định tính**; metric FileCreate→Finding chưa điền số.

**Giới hạn E3:** payload packed (C5) che static triage; **memory-only loader** không kích hoạt Event 11 — phụ thuộc Frida + Sysmon E1 lineage (reflective loading, Module Stomping); parent PID spoofing qua `UpdateProcThreadAttribute` không được chống đầy đủ.

### 7.2.4. E4 — Né hook user-mode

Bảng 3.9 là điểm tăng cường so với single-layer tracer [7]. Hell's Gate / Halo's Gate / Tartarus Gate tự đọc syscall number, tự assemble `syscall` — hook user-mode bị bypass.

Khi malware **direct syscall** hoặc **unhook** `ntdll.dll` (O1/O2):

| Lớp | Trạng thái | Hệ quả |
|-----|------------|--------|
| Frida export hook | Miss toàn bộ | Mất address/size → congruence yếu |
| Sysmon Event 8 (CreateRemoteThread) | Vẫn fire (kernel ETW TI) | Fallback EXECUTE coarse |
| Sysmon Event 10 (ProcessAccess) | Vẫn fire | Fallback access pattern |
| Correlator | Degraded mode | Finding ngưỡng thấp; classifier kém chi tiết |

**Graceful degradation** — recall giảm, **không về zero**. Sysmon callback ở kernel — mọi syscall đều phải đi qua. Tuy nhiên **thiếu benchmark định lượng**: chưa có session so sánh loader direct-syscall với Frida on/off. ETW TI là hướng thu syscall args từ kernel thay Frida.

### 7.2.5. E5 — Né sandbox (hạn chế lớn nhất)

Paper [7] định lượng ảnh hưởng của E5 bằng ablation: không có anti-evasion (Detours), chỉ **6,2 %** mẫu năm 2019 lộ injection, so với **11,8 %** với BluePill — malware phát hiện môi trường phân tích rồi **không thực hiện** injection.

Luận văn **không triển khai** module tương đương; `extensions/evasion.py` chỉ **ghi signal**. Hệ quả: malware E5 có thể thoát sớm → zero finding; recall lab **không so sánh được** với paper; tên đề tài **rộng hơn** phạm vi (E1–E4).

Đề tài tập trung né tránh **ở tầng triển khai injection và instrumentation** (E1–E4), không phải **môi trường phân tích** (E5). Kết quả ablation của [7] là căn cứ cho giới hạn này, formal hóa ở O7 và §3.11.2.

### 7.2.6. E6 — Anti-instrumentation

Frida inject **agent** vào process target — tương tự DBI của [7], nhưng [7] có anti-evasion của BluePill còn Frida thì không. E6 gồm: scan `frida-agent`, port 27042, timing hook, thread `gum-js-loop`. Luận văn mitigates **một phần** qua `spawn` mode và auto-attach victim; **không** stealth agent (O5 out-of-scope). Recall trên malware anti-analysis thực có thể thấp hơn kết quả trên test synthetic; claim phụ thuộc Frida phải gắn *conditional on Frida not being detected* (M5).

**Bảng 7.3.** Tóm tắt thảo luận E1–E6

| Nhóm | Tăng cường | Evidence | Hạn chế |
|------|------------|----------|---------|
| E1 | Cao | 59 test methodology; NT API variant | API ngoài manifest |
| E2 | Cao | Section-mapping ≥70 | Mockingjay/PoolParty chưa malware thật |
| E3 | TB–cao | Provenance test; E11→E1 | Memory-only; packed |
| E4 | TB | Bảng 3.9; Sysmon config | Thiếu benchmark syscall |
| E5 | **Không** | Trích dẫn ablation [7] (6,2 % vs 11,8 %) | Không anti-evasion module |
| E6 | Thấp | spawn; limitation doc | Anti-Frida (O5) |

---

## 7.3. So sánh với các hướng tiếp cận khác

### 7.3.1. Signature và rule API (Sigma, YARA behavior)

**Ưu:** triển khai nhanh, latency thấp. **Nhược:** thua E1 và E2 — thay Win32 sang NT đủ để miss. Noirlycan không thay rule production — phục vụ **nghiên cứu, đào tạo, audit**.

### 7.3.2. Behavior graph (Starink et al. [15])

Đồ thị hành vi đầy đủ với ràng buộc *same buffer* chặt hơn; chi phí graph matching cao, khó scale endpoint. [7] đơn giản hóa thành stream rule 2-of-3 — luận văn bám [7] vì cân bằng độ tổng quát và chi phí lab (Bảng 2.2).

### 7.3.3. EDR thương mại

Defender, Elastic Defend, CrowdStrike Falcon kết hợp kernel driver, ML, cloud correlation — vượt phạm vi luận văn; rule **đóng nguồn**. Noirlycan: mã nguồn mở, threat model minh bạch. Sysmon [11] chọn vì driver ký Microsoft và schema công khai.

### 7.3.4. Sandbox động (Cuckoo, Hatching Triage)

[7] chứng minh evasion che giấu injection (ablation 6,2 % vs 11,8 %) và công cụ công khai bỏ sót trung bình **21,2 %**. Noirlycan bổ sung **quan sát endpoint real-time** trong lab cô lập — bổ trợ, không cạnh tranh quy mô 56k mẫu.

**Bảng 7.4.** So sánh tổng hợp hướng tiếp cận

| Tiêu chí | Signature | [7] BluePill | Sandbox | EDR | Noirlycan |
|----------|-----------|----------|---------|-----|-----------|
| E1 | Yếu | Mạnh | Yếu–TB | Khá–Mạnh | Mạnh |
| E2 | Yếu | Mạnh | Yếu | Khá | Mạnh |
| E3 provenance | TB | Yếu | TB | Khá | **Extension** |
| E4 | Yếu | TB | TB | Mạnh | TB (Sysmon) |
| E5 | TB | **Mạnh** | Yếu (bỏ sót 18–24 %) | Khá | **Không** |
| Mở nguồn | Có | Artifact [14] | Một phần | Không | **Có** |
| Real-time endpoint | Có | Không | Không | Có | **Có (lab)** |

---

## 7.4. Độ tin cậy của kết quả thực nghiệm

### 7.4.1. Internal validity

Ground truth của 59 test methodology do **tác giả gắn nhãn** — phù hợp kiểm chứng *specification* [7] nhưng yếu về đại diện malware thật. Rủi ro bias: người viết test cũng viết correlator. Giảm thiểu: audit code-vs-paper phát hiện D1/D2/D3; Paper-Subset 100 mẫu Sap4Sec [14] và PoC-Bench (§6.10).

### 7.4.2. External validity

Chỉ **Windows 10/11 client x64**, lab VM cô lập. Không Server, ARM, enterprise fleet đa EDR. **Không khái quát hóa** sang production. Dataset [7] giai đoạn 2017–2023 — kỹ thuật 2024+ có rule classifier nhưng **chưa evaluate** trên corpus.

### 7.4.3. Construct validity

- **M1 (ba primitive):** không cover kernel injection (O3) — đúng phạm vi user-mode. BYOVD cần telemetry khác (DSE, HVCI logs).
- **M4 (memory congruence):** D1 (execute thiếu address) đã fix một phần qua Rip/`lpStartAddress`; edge case `ResumeThread` không context vẫn suy yếu congruence.
- **M5 (Frida fidelity):** protocol có; **drop-rate chưa điền** — claim phụ thuộc Frida phải gắn *conditional on M5*. Frida overhead thay đổi timing — có thể ảnh hưởng race APC hiếm.

### 7.4.4. Conclusion validity

| Không claim | Có thể claim |
|-------------|--------------|
| Prevalence 16,5% / bỏ sót 21,2% | 59 test methodology pass; section-mapping ≥70 |
| Precision/recall corpus lớn | Vượt baseline signature E1/E2 (test) |
| Chống E5 toàn diện | Provenance + telemetry kép (test định tính) |
| Thay EDR/sandbox production | Replication [7] trên Windows lab |

---

## 7.5. Ý nghĩa thực tiễn

### 7.5.1. Phòng lab an ninh mạng giáo dục

Hệ thống phù hợp tại khoa CNTT — UET và tương tự: **giảng dạy** MITRE T1055 [12] với loader PoC MessageBox; **điều tra số** correlate file drop với injection; **thesis replication** fork artifact, chạy subset Sap4Sec, mở rộng anti-evasion E5.

### 7.5.2. Giới hạn triển khai production

**Không khuyến nghị** deploy như EDR production: chưa có TLS/mTLS bắt buộc giữa agent và console, audit log chưa bất biến, chưa có sensor ETW-TI, không scale multi-host, chưa hardening O4/O5, không SLA. Console đã có xác thực, RBAC và lệnh agent ký Ed25519, nhưng Noirlycan vẫn là **research prototype** — analyst review bắt buộc.

### 7.5.3. Tích hợp workflow SOC (tương lai)

Finding JSONL có thể ingest SIEM (Elasticsearch, Splunk) qua parser tùy chỉnh — hướng mở rộng ngoài phạm vi luận văn.

---

## 7.6. Đạo đức nghiên cứu

Luận văn tuân thủ nguyên tắc nghiên cứu mã độc có trách nhiệm: (1) **cô lập** VM không kết nối mạng sản xuất, snapshot revert; (2) **PoC an toàn** dùng MessageBox; (3) **không phát tán** hash/mẫu từ [14]; (4) **trích dẫn** [7], [14] đúng license và DOI; (5) **transparency** threat model và limitation E5/E6 công khai.

---

## 7.7. Giải thích tên đề tài versus phạm vi hiện thực

Tên đề tài rộng (bao gồm E5). Phạm vi hiện thực **cố ý thu hẹp** E1–E4 vì anti-evasion của [7] dựa trên BluePill (DBI) — một hệ thống riêng vượt phạm vi thesis một năm. Replication lõi [7] + extension lab đã đủ đóng góp nếu trung thực về E5. E5 là **hướng phát triển bắt buộc** (Kết luận §4), không phải thất bại im lặng.

---

## 7.8. Hướng phát triển

**Bảng 7.5.** Lộ trình ưu tiên hướng phát triển

| Ưu tiên | Hướng | Đối phó | Nguồn |
|---------|-------|---------|-------|
| Cao | Anti-evasion subset | E5 | [14], paper §6 |
| Cao | Benchmark direct-syscall | E4 | PoC + Frida on/off |
| Cao | Frida fidelity benchmark (M5) | E6, construct | `frida-fidelity.md` |
| Trung | ETW TI provider | E4 | Thay Frida args |
| Trung | PoC-Bench + Paper-Subset 100 | E1, E2 | Sap4Sec [14] |
| Trung | Fix D1/D3 hoàn chỉnh | Congruence/temporal | Hooks + correlator |
| Thấp | ML classifier primitive sequence | E1 edge | Thay rule |
| Thấp | Cross-host correlation | Multi-stage | `injection_graph.py` |

**Gần (6–12 tháng):** hoàn thiện M5 + PoC-Bench. **Trung hạn:** port subset anti-evasion → claim "tăng cường dưới E5". **Dài hạn:** kernel ETW thay Frida — giảm E6, tăng tin cậy E4.

---

## 7.9. Bài học cho nghiên cứu replication

1. **Audit code-vs-paper trước khi claim** — D1/D2/D3 cho thấy implementation "gần đúng" vẫn có thể sai diễn giải (D1 ban đầu cho EXECUTE đóng góp 2-of-3 mà không có entry address → congruence bypass).
2. **Tách số liệu paper và thesis** — 16,5 %/21,2 % là của [7], không của Noirlycan.
3. **Extension phải map threat model** — provenance và Sysmon fallback có giá trị khi gắn E3/E4 cụ thể.

---

## 7.10. Tóm tắt chương

Luận văn **tăng cường có căn cứ** dưới **E1–E4** qua replication [7], kiến trúc Sysmon ∪ Frida, và pipeline provenance; **chưa** tăng cường dưới **E5**. Số liệu 16,5 % và 21,2 % [7] là động lực, không phải kết quả luận văn. So với signature, behavior graph [15], sandbox và EDR, Noirlycan là **công cụ lab mở, audit được, real-time endpoint**. Hạn chế validity đã khai báo; hướng phát triển ưu tiên anti-evasion E5, benchmark E4, và Frida fidelity M5. Luận văn định vị là **Replication + Extension Study** với Di Pietro et al. [7] là xương sống lý luận.
