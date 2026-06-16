# KẾT LUẬN

## 1. Khái quát công trình

Luận văn *Tăng cường phát hiện mã độc dưới các hình thức né tránh* đã nghiên cứu, thiết kế, hiện thực và đánh giá hệ thống **Noirlycan Telemetry** trên nền Windows 10/11 trong phòng lab cô lập. Công trình lấy **Di Pietro, D'Elia và Querzoni (ASIA CCS 2025) [4]** làm căn cứ khoa học trung tâm — nghiên cứu đã chứng minh trên **56.340 mẫu** malware Windows (2017–2023) rằng process injection (MITRE T1055 [9]) vẫn phổ biến (**~16,5 %** số mẫu) và sandbox phổ biến thiếu anti-evasion bỏ sót tới **21,2 %** mẫu injection; đồng thời đề xuất phương pháp phát hiện chịu biến thể triển khai nhờ *operational primitive* (allocate, write, execute), *equivalence class* API, quy tắc **2-of-3**, *memory range congruence* và *temporal ordering*.

Luận văn **không tái lập** quy mô thống kê prevalence của [4], mà trả lời câu hỏi bổ sung: *làm thế nào triển khai và tăng cường phương pháp đó trên endpoint lab Windows khi malware áp dụng né tránh E1–E4 (biến thể API, gộp bước, che attribution, né hook user-mode)?* Câu hỏi về né sandbox (E5) được thừa nhận là **ngoài phạm vi hiện thực**, với module anti-evasion của [4] là hướng phát triển bắt buộc.

---

## 2. Các kết quả đạt được

### 2.1. Mục tiêu nghiên cứu RO1–RO5

**Bảng K.1.** Tóm tắt đạt mục tiêu nghiên cứu

| Mục tiêu | Nội dung | Kết quả | Evidence |
|----------|----------|---------|----------|
| **RO1** | Hiện thực lõi [4] trên Frida + correlator | **Đạt** | `services/analysis/domain/correlation.py`, `kernel/classification/api_manifest.py`, 11 test correlation |
| **RO2** | Telemetry kép Sysmon ∪ Frida (E4) | **Một phần** | Config E8/E10; Bảng 3.9; thiếu benchmark syscall thuần |
| **RO3** | Pipeline provenance (E3) | **Một phần** | `file_watch.py`, triage, test `related_file` |
| **RO4** | Đánh giá biến thể injection | **Một phần** | 31 test pass; PoC-Bench chưa hoàn thiện |
| **RO5** | Threat model + ranh giới claim | **Đạt** | Chương 3; `docs/audit-and-threat-model.md` |

### 2.2. Về phương pháp và hiện thực

Đã hiện thực hóa đầy đủ các thành phần phương pháp [4] trong `services/analysis/domain/correlation.py`, `kernel/classification/api_manifest.py`, `kernel/analysis/primitives.py` và `windows_injection_hooks.js`:

- Ba operational primitive *allocate*, *write*, *execute* với **equivalence class** API — chống **E1** (biến thể Win32/NT).
- Quy tắc **≥ 2/3 primitive** khác loại trên cùng `(actor_pid, target_pid)` — chống **E2** (gộp/ẩn bước, section-mapping, Mockingjay).
- **Memory range congruence** và **temporal ordering** theo [4], [12]; fix deviation D1/D3 có test regression.
- **Technique classifier** 21+ kỹ thuật (`InjectionTechnique`), bao phủ biến thể beyond paper §4 (PoolParty, Mockingjay, Ghosting, …).

Kiểm chứng tự động: **31 test case pass** (`test_correlation.py`: 11 test; `test_ired_team_classifier.py`: 20 test). Case study **section-mapping** (*neurevt*-class) đạt score ≥ 70 — khớp pattern dominant trong dataset [4].

Audit code-vs-paper phát hiện và sửa ba deviation methodology (D1: execute thiếu address; D2: read API lẫn write; D3: temporal quá lỏng) — minh chứng trung thực khoa học replication.

### 2.3. Về tăng cường chống né tránh

**Bảng K.2.** Kết quả theo nhóm né tránh E1–E6

| Nhóm | Mô tả | Kết quả luận văn | Ghi chú |
|------|-------|------------------|---------|
| **E1** | Biến thể API | **Đạt** | Correlator phát hiện NT API thay Win32; vượt baseline signature |
| **E2** | Gộp/ẩn bước | **Đạt** | Section-mapping ≥70; 20 test classifier biến thể |
| **E3** | Né attribution | **Một phần** | Provenance E11→E1→Finding; định tính trên lab |
| **E4** | Né hook user-mode | **Một phần** | Kiến trúc Sysmon fallback; chưa benchmark định lượng |
| **E5** | Né sandbox/VM | **Chưa triển khai** | `kernel/analysis/evasion.py` ghi signal only; 21,2 % miss là của [4] |
| **E6** | Anti-Frida | **Hạn chế** | `spawn` mode; không countermeasure chủ động |

### 2.4. Về công cụ và tài liệu

- CLI `noirlycan-telemetry` (run, spawn, triage, dashboard, batch, corpus, reclassify).
- Session **JSONL**, SQLite cache corpus, dashboard analyst (Flask/Django).
- API reclassify offline; audit code-vs-paper; **threat model formal** E1–E6, C1–C7, O1–O7, M1–M6, T1–T9 (Chương 3).
- Sơ đồ kiến trúc (`docs/architecture-diagrams.md`, `architecture-comparison-template.svg`); hướng dẫn tái lập (Phụ lục C); manifest API (Phụ lục A); config Sysmon (Phụ lục B).

---

## 3. Những hạn chế của luận văn

Luận văn khai báo rõ các hạn chế sau — không che giấu trước hội đồng:

1. **E5 — Anti-sandbox/VM:** Không có module anti-evasion tương đương [4] §6. Không claim tăng cường recall dưới malware phát hiện VM/timing và **không inject** trong lab. Số liệu **21,2 %** sandbox miss thuộc [4], không phải kết quả Noirlycan.

2. **Quy mô đánh giá:** Không đo prevalence **16,5 %** hay miss **21,2 %** trên dataset riêng. Kết quả định lượng chính dựa trên 31 test synthetic; PoC-Bench (5 loader) và Paper-Subset (100 mẫu Sap4Sec [11]) **chưa hoàn thiện**.

3. **E4 — Direct syscall:** Thiếu benchmark loader syscall thuần đo tỷ lệ phát hiện khi Frida miss hoàn toàn. Kiến trúc fallback Sysmon đã thiết kế (Bảng 3.9) nhưng số liệu degradation chưa có.

4. **Frida fidelity (M5):** Protocol benchmark có (`docs/experiments/frida-fidelity.md`); drop-rate trên VM Windows **chưa điền**. Claim phụ thuộc đối số Frida là *conditional*.

5. **Deviation còn lại:** Một số edge case execute primitive (ví dụ `ResumeThread` không kèm CONTEXT) vẫn có thể suy yếu memory congruence so với paper.

6. **Classifier precision/recall:** 20 test xác nhận rule hoạt động trên synthetic; **không có** ground truth corpus đo precision phân loại kỹ thuật.

Các hạn chế được thảo luận chi tiết ở Chương 3 (§3.11, §3.13), Chương 6 (§6.9–6.13) và Chương 7.

---

## 4. Kiến nghị

### 4.1. Cho tác giả trước bảo vệ

- Chạy **Frida fidelity benchmark** trên VM Windows thật theo Phụ lục E; điền drop-rate vào Chương 6.
- Hoàn thiện **PoC-Bench** (5 loader an toàn) và chạy ít nhất **20 mẫu** subset Sap4Sec [11] với JSONL ground truth.
- Xây **loader direct-syscall** tối thiểu để đo recall degradation E4 (Frida on vs off).
- Rà soát lại toàn bộ claim trong bản luận văn đối chiếu Bảng 3.11 (claim được / claim cấm).

### 4.2. Cho hướng nghiên cứu tiếp theo

| Hướng | Mục tiêu | Đối phó né tránh |
|-------|----------|-----------------|
| Port subset anti-evasion từ artifact [11] | Recall lab gần paper | **E5** |
| ETW Threat Intelligence thay/bổ sung Frida | Syscall args từ kernel | **E4**, **E6** |
| ML classifier trên chuỗi primitive | Giảm rule maintenance | E1 edge cases |
| Metric recursive injection (~2 % [4]) | Multi-stage A→B→C | `injection_graph.py` |
| Cross-host correlation | Enterprise lab scale | E3 attribution |

---

## 5. Kết luận chung

Process injection là hành vi then chốt mà malware Windows dùng để **né phát hiện signature** và **né attribution** — thực thi payload dưới danh nghĩa tiến trình uy tín thay vì binary dễ bị chặn. Công trình Di Pietro et al. (ASIA CCS 2025) [4] cung cấp nền tảng phương pháp mạnh chống biến thể triển khai (**E1**, **E2**) và bằng chứng quy mô lớn về tác động né tránh sandbox (**E5** — **21,2 %** miss khi thiếu anti-evasion).

Luận văn đã **tăng cường phát hiện mã độc dưới các hình thức né tránh E1–E4** bằng cách:

1. **Hiện thực có kiểm chứng** phương pháp [4] trên Windows 10/11 lab (Frida hooks + correlator Python, 31 test pass).
2. **Bổ sung telemetry kernel** (Sysmon Event 1, 7, 8, 10, 11) và document *graceful degradation* khi hook user-mode bị né (**E4**).
3. **Mở rộng pipeline file provenance** liên kết file-drop với chuỗi injection (**E3**).
4. **Formal hóa threat model** và ranh giới claim khoa học — tách bạch replication [4], extension lab, và những gì **cấm** tuyên bố (prevalence 56k, anti-E5 toàn diện, thay EDR production).

Đề tài hoàn thành mục tiêu luận văn thạc sĩ theo format UET: có **căn cứ lý luận** [4], [7], [12]; có **hiện thực** artifact mã nguồn mở; có **đánh giá và kiểm chứng** methodology; có **thảo luận và thừa nhận hạn chế** trung thực — đặc biệt khoảng cách **E5** so với paper gốc.

Hướng mở rộng tự nhiên — anti-evasion module, benchmark E4/M5, PoC-Bench quy mô — sẽ cho phép luận văn hoặc công trình tiếp theo claim *tăng cường* gần đúng nghĩa rộng của tên đề tài (*các hình thức né tránh*), trong đó **21,2 %** của [4] vẫn là mốc đích đến có căn cứ thực nghiệm, không phải con số marketing.
