# Outline luận văn thạc sĩ — Noirlycan

> **Bản luận văn đầy đủ (theo format UET):** xem thư mục [`thesis/`](../thesis/README.md).

> **Tên đề tài chính thức:** *Tăng cường phát hiện mã độc dưới các hình thức né tránh*
>
> *Căn cứ phương pháp:* Di Pietro et al., ASIA CCS 2025 — 2-of-3 operational primitive.
> *Artifact:* Noirlycan Telemetry (`thesis/`).

**Định dạng:** ACM/IEEE-style master thesis, ~60–80 trang.
**Ngôn ngữ:** Tiếng Anh (khuyến nghị — phù hợp citation) hoặc tiếng Việt theo
yêu cầu của trường. Outline dưới đây mô tả mục tiêu, đầu ra, và tham chiếu
sang artifact trong repo cho từng chương.

---

## Cấu trúc tổng thể

| # | Chương | Trang ~ | Trạng thái repo |
|---|--------|---------|-----------------|
| - | Front matter (Abstract, Lời cảm ơn, Mục lục, Danh mục viết tắt) | 4 | — |
| 1 | Mở đầu | 5–7 | README có vật liệu |
| 2 | Cơ sở lý thuyết (Background) | 8–10 | Cần viết |
| 3 | Công trình liên quan (Related Work) | 6–8 | Cần viết |
| 4 | Threat Model & Assumptions | 4–6 | [audit-and-threat-model.md §3](audit-and-threat-model.md) — sẵn nội dung |
| 5 | Phương pháp (Methodology) | 8–10 | [report-asiaccs25-comparison.md §4](report-asiaccs25-comparison.md) + [audit-and-threat-model.md §2](audit-and-threat-model.md) |
| 6 | Thiết kế và hiện thực (Design & Implementation) | 10–12 | Code repo |
| 7 | Đánh giá thực nghiệm (Evaluation) | 8–10 | **Chưa có** — cần thí nghiệm |
| 8 | Thảo luận và hạn chế (Discussion) | 4–5 | Phần trong audit |
| 9 | Kết luận và hướng phát triển | 2–3 | — |
| - | Tài liệu tham khảo | 3–4 | — |
| - | Phụ lục (A: API list, B: Sysmon config, C: Reproducibility) | 4–6 | configs/ + manifest |

---

## Chương 1 — Mở đầu

### 1.1. Bối cảnh
- Process injection là *base technique* T1055 trong MITRE ATT&CK, vẫn phổ biến
  trong malware Windows hiện đại (16.5 % mẫu 2017–2023 theo Di Pietro et al.,
  2025).
- Khoảng cách: nhiều phương pháp phát hiện tập trung **một kỹ thuật** hoặc
  **graph khớp chính xác** — khó tổng quát hóa khi malware đa hình.

### 1.2. Phát biểu vấn đề
- Cần phương pháp phát hiện process injection (a) tổng quát theo *operational
  primitive*, (b) chịu được biến thể triển khai, (c) gắn được với *nguồn gốc
  file* để hỗ trợ điều tra trên endpoint.

### 1.3. Mục tiêu nghiên cứu
- **RO1.** Hiện thực hóa lõi 2-of-3 primitive + memory congruence + temporal
  ordering của Di Pietro et al. (2025) trên Frida + Sysmon.
- **RO2.** Mở rộng pipeline để gắn *file provenance* (Sysmon Event 11 + static
  triage) vào chuỗi injection — đóng góp kiến trúc cho lab Windows 10/11.
- **RO3.** Đánh giá độ chính xác trên (a) bộ loader PoC tự xây và (b) subset
  artifact của paper gốc.

### 1.4. Đóng góp
1. **Replication có kiểm chứng** lõi phương pháp paper, công khai code +
   test (xem [docs/audit-and-threat-model.md](audit-and-threat-model.md)).
2. **Extension: file provenance + dashboard tương tác** —
   [src/noirlycan_telemetry/dashboard](../src/noirlycan_telemetry/dashboard).
3. **Bộ benchmark loader PoC** (sẽ xây ở Chương 7) — section-mapping,
   shellcode, APC, reflective DLL.
4. **Tài liệu hóa threat model formal** + assumption M1–M5.

### 1.5. Phạm vi
- In-scope: Windows 10/11 user-mode malware, Frida-attachable target.
- Out-of-scope: kernel-mode, direct syscall, anti-evasion chủ động — xem
  [audit §3.3 O1–O7](audit-and-threat-model.md).

### 1.6. Bố cục luận văn — như bảng trên.

---

## Chương 2 — Cơ sở lý thuyết

### 2.1. Windows process model
- Process, thread, PEB/TEB.
- Virtual memory: section objects, page protection (PAGE_EXECUTE_READWRITE).
- NT API vs Win32 API layer (`ntdll.dll` ↔ `kernel32.dll`).

### 2.2. Process injection — định nghĩa
- 3 thao tác *operational*: allocate, write, execute (Klein et al. 2017).
- Cùng vùng nhớ → "same buffer" theo Starink et al. 2023.

### 2.3. Taxonomy kỹ thuật injection
- Classic Remote Thread, APC, Early Bird, SetWindowsHookEx, Thread Hijacking,
  Process Hollowing (classic + section), Reflective DLL, Module Stomping,
  AtomBombing, Process Doppelgänging, Ghosting/Herpaderping.
- Tham chiếu MITRE ATT&CK T1055 family.

### 2.4. Công cụ telemetry
- **Sysmon** event reference (1, 3, 7, 8, 10, 11, 15) — xem
  [configs/sysmon-noirlycan.xml](../configs/sysmon-noirlycan.xml).
- **Frida** — Stalker, Interceptor; ưu/nhược so với ETW, EDR hook.
- **ETW** Threat Intelligence provider — đối thủ tiềm năng cho hướng tương lai.

---

## Chương 3 — Công trình liên quan

| Nhóm | Tài liệu chính | Nội dung | Đóng góp / hạn chế so với luận văn |
|------|----------------|---------|------------------------------------|
| Định nghĩa primitive | Klein et al. (USENIX 2017) | 3-step categorisation | Cơ sở; không bao phủ section mapping |
| Behaviour graph | Starink et al. (TIFS 2023) | API graph + memory congruence | Cứng theo API; paper 2025 nới |
| Methodology paper | **Di Pietro, D'Elia, Querzoni (ASIA CCS 2025)** | 2/3 rule + equivalence class | Đối tượng replication |
| EDR practice | Microsoft Defender, Elastic, CrowdStrike | rule-based + ML | Đóng (close-source) |
| Sandbox | Cuckoo, CAPE, Hatching Triage | dynamic trace | Paper 2025 so sánh: 21.2 % miss |
| Anti-evasion | Korkin (2022), Hosseini & Antoniou (2023) | kỹ thuật bypass | Paper tích hợp; luận văn out-of-scope |

(~25 cite tổng cộng, đủ cho master thesis.)

---

## Chương 4 — Threat Model & Assumptions

**Nguồn:** Toàn bộ [docs/audit-and-threat-model.md §3](audit-and-threat-model.md)
đã đủ formal — chuyển sang đây với biểu đồ trust boundary và bảng C1–C7,
O1–O7, E1–E6, M1–M5, T1–T9.

Mục cuối: **Scientific Claims** — chia rõ claim được/không được tuyên bố.

---

## Chương 5 — Phương pháp

### 5.1. Tổng quan pipeline
- Sơ đồ đầy đủ (paper + Noirlycan + so sánh):
  [architecture-diagrams.md](architecture-diagrams.md).
- Slide 1 trang FigJam:
  [architecture-diagrams-slide.md](architecture-diagrams-slide.md).
- Đối chiếu chi tiết:
  [report-asiaccs25-comparison.md §3.2](report-asiaccs25-comparison.md).

### 5.2. Định nghĩa primitive — kế thừa paper
- 3 primitive + lý do loại CONTEXT_READ khỏi đếm.
- Bảng API equivalence class — xem
  [injection_api_manifest.py](../src/noirlycan_telemetry/kernel/classification/api_manifest.py).

### 5.3. Quy tắc 2-of-3
- Phát biểu chính thức: `∃ k₁ ≠ k₂ ∈ {ALLOCATE, WRITE, EXECUTE}` quan sát trên
  cùng `(actor_pid, target_pid)` với memory congruence + temporal ordering.

### 5.4. Memory range congruence
- Định nghĩa khoảng nửa mở `[address, address+size)`; điều kiện overlap.
- D1 mở rộng: extract `Rip` từ `CONTEXT` cho `SetThreadContext` —
  [windows_injection_hooks.js readInstructionPointerFromContext](../src/noirlycan_telemetry/frida_hooks/windows_injection_hooks.js).

### 5.5. Temporal ordering (sau D3 fix)
- Reject mọi đảo bậc allocate/write/execute; cho phép allocate lặp.
- Mã: [correlation._has_temporal_consistency](../src/noirlycan_telemetry/services/analysis/domain/correlation.py).

### 5.6. Mở rộng: File provenance
- Sysmon Event 11 → static triage (SHA256, PE, signature, entropy) → liên kết
  với ProcessCreate qua image path → gắn vào Finding.

### 5.7. Phân loại kỹ thuật
- 21 enum trong `InjectionTechnique`, rule-based; xem
  [technique_classifier.py](../src/noirlycan_telemetry/technique_classifier.py).
- Bảng "rule → kỹ thuật → ATT&CK ID".

---

## Chương 6 — Thiết kế và hiện thực

### 6.1. Kiến trúc tổng thể
- Sơ đồ phân lớp, module map, sequence diagram:
  [architecture-diagrams.md §2](architecture-diagrams.md).
- Module map bổ sung: [report-asiaccs25-comparison.md](report-asiaccs25-comparison.md).

### 6.2. Collector
- `cli.py`, `collector_runtime.py`, `frida_manager.py`, `sysmon.py`,
  `file_watch.py`.

### 6.3. Frida hooks
- Lớp helper, `emit` vs `emitObservation`, xử lý `Zw*` aliases.
- Xử lý CONTEXT pointer (đoạn cho D1).

### 6.4. Correlation engine
- State machine, expiration window 300s, network watch hook.

### 6.5. Static triage + payload classifier
- Entropy, PE header, Authenticode, suspicious imports.

### 6.6. Dashboard
- Flask + tabs Overview/Findings/Network/Primitives/Sessions; JSONL export.

### 6.7. Reproducibility artifact
- Dockerfile (offline analyzer), VM image hash, sample SHA256 list (paper
  artifact + PoC loader). Xem Phụ lục C.

---

## Chương 7 — Đánh giá thực nghiệm

### 7.1. Câu hỏi đánh giá
- **RQ1.** Implementation có khớp ground-truth của paper artifact không?
- **RQ2.** Phương pháp có phát hiện được benchmark loader PoC tự xây không?
- **RQ3.** File provenance extension có tăng giá trị forensic đo được không?
- **RQ4.** Frida đủ trung thực cho kết luận khoa học không?

### 7.2. Dataset
| Tên | Kích thước | Nguồn | Ground truth |
|-----|-----------|-------|--------------|
| PoC-Bench | 5 loader (section-map, shellcode, APC, reflective DLL, hollowing) | Tự viết, Phụ lục D | Tác giả gắn nhãn |
| Paper-Subset | 100 mẫu | [Sap4Sec/process-injection](https://github.com/Sap4Sec/process-injection) | Paper artifact |
| Benign-Baseline | 50 chương trình hợp pháp | OS, Chocolatey | Không injection |

### 7.3. Phương pháp đo
- Precision, recall, F1 cho phát hiện chain.
- Precision, recall cho phân loại 12 kỹ thuật.
- Drop-rate Frida — xem
  [docs/experiments/frida-fidelity.md](experiments/frida-fidelity.md).
- Forensic-value extension: thời gian từ FileCreate đến Finding.

### 7.4. Kết quả
- Bảng số, biểu đồ confusion matrix.
- So sánh với baseline: Cuckoo Sandbox + ATT&CK rule, Sigma rule.
- Recursive chain prevalence — đối chiếu 2 % của paper (nếu đủ mẫu).

### 7.5. Mối đe dọa với validity
- Internal: số mẫu ít, ground truth do tác giả tự gắn.
- External: chỉ Windows 10/11; không bao phủ Windows Server.
- Construct: Frida có overhead; xem fidelity benchmark.

---

## Chương 8 — Thảo luận và hạn chế

- Khẳng định lại scientific claims (audit §3.8).
- Hạn chế theo audit §2.10 (D4–D8): anti-evasion, direct syscall, kernel mode.
- Câu hỏi mở: kernel ETW provider vs Frida; ML-based vs rule-based classifier.

---

## Chương 9 — Kết luận

### 9.1. Tóm tắt đóng góp
- Replication có kiểm chứng + extension provenance + tooling + benchmark.

### 9.2. Hướng phát triển
- **Tương lai gần:** ETW Threat Intelligence provider thay/đi cùng Frida.
- **Trung hạn:** ML classifier trên primitive sequence; cross-host correlation.
- **Dài hạn:** Tích hợp anti-evasion module theo paper gốc.

---

## Phụ lục

### A. Bảng đầy đủ API equivalence classes
- Sinh từ [injection_api_manifest.py](../src/noirlycan_telemetry/injection_api_manifest.py).

### B. Sysmon configuration
- [configs/sysmon-noirlycan.xml](../configs/sysmon-noirlycan.xml).

### C. Reproducibility
- Hướng dẫn build, VM image, sample list, hash, license note.

### D. Mã nguồn loader PoC
- Section-mapping, shellcode, APC, reflective DLL (đóng gói không có payload
  thực, chỉ MessageBox).

### E. Frida fidelity benchmark
- Driver script + protocol — [docs/experiments/frida-fidelity.md](experiments/frida-fidelity.md).

---

## Lộ trình viết (khuyến nghị 12 tuần)

| Tuần | Việc | Deliverable |
|------|------|-------------|
| 1 | Outline + đăng ký đề tài | Outline này được GVHD duyệt |
| 2–3 | Chương 2 + 3 | Related work draft |
| 4 | Chương 4 (Threat Model) | Audit doc chuyển thành chapter |
| 5 | Sửa code theo audit (D1/D2/D3 đã xong; D5/D6 nếu thời gian) | Repo ổn định |
| 6 | Chương 5 + 6 | Methodology + Implementation draft |
| 7–8 | Xây PoC-Bench + chạy Paper-Subset | Dataset + log |
| 9 | Frida fidelity benchmark | Số liệu M5 |
| 10 | Chương 7 | Evaluation draft |
| 11 | Chương 1 + 8 + 9 + Abstract | Bản đầy đủ |
| 12 | Hiệu đính + format LaTeX | Bản nộp |

---

## Checklist trước khi nộp

- [ ] Tất cả claim trong Chương 9 có evidence trong Chương 7.
- [ ] Không claim quá phạm vi audit §3.8.
- [ ] Mọi figure/bảng có cite.
- [ ] Reproducibility artifact (mã + dataset hash + VM build) sẵn sàng.
- [ ] Cite Di Pietro et al. (2025) đúng ACM format ở mọi nơi.
- [ ] Threat model + assumptions formal có trong chương 4.
- [ ] Limitations rõ ràng, không bị che giấu.
- [ ] Đạo đức nghiên cứu: VM cô lập, không phát tán mẫu thật trong artifact.
