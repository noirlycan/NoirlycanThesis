# KẾT LUẬN

## 1. Khái quát công trình

Luận văn đã thiết kế, hiện thực và đánh giá **Noirlycan Telemetry** trên Windows 10/11 lab cô lập. Căn cứ trung tâm là **Di Pietro, D'Elia, Querzoni (ASIA CCS 2025) [4]** — chứng minh trên **56.340 mẫu** malware Windows (2017–2023) rằng process injection (T1055 [9]) còn phổ biến (**~16,5 %**), sandbox thiếu anti-evasion bỏ sót **21,2 %** mẫu; đề xuất phát hiện chịu biến thể nhờ *operational primitive*, *equivalence class* API, **2-of-3**, *memory range congruence*, *temporal ordering*.

Luận văn **không tái lập** quy mô thống kê [4] mà trả lời: *triển khai phương pháp đó trên endpoint lab thế nào khi malware né E1–E4 (biến thể API, gộp bước, che attribution, né hook user-mode)?* E5 **ngoài phạm vi** vì cần sandbox sửa đổi vượt khuôn khổ thạc sĩ.

---

## 2. Các kết quả đạt được

### 2.1. Mục tiêu nghiên cứu RO1–RO5

**Bảng K.1.** Tóm tắt đạt mục tiêu nghiên cứu

| Mục tiêu | Nội dung | Kết quả | Evidence |
|----------|----------|---------|----------|
| **RO1** | Lõi [4] trên Frida + correlator | **Đạt** | `correlation.py`, `api_manifest.py`, 11 test |
| **RO2** | Telemetry kép Sysmon ∪ Frida (E4) | **Một phần** | E8/E10; Bảng 3.9; thiếu benchmark syscall |
| **RO3** | Pipeline provenance (E3) | **Một phần** | `file_watch.py`, triage, test `related_file` |
| **RO4** | Đánh giá biến thể injection | **Một phần** | 31 test; PoC-Bench chưa xong |
| **RO5** | Threat model + ranh giới claim | **Đạt** | Chương 3; `audit-and-threat-model.md` |

RO1, RO5 đạt; RO2–RO4 một phần do thiếu phép đo định lượng cuối.

### 2.2. Kiểm chứng giả thuyết H1–H5

| Giả thuyết | Kết luận |
|------------|----------|
| H1 (E1) | **Chấp nhận** |
| H2 (E2) | **Chấp nhận** |
| H3 (E3) | **Chấp nhận một phần** |
| H4 (E4) | **Chưa đủ số liệu** |
| H5 (Frida) | **Chưa kiểm chứng** |

H1, H2 chấp nhận trên test case và case study *neurevt*. H3 một phần vì chưa kiểm chứng trên malware né attribution thật. H4, H5 cần thêm benchmark.

### 2.3. Về phương pháp và hiện thực

Đã hiện thực đầy đủ phương pháp [4] trong `correlation.py`, `api_manifest.py`, `primitives.py`, `windows_injection_hooks.js`:

- Ba primitive *allocate*/*write*/*execute* với **equivalence class** API — chống **E1**. Quy `VirtualAllocEx`/`NtAllocateVirtualMemory`/`NtMapViewOfSection` về *allocate*; `WriteProcessMemory`/`NtWriteVirtualMemory` về *write*; `CreateRemoteThread`/`NtCreateThreadEx`/`QueueUserAPC`/`SetThreadContext`+`ResumeThread` về *execute*.
- Quy tắc **≥ 2/3 primitive** khác loại trên cùng `(actor_pid, target_pid)` — chống **E2** (section-mapping, Mockingjay gộp bước).
- **Memory range congruence** và **temporal ordering** [4], [12]; fix D1/D3 có test regression. **Technique classifier** 21+ kỹ thuật, beyond §4 (PoolParty, Mockingjay, Ghosting).

**31 test pass** (correlation 11; classifier 20). Section-mapping (*neurevt*) score ≥ 70 — khớp pattern dominant [4]. Audit sửa D1, D2, D3 tại `docs/audit-and-threat-model.md`.

### 2.4. Về tăng cường chống né tránh

**Bảng K.2.** Kết quả theo nhóm né tránh E1–E6

| Nhóm | Mô tả | Kết quả | Ghi chú |
|------|-------|---------|---------|
| **E1** | Biến thể API | **Đạt** | Correlator phát hiện NT API; vượt baseline signature |
| **E2** | Gộp/ẩn bước | **Đạt** | Section-mapping ≥70; 20 test classifier |
| **E3** | Né attribution | **Một phần** | Provenance E11→E1→Finding |
| **E4** | Né hook user-mode | **Một phần** | Sysmon fallback; chưa benchmark |
| **E5** | Né sandbox/VM | **Chưa** | `evasion.py` signal only; 21,2 % thuộc [4] |
| **E6** | Anti-Frida | **Hạn chế** | `spawn` mode; không countermeasure |

Với E5/E6, "signal only" nghĩa ghi nhận truy vấn `IsDebuggerPresent`, `ProcessDebugPort`, artifact VM nhưng không ngụy trang môi trường — phù hợp lab cô lập.

### 2.5. Về công cụ và tài liệu

- CLI `noirlycan-telemetry` (run, spawn, triage, dashboard, batch, corpus, reclassify); session **JSONL**, SQLite cache, dashboard Flask/Django.
- API reclassify offline; **threat model formal** E1–E6, C1–C7, O1–O7, M1–M6, T1–T9 (Chương 3); hướng dẫn tái lập (Phụ lục C); manifest API (A); config Sysmon (B).

Reclassify offline cho phép áp rule cải tiến lên JSONL cũ không cần chạy lại malware.

---

## 3. Những hạn chế của luận văn

1. **E5 — Anti-sandbox/VM:** Không có module anti-evasion tương đương [4] §6. Số liệu **21,2 %** thuộc [4], không phải Noirlycan.
2. **Quy mô đánh giá:** Không đo prevalence **16,5 %** hay miss **21,2 %** trên dataset riêng. Định lượng dựa trên 31 test synthetic; PoC-Bench và Paper-Subset (100 mẫu Sap4Sec [11]) **chưa xong**.
3. **E4 — Direct syscall:** Thiếu benchmark loader syscall thuần. Hell's Gate/Halo's Gate bỏ qua `ntdll.dll` — Frida user-mode mất tầm nhìn, chỉ ETW kernel chứng kiến.
4. **Frida fidelity (M5):** drop-rate VM Windows **chưa điền** — claim phụ thuộc Frida là *conditional*.
5. **Deviation còn lại:** `ResumeThread` không kèm CONTEXT có thể suy yếu congruence; `SetThreadContext`+`ResumeThread` cách hàng trăm ms vượt cửa sổ temporal.
6. **Classifier precision/recall:** **không có** ground truth corpus đo precision. Hollowing/Doppelgänging/Herpaderping có thể nhầm khi telemetry không đủ.

Chi tiết tại §3.11, §3.13, §6.9–6.13 và Chương 7.

---

## 4. Kiến nghị

### 4.1. Cho tác giả trước bảo vệ

- Chạy **Frida fidelity benchmark** trên VM Windows (Phụ lục E); điền drop-rate.
- Hoàn thiện **PoC-Bench** (5 loader) và chạy ≥ **20 mẫu** Sap4Sec [11].
- Xây loader direct-syscall đo recall degradation E4; rà soát claim đối chiếu Bảng 3.11.

### 4.2. Cho hướng nghiên cứu tiếp theo

| Hướng | Mục tiêu | Đối phó |
|-------|----------|---------|
| Port anti-evasion từ [11] | Recall lab gần paper | **E5** |
| ETW-TI thay/bổ sung Frida | Syscall args kernel | **E4**, **E6** |
| ML classifier chuỗi primitive | Giảm rule maintenance | E1 edge |
| Recursive injection (~2 % [4]) | Multi-stage A→B→C | `injection_graph.py` |
| Cross-host correlation | Enterprise scale | E3 |

ETW-TI (`Microsoft-Windows-Threat-Intelligence`) giải quyết cả E4 và E6; chỉ phát cho driver có ELAM — rào cản hành chính, không kỹ thuật.

---

## 5. So sánh và ý nghĩa

**So với [4]:** Xác nhận 2-of-3 trên endpoint (H1, H2) nhưng **không vượt** quy mô thống kê hay module E5. Bổ sung: real-time, dashboard, extension E3, audit replication có test. [4] hậu phân tích batch trên Cuckoo-like; Noirlycan phát hiện chủ động trên endpoint, delay tính bằng giây.

**So với Klein [7], Starink [12]:** Cụ thể hóa primitive và congruence thành artifact chạy được, không dừng ở lý thuyết.

**So với sandbox/EDR:** Không cạnh tranh recall 56k; cung cấp **công cụ lab mở** cho giảng dạy và tái lập [4] tại Việt Nam [13].

**Ý nghĩa:** Kỹ sư DFIR dùng Noirlycan hiểu *tại sao* rule API fail và *khi nào* cần telemetry kernel. Hạn chế E5 nhắc rằng phát hiện injection không đủ nếu malware phát hiện môi trường phân tích — bài học 21,2 % của [4], quan trọng cho nhóm Việt Nam còn dùng sandbox tự dựng.

## 6. Kết luận chung

Process injection là hành vi then chốt mà malware Windows dùng để **né signature** và **né attribution**. [4] cung cấp nền tảng chống biến thể (**E1**, **E2**) và bằng chứng quy mô về né sandbox (**E5** — **21,2 %** miss). *Operational primitive* và *2-of-3 rule* phù hợp endpoint vì không phụ thuộc tên hàm mà quan tâm hành vi semantic.

Luận văn đã **tăng cường phát hiện E1–E4** bằng: (1) hiện thực có kiểm chứng phương pháp [4] trên Windows 10/11 lab (Frida + correlator, 31 test pass); (2) bổ sung telemetry kernel (Sysmon Event 1, 7, 8, 10, 11) với *graceful degradation* khi hook user-mode bị né (**E4**); (3) mở rộng pipeline file provenance liên kết file-drop với chuỗi injection (**E3**); (4) formal hóa threat model và ranh giới claim — tách replication [4], extension lab, và những gì **cấm** tuyên bố (prevalence 56k, anti-E5, thay EDR production).

Đề tài hoàn thành mục tiêu thạc sĩ format UET: **căn cứ lý luận** [4], [7], [12]; **hiện thực** artifact mã nguồn mở; **đánh giá** methodology; **thừa nhận hạn chế** trung thực — đặc biệt khoảng cách **E5**. Hướng mở rộng (anti-evasion, benchmark E4/M5, PoC-Bench quy mô) sẽ cho phép công trình tiếp theo claim *tăng cường* gần đúng nghĩa rộng của tên đề tài, với **21,2 %** của [4] là mốc đích đến có căn cứ thực nghiệm.
