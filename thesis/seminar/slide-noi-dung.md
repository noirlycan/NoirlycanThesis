# Nội dung slide seminar — 30 phút (~25 slide)

**Đề tài:** Tăng cường phát hiện mã độc trước các kĩ thuật né tránh  
**Hệ thống:** Noirlycan Telemetry  
**Thời lượng:** ~30 phút (demo 5–7 phút, Q&A cuối)

> Copy từng slide sang PowerPoint/Google Slides. Ghi chú speaker nằm dưới dòng `--- Speaker ---`.

---

## Slide 1 — Tiêu đề

**Tăng cường phát hiện mã độc trước các kĩ thuật né tránh**

Hiện thực và mở rộng phương pháp ASIA CCS 2025 trên lab endpoint Windows

- Sinh viên: [Họ tên — MSV]
- GVHD: [Tên thầy/cô]
- Khoa Công nghệ thông tin — ĐHQGHN

--- Speaker ---
Chào thầy/cô và các bạn. Em trình bày đề tài thạc sĩ về phát hiện process injection khi malware né tránh, căn cứ paper ASIA CCS 2025 tại Hà Nội.

---

## Slide 2 — Outline

1. Vấn đề & động cơ  
2. Cơ sở: paper [4] và khoảng trống  
3. Phương pháp & hệ thống Noirlycan  
4. Thực nghiệm & kết quả  
5. Demo live  
6. Ý nghĩa, hạn chế, kết luận  

--- Speaker ---
Buổi seminar ~30 phút: ~20 phút trình bày, ~5–7 phút demo, còn lại Q&A.

---

## Slide 3 — Vấn đề: Process injection

- **T1055** — malware chạy payload trong process nạn nhân  
- Che attribution: inject vào `explorer.exe`, binary đã ký…  
- Rule EDR đơn giản (`CreateRemoteThread` + `WriteProcessMemory`) dễ bỏ sót  

**Hình gợi ý:** sơ đồ actor → target process

--- Speaker ---
Injection là hành vi then chốt, không chỉ là một API đơn lẻ.

---

## Slide 4 — Malware né tránh (E1–E6)

| Nhóm | Ý tưởng |
|------|---------|
| E1 | Đổi API (`Nt*` thay Win32) |
| E2 | Gộp bước (section-mapping) |
| E3 | Che nguồn (file-drop loader) |
| E4 | Direct syscall / unhook |
| E5 | Phát hiện sandbox → không chạy |
| E6 | Anti-Frida / anti-debug |

**Phạm vi luận văn:** E1–E4 (E5 **ngoài phạm vi**)

--- Speaker ---
Luận văn formal hóa 6 nhóm; E5 em khai báo out-of-scope vì cần module anti-evasion riêng của paper.

---

## Slide 5 — Paper [4]: số liệu motivation

**Di Pietro et al., ASIA CCS 2025, Hanoi**

| Số liệu | Ý nghĩa |
|---------|---------|
| 56.340 mẫu | Quy mô nghiên cứu paper |
| ~**16,5%** có injection | Vẫn phổ biến |
| **21,2%** sandbox miss | Thiếu anti-evasion |

⚠️ Đây là số liệu **paper**, không phải kết quả em đo lại.

--- Speaker ---
Nhấn mạnh: 21,2% là lý do nghiên cứu quan trọng, không phải metric Noirlycan.

---

## Slide 6 — Paper [4]: phương pháp cốt lõi

Ba **operational primitive:**

1. **Allocate** — vùng thực thi  
2. **Write** — ghi/map payload  
3. **Execute** — kích hoạt thread/context  

**Quy tắc ≥2/3** + memory congruence + thứ tự thời gian

--- Speaker ---
Paper gom mọi biến thể API vào 3 primitive semantic — điểm then chốt em replicate.

---

## Slide 7 — Khoảng trống: paper vs luận văn

| | Paper [4] | Luận văn (Noirlycan) |
|---|-----------|----------------------|
| Môi trường | Sandbox QEMU batch | **Endpoint lab real-time** |
| Telemetry | Custom API tracer | **Frida + Sysmon** |
| Provenance file | Không | **File-drop → finding** |
| Giao diện | Dataset/log | **Dashboard React** |
| Quy mô đánh giá | 56k mẫu | **31 test + case study** |

**Hình:** mermaid Paper vs Noirlycan — `docs/architecture-diagrams-slide.md`

--- Speaker ---
Em không cạnh tranh quy mô 56k; em trả lời câu hỏi triển khai endpoint.

---

## Slide 8 — Câu hỏi & mục tiêu RO1–RO5

**Câu hỏi:** Hiện thực 2-of-3 [4] trên Windows lab + mở rộng E3/E4?

| RO | Nội dung | Trạng thái |
|----|----------|------------|
| RO1 | Lõi [4] | ✅ Đạt |
| RO2 | Sysmon fallback | ⚠️ Một phần |
| RO3 | File provenance | ⚠️ Một phần |
| RO4 | Benchmark biến thể | ⚠️ Một phần |
| RO5 | Threat model | ✅ Đạt |

--- Speaker ---
RO1 và RO5 là cột sống; RO2–RO4 còn thiếu số liệu VM quy mô lớn.

---

## Slide 9 — Giả thuyết H1–H5

| H | Nội dung | Kết quả |
|---|----------|---------|
| H1 | 2-of-3 chống E1 (API variant) | ✅ Chấp nhận |
| H2 | 2-of-3 chống E2 (section-map) | ✅ Chấp nhận |
| H3 | Provenance chống E3 | ⚠️ Một phần |
| H4 | Sysmon chống E4 | ❌ Chưa đủ số liệu |
| H5 | Frida fidelity | ❌ Chưa kiểm chứng |

--- Speaker ---
31 unit test chủ yếu chứng minh H1, H2; H4/H5 cần benchmark VM.

---

## Slide 10 — Pipeline phát hiện

```text
File drop → Triage → ProcessCreate → Frida hooks
    → Correlator (≥2/3) → Finding → Network watch (5 min)
    → Dashboard
```

**Hình:** flowchart ngang (5–6 hộp)

--- Speaker ---
Điểm khác paper: bắt đầu từ file trên đĩa, không chỉ trace API thuần.

---

## Slide 11 — Quy tắc 2-of-3 (ví dụ)

**Section-mapping / hollowing:**

- Allocate: `NtAllocateVirtualMemory`  
- Write: `NtMapViewOfSection` / `NtWriteVirtualMemory`  
- Execute: `SetThreadContext` + `ResumeThread`  

→ ≥2 primitive khác loại, cùng vùng nhớ, đúng thứ tự thời gian → **Finding score ≥70**

Baseline signature `VirtualAllocEx→WPM→CRT` → **FAIL**

--- Speaker ---
Đây là case study em dùng cả trong test lẫn demo.

---

## Slide 12 — Kiến trúc 3 đơn vị

```text
Windows VM          Mac / Server           Browser
noirlycan-agent  →  noirlycan-backend  ←  dashboard-ui
Frida+Sysmon        FastAPI :8888          React :5173
```

- Agent: thu thập, correlate local, gửi ingest  
- Backend: SQLite, rules, agents, findings API  
- Dashboard: Overview, Findings, File drops, Network  

--- Speaker ---
Tách 3 máy trong lab: VM Windows, server backend, browser analyst.

---

## Slide 13 — Thu thập: Frida + Sysmon

| Nguồn | Event / dữ liệu |
|-------|-----------------|
| **Frida** | API args, memory primitive, actor/target PID |
| **Sysmon E1** | ProcessCreate, lineage |
| **Sysmon E11** | FileCreate (.exe…) |
| **Sysmon E8/E10** | Remote thread, process access |
| **Sysmon E3** | NetworkConnect (post-finding watch) |
| **File watcher** | Copy mới vào folder watch |

Config: `configs/sysmon-noirlycan.xml`

--- Speaker ---
Telemetry kép: Frida chi tiết API; Sysmon bù khi hook user-mode bị né.

---

## Slide 14 — Correlator & classifier

**Correlator** (`correlation.py`):

- Equivalence class API (manifest)  
- Memory overlap + temporal order  
- Network watch khi score ≥70, 5 phút  

**Classifier** (rule-based):

- 21+ kỹ thuật: hollowing, APC, reflective DLL, PoolParty…  
- 20 unit test  

--- Speaker ---
Classifier bổ sung paper — gán tên kỹ thuật cho finding, không chỉ “có injection”.

---

## Slide 15 — Dashboard (screenshot)

**Tab chính:**

- **Overview** — KPI findings, file drops, injection chains  
- **Findings** — nhóm actor → target, score, APIs  
- **File drops** — provenance file nguồn  
- **Network** — connection + beacon candidate  

**Hình:** chụp từ lab — `thesis/seminar/images/`

--- Speaker ---
Nếu chưa có screenshot, demo live thay slide tĩnh.

---

## Slide 16 — Thực nghiệm: môi trường

- Windows 10/11 x64 VM (snapshot)  
- Sysmon v15 + config lab (Admin cài)  
- Agent: `--watch-sysmon --auto-attach-new-processes`  
- Backend `--host 0.0.0.0 --port 8888`  
- pytest 31 test (CI + local)  

--- Speaker ---
Nêu rõ VM cô lập — không chạy malware trên mạng production.

---

## Slide 17 — Kết quả: 31 unit test

| Nhóm test | Số lượng | Kết quả |
|-----------|----------|---------|
| Correlation | 11 | ✅ Pass |
| Classifier | 20 | ✅ Pass |
| **Tổng** | **31** | **0 failed** |

Case nổi bật:

- Section-mapping → score ≥70  
- AES loader → CRITICAL ≥85  

--- Speaker ---
Đây là evidence mạnh nhất hiện tại — reproducible, không cần VM lúc CI.

---

## Slide 18 — Kết quả: so baseline signature

| Kịch bản | Rule API đơn | Noirlycan 2-of-3 |
|----------|--------------|------------------|
| Classic CRT injection | Có thể bắt | ✅ |
| Section-mapping | ❌ Miss | ✅ |
| Chỉ 1 primitive | ❌ (đúng) | ❌ (đúng) |

**Ý nghĩa:** semantic primitive > tên API cố định

--- Speaker ---
Slide này trả lời “kết quả có ý nghĩa gì” — chống E1/E2 cụ thể.

---

## Slide 19 — Kết quả: extension E3 & E4

**E3 — Provenance:**

- File-drop → triage (hash, PE, entropy) → `related_file` trong finding  
- Dashboard tab File drops  

**E4 — Sysmon fallback:**

- EID 1/8/10 khi Frida thiếu tên process / syscall né hook  
- **Chưa** benchmark loader syscall thuần (H4 pending)  

--- Speaker ---
Thành công E3 qualitative; E4 thiết kế có, số liệu A/B chưa có.

---

## Slide 20 — Demo live (1/2): chuẩn bị

**Trước seminar:**

1. Backend + dashboard chạy trên Mac  
2. Agent VM online (Agents tab xanh)  
3. Sysmon Running (hoặc Plan B: Frida-only)  
4. Loader `.exe` sẵn trong folder watch  

**Script:** `thesis/seminar/demo-script.md`

--- Speaker ---
Chuyển sang demo — hoặc video backup nếu mạng VM lỗi.

---

## Slide 21 — Demo live (2/2): kịch bản

1. Copy `.exe` mới → **File drops**  
2. **Findings** — injection chain, score, APIs  
3. (Optional) **Network** — beacon destination  
4. **Rules** — min primitives, capture window  

--- Speaker ---
Nói to từng bước: “đây là file nguồn”, “đây là actor/target”, “đây là 2-of-3 primitive”.

---

## Slide 22 — Hạn chế

1. **Không** replicate 56k / 21,2%  
2. **E5** out-of-scope — không anti-sandbox module  
3. **H4/H5** chưa benchmark VM  
4. Frida user-mode — direct syscall vẫn là rủi ro  
5. PoC-Bench / Sap4Sec subset **chưa xong**  

--- Speaker ---
Slide trung thực — thầy thường hỏi phạm vi; chuẩn bị sẵn.

---

## Slide 23 — Ý nghĩa

**Khoa học:**

- Xác nhận 2-of-3 [4] chạy trên endpoint  
- Mở rộng provenance + console lab  

**Thực tiên:**

- Công cụ mở cho dạy/học DFIR tại UET  
- Tái lập paper [4] không cần sandbox đóng  

**So với [4]:** bổ sung engineering, không thay thế thống kê quy mô

--- Speaker ---
Nhấn: em đóng góp artifact + extension, không claim prevalence mới.

---

## Slide 24 — Hướng tiếp theo

- Hoàn thiện PoC-Bench (5 loader)  
- Subset Sap4Sec [11]  
- Frida fidelity + direct-syscall benchmark  
- Module anti-evasion (E5) — hướng paper  
- ETW-TI cho kernel visibility  

--- Speaker ---
Ngắn gọn — cho thấy em biết đường đi sau thạc sĩ.

---

## Slide 25 — Kết luận & Q&A

**Ba điểm chính:**

1. Hiện thực có kiểm chứng phương pháp ASIA CCS 2025 (31 test)  
2. Mở rộng file provenance + telemetry kép + dashboard lab  
3. Ranh giới claim rõ — E5/56k ngoài phạm vi  

**Cảm ơn thầy/cô — em sẵn sàng câu hỏi.**

--- Speaker ---
Mời Q&A. Câu hay gặp: “Sao không đo 21,2%?” → E5 out-of-scope. “Frida bị né?” → Sysmon partial + H4 future.

---

## Phụ lục slide (dự phòng)

- Bảng E1–E6 đầy đủ — copy từ `chapters/01-mo-dau.md` Bảng M.1  
- Screenshot lỗi Sysmon / Plan B demo  
- Lệnh `scripts/lab_stack.py up`  
