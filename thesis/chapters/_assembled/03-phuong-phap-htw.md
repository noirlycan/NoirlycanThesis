# CHƯƠNG 2. PHƯƠNG PHÁP TĂNG CƯỜNG PHÁT HIỆN MÃ ĐỘC DƯỚI NÉ TRÁNH

Chương này trình bày **định nghĩa bài toán**, **threat model**, **phương pháp giải quyết** (kế thừa và mở rộng [4]), và **phân tích đánh giá phương pháp** — phân biệt rõ kết quả đã có và đóng góp của luận văn (nguyên tắc khởi–thừa–chuyển–kết). Phần đầu formal hóa đối thủ và giả định; phần sau mô tả pipeline 2-of-3, provenance và telemetry kép.

---

Chương này xây dựng **mô hình đe dọa formal** cho Noirlycan: tài sản, đối thủ, giả định môi trường/phương pháp, ranh giới tin cậy telemetry, mối đe dọa, **ranh giới claim khoa học**. Căn cứ audit đối chiếu Noirlycan với Di Pietro et al. (ASIA CCS 2025) [7], `docs/audit-and-threat-model.md`, taxonomy E1–E6.

## 2.1. Phạm vi và hệ thống quan tâm

### 2.1.1. System Under Analysis (SUA)

SUA là **một host Windows 10/11** trong lab cô lập. Phạm vi: *phát hiện hành vi inject ở endpoint*; SIEM, multi-tenant ngoài đề tài.

**Bảng 2.1.** Thành phần hệ thống Noirlycan

| Thành phần | Privilege | Cơ chế quan sát | Module repo |
|------------|-----------|-----------------|-------------|
| Sysmon driver | **Kernel** | Process/Image/Object callback, Minifilter, ETW Threat Intelligence | `sysmon.py` |
| Sysmon service | User (LocalSystem) | Thu event từ driver, ghi Event Log | `sensors/sysmon.py` |
| Frida agent | **User (in-target)** | `Interceptor.attach` trên `ntdll`/`kernel32`/`user32` | `sensors/frida_monitor.py`, `frida_hooks/handlers.js` |
| Python collector | User | Đọc Event Log + Frida bus, correlate | `runtime/pipeline.py`, `detection/correlator.py` |
| Static triage | User | SHA256, PE header, entropy, Authenticode | `triage.py`, `payload.py` |
| Console | User (máy analyst) | FastAPI + React + WebSocket, JSONL export | `noirlycan_backend/`, `dashboard-ui/` |
| Target process | User | Loader malware / PoC | — |

Driver kernel ghi sự kiện không che được bởi user-mode adversary; Frida là *granular API tracer* cung cấp tham số (addr, size, prot); collector correlate `(actor_pid, target_pid)` window 300s. Frida mất signal khi direct syscall (E4); Sysmon vẫn ghi Event 8/10 — *defense-in-depth* (mục 3.8).

### 2.1.2. Ranh giới hệ thống

```
┌─────────────────────────────────────────────────────────────────┐
│  Host Windows lab VM (UNTRUSTED — chứa malware)                 │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │ Target process  │  │ Sysmon driver   │  │ Collector       │  │
│  │ + Frida agent   │  │ (kernel)        │  │ Python          │  │
│  │ (user-mode)     │  │ TRUSTED*        │  │ TRUSTED         │  │
│  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘  │
│           │                    │                     │            │
│           └────────────────────┴─────────────────────┘            │
│                         JSONL session log                         │
└───────────────────────────────┬─────────────────────────────────┘
                                │ (file ACL, lab network only)
                                ▼
                    Analyst workstation (TRUSTED)
```

\* Sysmon tin cậy nếu O3 không xảy ra; BYOVD vẫn khả thi nhưng khó (xem 3.4.3). Phạm vi chỉ pipeline host → analyst, nhất quán [7].

## 2.2. Phân loại hình thức né tránh (E1–E6)

Ký hiệu **E1–E6** cho sáu nhóm né tránh process injection (thống nhất Bảng 1.1).

**Bảng 2.2.** Taxonomy né tránh và phản ứng hệ thống

| ID | Hình thức né tránh | Mô tả | Mitigation Noirlycan | Trạng thái |
|----|-------------------|-------|----------------------|------------|
| **E1** | Biến thể API | Win32 ↔ NT API, đổi thread/APC | Equivalence + 2-of-3 [7] | **Xử lý** (có test) |
| **E2** | Gộp/ẩn bước | Section mapping, Mockingjay (RWX) | 2-of-3 + classifier section-mapping | **Xử lý** (có test) |
| **E3** | Né attribution | Inject tiến trình hợp pháp; file-drop loader | Sysmon lineage + provenance + triage | **Mở rộng** |
| **E4** | Né hook user-mode | Direct syscall, unhook `ntdll` | Sysmon E8/E10 fallback | **Một phần** |
| **E5** | Né sandbox/VM | Timing, env fingerprint — không inject | Không có module anti-evasion | **Out-of-scope** |
| **E6** | Né instrumentation | Anti-Frida, anti-debug | `spawn` mode; documented | **Hạn chế** |

E1 phản ánh không gian API rộng cho cùng primitive *WRITE-cross-process*. E2: section mapping gộp allocate+write. E3 tấn công *attribution*. E4 là *visibility floor* user-mode. E5/E6 là né tránh *meta*. **Lưu ý:** ký hiệu E1–E6 ở mục 3.5 là **giả định môi trường**, khác ngữ cảnh.

## 2.3. Tài sản cần bảo vệ (Assets)

**Bảng 2.3.** Tài sản và mục tiêu bảo vệ

| ID | Tài sản | Định nghĩa | Liên quan né tránh |
|----|---------|------------|-------------------|
| **A1** | Toàn vẹn phát hiện | Finding phản ánh đúng hành vi inject thực tế | E1, E2, E4 |
| **A2** | Sẵn sàng collector | Collector/Frida không crash; log đủ event | E6 |
| **A3** | Cô lập lab | Malware không lan ra production | An toàn nghiên cứu |

A1 là tài sản **trung tâm**; không yêu cầu phát hiện khi malware không inject (E5) — đồng bộ [7] (evasion làm giảm injection quan sát được: 11,8 % → 6,2 % khi bỏ anti-evasion). Ưu tiên *integrity* hơn *coverage*.

## 2.4. Mô hình đối thủ (Adversary Model)

### 2.4.1. Loại đối thủ

**Đối thủ:** tác giả malware Windows **user-mode** (Tier 2 Microsoft SDL) — botnet loader, trojan banker, RAT, red-team implant.

**Mục tiêu đối thủ:** (1) inject thành công; (2) tránh telemetry lab; (3) persistence/beacon (tùy mẫu, ngoài phạm vi).

**Không phải đối thủ:** insider admin tắt Sysmon; APT kernel rootkit (O3); analyst giả mạo log. OS bị khống chế ngoài threat model — kế thừa [7][10][15].

### 2.4.2. Năng lực giả định CÓ (C1–C7)

**Bảng 2.4.** Năng lực đối thủ trong phạm vi

| ID | Năng lực | Ví dụ | Né tránh liên quan |
|----|----------|-------|-------------------|
| **C1** | Gọi mọi Win32/NT API export | `NtWriteVirtualMemory`, `RtlCreateUserThread` | E1 |
| **C2** | Section mapping | `NtCreateSection` + `NtMapViewOfSection` | E1, E2 |
| **C3** | Process hollowing | `CREATE_SUSPENDED` + `SetThreadContext` + `ResumeThread` | E2, E3 |
| **C4** | DLL/reflective load | `LoadLibrary*`, manual PE map | E1, E3 |
| **C5** | Mã hóa payload runtime | XOR/AES stub | Che static, không che runtime |
| **C6** | Drop file rồi spawn | `%TEMP%\*.exe` → ProcessCreate | E3 |
| **C7** | Evasion **thụ động** | `IsDebuggerPresent`, sleep ngắn | E6; phần E5 |

C5 che static nhưng không che runtime primitive — lý do behavioral detection bền hơn signature; C7 **cố ý không** gồm anti-sandbox đầy đủ (E5/O7).

### 2.4.3. Năng lực NGOÀI phạm vi (O1–O7)

**Bảng 2.5.** Out-of-scope capabilities

| ID | Năng lực ngoài phạm vi | Lý do loại trừ | Hệ quả nếu xảy ra |
|----|------------------------|----------------|-------------------|
| **O1** | Direct syscall stub | Frida miss API-arg; paper cũng giới hạn user tracer | FN Frida; Sysmon E8/E10 vẫn báo |
| **O2** | Unhook/patch `ntdll` | Cùng O1 | Tương tự O1 |
| **O3** | **Kernel-mode** rootkit/BYOVD tắt Sysmon | Paper/repo user-space focus | Toàn bộ telemetry kernel mù |
| **O4** | TOCTOU/side-channel collector | Ngoài injection study | Collector integrity fail |
| **O5** | Anti-Frida **chủ động** | Lab prototype | Malware abort → miss behavior |
| **O6** | Process Ghosting/Herpaderping mới | Taxonomy mở rộng dần | FN kỹ thuật chưa cover |
| **O7** | Sandbox-aware evasion **chủ động** | Paper có anti-evasion; luận văn không | Malware không inject → recall thấp |

O1/O2 không đồng nghĩa detection = 0: Sysmon vẫn ghi Event 8 vì `PsSetCreateThreadNotifyRoutine` được gọi sau syscall qua KiSystemCall64. O3 là ranh giới cứng.

## 2.5. Giả định môi trường (Environmental Assumptions)

Ký hiệu **E1–E6** environmental — khác né tránh E1–E6 (mục 3.2).

**Bảng 2.6.** Giả định môi trường vận hành

| ID | Giả định | Mô tả | Vi phạm → hậu quả | Liên quan né tránh |
|----|----------|-------|-------------------|-------------------|
| **E1** | Sysmon config `sysmon-noirlycan.xml` | Event 1,3,7,8,10,11 enabled | Mất lineage/provenance | E4, E3 |
| **E2** | Frida attach **trước** API inject đầu | Ưu tiên `spawn` | Late attach → FN (T2) | E6 |
| **E3** | Không pure direct syscall mọi API | Ít nhất một call qua export hook | Pure syscall → Frida trống | E4 |
| **E4** | Clock monotonic trong window 300s | `detection/correlator.py` | VM rollback → temporal sai | — |
| **E5** | Không collision `(actor_pid, target_pid)` benign | Lab ít noise | Gom nhầm chain → FP (T8) | — |
| **E6** | VM cô lập, không credential thật | Ethics lab | Rủi ro ngoài phạm vi khoa học | E5 |

E3 thực dụng: malware in-the-wild đến 2023 dùng hỗn hợp direct syscall + API thường. Pure syscall everywhere thuộc O1.

## 2.6. Giả định phương pháp (Methodological Assumptions M1–M6)

**Bảng 2.7.** Giả định khoa học — căn cứ phương pháp [7]

| ID | Giả định | Nguồn / justification | Rủi ro nếu sai |
|----|----------|----------------------|----------------|
| **M1** | A/W/E trên cùng vùng nhớ **đủ mô tả** injection user-mode | Klein và Kotler [10]; [7] §3.1 | FN kỹ thuật kernel (O3) |
| **M2** | ≥ 2/3 primitive khác loại **đủ kết luận** injection | [7] §3.2 | FP từ benign debug tool |
| **M3** | API cùng equivalence class thay thế được | [7] Table 1 | FN khi API chưa liệt kê |
| **M4** | Memory overlap là proxy cho *same buffer* | Starink [15]; [7] §3.3 | FP/FN edge case |
| **M5** | Frida hook **trung thực** về argument/thứ tự | Frida [8]; cần benchmark | Drop event → sai 2-of-3 |
| **M6** | Sysmon kernel callbacks không bị user-mode sửa | Driver ring 0; chỉ O3 phá | Mất lớp kernel nếu O3 |

M1–M3 là cơ sở 2-of-3; M4 là *bridging assumption* (overlap address+size). **M5 cần justification:** Chương 6 đề xuất protocol Frida fidelity (ETW/SilkETW ≥ 1000 lệnh gọi synthetic); claim Frida gắn *conditional on M5*. **D1 đã sửa:** EXECUTE thiếu `address` được phục hồi bằng `lpStartAddress`/`Rip` từ CONTEXT.

## 2.7. Ma trận né tránh ↔ mitigation (tổng hợp)

**Bảng 2.8.** Ma trận đối thủ – hình thức né tránh – mitigation – hạn chế

| Né tránh | Năng lực C | Out-of-scope O | Module Noirlycan | Mức độ mitigation | Hạn chế còn lại |
|----------|-----------|----------------|------------------|-------------------|-----------------|
| E1 | C1,C2,C4 | — | `detection/api_classes.py`, `detection/correlator.py` | Cao | API mới chưa trong manifest |
| E2 | C2,C3 | — | 2-of-3, `technique_classifier.py` | Cao | Mockingjay edge (RWX) |
| E3 | C3,C6 | — | Sysmon E1/E11, `file_watch.py`, triage | TB-cao | Inject không qua file-drop |
| E4 | (via O1/O2) | O1,O2 | Sysmon E8/E10 | TB | Mất address/size |
| E5 | C7 phần | **O7** | `evasion.py` ghi signal | **Không** | Recall < paper |
| E6 | C7 | O5 | `spawn`, docs | Thấp | Không stealth Frida |

## 2.8. Ma trận tin cậy lớp telemetry (Telemetry Layer Trust Matrix)

Trả lời phản biện *"Frida bị bypass — phương pháp còn ý nghĩa gì?"*: **graceful degradation** — khi hook user-mode bị né, Sysmon (kernel callback) vẫn cung cấp primitive EXECUTE từ EID 8 và bằng chứng handle + call stack từ EID 10; detection giảm về số primitive quan sát được nhưng không về zero, và việc kernel thấy remote thread mà Frida không thấy được gắn cờ *hook bypass*. Đây là đóng góp định tính so với [7], vốn dùng một lớp instrumentation (BluePill/Pin).

**Bảng 2.9.** Telemetry Layer Trust Matrix

| Nguồn telemetry | Privilege | Cơ chế bắt | Bị bypass bởi | Phạm vi quan sát | Vai trò trong correlator |
|-----------------|-----------|------------|---------------|------------------|--------------------------|
| Sysmon Event 1 (ProcessCreate) | Kernel | Process notify | O3 | Process create | Lineage, parent PID — **E3** |
| Sysmon Event 7 (ImageLoad) | Kernel | Image notify | O3 | DLL/PE map | Reflective vs `LoadLibrary` |
| Sysmon Event 8 (CreateRemoteThread) | Kernel | ETW TI | O3 | Cross-process thread **kể cả direct syscall** | Fallback EXECUTE — **E4** |
| Sysmon Event 10 (ProcessAccess) | Kernel | ObCallback | O3 | `OpenProcess`+VM_WRITE | Fallback access — **E4** |
| Sysmon Event 11 (FileCreate) | Kernel | Minifilter | O3 | File exec/script mới | Provenance — **E3** |
| Sysmon Event 3 (NetworkConnect) | Kernel | ETW WFP | O3 | TCP/UDP | Post-injection beacon |
| Frida hooks (~121 API) | **User** | Export intercept | **O1,O2,O5** | NT API args (addr,size,prot) | Primitive, congruence — **E1,E2** |
| Static triage | User | Disk read | C5 | Hash, PE, entropy, signature | Payload class |

**Kết luận:** với O1/O2, Frida mất granularity nhưng Sysmon vẫn fire Event 8/10 → correlator thấy *process_access + execute* với confidence giảm; detection khả thi ở mức "có cross-process injection" thay vì chi tiết kỹ thuật — recall giảm, **không về 0**.

## 2.9. Mối đe dọa và mitigations (T1–T9)

**Bảng 2.10.** Threat catalog

| ID | Threat | Né tránh | Mức | Mitigation hiện có | Mitigation đề xuất / trạng thái |
|----|--------|----------|-----|-------------------|--------------------------------|
| **T1** | Direct syscall bỏ qua Frida | E4/O1 | Cao | Sysmon E8/E10 fallback | ETW TI provider (future) |
| **T2** | Late attach miss primitive đầu | E6 | Cao | `spawn` mode | Auto-attach chỉ file-drop |
| **T3** | EXECUTE thiếu address | E2 edge | TB | **Đã fix D1:** `lpStartAddress`/Rip | Test regression |
| **T4** | Frida agent bị detect | E6/O5 | TB | — | Out-of-scope |
| **T5** | Anti-evasion sandbox | E5/O7 | Cao | `evasion.py` signal only | Future module như [7] |
| **T6** | Read API lẫn write count | — | TB | **Đã fix D2:** tách `remote_read` | — |
| **T7** | Temporal ordering lỏng | — | Thấp | **Đã fix D3:** reject đảo bậc A/W/E | — |
| **T8** | Collision `(actor,target)` benign | — | Thấp | Window 300s + PID pair | Đo FP Benign-Baseline (Ch.6) |
| **T9** | Kernel-mode injection | O3 | Cao | — | Out-of-scope |

T3, T6, T7 là **deviation methodology** phát hiện qua audit code-vs-paper — cung cấp scientific provenance.

## 2.10. Trust boundary và luồng dữ liệu

**Bảng 2.11.** Ranh giới tin cậy theo thành phần

| Thành phần | Tin cậy | Điều kiện |
|------------|---------|-----------|
| Malware / target process | **Không tin cậy** | Luôn |
| Frida agent | Tin cậy có điều kiện | E2, E3 env; không O5 |
| Sysmon driver | Tin cậy | Không O3 |
| Collector Python | Tin cậy | Không O4 |
| JSONL session log | Tin cậy | File ACL lab |
| Analyst workstation | Tin cậy | Ngoài SUA |

Luồng dữ liệu forensic:

```
FileCreate (E11) → static triage → ProcessCreate (E1) → Frida primitives
                                                      ↘ Sysmon E8/E10
                              → correlator (2-of-3 + congruence + temporal)
                              → technique_classifier → Finding + score
                              → dashboard / JSONL
```

Finding là *hypothesis* dựa trên M1–M6, không phải ground truth. Score ≥ 50/70 thể hiện 2-of-3 + congruence + ordering đã thoả; phán quyết cuối thuộc analyst.

## 2.11. Ranh giới claim khoa học (Scientific Claims Boundaries)

Phân tách claim có evidence và claim **cấm** nếu chưa có Chương 6.

### 2.11.1. Claim ĐƯỢC PHÉP bảo vệ (có căn cứ audit)

| ID | Claim | Evidence |
|----|-------|----------|
| **C-IMPL** | Lõi 2-of-3 + congruence + temporal của [7] đã hiện thực trên Frida+Sysmon Windows 10/11 | `detection/correlator.py`, `detection/api_classes.py`, `test_correlation.py` |
| **C-AUDIT** | Ba deviation D1/D2/D3 đã phát hiện và sửa có test regression | `docs/audit-and-threat-model.md` |
| **C-EXT** | Pipeline file provenance → lineage → finding cung cấp ngữ cảnh [7] không có | `file_watch.py`, `detection/correlator.py` |
| **C-CASE** | Section-mapping (*neurevt*) phát hiện đúng pattern primitive trên PoC | `test_detects_section_mapping_write_execute_chain` |
| **C-ARCH** | Sysmon ∪ Frida document graceful degradation dưới E4 | Bảng 2.9, mục 3.8 |
| **C-TAX** | Taxonomy mở rộng (36 kỹ thuật enum) | `technique_classifier.py` — không kèm precision số |

### 2.11.2. Claim KHÔNG ĐƯỢC PHÉP (cấm nếu chưa bổ sung evaluation)

| Claim cấm | Lý do |
|-----------|-------|
| "Precision/recall ngang/hơn [7]" | Không dataset 56k; không baseline Cuckoo |
| "Phát hiện kỹ thuật X với Y%" | Classifier chưa eval ground truth |
| "Tái lập prevalence 16,5 % / tỷ lệ bỏ sót 21,2 % của công cụ công khai" | Số liệu thuộc [7] |
| "Chống E5 toàn diện" | O7 — không anti-evasion |
| "Production-ready EDR thay thương mại" | Lab prototype; M5 chưa đủ |
| "Frida đủ tin cậy mọi điều kiện" | O1/O5; cần M5 |
| "Phương pháp mới thay [7]" | Sai — lõi là [7]; luận văn replication + extension |

Bảng claim cấm là checklist self-guard chống *claim creep*.

### 2.11.3. Claim có điều kiện (conditional)

| Claim | Điều kiện |
|-------|-----------|
| "Tăng cường phát hiện dưới E1/E2" | Malware **đã thực hiện** inject; trong manifest API |
| "Giảm FN dưới E4" | Sysmon E1 env assumption; không O3 |
| "Tăng cường truy vết E3" | Có file-drop + Event 11; static triage readable |

## 2.12. Mapping threat model ↔ mục tiêu nghiên cứu (RO1–RO5)

**Bảng 2.12.** Liên kết RO và threat model

| Mục tiêu (Chương Mở đầu) | Threat model |
|--------------------------|--------------|
| RO1 — Hiện thực [7] | M1–M4; C-IMPL; T3/T6/T7 fixes |
| RO2 — Telemetry kép E4 | Bảng 2.9; T1; O1/O2 degradation |
| RO3 — Provenance E3 | Sysmon E11/E1; C-EXT |
| RO4 — Đánh giá biến thể | C-CASE; E1/E2; **không** claim prevalence |
| RO5 — Tài liệu hóa threat model | Toàn chương 2; scientific claims §3.11 |

Mapping bảo đảm truy nguyên hai chiều giữa RO và threat model.

## 2.13. Hạn chế threat model và tính hợp lệ ngoại vi (*validity*)

### 2.13.1. Internal validity

- Ground truth PoC do tác giả gắn nhãn — bias có thể có.
- Số mẫu nhỏ so với [7] — không generalize prevalence.
- Frida overhead có thể thay đổi timing — ảnh hưởng race condition hiếm (không đo đầy đủ).

Bias kiềm chế bằng công khai mã PoC và config Sysmon để tái lập.

### 2.13.2. External validity

- Chỉ Windows 10/11 client — không Windows Server, không Linux.
- Lab VM ≠ enterprise endpoint có EDR đa agent.
- Mẫu 2017–2023 trong [7] — kỹ thuật 2024+ (một số) chỉ có rule chưa evaluate.

Windows 10/11 client là *deliberate scoping*: server và Linux (ptrace, LD_PRELOAD) ngoài T1055 Windows.

### 2.13.3. Construct validity

- Primitive abstraction M1 có thể không map một số kỹ thuật mới (PoolParty phức tạp) — classifier bổ sung, không thay 2-of-3.
- Score finding (≥ 50/70) là heuristic lab, chưa calibrate trên corpus.

PoolParty và biến thể 2024 làm primitive A/W/E có thể không phân giải đủ mịn. Chương 7 mở rộng.

## 2.14. Tóm tắt chương

Chương 2 đã xây dựng threat model formal: telemetry kép Sysmon + Frida; A1–A3; C1–C7; O1–O7; E1–E6 và M1–M6; ma trận tin cậy giải thích graceful degradation dưới E4; T1–T9; ranh giới claim phân tách replication [7], extension, claim cấm. Threat model làm khung cho Chương 5 và 6 — thí nghiệm phải map C-IMPL/C-EXT/C-CASE, không vượt §3.11.

---

Chương này trình bày phương pháp luận, căn cứ công trình Di Pietro, D'Elia, Querzoni tại ASIA CCS 2025 [7], phát hiện process injection khi malware né signature API (E1) hoặc gộp/ẩn bước operational (E2). Luận văn kế thừa lõi — ba *operational primitive*, *equivalence class*, *2-of-3*, *memory congruence*, *temporal ordering* — và mở rộng hai tầng chống E3, E4. **Module anti-evasion E5 không được hiện thực** trong Noirlycan.

---

## 2.15. Tổng quan pipeline phương pháp

### 2.15.1. Hai tầng tăng cường

Phương pháp gồm hai tầng:

1. **Tầng chống biến thể (E1, E2)** — kế thừa [7]: mọi lời gọi API injection ánh xạ vào một trong ba primitive *allocate*, *write*, *execute*; chuỗi được kết luận khi có ≥2 primitive khác loại trên cùng cặp `(actor_pid, target_pid)` thỏa congruence + temporal.
2. **Tầng ngữ cảnh (E3, E4)** — đóng góp của luận văn: (a) pipeline *file provenance* phục hồi loader khi victim hợp pháp; (b) *telemetry kép* Sysmon ∪ Frida giảm FN khi user-mode hook bị né.

So với pipeline batch của [7] (BluePill/Pin → trace → analyzer offline), Noirlycan chạy trên Windows real-time: khác biệt then chốt là trục thời gian — Noirlycan dùng cửa sổ trượt và re-evaluation tăng dần.

### 2.15.2. Luồng dữ liệu end-to-end

```
[1. Thu thập] FileDropWatcher/Sysmon E11,E15→FileEvent; Sysmon E1→ProcessEvent;
              Frida hooks→MemoryPrimitive; Sysmon E3→NetworkConnectionEvent
[2. Tiền xử lý] FileTriage (SHA256, PE, entropy, Authenticode);
                runtime_event_to_primitive / runtime_event_to_process
[3. Tương quan] Correlator.add_file/add_process/add_primitive
                → 2-of-3 + temporal + congruence → scoring → Finding
[4. Đầu ra] JSONL → Dashboard → export/reclassify
```

Noirlycan duy trì **cửa sổ trượt 300s** (`Correlator.window_seconds=300`), đánh giá lại chuỗi mỗi khi có primitive mới. Giá trị 300s dự phòng *delayed execution* mà không bùng nổ bộ nhớ.

### 2.15.3. Định nghĩa đối tượng quan sát

Ký hiệu:

| Ký hiệu | Ý nghĩa |
|---------|---------|
| $\mathcal{P}$ | Tập tiến trình trên host |
| $\pi \in \{\texttt{allocate}, \texttt{write}, \texttt{execute}\}$ | Operational primitive theo [7], [10] |
| $\mathrm{obs}(t, a, v, \pi, r)$ | Quan sát primitive $\pi$ lúc $t$, actor $a$, victim $v$, vùng nhớ $r = [addr, addr+size)$ |
| $K \subseteq \{\texttt{A}, \texttt{W}, \texttt{E}\}$ | Tập loại primitive đã quan sát trên một chuỗi |
| $\mathrm{score}(K, ctx)$ | Điểm tin cậy 0–100 sau khi thỏa quy tắc phát hiện |

Một **Finding** gồm: timestamp, actor/target PID + image, danh sách primitive, score, evidence, kỹ thuật suy luận, `related_file`. Finding immutable; cập nhật chỉ *upgrade* score.

---

## 2.16. Giả thuyết, tính khả thi và tiêu chí kiểm chứng

Theo [2], chương này gắn với **H1–H5** (§1.3.3). Mỗi giả thuyết quy định biến độc lập, biến phụ thuộc, thí nghiệm, ngưỡng chấp nhận; neo vào thành phần code giúp phản nghiệm khả thi.

**Bảng 2.1.** Giả thuyết ↔ thành phần phương pháp ↔ tiêu chí

| Giả thuyết | Thành phần Noirlycan | Tiêu chí chấp nhận |
|------------|----------------------|-------------------|
| **H1** (E1) | `detection/api_classes.py`, correlator 2-of-3 | Test correlation pass; NT API thay Win32 vẫn ≥2 primitive |
| **H2** (E2) | Congruence + temporal + section-mapping rule | Score ≥ 70 trên case `section_mapping` |
| **H3** (E3) | `file_watch.py`, triage, `related_file` | Finding chứa path + hash file-drop |
| **H4** (E4) | Sysmon E8/E10 + Frida hooks | Case syscall: Sysmon bắt khi Frida miss (thiết kế; số liệu pending) |
| **H5** (E6/M5) | `frida-fidelity.md` protocol | Drop-rate < 1 % trên VM |

**Tính khả thi:** artifact [14] và paper [7] công khai; stack Sysmon/Frida/Python có sẵn. Rủi ro: benchmark VM Windows (H4, H5) phụ thuộc thời gian lab và ổn định Frida.

**Well-posed problem:** vấn đề là *tăng cường phát hiện dưới E1–E4 trên endpoint lab*, không phải tái lập các số liệu prevalence/bỏ sót của [7] (phát biểu sau không kiểm chứng được trong phạm vi luận văn).

---

## 2.17. Operational primitive và equivalence class (chống E1)

### 2.17.1. Ba primitive theo [7]

Theo Klein và Kotler [10] và formal hóa của [7], process injection user-mode mô hình bằng ba thao tác độc lập với họ API:

1. **Allocate ($\texttt{A}$)** — chuẩn bị vùng nhớ qua `VirtualAllocEx`, `NtCreateSection` + `NtMapViewOfSection`, hoặc đổi protection sang `PAGE_EXECUTE_READWRITE` qua `VirtualProtectEx`.
2. **Write ($\texttt{W}$)** — đặt payload qua `WriteProcessMemory` hoặc ghi ngầm qua mapping.
3. **Execute ($\texttt{E}$)** — chuyển luồng thực thi qua `CreateRemoteThread`/`NtCreateThreadEx`, `QueueUserAPC`, `SetThreadContext` + `ResumeThread`, `LoadLibrary` remote, hoặc `SetWindowsHookEx`.

**E1:** malware thay `CreateRemoteThread` bằng `NtCreateThreadEx`, thay Win32 bằng NT/Zw, hoặc resolve API runtime qua `GetProcAddress`. [7] khớp **lớp tương đương** chứ không khớp chuỗi API cố định, nên tổ hợp NT thuần vẫn được phát hiện như A+W+E hợp lệ.

### 2.17.2. Bảng equivalence class

**Bảng 2.2.** Lớp tương đương API theo [7] (trích; manifest `PAPER_API_CLASSES`, Phụ lục A)

| Lớp | Primitive | Ví dụ API |
|-----|-----------|-----------|
| allocate | A | `VirtualAllocEx`, `NtAllocateVirtualMemory`, `VirtualProtectEx`, `NtCreateSection`, `CreateFileMapping*`, `MapViewOfFile*` |
| write | W | `WriteProcessMemory`, `NtWriteVirtualMemory`, `NtMapViewOfSection`, `NtUnmapViewOfSection`, `RtlCopyMemory` |
| execute | E | `CreateRemoteThread*`, `NtCreateThreadEx`, `QueueUserAPC`, `SetThreadContext`, `ResumeThread`, `LoadLibrary*`, `SetWindowsHookEx*`, `NtAddAtom` |
| remote_read | *(quan sát)* | `ReadProcessMemory`, `NtReadVirtualMemory` — **không** tính vào 2-of-3 (D2) |
| context_read | *(lab)* | `GetThreadContext`, `NtGetContextThread` — chỉ báo hijack-prep |

`remote_read` và `context_read` là *observation-only*: log phục vụ classifier nhưng không nâng $|K|$ vì đọc remote không cấu thành tấn công (debugger cũng làm). `IRED_TEAM_API_CLASSES` bổ sung fiber, threadpool, window memory, TXF — không thay quy tắc 2-of-3.

### 2.17.3. Cơ chế hook chống E1

Frida `Interceptor.attach` gắn trên export của `kernel32.dll`, `ntdll.dll`, `user32.dll`. Alias `Zw*` resolve cùng stub với `Nt*`. Tập `DYNAMIC_INJECTION_APIS` bao phủ API resolve động qua `GetProcAddress`: agent hook xen kẽ khi `GetProcAddress` trả về địa chỉ trong tập theo dõi. Mỗi lần gọi thành công phát sinh `memory_primitive` hoặc `api_observation` với `kind`, `address`, `size`, `protection`, và (nếu có) `thread_parameter` hoặc trích đoạn `CONTEXT`.

---

## 2.18. Quy tắc 2-of-3 (chống E2)

### 2.18.1. Động cơ né tránh E2

Malware gộp/ẩn bước để né chuỗi A→W→E đầy đủ: **section mapping** (`NtCreateSection`+`NtMapViewOfSection` remote — chỉ W+E); **Mockingjay/RWX sẵn có** (W+E hoặc E); **Process Hollowing section variant** (allocate+write gộp trong map, execute qua `SetThreadContext`+`ResumeThread`).

[7] chứng minh yêu cầu đủ ba bước gây FN; quy tắc **≥2 trong 3 primitive khác loại** tăng recall, giữ precision nhờ congruence + temporal.

### 2.18.2. Phát biểu hình thức

Cho cặp $(a, v)$ trong cửa sổ $T$:

$$\mathcal{O}_{a,v,T} = \{\, \mathrm{obs}(t_i, a, v, \pi_i, r_i) \mid t_i \in T \,\}$$

$$K = \{\, \pi \mid \exists\, \mathrm{obs}(\cdot, a, v, \pi, \cdot) \in \mathcal{O}_{a,v,T} \,\}$$

**Quy tắc 2-of-3** (phương trình 2.14):

$$|K \cap \{\texttt{A}, \texttt{W}, \texttt{E}\}| \geq 2$$ (2.14)

**Điều kiện bổ sung** ([7] §3.3–3.4):

$$\mathrm{Congruence}(\mathcal{O}_{a,v,T}) \land \mathrm{Temporal}(\mathcal{O}_{a,v,T})$$ (2.15)

Implementation: `operational_kind_count(kinds) >= 2` trong `_evaluate_chain`, loại `CONTEXT_READ` khỏi đếm. Độ trễ $O(|P|)$ trên bucket $(a, v)$, thực tế dưới 100 phần tử mỗi cặp.

### 2.18.3. Ví dụ minh họa E2

| Kịch bản | Primitive quan sát | $|K|$ | Kết luận |
|----------|-------------------|-------|----------|
| Classic DLL injection | A + W + E | 3 | Finding (cao điểm) |
| Section-mapping (*neurevt*) | W (`NtMapViewOfSection`) + E (`ResumeThread`) | 2 | Finding (test `test_detects_section_mapping_write_execute_chain`) |
| Chỉ `WriteProcessMemory` | W | 1 | **Không** finding (`test_requires_two_distinct_primitives`) |
| Debugger remote read | A + read-only | 1 | **Không** (D2: read không tính W) |

Ba dòng cuối thể hiện vai trò *gating*: không alarm hoạt động đơn lẻ, kích hoạt khi đủ hai trục tác vụ.

---

## 2.19. Memory range congruence

### 2.19.1. Định nghĩa

Hai quan sát đồng nhất vùng nhớ nếu $r_1 = [addr_1, addr_1 + size_1)$ và $r_2$ giao nhau:

$$\mathrm{overlap}(r_1, r_2) \iff addr_1 < addr_2 + size_2 \;\land\; addr_2 < addr_1 + size_1$$ (2.16)

Starink et al. [15] dùng ý tưởng tương tự; [7] áp dụng overlap để loại FP khi process có nhiều thao tác heap độc lập (allocate A, write B không overlap → không ghép).

### 2.19.2. Thuật toán trong Noirlycan

`_has_memory_congruence` xây tập khoảng từ mỗi primitive qua `_memory_link_ranges`:

- `address` + `size` lấy từ tham số API;
- `thread_parameter` trên EXECUTE — ví dụ tham số thứ hai của `CreateRemoteThread` trỏ buffer chứa đường dẫn DLL (pattern LoadLibrary remote thread);
- `context_pointer` liên kết `GetThreadContext` ↔ `SetThreadContext` qua trường `Rip` trong `CONTEXT` x86-64;
- `address == 0` coi như thiếu (thường gặp với `NtAllocateVirtualMemory` khi `*BaseAddress` chưa fill).

Congruence yêu cầu **ít nhất một cặp primitive khác loại** có overlap. Ngoại lệ: khi `NtAllocateVirtualMemory` không trả address nhưng có WRITE + EXECUTE cross-process, chuỗi vẫn chấp nhận nếu `operational_kind_count >= 2` và chỉ một loại có range — *safe relaxation*.

### 2.19.3. Deviation D1 (khai báo trung thực)

Execute-level API (`ResumeThread`, `NtCreateThreadEx` không kèm `lpStartAddress`) lịch sử không mang `address`. Fix D1: hook đọc `Rip` từ `CONTEXT` cho `SetThreadContext`, `lpStartAddress` cho `CreateRemoteThread`, `StartRoutine` cho `NtCreateThreadEx` (test `test_set_thread_context_with_rip_overlaps_write_buffer`). Khi execute vẫn thiếu address, congruence suy yếu; luận văn **không claim** precision tương đương paper trên mọi biến thể execute-only.

---

## 2.20. Temporal ordering

### 2.20.1. Quy tắc [7]

Thứ tự canonical **A → W → E**, với hai ngoại lệ: (1) allocate lặp (resize buffer, đổi protection RWX→RX sau khi ghi); (2) gộp bước (section mapping phát sinh W đồng thời với map; thứ tự A–W không xác định từ trace).

### 2.20.2. Formal hóa implementation

Gán bậc:

$$\mathrm{rank}(\texttt{A}) = 0,\; \mathrm{rank}(\texttt{W}) = 1,\; \mathrm{rank}(\texttt{E}) = 3$$

(`CONTEXT_READ` = 2, không gây reject.) Sắp xếp primitive theo timestamp; duyệt tuần tự, với mỗi $\pi \in \{\texttt{A}, \texttt{W}, \texttt{E}\}$:

$$\text{nếu } \mathrm{rank}(\pi) < \mathrm{last\_rank} \text{ và } \pi \in \{\texttt{A}, \texttt{W}\} \Rightarrow \text{reject}$$ (2.17)

Fix D3: từ chối WRITE sau EXECUTE (`test_rejects_write_after_execute_temporal_order`) vì write-sau-execute thường là cập nhật cấu hình hậu injection. Cho phép allocate sau write (re-protect). Gap rank W–E = 2 để chừa khe cho `CONTEXT_READ`.

---

## 2.21. Pipeline file provenance (chống E3)

### 2.21.1. Động cơ né tránh E3

Malware né attribution bằng cách inject vào tiến trình hợp pháp (`msedge.exe`, `explorer.exe`, `svchost.exe`). Detector chỉ nhìn victim sẽ **mất dấu loader gốc** — đặc biệt khi loader tự xoá sau spawn. Paper [7] không xây pipeline file→process cho lab endpoint; lớp provenance là đóng góp của luận văn.

### 2.21.2. Luồng provenance

```
Sysmon E11/E15 (FileCreate)  ──┐
FileDropWatcher (poll)       ──┼→  FileEvent  →  FileTriage
                               │       ↓
Sysmon E1 (ProcessCreate)  ────┘  add_process: created_from_file = image path
                                         ↓
                              add_primitive → Finding.related_file
```

`_related_file_for_process` liên kết theo ưu tiên: (1) `created_from_file` — khớp chính xác image path và file drop; (2) image khớp `files_by_path` (E11 đến sau ProcessCreate); (3) image của parent — fallback. Thứ tự phản ánh độ tin cậy giảm dần.

### 2.21.3. Static triage

Module `triage.py` tính thuộc tính tĩnh: SHA256, entropy Shannon (1 MB đầu — gần 8 gợi ý packed); PE header qua `pefile`, Authenticode qua `signtool`; import injection API đáng ngờ; heuristic thư mục (`%TEMP%`, `%APPDATA%\Local\Temp`, `C:\Windows\Tasks`).

Metadata làm giàu scoring (§4.10) và hỗ trợ analyst truy ngược file drop tới loader dù victim hợp pháp. Triage *lazy*, không quét đệ quy toàn ổ đĩa.

---

## 2.22. Telemetry kép (chống E4)

### 2.22.1. Động cơ né tránh E4

**Direct syscall** (stub `syscall` tự xây thay vì `Nt*` export) và **unhook ntdll** (đọc bản gốc từ đĩa, ghi đè bản hook) né Frida user-mode. Sysmon driver đăng ký kernel callback (`PsSetCreateThreadNotifyRoutine`, `ObRegisterCallbacks`) — Event ID 8/10/11/1 — không phụ thuộc export hook, vẫn hoạt động dưới direct syscall.

### 2.22.2. Ma trận bổ sung

| Tình huống E4 | Frida | Sysmon | Kết quả mong đợi |
|---------------|-------|--------|------------------|
| Win32/NT qua export | Có primitive + address | E8/E10 (context) | Finding đầy đủ |
| Syscall thuần, unhook | Miss primitive | E8/E10 vẫn log | Cảnh báo một phần; **thiếu congruence** |
| File drop + spawn | Miss nếu attach trễ | E11 + E1 | Provenance vẫn có |

Sự kiện Sysmon E10 cung cấp thông tin truy cập tiến trình và quyền trên handle nhưng không có cặp `address`/`size` để đối chiếu vùng nhớ. Kết hợp nguồn này với Frida có thể bổ sung ngữ cảnh cho cảnh báo; luận văn chưa có phép đo để khẳng định tỷ lệ âm tính giả giảm dưới E4. Khi chỉ còn sự kiện Sysmon, mức chắc chắn của kết luận phải được hạ tương ứng với bằng chứng còn lại.

### 2.22.3. Chế độ spawn

`noirlycan-agent spawn` khởi chạy mẫu **dưới Frida từ đầu** (spawn-then-attach), giảm miss primitive đầu (liên quan E6: malware kiểm tra hook khi khởi động và self-terminate, attach-after-spawn bỏ lỡ). Đây là methodology bảo đảm fidelity, không thay anti-evasion E5.

---

## 2.23. Phân loại kỹ thuật injection

Sau khi có Finding, `technique_classifier.py` áp dụng **rule-based classifier** (36 enum), căn cứ taxonomy §4 của [7] và mở rộng iRed.team:

| Rule (rút gọn) | Kỹ thuật | ATT&CK |
|----------------|----------|--------|
| W section + E resume + CREATE_SUSPENDED | `process_hollowing_section` | T1055.012 |
| CRT + thread_parameter trong write buffer | `dll_injection` | T1055.001 |
| APC + suspended child | `early_bird_apc_injection` | T1055.004 |
| Local A+W RWX, không transfer | `shellcode_injection` / staging | T1055.002 |
| TXF + section | `process_doppelganging` | T1055.013 |
| NtSetInformationFile + section | `process_ghosting` | T1055.012 |

`apply_classification` gọi sau scoring; confidence `high` khi đủ 3 primitive + `execution_confirmed`. Ghosting/Herpaderping phụ thuộc precursor (xoá image sau `NtCreateSection`, rewrite sau map); thiếu precursor, classifier rơi về nhãn tổng quát.

**E5:** classifier không chạy nếu malware không inject do phát hiện VM — out-of-scope; recall trên lab có thể thấp hơn [7] với họ malware có anti-VM mạnh.

---

## 2.24. Mô hình scoring

Điểm 0–100 (`Correlator._score`) **không** thay quy tắc 2-of-3 mà **xếp hạng** finding và lọc `minimum_score` (mặc định 50). Tách *gating logic* khỏi *ranking logic* cho phép tinh chỉnh ngưỡng mà không phá định nghĩa khoa học.

| Thành phần | Điểm | Điều kiện |
|------------|------|-----------|
| W + E + execution confirmed | +45 | Chuỗi mạnh nhất |
| ≥ 2 operational kinds | +35 | Thay thế khi chưa confirm execute |
| A + W + E + confirmed | +20 | Bonus đủ ba bước |
| Cross-process | +15 | `target_pid ≠ actor_pid` |
| Section mapping API | +10 | `NtMapViewOfSection`, … |
| Executable protection | +10 | PAGE_EXECUTE* trong details |
| CREATE_SUSPENDED | +15 | ProcessEvent flags |
| Related file | +10 | Provenance E3 |
| PE / unsigned / entropy ≥ 7 | +5 / +10 / +5 | Static triage |

Severity: CRITICAL ≥ 85, HIGH ≥ 70, MEDIUM ≥ 50. Score ≥ 70 kích hoạt **network watch** 300s trên `target_pid` (Sysmon E3).

Heuristic giảm FP: `_resume_only_spawn_to_trusted_target` cap score ≤ 50 khi chỉ có ResumeThread vào Program Files mà không kèm write/context — pattern installer hợp pháp.

---

## 2.25. Thuật toán (pseudo-code)

### Thuật toán 4.1 — Ánh xạ API → primitive

```
function MAP_API(api):
    for class in PAPER_API_CLASSES ∪ IRED_TEAM_API_CLASSES:
        if api in class.apis:
            return OBSERVATION_ONLY if class.primitive=="observation" else class.primitive
    return UNKNOWN

function ON_API_CALL(api, args, retval):
    if not success(retval): return
    kind ← MAP_API(api)
    if kind == OBSERVATION_ONLY: emit api_observation(...); return
    range ← extract_memory_range(api, args, retval)
    emit memory_primitive(kind, actor_pid, target_pid, range, api, details)
```

### Thuật toán 4.2 — Correlator: đánh giá chuỗi

```
function ADD_PRIMITIVE(p):
    enrich p with actor_image, target_image
    bucket[(p.actor_pid, p.target_pid)].append(p)
    expire events older than WINDOW
    return EVALUATE_CHAIN(p.actor_pid, p.target_pid)

function EVALUATE_CHAIN(actor, target):
    P ← bucket[(actor, target)]; K ← {p.kind | p∈P} \ {CONTEXT_READ}
    if |K ∩ {A,W,E}| < 2 or not TEMPORAL_OK(P) or not CONGRUENCE_OK(P): return []
    score, evidence ← SCORE(P, related_process, related_file)
    if score < minimum_score or score ≤ previous_reported_score: return []
    finding ← Finding(..., apply_classification(...))
    if score ≥ 70: enable_network_watch(target)
    return [finding]
```

### Thuật toán 4.3 — Congruence

```
function CONGRUENCE_OK(P):
    ranges_by_kind ← group memory_link_ranges(p) for p in P
    if count_linked_primitives < 2: return TRUE
    for (kind1,kind2) with kind1≠kind2, r1∈ranges[kind1], r2∈ranges[kind2]:
        if overlap(r1, r2): return TRUE
    if |operational_kinds| ≥ 2 and only WRITE has ranges: return TRUE
    return FALSE
```

### Thuật toán 4.4 — File provenance

```
function ADD_PROCESS(proc):
    if normalize(proc.image) in files_by_path: proc.created_from_file ← path
    processes_by_pid[proc.pid] ← proc

function RELATED_FILE(proc):
    if proc.created_from_file: return files[proc.created_from_file]
    if proc.image in files: return files[proc.image]
    if parent exists: return files[parent.image]
    return NULL
```

---

## 2.26. Ranh giới phương pháp so với [7]

| Khía cạnh | [7] | Luận văn (Noirlycan) |
|-----------|-----|----------------------|
| 2-of-3 + congruence + temporal | ✅ | ✅ (có test) |
| Equivalence class | Table 1 đầy đủ | `PAPER_API_CLASSES` + lab extension |
| Anti-evasion E5 | ✅ Tích hợp | ❌ **Không hiện thực** — chỉ ghi `extensions/evasion.py` signal |
| Dataset 56k + prevalence | ✅ | ❌ Ngoài phạm vi |
| File provenance E3 | ❌ | ✅ Đóng góp |
| Real-time endpoint | ❌ | ✅ Đóng góp |
| Recursive chain metric ~2% | ✅ | ⚠️ `InjectionGraph` một phần |

Luận văn không claim số 16,5 % hay 21,2 % của [7]; các con số đó đo trên corpus 56k mẫu với BluePill có anti-evasion, điều kiện luận văn không tái tạo. Mọi cải tiến trên lab phải được hiểu trong phạm vi E1–E4.

---

## 2.27. Ví dụ đi sâu: phân tích chuỗi section-mapping

Xét chuỗi cross-process vào `msedge.exe` (case study *neurevt* [7], test `test_detects_section_mapping_write_execute_chain`):

**B1 — Provenance:** Sysmon E11 ghi `loader.exe` trong `%TEMP%`. Triage: PE=True, signed=False, entropy=7,2. Khi loader spawn (E1, `CREATE_SUSPENDED`), `add_process` gắn `created_from_file`.

**B2 — W:** Hook bắt `NtMapViewOfSection` với `target_pid`=Edge, `address`=0x200000, `protection`=EXECUTE_READWRITE. Map remote vừa write vừa expose vùng executable — không cần `VirtualAllocEx` riêng.

**B3 — Gating:** $K=\{\texttt{W},\texttt{E}\}$, $|K|=2$ thỏa (4.1); ResumeThread sau MapView thỏa temporal; congruence chấp nhận khi đủ operational kinds.

**B4 — Scoring:** +45 (W+E confirmed) +15 (cross-process) +10 (section) +15 (SUSPENDED) +10 (related_file) +10 (unsigned) ≥ 70 (HIGH).

**B5 — Classifier:** W+E resume → `section_mapping_injection` (hoặc hollowing nếu thêm context).

Baseline `VirtualAllocEx→WriteProcessMemory→CreateRemoteThread` không match — minh chứng giá trị phương pháp [7] dưới E2.

## 2.28. Ví dụ đi sâu: classic DLL injection (E1)

Malware E1 thay `CreateRemoteThread` bằng `NtCreateThreadEx`:

1. `VirtualAllocEx` → A, range $r_a$
2. `WriteProcessMemory` ghi đường dẫn DLL → W, $r_w$ overlap $r_a$
3. `NtCreateThreadEx` với `StartRoutine = LoadLibraryW`, `Argument = r_a` → E, `thread_parameter` overlap $r_w$

Equivalence class map cả ba vào $\{\texttt{A},\texttt{W},\texttt{E}\}$ dù tên khác Win32. Congruence qua $r_a \cap r_w$ và $r_w \cap \text{thread\_parameter}$. Pattern `_dll_path_remote_thread_pattern` tăng +5 score; classifier kết luận `dll_injection` (T1055.001).

## 2.29. Self-injection và local staging

Paper [7] tập trung cross-process; Noirlycan mở rộng `actor_pid == target_pid` (self-injection, dùng để decode payload trước khi inject ra ngoài): `VirtualAlloc` + `memcpy` local RWX → A+W, evidence `local_staging`. Config `.classifier_rules.json` có thể bật `ignore_same_process_findings` để giảm FP từ installer/JIT. Phương pháp vẫn áp 2-of-3 nguyên vẹn; scoring ưu tiên cross-process (+15).

## 2.30. CONTEXT_READ — extension lab

`GetThreadContext`/`NtGetContextThread` hook với kind `CONTEXT_READ` để hỗ trợ classifier, không làm primitive thứ tư: không đếm vào $|K|$; +5 score khi hijack prep chưa confirmed; classifier dùng `context_read + SET_SUSPENDED` để nhãn `thread_hijack` hoặc `process_hollowing_classic`. Khai báo rõ để tránh hiểu nhầm là primitive thứ tư của [7] (deviation D7).

## 2.31. Chiến lược giảm false positive

| Heuristic | Mục đích |
|-----------|----------|
| `minimum_score` ≥ 50 | Lọc chuỗi yếu |
| `_resume_only_spawn_to_trusted_target` | Cap 50 — installer resume Edge/Program Files |
| `missing_execution_transfer` cap 75 | Staging chưa execute |
| `require_cross_process_findings` (config) | Lab chỉ báo inject cross-process |
| Network watch chỉ khi score ≥ 70 | Tránh alert noise |

Đây là **lab tuning**, không thay định nghĩa 2-of-3 [7]: chỉ điều chỉnh mức trình bày, không thêm/bớt điều kiện logic cốt lõi.

## 2.32. Liên hệ MITRE ATT&CK

Technique classifier ánh xạ finding sang sub-technique T1055 để tích hợp threat-informed defense:

| Pattern primitive + evidence | ATT&CK (ví dụ) |
|------------------------------|----------------|
| CRT + LoadLibrary remote | T1055.001 DLL injection |
| APC + suspended | T1055.004 Asynchronous Procedure Call |
| Section + resume | T1055.012 Process Hollowing |
| SetWindowsHookEx | T1055.004 Hook injection |
| TxF + section | T1055.013 Process Doppelgänging |

Phân loại tách biệt với 2-of-3; lỗi nhãn không làm mất finding.

## 2.33. So sánh pipeline [7] và Noirlycan

**Bảng 2.3.** Pipeline phân tích — paper vs luận văn

| Giai đoạn | [7] Sap4Sec | Noirlycan |
|-----------|-------------|-----------|
| Môi trường thực thi | Batch DBI (BluePill/Pin) | Windows 10/11 VM lab |
| Thu thập trace | API logger toàn process tree | Frida hook + Sysmon events |
| Anti-evasion E5 | Có — patch env/timing | **Không** |
| Phân tích | Offline analyzer Python | Online Correlator 300s window |
| Đầu ra | Label + technique + log | Finding JSONL + dashboard |
| Provenance file | Không | FileCreate + triage + lineage |
| Quy mô đánh giá | 56.340 mẫu | 59 test methodology + replay 20 session lab |

Noirlycan **operationalize** phương pháp [7] cho analyst endpoint và bổ sung E3/E4; không thay thế nghiên cứu thống kê của paper.

## 2.34. Giả định phương pháp (M1–M5)

| ID | Giả định | Ảnh hưởng |
|----|----------|-----------|
| M1 | API qua export hookable hoặc Sysmon-visible | E4 partial |
| M2 | Injection trong cửa sổ 300s | Expiration |
| M3 | User-mode injection | Không kernel primitive |
| M4 | Lab cô lập | E5 không cần fake production |
| M5 | Frida fidelity chấp nhận | RQ5 — cần đo |

Vi phạm M1 (syscall thuần + unhook ntdll + tránh API có Sysmon callback) → 2-of-3 không khả dụng. Vi phạm M2 (*time bomb* > 300s) → correlator hết hạn primitive đầu.

## 2.35. Mở rộng tương lai phương pháp

Ba hướng ngoài phạm vi luận văn:

1. **ETW Threat Intelligence provider** — thay/đi cùng Frida, giảm E4/E6 vì ETW-TI cung cấp sự kiện kernel cho `VirtualAllocEx`, `WriteProcessMemory`, `SetThreadContext`; ánh xạ về cùng equivalence class [7].
2. **ML trên chuỗi primitive** — embedding API sequence thay rule classifier; yêu cầu dataset lớn và đánh giá robustness.
3. **Anti-evasion E5 port** — tích hợp module patch timing/CPUID/registry từ Sap4Sec [14] để so sánh recall trên Paper-Subset.

## 2.36. Giám sát mạng hậu injection

Sau khi finding đạt score ≥ 70, phương pháp kích hoạt **network watch** trên `target_pid` 300s. Sysmon E3 lọc theo PID, chỉ lưu connection từ PID victim. Mục tiêu: bắt beacon sau khi payload chạy trong tiến trình hợp pháp.

Heuristic `is_external_beacon_candidate` đánh dấu IP/hostname ngoài RFC1918; kết nối nội bộ giữ lại cho phân tích lateral movement nhưng không nâng severity. Module `network.py` và test `test_network_watch.py` xác nhận chỉ connection trong cửa sổ watch mới correlate với finding.

## 2.37. Tóm tắt chương

Chương 2 trình bày phương pháp phát hiện process injection: kế thừa operational primitive và 2-of-3 của [7] chống E1, E2; bổ sung memory congruence và temporal ordering dưới dạng phát biểu hình thức và pseudo-code; mở rộng pipeline provenance file (E3) để truy ngược loader từ victim hợp pháp; telemetry kép Sysmon–Frida (E4) duy trì khả năng phát hiện khi user-mode hook bị né. Module anti-sandbox (E5) **không hiện thực** — hạn chế thảo luận ở Chương 6 và 7. Chương 5 mô tả hiện thực các module trong artifact Noirlycan.