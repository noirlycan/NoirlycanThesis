# CHƯƠNG 3. THREAT MODEL THEO HÌNH THỨC NÉ TRÁNH

Chương này xây dựng **mô hình đe dọa formal** cho Noirlycan: tài sản, đối thủ, giả định môi trường/phương pháp, ranh giới tin cậy telemetry, mối đe dọa, **ranh giới claim khoa học**. Căn cứ audit đối chiếu Noirlycan với Di Pietro et al. (ASIA CCS 2025) [7], `docs/audit-and-threat-model.md`, taxonomy E1–E6.

## 3.1. Phạm vi và hệ thống quan tâm

### 3.1.1. System Under Analysis (SUA)

SUA là **một host Windows 10/11** trong lab cô lập. Phạm vi: *phát hiện hành vi inject ở endpoint*; SIEM, multi-tenant ngoài đề tài.

**Bảng 3.1.** Thành phần hệ thống Noirlycan

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

### 3.1.2. Ranh giới hệ thống

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

## 3.2. Phân loại hình thức né tránh (E1–E6)

Ký hiệu **E1–E6** cho sáu nhóm né tránh process injection (thống nhất Bảng 1.1).

**Bảng 3.2.** Taxonomy né tránh và phản ứng hệ thống

| ID | Hình thức né tránh | Mô tả | Mitigation Noirlycan | Trạng thái |
|----|-------------------|-------|----------------------|------------|
| **E1** | Biến thể API | Win32 ↔ NT API, đổi thread/APC | Equivalence + 2-of-3 [7] | **Xử lý** (có test) |
| **E2** | Gộp/ẩn bước | Section mapping, Mockingjay (RWX) | 2-of-3 + classifier section-mapping | **Xử lý** (có test) |
| **E3** | Né attribution | Inject tiến trình hợp pháp; file-drop loader | Sysmon lineage + provenance + triage | **Mở rộng** |
| **E4** | Né hook user-mode | Direct syscall, unhook `ntdll` | Sysmon E8/E10 fallback | **Một phần** |
| **E5** | Né sandbox/VM | Timing, env fingerprint — không inject | Không có module anti-evasion | **Out-of-scope** |
| **E6** | Né instrumentation | Anti-Frida, anti-debug | `spawn` mode; documented | **Hạn chế** |

E1 phản ánh không gian API rộng cho cùng primitive *WRITE-cross-process*. E2: section mapping gộp allocate+write. E3 tấn công *attribution*. E4 là *visibility floor* user-mode. E5/E6 là né tránh *meta*. **Lưu ý:** ký hiệu E1–E6 ở mục 3.5 là **giả định môi trường**, khác ngữ cảnh.

## 3.3. Tài sản cần bảo vệ (Assets)

**Bảng 3.3.** Tài sản và mục tiêu bảo vệ

| ID | Tài sản | Định nghĩa | Liên quan né tránh |
|----|---------|------------|-------------------|
| **A1** | Toàn vẹn phát hiện | Finding phản ánh đúng hành vi inject thực tế | E1, E2, E4 |
| **A2** | Sẵn sàng collector | Collector/Frida không crash; log đủ event | E6 |
| **A3** | Cô lập lab | Malware không lan ra production | An toàn nghiên cứu |

A1 là tài sản **trung tâm**; không yêu cầu phát hiện khi malware không inject (E5) — đồng bộ [7] (evasion làm giảm injection quan sát được: 11,8 % → 6,2 % khi bỏ anti-evasion). Ưu tiên *integrity* hơn *coverage*.

## 3.4. Mô hình đối thủ (Adversary Model)

### 3.4.1. Loại đối thủ

**Đối thủ:** tác giả malware Windows **user-mode** (Tier 2 Microsoft SDL) — botnet loader, trojan banker, RAT, red-team implant.

**Mục tiêu đối thủ:** (1) inject thành công; (2) tránh telemetry lab; (3) persistence/beacon (tùy mẫu, ngoài phạm vi).

**Không phải đối thủ:** insider admin tắt Sysmon; APT kernel rootkit (O3); analyst giả mạo log. OS bị khống chế ngoài threat model — kế thừa [7][10][15].

### 3.4.2. Năng lực giả định CÓ (C1–C7)

**Bảng 3.4.** Năng lực đối thủ trong phạm vi

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

### 3.4.3. Năng lực NGOÀI phạm vi (O1–O7)

**Bảng 3.5.** Out-of-scope capabilities

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

## 3.5. Giả định môi trường (Environmental Assumptions)

Ký hiệu **E1–E6** environmental — khác né tránh E1–E6 (mục 3.2).

**Bảng 3.6.** Giả định môi trường vận hành

| ID | Giả định | Mô tả | Vi phạm → hậu quả | Liên quan né tránh |
|----|----------|-------|-------------------|-------------------|
| **E1** | Sysmon config `sysmon-noirlycan.xml` | Event 1,3,7,8,10,11 enabled | Mất lineage/provenance | E4, E3 |
| **E2** | Frida attach **trước** API inject đầu | Ưu tiên `spawn` | Late attach → FN (T2) | E6 |
| **E3** | Không pure direct syscall mọi API | Ít nhất một call qua export hook | Pure syscall → Frida trống | E4 |
| **E4** | Clock monotonic trong window 300s | `detection/correlator.py` | VM rollback → temporal sai | — |
| **E5** | Không collision `(actor_pid, target_pid)` benign | Lab ít noise | Gom nhầm chain → FP (T8) | — |
| **E6** | VM cô lập, không credential thật | Ethics lab | Rủi ro ngoài phạm vi khoa học | E5 |

E3 thực dụng: malware in-the-wild đến 2023 dùng hỗn hợp direct syscall + API thường. Pure syscall everywhere thuộc O1.

## 3.6. Giả định phương pháp (Methodological Assumptions M1–M6)

**Bảng 3.7.** Giả định khoa học — căn cứ phương pháp [7]

| ID | Giả định | Nguồn / justification | Rủi ro nếu sai |
|----|----------|----------------------|----------------|
| **M1** | A/W/E trên cùng vùng nhớ **đủ mô tả** injection user-mode | Klein và Kotler [10]; [7] §3.1 | FN kỹ thuật kernel (O3) |
| **M2** | ≥ 2/3 primitive khác loại **đủ kết luận** injection | [7] §3.2 | FP từ benign debug tool |
| **M3** | API cùng equivalence class thay thế được | [7] Table 1 | FN khi API chưa liệt kê |
| **M4** | Memory overlap là proxy cho *same buffer* | Starink [15]; [7] §3.3 | FP/FN edge case |
| **M5** | Frida hook **trung thực** về argument/thứ tự | Frida [8]; cần benchmark | Drop event → sai 2-of-3 |
| **M6** | Sysmon kernel callbacks không bị user-mode sửa | Driver ring 0; chỉ O3 phá | Mất lớp kernel nếu O3 |

M1–M3 là cơ sở 2-of-3; M4 là *bridging assumption* (overlap address+size). **M5 cần justification:** Chương 6 đề xuất protocol Frida fidelity (ETW/SilkETW ≥ 1000 lệnh gọi synthetic); claim Frida gắn *conditional on M5*. **D1 đã sửa:** EXECUTE thiếu `address` được phục hồi bằng `lpStartAddress`/`Rip` từ CONTEXT.

## 3.7. Ma trận né tránh ↔ mitigation (tổng hợp)

**Bảng 3.8.** Ma trận đối thủ – hình thức né tránh – mitigation – hạn chế

| Né tránh | Năng lực C | Out-of-scope O | Module Noirlycan | Mức độ mitigation | Hạn chế còn lại |
|----------|-----------|----------------|------------------|-------------------|-----------------|
| E1 | C1,C2,C4 | — | `detection/api_classes.py`, `detection/correlator.py` | Cao | API mới chưa trong manifest |
| E2 | C2,C3 | — | 2-of-3, `technique_classifier.py` | Cao | Mockingjay edge (RWX) |
| E3 | C3,C6 | — | Sysmon E1/E11, `file_watch.py`, triage | TB-cao | Inject không qua file-drop |
| E4 | (via O1/O2) | O1,O2 | Sysmon E8/E10 | TB | Mất address/size |
| E5 | C7 phần | **O7** | `evasion.py` ghi signal | **Không** | Recall < paper |
| E6 | C7 | O5 | `spawn`, docs | Thấp | Không stealth Frida |

## 3.8. Ma trận tin cậy lớp telemetry (Telemetry Layer Trust Matrix)

Trả lời phản biện *"Frida bị bypass — phương pháp còn ý nghĩa gì?"*: **graceful degradation** — khi hook user-mode bị né, Sysmon (kernel callback) vẫn cung cấp primitive EXECUTE từ EID 8 và bằng chứng handle + call stack từ EID 10; detection giảm về số primitive quan sát được nhưng không về zero, và việc kernel thấy remote thread mà Frida không thấy được gắn cờ *hook bypass*. Đây là đóng góp định tính so với [7], vốn dùng một lớp instrumentation (BluePill/Pin).

**Bảng 3.9.** Telemetry Layer Trust Matrix

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

## 3.9. Mối đe dọa và mitigations (T1–T9)

**Bảng 3.10.** Threat catalog

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

## 3.10. Trust boundary và luồng dữ liệu

**Bảng 3.11.** Ranh giới tin cậy theo thành phần

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

## 3.11. Ranh giới claim khoa học (Scientific Claims Boundaries)

Phân tách claim có evidence và claim **cấm** nếu chưa có Chương 6.

### 3.11.1. Claim ĐƯỢC PHÉP bảo vệ (có căn cứ audit)

| ID | Claim | Evidence |
|----|-------|----------|
| **C-IMPL** | Lõi 2-of-3 + congruence + temporal của [7] đã hiện thực trên Frida+Sysmon Windows 10/11 | `detection/correlator.py`, `detection/api_classes.py`, `test_correlation.py` |
| **C-AUDIT** | Ba deviation D1/D2/D3 đã phát hiện và sửa có test regression | `docs/audit-and-threat-model.md` |
| **C-EXT** | Pipeline file provenance → lineage → finding cung cấp ngữ cảnh [7] không có | `file_watch.py`, `detection/correlator.py` |
| **C-CASE** | Section-mapping (*neurevt*) phát hiện đúng pattern primitive trên PoC | `test_detects_section_mapping_write_execute_chain` |
| **C-ARCH** | Sysmon ∪ Frida document graceful degradation dưới E4 | Bảng 3.9, mục 3.8 |
| **C-TAX** | Taxonomy mở rộng (36 kỹ thuật enum) | `technique_classifier.py` — không kèm precision số |

### 3.11.2. Claim KHÔNG ĐƯỢC PHÉP (cấm nếu chưa bổ sung evaluation)

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

### 3.11.3. Claim có điều kiện (conditional)

| Claim | Điều kiện |
|-------|-----------|
| "Tăng cường phát hiện dưới E1/E2" | Malware **đã thực hiện** inject; trong manifest API |
| "Giảm FN dưới E4" | Sysmon E1 env assumption; không O3 |
| "Tăng cường truy vết E3" | Có file-drop + Event 11; static triage readable |

## 3.12. Mapping threat model ↔ mục tiêu nghiên cứu (RO1–RO5)

**Bảng 3.12.** Liên kết RO và threat model

| Mục tiêu (Chương Mở đầu) | Threat model |
|--------------------------|--------------|
| RO1 — Hiện thực [7] | M1–M4; C-IMPL; T3/T6/T7 fixes |
| RO2 — Telemetry kép E4 | Bảng 3.9; T1; O1/O2 degradation |
| RO3 — Provenance E3 | Sysmon E11/E1; C-EXT |
| RO4 — Đánh giá biến thể | C-CASE; E1/E2; **không** claim prevalence |
| RO5 — Tài liệu hóa threat model | Toàn chương 3; scientific claims §3.11 |

Mapping bảo đảm truy nguyên hai chiều giữa RO và threat model.

## 3.13. Hạn chế threat model và tính hợp lệ ngoại vi (*validity*)

### 3.13.1. Internal validity

- Ground truth PoC do tác giả gắn nhãn — bias có thể có.
- Số mẫu nhỏ so với [7] — không generalize prevalence.
- Frida overhead có thể thay đổi timing — ảnh hưởng race condition hiếm (không đo đầy đủ).

Bias kiềm chế bằng công khai mã PoC và config Sysmon để tái lập.

### 3.13.2. External validity

- Chỉ Windows 10/11 client — không Windows Server, không Linux.
- Lab VM ≠ enterprise endpoint có EDR đa agent.
- Mẫu 2017–2023 trong [7] — kỹ thuật 2024+ (một số) chỉ có rule chưa evaluate.

Windows 10/11 client là *deliberate scoping*: server và Linux (ptrace, LD_PRELOAD) ngoài T1055 Windows.

### 3.13.3. Construct validity

- Primitive abstraction M1 có thể không map một số kỹ thuật mới (PoolParty phức tạp) — classifier bổ sung, không thay 2-of-3.
- Score finding (≥ 50/70) là heuristic lab, chưa calibrate trên corpus.

PoolParty và biến thể 2024 làm primitive A/W/E có thể không phân giải đủ mịn. Chương 7 mở rộng.

## 3.14. Tóm tắt chương

Chương 3 đã xây dựng threat model formal: telemetry kép Sysmon + Frida; A1–A3; C1–C7; O1–O7; E1–E6 và M1–M6; ma trận tin cậy giải thích graceful degradation dưới E4; T1–T9; ranh giới claim phân tách replication [7], extension, claim cấm. Threat model làm khung cho Chương 5 và 6 — thí nghiệm phải map C-IMPL/C-EXT/C-CASE, không vượt §3.11.
