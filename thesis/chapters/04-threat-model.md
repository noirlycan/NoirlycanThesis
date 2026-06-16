# CHƯƠNG 3. THREAT MODEL THEO HÌNH THỨC NÉ TRÁNH

Chương này xây dựng **mô hình đe dọa formal** (*formal threat model*) cho hệ thống Noirlycan và phạm vi luận văn *Tăng cường phát hiện mã độc dưới các hình thức né tránh*. Mục tiêu là định nghĩa rõ: (a) tài sản cần bảo vệ, (b) đối thủ và năng lực né tránh, (c) giả định môi trường và phương pháp, (d) ranh giới tin cậy giữa các lớp telemetry, (e) mối đe dọa còn lại và mitigations, (f) **ranh giới claim khoa học** — những gì luận văn được phép và không được phép tuyên bố trước hội đồng.

Threat model căn cứ audit đối chiếu implementation Noirlycan với Di Pietro et al. (ASIA CCS 2025) [4], tài liệu `docs/audit-and-threat-model.md`, và phân loại né tránh E1–E6 đã giới thiệu ở Chương 1 (Mở đầu) và Chương 2 (Công trình liên quan).

## 3.1. Phạm vi và hệ thống quan tâm

### 3.1.1. System Under Analysis (SUA)

Hệ thống quan tâm là **một host Windows 10 hoặc 11** trong phòng lab cô lập (máy ảo hoặc bare-metal không kết nối mạng production), cài đặt các thành phần sau:

**Bảng 3.1.** Thành phần hệ thống Noirlycan

| Thành phần | Privilege | Cơ chế quan sát | Module repo |
|------------|-----------|-----------------|-------------|
| Sysmon driver (`SysmonDrv.sys`) | **Kernel (ring 0)** | `PsSetCreateProcessNotifyRoutineEx`, `PsSetLoadImageNotifyRoutine`, `ObRegisterCallbacks`, Minifilter `FltRegisterFilter`, ETW Threat Intelligence | `sysmon.py` |
| Sysmon service (`Sysmon.exe`) | User (LocalSystem) | Thu thập event từ driver, ghi Windows Event Log | `services/collector/infrastructure/sysmon.py` |
| Frida agent | **User (trong target process)** | `Interceptor.attach` trên export `ntdll.dll` / `kernel32.dll` / `user32.dll` | `services/collector/infrastructure/frida_manager.py`, `frida_hooks/windows_injection_hooks.js` |
| Python collector | User | Đọc Event Log + Frida message bus, correlate | `services/collector/application/collector_runtime.py`, `services/analysis/domain/correlation.py` |
| Static triage | User | SHA256, PE header, entropy, Authenticode trên file mới | `services/collector/infrastructure/triage.py`, `kernel/analysis/payload.py` |
| Dashboard analyst | User (host hoặc remote lab) | Django REST + WebSocket UI, JSONL export | `services/dashboard/` |
| Target process | User | Loader malware / PoC injection | Mẫu thí nghiệm |

**Hệ quả thiết kế quan trọng:** Hai lớp telemetry Frida (user-mode) và Sysmon (kernel-mode) có **khả năng chống bypass khác nhau**. Frida mất signal khi đối thủ direct syscall (E4); Sysmon kernel callback vẫn ghi cross-process artifact (Event 8 CreateRemoteThread, Event 10 ProcessAccess). Luận văn coi đây là *defense-in-depth* có chủ đích, không phải redundancy ngẫu nhiên — chi tiết mục 3.8.

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

\* Sysmon driver tin cậy **nếu** giả định O3 không xảy ra (không có kernel rootkit tắt driver).

Phạm vi threat model **không bao gồm** mạng ngoài lab, SIEM enterprise, hoặc cloud triage — chỉ pipeline từ host bị nhiễm đến analyst.

## 3.2. Phân loại hình thức né tránh (E1–E6)

Luận văn dùng ký hiệu **E1–E6** cho sáu nhóm né tránh liên quan process injection (thống nhất Chương 1, Bảng 1.1). Chương 3 ánh xạ từng nhóm lên năng lực đối thủ, mitigation Noirlycan, và trạng thái xử lý.

**Bảng 3.2.** Taxonomy né tránh và phản ứng hệ thống

| ID | Hình thức né tránh | Mô tả | Mitigation Noirlycan | Trạng thái |
|----|-------------------|-------|----------------------|------------|
| **E1** | Biến thể API | Thay Win32 bằng NT API, đổi cơ chế thread/APC | Equivalence class + 2-of-3 [4] (`kernel/classification/api_manifest.py`, `services/analysis/domain/correlation.py`) | **Được xử lý** (có test) |
| **E2** | Gộp/ẩn bước | Section mapping, Mockingjay (RWX sẵn có), thiếu primitive riêng lẻ | Quy tắc 2-of-3; classifier section-mapping (`kernel/classification/technique_classifier.py`) | **Được xử lý** (có test) |
| **E3** | Né attribution | Inject vào tiến trình hợp pháp; file-drop loader che nguồn | Sysmon lineage (E1) + file provenance (E11) + static triage | **Mở rộng đề tài** |
| **E4** | Né hook user-mode | Direct syscall stub, unhooking `ntdll` | Sysmon kernel E8/E10 fallback; graceful degradation | **Một phần** |
| **E5** | Né sandbox/VM | Timing check, env fingerprint — không chạy injection | Không có module anti-evasion | **Out-of-scope** |
| **E6** | Né instrumentation | Anti-Frida, anti-debug, phát hiện agent | `spawn` mode; khai báo limitation | **Hạn chế** |

**Lưu ý ký hiệu:** E1–E6 ở Bảng 3.2 là **nhóm né tránh của đối thủ malware**. Mục 3.5 dùng ký hiệu **E1–E6** riêng cho **giả định môi trường** (environmental assumptions) — hai hệ ký hiệu trùng tên nhưng ngữ cảnh khác nhau; trong luận văn, khi nói "giả định E-spawn" ám chỉ environmental assumption, khi nói "chống E4" ám chỉ hình thức né tránh.

## 3.3. Tài sản cần bảo vệ (Assets)

**Bảng 3.3.** Tài sản và mục tiêu bảo vệ

| ID | Tài sản | Định nghĩa | Liên quan né tránh |
|----|---------|------------|-------------------|
| **A1** | Tính toàn vẹn phát hiện | Finding injection phản ánh đúng hành vi thực tế trên host khi malware thực hiện inject (không bỏ sót oan vì E1/E2/E4 nếu trong phạm vi claim) | E1, E2, E4 |
| **A2** | Tính sẵn sàng collector | Collector và Frida agent không crash vì mẫu độc; session log ghi đủ event trong window phân tích | E6 (anti-Frida có thể gây abort) |
| **A3** | Tính cô lập lab | Mẫu malware không lan ra mạng production hoặc host ngoài VM | Không phải mục tiêu phát hiện; ranh giới an toàn nghiên cứu |

A1 là tài sản **trung tâm** của luận văn. A1 **không** yêu cầu phát hiện khi malware chủ động không inject (E5) — đó là giới hạn có chủ ý, đồng bộ với paper [4] khi thiếu anti-evasion (21,2 % miss).

## 3.4. Mô hình đối thủ (Adversary Model)

### 3.4.1. Loại đối thủ

**Đối thủ:** Tác giả malware Windows **user-mode** (Tier 2 theo phân loại Microsoft SDL) — botnet loader, trojan banker, RAT staging, hoặc red-team implant trong phạm vi lab.

**Mục tiêu đối thủ:**

1. Thực thi payload trong tiến trình nạn nhân (inject thành công);
2. Tránh bị phát hiện bởi telemetry lab (E1–E6 tùy khả năng);
3. (Tùy mẫu) Duy trì persistence hoặc beacon — ngoài phạm vi đánh giá injection thuần.

**Đối thủ không phải:** Insider có quyền admin tắt Sysmon; APT với kernel rootkit signed-driver (O3); analyst cố ý giả mạo log (ngoài phạm vi).

### 3.4.2. Năng lực giả định CÓ (C1–C7)

**Bảng 3.4.** Năng lực đối thủ trong phạm vi

| ID | Năng lực | Ví dụ | Né tránh liên quan |
|----|----------|-------|-------------------|
| **C1** | Gọi mọi Win32 / NT API user-mode export | `NtWriteVirtualMemory`, `RtlCreateUserThread` | E1 |
| **C2** | Section mapping thay allocate+write tách rời | `NtCreateSection` + `NtMapViewOfSection` | E1, E2 |
| **C3** | Process hollowing classic | `CreateProcess(CREATE_SUSPENDED)` + `SetThreadContext` + `ResumeThread` | E2, E3 |
| **C4** | Load DLL từ disk hoặc reflective/manual map | `LoadLibrary*`, PE mapping thủ công | E1, E3 |
| **C5** | Mã hóa payload trong resource, giải mã runtime | XOR/AES stub trước inject | Che static triage, không che primitive runtime |
| **C6** | Drop file thực thi xuống đĩa rồi spawn | `%TEMP%\*.exe` → ProcessCreate | E3 |
| **C7** | Evasion **thụ động** một mức | `IsDebuggerPresent`, `NtQueryInformationProcess`, sleep ngắn | E6; một phần E5 |

C7 **cố ý không** bao gồm bộ anti-sandbox đầy đủ (VM registry scan, MAC check, process blacklist dài) — đó thuộc E5/O7.

### 3.4.3. Năng lực NGOÀI phạm vi (O1–O7)

**Bảng 3.5.** Out-of-scope capabilities

| ID | Năng lực ngoài phạm vi | Lý do loại trừ | Hệ quả nếu xảy ra |
|----|------------------------|----------------|-------------------|
| **O1** | Direct syscall stub bỏ qua user-mode export hook | Frida miss API-arg; paper cũng giới hạn user tracer | FN một phần Frida; Sysmon E8/E10 vẫn có thể báo (E4 degradation) |
| **O2** | Unhooking / patch `ntdll` trước inject | Cùng phạm vi O1 | Tương tự O1 |
| **O3** | **Kernel-mode adversary** — rootkit, BYOVD, abuse signed driver tắt Sysmon | Paper và repo đều user-space focus; cần Secure Boot + HVCI + driver policy | Toàn bộ telemetry kernel mù |
| **O4** | Side-channel / TOCTOU tấn công collector Python | Không phải malware Windows injection study | Collector integrity fail — ngoài đề tài |
| **O5** | Anti-Frida **chủ động** (scan `frida-agent`, gum, port) | Lab prototype; không harden agent | Malware abort → miss behavior (E6) |
| **O6** | Process Ghosting / Herpaderping **phiên bản mới** chưa có rule | Taxonomy mở rộng dần; một số biến thể đã có rule precursor | FN trên kỹ thuật chưa cover |
| **O7** | Sandbox-aware evasion **chủ động** (E5 đầy đủ) | Paper có anti-evasion module; luận văn không hiện thực | Malware không inject → không có finding; recall thấp hơn paper |

O1/O2 **không** đồng nghĩa detection = 0: ma trận tin cậy (mục 3.8) mô tả fallback kernel. O3 là ranh giới cứng — cả [4] lẫn Noirlycan đều không claim chống kernel adversary.

## 3.5. Giả định môi trường (Environmental Assumptions)

Ký hiệu **E1–E6** (environmental) — không nhầm với nhóm né tránh E1–E6 (mục 3.2).

**Bảng 3.6.** Giả định môi trường vận hành

| ID | Giả định | Mô tả | Vi phạm → hậu quả | Liên quan né tránh |
|----|----------|-------|-------------------|-------------------|
| **E1** | Sysmon chạy với config `sysmon-noirlycan.xml` | Event 1, 3, 7, 8, 10, 11 enabled | Mất lineage, fallback E4, provenance E3 | E4, E3 |
| **E2** | Frida attach **trước** API injection đầu tiên | Ưu tiên `spawn` mode | Late attach → miss primitive đầu → FN (T2) | E6 |
| **E3** | Target không dùng **pure** direct syscall cho mọi API inject | Ít nhất một call đi qua export hooked | Pure syscall → Frida trống; chỉ còn Sysmon coarse signal | E4 |
| **E4** | Đồng hồ host monotonic trong correlation window (300 s) | `services/analysis/domain/correlation.py` window | VM snapshot/restore → temporal sai | — |
| **E5** | Không có process benign khác gây collision `(actor_pid, target_pid)` | Lab ít noise | Gom nhầm chain → FP (T8) | — |
| **E6** | VM cô lập, không credential/dữ liệu thật | Ethics lab | Rủi ro vận hành ngoài phạm vi khoa học | E5 (môi trường lab ≠ production) |

E3 là giả định **thực dụng** cho phạm vi luận văn: nhiều mẫu malware vẫn gọi qua `ntdll` export; pure syscall everywhere thuộc O1 và được xử lý như degradation, không như failure hoàn toàn.

## 3.6. Giả định phương pháp (Methodological Assumptions M1–M6)

**Bảng 3.7.** Giả định khoa học — căn cứ phương pháp [4]

| ID | Giả định | Nguồn / justification | Rủi ro nếu sai |
|----|----------|----------------------|----------------|
| **M1** | Ba primitive allocate/write/execute trên cùng vùng nhớ **đủ mô tả** injection user-mode | Klein [7]; [4] §3.1 | FN trên kỹ thuật kernel (O3) hoặc kỹ thuật không map được primitive |
| **M2** | Quan sát ≥ 2/3 primitive khác loại **đủ kết luận** injection với precision chấp nhận được | [4] §3.2; prevalence study | FP từ benign debug tool gọi cross-process API |
| **M3** | API trong cùng equivalence class có ngữ nghĩa thay thế được | [4] Table 1; `PAPER_API_CLASSES` | FN khi malware dùng API chưa liệt kê |
| **M4** | Memory range overlap/contain là proxy hợp lý cho *same buffer* | Starink [12]; [4] §3.3 | FP/FN trên edge case vùng nhớ lớn hoặc execute thiếu address |
| **M5** | Frida user-mode hook **trung thực** về argument và thứ tự gọi dưới load thí nghiệm | Frida docs [5]; cần benchmark fidelity | Drop event → sai primitive count → sai 2-of-3 |
| **M6** | Sysmon kernel callbacks **không bị** attacker user-mode sửa đổi | Driver ring 0; chỉ O3 phá được | Mất toàn bộ lớp kernel nếu O3 |

**M5 — cần justification thực nghiệm:** Luận văn **không thể** giả định M5 mà không đo. Chương 6 (Đánh giá) đề xuất protocol Frida fidelity: so sánh output Frida với ETW/`SilkETW` trên ≥ 1000 lệnh gọi API injection synthetic. Cho đến khi có số liệu, mọi claim phụ thuộc Frida granularity phải gắn nhãn *conditional on M5*.

**M4 — deviation đã audit:** Khi primitive EXECUTE thiếu trường `address` (ví dụ `ResumeThread`), correlator có thể bỏ qua memory congruence cho cặp đó — deviation D1 đã được sửa bằng cách extract `lpStartAddress` / `Rip` từ CONTEXT trong Frida hooks. Luận văn thừa nhận đây từng là lỗ hổng methodology.

## 3.7. Ma trận né tránh ↔ mitigation (tổng hợp)

**Bảng 3.8.** Ma trận đối thủ – hình thức né tránh – mitigation – hạn chế

| Né tránh | Năng lực C | Out-of-scope O | Module Noirlycan | Mức độ mitigation | Hạn chế còn lại |
|----------|-----------|----------------|------------------|-------------------|-----------------|
| E1 | C1, C2, C4 | — | `kernel/classification/api_manifest.py`, `services/analysis/domain/correlation.py` | Cao | API mới chưa trong manifest |
| E2 | C2, C3 | — | 2-of-3, `kernel/classification/technique_classifier.py` | Cao | Mockingjay edge (RWX only) |
| E3 | C3, C6 | — | Sysmon E1/E11, `file_watch.py`, triage | Trung bình–cao | Inject không qua file-drop |
| E4 | (via O1/O2) | O1, O2 | Sysmon E8/E10 | Trung bình | Mất address/size; classifier yếu |
| E5 | C7 (một phần) | **O7** | `kernel/analysis/evasion.py` (ghi signal only) | **Không** | Recall < paper khi malware không chạy |
| E6 | C7 | O5 | `spawn`, documentation | Thấp | Không stealth Frida |

## 3.8. Ma trận tin cậy lớp telemetry (Telemetry Layer Trust Matrix)

Ma trận này trả lời câu hỏi phản biện: *"Frida bị bypass bởi direct syscall — phương pháp còn ý nghĩa gì?"* Câu trả lời: **graceful degradation** — detection chuyển từ semantic primitive sang coarse cross-process signal, không về zero.

**Bảng 3.9.** Telemetry Layer Trust Matrix

| Nguồn telemetry | Privilege | Cơ chế bắt | Bị bypass bởi | Phạm vi quan sát | Vai trò trong correlator |
|-----------------|-----------|------------|---------------|------------------|--------------------------|
| Sysmon Event 1 (ProcessCreate) | Kernel | Process notify | O3 | Mọi process create | Lineage, `CREATE_SUSPENDED`, parent PID — **E3** |
| Sysmon Event 7 (ImageLoad) | Kernel | Image notify | O3 | DLL/PE map | Reflective vs `LoadLibrary` — phân loại |
| Sysmon Event 8 (CreateRemoteThread) | Kernel | ETW Threat Intelligence | O3 | Cross-process thread **kể cả direct syscall** | Fallback EXECUTE — **E4** |
| Sysmon Event 10 (ProcessAccess) | Kernel | ObRegisterCallbacks | O3 | `OpenProcess` + VM_WRITE etc. | Fallback access — **E4** |
| Sysmon Event 11 (FileCreate) | Kernel | Minifilter | O3 | File executable/script mới | File provenance — **E3** |
| Sysmon Event 3 (NetworkConnect) | Kernel | ETW WFP | O3 | TCP/UDP | Post-injection beacon (watch hook) |
| Frida hooks (~121 API) | **User** | Export intercept | **O1, O2, O5** | NT API **arguments** (addr, size, prot) | Primitive detail, congruence input — **E1, E2** |
| Static triage | User | Disk read | C5 (encrypted) | Hash, PE, entropy, signature | Payload class trước runtime |

**Kết luận thiết kế (trình bày như điểm mạnh, không che limitation):**

Khi đối thủ O1/O2 (direct syscall / unhook):

1. **Frida** mất granularity → không đủ input cho memory congruence đầy đủ và phân loại kỹ thuật chi tiết.
2. **Sysmon kernel** vẫn fire Event 8/10 → correlator có thể thấy pattern *process_access + execute* với confidence **giảm** (chỉ còn 2 primitive coarse, không có address).
3. **Detection khả thi ở mức** "có cross-process injection vào target X" thay vì "section-mapping hollowing variant *neurevt* class" — recall giảm, **không về 0**.

Đây là đóng góp kiến trúc luận văn so với paper [4] (một lớp tracer QEMU): **phân tách rõ trust boundary** và document degradation path.

## 3.9. Mối đe dọa và mitigations (T1–T9)

**Bảng 3.10.** Threat catalog

| ID | Threat | Né tránh | Mức | Mitigation hiện có | Mitigation đề xuất / trạng thái |
|----|--------|----------|-----|-------------------|--------------------------------|
| **T1** | Direct syscall bỏ qua Frida (mất API-arg) | E4 / O1 | Cao | Sysmon E8/E10 fallback | ETW Threat Intelligence provider bổ sung (future) |
| **T2** | Late attach miss primitive đầu chuỗi | E6 | Cao | `spawn` mode documented | Mặc định `spawn` trong benchmark; auto-attach chỉ file-drop |
| **T3** | EXECUTE primitive thiếu address → yếu congruence | E2 edge | Trung | **Đã fix D1:** `lpStartAddress` / Rip trong hooks | Duy trì test regression |
| **T4** | Frida agent bị detect → malware abort | E6 / O5 | Trung | Không | Out-of-scope; ghi limitation |
| **T5** | Anti-evasion sandbox — malware không inject | E5 / O7 | Cao | `kernel/analysis/evasion.py` ghi signal only | Future: timing/env patch module như [4] |
| **T6** | Read API lẫn vào write count | — | Trung | **Đã fix D2:** tách `remote_read` khỏi 2-of-3 | — |
| **T7** | Temporal ordering quá lỏng | — | Thấp | **Đã fix D3:** reject mọi đảo bậc A/W/E | — |
| **T8** | Collision `(actor, target)` từ process benign | — | Thấp | Window 300s + PID pair | Đo FP trên Benign-Baseline (Chương 6) |
| **T9** | Kernel-mode injection | O3 | Cao | Không | Out-of-scope; paper cũng không phủ |

T3, T6, T7 là **deviation methodology** đã phát hiện qua audit code-vs-paper — minh chứng luận văn trung thực về limitation implementation, không chỉ claim thành công.

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

Finding **không** được coi là ground truth tuyệt đối — là *hypothesis* dựa trên M1–M6, cần analyst xác nhận.

## 3.11. Ranh giới claim khoa học (Scientific Claims Boundaries)

Phần này **bắt buộc** cho hội đồng — phân tách claim có evidence trong repo/test và claim **cấm** tuyên bố nếu chưa có Chương 6.

### 3.11.1. Claim ĐƯỢC PHÉP bảo vệ (có căn cứ audit)

| ID | Claim | Evidence |
|----|-------|----------|
| **C-IMPL** | Lõi 2-of-3 primitive + memory congruence + temporal ordering của [4] đã hiện thực trên Frida + Sysmon Windows 10/11 lab | `services/analysis/domain/correlation.py`, `kernel/classification/api_manifest.py`, `tests/test_correlation.py` |
| **C-AUDIT** | Ba deviation methodology (D1/D2/D3) đã phát hiện và sửa có test regression | `docs/audit-and-threat-model.md`, test suite |
| **C-EXT** | Pipeline file provenance → process lineage → injection finding cung cấp ngữ cảnh [4] không mô hình hóa | `services/collector/infrastructure/file_watch.py`, `services/analysis/domain/correlation.py` linking |
| **C-CASE** | Kịch bản section-mapping (class *neurevt*) phát hiện đúng pattern primitive trên PoC | `test_detects_section_mapping_write_execute_chain` |
| **C-ARCH** | Kiến trúc Sysmon ∪ Frida document graceful degradation dưới E4 | Bảng 3.9, mục 3.8 |
| **C-TAX** | Taxonomy mở rộng beyond paper §4 (36 kỹ thuật enum) | `kernel/classification/technique_classifier.py` — **không** kèm precision số |

### 3.11.2. Claim KHÔNG ĐƯỢC PHÉP (cấm nếu chưa bổ sung evaluation)

| Claim cấm | Lý do |
|-----------|-------|
| "Precision/recall ngang hoặc hơn paper [4]" | Không có dataset 56k; không baseline Cuckoo trong repo |
| "Phát hiện kỹ thuật X với độ chính xác Y%" | Classifier chưa đánh giá ground truth |
| "Tái lập prevalence 16,5 % / sandbox miss 21,2 %" | Số liệu thuộc [4], không phải luận văn |
| "Chống E5 toàn diện" | O7 — không anti-evasion module |
| "Production-ready EDR thay thế thương mại" | Lab prototype; M5 chưa đầy đủ |
| "Frida user-mode đủ tin cậy mọi điều kiện" | O1/O5; cần M5 benchmark |
| "Phương pháp detection mới thay thế [4]" | Sai — phương pháp lõi là của [4]; luận văn là replication + extension |

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
| RO1 — Hiện thực [4] | M1–M4; C-IMPL; T3/T6/T7 fixes |
| RO2 — Telemetry kép E4 | Bảng 3.9; T1; O1/O2 degradation |
| RO3 — Provenance E3 | Sysmon E11/E1; C-EXT |
| RO4 — Đánh giá biến thể | C-CASE; E1/E2; **không** claim prevalence |
| RO5 — Tài liệu hóa threat model | Toàn chương 3; scientific claims §3.11 |

## 3.13. Hạn chế threat model và tính hợp lệ ngoại vi (*validity*)

### 3.13.1. Internal validity

- Ground truth PoC do tác giả gắn nhãn — bias có thể có.
- Số mẫu nhỏ so với [4] — không generalize prevalence.
- Frida overhead có thể thay đổi timing — ảnh hưởng race condition hiếm (không đo đầy đủ).

### 3.13.2. External validity

- Chỉ Windows 10/11 client — không Windows Server, không Linux.
- Lab VM ≠ enterprise endpoint có EDR đa agent.
- Mẫu 2017–2023 trong [4] — kỹ thuật 2024+ (một số) chỉ có rule chưa evaluate.

### 3.13.3. Construct validity

- Primitive abstraction M1 có thể không map một số kỹ thuật mới (PoolParty phức tạp) — classifier bổ sung, không thay 2-of-3.
- Score finding (≥ 50/70) là heuristic lab, chưa calibrate trên corpus.

Luận văn **không che** các hạn chế này; Chương 7 (Thảo luận) mở rộng thêm.

## 3.14. Tóm tắt chương

Chương 3 đã xây dựng threat model formal cho Noirlycan: hệ thống lab Windows với telemetry kép kernel (Sysmon) và user (Frida); tài sản A1–A3; đối thủ user-mode với năng lực C1–C7; ranh giài out-of-scope O1–O7 (đặc biệt O3 kernel, O7 anti-sandbox); taxonomy né tránh E1–E6 với mitigation tương ứng; giả định môi trường E1–E6 và phương pháp M1–M6; ma trận tin cậy telemetry giải thích graceful degradation dưới E4; catalog mối đe dọa T1–T9; và **ranh giới claim khoa học** phân tách rõ replication [4], extension provenance/architecture, versus những gì cấm claim (prevalence 16,5 %/21,2 %, anti-E5, production EDR).

Threat model này phục vụ hai mục đích: (1) cho hội đồng đánh giá **scope** và trung thực khoa học; (2) làm khung cho Chương 5 (Phương pháp) và Chương 6 (Đánh giá) — mọi thí nghiệm phải map lại C-IMPL/C-EXT/C-CASE và không vượt claim §3.11.
