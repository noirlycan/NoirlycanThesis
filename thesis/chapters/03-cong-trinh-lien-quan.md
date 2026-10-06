# CHƯƠNG 2. CÔNG TRÌNH LIÊN QUAN

Chương này khảo sát các hướng phát hiện process injection trên Windows, trọng tâm **chống né tránh** (biến thể API, gộp bước, né attribution, né hook, né sandbox), nhằm xác định vị trí luận văn so với công trình căn cứ Di Pietro et al. (ASIA CCS 2025) [7].

## 2.1. Bối cảnh: cuộc đua vũ trang giữa phát hiện và né tránh

Process injection (T1055 [12]) là kỹ thuật then chốt của malware Windows vì ba lý do gắn với né tránh: (1) thực thi payload trong tiến trình uy tín thay vì tạo tiến trình mới — **né attribution** (E3); (2) chọn tập API khác nhau (`CreateRemoteThread` so với `NtCreateThreadEx`) — **biến thể API** (E1); (3) phát hiện sandbox/debugger rồi không inject — **né sandbox** (E5).

Phương pháp truyền thống chia thành ba nhóm (Bảng 2.1). Cộng đồng đã chuyển từ khớp chuỗi API sang mô hình hành vi trừu tượng hơn — *operational primitive* — nơi Di Pietro et al. [7] là mốc quan trọng nhất.

**Bảng 2.1.** Phân loại hướng tiếp cận phát hiện process injection và khả năng chống né tránh

| Nhóm | Cơ chế cốt lõi | Đại diện | Chống E1 | Chống E2 | Chống E3 | Chống E4 | Chống E5 |
|------|----------------|----------|----------|----------|----------|----------|----------|
| Signature / rule API | Khớp chuỗi hoặc tập API cố định | Sigma, YARA, AV | Yếu | Yếu–TB | Yếu | Yếu | TB |
| Behavior graph | Đồ thị handle, vùng nhớ, tiến trình | Starink et al. [15] | Khá | Khá | TB | TB | Phụ thuộc |
| Operational primitive | A/W/E + equivalence class | Klein [10], **[7]** | **Mạnh** | **Mạnh** | Yếu | TB | **Cần module** |
| Memory forensic | Quét vùng thực thi RAM | Barabosch et al. [5] (Quincy) | Mạnh (offline) | Mạnh (offline) | TB | N/A | N/A |
| EDR thương mại | Rule + ML + kernel driver | Defender, Elastic, CrowdStrike | Khá–mạnh | Khá | Khá | Mạnh | Khá |

Luận văn chọn [7] làm **căn cứ phương pháp chính** vì đây là công trình duy nhất vừa (a) đề xuất framework phát hiện chịu biến thể triển khai, (b) **định lượng trực tiếp** tác động né sandbox trên dataset 56.340 mẫu, vừa (c) công bố artifact tái lập được [14].

## 2.2. Phát hiện dựa trên signature và rule API

Signature — khớp chuỗi API, hash, byte, hoặc rule Sigma/YARA — phổ biến trong SOC và AV. Rule điển hình cho remote thread injection yêu cầu tuần tự `OpenProcess` → `VirtualAllocEx` → `WriteProcessMemory` → `CreateRemoteThread`. Cách này **dễ bị phá** bởi E1 (thay `CreateRemoteThread` bằng `NtCreateThreadEx`) và E2 (gộp allocate+write vào `NtMapViewOfSection`).

Hạn chế nằm ở **mức trừu tượng quá thấp**: rule mô tả *cách* triển khai thay vì *điều gì* bắt buộc xảy ra trên bộ nhớ. Di Pietro et al. [7] lập luận signature tạo false negative cao trên malware đa hình — củng cố bằng việc VirusTotal/CAPE bỏ sót trung bình 21,2 % mẫu mà phương pháp primitive phát hiện được (mục 2.6.4). Luận văn không đề xuất signature mới; hiện thực framework primitive [7] như lớp semantic trên signature.

## 2.3. Klein và Kotler (2019) — Phân loại operational primitive

Klein và Kotler [10] đặt ba bước tối thiểu mọi process injection user-mode phải thực hiện:

1. **Allocate** — chuẩn bị vùng nhớ có thể chứa mã thực thi (kể cả đổi protection sang RWX/RX).
2. **Write** — đặt payload vào vùng đó, trực tiếp (`WriteProcessMemory`) hoặc qua section mapping.
3. **Execute** — kích hoạt thực thi qua tạo thread mới, hijack thread, hoặc APC.

Đóng góp của Klein là **mô hình khái niệm**: ba primitive mô tả bản chất thao tác mọi kỹ thuật phải tuân theo. Tuy nhiên [10] chưa xây dựng lớp tương đương API, quy tắc quyết định khi chỉ thấy hai trong ba primitive (E2), ràng buộc vùng nhớ, và đánh giá quy mô lớn.

Di Pietro et al. [7] kế thừa và bổ sung bốn thành phần (equivalence class, 2-of-3, memory congruence, temporal ordering) — biến mô hình khái niệm thành **framework phát hiện có thể triển khai**. Noirlycan dùng `PrimitiveKind.ALLOCATE/WRITE/EXECUTE` (`models.py`) và `PAPER_API_CLASSES` (`detection/api_classes.py`), bổ sung `CONTEXT_READ` cho `GetThreadContext`. Cả Klein và [7] giới hạn user-mode; kernel-mode nằm ngoài (Chương 3, O3).

## 2.4. Barabosch et al. (2017) — Phân tích memory dump

Barabosch et al. [5] (Quincy) và các Volatility plugin tiếp cận injection **offline**: dump RAM, quét vùng executable bất thường, phát hiện shellcode hoặc PE mapping thủ công. Ưu điểm: không phụ thuộc chuỗi API. Nhược điểm: không real-time, chi phí dump RAM cao, khó phân biệt JIT hợp pháp (CLR, V8, JVM), và không đối phó E5. Luận văn xem memory forensic là **bổ trợ điều tra sau sự cố**; Noirlycan kết hợp Frida + Sysmon theo hướng tracer động của [7].

## 2.5. Starink et al. (2023) — Behavior graph và memory congruence

Starink et al. [15] đề xuất **behavior graph**: node là thực thể (process, thread, memory region, handle); cạnh là quan hệ thao tác. Phát hiện injection = tìm subgraph khớp mẫu. Công trình nhấn mạnh ràng buộc **cùng buffer** — mọi primitive phải thao tác trên cùng vùng nhớ vật lý — loại trừ việc hai chuỗi thao tác trên hai vùng nhớ khác nhau bị gom nhầm thành một injection chain.

**Bảng 2.2.** So sánh behavior graph [15] và operational primitive [7]

| Khía cạnh | Starink et al. [15] | Di Pietro et al. [7] |
|-----------|---------------------|----------------------|
| Cấu trúc dữ liệu | Đồ thị đầy đủ (node/edge) | Ba primitive + equivalence class |
| Ràng buộc vùng nhớ | Same buffer (chặt) | Overlap/contain (nới lỏng) |
| Chống E1 | Phụ thuộc node label API | Equivalence class |
| Chi phí tính toán | Cao (graph matching) | Thấp (rule 2-of-3 stream) |
| Đánh giá né sandbox | Không tập trung | Có (ablation BluePill vs Detours: 11,8 % vs 6,2 %) |

Di Pietro et al. [7] đơn giản hóa *same buffer* thành **memory range congruence**: hai primitive cùng vùng nhớ nếu khoảng `[addr, addr+size)` giao hoặc chứa nhau. Cách này loại false positive khi cùng actor có nhiều allocation độc lập, đồng thời cho phép section mapping. Noirlycan hiện thực trong `_has_memory_congruence()` (`detection/correlator.py`). [7] cân bằng tốt hơn Starink giữa tổng quát và chi phí, tương thích stream processing event-by-event.

## 2.6. Di Pietro, D'Elia, Querzoni (ASIA CCS 2025) — Căn cứ khoa học chính

### 2.6.1. Thông tin công trình và bối cảnh

> Di Pietro, G., D'Elia, D. C., & Querzoni, L. (2025). *Can You Run My Code? A Close Look at Process Injection in Windows Malware.* ASIA CCS '25, Hanoi. DOI: 10.1145/3708821.3736206. Artifact [14].

Tác giả thuộc Sapienza University of Rome; D'Elia là tác giả Bluepill nên module anti-evasion được thiết kế đồng bộ với pipeline. Paper đặt **ba câu hỏi nghiên cứu**:

| ID | Câu hỏi | Ý nghĩa với luận văn |
|----|---------|----------------------|
| **RQ1** | Kỹ thuật injection nào phổ biến nhất trong malware hiện đại? Việc công bố thông tin về kỹ thuật có ảnh hưởng tới mức độ được dùng không? | Baseline prevalence (16,5 %); luận văn **không tái lập** |
| **RQ2** | Có tương quan giữa family malware và kỹ thuật injection không? Kỹ thuật của mỗi family có thay đổi theo thời gian không? | Bối cảnh; ngoài phạm vi luận văn |
| **RQ3** | Phương pháp có dùng được trong các giải pháp bảo mật không, với hiệu năng (vd. false positive) ra sao? | Overhead 1,35 %, công cụ công khai bỏ sót 21,2 % — **động lực** đưa phương pháp lên endpoint |

### 2.6.2. Phương pháp cốt lõi

#### (a) Ba operational primitive và equivalence class

Đóng góp của [7] là **ánh xạ mỗi primitive sang lớp tương đương API** (Bảng 2.3). API mới chỉ cần thêm vào lớp tương ứng mà không phải sửa correlator.

**Bảng 2.3.** Lớp tương đương API theo Di Pietro et al. [7] (rút gọn)

| Primitive | Ví dụ API trong lớp | Vai trò chống né tránh |
|-----------|---------------------|------------------------|
| Allocate | `VirtualAllocEx`, `NtAllocateVirtualMemory`, `VirtualProtectEx`, `NtCreateSection`, `CreateFileMappingW`, `MapViewOfFile` | Chống E1 |
| Write | `WriteProcessMemory`, `NtWriteVirtualMemory`, `NtMapViewOfSection`, `RtlCopyMemory` | Chống E1/E2: section mapping = allocate ∧ write |
| Execute | `CreateRemoteThread(Ex)`, `NtCreateThreadEx`, `QueueUserAPC`, `SetThreadContext`, `ResumeThread`, `LoadLibrary*` | Chống E1 |

Equivalence class cho phép correlator kết luận có injection dựa trên **ngữ nghĩa**, không phụ thuộc tên API — trực tiếp đối phó E1.

#### (b) Quy tắc 2-of-3

Yêu cầu **đủ cả ba** primitive → false negative cao (malware gộp bước hoặc dùng vùng RWX sẵn có — Mockingjay, APC variants); yêu cầu **chỉ một** → false positive cao (debugger, profiler, hot-patching đều gọi `VirtualAllocEx`/`WriteProcessMemory`).

Cân bằng: **quan sát ít nhất hai primitive khác loại** trên cùng cặp `(actor_pid, target_pid)`, kèm memory congruence và temporal ordering. Quy tắc này chống **E2** vì chấp nhận malware nén ba bước thành hai. Noirlycan hiện thực `operational_kind_count(kinds) >= 2` (`detection/correlator.py`); `CONTEXT_READ` được ghi nhận nhưng **không tính** vào 2-of-3.

#### (c) Memory range congruence

Hai primitive *congruent* khi vùng địa chỉ giao nhau:

\[
[p_1.\text{addr},\, p_1.\text{addr}+p_1.\text{size}) \cap [p_2.\text{addr},\, p_2.\text{addr}+p_2.\text{size}) \neq \emptyset
\]

Mục đích: tránh gom nhầm allocate ở địa chỉ *a* với write ở địa chỉ *b* không liên quan. Kế thừa Starink [15], đơn giản hóa thành phép kiểm tra giao khoảng O(1).

#### (d) Temporal consistency

Thứ tự tự nhiên: Allocate → Write → Execute. Paper cho phép gộp bước (`NtMapViewOfSection` = allocate + write), lặp allocate (resize, đổi protection RW → RX), nhưng không cho phép EXECUTE trước WRITE trên cùng vùng. Noirlycan hiện thực `_has_temporal_consistency()` với bậc `ALLOCATE=0, WRITE=1, EXECUTE=3`.

### 2.6.3. Hạ tầng thực nghiệm và dataset

- **Nguồn mẫu:** VirusTotal Academic + VX Underground Bazaar, 2017–2023; 334.885 mẫu PE → **56.340 mẫu** thuộc 2.667 family (khử trùng lặp bằng vhash của VirusTotal, mỗi family ≤5 % mẫu/năm theo nhãn AVClass).
- **Monitoring:** BluePill — framework phân tích malware evasive xây trên DBI Intel Pin — hook API ở cả mức thư viện lẫn mức system call, kèm các biện pháp anti-evasion có sẵn; theo dõi cả tiến trình con và tiến trình bị inject (`-follow_execv`). Bản thứ hai trên Microsoft Detours (không anti-evasion) dùng cho ablation. So sánh với công cụ công khai: báo cáo hành vi của VirusTotal và CAPE.

Anti-evasion là thành phần quan trọng khi đo prevalence: thiếu nó, malware **chủ động không chạy** payload (E5) và injection không được quan sát — trên tập 2019, Detours chỉ thấy 6,2 % so với 11,8 % của BluePill.

### 2.6.4. Kết quả chính

**Bảng 2.4.** Tóm tắt kết quả thực nghiệm Di Pietro et al. [7]

| Chỉ số | Giá trị | Diễn giải |
|--------|---------|-----------|
| Tỷ lệ mẫu có injection (2017–2023) | **~16,5 %** | Trả lời RQ1; xu hướng tăng |
| Công cụ công khai bỏ sót (VirusTotal 24,0 %, CAPE 18,3 %) | **21,2 %** trung bình | Trả lời RQ3 — phương pháp primitive bổ sung được cho sandbox hiện có |
| Ablation anti-evasion (tập 2019) | Detours **6,2 %** vs BluePill **11,8 %** | Evasion che giấu injection |
| Overhead phân tích | **1,35 %** | Đủ nhẹ để tích hợp vào AV/EDR |
| Mẫu multi-stage đệ quy (A→B→C) | ~2 % | Injection lồng nhau |
| Biến thể dominant family đa kỹ thuật | Section-mapping hollowing | Case study *neurevt* |

Hai con số mang ý nghĩa: (1) injection không hiếm — đáng đầu tư phương pháp tổng quát; (2) né môi trường phân tích (E5) làm giảm recall ngay cả khi có phương pháp tốt.

**Lưu ý:** Hai con số thuộc paper [7]. Luận văn **không claim** đã tái lập trên 56.340 mẫu; Noirlycan chưa có module anti-evasion tương đương (Chương 3, O7). Số liệu được trích dẫn làm **động lực**.

### 2.6.5. Taxonomy kỹ thuật và case study *neurevt*

Paper phân loại **12 kỹ thuật injection chính**: Classic Remote Thread, APC, Early Bird APC, SetWindowsHookEx, Thread Hijacking, Process Hollowing (classic + section), AtomBombing, Reflective DLL, Module Stomping, Process Doppelgänging, Process Ghosting/Herpaderping.

**Case study *neurevt*** (Paper §3.5) là ví dụ điển hình **E1 + E2**: thay `VirtualAllocEx` + `WriteProcessMemory` bằng `NtCreateSection` + `NtMapViewOfSection` (gộp allocate và write, chuyển sang NT native né hook); kích hoạt qua `SetThreadContext` + `ResumeThread` trên tiến trình suspended — biến thể **Process Hollowing** dominant [7]. Signature dò `CreateRemoteThread` vô hiệu, nhưng framework 2-of-3 **không bị phá**: correlator vẫn thấy write + execute trên cùng vùng section. Noirlycan có test `test_detects_section_mapping_write_execute_chain` xác nhận kịch bản này đạt score ≥ 70.

**Hạn chế:** test trên loader PoC lab, không phải sample *neurevt* gốc. Luận văn claim **phát hiện đúng pattern primitive**, không claim đã phân tích lại family trên malware thật.

### 2.6.6. Module anti-evasion và quan hệ với đề tài

Paper §6 mô tả module anti-evasion: bypass **timing checks** (sleep acceleration, RDTSC manipulation), bypass **environment fingerprint** (registry VM, MAC, process artifact), tránh malware **skip injection**. Module này giải thích vì sao framework primitive đạt recall cao hơn Cuckoo **trên cùng corpus** — không chỉ vì 2-of-3 mà vì malware thực sự chạy trong môi trường đã che giấu.

**Bảng 2.5.** Vai trò anti-evasion trong [7] so với Noirlycan

| Khía cạnh | Paper [7] | Noirlycan |
|-----------|-----------|-----------|
| Anti-evasion timing/env | BluePill (DBI) | **Out-of-scope** (`extensions/evasion.py` chỉ ghi signal) |
| Phát hiện primitive E1/E2 | Có (BluePill hook thư viện + syscall) | Có (Frida + Sysmon + correlator) |
| Phát hiện khi malware không chạy (E5) | Giảm nhờ anti-evasion | **Không xử lý** |
| Số liệu 21,2 % (công cụ công khai bỏ sót) | Đo trên corpus paper | Trích dẫn, không tái lập |

Luận văn tách hai lớp: (1) chống E1–E4 khi malware *đã* injection — mục tiêu chính; (2) chống E5 khi malware *không* thực hiện — paper giải quyết, luận văn khai báo ngoài phạm vi.

### 2.6.7. Hạn chế tự công bố của paper [7]

| Hạn chế | Mô tả | Ảnh hưởng luận văn |
|---------|-------|-------------------|
| User-space only | Kernel injection không trong scope | O3 threat model |
| Tracer user-mode có thể bị bypass | Direct syscall stub | E4 — Noirlycan bổ sung Sysmon kernel |
| Dataset đến 2023 | Thiếu PoolParty, Mockingjay đầy đủ | Mở rộng taxonomy qua iRed.team |
| Phụ thuộc chất lượng trace | Drop event → sai primitive count | Giả định M5 (Frida fidelity) |
| Không có file provenance end-to-end | Bắt đầu từ process đã chạy | Đóng góp RO3 luận văn |

Mỗi hạn chế ứng với một hướng mở rộng trong Noirlycan, làm cấu trúc Replication + Extension trở nên tự nhiên.

### 2.6.8. Đóng góp khoa học paper và vị trí artifact

**Bảng 2.6.** Đóng góp Di Pietro et al. [7]

| ID | Đóng góp | Loại |
|----|----------|------|
| C1 | Framework 2-of-3 + equivalence class + congruence + temporal | Methodology |
| C2 | Prevalence ~16,5 % trên 56k mẫu | Empirical |
| C3 | Công cụ công khai bỏ sót 21,2 %; ablation anti-evasion 6,2 % vs 11,8 % | Comparative |
| C4 | Anti-evasion ablation | Engineering + Empirical |
| C5 | Phân tích biến thể theo thời gian (section mapping) | Forensic |
| C6 | Artifact công khai [14] | Reproducibility |

Artifact `Sap4Sec/process-injection` [14] là cơ sở cho RO3. Noirlycan là **implementation độc lập** trên Frida + Sysmon, audit đối chiếu paper (docs/audit-and-threat-model.md).

## 2.7. Né tránh sandbox và phân tích chống phân tích

D'Elia et al. [6] và Galloro et al. [9] khảo sát định lượng các kỹ thuật malware né sandbox trên corpus lớn: phát hiện VM (CPUID, registry, driver), timing attack (sleep, RDTSC delta), kiểm tra tool (Wireshark, Procmon, Frida artifact), và hành vi có điều kiện.

**Bảng 2.7.** Phân loại né tránh sandbox và liên hệ với injection

| Kỹ thuật né tránh | Mục tiêu | Tác động lên phát hiện injection |
|-------------------|----------|----------------------------------|
| VM/sandbox fingerprint | E5 | Malware không gọi API → log trống |
| Timing / delayed execution | E5 | Injection sau window phân tích |
| User interaction gate | E5 | Sandbox batch fail |
| Anti-debug (E6) | Dừng trước inject | Miss behavior |
| Direct syscall (E4) | Né hook | Injection xảy ra nhưng mất API trace |

Chỉ [7] định lượng ảnh hưởng của evasion lên việc quan sát injection trên corpus lớn (ablation 6,2 % vs 11,8 %). D'Elia et al. [6] và Galloro et al. [9] cung cấp taxonomy và số liệu dọc cho E5/E6 nhưng không thay số liệu paper. Luận văn dùng để justify anti-evasion là hướng phát triển bắt buộc; Noirlycan **chưa hiện thực** module tương đương.

## 2.8. EDR thương mại và thực hành phòng thủ

EDR/EPP thương mại (Defender, Elastic Defend, CrowdStrike Falcon) kết hợp kernel driver, ETW provider, ML, và threat intelligence; cũng quan sát cross-process memory operation và thread creation — gần với primitive model. Tuy nhiên rule và model đóng nguồn (không audit được equivalence class hay 2-of-3 tương đương [7]); tối ưu production không công bố ablation né sandbox; không cung cấp pipeline provenance file→injection cho lab cá nhân.

Noirlycan **không cạnh tranh** với EDR thương mại. Vị trí: **công cụ lab mã nguồn mở**, minh bạch rule, phục vụ replication [7] và đào tạo analyst. Sysmon [11] được chọn làm lớp kernel vì phổ biến trong forensic community và có schema công khai, tránh tự viết kernel driver.

## 2.9. MITRE ATT&CK và chuẩn hóa taxonomy

MITRE ATT&CK T1055 [12] liệt kê hơn một chục sub-technique injection. Chuẩn hóa này giúp analyst giao tiếp nhưng **không cung cấp thuật toán phát hiện**.

Noirlycan `classification/technique_classifier.py` map output rule-based lên nhãn ATT&CK, mở rộng từ ~12 kỹ thuật paper lên **36 enum** (17 đạt FULL coverage: hook + classifier + test). Tách biệt giữa "phát hiện có injection" (correlator primitive) và "phân loại kỹ thuật gì" (technique classifier) giữ hai bài toán độc lập. Classifier **chưa được đánh giá** precision/recall trên ground truth corpus (Chương 3).

## 2.10. Khoảng trống nghiên cứu

**Bảng 2.8.** Khoảng trống nghiên cứu và định vị luận văn

| Khoảng trống | Paper [7] | EDR thương mại | Sandbox (Cuckoo) | Noirlycan |
|--------------|-----------|----------------|------------------|-----------|
| Framework primitive chống E1/E2 | ✅ Batch DBI | Một phần (đóng) | Yếu (signature) | ✅ Real-time Windows lab |
| Prevalence 56k | ✅ | Không công bố | Không | ❌ Out-of-scope |
| Anti-evasion E5 | ✅ | Một phần | Yếu → bỏ sót 18–24 % | ❌ Ghi signal |
| Telemetry kernel khi E4 | Không (DBI user-mode, có hook syscall) | ✅ | Guest agent dễ detect | ✅ Sysmon E8/E10/E11 |
| File provenance → injection (E3) | ❌ | Một phần | Một phần | ✅ Pipeline end-to-end |
| Công cụ analyst lab mở | Artifact batch | Đóng | Cuckoo web UI | ✅ Dashboard + JSONL |
| Audit replication có test | Artifact paper | N/A | N/A | ✅ 31+ unit test |
| Đánh giá Frida fidelity (M5) | N/A | N/A | N/A | ⚠️ Protocol đề xuất |

**Khoảng trống trung tâm:** Paper [7] chứng minh phương pháp ở quy mô sandbox batch, nhưng chưa có (a) triển khai vận hành trên endpoint Windows thật với telemetry kép kernel/user, (b) liên kết injection finding với nguồn file drop, (c) threat model formal cho từng hình thức né tránh E1–E6. Noirlycan nhắm (a)–(c) trong phạm vi **Replication + Extension**, không claim phương pháp detection mới thay [7].

## 2.11. Định vị luận văn: Replication + Extension

1. **Replication có kiểm chứng:** Hiện thực 2-of-3 + memory congruence + temporal ordering + `PAPER_API_CLASSES` trên Frida (`frida_hooks/handlers.js`) và correlator Python (`detection/correlator.py`, `detection/primitives.py`). Audit phát hiện ba lệch lạc (D1: execute thiếu address; D2: read API lẫn write; D3: temporal quá lỏng) — đã sửa và verify bằng test.

2. **Extension kiến trúc:** (a) Sysmon kernel fallback chống E4 (event 8/10/11) bù đắp khi tracer user-mode bị bypass; (b) file provenance pipeline chống E3, liên kết file drop với tiến trình actor; (c) mở rộng taxonomy `technique_classifier.py` beyond paper §4 cho kỹ thuật xuất hiện sau 2023.

3. **Honest scope:** Không claim prevalence 16,5 % / miss 21,2 %; không claim anti-evasion E5; không claim production EDR.

**Bảng 2.9.** Claim được phép và không được phép

| Được claim | Không được claim |
|------------|------------------|
| Hiện thực [7] trên Frida + Sysmon với unit test | Phương pháp detection mới hơn [7] |
| Phát hiện pattern section-mapping (*neurevt*-class) trên PoC | Precision/recall ngang paper trên 56k mẫu |
| Giảm FN một phần dưới E4 nhờ Sysmon | Chống E5 toàn diện như paper |
| Pipeline provenance tăng giá trị forensic E3 | Thay thế Cuckoo/EDR thương mại |

## 2.12. Literature map và tóm tắt chương

**Hình 2.1 (Literature map).** Vị trí luận văn:

```
[Signature / Sigma] ──► yếu trước E1/E2
       │
[Klein primitive A-W-E] ──► nền tảng lý thuyết
       │
[Starink behavior graph] ──► congruence bổ sung
       │
[Di Pietro et al. 2025] ──► CĂN CỨ CHÍNH: 2-of-3 + 56k + ablation E5
       │
  ┌────┴────┐
[Sandbox] [EDR đóng]
       │
       └─► Noirlycan: replication [7] + E3 provenance + E4 Sysmon
```

**Bảng 2.10.** Literature map — ai giải quyết gì

| Vấn đề | Klein [10] | Starink [15] | Paper [7] | Noirlycan |
|--------|-----------|--------------|-----------|-----------|
| Primitive A-W-E | ✅ Định nghĩa | Một phần | ✅ Formal + 2-of-3 | ✅ Replication |
| Chống E1 biến thể API | ❌ | ❌ | ✅ Equivalence class | ✅ |
| Chống E2 gộp bước | ❌ | Một phần | ✅ Section-mapping | ✅ Test ≥70 |
| Prevalence quy mô lớn | ❌ | ❌ | ✅ 56k | ❌ |
| Anti-E5 sandbox | ❌ | ❌ | ✅ Module | ❌ |
| Real-time endpoint | ❌ | ❌ | ❌ Batch DBI | ✅ |
| File provenance E3 | ❌ | ❌ | ❌ | ✅ Extension |

Chương 2 đã khảo sát signature, primitive Klein [10], behavior graph Starink [15], và phân tích chi tiết Di Pietro et al. [7] với ba RQ, **16,5 %** prevalence, **21,2 %** bỏ sót của công cụ công khai, ablation anti-evasion, case study *neurevt*, module anti-evasion. Các khảo sát né sandbox [9], [6] và EDR bổ sung bối cảnh.

Khoảng trống: thiếu triển khai real-time Windows + telemetry kép + provenance + threat model formal. Luận văn định vị là **Replication + Extension** của [7], tăng cường phát hiện dưới **E1–E4** trong phòng lab, thừa nhận **E5/E6** và prevalence scale ngoài phạm vi. Chương 3 trình bày threat model formal — tài sản, đối thủ C1–C7, out-of-scope O1–O7, giả định E1–E6 và M1–M6, ma trận tin cậy telemetry, và ranh giới claim khoa học.
