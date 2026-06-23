# CHƯƠNG 4. THỰC NGHIỆM, KẾT QUẢ VÀ SO SÁNH ĐÁNH GIÁ

Chương mô tả công cụ thực nghiệm, môi trường, dữ liệu, cách tổ chức thí nghiệm, kết quả định lượng và định tính, ví dụ điển hình, **so sánh với nghiên cứu liên quan** và thảo luận (Discussion trong khuôn IMRAD). Nguyên tắc tái tạo được: đủ chi tiết để người có năng lực tương đương lặp lại thực nghiệm.

---

Phần đầu chương trình bày **nghiên cứu liên quan và baseline so sánh** theo hướng dẫn HTW — đặt sau phương pháp và hiện thực, trước kết quả thực nghiệm. Căn cứ trung tâm là Di Pietro et al. (ASIA CCS 2025) [4]; các công trình [7], [12] bổ sung nền tảng primitive và behavior graph.

## 4.1. Bối cảnh: cuộc đua vũ trang giữa phát hiện và né tránh

Process injection (T1055 [9]) là kỹ thuật then chốt của malware Windows vì ba lý do gắn với né tránh: (1) thực thi payload trong tiến trình uy tín thay vì tạo tiến trình mới — **né attribution** (E3); (2) chọn tập API khác nhau (`CreateRemoteThread` so với `NtCreateThreadEx`) — **biến thể API** (E1); (3) phát hiện sandbox/debugger rồi không inject — **né sandbox** (E5).

Phương pháp truyền thống chia thành ba nhóm (Bảng 2.1). Cộng đồng đã chuyển từ khớp chuỗi API sang mô hình hành vi trừu tượng hơn — *operational primitive* — nơi Di Pietro et al. [4] là mốc quan trọng nhất.

**Bảng 4.1.** Phân loại hướng tiếp cận phát hiện process injection và khả năng chống né tránh

| Nhóm | Cơ chế cốt lõi | Đại diện | Chống E1 | Chống E2 | Chống E3 | Chống E4 | Chống E5 |
|------|----------------|----------|----------|----------|----------|----------|----------|
| Signature / rule API | Khớp chuỗi hoặc tập API cố định | Sigma, YARA, AV | Yếu | Yếu–TB | Yếu | Yếu | TB |
| Behavior graph | Đồ thị handle, vùng nhớ, tiến trình | Starink et al. [12] | Khá | Khá | TB | TB | Phụ thuộc |
| Operational primitive | A/W/E + equivalence class | Klein [7], **[4]** | **Mạnh** | **Mạnh** | Yếu | TB | **Cần module** |
| Memory forensic | Quét vùng thực thi RAM | Barabosch [3], Quincy | Mạnh (offline) | Mạnh (offline) | TB | N/A | N/A |
| EDR thương mại | Rule + ML + kernel driver | Defender, Elastic, CrowdStrike | Khá–mạnh | Khá | Khá | Mạnh | Khá |

Luận văn chọn [4] làm **căn cứ phương pháp chính** vì đây là công trình duy nhất vừa (a) đề xuất framework phát hiện chịu biến thể triển khai, (b) **định lượng trực tiếp** tác động né sandbox trên dataset 56.340 mẫu, vừa (c) công bố artifact tái lập được [11].

## 4.2. Phát hiện dựa trên signature và rule API

Signature — khớp chuỗi API, hash, byte, hoặc rule Sigma/YARA — phổ biến trong SOC và AV. Rule điển hình cho remote thread injection yêu cầu tuần tự `OpenProcess` → `VirtualAllocEx` → `WriteProcessMemory` → `CreateRemoteThread`. Cách này **dễ bị phá** bởi E1 (thay `CreateRemoteThread` bằng `NtCreateThreadEx`) và E2 (gộp allocate+write vào `NtMapViewOfSection`).

Hạn chế nằm ở **mức trừu tượng quá thấp**: rule mô tả *cách* triển khai thay vì *điều gì* bắt buộc xảy ra trên bộ nhớ. Di Pietro et al. [4] lập luận signature tạo false negative cao trên malware đa hình — củng cố bằng 21,2 % sandbox miss (mục 2.6.4). Luận văn không đề xuất signature mới; hiện thực framework primitive [4] như lớp semantic trên signature.

## 4.3. Klein et al. (2017) — Phân loại operational primitive

Klein et al. [7] đặt ba bước tối thiểu mọi process injection user-mode phải thực hiện:

1. **Allocate** — chuẩn bị vùng nhớ có thể chứa mã thực thi (kể cả đổi protection sang RWX/RX).
2. **Write** — đặt payload vào vùng đó, trực tiếp (`WriteProcessMemory`) hoặc qua section mapping.
3. **Execute** — kích hoạt thực thi qua tạo thread mới, hijack thread, hoặc APC.

Đóng góp của Klein là **mô hình khái niệm**: ba primitive mô tả bản chất thao tác mọi kỹ thuật phải tuân theo. Tuy nhiên [7] chưa xây dựng lớp tương đương API, quy tắc quyết định khi chỉ thấy hai trong ba primitive (E2), ràng buộc vùng nhớ, và đánh giá quy mô lớn.

Di Pietro et al. [4] kế thừa và bổ sung bốn thành phần (equivalence class, 2-of-3, memory congruence, temporal ordering) — biến mô hình khái niệm thành **framework phát hiện có thể triển khai**. Noirlycan dùng `PrimitiveKind.ALLOCATE/WRITE/EXECUTE` (`kernel/entities/models.py`) và `PAPER_API_CLASSES` (`kernel/classification/api_manifest.py`), bổ sung `CONTEXT_READ` cho `GetThreadContext`. Cả Klein và [4] giới hạn user-mode; kernel-mode nằm ngoài (Chương 3, O3).

## 4.4. Barabosch et al. (2017) — Phân tích memory dump

Barabosch et al. [3] và các công cụ memory forensic (Quincy, Volatility plugin) tiếp cận injection **offline**: dump RAM, quét vùng executable bất thường, phát hiện shellcode hoặc PE mapping thủ công. Ưu điểm: không phụ thuộc chuỗi API. Nhược điểm: không real-time, chi phí dump RAM cao, khó phân biệt JIT hợp pháp (CLR, V8, JVM), và không đối phó E5. Luận văn xem memory forensic là **bổ trợ điều tra sau sự cố**; Noirlycan kết hợp Frida + Sysmon theo hướng tracer động của [4].

## 4.5. Starink et al. (2023) — Behavior graph và memory congruence

Starink et al. [12] đề xuất **behavior graph**: node là thực thể (process, thread, memory region, handle); cạnh là quan hệ thao tác. Phát hiện injection = tìm subgraph khớp mẫu. Công trình nhấn mạnh ràng buộc **cùng buffer** — mọi primitive phải thao tác trên cùng vùng nhớ vật lý — loại trừ việc hai chuỗi thao tác trên hai vùng nhớ khác nhau bị gom nhầm thành một injection chain.

**Bảng 4.2.** So sánh behavior graph [12] và operational primitive [4]

| Khía cạnh | Starink et al. [12] | Di Pietro et al. [4] |
|-----------|---------------------|----------------------|
| Cấu trúc dữ liệu | Đồ thị đầy đủ (node/edge) | Ba primitive + equivalence class |
| Ràng buộc vùng nhớ | Same buffer (chặt) | Overlap/contain (nới lỏng) |
| Chống E1 | Phụ thuộc node label API | Equivalence class |
| Chi phí tính toán | Cao (graph matching) | Thấp (rule 2-of-3 stream) |
| Đánh giá né sandbox | Không tập trung | Có (21,2 % miss) |

Di Pietro et al. [4] đơn giản hóa *same buffer* thành **memory range congruence**: hai primitive cùng vùng nhớ nếu khoảng `[addr, addr+size)` giao hoặc chứa nhau. Cách này loại false positive khi cùng actor có nhiều allocation độc lập, đồng thời cho phép section mapping. Noirlycan hiện thực trong `_has_memory_congruence()` (`services/analysis/domain/correlation.py`). [4] cân bằng tốt hơn Starink giữa tổng quát và chi phí, tương thích stream processing event-by-event.

## 4.6. Di Pietro, D'Elia, Querzoni (ASIA CCS 2025) — Căn cứ khoa học chính

### 4.6.1. Thông tin công trình và bối cảnh

> Di Pietro, G., D'Elia, D. C., & Querzoni, L. (2025). *Can You Run My Code? A Close Look at Process Injection in Windows Malware.* ASIA CCS '25, Hanoi. DOI: 10.1145/3708821.3736206. Artifact [11].

Tác giả thuộc Sapienza University of Rome; D'Elia là tác giả Bluepill nên module anti-evasion được thiết kế đồng bộ với pipeline. Paper đặt **ba câu hỏi nghiên cứu**:

| ID | Câu hỏi | Ý nghĩa với luận văn |
|----|---------|----------------------|
| **RQ1** | Injection phổ biến đến đâu trong malware Windows 2017–2023? | Baseline prevalence; luận văn **không tái lập** |
| **RQ2** | Có phương pháp tổng quát hơn signature, đủ rẻ cho sandbox quy mô lớn? | Framework 2-of-3 — **đối tượng replication** |
| **RQ3** | Sandbox công cộng bỏ sót bao nhiêu mẫu vì anti-evasion? | 21,2 % — **động lực** đề tài |

### 4.6.2. Phương pháp cốt lõi

#### (a) Ba operational primitive và equivalence class

Đóng góp của [4] là **ánh xạ mỗi primitive sang lớp tương đương API** (Bảng 2.3). API mới chỉ cần thêm vào lớp tương ứng mà không phải sửa correlator.

**Bảng 4.3.** Lớp tương đương API theo Di Pietro et al. [4] (rút gọn)

| Primitive | Ví dụ API trong lớp | Vai trò chống né tránh |
|-----------|---------------------|------------------------|
| Allocate | `VirtualAllocEx`, `NtAllocateVirtualMemory`, `VirtualProtectEx`, `NtCreateSection`, `CreateFileMappingW`, `MapViewOfFile` | Chống E1 |
| Write | `WriteProcessMemory`, `NtWriteVirtualMemory`, `NtMapViewOfSection`, `RtlCopyMemory` | Chống E1/E2: section mapping = allocate ∧ write |
| Execute | `CreateRemoteThread(Ex)`, `NtCreateThreadEx`, `QueueUserAPC`, `SetThreadContext`, `ResumeThread`, `LoadLibrary*` | Chống E1 |

Equivalence class cho phép correlator kết luận có injection dựa trên **ngữ nghĩa**, không phụ thuộc tên API — trực tiếp đối phó E1.

#### (b) Quy tắc 2-of-3

Yêu cầu **đủ cả ba** primitive → false negative cao (malware gộp bước hoặc dùng vùng RWX sẵn có — Mockingjay, APC variants); yêu cầu **chỉ một** → false positive cao (debugger, profiler, hot-patching đều gọi `VirtualAllocEx`/`WriteProcessMemory`).

Cân bằng: **quan sát ít nhất hai primitive khác loại** trên cùng cặp `(actor_pid, target_pid)`, kèm memory congruence và temporal ordering. Quy tắc này chống **E2** vì chấp nhận malware nén ba bước thành hai. Noirlycan hiện thực `operational_kind_count(kinds) >= 2` (`services/analysis/domain/correlation.py`); `CONTEXT_READ` được ghi nhận nhưng **không tính** vào 2-of-3.

#### (c) Memory range congruence

Hai primitive *congruent* khi vùng địa chỉ giao nhau:

\[
[p_1.\text{addr},\, p_1.\text{addr}+p_1.\text{size}) \cap [p_2.\text{addr},\, p_2.\text{addr}+p_2.\text{size}) \neq \emptyset
\]

Mục đích: tránh gom nhầm allocate ở địa chỉ *a* với write ở địa chỉ *b* không liên quan. Kế thừa Starink [12], đơn giản hóa thành phép kiểm tra giao khoảng O(1).

#### (d) Temporal consistency

Thứ tự tự nhiên: Allocate → Write → Execute. Paper cho phép gộp bước (`NtMapViewOfSection` = allocate + write), lặp allocate (resize, đổi protection RW → RX), nhưng không cho phép EXECUTE trước WRITE trên cùng vùng. Noirlycan hiện thực `_has_temporal_consistency()` với bậc `ALLOCATE=0, WRITE=1, EXECUTE=3`.

### 4.6.3. Hạ tầng thực nghiệm và dataset

- **Nguồn mẫu:** VirusTotal Academic + VX Underground Bazaar, 2017–2023; 334.885 mẫu Windows → **56.340 mẫu** thuộc 2.667 family (lọc qua imphash/ssdeep).
- **Sandbox:** QEMU + custom tracer (tương tự Bluepill) + **module anti-evasion** (timing, env fingerprint, artifact). Baseline: Cuckoo, Hatching Triage.

Module anti-evasion là thành phần **không thể tách rời** khi trả lời RQ3: thiếu nó, sandbox miss vì malware **chủ động không chạy** payload (E5), không phải vì phương pháp phát hiện yếu.

### 4.6.4. Kết quả chính

**Bảng 4.4.** Tóm tắt kết quả thực nghiệm Di Pietro et al. [4]

| Chỉ số | Giá trị | Diễn giải |
|--------|---------|-----------|
| Tỷ lệ mẫu có injection (2017–2023) | **~16,5 %** | Trả lời RQ1; xu hướng tăng |
| Sandbox miss (thiếu anti-evasion) | **21,2 %** | Trả lời RQ3 — né sandbox che hành vi |
| Mẫu multi-stage đệ quy (A→B→C) | ~2 % | Injection lồng nhau |
| Biến thể dominant family đa kỹ thuật | Section-mapping hollowing | Case study *neurevt* |

Hai con số mang ý nghĩa: (1) injection không hiếm — đáng đầu tư phương pháp tổng quát; (2) né môi trường phân tích (E5) làm giảm recall ngay cả khi có phương pháp tốt.

**Lưu ý:** Hai con số thuộc paper [4]. Luận văn **không claim** đã tái lập trên 56.340 mẫu; Noirlycan chưa có module anti-evasion tương đương (Chương 3, O7). Số liệu được trích dẫn làm **động lực**.

### 4.6.5. Taxonomy kỹ thuật và case study *neurevt*

Paper phân loại **12 kỹ thuật injection chính**: Classic Remote Thread, APC, Early Bird APC, SetWindowsHookEx, Thread Hijacking, Process Hollowing (classic + section), AtomBombing, Reflective DLL, Module Stomping, Process Doppelgänging, Process Ghosting/Herpaderping.

**Case study *neurevt*** (Paper §3.5) là ví dụ điển hình **E1 + E2**: thay `VirtualAllocEx` + `WriteProcessMemory` bằng `NtCreateSection` + `NtMapViewOfSection` (gộp allocate và write, chuyển sang NT native né hook); kích hoạt qua `SetThreadContext` + `ResumeThread` trên tiến trình suspended — biến thể **Process Hollowing** dominant [4]. Signature dò `CreateRemoteThread` vô hiệu, nhưng framework 2-of-3 **không bị phá**: correlator vẫn thấy write + execute trên cùng vùng section. Noirlycan có test `test_detects_section_mapping_write_execute_chain` xác nhận kịch bản này đạt score ≥ 70.

**Hạn chế:** test trên loader PoC lab, không phải sample *neurevt* gốc. Luận văn claim **phát hiện đúng pattern primitive**, không claim đã phân tích lại family trên malware thật.

### 4.6.6. Module anti-evasion và quan hệ với đề tài

Paper §6 mô tả module anti-evasion: bypass **timing checks** (sleep acceleration, RDTSC manipulation), bypass **environment fingerprint** (registry VM, MAC, process artifact), tránh malware **skip injection**. Module này giải thích vì sao framework primitive đạt recall cao hơn Cuckoo **trên cùng corpus** — không chỉ vì 2-of-3 mà vì malware thực sự chạy trong môi trường đã che giấu.

**Bảng 4.5.** Vai trò anti-evasion trong [4] so với Noirlycan

| Khía cạnh | Paper [4] | Noirlycan |
|-----------|-----------|-----------|
| Anti-evasion timing/env | Tích hợp QEMU | **Out-of-scope** (`kernel/analysis/evasion.py` chỉ ghi signal) |
| Phát hiện primitive E1/E2 | Có (custom tracer) | Có (Frida + correlator) |
| Phát hiện khi malware không chạy (E5) | Giảm nhờ anti-evasion | **Không xử lý** |
| Số liệu 21,2 % miss | Đo trên corpus paper | Trích dẫn, không tái lập |

Luận văn tách hai lớp: (1) chống E1–E4 khi malware *đã* injection — mục tiêu chính; (2) chống E5 khi malware *không* thực hiện — paper giải quyết, luận văn khai báo ngoài phạm vi.

### 4.6.7. Hạn chế tự công bố của paper [4]

| Hạn chế | Mô tả | Ảnh hưởng luận văn |
|---------|-------|-------------------|
| User-space only | Kernel injection không trong scope | O3 threat model |
| Tracer user-mode có thể bị bypass | Direct syscall stub | E4 — Noirlycan bổ sung Sysmon kernel |
| Dataset đến 2023 | Thiếu PoolParty, Mockingjay đầy đủ | Mở rộng taxonomy qua iRed.team |
| Phụ thuộc chất lượng trace | Drop event → sai primitive count | Giả định M5 (Frida fidelity) |
| Không có file provenance end-to-end | Bắt đầu từ process đã chạy | Đóng góp RO3 luận văn |

Mỗi hạn chế ứng với một hướng mở rộng trong Noirlycan, làm cấu trúc Replication + Extension trở nên tự nhiên.

### 4.6.8. Đóng góp khoa học paper và vị trí artifact

**Bảng 4.6.** Đóng góp Di Pietro et al. [4]

| ID | Đóng góp | Loại |
|----|----------|------|
| C1 | Framework 2-of-3 + equivalence class + congruence + temporal | Methodology |
| C2 | Prevalence ~16,5 % trên 56k mẫu | Empirical |
| C3 | Sandbox miss 21,2 % — định lượng E5 | Comparative |
| C4 | Anti-evasion ablation | Engineering + Empirical |
| C5 | Phân tích biến thể theo thời gian (section mapping) | Forensic |
| C6 | Artifact công khai [11] | Reproducibility |

Artifact `Sap4Sec/process-injection` [11] là cơ sở cho RO3. Noirlycan là **implementation độc lập** trên Frida + Sysmon, audit đối chiếu paper (docs/audit-and-threat-model.md).

## 4.7. Né tránh sandbox và phân tích chống phân tích

Korkin [8] và Hosseini & Antoniou [6] khảo sát kỹ thuật malware né sandbox: phát hiện VM (CPUID, registry, driver), timing attack (sleep, RDTSC delta), kiểm tra tool (Wireshark, Procmon, Frida artifact), và hành vi có điều kiện.

**Bảng 4.7.** Phân loại né tránh sandbox và liên hệ với injection

| Kỹ thuật né tránh | Mục tiêu | Tác động lên phát hiện injection |
|-------------------|----------|----------------------------------|
| VM/sandbox fingerprint | E5 | Malware không gọi API → log trống |
| Timing / delayed execution | E5 | Injection sau window phân tích |
| User interaction gate | E5 | Sandbox batch fail |
| Anti-debug (E6) | Dừng trước inject | Miss behavior |
| Direct syscall (E4) | Né hook | Injection xảy ra nhưng mất API trace |

Chỉ [4] định lượng miss rate 21,2 % gắn trực tiếp với injection trên corpus lớn. Korkin [8] và Hosseini [6] cung cấp taxonomy E5/E6 nhưng không thay số liệu paper. Luận văn dùng để justify anti-evasion là hướng phát triển bắt buộc; Noirlycan **chưa hiện thực** module tương đương.

## 4.8. EDR thương mại và thực hành phòng thủ

EDR/EPP thương mại (Defender, Elastic Defend, CrowdStrike Falcon) kết hợp kernel driver, ETW provider, ML, và threat intelligence; cũng quan sát cross-process memory operation và thread creation — gần với primitive model. Tuy nhiên rule và model đóng nguồn (không audit được equivalence class hay 2-of-3 tương đương [4]); tối ưu production không công bố ablation né sandbox; không cung cấp pipeline provenance file→injection cho lab cá nhân.

Noirlycan **không cạnh tranh** với EDR thương mại. Vị trí: **công cụ lab mã nguồn mở**, minh bạch rule, phục vụ replication [4] và đào tạo analyst. Sysmon [10] được chọn làm lớp kernel vì phổ biến trong forensic community và có schema công khai, tránh tự viết kernel driver.

## 4.9. MITRE ATT&CK và chuẩn hóa taxonomy

MITRE ATT&CK T1055 [9] liệt kê hơn một chục sub-technique injection. Chuẩn hóa này giúp analyst giao tiếp nhưng **không cung cấp thuật toán phát hiện**.

Noirlycan `kernel/classification/technique_classifier.py` map output rule-based lên nhãn ATT&CK, mở rộng từ ~12 kỹ thuật paper lên **36 enum** (17 đạt FULL coverage: hook + classifier + test). Tách biệt giữa "phát hiện có injection" (correlator primitive) và "phân loại kỹ thuật gì" (technique classifier) giữ hai bài toán độc lập. Classifier **chưa được đánh giá** precision/recall trên ground truth corpus (Chương 3).

## 4.10. Khoảng trống nghiên cứu

**Bảng 4.8.** Khoảng trống nghiên cứu và định vị luận văn

| Khoảng trống | Paper [4] | EDR thương mại | Sandbox (Cuckoo) | Noirlycan |
|--------------|-----------|----------------|------------------|-----------|
| Framework primitive chống E1/E2 | ✅ Batch QEMU | Một phần (đóng) | Yếu (signature) | ✅ Real-time Windows lab |
| Prevalence 56k | ✅ | Không công bố | Không | ❌ Out-of-scope |
| Anti-evasion E5 | ✅ | Một phần | Yếu → 21,2 % miss | ❌ Ghi signal |
| Telemetry kernel khi E4 | Tracer tùy biến | ✅ | Guest agent dễ detect | ✅ Sysmon E8/E10/E11 |
| File provenance → injection (E3) | ❌ | Một phần | Một phần | ✅ Pipeline end-to-end |
| Công cụ analyst lab mở | Artifact batch | Đóng | Cuckoo web UI | ✅ Dashboard + JSONL |
| Audit replication có test | Artifact paper | N/A | N/A | ✅ 31+ unit test |
| Đánh giá Frida fidelity (M5) | N/A | N/A | N/A | ⚠️ Protocol đề xuất |

**Khoảng trống trung tâm:** Paper [4] chứng minh phương pháp ở quy mô sandbox batch, nhưng chưa có (a) triển khai vận hành trên endpoint Windows thật với telemetry kép kernel/user, (b) liên kết injection finding với nguồn file drop, (c) threat model formal cho từng hình thức né tránh E1–E6. Noirlycan nhắm (a)–(c) trong phạm vi **Replication + Extension**, không claim phương pháp detection mới thay [4].

---

Chương này đánh giá mức độ đạt mục tiêu *tăng cường phát hiện mã độc dưới các hình thức né tránh* thông qua artifact Noirlycan, căn cứ [4]. Phạm vi **cố ý loại trừ E5** (né sandbox/VM): module anti-evasion của [4] — tăng recall ~21,2 % — **không** được hiện thực; luận văn **không** so sánh recall với paper trên dataset 56.340 mẫu. Đánh giá tập trung năm trục: (1) kiểm chứng 2-of-3 và biến thể E1/E2 qua test; (2) case study section-mapping; (3) provenance E3; (4) telemetry kép E4; (5) protocol Frida fidelity (E6).

---

## 4.11. Câu hỏi nghiên cứu đánh giá (RQ1–RQ5)

Mỗi RQ ánh xạ tới một hoặc nhiều nhóm né tránh E1–E6 (Chương 2) và tới một loại bằng chứng khả thi (test, case study, đánh giá thiết kế).

**Bảng 4.1.** Câu hỏi đánh giá và ánh xạ nhóm né tránh

| ID | Câu hỏi | Nhóm né tránh | Tiêu chí thành công |
|----|---------|---------------|---------------------|
| **RQ1** | Hiện thực [4] có phát hiện biến thể API (E1) và gộp bước (E2)? | E1, E2 | Test correlation pass; section-mapping score ≥ 70 |
| **RQ2** | Telemetry kép Sysmon+Frida có bổ sung khi Frida miss (E4)? | E4 | Thiết kế + config E8/E10; case thiếu syscall thuần |
| **RQ3** | Pipeline provenance có gắn file-drop với injection (E3)? | E3 | Finding chứa `related_file`, metadata triage |
| **RQ4** | Classifier có nhận diện kỹ thuật né tránh hiện đại? | E1, E2 | 20 test classifier pass; đúng technique label |
| **RQ5** | Frida có đủ trung thực (fidelity) cho kết luận khoa học? | E6 | Protocol `frida-fidelity.md`; drop-rate trên VM |

**E5 out-of-scope:** cần module anti-evasion [4] §6. Số liệu ablation [4] được trích dẫn là **upper bound** lý thuyết.

---

## 4.12. Môi trường và phương pháp đo

### 4.12.1. Môi trường thí nghiệm

Môi trường đảm bảo tái lập: cấu hình YAML/XML đi kèm mã nguồn, phụ thuộc Python khoá qua `uv.lock`. VM cô lập, snapshot–rollback giữa các lần chạy loader.

| Thành phần | Cấu hình |
|------------|----------|
| OS | Windows 10/11 x64, VM cô lập |
| Sysmon | v15.x, config `configs/sysmon-noirlycan.xml` |
| Frida | Python package `frida` + `windows_injection_hooks.js` |
| Collector | `noirlycan-telemetry` 0.x, Python 3.11 |
| Test runner | `uv run pytest` hoặc `python -m pytest` |

Ground truth do tác giả gắn nhãn — rủi ro *internal validity* (xem 6.6); test phát biểu theo *specification* [4] (2-of-3, equivalence class, congruence, temporal), không theo implementation, giảm thiểu lệ thuộc.

### 4.12.2. Loại đánh giá

Sáu loại bằng chứng, từ chặt chẽ tới định tính: (1) Unit test tổng hợp chuỗi API/primitive (CI Linux); (2) Case study section-mapping tương đương *neurevt* [4]; (3) Case study mở rộng `test_aes_loader_chain_upgrades_to_critical`; (4) Baseline signature A→W→E so với correlator 2-of-3; (5) Đánh giá định tính provenance/dashboard (RQ3); (6) Protocol fidelity Frida (RQ5).

Dataset PoC-Bench (5 loader) và Paper-Subset (100 mẫu Sap4Sec) **chưa hoàn thiện**; kết quả định lượng dựa trên 31 test methodology.

---

## 4.13. Bộ test methodology (31 test)

### 4.13.1. Cấu trúc bộ test

Hai file tách theo trách nhiệm: correlation rules và classification, phản ánh hai tầng — phát hiện sự kiện đáng ngờ rồi gán nhãn MITRE.

```bash
uv run pytest tests/test_correlation.py tests/test_ired_team_classifier.py -v
```

Kết quả: **31 passed, 0 failed**.

**Bảng 4.2.** Phân bổ test

| File | Số test | Phạm vi |
|------|---------|---------|
| `test_correlation.py` | 11 | 2-of-3, congruence, temporal, scoring, provenance |
| `test_ired_team_classifier.py` | 20 | Phân loại kỹ thuật biến thể |
| **Tổng** | **31** | RQ1, RQ4 |

### 4.13.2. Chi tiết `test_correlation.py` (11 test)

Bộ test bao phủ *positive path* và *negative path*. Test reject quan trọng vì 2-of-3 nhạy: thiếu congruence hoặc temporal sẽ bùng phát FP.

| Test | Mục đích | RQ |
|------|----------|-----|
| `test_requires_two_distinct_primitives` | Một primitive W — **không** finding | RQ1 |
| `test_rejects_unrelated_memory_ranges` | WRITE @0x1000, EXECUTE @0x5000 — reject congruence | RQ1 |
| `test_detects_section_mapping_write_execute_chain` | **E2 section-mapping**, score ≥ 70, related_file | RQ1, RQ3 |
| `test_resolves_target_image_from_child_process` | Resolve `msedge.exe` từ ProcessEvent | RQ3 |
| `test_rejects_write_after_execute_temporal_order` | Fix D3 — WRITE sau EXECUTE reject | RQ1 |
| `test_set_thread_context_with_rip_overlaps_write_buffer` | Fix D1 — Rip trong buffer W | RQ1 |
| `test_detects_classic_dll_injection_chain` | A+W+E, DLL path remote thread | RQ1 |
| `test_nt_allocate_zero_address_skips_congruence_with_write_execute` | Edge NtAllocate address 0 | RQ1 |
| `test_detects_local_shellcode_staging` | Self-inject A+W, local_staging | RQ1 |
| `test_aes_loader_chain_upgrades_to_critical` | Chuỗi lab đầy đủ → CRITICAL, hollowing_section | RQ1, RQ4 |
| `test_read_only_apis_do_not_satisfy_two_of_three` | D2 — read ∉ write class | RQ1 |

### 4.13.3. Chi tiết `test_ired_team_classifier.py` (20 test — trích)

Hai mươi test biên soạn theo *ired.team* và ATT&CK, gồm biến thể chi tiết (PoolParty, Process Ghosting) lẫn cổ điển (DLL injection, thread hijack), tránh over-fit.

| Test (rút gọn) | Kỹ thuật kỳ vọng |
|----------------|-------------------|
| `test_early_bird_apc_classification` | `early_bird_apc_injection` |
| `test_local_alertable_wake_classification` | `local_apc_injection` |
| `test_poolparty_tp_work_classification` | `poolparty` |
| `test_process_ghosting_precursor_classification` | `process_ghosting` |
| `test_thread_hijack_classification` | `thread_hijack` |
| `test_reflective_dll_classification` | `reflective_dll_injection` |
| `test_section_mapping_classification` | `section_mapping_injection` |
| `test_propagate_injection_classification` | `propagate_injection` |
| `test_instrumentation_callback_classification` | `instrumentation_callback` |
| … | (10 test bổ sung APC, fiber, window, doppelgänging, …) |

20 test **pass** — RQ4 đạt trên tập rule synthetic; không tương đương precision/recall trên malware thực (xem 6.9).

---

## 4.14. Case study: Section-mapping (E2) — biến thể *neurevt*

### 4.14.1. Bối cảnh [4]

Paper [4] §3.5 (case study *neurevt*) mô tả biến thể Process Hollowing dominant: thay `VirtualAllocEx` + `WriteProcessMemory`, malware mở section bằng `NtCreateSection` rồi map vào process đích bằng `NtMapViewOfSection` với `PAGE_EXECUTE_READWRITE`; thực thi qua `SetThreadContext` + `ResumeThread` trên thread `CREATE_SUSPENDED`. Đây là **E2 — gộp bước allocate/write**: một `NtMapViewOfSection` thay hai bước, né signature đếm đủ ba API.

### 4.14.2. Thiết lập test

Test `test_detects_section_mapping_write_execute_chain` mô phỏng:

1. **File drop:** `loader.exe` trong Temp, unsigned, entropy 7,2.
2. **Process:** PID 1337, cờ `CREATE_SUSPENDED`, parent `explorer.exe`.
3. **Primitive W:** `NtMapViewOfSection` → target `msedge.exe` PID 4242, address 0x200000, `PAGE_EXECUTE_READWRITE`.
4. **Primitive E:** `ResumeThread`, address None — yêu cầu correlator kế thừa target từ context.

### 4.14.3. Kết quả

**Bảng 4.3.** Kết quả case study section-mapping

| Chỉ số | Giá trị |
|--------|---------|
| Số finding | 1 |
| Score | ≥ 70 (HIGH) |
| `related_file` | `...\loader.exe` |
| `evidence.section_mapping` | true |
| Primitive kinds | write, execute |
| Baseline signature A→W→E | **FAIL** (thiếu VirtualAllocEx, WriteProcessMemory) |
| Correlator 2-of-3 | **PASS** |

Noirlycan **phát hiện** biến thể dominant mà rule signature bỏ sót — phục vụ RQ1, chống E2. Metadata (`related_file`, `evidence.section_mapping`) đủ để analyst phục dựng câu chuyện tấn công.

### 4.14.4. Case study mở rộng — AES loader lab

`test_aes_loader_chain_upgrades_to_critical` mô phỏng chuỗi từ `aes_decrypt_loader.exe` → Edge với `NtWriteVirtualMemory`, `NtMapViewOfSection`, `GetThreadContext`, `SetThreadContext` đan xen (pattern shellcode AES). Score tăng dần: staging dưới 70, sau execute xác nhận finding **upgrade ≥ 85 (CRITICAL)**; technique `process_hollowing_section`, `execution_confirmed: true`. Correlator **upgrade** finding khi primitive mới tăng score thay vì tạo finding rời rạc — phù hợp real-time, giảm alert fatigue.

---

## 4.15. Đánh giá theo từng RQ

### 4.15.1. RQ1 — E1/E2 (methodology [4])

**ĐẠT.** 11/11 test correlation pass; 2-of-3, congruence, temporal khớp audit sau fix D1–D3; section-mapping score ≥ 70. Hạn chế: test synthetic; RQ1 áp dụng cho *specification correctness*, không cho *real-world recall*.

### 4.15.2. RQ2 — E4 (telemetry kép)

**MỘT PHẦN — thiết kế đạt, số liệu syscall thuần chưa đủ.**

**Bảng 4.4.** Đánh giá E4

| Tiêu chí | Trạng thái | Ghi chú |
|----------|------------|---------|
| Sysmon E8 CreateRemoteThread trong config | ✅ | Kernel callback |
| Sysmon E10 ProcessAccess | ✅ | OpenProcess cross-process |
| Parser ghi TelemetryEvent raw | ✅ | JSONL |
| Thí nghiệm A/B Frida + sample syscall | ❌ | Cần driver `frida-fidelity` + sample unhooked |
| Congruence khi chỉ Sysmon | ❌ | Thiếu address — đúng thiết kế |

Luận văn claim **defense-in-depth**, không thay Frida bằng Sysmon cho 2-of-3. Sysmon E10/E8 cho tín hiệu cross-process nhưng không có địa chỉ buffer; vai trò *backstop* khi Frida bị né.

### 4.15.3. RQ3 — E3 (provenance)

**MỘT PHẦN.** `test_detects_section_mapping_write_execute_chain`: `related_file` khớp loader; `test_resolves_target_image_from_child_process`: lineage qua ProcessEvent. Pipeline FileDropWatcher / Sysmon E11 → triage → `add_process(created_from_file)` → scoring +10. Chưa có metric *thời gian FileCreate → Finding* trên N mẫu thật.

### 4.15.4. RQ4 — Classifier

**ĐẠT trên 20 test.** Bao phủ kỹ thuật [4] (hollowing, APC, DLL, reflective, doppelgänging); mở rộng PoolParty, Ghosting, instrumentation callback. Chưa có precision/recall trên ground-truth dataset.

### 4.15.5. RQ5 — Frida fidelity

**CHƯA HOÀN TẤT — protocol sẵn, bảng kết quả VM cần điền.** Protocol `docs/experiments/frida-fidelity.md`: driver spawn benign + injection PoC; đo primitive Frida so với ground-truth ETW kernel; drop-rate = missed / expected theo họ API. Giả định M5: overhead Frida chấp nhận được cho lab. Phát biểu hiện ở mức "đủ minh hoạ phương pháp".

---

## 4.16. So sánh với baseline signature

### 4.16.1. Baseline định nghĩa

**Baseline Σ:** detector rule-based quan sát **lần lượt** ba API trên cùng `(actor, target)` trong cửa sổ thời gian, không equivalence class, không 2-of-3:

$$\texttt{VirtualAllocEx} \rightarrow \texttt{WriteProcessMemory} \rightarrow \texttt{CreateRemoteThread}$$

Đại diện rule SIEM/EDR dạng "string match API name" phổ biến.

### 4.16.2. Kết quả so sánh

**Bảng 4.5.** Baseline signature vs Noirlycan correlator

| Kịch bản | Baseline Σ | Noirlycan 2-of-3 | Ghi chú |
|----------|------------|------------------|---------|
| Classic DLL (test) | PASS | PASS | Tương đương |
| Section-mapping W+E | **FAIL** | **PASS** | E2 né signature |
| APC `NtQueueApcThreadEx` | **FAIL** | PASS (classifier) | E1 API variant |
| NtMapViewOfSection + Resume | **FAIL** | **PASS** | Dominant [4] |
| Chỉ WriteProcessMemory | FAIL | FAIL | Cả hai đúng (FP tránh) |
| WRITE + EXECUTE unrelated mem | FAIL | FAIL | Congruence |

Noirlycan dominates baseline trên E1/E2. Hai dòng cuối cả hai FAIL là kết quả mong muốn — giữ specificity.

---

## 4.17. So sánh với paper [4]

**Bảng 4.6.** Đối chiếu phạm vi [4] vs luận văn

| Khía cạnh | Di Pietro et al. [4] | Luận văn Noirlycan |
|-----------|----------------------|---------------------|
| Quy mô dataset | 56.340 mẫu | Unit test + case study |
| Prevalence injection | ~16,5 % | Không đo |
| Sandbox miss rate | 21,2 % (với anti-evasion) | Không đo |
| Anti-evasion E5 | ✅ Tích hợp | ❌ **Không hiện thực** |
| 2-of-3 + congruence + temporal | ✅ | ✅ (31 test) |
| Phân loại 12+ kỹ thuật | ✅ Có metric | ✅ Rule-based, chưa metric dataset |
| Endpoint real-time | ❌ | ✅ |
| File provenance E3 | ❌ | ✅ |
| Dashboard analyst | ❌ | ✅ |
| Recursive chain 2 % | ✅ Báo cáo | ⚠️ Graph only |

Recall malware thật **có thể thấp hơn** [4] vì thiếu E5 (malware phát hiện VM có thể không inject) — **gap phạm vi** đã khai báo (Chương 3). Luận văn mở rộng [4] ở ba điểm: endpoint real-time, provenance E3, dashboard.

---

## 4.18. Tổng hợp kết quả theo nhóm né tránh

**Bảng 4.7.** Tổng hợp đánh giá E1–E6

| Nhóm | Tiêu chí đo | Kết quả | Trạng thái |
|------|-------------|---------|------------|
| **E1** | Equivalence + hook coverage | 31 test pass; manifest ↔ hooks | **Đạt** |
| **E2** | 2-of-3 section-mapping | score ≥ 70; baseline FAIL | **Đạt** |
| **E3** | Provenance linkage | Test + pipeline; chưa metric N mẫu | **Một phần** |
| **E4** | Sysmon fallback | Config + thiết kế; thiếu benchmark syscall | **Một phần** |
| **E5** | Anti-sandbox | Không module | **Ngoài phạm vi** |
| **E6** | Anti-Frida | `spawn` + evasion log; fidelity pending | **Hạn chế** |

**Bảng 4.8.** Tóm tắt RQ

| RQ | Kết luận |
|----|----------|
| RQ1 | ✅ Đạt |
| RQ2 | ⚠️ Một phần |
| RQ3 | ⚠️ Một phần |
| RQ4 | ✅ Đạt (synthetic) |
| RQ5 | ⏳ Protocol có, số liệu pending |

---

## 4.19. Mối đe dọa với validity

### 4.19.1. Internal validity

Ground truth do tác giả viết — rủi ro confirmation bias, nhưng phù hợp mục đích kiểm chứng specification [4]. Edge case ResumeThread không address làm congruence suy yếu (D1 partial); giảm thiểu bằng kế thừa target qua context process.

### 4.19.2. External validity

Chỉ Windows 10/11 user-mode; không Server, không kernel injection. Không E5 → không generalize recall malware anti-VM. FP rate trên enterprise có thể khác.

### 4.19.3. Construct validity

Frida thay đổi timing — có thể ảnh hưởng race condition trong APC injection; fidelity benchmark (RQ5) đo mức ảnh hưởng. Score 0–100 là heuristic lab, chưa calibrated trên FP/FN quy mô lớn; ngưỡng HIGH/CRITICAL có thể cần điều chỉnh thực địa.

### 4.19.4. Conclusion validity

**Không** claim: thay thế sandbox/EDR thương mại; số liệu [4] trên 56.340 mẫu; phát hiện đầy đủ dưới E5/E6/kernel.

**Claim được** (với evidence Chương 4): hiện thực kiểm chứng 2-of-3 + equivalence [4] trên Windows lab; tăng cường so với baseline signature trên E1/E2; extension provenance và telemetry kép cho E3/E4 ở mức thiết kế + test.

---

## 4.20. Hạn chế và hướng bổ sung

Theo thứ tự ưu tiên triển khai:

1. **E5:** Tích hợp subset anti-evasion [4] (timing patch, env check, masking artifact VM).
2. **PoC-Bench:** Năm loader (section-map, shellcode, APC, reflective, hollowing) chạy trên VM với JSONL ground truth.
3. **Paper-Subset:** 100 mẫu Sap4Sec — đo agreement với log paper.
4. **E4 benchmark:** Sample direct-syscall so session Frida on/off.
5. **RQ5:** Hoàn thiện bảng drop-rate Frida trên VM Windows.

---

## 4.21. Phân tích chi tiết kết quả scoring

**Bảng 4.9.** Phân rã điểm case study section-mapping (ước lượng từ `_score`)

| Thành phần | Điểm cộng |
|------------|-----------|
| W + E + execution_confirmed | +45 |
| cross_process | +15 |
| section_mapping (NtMapViewOfSection) | +10 |
| executable_protection | +10 |
| CREATE_SUSPENDED | +15 |
| related_file | +10 |
| PE + unsigned | +5 +10 |
| **Tổng (cap 100)** | **≥ 70** |

Assertion `score >= 70` — không yêu cầu CRITICAL (85) vì thiếu full context hijack. Phản ánh *graded severity*: HIGH cho bằng chứng đủ alert; CRITICAL chỉ cho chuỗi đủ A/W/E và context overlap.

## 4.22. Classifier — ma trận kỹ thuật đã kiểm (20 test)

**Bảng 4.10.** Kết quả phân loại rule-based (tất cả PASS)

| # | Kỹ thuật test | Nhóm né tránh liên quan |
|---|---------------|-------------------------|
| 1 | early_bird_apc_injection | E2 — APC thay CRT |
| 2 | local_apc_injection | E2 — alertable wake |
| 3 | apc_injection | E1 — NtQueueApcThread |
| 4 | poolparty | E1 — threadpool API |
| 5 | process_ghosting | E2 — file delete transacted |
| 6 | process_doppelganging | E2 — TxF section |
| 7 | thread_hijack | E2 — context read/set |
| 8 | reflective_dll_injection | E1 — manual map |
| 9 | dll_injection | E1 — NT thread |
| 10 | section_mapping_injection | E2 — dominant [4] |
| 11 | shellcode_injection | E2 — local RWX |
| 12 | module_stomping | E2 — overwrite .text |
| 13 | hook_injection | E1 — SetWindowsHookEx |
| 14 | fiber_injection | E1 — fiber API |
| 15 | extra_window_memory_injection | E1 — window long |
| 16 | propagate_injection | Multi-stage |
| 17 | instrumentation_callback | E4-adjacent |
| 18 | process_hollowing_section | E2 — [4] dominant |
| 19 | process_hollowing_classic | E2 — unmap + write |
| 20 | pe_injection / entrypoint | E2 — patch EP |

Không có test E5 — classifier không có cơ hội chạy nếu sample không inject.

## 4.23. Đánh giá E5 — thừa nhận hạn chế (bắt buộc)

Paper [4] §6 mô tả module anti-evasion sandbox QEMU gồm: patch timing (`Sleep`, `GetTickCount`, `QueryPerformanceCounter`); che artifact VM (registry `HKLM\HARDWARE\Description\System` chứa "VBOX/VMware", MAC prefix hypervisor, `vmtoolsd.exe`); ablation **+21,2 %** mẫu injection.

Noirlycan **`kernel/analysis/evasion.py`** chỉ phát hiện và log signal (`IsDebuggerPresent`, `NtQueryInformationProcess` với `ProcessDebugPort`) — **không** patch giá trị trả về. Do đó: (1) malware E5 trong VM có thể **thoát sớm** → zero finding; (2) không replicate được 16,5 % prevalence hay 21,2 % sandbox gap; (3) RQ **cố ý bỏ qua E5** (Chương 3 §3.6).

Hướng phát triển: port subset anti-evasion Sap4Sec hoặc chế độ ETW-only giảm dấu vết Frida.

## 4.24. Đánh giá định tính dashboard và JSONL

Trên session lab thực: JSONL chứa đủ chuỗi `file` → `sysmon` → `primitive` → `finding`, replay offline; dashboard Findings hiển thị `related_file.path`, SHA256, technique badge — analyst nắm tình huống dưới 30 giây; export JSONL phục vụ lưu trữ evidence (Phụ lục C). Bổ sung RQ3 ở mức *qualitative acceptance*; đánh giá định lượng cần khảo sát người dùng — vượt phạm vi.

## 4.25. Công thức metric (định nghĩa cho mở rộng tương lai)

$$\mathrm{Precision} = \frac{TP}{TP + FP}, \quad \mathrm{Recall} = \frac{TP}{TP + FN}$$

$$\mathrm{F1} = \frac{2 \cdot \mathrm{Precision} \cdot \mathrm{Recall}}{\mathrm{Precision} + \mathrm{Recall}}$$

**TP:** finding score ≥ threshold, ground truth injection = true. **FP:** finding trên sample benign. **FN:** không sinh finding trên sample injection. Hiện chỉ có TP synthetic trong 31 test (không có FP/FN corpus); không điền số Precision/Recall giả.

## 4.26. Kiểm chứng giả thuyết H1–H5

**Bảng 4.11.** Kết quả kiểm chứng giả thuyết (theo [14], [15])

| Giả thuyết | Kết luận | Bằng chứng | Ghi chú |
|------------|----------|------------|---------|
| **H1** | **Chấp nhận** | 11 test `test_correlation.py`; NT API variants | E1: equivalence class hoạt động |
| **H2** | **Chấp nhận** | `test_detects_section_mapping_write_execute_chain`, score ≥ 70 | E2: 2-of-3 đủ với W+E |
| **H3** | **Chấp nhận một phần** | `test_file_drop_links_to_injection_finding`, dashboard qualitative | Chưa có metric forensic quy mô |
| **H4** | **Chưa đủ số liệu** | Config Sysmon E8/E10; thiết kế Bảng 3.9 | Cần loader direct-syscall |
| **H5** | **Chưa kiểm chứng** | Protocol Phụ lục E | Chờ benchmark VM Windows |

H1–H3 đủ kết luận luận văn đạt mục tiêu *tăng cường E1–E3*; H4–H5 là điều kiện cần cho claim đầy đủ E4/E6.

## 4.27. Tóm tắt chương

Chương 4 đánh giá Noirlycan theo RQ1–RQ5 và **kiểm chứng H1–H5**: **31 test pass** xác nhận methodology [4] chống E1/E2 (**H1, H2 chấp nhận**); case study **section-mapping** đạt score ≥ 70, vượt baseline; classifier pass 20 test biến thể (RQ4). Provenance E3 (**H3 một phần**) và telemetry kép E4 (**H4 chưa đủ số liệu**). **E5 không triển khai** — recall lab không so sánh được với 21,2 %. Frida fidelity (**H5 chưa kiểm chứng**) ở mức protocol. Kết quả phù hợp luận văn thạc sĩ *tăng cường phát hiện dưới E1–E4*; định hướng tiếp theo ở Chương 7.

---

Chương này tổng hợp ý nghĩa khoa học và thực tiễn, đặt kết quả Chương 6 trong bối cảnh Di Pietro et al. (ASIA CCS 2025) [4]. Trọng tâm là **phạm vi tăng cường đạt được** (E1–E4), **khoảng cách có chủ ý** so với paper (E5), và **ranh giới claim**. Luận văn định vị là *Replication + Extension Study*.

---

## 4.28. Tổng hợp ý nghĩa khoa học đối với đề tài

### 4.28.1. Câu hỏi nghiên cứu và câu trả lời

Câu hỏi trung tâm: *Có thể tăng cường phát hiện process injection khi malware né rule cứng, né hook user-mode và che nguồn gốc?* Chương 6 (31 test pass — 11 correlator, 20 classifier) trả lời **có, trong phạm vi E1–E4**, qua ba yếu tố:

1. **Phương pháp [4]** — abstraction *operational primitive* (allocate, write, execute) chịu E1 và E2 nhờ 2-of-3, memory congruence và temporal ordering. Correlator gom API cùng *semantic outcome* vào equivalence class.
2. **Telemetry kép** — Frida ∪ Sysmon giảm FN khi hook bị né (E4), *graceful degradation* ở Bảng 3.9.
3. **Pipeline provenance** — Event 11 → triage → ProcessCreate → Finding, đối trọng E3 mà [4] không mô hình hóa end-to-end.

Đóng góp ở **tăng cường thực nghiệm có kiểm chứng** và **threat model formal** cho E1–E6.

### 4.28.2. Vị trí so với số liệu quy mô lớn của [4]

**16,5 %** (prevalence) và **21,2 %** (sandbox miss) thuộc **[4]**, đo trên 56.340 mẫu với sandbox QEMU và anti-evasion. Luận văn **trích dẫn** làm động lực, **không claim** đã tái lập — dataset không công khai toàn bộ, sandbox QEMU patched vượt phạm vi thesis thạc sĩ.

**Bảng 4.1.** Phân tách vai trò số liệu [4] và kết quả luận văn

| Chỉ số | Nguồn | Vai trò | Claim |
|--------|-------|--------|-------|
| ~16,5% prevalence | [4], RQ1 | Động lực | Trích dẫn |
| 21,2% sandbox miss | [4], RQ3 | E5 giảm recall | Trích dẫn |
| 2-of-3 framework | [4], RQ2 | Căn cứ phương pháp | **Replication** có test |
| Anti-evasion ablation | [4], §6 | Giải thích sandbox miss | **Out-of-scope** |

Phân tách này là yêu cầu **trung thực khoa học** (§3.11).

### 4.28.3. Replication versus extension

**Bảng 4.2.** Phân loại đóng góp theo loại nghiên cứu

| Thành phần | Loại | Căn cứ |
|------------|------|--------|
| 2-of-3 + equivalence class + congruence + temporal | Replication [4] | `correlation.py`, 11 test |
| Section-mapping (*neurevt*-class) | Replication validation | `test_detects_section_mapping_*` |
| Audit D1/D2/D3 và fix | Methodology validation | `docs/audit-and-threat-model.md` |
| Sysmon ∪ Frida | Extension (E4) | Bảng 3.9 |
| File provenance pipeline | Extension (E3) | `file_watch.py` |
| Taxonomy 21+ enum | Extension | `technique_classifier.py`, 20 test |
| Dashboard + JSONL | Engineering artifact | `services/dashboard/` |
| Anti-evasion E5 | **Không có** | `evasion.py` ghi signal only |

---

## 4.29. Thảo luận theo từng nhóm né tránh

### 4.29.1. E1 — Biến thể API

E1 phổ biến nhất vì chi phí thấp: thay `CreateRemoteThread` bằng `NtCreateThreadEx` đủ để rule khớp tên hàm thất bại. Test `test_signature_baseline_misses_nt_api_variant`: rule Win32 **miss** biến thể NT trong khi correlator 2-of-3 **detect**. Manifest `PAPER_API_CLASSES` và `IRED_TEAM_API_CLASSES` ánh xạ cả hai họ vào cùng class ALLOCATE/WRITE/EXECUTE.

**Hạn chế:** API hiếm chưa có trong manifest (ví dụ `NtAllocateVirtualMemoryEx`) → FN có thể xảy ra (M3). Cập nhật manifest theo MITRE ATT&CK [9] là nhu cầu vận hành.

### 4.29.2. E2 — Gộp và ẩn bước

Quy tắc **2-of-3** xử lý E2: malware gộp allocate+write qua `NtCreateSection` + `NtMapViewOfSection`, hoặc bỏ allocate (Mockingjay — W+E vào RWX có sẵn), vẫn đủ nếu còn ≥2 primitive khác loại trên cùng vùng nhớ.

Case ***neurevt*** (paper §3.5) — **section-mapping hollowing** — được phát hiện với score ≥ 70. Pattern W+E cross-process vào `msedge.exe` khớp mô tả paper, dù **không** chạy lại sample gốc. Chuỗi: `NtCreateSection`, `NtMapViewOfSection`, EXECUTE (`NtQueueApcThread` hoặc `SetThreadContext`+`ResumeThread`).

**Mockingjay và PoolParty** có rule classifier; 20 test pass nhưng **chưa đánh giá trên malware thật**; PoC-Bench bắt buộc trước bảo vệ. **Temporal (D3):** `test_rejects_write_after_execute_temporal_order` — WRITE sau EXECUTE bị reject (tránh FP với JIT).

### 4.29.3. E3 — Né attribution

E3 là đóng góp **độc lập** so với [4]. Paper bắt đầu từ process đã chạy; **file-drop → spawn → inject** không được mô hình hóa end-to-end. Emotet, IcedID, Cobalt Strike thường drop file vào `%APPDATA%`/`%TEMP%`, spawn child, rồi inject từ child.

Pipeline Noirlycan:

```
Event 11 (FileCreate) → triage (SHA256, PE, entropy, Authenticode)
    → Event 1 (ProcessCreate, parent/child)
    → Frida primitives → Finding.related_file
```

Test `test_detects_section_mapping_write_execute_chain` và `test_resolves_target_image_from_child_process` xác nhận liên kết **định tính**; metric FileCreate→Finding chưa điền số.

**Giới hạn E3:** payload packed (C5) che static triage; **memory-only loader** không kích hoạt Event 11 — phụ thuộc Frida + Sysmon E1 lineage (reflective loading, Module Stomping); parent PID spoofing qua `UpdateProcThreadAttribute` không được chống đầy đủ.

### 4.29.4. E4 — Né hook user-mode

Bảng 3.9 là điểm tăng cường so với single-layer tracer [4]. Hell's Gate / Halo's Gate / Tartarus Gate tự đọc syscall number, tự assemble `syscall` — hook user-mode bị bypass.

Khi malware **direct syscall** hoặc **unhook** `ntdll.dll` (O1/O2):

| Lớp | Trạng thái | Hệ quả |
|-----|------------|--------|
| Frida export hook | Miss toàn bộ | Mất address/size → congruence yếu |
| Sysmon Event 8 (CreateRemoteThread) | Vẫn fire (kernel ETW TI) | Fallback EXECUTE coarse |
| Sysmon Event 10 (ProcessAccess) | Vẫn fire | Fallback access pattern |
| Correlator | Degraded mode | Finding ngưỡng thấp; classifier kém chi tiết |

**Graceful degradation** — recall giảm, **không về zero**. Sysmon callback ở kernel — mọi syscall đều phải đi qua. Tuy nhiên **thiếu benchmark định lượng**: chưa có session so sánh loader direct-syscall với Frida on/off. ETW TI là hướng thu syscall args từ kernel thay Frida.

### 4.29.5. E5 — Né sandbox (hạn chế lớn nhất)

Paper [4] định lượng **21,2 %** miss khi thiếu anti-evasion — malware phát hiện VM/timing rồi **không thực hiện** injection. Module paper patch ở QEMU TCG: giả timing, giả `CPUID`, ẩn registry VMware/VirtualBox, can thiệp `GetSystemTimeAsFileTime`.

Luận văn **không triển khai** module tương đương; `kernel/analysis/evasion.py` chỉ **ghi signal**. Hệ quả: malware E5 có thể thoát sớm → zero finding; recall lab **không so sánh được** với paper; tên đề tài **rộng hơn** phạm vi (E1–E4).

Đề tài tập trung né tránh **ở tầng triển khai injection và instrumentation** (E1–E4), không phải **môi trường phân tích** (E5). Số liệu 21,2 % là **upper bound lý thuyết**, formal hóa ở O7 và §3.11.2.

### 4.29.6. E6 — Anti-instrumentation

Frida inject **agent** vào process target — surface lớn hơn tracer QEMU. E6 gồm: scan `frida-agent`, port 27042, timing hook, thread `gum-js-loop`. Luận văn mitigates **một phần** qua `spawn` mode và auto-attach victim; **không** stealth agent (O5 out-of-scope). Recall trên malware anti-analysis thực có thể thấp hơn 31 test synthetic; claim phụ thuộc Frida phải gắn *conditional on Frida not being detected* (M5).

**Bảng 4.3.** Tóm tắt thảo luận E1–E6

| Nhóm | Tăng cường | Evidence | Hạn chế |
|------|------------|----------|---------|
| E1 | Cao | 31 test; NT API variant | API ngoài manifest |
| E2 | Cao | Section-mapping ≥70 | Mockingjay/PoolParty chưa malware thật |
| E3 | TB–cao | Provenance test; E11→E1 | Memory-only; packed |
| E4 | TB | Bảng 3.9; Sysmon config | Thiếu benchmark syscall |
| E5 | **Không** | Trích dẫn [4] 21,2% | Không anti-evasion module |
| E6 | Thấp | spawn; limitation doc | Anti-Frida (O5) |

---

## 4.30. So sánh với các hướng tiếp cận khác

### 4.30.1. Signature và rule API (Sigma, YARA behavior)

**Ưu:** triển khai nhanh, latency thấp. **Nhược:** thua E1 và E2 — thay Win32 sang NT đủ để miss. Noirlycan không thay rule production — phục vụ **nghiên cứu, đào tạo, audit**.

### 4.30.2. Behavior graph (Starink et al. [12])

Đồ thị hành vi đầy đủ với ràng buộc *same buffer* chặt hơn; chi phí graph matching cao, khó scale endpoint. [4] đơn giản hóa thành stream rule 2-of-3 — luận văn bám [4] vì cân bằng độ tổng quát và chi phí lab (Bảng 2.2).

### 4.30.3. EDR thương mại

Defender, Elastic Defend, CrowdStrike Falcon kết hợp kernel driver, ML, cloud correlation — vượt phạm vi luận văn; rule **đóng nguồn**. Noirlycan: mã nguồn mở, threat model minh bạch. Sysmon [10] chọn vì driver ký Microsoft và schema công khai.

### 4.30.4. Sandbox động (Cuckoo, Hatching Triage)

[4] chứng minh **21,2 %** miss khi thiếu anti-evasion. Noirlycan bổ sung **quan sát endpoint real-time** trong lab cô lập — bổ trợ, không cạnh tranh quy mô 56k mẫu.

**Bảng 4.4.** So sánh tổng hợp hướng tiếp cận

| Tiêu chí | Signature | [4] QEMU | Sandbox | EDR | Noirlycan |
|----------|-----------|----------|---------|-----|-----------|
| E1 | Yếu | Mạnh | Yếu–TB | Khá–Mạnh | Mạnh |
| E2 | Yếu | Mạnh | Yếu | Khá | Mạnh |
| E3 provenance | TB | Yếu | TB | Khá | **Extension** |
| E4 | Yếu | TB | TB | Mạnh | TB (Sysmon) |
| E5 | TB | **Mạnh** | Yếu (21,2%) | Khá | **Không** |
| Mở nguồn | Có | Artifact [11] | Một phần | Không | **Có** |
| Real-time endpoint | Có | Không | Không | Có | **Có (lab)** |

---

## 4.31. Độ tin cậy của kết quả thực nghiệm

### 4.31.1. Internal validity

Ground truth 31 test do **tác giả gắn nhãn** — phù hợp kiểm chứng *specification* [4] nhưng yếu về đại diện malware thật. Rủi ro bias: người viết test cũng viết correlator. Giảm thiểu: audit code-vs-paper phát hiện D1/D2/D3; Paper-Subset 100 mẫu Sap4Sec [11] và PoC-Bench (§6.10).

### 4.31.2. External validity

Chỉ **Windows 10/11 client x64**, lab VM cô lập. Không Server, ARM, enterprise fleet đa EDR. **Không khái quát hóa** sang production. Dataset [4] giai đoạn 2017–2023 — kỹ thuật 2024+ có rule classifier nhưng **chưa evaluate** trên corpus.

### 4.31.3. Construct validity

- **M1 (ba primitive):** không cover kernel injection (O3) — đúng phạm vi user-mode. BYOVD cần telemetry khác (DSE, HVCI logs).
- **M4 (memory congruence):** D1 (execute thiếu address) đã fix một phần qua Rip/`lpStartAddress`; edge case `ResumeThread` không context vẫn suy yếu congruence.
- **M5 (Frida fidelity):** protocol có; **drop-rate chưa điền** — claim phụ thuộc Frida phải gắn *conditional on M5*. Frida overhead thay đổi timing — có thể ảnh hưởng race APC hiếm.

### 4.31.4. Conclusion validity

| Không claim | Có thể claim |
|-------------|--------------|
| Prevalence 16,5% / miss 21,2% | 31 test pass; section-mapping ≥70 |
| Precision/recall corpus lớn | Vượt baseline signature E1/E2 (test) |
| Chống E5 toàn diện | Provenance + telemetry kép (test định tính) |
| Thay EDR/sandbox production | Replication [4] trên Windows lab |

---

## 4.32. Ý nghĩa thực tiễn

### 4.32.1. Phòng lab an ninh mạng giáo dục

Hệ thống phù hợp tại khoa CNTT — UET và tương tự: **giảng dạy** MITRE T1055 [9] với loader PoC MessageBox; **điều tra số** correlate file drop với injection; **thesis replication** fork artifact, chạy subset Sap4Sec, mở rộng anti-evasion E5.

### 4.32.2. Giới hạn triển khai production

**Không khuyến nghị** deploy như EDR production: thiếu authentication dashboard, scale multi-host, hardening O4/O5, SLA. Noirlycan là **research prototype** — analyst review bắt buộc. Dashboard Django chưa có RBAC, audit log, TLS bắt buộc.

### 4.32.3. Tích hợp workflow SOC (tương lai)

Finding JSONL có thể ingest SIEM (Elasticsearch, Splunk) qua parser tùy chỉnh — hướng mở rộng ngoài phạm vi luận văn.

---

## 4.33. Đạo đức nghiên cứu

Luận văn tuân thủ nguyên tắc nghiên cứu mã độc có trách nhiệm: (1) **cô lập** VM không kết nối mạng sản xuất, snapshot revert; (2) **PoC an toàn** dùng MessageBox; (3) **không phát tán** hash/mẫu từ [11]; (4) **trích dẫn** [4], [11] đúng license và DOI; (5) **transparency** threat model và limitation E5/E6 công khai.

---

## 4.34. Giải thích tên đề tài versus phạm vi hiện thực

Tên đề tài rộng (bao gồm E5). Phạm vi hiện thực **cố ý thu hẹp** E1–E4 vì module anti-evasion [4] là engineering riêng (QEMU TCG patch) vượt phạm vi thesis một năm. Replication lõi [4] + extension lab đã đủ đóng góp nếu trung thực về E5. E5 là **hướng phát triển bắt buộc** (Kết luận §4), không phải thất bại im lặng.

---

## 4.35. Hướng phát triển

**Bảng 4.5.** Lộ trình ưu tiên hướng phát triển

| Ưu tiên | Hướng | Đối phó | Nguồn |
|---------|-------|---------|-------|
| Cao | Anti-evasion subset | E5 | [11], paper §6 |
| Cao | Benchmark direct-syscall | E4 | PoC + Frida on/off |
| Cao | Frida fidelity benchmark (M5) | E6, construct | `frida-fidelity.md` |
| Trung | ETW TI provider | E4 | Thay Frida args |
| Trung | PoC-Bench + Paper-Subset 100 | E1, E2 | Sap4Sec [11] |
| Trung | Fix D1/D3 hoàn chỉnh | Congruence/temporal | Hooks + correlator |
| Thấp | ML classifier primitive sequence | E1 edge | Thay rule |
| Thấp | Cross-host correlation | Multi-stage | `injection_graph.py` |

**Gần (6–12 tháng):** hoàn thiện M5 + PoC-Bench. **Trung hạn:** port subset anti-evasion → claim "tăng cường dưới E5". **Dài hạn:** kernel ETW thay Frida — giảm E6, tăng tin cậy E4.

---

## 4.36. Bài học cho nghiên cứu replication

1. **Audit code-vs-paper trước khi claim** — D1/D2/D3 cho thấy implementation "gần đúng" vẫn có thể sai diễn giải (D1 ban đầu cho EXECUTE đóng góp 2-of-3 mà không có entry address → congruence bypass).
2. **Tách số liệu paper và thesis** — 16,5 %/21,2 % là của [4], không của Noirlycan.
3. **Extension phải map threat model** — provenance và Sysmon fallback có giá trị khi gắn E3/E4 cụ thể.

---

## 4.37. Tóm tắt chương

Luận văn **tăng cường có căn cứ** dưới **E1–E4** qua replication [4], kiến trúc Sysmon ∪ Frida, và pipeline provenance; **chưa** tăng cường dưới **E5**. Số liệu 16,5 % và 21,2 % [4] là động lực, không phải kết quả luận văn. So với signature, behavior graph [12], sandbox và EDR, Noirlycan là **công cụ lab mở, audit được, real-time endpoint**. Hạn chế validity đã khai báo; hướng phát triển ưu tiên anti-evasion E5, benchmark E4, và Frida fidelity M5. Luận văn định vị là **Replication + Extension Study** với Di Pietro et al. [4] là xương sống lý luận.