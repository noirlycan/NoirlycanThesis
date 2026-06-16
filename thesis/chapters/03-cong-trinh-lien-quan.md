# CHƯƠNG 2. CÔNG TRÌNH LIÊN QUAN

Chương này khảo sát các hướng nghiên cứu và thực hành liên quan đến phát hiện process injection trên Windows, với trọng tâm đặt vào khả năng **chống né tránh** (*anti-evasion*) ở các tầng khác nhau: biến thể triển khai API, gộp bước injection, né attribution, né hook user-mode, và né sandbox. Mục tiêu là xác định vị trí khoa học của luận văn *Tăng cường phát hiện mã độc dưới các hình thức né tránh* so với công trình căn cứ Di Pietro, D'Elia và Querzoni (ASIA CCS 2025) [4], đồng thời làm rõ khoảng trống mà hệ thống Noirlycan nhắm tới lấp đầy.

## 2.1. Bối cảnh: cuộc đua vũ trang giữa phát hiện và né tránh

Process injection (MITRE ATT&CK T1055 [9]) vẫn là kỹ thuật then chốt của malware Windows hiện đại vì ba lý do gắn trực tiếp với né tránh. Thứ nhất, malware thực thi payload trong tiến trình nạn nhân uy tín (`explorer.exe`, trình duyệt, binary ký số) thay vì tạo tiến trình mới dễ bị EDR chặn — đây là hình thức **né attribution** (E3). Thứ hai, mỗi triển khai injection có thể chọn tập API khác nhau (`CreateRemoteThread` so với `NtCreateThreadEx`, `VirtualAllocEx` so với section mapping) để lách rule cứng — **biến thể API** (E1). Thứ ba, malware có thể phát hiện sandbox hoặc debugger rồi không thực hiện injection, khiến phân tích động trả về kết quả âm tính giả — **né sandbox** (E5).

Phương pháp phát hiện truyền thống chia thành ba nhóm chính (Bảng 2.1). Không nhóm nào tự thân giải quyết đồng thời mọi hình thức né tránh; cộng đồng nghiên cứu hai thập kỷ qua đã dần chuyển từ khớp chuỗi API cụ thể sang mô hình hóa hành vi ở mức trừu tượng hơn — *operational primitive* — nơi Di Pietro et al. [4] đóng vai trò mốc quan trọng nhất trong phạm vi luận văn này.

**Bảng 2.1.** Phân loại hướng tiếp cận phát hiện process injection và khả năng chống né tránh

| Nhóm | Cơ chế cốt lõi | Đại diện | Chống E1 (biến thể API) | Chống E2 (gộp/ẩn bước) | Chống E3 (attribution) | Chống E4 (né hook) | Chống E5 (sandbox) |
|------|----------------|----------|-------------------------|-------------------------|------------------------|--------------------|--------------------|
| Signature / rule API | Khớp chuỗi hoặc tập API cố định | Sigma, YARA behavior, rule AV | Yếu | Yếu–trung bình | Yếu | Yếu (hook user-mode) | Trung bình (phụ thuộc môi trường) |
| Behavior graph | Đồ thị quan hệ handle, vùng nhớ, tiến trình | Starink et al. [12] | Khá | Khá | Trung bình | Trung bình | Phụ thuộc anti-evasion |
| Operational primitive | Ba thao tác allocate/write/execute + equivalence class | Klein [7], **Di Pietro et al. [4]** | **Mạnh** | **Mạnh** (quy tắc 2-of-3) | Yếu (paper không trọng tâm) | Trung bình (tracer user-mode) | **Cần module anti-evasion** |
| Memory forensic | Quét vùng thực thi trong RAM | Barabosch et al. [3], Quincy | Mạnh (offline) | Mạnh (offline) | Trung bình | Không áp dụng real-time | Không real-time |
| EDR thương mại | Rule + ML + kernel driver | Microsoft Defender, Elastic, CrowdStrike | Khá–mạnh (đóng nguồn) | Khá | Khá | Mạnh (kernel) | Khá (tùy sản phẩm) |

Luận văn chọn [4] làm **căn cứ phương pháp chính** vì đây là công trình duy nhất trong phạm vi nghiên cứu vừa (a) đề xuất framework phát hiện chịu biến thể triển khai, vừa (b) **định lượng trực tiếp** tác động né tránh sandbox lên tỷ lệ phát hiện injection trên dataset quy mô lớn (56.340 mẫu), vừa (c) công bố artifact tái lập được [11]. Các công trình còn lại được xem xét như nền tảng lý thuyết, đối chiếu, hoặc bối cảnh thực hành.

## 2.2. Phát hiện dựa trên signature và rule API

Phương pháp signature — khớp chuỗi lệnh gọi API, hash, chuỗi byte, hoặc rule Sigma/YARA trên log hệ thống — vẫn phổ biến trong SOC và AV vì chi phí triển khai thấp và độ trễ nhỏ. Một rule điển hình cho classic remote thread injection có thể yêu cầu tuần tự `OpenProcess` → `VirtualAllocEx` → `WriteProcessMemory` → `CreateRemoteThread`. Cách tiếp cận này hiệu quả với mẫu không đa hình, nhưng **dễ bị phá** bởi E1: thay `CreateRemoteThread` bằng `NtCreateThreadEx` hoặc `RtlCreateUserThread` là đủ để rule thất bại nếu rule không liệt kê mọi biến thể. Tương tự, E2 phá signature khi malware gộp allocate và write vào một lệnh gọi `NtMapViewOfSection` sau `NtCreateSection`.

Hạn chế cơ bản của signature không nằm ở implementation cụ thể mà ở **mức trừu tượng quá thấp**: rule mô tả *cách* malware triển khai injection thay vì *điều gì* bắt buộc phải xảy ra trên bộ nhớ nạn nhân. Di Pietro et al. [4] lập luận rằng phương pháp signature và behavior graph cứng (khớp đồ thị API chính xác) tạo false negative đáng kể trên malware thực tế đa hình API — kết luận được củng cố bằng số liệu 21,2 % mẫu injection bị sandbox miss (mục 2.6.4). Luận văn **không** đề xuất phương pháp signature mới; thay vào đó, hiện thực framework primitive của [4] như lớp phát hiện semantic nằm trên signature.

## 2.3. Klein et al. (2017) — Phân loại operational primitive

Klein et al. [7] là công trình nền tảng đặt ra ba bước tối thiểu mọi process injection user-mode phải thực hiện trên bộ nhớ tiến trình nạn nhân:

1. **Allocate** — cấp phát hoặc chuẩn bị vùng nhớ có thể chứa mã thực thi (bao gồm thay đổi page protection).
2. **Write** — đặt payload vào vùng nhớ đó.
3. **Execute** — kích hoạt luồng thực thi từ vùng nhớ đó.

Đóng góp của Klein nằm ở **mô hình khái niệm**: thay vì liệt kê hàng chục kỹ thuật injection riêng lẻ, ba primitive mô tả *bản chất thao tác* mà mọi kỹ thuật phải tuân theo. Tuy nhiên, công trình [7] chưa xây dựng:

- **Lớp tương đương API** (*equivalence class*) — không chỉ rõ `NtAllocateVirtualMemory` và `VirtualAllocEx` thuộc cùng primitive allocate;
- **Quy tắc quyết định** khi chỉ quan sát được hai trong ba primitive (trường hợp gộp bước hoặc ẩn bước — E2);
- **Ràng buộc vùng nhớ** để phân biệt injection chain với nhiều thao tác heap độc lập;
- **Đánh giá quy mô lớn** trên corpus malware thực tế và phân tích né tránh sandbox.

Di Pietro et al. [4] kế thừa trực tiếp ba primitive của Klein và bổ sung bốn thành phần phương pháp (equivalence class, quy tắc 2-of-3, memory congruence, temporal ordering) — biến mô hình khái niệm thành **framework phát hiện có thể triển khai và đo lường**. Trong repo Noirlycan, định nghĩa `PrimitiveKind.ALLOCATE / WRITE / EXECUTE` trong `kernel/entities/models.py` và manifest `PAPER_API_CLASSES` trong `kernel/classification/api_manifest.py` bám sát phân loại Klein–Di Pietro.

**Hạn chế kế thừa:** Klein (và paper [4]) giới hạn user-mode injection; kernel-mode injection (driver-based, kernel APC) nằm ngoài ba primitive này. Luận văn khai báo giới hạn tương tự (Chương 3, O3).

## 2.4. Barabosch et al. (2017) — Phân tích memory dump

Barabosch et al. [3] và các công cụ memory forensic (Quincy, Volatility plugin) tiếp cận injection từ góc **offline**: dump RAM, quét vùng executable bất thường, phát hiện shellcode hoặc PE mapping thủ công trong tiến trình nạn nhân. Ưu điểm: không phụ thuộc chuỗi API — malware đã thực thi xong vẫn để lại dấu vết trong bộ nhớ, chống hiệu quả E1 và E2 *sau khi* injection hoàn tất.

Nhược điểm đối với mục tiêu luận văn:

- **Không real-time** — không phù hợp endpoint monitoring liên tục;
- **Chi phí I/O cao** — dump toàn bộ RAM không khả thi trên mọi host;
- **Không ghi nhận chuỗi thao tác** — khó phân biệt injection với JIT hợp pháp hoặc self-modifying code benign;
- **Không đối phó E5** — nếu malware không inject trong sandbox, memory dump cũng không có gì để phát hiện.

Luận văn xem memory forensic là **bổ trợ điều tra sau sự cố**, không thay thế pipeline telemetry real-time của Noirlycan. Quan hệ với [4]: paper dùng tracer động (tương tự EDR) thay vì dump RAM; Noirlycan kết hợp Frida + Sysmon theo hướng đó.

## 2.5. Starink et al. (2023) — Behavior graph và memory congruence

Starink et al. [12] đề xuất mô hình **behavior graph**: các node là thực thể (process, thread, memory region, handle); các cạnh là quan hệ thao tác (allocate, write, execute, open). Phát hiện injection = tìm subgraph khớp mẫu injection trong đồ thị hành vi. Công trình nhấn mạnh ràng buộc **cùng buffer** — mọi primitive phải thao tác trên cùng vùng nhớ vật lý, không chỉ cùng process pair.

**Bảng 2.2.** So sánh behavior graph [12] và operational primitive [4]

| Khía cạnh | Starink et al. [12] | Di Pietro et al. [4] |
|-----------|---------------------|----------------------|
| Cấu trúc dữ liệu | Đồ thị đầy đủ (node/edge) | Ba primitive + equivalence class |
| Ràng buộc vùng nhớ | Same buffer (chặt) | Overlap/contain (nới lỏng có chứng minh) |
| Chống E1 | Phụ thuộc node label API | Equivalence class gom API tương đương |
| Chi phí tính toán | Cao hơn (graph matching) | Thấp hơn (rule 2-of-3 trên stream event) |
| Triển khai sandbox batch | Có | Có (QEMU + custom tracer) |
| Đánh giá né sandbox | Không tập trung | Có (21,2 % miss rate) |

Di Pietro et al. [4] đơn giản hóa ràng buộc *same buffer* của Starink thành **memory range congruence**: hai primitive *p₁*, *p₂* được coi là cùng vùng nhớ nếu khoảng địa chỉ nửa mở `[addr, addr+size)` của chúng giao nhau hoặc chứa nhau. Cách này đủ để loại false positive khi cùng actor thực hiện nhiều allocation độc lập, đồng thời cho phép section mapping (một API gắn với hai primitive). Noirlycan hiện thực trực tiếp quy tắc overlap trong `_has_memory_congruence()` (`services/analysis/domain/correlation.py`).

**Hạn chế Starink so với luận văn:** behavior graph vẫn có thể bị E1 nếu node label gắn cứng tên API thay vì equivalence class; chi phí đồ thị khó scale trên endpoint cá nhân. [4] được chọn vì cân bằng tốt hơn giữa độ tổng quát và chi phí triển khai lab.

## 2.6. Di Pietro, D'Elia, Querzoni (ASIA CCS 2025) — Căn cứ khoa học chính

### 2.6.1. Thông tin công trình và bối cảnh

> Di Pietro, G., D'Elia, D. C., & Querzoni, L. (2025). *Can You Run My Code? A Close Look at Process Injection in Windows Malware.* Proceedings of the 20th ACM Asia Conference on Computer and Communications Security (ASIA CCS '25), Hanoi, Vietnam. DOI: 10.1145/3708821.3736206. Artifact: [github.com/Sap4Sec/process-injection](https://github.com/Sap4Sec/process-injection) [11].

Tác giả thuộc Sapienza University of Rome; nhóm có kinh nghiệm phân tích malware động và sandbox evasion (D'Elia là tác giả framework Bluepill). Paper được công bố tại ASIA CCS 2025 ở Hà Nội — bối cảnh phù hợp luận văn thạc sĩ tại Việt Nam và tạo điều kiện truy cập artifact công khai.

Paper đặt ra **ba câu hỏi nghiên cứu (RQ)**:

| ID | Câu hỏi | Ý nghĩa với luận văn |
|----|---------|----------------------|
| **RQ1** | Process injection phổ biến đến đâu trong malware Windows 2017–2023? | Cung cấp baseline prevalence; luận văn **không tái lập** trên 56k mẫu |
| **RQ2** | Có phương pháp tổng quát hơn signature API, đủ rẻ cho sandbox quy mô lớn? | Framework 2-of-3 — **đối tượng replication** của Noirlycan |
| **RQ3** | Sandbox công cộng bỏ sót bao nhiêu mẫu injection vì anti-evasion? | 21,2 % — **động lực** cho đề tài né tránh; luận văn trích dẫn, không claim lại |

### 2.6.2. Phương pháp cốt lõi

#### (a) Ba operational primitive và equivalence class

Mọi injection user-mode phải thực hiện allocate, write, execute trên bộ nhớ nạn nhân [7]. Đóng góp phương pháp của [4] là **ánh xạ mỗi primitive sang lớp tương đương API** (Bảng 2.3 — rút gọn từ Table 1 paper và `PAPER_API_CLASSES` trong repo).

**Bảng 2.3.** Lớp tương đương API theo Di Pietro et al. [4] (rút gọn)

| Primitive | Ví dụ API trong lớp | Vai trò chống né tránh |
|-----------|---------------------|------------------------|
| Allocate | `VirtualAllocEx`, `NtAllocateVirtualMemory`, `VirtualProtectEx`, `NtCreateSection`, `CreateFileMappingW`, `MapViewOfFile` | Chống E1: thay API cấp phát |
| Write | `WriteProcessMemory`, `NtWriteVirtualMemory`, `NtMapViewOfSection`, `RtlCopyMemory` | Chống E1/E2: section mapping = allocate ∧ write |
| Execute | `CreateRemoteThread(Ex)`, `NtCreateThreadEx`, `QueueUserAPC`, `SetThreadContext`, `ResumeThread`, `LoadLibrary*` | Chống E1: thay cơ chế kích hoạt thực thi |

Equivalence class cho phép correlator kết luận *có injection* khi quan sát **ngữ nghĩa** ba thao tác, không phụ thuộc tên API cụ thể — trực tiếp đối phó E1.

#### (b) Quy tắc 2-of-3

Paper lập luận:

- Yêu cầu **đủ cả ba** primitive → false negative cao (malware gộp bước hoặc khai thác vùng RWX sẵn có — Mockingjay, một số biến thể APC).
- Yêu cầu **chỉ một** primitive → false positive cao (nhiều ứng dụng hợp pháp gọi `VirtualAllocEx` hoặc `WriteProcessMemory` trong debug/optimization).

Cân bằng: **quan sát ít nhất hai primitive khác loại** trên cùng cặp `(actor_pid, target_pid)`, kèm memory congruence và temporal ordering. Quy tắc này là cơ chế chính chống **E2** (gộp/ẩn bước). Trong Noirlycan, điều kiện `operational_kind_count(kinds) >= 2` trong `services/analysis/domain/correlation.py` hiện thực trực tiếp quy tắc này; `CONTEXT_READ` (từ `GetThreadContext`) được ghi nhận nhưng **không tính** vào 2-of-3 — đúng tinh thần paper.

#### (c) Memory range congruence

Hai primitive *congruent* khi vùng địa chỉ giao nhau:

\[
[p_1.\text{addr},\, p_1.\text{addr}+p_1.\text{size}) \cap [p_2.\text{addr},\, p_2.\text{addr}+p_2.\text{size}) \neq \emptyset
\]

Mục đích: tránh gom nhầm allocate ở địa chỉ *a* với write ở địa chỉ *b* không liên quan trong cùng process pair. Kế thừa tinh thần Starink [12], đơn giản hóa cho stream processing.

#### (d) Temporal consistency

Thứ tự tự nhiên: Allocate → Write → Execute. Paper **cho phép**:

- **Gộp bước** trong một API (`NtMapViewOfSection` = allocate + write đồng thời);
- **Lặp allocate** (resize, đổi protection RW → RX sau write).

Paper **không cho phép** đảo bậc nghiêm trọng (execute trước write trên cùng vùng). Noirlycan hiện thực qua `_has_temporal_consistency()` với bậc `ALLOCATE=0, WRITE=1, EXECUTE=3`.

### 2.6.3. Hạ tầng thực nghiệm và dataset

Paper xây pipeline phân tích trên:

- **Nguồn mẫu:** VirusTotal Academic + VX Underground Bazaar, giai đoạn 2017–2023;
- **Lọc:** 334.885 mẫu Windows → **56.340 mẫu** đại diện thuộc 2.667 family;
- **Sandbox:** QEMU + custom tracer (tương tự Bluepill) + **module anti-evasion** (bypass timing check, env fingerprint);
- **Baseline so sánh:** Cuckoo Sandbox, Hatching Triage, và các công cụ phổ biến khác.

Module anti-evasion là thành phần **không thể tách rời** khi paper trả lời RQ3: without anti-evasion, sandbox miss injection vì malware **chủ động không chạy** payload (E5), không phải vì phương pháp phát hiện primitive yếu.

### 2.6.4. Kết quả chính — prevalence, sandbox miss, và ý nghĩa né tránh

**Bảng 2.4.** Tóm tắt kết quả thực nghiệm Di Pietro et al. [4]

| Chỉ số | Giá trị | Diễn giải |
|--------|---------|-----------|
| Tỷ lệ mẫu có injection (2017–2023) | **~16,5 %** | Trả lời RQ1; xu hướng tăng theo năm |
| Mẫu injection bị sandbox miss (thiếu anti-evasion) | **21,2 %** | Trả lời RQ3; **né sandbox che hành vi injection** |
| Mẫu multi-stage đệ quy (A→B→C) | ~2 % | Injection lồng nhau — paper theo dõi re-trace |
| Biến thể dominant trong family đa kỹ thuật | Section-mapping hollowing | Case study *neurevt* |

Hai con số **16,5 %** và **21,2 %** mang ý nghĩa kép cho luận văn:

1. **16,5 %** khẳng định injection không phải kỹ thuật hiếm — đáng đầu tư phương pháp phát hiện tổng quát, không chỉ rule cho từng kỹ thuật.
2. **21,2 %** chứng minh **né tránh môi trường phân tích** (E5) làm giảm recall đáng kể ngay cả khi đã có phương pháp phát hiện tốt — sandbox không có anti-evasion *under-report* prevalence thực tế.

**Lưu ý quan trọng (trung thực khoa học):** Hai con số trên thuộc **paper [4]**, đo trên corpus và hạ tầng của tác giả. Luận văn **không được claim** đã tái lập prevalence trên 56.340 mẫu; Noirlycan chưa tích hợp module anti-evasion tương đương (Chương 3, O7). Số liệu được trích dẫn làm **động lực và baseline tham chiếu**, không phải kết quả của luận văn.

Ablation anti-evasion trong [4]: khi bật module chống timing/env check, tỷ lệ phát hiện injection tăng tương ứng phần sandbox đã miss — chứng minh một phần 21,2 % là do **malware không thực hiện hành vi**, không phải do correlator primitive không nhận ra pattern khi có log.

### 2.6.5. Taxonomy kỹ thuật và case study *neurevt*

Paper phân loại **12 kỹ thuật injection chính** trong dataset: Classic Remote Thread, APC, Early Bird APC, SetWindowsHookEx, Thread Hijacking, Process Hollowing (classic + section variant), AtomBombing, Reflective DLL, Module Stomping, Process Doppelgänging, Process Ghosting/Herpaderping, và các biến thể liên quan. Mỗi kỹ thuật ánh xạ lên tập primitive và equivalence class tương ứng.

**Case study *neurevt*** (Paper §3.5) là ví dụ điển hình **E1 + E2**:

- Thay cặp `VirtualAllocEx` + `WriteProcessMemory` bằng `NtCreateSection` + `NtMapViewOfSection` (local và remote) — **gộp allocate và write**;
- Kích hoạt thực thi qua `SetThreadContext` + `ResumeThread` trên tiến trình suspended — biến thể **Process Hollowing** dominant trong family đa kỹ thuật của dataset [4].

Paper coi đây là minh chứng framework 2-of-3 **không bị phá** bởi section mapping: correlator vẫn thấy write + execute (hoặc allocate + execute) trên cùng vùng section. Noirlycan có test `test_detects_section_mapping_write_execute_chain` xác nhận kịch bản `NtMapViewOfSection` + `ResumeThread` cross-process vào `msedge.exe` đạt score ≥ 70 — trực tiếp phản ánh case study paper.

**Hạn chế case study trong luận văn:** test trên loader PoC lab, không phải sample *neurevt* gốc từ corpus 56k. Luận văn claim **phát hiện đúng pattern primitive** của biến thể section-mapping, không claim đã phân tích lại family *neurevt* trên malware thật.

### 2.6.6. Module anti-evasion và quan hệ với đề tài

Paper §6 mô tả module anti-evasion tích hợp trong sandbox:

- Bypass **timing checks** (sleep acceleration, RDTSC manipulation detection);
- Bypass **environment fingerprint** (registry key VM, MAC address, process list artifact);
- Tránh malware **skip injection** khi phát hiện phân tích.

Module này giải thích vì sao framework primitive của paper đạt recall cao hơn Cuckoo **trên cùng corpus** — không chỉ vì 2-of-3 rule mà còn vì **malware thực sự chạy injection** trong môi trường đã được che giấu.

**Bảng 2.5.** Vai trò anti-evasion trong [4] so với Noirlycan

| Khía cạnh | Paper [4] | Noirlycan (luận văn) |
|-----------|-----------|----------------------|
| Anti-evasion timing/env | Tích hợp trong QEMU sandbox | **Out-of-scope** (`kernel/analysis/evasion.py` chỉ ghi signal) |
| Phát hiện primitive E1/E2 | Có (custom tracer) | Có (Frida + correlator) |
| Phát hiện khi malware không chạy (E5) | Giảm nhờ anti-evasion | **Không xử lý** — recall lab có thể thấp hơn paper |
| Số liệu 21,2 % miss | Đo trên corpus paper | Trích dẫn, không tái lập |

Luận văn **tách bạch** hai lớp vấn đề:

1. **Chống E1–E4 khi malware *đã* thực hiện injection** — mục tiêu chính, hiện thực [4] + extension Sysmon/provenance;
2. **Chống E5 khi malware *không* thực hiện injection** — paper giải quyết bằng anti-evasion; luận văn khai báo ngoài phạm vi, đề xuất hướng phát triển (Chương Kết luận).

### 2.6.7. Hạn chế tự công bố của paper [4]

Paper thừa nhận các giới hạn sau — luận văn kế thừa và không che giấu:

| Hạn chế | Mô tả | Ảnh hưởng luận văn |
|---------|-------|-------------------|
| User-space only | Kernel injection không trong scope | O3 threat model |
| Tracer user-mode có thể bị bypass | Direct syscall stub | E4 — Noirlycan bổ sung Sysmon kernel |
| Dataset đến 2023 | Thiếu PoolParty (2023), Mockingjay (2023) đầy đủ | Noirlycan mở rộng taxonomy qua iRed.team |
| Phụ thuộc chất lượng trace | Drop event → sai primitive count | Giả định M5 (Frida fidelity) |
| Không có file provenance end-to-end | Bắt đầu từ process đã chạy | Đóng góp RO3 của luận văn |

### 2.6.8. Đóng góp khoa học paper và vị trí artifact

**Bảng 2.6.** Đóng góp Di Pietro et al. [4]

| ID | Đóng góp | Loại |
|----|----------|------|
| C1 | Framework 2-of-3 + equivalence class + congruence + temporal | Methodology |
| C2 | Prevalence ~16,5 % trên 56k mẫu | Empirical |
| C3 | Sandbox miss 21,2 % — định lượng E5 | Comparative |
| C4 | Anti-evasion ablation | Engineering + Empirical |
| C5 | Phân tích biến thể theo thời gian (section mapping) | Forensic |
| C6 | Artifact công khai [11] | Reproducibility |

Artifact `Sap4Sec/process-injection` [11] chứa analyzer rules, dataset metadata, và log thí nghiệm — là cơ sở cho RO3 luận văn (đối chiếu subset). Luận văn **không fork** artifact làm phương pháp mới; Noirlycan là **implementation độc lập** trên Frida + Sysmon, audit đối chiếu paper (docs/audit-and-threat-model.md).

## 2.7. Né tránh sandbox và phân tích chống phân tích

Korkin [8] và Hosseini & Antoniou [6] khảo sát có hệ thống kỹ thuật malware dùng để né sandbox và công cụ phân tích động trên Windows: phát hiện VM (CPUID, registry, driver), timing attack (sleep dài, đo delta RDTSC), kiểm process/tool (Wireshark, Procmon, Frida artifact), và **hành vi có điều kiện** (chỉ decrypt/inject sau khi môi trường “sạch”).

**Bảng 2.7.** Phân loại né tránh sandbox và liên hệ với injection

| Kỹ thuật né tránh | Mục tiêu | Tác động lên phát hiện injection |
|-------------------|----------|----------------------------------|
| VM/sandbox fingerprint | E5 | Malware không gọi API injection → log trống |
| Timing / delayed execution | E5 | Injection xảy ra sau window phân tích |
| User interaction gate | E5 | Cần click/input — sandbox batch fail |
| Anti-debug (E6) | Dừng trước inject | Tương tự miss behavior |
| Direct syscall (E4) | Né hook | Injection vẫn có thể xảy ra nhưng mất API trace |

Trong các công trình liên quan, **chỉ [4] định lượng miss rate 21,2 %** gắn trực tiếp với injection trên corpus lớn. Korkin [8] và Hosseini [6] cung cấp **taxonomy E5/E6** và best practice, nhưng không thay thế số liệu paper. Luận văn dùng khảo sát này để **justify** vì sao anti-evasion là hướng phát triển bắt buộc, đồng thời thừa nhận Noirlycan **chưa hiện thực** module tương đương Bluepill/paper.

## 2.8. EDR thương mại và thực hành phòng thủ

EDR/EPP thương mại (Microsoft Defender for Endpoint, Elastic Defend, CrowdStrike Falcon, v.v.) kết hợp kernel driver, ETW provider, machine learning trên telemetry, và threat intelligence. Về mặt nguyên tắc, EDR hiện đại cũng quan sát cross-process memory operation và thread creation — gần với primitive model. Tuy nhiên:

- **Rule và model đóng nguồn** — không thể audit equivalence class hay 2-of-3 rule tương đương [4];
- **Tối ưu production** — latency, false positive trên phần mềm hợp pháp, không công bố ablation né sandbox;
- **Không cung cấp pipeline provenance file→injection** cho phòng lab cá nhân.

Noirlycan **không cạnh tranh** với EDR thương mại về quy mô triển khai. Vị trí luận văn: **công cụ lab mã nguồn mở**, minh bạch rule, phục vụ nghiên cứu replication [4] và đào tạo analyst. Sysmon [10] — driver ký bởi Microsoft — được chọn làm lớp kernel vì phổ biến trong forensic community và có tài liệu event schema công khai.

## 2.9. MITRE ATT&CK và chuẩn hóa taxonomy

MITRE ATT&CK T1055 [9] liệt kê hơn một chục sub-technique injection (Process Hollowing, Thread Execution Hijacking, APC Injection, v.v.). Chuẩn hóa này giúp analyst giao tiếp sau phát hiện, nhưng **không cung cấp thuật toán phát hiện** — mỗi vendor map sub-technique sang rule riêng.

Noirlycan `kernel/classification/technique_classifier.py` map output rule-based lên nhãn ATT&CK tương ứng, mở rộng từ ~12 kỹ thuật paper lên **36 enum** (17 đạt FULL coverage: hook + classifier + test). Mở rộng này phục vụ **phân loại sau phát hiện primitive**, không thay thế 2-of-3 rule. Luận văn thừa nhận classifier **chưa được đánh giá** precision/recall trên ground truth corpus (Chương 3 — scientific claims).

## 2.10. Khoảng trống nghiên cứu

Tổng hợp khảo sát, Bảng 2.8 liệt kê khoảng trống giữa paper [4], thực hành EDR, và nhu cầu phòng lab endpoint Windows.

**Bảng 2.8.** Khoảng trống nghiên cứu và định vị luận văn

| Khoảng trống | Paper [4] | EDR thương mại | Sandbox (Cuckoo) | Luận văn (Noirlycan) |
|--------------|-----------|----------------|------------------|----------------------|
| Framework primitive chống E1/E2 | ✅ Batch QEMU | Một phần (đóng) | Yếu (signature) | ✅ Real-time Windows lab |
| Định lượng prevalence 56k | ✅ | Không công bố | Không | ❌ Out-of-scope |
| Anti-evasion E5 | ✅ Module tích hợp | Một phần | Yếu → 21,2 % miss | ❌ Out-of-scope; ghi signal |
| Telemetry kernel khi E4 | Tracer tùy biến | ✅ | Guest agent dễ detect | ✅ Sysmon E8/E10/E11 |
| File provenance → injection (E3) | ❌ | Một phần | Một phần | ✅ Pipeline end-to-end |
| Công cụ analyst lab mở | Artifact batch | Đóng | Cuckoo web UI | ✅ Dashboard + JSONL |
| Audit replication có test | Artifact paper | N/A | N/A | ✅ 31+ unit test + audit doc |
| Đánh giá Frida fidelity (M5) | N/A (QEMU tracer) | N/A | N/A | ⚠️ Protocol đề xuất, Chương 6 |

**Khoảng trống trung tâm luận văn lấp đầy:** Paper [4] chứng minh phương pháp và prevalence ở quy mô sandbox batch, nhưng **chưa cung cấp** (a) triển khai vận hành trên endpoint Windows thật với telemetry kép kernel/user, (b) liên kết injection finding với nguồn file drop, (c) tài liệu threat model formal cho từng hình thức né tránh E1–E6. Noirlycan nhắm (a)–(c) trong phạm vi **Replication + Extension Study**, không claim phương pháp detection mới thay [4].

## 2.11. Định vị luận văn: Replication + Extension

Luận văn định khung phương pháp luận như sau:

1. **Replication có kiểm chứng:** Hiện thực lõi 2-of-3 + memory congruence + temporal ordering + `PAPER_API_CLASSES` trên Frida hooks (`windows_injection_hooks.js`) và correlator Python (`services/analysis/domain/correlation.py`, `kernel/analysis/primitives.py`). Audit phát hiện ba lệch lạc implementation (D1: execute thiếu address; D2: read API lẫn write; D3: temporal quá lỏng) — đã sửa và verify bằng test.

2. **Extension kiến trúc:** (a) Sysmon kernel fallback chống E4; (b) file provenance pipeline chống E3; (c) mở rộng taxonomy `kernel/classification/technique_classifier.py` beyond paper §4.

3. **Honest scope:** Không claim prevalence 16,5 % / miss 21,2 %; không claim anti-evasion E5; không claim production EDR.

**Bảng 2.9.** Claim được phép và không được phép (tóm tắt — chi tiết Chương 3)

| Được claim | Không được claim |
|------------|------------------|
| Hiện thực [4] trên Frida + Sysmon với unit test | Phương pháp detection mới hơn [4] |
| Phát hiện pattern section-mapping (*neurevt*-class) trên PoC | Precision/recall ngang paper trên 56k mẫu |
| Giảm FN một phần dưới E4 nhờ Sysmon | Chống E5 toàn diện như paper |
| Pipeline provenance tăng giá trị forensic E3 | Thay thế Cuckoo/EDR thương mại |

## 2.12. Tóm tắt chương

Chương 2 đã khảo sát phương pháp signature, nền tảng primitive Klein [7], behavior graph Starink [12], và phân tích chi tiết Di Pietro et al. [4] — công trình căn cứ với ba RQ, kết quả **16,5 %** prevalence injection và **21,2 %** sandbox miss do né tránh, case study *neurevt* minh họa E1/E2, và module anti-evasion giải thích giới hạn sandbox không có E5 countermeasure. Các khảo sát né sandbox [6], [8] và thực hành EDR bổ sung bối cảnh nhưng không thay số liệu paper.

Khoảng trống: thiếu triển khai real-time Windows + telemetry kép + provenance + threat model formal. Luận văn *Tăng cường phát hiện mã độc dưới các hình thức né tránh* định vị là **Replication + Extension** của [4], tăng cường phát hiện dưới **E1–E4** trong phòng lab, thừa nhận **E5/E6** và prevalence scale nằm ngoài phạm vi hiện tại. Chương 3 trình bày threat model formal — tài sản, đối thủ C1–C7, out-of-scope O1–O7, giả định E1–E6 và M1–M6, ma trận tin cậy telemetry, và ranh giới claim khoa học.
