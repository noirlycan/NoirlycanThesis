# TRANG PHỤ BÌA

*(Theo mẫu Phụ lục 2 — điền thông tin cá nhân trước khi in)*

**ĐẠI HỌC QUỐC GIA HÀ NỘI**  
**TRƯỜNG ĐẠI HỌC CÔNG NGHỆ**

**PHAN VINH CƠ**

## TĂNG CƯỜNG PHÁT HIỆN MÃ ĐỘC DƯỚI CÁC HÌNH THỨC NÉ TRÁNH

Ngành: Công nghệ thông tin  
Chuyên ngành: *(điền)*  
Mã số: *(điền)*

**LUẬN VĂN THẠC SĨ**  
**KỸ THUẬT MÁY TÍNH** *(điền ngành chính thức)*

**NGƯỜI HƯỚNG DẪN KHOA HỌC:** *(Chức danh, họ tên)*

---

# LỜI CAM ĐOAN

Tôi xin cam đoan luận văn thạc sĩ *Tăng cường phát hiện mã độc dưới các hình thức né tránh* là công trình nghiên cứu của riêng tôi dưới sự hướng dẫn của *(tên giáo viên hướng dẫn)*. Các kết quả, ý tưởng và tài liệu trích dẫn đã được nêu rõ nguồn gốc. Phương pháp phát hiện process injection căn cứ chính vào công trình Di Pietro, D'Elia và Querzoni (ASIA CCS 2025) [4]; phần hiện thực tham chiếu repository `NoirlycanThesis`.

Tôi xin cam đoan không sao chép, trích dẫn sai hoặc sử dụng tài liệu của người khác mà không ghi nguồn. Mọi sai sót là trách nhiệm của tôi.

*(Chữ ký, họ tên)*

---

# DANH MỤC CÁC KÝ HIỆU VÀ CHỮ VIẾT TẮT

| Viết tắt | Tiếng Anh | Tiếng Việt |
|----------|-----------|------------|
| APC | Asynchronous Procedure Call | Lời gọi thủ tục bất đồng bộ |
| API | Application Programming Interface | Giao diện lập trình ứng dụng |
| ATT&CK | Adversarial Tactics, Techniques, and Common Knowledge | Khung MITRE mô tả hành vi đối phóng |
| AV | Antivirus | Phần mềm diệt virus |
| DLL | Dynamic Link Library | Thư viện liên kết động |
| EDR | Endpoint Detection and Response | Phát hiện và phản ứng tại điểm cuối |
| ETW | Event Tracing for Windows | Theo dõi sự kiện Windows |
| JSONL | JSON Lines | Định dạng log từng dòng JSON |
| NT API | Native API (ntdll.dll) | Tập API native của Windows |
| PE | Portable Executable | Định dạng thực thi Windows |
| PID | Process Identifier | Định danh tiến trình |
| PoC | Proof of Concept | Minh chứng khái niệm |
| RWX | Read-Write-Execute | Quyền đọc–ghi–thực thi trên vùng nhớ |
| SHA256 | Secure Hash Algorithm 256-bit | Hàm băm SHA-256 |
| VM | Virtual Machine | Máy ảo |

**Ký hiệu toán trong luận văn**

- $A$, $W$, $E$: ba operational primitive *allocate*, *write*, *execute*.
- $\text{addr}(p)$, $\text{size}(p)$: địa chỉ và kích thước gắn với primitive $p$.
- Hai khoảng nhớ $[a, a+s)$ và $[b, b+s')$ *chồng nhau* khi $a < b+s'$ và $b < a+s$.

---

# MỞ ĐẦU

## 1.1. Lý do chọn đề tài

Trong bối cảnh an ninh mạng hiện đại, mã độc Windows không còn giới hạn ở việc che giấu *nội dung* tĩnh — mã hóa payload, packer, obfuscation chuỗi — mà ngày càng chủ động **né tránh phát hiện** ở tầng hành vi động. Các hình thức né tránh này bao gồm: thay thế API tương đương để lách rule cứng của EDR/AV; gộp hoặc ẩn các bước trung gian trong chuỗi injection; inject payload vào tiến trình hợp pháp để che nguồn gốc (attribution); phát hiện sandbox hoặc debugger rồi ngừng hành vi độc hại; gọi syscall trực tiếp hoặc unhook thư viện hệ thống để bỏ qua instrumentation user-mode [4], [6], [8]. Trong số các kỹ thuật hành vi then chốt, **process injection** (MITRE ATT&CK T1055 [9]) đóng vai trò đặc biệt: malware thực thi payload dưới danh nghĩa tiến trình đã có uy tín như `explorer.exe`, `msedge.exe`, hoặc binary đã ký số, khiến các phương pháp phát hiện dựa trên signature API đơn lẻ hoặc sandbox thiếu lớp chống né tránh dễ bỏ sót [4], [9].

Công trình *Can You Run My Code? A Close Look at Process Injection in Windows Malware* của Di Pietro, D'Elia và Querzoni, công bố tại ASIA CCS 2025 [4] — **căn cứ khoa học chính** của luận văn này — cung cấp bằng chứng thực nghiệm quy mô lớn về mức độ phổ biến và độ phức tạp của injection trong malware thực tế. Tác giả phân tích **56.340 mẫu malware** thu thập trong giai đoạn 2017–2023 và ước lượng khoảng **16,5 %** số mẫu thể hiện hành vi injection. Con số này cho thấy injection không phải kỹ thuật hiếm mà là thành phần cấu trúc của hệ sinh thái mã độc Windows hiện đại. Đáng chú ý hơn, paper chỉ ra rằng **21,2 %** các mẫu injection trong tập nghiên cứu bị các sandbox phổ biến bỏ sót khi thiếu cơ chế chống né tránh môi trường phân tích — malware có thể phát hiện VM, timing bất thường, hoặc thiếu thành phần người dùng thực rồi *không thực hiện* injection trong môi trường lab, dẫn đến đánh giá thấp sai lệch về prevalence thực tế [4], [6].

Để đối phó các hình thức né tránh bằng biến thể triển khai (thay API, gộp bước), paper [4] đề xuất abstraction **operational primitive** gồm ba thao tác ngữ nghĩa trên bộ nhớ nạn nhân: *allocate* (chuẩn bị vùng thực thi), *write* (đặt payload), và *execute* (kích hoạt thực thi). Mỗi primitive được ánh xạ vào một **lớp tương đương API** (*equivalence class*) — ví dụ `VirtualAllocEx`, `NtAllocateVirtualMemory`, `NtCreateSection` đều thuộc lớp *allocate*. Quy tắc **ít nhất hai trong ba primitive** (*2-of-3*), kết hợp **đồng nhất vùng nhớ** (*memory range congruence*) và **thứ tự thời gian** (*temporal ordering*), cho phép phát hiện injection mà không phụ thuộc vào chuỗi API cụ thể — đây là điểm then chốt để giảm false negative khi malware né signature bằng cách thay `CreateRemoteThread` bằng `NtCreateThreadEx`, hoặc thay cặp `VirtualAllocEx` + `WriteProcessMemory` bằng `NtCreateSection` + `NtMapViewOfSection` [4], [7].

Tuy nhiên, paper [4] triển khai framework phân tích trên **sandbox QEMU batch** với mục tiêu nghiên cứu quy mô dataset và thống kê prevalence, chưa cung cấp pipeline vận hành cho **phòng lab Windows endpoint** — môi trường mà analyst thực tế thường điều tra sự cố. Trong lab Windows, mã độc thường kết hợp thêm các hình thức né tránh không được paper xử lý đầy đủ trong artifact công khai: **file-drop loader** (thả executable xuống đĩa, spawn, rồi inject cross-process) để che attribution; **direct syscall** hoặc unhooking `ntdll.dll` để né hook user-mode; và **anti-instrumentation** nhắm vào Frida hoặc debugger. Paper có module anti-evasion tích hợp cho sandbox (bypass timing check, env fingerprint) [4], nhưng module này chưa được chuyển thành giải pháp vận hành trên host Windows thông thường.

Xuất phát từ khoảng trống trên, luận văn *Tăng cường phát hiện mã độc dưới các hình thức né tránh* nhằm:

1. **Áp dụng và hiện thực hóa** phương pháp chống biến thể API của [4] trên endpoint lab Windows 10/11 thông qua hệ thống **Noirlycan Telemetry**;
2. **Bổ sung lớp phòng thủ kernel** (Sysmon) khi hook user-mode (Frida) bị né bởi direct syscall hoặc unhooking;
3. **Tăng cường truy vết nguồn gốc** file → process → injection để đối phó né tránh bằng inject vào tiến trình sạch;
4. **Đánh giá có kiểm chứng** trên kịch bản injection biến thể (section-mapping, APC, reflective DLL, PoolParty, v.v.) với ground truth do tác giả luận văn xây dựng.

Đề tài có ý nghĩa thực tiễn đối với các phòng lab an ninh mạng tại Việt Nam và khu vực: cung cấp công cụ mã nguồn mở, có tài liệu threat model formal, giúp sinh viên và researcher tái lập phương pháp [4] mà không phụ thuộc sandbox đóng hoặc EDR thương mại. Đồng thời, luận văn cam kết **trung thực khoa học** về phạm vi: các nhóm né tránh ngoài khả năng hiện thực (đặc biệt E5 — anti-sandbox/VM) được khai báo rõ, không mở rộng claim vượt evidence thí nghiệm.

## 1.2. Phân loại hình thức né tránh trong phạm vi đề tài

Luận văn tổ chức các hình thức né tránh liên quan trực tiếp process injection thành **sáu nhóm E1–E6** (Bảng 1.1). Phân loại này thống nhất với threat model formal (Chương 3) và ma trận mitigation trong hệ thống Noirlycan. Mỗi nhóm mô tả *cách malware né phát hiện* và *cơ chế tăng cường* mà luận văn đề xuất — không phải mọi nhóm đều nằm trong phạm vi hiện thực đầy đủ.

**Bảng 1.1.** Hình thức né tránh và cơ chế đối phó của luận văn

| Nhóm | Tên | Mô tả | Cơ chế tăng cường phát hiện | Phạm vi luận văn |
|------|-----|-------|----------------------------|------------------|
| E1 | Biến thể API | Thay Win32 bằng NT API tương đương: `CreateRemoteThread` → `NtCreateThreadEx`; `VirtualAllocEx` → `NtAllocateVirtualMemory` | Lớp tương đương API + quy tắc 2-of-3 theo [4] | Trong phạm vi |
| E2 | Gộp/ẩn bước | Section mapping (`NtCreateSection` + `NtMapViewOfSection`) gộp allocate+write; Mockingjay khai thác vùng RWX có sẵn, bỏ allocate riêng | Quy tắc 2-of-3 (chỉ cần ≥2 primitive); classifier section-mapping | Trong phạm vi |
| E3 | Né attribution | Inject vào tiến trình hợp pháp; file-drop loader che nguồn; không tạo process “lạ” dễ bị chặn | Sysmon lineage (Event 1) + file provenance (Event 11) + static triage | Trong phạm vi (extension) |
| E4 | Né hook user-mode | Direct syscall stub, unhooking `ntdll`, patch ETW/AMSI | Sysmon kernel callback (Event 8, 10) fallback khi Frida miss | Trong phạm vi (một phần) |
| E5 | Né sandbox/VM | Timing check, env fingerprint, kiểm CPUID/Hypervisor — malware *không chạy* injection trong lab | Paper [4] tích hợp anti-evasion; ablation +21,2 % phát hiện | **Ngoài phạm vi hiện thực** |
| E6 | Né instrumentation | Anti-Frida, anti-debug, phát hiện agent rồi abort hoặc đổi hành vi | `spawn` mode; khai báo limitation; ưu tiên Sysmon fallback | Hạn chế; không chủ động đối phó |

Nhóm **E5** cần được làm rõ đặc biệt theo nguyên tắc trung thực khoa học. Paper [4] báo cáo rằng khoảng 21,2 % mẫu injection trong dataset bị sandbox bỏ sót vì malware phát hiện môi trường phân tích và *từ chối thực thi* payload injection — đây là dạng né tránh *passive* (không inject) chứ không phải né rule sau khi đã inject. Paper giải quyết bằng module anti-evasion tích hợp (patch timing, giả lập môi trường). Luận văn **không hiện thực** module anti-evasion tương đương; hệ thống Noirlycan chỉ *ghi nhận* tín hiệu evasion (`kernel/analysis/evasion.py`) mà không bypass. Hệ quả: các kết luận prevalence và recall của luận văn **không được** so sánh trực tiếp với số liệu 16,5 % / 21,2 % của paper trên cùng điều kiện thí nghiệm. E5 được nêu trong threat model và hướng phát triển (Kết luận), không phải claim đóng góp hiện tại.

Nhóm **E4** nằm trong phạm vi *một phần*: khi malware direct-syscall, Frida hook user-mode miss toàn bộ đối số API — mất khả năng memory congruence chi tiết. Tuy nhiên, Sysmon driver (kernel-mode) vẫn ghi **CreateRemoteThread** (Event 8) và **ProcessAccess** (Event 10) qua callback kernel, không phụ thuộc hook `ntdll` [10]. Noirlycan kết hợp hai lớp telemetry theo ma trận tin cậy (Hình 1.1 — mô tả trong Chương 5) để giảm false negative khi E4 xảy ra, dù mất granularity so với trace đầy đủ của paper.

**Bảng 1.2.** Mối quan hệ giữa nhóm né tránh và kỹ thuật injection điển hình

| Kỹ thuật injection | E1 | E2 | E3 | E4 | E5 | E6 |
|--------------------|----|----|----|----|----|-----|
| Classic Remote Thread | ✓ | | ✓ | ✓ | | |
| Section-mapping / Hollowing | ✓ | ✓ | ✓ | ✓ | | |
| APC / Early Bird | | ✓ | ✓ | ✓ | | |
| Reflective DLL | ✓ | | ✓ | ✓ | | ✓ |
| Process Ghosting/Herpaderping | ✓ | ✓ | ✓ | ✓ | | |
| PoolParty / Mockingjay | | ✓ | ✓ | ✓ | | |

Ký hiệu ✓: kỹ thuật thường khai thác hình thức né tránh tương ứng.

## 1.3. Mục tiêu nghiên cứu

### 1.3.1. Mục tiêu tổng quát

Tăng cường khả năng phát hiện mã độc Windows sử dụng process injection và các hình thức né tránh E1–E4 trong phòng lab Windows 10/11, căn cứ phương pháp operational primitive và quy tắc 2-of-3 của Di Pietro et al. [4], thông qua hiện thực hóa và mở rộng có kiểm chứng trên hệ thống Noirlycan Telemetry.

### 1.3.2. Mục tiêu cụ thể

**RO1 — Hiện thực hóa lõi phương pháp [4].** Xây dựng bộ quy tắc phát hiện gồm: (a) ba operational primitive *allocate*, *write*, *execute*; (b) lớp tương đương API theo `PAPER_API_CLASSES` trong artifact [11]; (c) quy tắc 2-of-3 trên cùng cặp `(actor_pid, target_pid)`; (d) memory range congruence; (e) temporal ordering. Lớp thu thập gồm Frida hooks (`windows_injection_hooks.js`) và correlator Python (`services/analysis/domain/correlation.py`). Tiêu chí thành công: unit test khớp case study section-mapping (Neurevt) mô tả trong paper §3.5 [4].

**RO2 — Kiến trúc telemetry kép chống E4.** Thiết kế pipeline **Sysmon ∪ Frida**: Frida cung cấp đối số API chi tiết cho congruence; Sysmon kernel (Event 1, 7, 8, 10, 11) fallback khi user-mode hook bị bypass. Đánh giá drop-rate Frida và tỷ lệ phát hiện bổ sung nhờ Sysmon trên subset loader direct-syscall (nếu có trong benchmark).

**RO3 — Pipeline provenance chống E3.** Mở rộng paper [4] theo hướng lab Windows: liên kết Sysmon Event 11 (FileCreate) → static triage (SHA256, PE header, entropy, chữ ký Authenticode) → ProcessCreate lineage → Finding injection. Mục tiêu: analyst truy ngược từ phát hiện inject tới file nguồn trên đĩa, hỗ trợ điều tra sau sự cố.

**RO4 — Đánh giá trên benchmark biến thể injection.** Xây dựng bộ loader PoC (section-mapping, shellcode, APC, reflective DLL, hollowing precursor) và chạy trên subset artifact Sap4Sec/process-injection [11]. Đo precision, recall, F1 cho phát hiện chain; precision phân loại kỹ thuật (21+ enum trong `InjectionTechnique`).

**RO5 — Tài liệu hóa threat model và ranh giới claim.** Formal hóa đối thủ (C1–C7), out-of-scope (O1–O7), giả định (M1–M6), ma trận E1–E6 ↔ mitigation. Phân tách rõ claim được phép (E1–E4) và claim **không được** (E5 anti-evasion đầy đủ; prevalence 56k mẫu của paper).

## 1.4. Đối tượng và phạm vi nghiên cứu

### 1.4.1. Đối tượng nghiên cứu

- **Mã độc/loader Windows user-mode** sử dụng process injection kèm hình thức né tránh E1–E4, đặc biệt biến thể section-mapping và file-drop.
- **Phương pháp phát hiện** operational primitive, equivalence class, quy tắc 2-of-3, memory congruence, temporal ordering theo [4].
- **Hệ thống Noirlycan Telemetry** — artifact hiện thực luận văn: collector Python, Frida hooks, Sysmon poller, correlator, technique classifier, dashboard Flask [13].

### 1.4.2. Phạm vi trong luận văn

| Khía cạnh | Trong phạm vi |
|-----------|---------------|
| Hệ điều hành | Windows 10/11 (64-bit), lab VM cô lập |
| Chế độ malware | User-mode; cross-process và self-inject |
| Né tránh | E1 (biến thể API), E2 (gộp bước), E3 (attribution — extension), E4 (syscall/unhook — fallback Sysmon) |
| Telemetry | Sysmon (config `sysmon-noirlycan.xml`), Frida 16.x, static triage |
| Kỹ thuật injection | 21+ kỹ thuật trong taxonomy (paper [4] + iRed.team + mở rộng PoolParty/Mockingjay) |
| Đánh giá | PoC-Bench tự xây; subset Paper-Subset; Benign-Baseline; protocol Frida fidelity |

### 1.4.3. Phạm vi ngoài luận văn

| Khía cạnh | Ngoài phạm vi | Lý do |
|-----------|---------------|-------|
| E5 — Anti-sandbox/VM đầy đủ | Không hiện thực bypass | Paper [4] có module riêng; vượt phạm vi thesis engineering |
| E6 — Anti-Frida chủ động | Chỉ limitation + spawn | Đối thủ có thể detect agent; không ship countermeasure |
| Injection kernel-mode | Không | Sysmon/Frida user-mode không đủ; paper cũng tập trung user-mode |
| Prevalence 56.340 mẫu | Không tái lập quy mô | Luận văn tập trung replication có kiểm chứng + extension lab |
| EDR thương mại | Không so sánh trực tiếp | Đóng source; chỉ tham chiếu công trình liên quan |
| Windows Server / ARM | Không | Chưa validate ngoài desktop lab |

Luận văn **không** tuyên bố Noirlycan thay thế sandbox quy mô lớn của [4] hay EDR production. Phạm vi là **phòng lab có kiểm chứng** — nơi phương pháp [4] được áp dụng, mở rộng provenance, và đánh giá trên ground truth kiểm soát.

## 1.5. Phương pháp nghiên cứu

Luận văn kết hợp năm phương pháp bổ trợ nhau:

**1. Nghiên cứu tài liệu.** Khảo sát có hệ thống công trình nền tảng: Di Pietro et al. [4] (căn cứ chính); Klein et al. [7] (ba bước allocate/write/execute); Starink et al. [12] (behavior graph, memory congruence); khảo sát né tránh sandbox [6], anti-analysis [8]; MITRE ATT&CK T1055 [9]; tài liệu Sysmon [10] và Frida [5]; artifact Sap4Sec/process-injection [11].

**2. Phân tích threat model.** Chuyển hóa `docs/audit-and-threat-model.md` thành Chương 3 formal: tài sản (A1–A3), năng lực đối thủ (C1–C7), out-of-scope (O1–O7), giả định môi trường (E1–E6 trong threat model — khác với nhóm né tránh E1–E6), giả định phương pháp (M1–M6), ma trận threat T1–T9.

**3. Thiết kế và hiện thực hệ thống.** Áp dụng phương pháp [4] vào kiến trúc Noirlycan (Chương 5–6): `kernel/classification/api_manifest.py` (equivalence classes), `windows_injection_hooks.js` (Frida), `services/analysis/domain/correlation.py` (2-of-3 engine), `kernel/classification/technique_classifier.py` (21+ kỹ thuật), `file_watch.py` + static triage (provenance extension). Đối chiếu implementation với paper qua audit doc — ghi nhận deviation (D1–D8) và fix có chọn lọc.

**4. Thực nghiệm và đánh giá.** (a) Unit test correlation (31+ case); (b) PoC-Bench loader tự viết; (c) subset 100 mẫu artifact paper; (d) Benign-Baseline 50 chương trình hợp pháp; (e) Frida fidelity protocol — so sánh event Frida với ground truth. Metrics: precision, recall, F1; thời gian provenance; drop-rate Frida.

**5. Thảo luận và phản biện khoa học.** Phân tích hạn chế construct validity (Frida overhead), external validity (chỉ Windows 10/11 lab), và deviation so với paper. Không che giấu E5 out-of-scope hay inflation recall do thiếu anti-evasion.

**Bảng 1.3.** Ánh xạ phương pháp nghiên cứu với câu hỏi đánh giá (Chương 6)

| Phương pháp | Câu hỏi phục vụ |
|-------------|-----------------|
| Audit code-vs-paper | RQ1: Implementation có khớp artifact [4]? |
| PoC-Bench + Paper-Subset | RQ2: Phát hiện được loader biến thể? |
| Provenance pipeline | RQ3: Extension E3 có giá trị forensic? |
| Frida fidelity | RQ4: Frida đủ trung thực cho kết luận? |

## 1.6. Những đóng góp của luận văn

Luận văn đóng góp năm nhóm, phân tách rõ replication [4] và extension lab:

**Đóng góp 1 — Tăng cường chống né tránh biến thể API (E1) và gộp bước (E2).** Hiện thực có kiểm chứng lõi 2-of-3 + equivalence class của [4] trên Frida/Sysmon, với 31+ unit test bao phủ APC, section-mapping, PoolParty precursor, Ghosting precursor, reflective DLL, thread hijack. Deviation so với paper (D1–D3) được audit và khai báo; một số fix (temporal ordering, `lpStartAddress` cho execute primitive) cải thiện fidelity.

**Đóng góp 2 — Tăng cường chống né hook user-mode (E4).** Kiến trúc telemetry kép: Sysmon kernel callback bắt CreateRemoteThread/ProcessAccess khi Frida miss do direct syscall hoặc unhooking. Ma trận tin cậy theo lớp (kernel vs user) formal hóa ranh giới bypass — tránh claim sai “Frida miss = mù hoàn toàn”.

**Đóng góp 3 — Tăng cường chống né attribution (E3).** Pipeline `file mới trên đĩa → static triage → process lineage → injection Finding` — extension không có trong artifact batch sandbox của [4], phục vụ workflow analyst lab Windows. Dashboard Flask hỗ trợ điều tra tương tác (Overview, Findings, Primitives, Network).

**Đóng góp 4 — Công cụ lab mã nguồn mở.** CLI collector, JSONL session log, reclassify, corpus analytics, config Sysmon tái lập, Dockerfile analyzer offline. Artifact phục vụ giáo dục và nghiên cứu tái lập [4] tại môi trường UET/lab Việt Nam [13].

**Đóng góp 5 — Threat model và ranh giới claim khoa học.** Ma trận E1–E6 ↔ mitigation; scientific claims §3.8 audit: **không** claim anti-evasion E5, **không** claim prevalence 56k mẫu, **không** claim thay thế EDR. E5 explicitly out-of-scope với hướng phát triển (ETW Threat Intelligence, anti-evasion module).

**Bảng 1.4.** So sánh đóng góp luận văn với paper [4]

| Khía cạnh | Paper [4] | Luận văn (Noirlycan) |
|-----------|-----------|----------------------|
| Quy mô dataset | 56.340 mẫu, 2017–2023 | PoC-Bench + subset ~100 mẫu |
| Môi trường | QEMU sandbox batch | Windows 10/11 lab VM |
| Anti-evasion E5 | Có module tích hợp | **Out-of-scope** |
| File provenance | Không | Extension E3 |
| Telemetry | Trace nội bộ sandbox | Frida + Sysmon + dashboard |
| Phân loại kỹ thuật | 12 kỹ thuật chính | 21+ enum + rule catalog |
| Công khai | Sap4Sec/process-injection | NoirlycanThesis repo [13] |

## 1.7. Bố cục luận văn

Luận văn gồm phần mở đầu, bảy chương nội dung, kết luận, tài liệu tham khảo và phụ lục, trình bày theo format Trường Đại học Công nghệ — ĐHQGHN [2].

**Phần mở đầu** (tài liệu hiện tại) trình bày lý do chọn đề tài, phân loại né tránh E1–E6, mục tiêu RO1–RO5, đối tượng/phạm vi, phương pháp nghiên cứu, đóng góp và bố cục.

**Chương 1 — Cơ sở lý thuyết** (`02-co-so-ly-thuyet.md`) cung cấp nền tảng kỹ thuật: mô hình tiến trình Windows, virtual memory, lớp Win32/NT API; định nghĩa process injection và operational primitive [7], [4]; phân loại chi tiết E1–E6; taxonomy 10+ kỹ thuật injection; Sysmon events và Frida instrumentation.

**Chương 2 — Công trình liên quan** đặt [4] làm trục trung tâm, so sánh với Klein [7], Starink [12], sandbox/EDR, khảo sát evasion [6], [8]. Làm rõ vị trí luận văn: replication + extension lab, không cạnh tranh nghiên cứu prevalence.

**Chương 3 — Threat model và giả định** formal hóa đối thủ, tài sản, trust boundary, ma trận E1–E6, scientific claims. Nêu rõ E5 out-of-scope và O7 (sandbox-aware evasion).

**Chương 4 — Phương pháp tăng cường phát hiện** mô tả pipeline Noirlycan kế thừa [4]: equivalence classes, 2-of-3, memory congruence, temporal ordering; extension file provenance; technique classifier; sơ đồ kiến trúc (Hình 4.1 tham chiếu `docs/design/architecture-comparison-template.svg`).

**Chương 5 — Thiết kế và hiện thực** chi tiết module: collector, Frida hooks, correlator, static triage, dashboard, injection graph cho chuỗi đệ quy (~2 % prevalence paper [4]).

**Chương 6 — Đánh giá thực nghiệm** trả lời RQ1–RQ4: bảng precision/recall, confusion matrix phân loại kỹ thuật, Frida fidelity, giá trị forensic provenance. Không claim số liệu 21,2 % sandbox miss vì thiếu anti-evasion E5.

**Chương 7 — Thảo luận và hạn chế** phân tích deviation D1–D8, construct/external validity, so sánh với Sigma rule và sandbox baseline, hướng ETW thay Frida.

**Kết luận** tóm tắt đóng góp RO1–RO5, nhấn mạnh ranh giới E5, đề xuất tích hợp anti-evasion và ETW Threat Intelligence.

**Phụ lục** gồm: (A) bảng đầy đủ API equivalence classes từ `kernel/classification/api_manifest.py`; (B) cấu hình Sysmon; (C) hướng dẫn tái lập VM và hash mẫu; (D) mã loader PoC; (E) protocol Frida fidelity.

**Bảng 1.5.** Tóm tắt nội dung các chương

| Chương | Tiêu đề | Nội dung chính |
|--------|---------|----------------|
| Mở đầu | — | Đề tài, E1–E6, mục tiêu, phạm vi, phương pháp |
| 1 | Cơ sở lý thuyết | Windows, injection, primitive, Sysmon, Frida |
| 2 | Công trình liên quan | [4] trung tâm, so sánh related work |
| 3 | Threat model | E1–E6, C/O/M assumptions, claims |
| 4 | Phương pháp | 2-of-3, provenance, classifier |
| 5 | Hiện thực | Noirlycan modules |
| 6 | Đánh giá | RQ1–RQ4, metrics |
| 7 | Thảo luận | Hạn chế, E5, hướng phát triển |
| Kết luận | — | Tóm tắt, đóng góp, tương lai |

Luận văn sử dụng hệ thống trích dẫn số trong ngoặc vuông [n], tham chiếu chéo bảng và hình theo quy ước UET (Bảng X.Y, Hình X.Y). Tài liệu tham khảo đầy đủ tại `tai-lieu-tham-khao.md`, với [4] là nguồn được trích dẫn nhiều nhất xuyên suốt các chươn.

---

# CHƯƠNG 1. CƠ SỞ LÝ THUYẾT

Chương này trình bày nền tảng lý thuyết phục vụ luận văn *Tăng cường phát hiện mã độc dưới các hình thức né tránh*. Nội dung bao gồm: mô hình tiến trình và bộ nhớ ảo Windows; định nghĩa process injection trong bối cảnh né tránh phát hiện; phân loại sáu nhóm né tránh E1–E6; phương pháp operational primitive và quy tắc 2-of-3 theo Di Pietro et al. [4]; taxonomy chi tiết hơn mười kỹ thuật injection; và hai công cụ telemetry trung tâm — Sysmon (kernel) và Frida (user-mode). Các khái niệm ở đây được tham chiếu xuyên suốt Chương 2 (công trình liên quan), Chương 3 (threat model), Chương 4 (phương pháp) và Chương 5 (hiện thực Noirlycan).

## 1.1. Mô hình tiến trình Windows và bối cảnh injection

### 1.1.1. Process, thread và không gian địa chỉ

Trên Windows, **process** (*tiến trình*) là container cô lập gồm không gian địa chỉ ảo riêng, handle table, security context (token), và ít nhất một **thread** (*luồng*) thực thi. Mỗi thread có ngữ cảnh riêng: thanh ghi CPU, stack, và con trỏ tới **Thread Environment Block** (TEB). Process được mô tả bởi **Process Environment Block** (PEB) — cấu trúc user-mode chứa thông tin loader, danh sách module đã map, và tham số command line [7].

Kernel quản lý process qua **EPROCESS** (kernel structure) và expose capability cho user-mode qua Win32 API (`kernel32.dll`, `kernelbase.dll`) và **Native API** (`ntdll.dll`). Hầu hết thao tác injection của malware đi qua Native API hoặc syscall tương ứng, vì lớp Win32 thường là wrapper mỏng gọi xuống `ntdll` [4], [7].

**Bảng 1.1.** Thành phần chính của mô hình tiến trình Windows liên quan injection

| Thành phần | Vai trò | Liên quan injection |
|------------|---------|---------------------|
| PEB | Metadata process, loader data | Reflective DLL, module stomping đọc/ghi PEB |
| TEB | Ngữ cảnh thread, stack | APC queue, thread hijack |
| VAD (Virtual Address Descriptor) | Mô tả vùng nhớ ảo | Allocate/map section tạo VAD mới |
| Handle table | Quản lý handle process/thread | `OpenProcess` với `PROCESS_VM_WRITE` |
| Token / integrity level | Kiểm soát truy cập | UAC, cross-session injection hạn chế |
| Section object | Shared memory kernel | `NtCreateSection`, `NtMapViewOfSection` |

### 1.1.2. Process injection như hành vi né tránh attribution

**Process injection** (MITRE T1055 [9]) là họ kỹ thuật đưa mã thực thi vào **address space của tiến trình khác** (cross-process) hoặc cùng tiến trình (self-inject), rồi kích hoạt thực thi mà không tạo image file hợp lệ trên đĩa cho payload. Mục tiêu của attacker không chỉ là thực thi code mà còn **né tránh phát hiện ở tầng attribution**: sau injection, tiến trình hiển thị trên Task Manager vẫn là nạn nhân hợp pháp (`msedge.exe`, `svchost.exe`, …), che giấu nguồn gốc thực sự của hành vi độc hại [4], [3].

Di Pietro et al. [4] ước lượng **16,5 %** mẫu malware trong dataset 2017–2023 có injection — con số đủ lớn để coi injection là vector then chốt, không phải edge case. Paper cũng chỉ ra xu hướng malware chuyển từ classic remote thread sang **section-mapping** và **process hollowing** biến thể — các kỹ thuật vừa inject vừa né rule signature cố định (E1, E2).

### 1.1.3. Chuỗi hành vi điển hình: file-drop → spawn → inject

Trong phòng lab Windows, loader thường không chỉ inject mà kết hợp **file-drop** (E3):

1. Malware (hoặc macro/script) ghi file `.exe`/`.dll` xuống thư mục staging (`%TEMP%`, `%APPDATA%`, …).
2. Gọi `CreateProcess` hoặc `ShellExecute` spawn tiến trình mới — có thể với `CREATE_SUSPENDED` cho Early Bird / hollowing.
3. `OpenProcess` nạn nhân (cùng process mới hoặc process hệ thống khác).
4. Thực hiện chuỗi allocate → write → execute (hoặc biến thể gộp bước).
5. Payload chạy dưới identity nạn nhân; file gốc có thể bị xóa.

Luận văn mở rộng paper [4] bằng pipeline **provenance** bắt sự kiện bước 1–2 (Sysmon Event 11, Event 1) để liên kết Finding injection với file nguồn — đối trọng trực tiếp cho E3.

## 1.2. Bộ nhớ ảo, section object và lớp API

### 1.2.1. Virtual memory và page protection

Windows sử dụng **bộ nhớ ảo per-process** với phân trang (typically 4 KB page). Mỗi vùng có **protection** quyết định quyền đọc/ghi/thực thi: `PAGE_READWRITE` (RW), `PAGE_EXECUTE_READ` (RX), `PAGE_EXECUTE_READWRITE` (RWX), v.v. Injection an toàn về mặt OPSEC thường: allocate RW → write payload → đổi protection sang RX (`VirtualProtectEx`) trước execute — tránh vùng RWX dễ bị heuristic EDR phát hiện [7], [4].

Malware né heuristic có thể: (a) dùng section mapping map trực tiếp RX; (b) **Mockingjay** — ghi vào vùng RWX có sẵn trong DLL signed (bỏ bước allocate riêng, E2); (c) **module stomping** — ghi đè section `.text` của module đã load.

### 1.2.2. Section object và shared mapping

**Section object** là abstraction kernel cho vùng nhớ có thể map vào nhiều process. Chuỗi:

- `NtCreateSection` — tạo section từ file hoặc anonymous (commit memory).
- `NtMapViewOfSection` — map view vào address space local hoặc **remote** (target process handle).

Khi map remote, một l lệnh có thể đồng thời **allocate** (reserve VAD) và **write** (copy content từ section) — điển hình E2 “gộp bước”. Paper [4] xếp `NtCreateSection` vào lớp *allocate*, `NtMapViewOfSection` vào *write*; thực tế ngữ nghĩa phụ thuộc tham số — luận văn theo artifact Noirlycan cố định mapping này và khai báo deviation D8 trong audit.

### 1.2.3. Win32 API và Native API

**Bảng 1.2.** Phân lớp API liên quan injection

| Lớp | Thư viện | Ví dụ | Ghi chú |
|-----|----------|-------|---------|
| Win32 | `kernel32.dll` | `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread` | Wrapper documented |
| Native | `ntdll.dll` | `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx` | Syscall stub nội bộ |
| Direct syscall | Stub attacker | `syscall` instruction với SSN tự resolve | E4 — bypass hook user-mode |
| Kernel | `ntoskrnl.exe` | (không gọi trực tiếp user malware thông thường) | Out-of-scope luận văn |

Malware E1 thay Win32 bằng Native API tương đương để lách rule Sigma/EDR viết cho tên hàm Win32. Phương pháp [4] neutralize E1 bằng **equivalence class** — mọi API cùng ngữ nghĩa primitive được gom một lớp, rule phát hiện không phụ thuộc tên export cụ thể.

## 1.3. Process injection — định nghĩa và operational primitive

### 1.3.1. Ba bước cổ điển (Klein et al.)

Klein et al. [7] phân loại process injection Windows thành ba thao tác **operational** trên bộ nhớ nạn nhân:

1. **Allocate** — dành/chuẩn bị vùng nhớ có thể thực thi (allocation, section creation, thay đổi protection).
2. **Write** — ghi payload (shellcode, PE image, DLL) vào vùng đó.
3. **Execute** — chuyển luồng CPU tới payload (remote thread, APC, resume, set context, load library, …).

Ba bước này mô tả **ngữ nghĩa** hành vi, không ràng buộc API cụ thể — nền tảng cho abstraction của [4].

### 1.3.2. Cùng vùng nhớ (Starink et al.)

Starink et al. [12] dùng **behavior graph** — đồ thị API — và yêu cầu các bước injection liên quan thao tác trên **cùng buffer** bộ nhớ. Paper [4] formal hóa thành **memory range congruence**: hai primitive được correlate nếu khoảng địa chỉ `[address, address+size)` giao nhau hoặc chứa nhau. Mục đích: giảm false positive khi cùng actor mở nhiều allocation độc lập trong nạn nhân [4], [12].

### 1.3.3. Giới hạn abstraction

Abstraction primitive **không** cover toàn bộ hành vi độc hại Windows: không mô tả credential dumping, lateral movement, kernel exploit. Phạm vi luận văn giới hạn **user-mode cross-process / self inject** theo threat model (Chương 3). Primitive cũng **không** thay thế phân tích tĩnh — static triage bổ sung context payload (entropy, signature) cho E3.

## 1.4. Phân loại hình thức né tránh E1–E6

Luận văn nhóm né tránh liên quan injection thành sáu lớp E1–E6. Phân loại thống nhất Mở đầu, threat model, và đánh giá.

### 1.4.1. E1 — Né tránh bằng biến thể API

Attacker thay API Win32 bằng Native API hoặc biến thể ít bị rule hóa:

| API Win32 (dễ rule) | Thay thế Native / khác |
|---------------------|------------------------|
| `CreateRemoteThread` | `NtCreateThreadEx`, `RtlCreateUserThread` |
| `VirtualAllocEx` | `NtAllocateVirtualMemory` |
| `WriteProcessMemory` | `NtWriteVirtualMemory` |
| `OpenProcess` | `NtOpenProcess` |

**Cơ chế phát hiện [4]:** equivalence class — mọi biến thể cùng primitive. Noirlycan manifest `PAPER_API_CLASSES` trong `kernel/classification/api_manifest.py` [11], [13].

### 1.4.2. E2 — Né tránh bằng gộp hoặc ẩn bước

Attacker giảm số API observable bằng cách gộp allocate+write hoặc bỏ allocate:

- **Section mapping:** `NtCreateSection` + `NtMapViewOfSection` remote.
- **Process hollowing (section variant):** tạo process suspended, unmap image gốc, map section payload, set context entrypoint — dominant variant trong dataset [4].
- **Mockingjay:** chỉ write+execute vào RWX có sẵn trong `libcef.dll`, `mshtml.dll`, …
- **PoolParty:** lạm dụng thread pool wait callback — execute không qua `CreateRemoteThread` cổ điển.

**Cơ chế phát hiện [4]:** quy tắc **2-of-3** — không yêu cầu đủ cả ba primitive; chỉ cần ≥2 primitive khác loại trên cùng vùng nhớ. Ví dụ Mockingjay: W + E đủ điều kiện.

### 1.4.3. E3 — Né tránh bằng che attribution

Attacker tránh tạo tiến trình “đáng ngờ”:

- Inject vào browser, shell, service signed.
- File-drop: executable tên giả mạo, thư mục staging, xóa file sau spawn.
- Parent PID spoofing (ngoài phạm vi đầy đủ luận văn nhưng liên quan lineage).

**Cơ chế phát hiện (extension luận văn):** Sysmon Event 1 (parent/child, command line, `CreationUtcTime`), Event 11 (file path hash), static triage — pipeline provenance Noirlycan. Paper [4] batch sandbox không nhấn mạnh forensics file-drop trên endpoint.

### 1.4.4. E4 — Né tránh instrumentation user-mode

Attacker bypass hook Frida/EDR user-mode:

- **Direct syscall:** stub assembly gọi `syscall` với System Service Number (SSN), không đi qua export `ntdll` đã hook.
- **Unhooking:** restore `.text` section `ntdll.dll` từ bản sạch (disk hoặc `KnownDlls`).
- **Patch ETW/AMSI:** giảm telemetry/logging (kỹ thuật riêng trong classifier Noirlycan).

Frida `Interceptor.attach` trên export **miss** toàn bộ khi E4 thành công — mất đối số address/size cho congruence. **Sysmon kernel** (Event 8 CreateRemoteThread, Event 10 ProcessAccess) vẫn ghi cross-process artifact vì callback đăng ký ở kernel, không phụ thuộc hook user-mode [10]. Luận văn coi E4 “trong phạm vi một phần”: phát hiện được hành vi cross-process nhưng có thể mất chi tiết memory congruence.

### 1.4.5. E5 — Né tránh sandbox và môi trường phân tích

Malware **không thực hiện** injection khi phát hiện VM/sandbox/debugger:

- Timing: `RDTSC`, `GetTickCount`, sleep acceleration.
- Environment: thiếu file user, registry sandbox, MAC address VM vendor, CPUID hypervisor bit.
- Human interaction: không click, không cửa sổ visible.

Paper [4] báo **21,2 %** mẫu injection bị sandbox bỏ sót vì evasion này; module **anti-evasion** paper (patch timing, fake env) cải thiện recall đáng kể trong ablation. Luận văn **không hiện thực** anti-evasion tương đương — **E5 ngoài phạm vi hiện thực**. Noirlycan ghi signal evasion nhưng không bypass. Mọi so sánh recall với paper phải nêu disclaimer E5.

### 1.4.6. E6 — Né tránh instrumentation chủ độch (anti-Frida)

Attacker quét memory/process để tìm `frida-agent`, pipe Frida, breakpoint INT3, timing bất thường do hook — rồi abort hoặc đổi code path. Luận văn:

- Ưu tiên **`spawn` mode** (Frida attach trước entrypoint) giảm cửa sổ race.
- Khai báo **limitation** — không claim chống anti-Frida.
- Sysmon fallback một phần khi malware vẫn inject sau khi không detect agent.

**Bảng 1.3.** Tóm tắt nhóm né tránh E1–E6

| Nhóm | Tấn công vào | Phát hiện chính | Phạm vi luận văn |
|------|--------------|-----------------|------------------|
| E1 | Rule API cố định | Equivalence class [4] | ✓ Đầy đủ |
| E2 | Rule 3 bước tuần tự | 2-of-3 [4] | ✓ Đầy đủ |
| E3 | Analyst attribution | Provenance extension | ✓ Extension |
| E4 | Frida/EDR hook | Sysmon kernel fallback | ✓ Một phần |
| E5 | Sandbox/VM | Anti-evasion [4] | ✗ Out-of-scope |
| E6 | Frida agent | spawn; limitation | △ Hạn chế |

## 1.5. Operational primitive và quy tắc 2-of-3 theo Di Pietro et al. [4]

Phần này trình bày phương pháp **căn cứ khoa học chính** của luận văn — tóm tắt và formal hóa theo paper [4] và artifact Sap4Sec/process-injection [11].

### 1.5.1. Ba primitive và lớp tương đương API

Mỗi primitive ánh xạ tập API **thay thế được** về mặt ngữ nghĩa operational:

**Bảng 1.4.** Lớp tương đương API (rút gọn từ [4], Table 1; đầy đủ Phụ lục A)

| Primitive | Ví dụ API (equivalence class) |
|-----------|-------------------------------|
| **Allocate (A)** | `VirtualAllocEx`, `NtAllocateVirtualMemory`, `VirtualProtectEx`, `NtProtectVirtualMemory`, `NtCreateSection`, `CreateFileMappingA/W`, `MapViewOfFile(Ex)` |
| **Write (W)** | `WriteProcessMemory`, `NtWriteVirtualMemory`, `NtMapViewOfSection`, `NtUnmapViewOfSection`, `RtlCopyMemory` |
| **Execute (E)** | `CreateRemoteThread(Ex)`, `NtCreateThreadEx`, `RtlCreateUserThread`, `QueueUserAPC`, `NtQueueApcThread(Ex)`, `SetThreadContext`, `ResumeThread`, `LoadLibraryA/W`, `LdrLoadDll`, `SetWindowsHookEx`, `GlobalAddAtom` |

**Lưu ý:** `ReadProcessMemory` / `NtReadVirtualMemory` **không** là write primitive trong paper — dùng cho observation (reflective loader đọc headers). Noirlycan tách class `remote_read` khỏi đếm 2-of-3 [13].

Các class phụ trợ không phải primitive paper: `process_spawn`, `process_access`, `dynamic_resolve`, `context_read` — hỗ trợ classifier và evidence flags.

### 1.5.2. Quy tắc 2-of-3

**Phát biểu:** Phát hiện injection khi tồn tại ít nhất **hai primitive khác loại** trong tập {A, W, E} quan sát trên cùng cặp `(actor_pid, target_pid)` (hoặc self-inject khi `actor == target`), thỏa memory congruence và temporal ordering [4].

**Lý do:** Malware E2 thường che một bước — section mapping che allocate/write tách rời; Mockingjay che allocate. Yêu cầu 3/3 gây false negative cao. Yêu cầu 1/1 không đủ (chỉ `OpenProcess` là access, không phải primitive). Ngưỡng 2/3 cân bằng recall/precision theo đánh giá paper trên dataset lớn [4].

**Formal (ký hiệu):**

- `P` — tập primitive quan sát trong cửa sổ thời gian `T` (Noirlycan: 300 giây).
- `kind(p) ∈ {A, W, E}` — loại primitive.
- Điều kiện: `|{kind(p) : p ∈ P}| ≥ 2` ∧ `congruent(P)` ∧ `temporal(P)`.

### 1.5.3. Memory range congruence

Với mỗi primitive `p`, ghi `range(p) = [addr(p), addr(p)+size(p))` (khoảng nửa mở). Hai primitive `p`, `q` **congruent** nếu `range(p) ∩ range(q) ≠ ∅` hoặc một range chứa range kia [4], [12].

**Thách thức thực thi:** Execute API như `ResumeThread` không có address — paper track thread start address (`Rip`/`RIP`). Frida hook nên đọc `lpStartAddress` từ `CreateRemoteThread` / `NtCreateThreadEx` để gắn address cho primitive E (deviation D1 trong audit Noirlycan).

**Cross-kind only:** Engine Noirlycan so congruence giữa các kind khác nhau (A↔W, W↔E, A↔E) — đủ link chuỗi injection; tránh gom nhầm hai write độc lập cùng kind.

### 1.5.4. Temporal ordering

Thứ tự hợp lệ: **allocate → write → execute**, với ngoại lệ:

- **Gộp bước:** A và W đồng thời (section map) — timestamp bằng nhau hoặc map ngay sau create section.
- **Allocate lặp:** `VirtualProtectEx` sau write để RW→RX — vẫn là allocate kind, được phép lặp sau write [4].
- **Reject:** allocate *sau* execute (out-of-order không hợp lý cho injection chuẩn).

Noirlycan gán bậc `A=0, W=1, CONTEXT_READ=2, E=3`; reject khi allocate xuất hiện sau bậc cao hơn (deviation D3: cần siết thêm write sau execute).

### 1.5.5. Phân loại kỹ thuật sau phát hiện

Sau khi 2-of-3 kết luận injection, paper [4] dùng **tập API quan sát** và context (suspended process, section flag, APC, …) để gán nhãn kỹ thuật: Classic Remote Thread, APC, Early Bird, Thread Hijacking, Process Hollowing (classic/section), Reflective DLL, Module Stomping, AtomBombing, Process Doppelgänging, Ghosting/Herpaderping, v.v. Noirlycan mở rộng **21+ enum** (`InjectionTechnique`) bao gồm PoolParty, Mockingjay, fiber, thread pool [13].

### 1.5.6. Chuỗi injection đệ quy

Paper [4] báo ~**2 %** mẫu có injection lồng: A inject B, B inject C. Framework theo dõi re-trace khi victim resume. Noirlycan `injection_graph.py` và auto-attach Frida hỗ trợ một phần — metric prevalence chưa tái lập đủ quy mô paper.

## 1.6. Taxonomy kỹ thuật process injection (chi tiết)

Phần này mô tả **mười hai kỹ thuật chính** theo paper [4] cộng biến thể mở rộng trong Noirlycan — mỗi kỹ thuật: cơ chế, primitive điển hình, né tránh liên quan.

### 1.6.1. Classic Remote Thread Injection

**Cơ chế:** `OpenProcess` → `VirtualAllocEx` (A) → `WriteProcessMemory` (W) → `CreateRemoteThread` (E) trỏ `lpStartAddress` tới shellcode.

**Né tránh:** E1 (`NtCreateThreadEx`); E3 (target `explorer.exe`); E4 (direct syscall).

**Phát hiện [4]:** A+W+E — case đơn giản nhất cho 2-of-3.

### 1.6.2. DLL Injection (LoadLibrary)

**Cơ chế:** Thay shellcode bằng đường dẫn DLL; `CreateRemoteThread` gọi `LoadLibraryA/W` (E) sau khi write path string (W) vào remote memory (A thường implicit).

**Né tránh:** E3 — DLL dropped disk; E1 — `LdrLoadDll`.

**Phát hiện:** W+E; file provenance bổ sung cho E3.

### 1.6.3. APC Injection

**Cơ chế:** `OpenProcess`/`OpenThread` → allocate/write shellcode → `QueueUserAPC` (E) — APC queue gắn thread alertable; execute khi thread vào trạng thái alertable.

**Né tránh:** E2 — thiếu remote thread rõ ràng; E1 — `NtQueueApcThreadEx`.

**Phát hiện [4]:** W+E phổ biến; cần thread alertable hoặc force alert.

### 1.6.4. Early Bird APC Injection

**Cơ chế:** `CreateProcess(..., CREATE_SUSPENDED)` → allocate/write vào process con suspended → `QueueUserAPC` trên thread chính → `ResumeThread` (E). APC chạy trước entrypoint chính.

**Né tránh:** E2, E3 — không cần inject process đang chạy; victim mới spawn trông “sạch”.

**Phát hiện:** Evidence `create_suspended` + APC + resume; classifier `EARLY_BIRD_APC_INJECTION`.

### 1.6.5. Thread Execution Hijacking

**Cơ chế:** Suspend thread nạn nhân → `GetThreadContext` (context read) → sửa `Rip`/`RSP` → `SetThreadContext` (E) → `ResumeThread`.

**Né tránh:** E2 — không tạo thread mới (khó Event 8); E1 — `NtGetContextThread`/`NtSetContextThread`.

**Phát hiện [4]:** W + CONTEXT_READ + E; memory congruence qua `Rip` (extension D1 Noirlycan).

### 1.6.6. Process Hollowing (classic)

**Cơ chế:** `CreateProcess` suspended → `NtUnmapViewOfSection` unmap image gốc → allocate/write image độc hại → set thread context entrypoint → resume.

**Né tránh:** E1, E2, E3 — victim là process hợp pháp (`svchost` pattern).

**Phát hiện:** A+W+E hoặc unmap (write kind) + set context + resume; `PROCESS_HOLLOWING_CLASSIC`.

### 1.6.7. Process Hollowing (section-mapping variant)

**Cơ chế:** Dominant trong dataset [4]: `NtCreateSection` từ file payload → `NtMapViewOfSection` remote thay image → `SetThreadContext` + `ResumeThread`. Case study **Neurevt** trong paper §3.5.

**Né tránh:** E2 mạnh — gộp allocate+write.

**Phát hiện:** `NtMapViewOfSection` (W) + `ResumeThread` (E) = 2-of-3; test Noirlycan `test_detects_section_mapping_write_execute_chain`.

### 1.6.8. Reflective DLL Injection

**Cơ chế:** Loader manual-map PE DLL vào memory: parse headers, relocations, imports — **không** gọi `LoadLibrary`. Execute qua export hoặc shellcode bootstrap.

**Né tránh:** E1, E3 — không file DLL load event rõ; E6 — anti-analysis trong loader.

**Phát hiện [4]:** W+E; heuristic loại `LoadLibrary` present; Sysmon Event 7 (ImageLoad) absent cho reflective.

### 1.6.9. Module Stomping / Overloading

**Cơ chế:** Load DLL hợp pháp (RWX section hoặc RW) → ghi đè `.text` (W) → execute trong export/function pointer (E).

**Né tránh:** E2 — tái sử dụng mapping có sẵn; E3 — DLL signed.

**Phát hiện:** W+E trên range module đã load; ImageLoad trước write.

### 1.6.10. Process Doppelgänging

**Cơ chế:** Lạm dụng **NTFS transaction**: tạo file transacted, ghi payload, `CreateProcess` từ transacted section, rollback transaction — process chạy image “ma” không tồn tại disk.

**Né tránh:** E1, E3 — forensics disk miss file.

**Phát hiện:** Transaction API + spawn + inject primitives; `PROCESS_DOPPELGANGING` enum.

### 1.6.11. Process Ghosting và Process Herpaderping

**Ghosting:** Tạo file delete-pending, map section, ghi payload, tạo process từ section, đóng handle file (file bị xóa khi handle hết).

**Herpaderping:** Map file legitimate, ghi đè payload, tạo process, sau đó mới “sửa” file view — lừa scanner đọc file sạch.

**Né tránh:** E2, E3 — file system forensics khó.

**Phát hiện:** Pattern spawn + section + write; enum `PROCESS_GHOSTING`, `PROCESS_HERPADERPING` trong Noirlycan.

### 1.6.12. AtomBombing

**Cơ chế:** Ghi payload vào **global atom table** → `GlobalGetAtomName`/`NtQueueApcThread` kết hợp trick copy từ atom sang memory nạn nhân — execute qua APC.

**Né tránh:** E2 — đường dẫn không classic VirtualAllocEx.

**Phát hiện:** `GlobalAddAtom` (execute class trong manifest) + APC + write.

### 1.6.13. SetWindowsHookEx Injection

**Cơ chế:** Cài hook (`SetWindowsHookEx`) trỏ tới DLL trong process nạn nhân (thường cần DLL trong shared memory hoặc inject DLL trước).

**Né tránh:** E3 — DLL hợp pháp; execute qua message loop.

**Phát hiện:** `SetWindowsHookEx` (E) + W; `HOOK_INJECTION`.

### 1.6.14. Mockingjay Injection

**Cơ chế:** Tìm section **RWX** trong DLL signed (ví dụ `ssh.exe`, Chromium Embedded) → chỉ `WriteProcessMemory` (W) + hijack execution (E) — **không allocate** [7].

**Né tránh:** E2 mạnh — chỉ 2 primitive.

**Phát hiện [4]:** W+E đủ 2-of-3; classifier `MOCKINGJAY`.

### 1.6.15. PoolParty (Thread Pool)

**Cơ chế:** Lạm dụng Windows thread pool: queue work item / timer / wait callback trỏ shellcode đã write — execute không qua remote thread API cổ điển.

**Né tránh:** E2, E4 — tránh CreateRemoteThread signature.

**Phát hiện:** W + execute qua pool API (extension `POOLPARTY`); cần hook sâu hơn.

**Bảng 1.5.** Tóm tắt kỹ thuật injection, primitive và né tránh

| # | Kỹ thuật | Primitive điển hình | E1 | E2 | E3 |
|---|----------|---------------------|----|----|-----|
| 1 | Classic Remote Thread | A+W+E | ✓ | | ✓ |
| 2 | DLL Injection | W+E | ✓ | | ✓ |
| 3 | APC Injection | W+E | ✓ | ✓ | |
| 4 | Early Bird APC | W+E | | ✓ | ✓ |
| 5 | Thread Hijacking | W+E (+ctx) | ✓ | ✓ | |
| 6 | Hollowing classic | A+W+E | ✓ | | ✓ |
| 7 | Hollowing section | W+E | ✓ | ✓ | ✓ |
| 8 | Reflective DLL | W+E | ✓ | | ✓ |
| 9 | Module Stomping | W+E | | ✓ | ✓ |
| 10 | Doppelgänging | A+W+E | ✓ | ✓ | ✓ |
| 11 | Ghosting/Herpaderping | W+A+E | ✓ | ✓ | ✓ |
| 12 | AtomBombing | W+E | | ✓ | |
| 13 | SetWindowsHookEx | W+E | | | ✓ |
| 14 | Mockingjay | W+E | | ✓ | ✓ |
| 15 | PoolParty | W+E | | ✓ | |

## 1.7. Sysmon — telemetry kernel cho phát hiện injection

**Sysmon** (System Monitor) là thành phần Sysinternals ghi log hành vi hệ thống qua driver kernel `SysmonDrv.sys` [10]. Trong luận văn, Sysmon đóng vai **lớp phòng thủ chống E4** — quan sát artifact cross-process mà không phụ thuộc hook user-mode.

### 1.7.1. Kiến trúc Sysmon

Sysmon.exe (service LocalSystem) đăng ký với driver; driver cài callback kernel:

- `PsSetCreateProcessNotifyRoutineEx` — process create/exit.
- `PsSetLoadImageNotifyRoutine` — DLL/EXE map.
- `ObRegisterCallbacks` — handle operation (OpenProcess).
- Minifilter — file create.
- ETW Threat Intelligence — CreateRemoteThread, …

Log ghi vào Windows Event Log (channel `Microsoft-Windows-Sysmon/Operational`).

### 1.7.2. Sự kiện Sysmon trong phạm vi Noirlycan

**Bảng 1.6.** Sự kiện Sysmon và vai trò phát hiện injection / né tránh

| Event ID | Tên | Cơ chế kernel | Chống né tránh | Vai trò Noirlycan |
|----------|-----|---------------|----------------|-------------------|
| **1** | ProcessCreate | Process notify | E3, E4 (syscall spawn vẫn log) | Lineage, parent PID, `CreationUtcTime`, command line, `CurrentDirectory` |
| **3** | NetworkConnect | WFP ETW | — | Post-injection C2 beacon watch |
| **7** | ImageLoad | Image notify | E4 (kernel) | Phân biệt reflective vs LoadLibrary |
| **8** | CreateRemoteThread | ETW TI | **E4** — kể cả direct syscall | Fallback execute primitive; `SourceImage`, `TargetImage`, `StartAddress` |
| **10** | ProcessAccess | ObRegisterCallbacks | **E4** | `OpenProcess` với `GrantedAccess` suspicious (`0x1fffff`, `0x143a`, …) |
| **11** | FileCreate | Minifilter | E3 | File-drop provenance; hash SHA256 (config Noirlycan) |
| **15** | FileCreateStreamHash | Minifilter | E3 alt | ADS (ít dùng trong config hiện tại) |

Config `sysmon-noirlycan.xml` [13]: ProcessCreate broad; FileCreate filter extension executable/script; ProcessAccess filter access mask; CreateRemoteThread exclude none (log all); ImageLoad filter `ntdll`, `kernel32`.

### 1.7.3. Giới hạn Sysmon

- **Không** có đối số đầy đủ mọi NT API (vd. size write, protection flags) — Frida bổ sung congruence.
- **Kernel rootkit** (O3 threat model) có thể blind driver — out-of-scope.
- Event 8 không cover mọi execute vector (APC-only, thread pool) — cần Frida.
- Volume log cao nếu config quá rộng — lab VM chấp nhận được.

### 1.7.4. Sysmon và E4 — ma trận tin cậy

Khi malware direct-syscall `NtCreateThreadEx`:

- Frida miss → không có primitive chi tiết từ hook export.
- Sysmon Event 8 vẫn fire (kernel ETW TI) → có `StartAddress`, `SourceImage`, `TargetImage`.

Correlator Noirlycan merge hai nguồn: Sysmon event chuyển thành primitive EXECUTE sơ cấp; Frida cung cập W/A với address. Congruence có thể yếu hơn paper — khai báo trong đánh giá RQ2/RQ4.

## 1.8. Frida — instrumentation user-mode và kiến trúc telemetry kép

### 1.8.1. Frida overview

**Frida** là toolkit dynamic instrumentation [5]: inject **agent** JavaScript (V8) vào process target qua `frida-server` hoặc `frida-gadget`; hook function bằng `Interceptor.attach(address, { onEnter, onLeave })`. Noirlycan dùng Frida để:

- Hook export `kernel32.dll` / `ntdll.dll` liên quan injection (manifest `PAPER_API_CLASSES` + extensions iRed.team).
- Trích xuất đối số: `lpBaseAddress`, `nSize`, `flAllocationType`, `lpStartAddress`, `lpBuffer`, process/thread handles.
- Emit **observation** tới collector Python qua message bus JSON.

Script `windows_injection_hooks.js` (~1900 dòng) [13] implement helper normalize API (`Zw*` alias `Nt*`), xử lý CONTEXT pointer cho thread hijack, và phân biệt `emit` vs `emitObservation` (read-only không đếm 2-of-3).

### 1.8.2. Ưu điểm so với chỉ Sysmon

| Khía cạnh | Frida | Sysmon |
|-----------|-------|--------|
| Đối số API (addr, size, prot) | ✓ Chi tiết | ✗ Hạn chế |
| Memory congruence [4] | ✓ Trực tiếp | △ Một phần (StartAddress) |
| APC, MapView, Protect | ✓ Hook NT | ✗ Không log hết |
| Overhead | Cao hơn | Thấp hơn |
| E4 direct syscall | ✗ Miss | ✓ Event 8/10 |
| E6 anti-Frida | ✗ Risk | ✓ Không agent trong victim hook path |

### 1.8.3. Chế độ attach và E6

- **`spawn`:** Frida tạo process suspended, inject agent trước entrypoint — giảm miss primitive đầu (T2 threat model); giảm cửa sổ malware chạy trước hook.
- **`attach`:** Gắn process đang chạy — phù hợp file-drop đã spawn; risk miss early API.
- **`auto-attach-new-processes`:** Theo dõi victim sau injection đệ quy [4].

E6: malware scan Frida artifact → luận văn **không** triển khai stealth agent; ghi limitation và khuyến nghị spawn cho thí nghiệm.

### 1.8.4. Kiến trúc kép Sysmon ∪ Frida (Hình 1.1)

Luận văn đề xuất kiến trúc **tăng cường phát hiện dưới né tránh** bằng cách kết hợp:

```
[Loader/Malware] 
    → API calls → Frida hooks → Primitives (detail)
    → Kernel path → Sysmon driver → Events 1/7/8/10/11
         ↓
    [Collector Python] → Correlator (2-of-3, congruence, temporal)
         ↓
    Finding + Technique label + Provenance
         ↓
    [Dashboard / JSONL]
```

**Hình 1.1** (mô tả conceptual; bản đồ kiến trúc đầy đủ tại `docs/design/architecture-comparison-template.svg` và Chương 5) thể hiện trust boundary: Frida (user, untrusted nếu E4/E6) + Sysmon (kernel, trusted nếu O3 không xảy ra) → correlator (trusted).

### 1.8.5. Fidelity và giả định M5

Luận văn giả định Frida hook **trung thực** về thứ tự và đối số (M5 threat model) — cần benchmark Frida fidelity (Phụ lục E): so sánh N lần gọi API với ground truth ETW/`SilkETW` hoặc controlled PoC. Overhead hook có thể thay đổi timing — **không** claim đo lường E5 timing evasion.

### 1.8.6. Hướng thay thế: ETW Threat Intelligence

Microsoft **ETW Threat Intelligence** provider cung cấp syscall-level event kernel — không bypass bằng user-mode unhooking. Luận văn ghi nhận hướng phát triển thay/bổ sung Frida (Kết luận); hiện thực Noirlycan dùng Sysmon (đã tích hợp ETW TI cho Event 8) làm bước trung gian.

### 1.8.7. Tóm tắt chương

Chương 1 đã trình bày nền tảng lý thuyết cho luận văn *Tăng cường phát hiện mã độc dưới các hình thức né tránh*:

1. **Mô hình Windows** — process, thread, virtual memory, section object, và lớp Win32/NT API — bối cảnh mọi kỹ thuật injection.
2. **Process injection** — hành vi né attribution (T1055), prevalence ~16,5 % theo [4], chuỗi file-drop → spawn → inject trong lab.
3. **Sáu nhóm né tránh E1–E6** — từ biến thể API (E1) đến anti-sandbox (E5, **ngoài phạm vi hiện thực**) và anti-Frida (E6, hạn chế).
4. **Phương pháp [4]** — operational primitive (allocate, write, execute), equivalence class, quy tắc 2-of-3, memory congruence, temporal ordering — **căn cứ khoa học chính** của correlator Noirlycan.
5. **Taxonomy 15+ kỹ thuật** — từ classic remote thread đến PoolParty/Mockingjay, mỗi kỹ thuật gắn primitive và nhóm né tránh.
6. **Sysmon** — telemetry kernel (Event 1, 7, 8, 10, 11) fallback chống E4, provenance chống E3.
7. **Frida** — telemetry user-mode chi tiết cho congruence; kiến trúc kép Sysmon ∪ Frida tăng độ bền phát hiện dưới né tránh hook.

Chương 2 sẽ đặt phương pháp [4] trong bức tranh công trình liên quan (Klein [7], Starink [12], sandbox evasion [6], [8]) và làm rõ vị trí đóng góp replication + extension lab của luận văn so với nghiên cứu quy mô 56.340 mẫu của tác giả gốc.

---

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

---

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

---

# CHƯƠNG 4. PHƯƠNG PHÁP TĂNG CƯỜNG PHÁT HIỆN

Chương này trình bày phương pháp luận của luận văn *Tăng cường phát hiện mã độc dưới các hình thức né tránh*, căn cứ chính thức vào công trình Di Pietro, D'Elia và Querzoni tại ASIA CCS 2025 [4]. Phương pháp [4] được thiết kế để phát hiện process injection khi malware **né signature API** (nhóm né tránh E1) hoặc **gộp/ẩn bước operational** (E2). Luận văn kế thừa lõi phương pháp đó — ba *operational primitive*, lớp tương đương API (*equivalence class*), quy tắc *2-of-3*, đồng nhất vùng nhớ (*memory congruence*) và ràng buộc thứ tự thời gian (*temporal ordering*) — rồi mở rộng hai tầng bổ sung nhằm đối phó **né attribution** (E3) và **né hook user-mode** (E4). Các hình thức né tránh E5 (phát hiện sandbox/VM) và E6 (anti-instrumentation) được khai báo rõ trong Chương 3; **module anti-evasion của [4] tương ứng E5 không được hiện thực** trong artifact Noirlycan và không nằm trong phạm vi claim khoa học của luận văn.

---

## 4.1. Tổng quan pipeline phương pháp

### 4.1.1. Hai tầng tăng cường

Phương pháp luận văn gồm **hai tầng** bổ trợ lẫn nhau:

1. **Tầng phát hiện chống biến thể (E1, E2)** — kế thừa trực tiếp [4]: mọi lời gọi Windows API liên quan injection được ánh xạ vào một trong ba primitive *allocate*, *write*, *execute*; một chuỗi injection được kết luận khi quan sát **ít nhất hai primitive khác loại** trên cùng cặp `(actor_pid, target_pid)` và thỏa congruence + temporal.
2. **Tầng ngữ cảnh và phòng thủ sâu (E3, E4)** — đóng góp của luận văn: (a) pipeline *file provenance* gắn nguồn gốc file với chuỗi injection; (b) *telemetry kép* Sysmon (kernel) ∪ Frida (user-mode) để giảm false negative khi hook bị né.

Hình 4.1 (tham chiếu `docs/architecture-diagrams.md`) so sánh pipeline batch của [4] (QEMU sandbox → trace API → analyzer offline) với pipeline Noirlycan (lab Windows real-time: file/process events → Frida primitives → correlator → finding → dashboard).

### 4.1.2. Luồng dữ liệu end-to-end

Pipeline Noirlycan được mô tả bằng các giai đoạn sau:

```
[Giai đoạn 1 — Thu thập]
  FileDropWatcher / Sysmon E11,E15  →  FileEvent
  Sysmon E1                         →  ProcessEvent
  Frida hooks (windows_injection_hooks.js) → MemoryPrimitive
  Sysmon E3 (tùy chọn)              →  NetworkConnectionEvent

[Giai đoạn 2 — Tiền xử lý]
  FileTriage (SHA256, PE, entropy, Authenticode) → làm giàu FileEvent
  runtime_event_to_primitive / runtime_event_to_process → chuẩn hóa Frida

[Giai đoạn 3 — Tương quan]
  Correlator.add_file / add_process / add_primitive
    → kiểm 2-of-3 + temporal + congruence
    → scoring + technique_classifier
    → Finding

[Giai đoạn 4 — Đầu ra]
  JSONL session log  →  Dashboard analyst  →  export / reclassify
```

Khác với [4] — nơi phân tích chạy *post-mortem* trên trace tĩnh — Noirlycan duy trì **cửa sổ trượt 300 giây** (`Correlator.window_seconds = 300`) và đánh giá lại chuỗi `(actor_pid, target_pid)` mỗi khi có primitive mới, cho phép phát hiện real-time trong phòng lab.

### 4.1.3. Định nghĩa đối tượng quan sát

Ký hiệu dùng xuyên suốt chương:

| Ký hiệu | Ý nghĩa |
|---------|---------|
| $\mathcal{P}$ | Tập tiến trình trên host |
| $\pi \in \{\texttt{allocate}, \texttt{write}, \texttt{execute}\}$ | Operational primitive theo [4], [7] |
| $\mathrm{obs}(t, a, v, \pi, r)$ | Quan sát primitive $\pi$ lúc $t$, actor $a$, victim $v$, vùng nhớ $r = [addr, addr+size)$ |
| $K \subseteq \{\texttt{A}, \texttt{W}, \texttt{E}\}$ | Tập loại primitive đã quan sát trên một chuỗi |
| $\mathrm{score}(K, ctx)$ | Điểm tin cậy 0–100 sau khi thỏa quy tắc phát hiện |

Một **Finding** là bản ghi có cấu trúc gồm: timestamp, actor/target PID và image, danh sách primitive, điểm số, evidence, kỹ thuật injection suy luận (nếu có), và `related_file` khi pipeline provenance khớp.

---

## 4.2. Operational primitive và equivalence class (chống E1)

### 4.2.1. Ba primitive theo [4]

Theo Klein et al. [7] và formal hóa của [4], process injection user-mode có thể mô hình hóa bằng ba thao tác operational trên vùng nhớ victim:

1. **Allocate ($\texttt{A}$)** — chuẩn bị vùng nhớ (cấp phát, map section, đổi protection sang executable).
2. **Write ($\texttt{W}$)** — đặt payload (shellcode, PE, đường dẫn DLL) vào vùng đó.
3. **Execute ($\texttt{E}$)** — chuyển luồng thực thi tới vùng đó (remote thread, APC, resume, set context, load library, …).

**E1 (biến thể API):** malware thay `CreateRemoteThread` bằng `NtCreateThreadEx`, hoặc Win32 bằng NT/Zw export tương đương. Phương pháp [4] không khớp chuỗi API cố định mà khớp **lớp tương đương** — mọi API cùng ngữ nghĩa operational được gom vào một primitive.

### 4.2.2. Bảng equivalence class

Manifest `PAPER_API_CLASSES` trong `kernel/classification/api_manifest.py` liệt kê ánh xạ chính thức (Phụ lục A). Tóm tắt Bảng 4.1:

**Bảng 4.1.** Lớp tương đương API theo [4] (trích)

| Lớp | Primitive | Ví dụ API |
|-----|-----------|-----------|
| allocate | A | `VirtualAllocEx`, `NtAllocateVirtualMemory`, `VirtualProtectEx`, `NtCreateSection`, `CreateFileMapping*`, `MapViewOfFile*` |
| write | W | `WriteProcessMemory`, `NtWriteVirtualMemory`, `NtMapViewOfSection`, `NtUnmapViewOfSection`, `RtlCopyMemory` |
| execute | E | `CreateRemoteThread*`, `NtCreateThreadEx`, `QueueUserAPC`, `SetThreadContext`, `ResumeThread`, `LoadLibrary*`, `SetWindowsHookEx*`, `NtAddAtom` |
| remote_read | *(quan sát)* | `ReadProcessMemory`, `NtReadVirtualMemory` — **không** tính vào 2-of-3 (deviation D2 đã sửa) |
| context_read | *(lab)* | `GetThreadContext`, `NtGetContextThread` — chỉ báo hijack-prep, không tính 2-of-3 |

Mở rộng lab: `IRED_TEAM_API_CLASSES` bổ sung fiber, threadpool, window memory, TXF — phục vụ classifier iRed.team mà không thay đổi quy tắc 2-of-3 cốt lõi.

### 4.2.3. Cơ chế hook chống E1

Frida `Interceptor.attach` trên export của `kernel32.dll`, `ntdll.dll`, … Alias `Zw*` được resolve cùng stub với `Nt*`. Tập `DYNAMIC_INJECTION_APIS` trong `windows_injection_hooks.js` bao phủ API resolve động qua `GetProcAddress`. Mỗi lần gọi thành công phát sinh sự kiện `memory_primitive` hoặc `api_observation` với trường `kind` đã ánh xạ.

---

## 4.3. Quy tắc 2-of-3 (chống E2)

### 4.3.1. Động cơ né tránh E2

Malware thường **gộp hoặc ẩn bước** để né detector dựa trên chuỗi A→W→E đầy đủ:

- **Section mapping:** `NtCreateSection` + `NtMapViewOfSection` (remote) vừa map vừa ghi — chỉ cần W+E.
- **Mockingjay / RWX sẵn có:** payload copy vào vùng executable có sẵn — W+E hoặc chỉ E.
- **Process Hollowing (section variant):** allocate+write gộp trong map; execute qua `SetThreadContext` + `ResumeThread`.

Paper [4] chứng minh trên dataset lớn rằng yêu cầu **đủ ba bước** gây false negative đáng kể; quy tắc **ít nhất 2 trong 3 primitive khác loại** tăng recall mà vẫn giữ precision nhờ congruence và temporal.

### 4.3.2. Phát biểu hình thức

Cho cặp actor $a$ và victim $v$, tập quan sát trong cửa sổ thời gian $T$:

$$\mathcal{O}_{a,v,T} = \{\, \mathrm{obs}(t_i, a, v, \pi_i, r_i) \mid t_i \in T \,\}$$

Định nghĩa tập loại primitive:

$$K = \{\, \pi \mid \exists\, \mathrm{obs}(\cdot, a, v, \pi, \cdot) \in \mathcal{O}_{a,v,T} \,\}$$

**Quy tắc 2-of-3** (Công thức 4.1):

$$|K \cap \{\texttt{A}, \texttt{W}, \texttt{E}\}| \geq 2 \tag{4.1}$$

**Điều kiện bổ sung** (theo [4] §3.3–3.4), chuỗi chỉ được chấp nhận nếu:

$$\mathrm{Congruence}(\mathcal{O}_{a,v,T}) \land \mathrm{Temporal}(\mathcal{O}_{a,v,T}) \tag{4.2}$$

Implementation: `operational_kind_count(kinds) >= 2` trong `_evaluate_chain`, loại trừ `CONTEXT_READ` khỏi đếm (`kernel.analysis.primitives.operational_kind_count`).

### 4.3.3. Ví dụ minh họa E2

| Kịch bản | Primitive quan sát | $|K|$ | Kết luận |
|----------|-------------------|-------|----------|
| Classic DLL injection | A + W + E | 3 | Finding (cao điểm) |
| Section-mapping (*neurevt*) | W (`NtMapViewOfSection`) + E (`ResumeThread`) | 2 | Finding (test `test_detects_section_mapping_write_execute_chain`) |
| Chỉ `WriteProcessMemory` | W | 1 | **Không** finding (`test_requires_two_distinct_primitives`) |
| Debugger remote read | A + read-only | 1 | **Không** (D2: read không tính W) |

---

## 4.4. Memory range congruence

### 4.4.1. Định nghĩa

Hai quan sát $\mathrm{obs}_1, \mathrm{obs}_2$ **đồng nhất vùng nhớ** nếu khoảng nửa mở $r_1 = [addr_1, addr_1 + size_1)$ và $r_2 = [addr_2, addr_2 + size_2)$ **giao nhau**:

$$\mathrm{overlap}(r_1, r_2) \iff addr_1 < addr_2 + size_2 \;\land\; addr_2 < addr_1 + size_1 \tag{4.3}$$

Starink et al. [12] dùng ý tưởng tương tự trong behavior graph; [4] áp dụng để loại false positive khi cùng process thực hiện nhiều thao tác heap độc lập.

### 4.4.2. Thuật toán trong Noirlycan

Hàm `_has_memory_congruence` xây dựng tập khoảng từ mỗi primitive qua `_memory_link_ranges`:

- `address` + `size` chính;
- `thread_parameter` trên EXECUTE (DLL path buffer cho `CreateRemoteThread`);
- `context_pointer` liên kết `GetThreadContext` ↔ `SetThreadContext`;
- `address == 0` coi như thiếu (hook không đọc được base — thường gặp với `NtAllocateVirtualMemory`).

Congruence yêu cầu **ít nhất một cặp primitive khác loại** có khoảng overlap. Ngoại lệ thực dụng: khi `NtAllocateVirtualMemory` không trả address nhưng có nhiều WRITE + EXECUTE cross-process, chuỗi vẫn được chấp nhận nếu `operational_kind_count >= 2` và chỉ một loại có range (`services/analysis/domain/correlation.py` dòng 454–458).

### 4.4.3. Deviation D1 (khai báo trung thực)

Execute-level API (`ResumeThread`, …) lịch sử không mang `address`. Fix D1: hook đọc `Rip` từ `CONTEXT` cho `SetThreadContext`, `lpStartAddress` cho `CreateRemoteThread` — test `test_set_thread_context_with_rip_overlaps_write_buffer` xác nhận. Khi execute vẫn thiếu address, congruence có thể suy yếu; luận văn **không claim** precision tương đương paper trên mọi biến thể execute-only.

---

## 4.5. Temporal ordering

### 4.5.1. Quy tắc [4]

Thứ tự canonical: **allocate → write → execute**, với hai ngoại lệ được paper cho phép:

1. **Allocate lặp** — resize, đổi protection RWX→RX.
2. **Gộp bước** — section mapping có thể phát sinh W đồng thời với map (allocate ngữ nghĩa đã xảy ra trước hoặc trong cùng API).

### 4.5.2. Formal hóa implementation

Gán bậc:

$$\mathrm{rank}(\texttt{A}) = 0,\; \mathrm{rank}(\texttt{W}) = 1,\; \mathrm{rank}(\texttt{E}) = 3$$

(`CONTEXT_READ` = 2, không gây reject.)

Sắp xếp primitive theo timestamp; duyệt tuần tự, với mỗi $\pi \in \{\texttt{A}, \texttt{W}, \texttt{E}\}$:

$$\text{nếu } \mathrm{rank}(\pi) < \mathrm{last\_rank} \text{ và } \pi \in \{\texttt{A}, \texttt{W}\} \Rightarrow \text{reject} \tag{4.4}$$

Fix D3: từ chối WRITE sau EXECUTE (`test_rejects_write_after_execute_temporal_order`). Cho phép allocate sau write (re-protect) vì rank A = 0 < last chỉ reject khi A xuất hiện **sau** W hoặc E đã nâng last_rank — logic trong `_has_temporal_consistency`.

---

## 4.6. Pipeline file provenance (chống E3)

### 4.6.1. Động cơ né tránh E3

Malware **né attribution** bằng cách inject vào tiến trình hợp pháp (`msedge.exe`, `explorer.exe`) thay vì giữ process tree bất thường. Signature chỉ nhìn injection trên victim sẽ **mất dấu loader gốc**. Paper [4] tập trung trace execution, không xây pipeline file→process end-to-end cho lab endpoint.

### 4.6.2. Luồng provenance

```
Sysmon E11/E15 (FileCreate)  ──┐
FileDropWatcher (poll)       ──┼→  FileEvent  →  FileTriage
                               │       ↓
Sysmon E1 (ProcessCreate)  ────┘  add_process: created_from_file = image path
                                         ↓
                              add_primitive → Finding.related_file
```

Hàm `_related_file_for_process` liên kết theo thứ tự ưu tiên: (1) `created_from_file`; (2) image path khớp `files_by_path`; (3) image của parent process.

### 4.6.3. Static triage

Module `triage.py` tính:

- SHA256, entropy Shannon (1 MB đầu);
- PE header (`pefile`), Authenticode (`signtool` / PowerShell);
- import injection API đáng ngờ;
- heuristic thư mục (`SUSPICIOUS_DIRECTORIES`).

Metadata làm giàu scoring (mục 4.9) và dashboard — hỗ trợ analyst **phá vỡ né attribution** bằng cách truy ngược file drop tới loader.

---

## 4.7. Telemetry kép (chống E4)

### 4.7.1. Động cơ né tránh E4

**Direct syscall** và **unhook ntdll** né Frida user-mode. Sysmon driver (`SysmonDrv.sys`) đăng ký kernel callback — Event ID 8 (CreateRemoteThread), 10 (ProcessAccess), 11 (FileCreate), 1 (ProcessCreate) — **không phụ thuộc** export hook trong process nạn nhân.

### 4.7.2. Ma trận bổ sung

| Tình huống E4 | Frida | Sysmon | Kết quả mong đợi |
|---------------|-------|--------|------------------|
| Win32/NT qua export | Có primitive + address | E8/E10 (context) | Finding đầy đủ |
| Syscall thuần, unhook | Miss primitive | E8/E10 vẫn log | Cảnh báo một phần; **thiếu congruence** |
| File drop + spawn | Miss nếu attach trễ | E11 + E1 | Provenance vẫn có |

Luận văn claim **giảm false negative một phần** dưới E4, không claim phát hiện injection đầy đủ khi chỉ có Sysmon (thiếu address/size cho congruence).

### 4.7.3. Chế độ spawn

`noirlycan-telemetry spawn` khởi chạy mẫu **dưới Frida từ đầu**, giảm rủi ro miss primitive đầu (liên quan E6). Đây là biện pháp methodology, không thay thế anti-evasion E5.

---

## 4.8. Phân loại kỹ thuật injection

Sau khi có Finding, `kernel/classification/technique_classifier.py` áp dụng **rule-based classifier** (21+ enum `InjectionTechnique`), căn cứ taxonomy §4 của [4] và mở rộng iRed.team:

| Rule (rút gọn) | Kỹ thuật | ATT&CK |
|----------------|----------|--------|
| W section + E resume + CREATE_SUSPENDED | `process_hollowing_section` | T1055.012 |
| CRT + thread_parameter trong write buffer | `dll_injection` | T1055.001 |
| APC + suspended child | `early_bird_apc_injection` | T1055.004 |
| Local A+W RWX, không transfer | `shellcode_injection` / staging | T1055.002 |
| TXF + section | `process_doppelganging` | T1055.013 |
| NtSetInformationFile + section | `process_ghosting` | T1055.012 |

`apply_classification` gọi sau scoring; confidence `high` khi đủ 3 primitive + execution_confirmed. Ghosting/Herpaderping có enum nhưng phụ thuộc precursor observation từ hook.

**E5:** classifier không chạy nếu malware **không inject** do phát hiện VM — out-of-scope; recall trên lab có thể thấp hơn [4].

---

## 4.9. Mô hình scoring

Điểm 0–100 (`Correlator._score`) **không** thay thế quy tắc 2-of-3 mà **xếp hạng** finding và lọc `minimum_score` (mặc định 50):

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

Severity: CRITICAL ≥ 85, HIGH ≥ 70, MEDIUM ≥ 50. Score ≥ 70 kích hoạt **network watch** 300 giây trên `target_pid` (Sysmon E3).

Heuristic giảm false positive: `_resume_only_spawn_to_trusted_target` cap score ≤ 50 khi chỉ ResumeThread vào Program Files.

---

## 4.10. Thuật toán (pseudo-code)

### Thuật toán 4.1 — Ánh xạ API → primitive

```
function MAP_API(api_name):
    for class in PAPER_API_CLASSES ∪ IRED_TEAM_API_CLASSES:
        if api_name in class.apis:
            if class.primitive == "observation":
                return OBSERVATION_ONLY
            return class.primitive
    return UNKNOWN

function ON_API_CALL(api, args, retval):
    if not success(retval): return
    kind ← MAP_API(api)
    if kind == OBSERVATION_ONLY:
        emit api_observation(...)
        return
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
    P ← bucket[(actor, target)]
    K ← { p.kind | p ∈ P } \ { CONTEXT_READ }
    if |K ∩ {A,W,E}| < 2: return []
    if not TEMPORAL_OK(P): return []
    if not CONGRUENCE_OK(P): return []
    score, evidence ← SCORE(P, related_process, related_file)
    if score < minimum_score: return []
    if score ≤ previous_reported_score: return []  // chỉ upgrade
    finding ← Finding(..., apply_classification(...))
    if score ≥ 70: enable_network_watch(target)
    return [finding]
```

### Thuật toán 4.3 — Congruence

```
function CONGRUENCE_OK(P):
    ranges_by_kind ← group memory_link_ranges(p) for p in P
    if count_linked_primitives < 2: return TRUE  // không đủ dữ liệu
    for each pair (kind1, kind2) where kind1 ≠ kind2:
        for r1 in ranges_by_kind[kind1], r2 in ranges_by_kind[kind2]:
            if overlap(r1, r2): return TRUE
    if |operational_kinds| ≥ 2 and only WRITE has ranges:
        return TRUE  // NtAllocateVirtualMemory edge case
    return FALSE
```

### Thuật toán 4.4 — File provenance

```
function ADD_PROCESS(proc):
    path ← normalize(proc.image)
    if path in files_by_path:
        proc.created_from_file ← path
    processes_by_pid[proc.pid] ← proc

function RELATED_FILE(proc):
    if proc.created_from_file: return files[proc.created_from_file]
    if proc.image in files: return files[proc.image]
    if parent exists: return files[parent.image]
    return NULL
```

---

## 4.11. Ranh giới phương pháp so với [4]

| Khía cạnh | [4] | Luận văn (Noirlycan) |
|-----------|-----|----------------------|
| 2-of-3 + congruence + temporal | ✅ | ✅ (có test) |
| Equivalence class | Table 1 đầy đủ | `PAPER_API_CLASSES` + lab extension |
| Anti-evasion E5 | ✅ Tích hợp | ❌ **Không hiện thực** — chỉ ghi `kernel/analysis/evasion.py` signal |
| Dataset 56k + prevalence | ✅ | ❌ Ngoài phạm vi |
| File provenance E3 | ❌ | ✅ Đóng góp |
| Real-time endpoint | ❌ | ✅ Đóng góp |
| Recursive chain metric ~2% | ✅ | ⚠️ `InjectionGraph` một phần |

Luận văn **không** claim số liệu 16,5 % hay 21,2 % của [4]; các con số đó thuộc paper gốc và phụ thuộc module anti-evasion mà luận văn **chưa triển khai**.

---

## 4.12. Ví dụ đi sâu: phân tích chuỗi section-mapping

Để minh họa cách các thành phần phương pháp tương tác, xét chuỗi cross-process vào `msedge.exe` (case study *neurevt* [4], test `test_detects_section_mapping_write_execute_chain`):

**Bước 1 — Provenance (E3):** Sysmon E11 hoặc file watcher ghi nhận `loader.exe` trong `%TEMP%`. Static triage: PE=True, signed=False, entropy=7,2. Khi loader spawn (E1, flag `CREATE_SUSPENDED`), `add_process` gắn `created_from_file`.

**Bước 2 — Primitive W:** Hook bắt `NtMapViewOfSection` với `target_pid` = Edge, `address` = 0x200000, `protection` = EXECUTE_READWRITE. Một lần map remote vừa đóng vai trò write vừa expose vùng executable — **không cần** quan sát `VirtualAllocEx` riêng (E2).

**Bước 3 — Kiểm 2-of-3:** $K = \{\texttt{W}, \texttt{E}\}$, $|K| = 2$ — thỏa Công thức (4.1).

**Bước 4 — Temporal:** ResumeThread (E) sau MapView (W); không có A lùi sau E — thỏa (4.4).

**Bước 5 — Congruence:** Execute không mang address; với chỉ W+E có range, `_has_memory_congruence` chấp nhận khi đủ operational kinds và overlap implicit qua cùng target (edge case Resume-only đã được test acceptance).

**Bước 6 — Scoring:** W+E confirmed → +45; cross-process +15; section +10; CREATE_SUSPENDED +15; related_file +10; unsigned +10 → tổng ≥ 70 (HIGH).

**Bước 7 — Classifier:** Rule `process_hollowing_section` nếu thêm context read/set; với W+E resume → `section_mapping_injection` hoặc hollowing tùy evidence.

So với baseline signature `VirtualAllocEx → WriteProcessMemory → CreateRemoteThread`, chuỗi này **không match** — minh chứng trực tiếp giá trị phương pháp [4] dưới E2.

## 4.13. Ví dụ đi sâu: classic DLL injection (E1)

Malware E1 thay `CreateRemoteThread` bằng `NtCreateThreadEx`:

1. `VirtualAllocEx` → A, range $r_a$
2. `WriteProcessMemory` ghi đường dẫn DLL → W, $r_w$ overlap $r_a$
3. `NtCreateThreadEx` start = `LoadLibraryW`, parameter = $r_a$ → E, `thread_parameter` overlap $r_w$

Equivalence class map cả ba API vào $\{\texttt{A}, \texttt{W}, \texttt{E}\}$ dù tên export khác Win32 classic. Congruence liên kết qua `thread_parameter` (Thuật toán 4.3). Pattern `_dll_path_remote_thread_pattern` tăng +5 score và classifier → `dll_injection` (MITRE T1055.001).

## 4.14. Self-injection và local staging

Paper [4] tập trung cross-process; Noirlycan mở rộng `actor_pid == target_pid`:

- `VirtualAlloc` + `memcpy` local RWX → A+W, `local_staging` evidence, score ≥ 50.
- Config `.classifier_rules.json` có thể bật `ignore_same_process_findings` nếu lab muốn giảm FP installer.

Phương pháp vẫn áp dụng 2-of-3; scoring ưu tiên cross-process (+15) để phân biệt mối đe dọa attribution E3.

## 4.15. CONTEXT_READ — extension lab (không phải primitive [4])

`GetThreadContext` / `NtGetContextThread` được hook với kind `CONTEXT_READ`:

- **Không** đếm vào $|K|$ cho 2-of-3.
- Tăng +5 score khi có hijack prep mà chưa execution_confirmed.
- Classifier dùng context_read + SET_SUSPENDED → `thread_hijack`, `process_hollowing_classic`.

Phải khai báo rõ trong luận văn để tránh reviewer hiểu nhầm là primitive thứ tư của [4] (audit D7).

## 4.16. Chiến lược giảm false positive

Paper [4] dùng congruence + temporal; Noirlycan bổ sung heuristic scoring:

| Heuristic | Mục đích |
|-----------|----------|
| `minimum_score` ≥ 50 | Lọc chuỗi yếu |
| `_resume_only_spawn_to_trusted_target` | Cap 50 — installer resume Edge/Program Files |
| `missing_execution_transfer` cap 75 | Staging chưa execute |
| `require_cross_process_findings` (config) | Lab chỉ báo inject cross-process |
| Network watch chỉ khi score ≥ 70 | Tránh alert noise |

Các heuristic là **lab tuning**, không thay đổi định nghĩa 2-of-3 [4].

## 4.17. Liên hệ MITRE ATT&CK

Mỗi finding có thể map technique classifier → sub-technique T1055:

| Pattern primitive + evidence | ATT&CK (ví dụ) |
|------------------------------|----------------|
| CRT + LoadLibrary remote | T1055.001 DLL injection |
| APC + suspended | T1055.004 Asynchronous Procedure Call |
| Section + resume | T1055.012 Process Hollowing |
| SetWindowsHookEx | T1055.004 Hook injection |
| TxF + section | T1055.013 Process Doppelgänging |

Phân loại phục vụ analyst sau bước phát hiện primitive — tách biệt với quyết định 2-of-3.

## 4.19. So sánh pipeline [4] và Noirlycan

**Bảng 4.2.** Pipeline phân tích — paper vs luận văn

| Giai đoạn | [4] Sap4Sec | Noirlycan |
|-----------|-------------|-----------|
| Môi trường thực thi | QEMU sandbox batch | Windows 10/11 VM lab |
| Thu thập trace | API logger toàn process tree | Frida hook + Sysmon events |
| Anti-evasion E5 | Có — patch env/timing | **Không** |
| Phân tích | Offline analyzer Python | Online Correlator 300s window |
| Đầu ra | Label + technique + log | Finding JSONL + dashboard |
| Provenance file | Không | FileCreate + triage + lineage |
| Quy mô đánh giá | 56.340 mẫu | 31 unit test + case study |

Noirlycan **không** thay thế nghiên cứu thống kê [4]; nó **operationalize** phương pháp detection cho analyst endpoint và bổ sung lớp E3/E4.

## 4.20. Giả định phương pháp (M1–M5)

Phương pháp Chương 4 dựa trên giả định Chương 3:

| ID | Giả định | Ảnh hưởng phương pháp |
|----|----------|----------------------|
| M1 | Malware gọi API qua export hookable hoặc Sysmon-visible | E4 partial |
| M2 | Injection trong cửa sổ 300s | Expiration correlator |
| M3 | User-mode injection | Không kernel primitive |
| M4 | Lab cô lập | E5 không cần fake production |
| M5 | Frida fidelity chấp nhận được | RQ5 — cần đo |

Vi phạm M1 (syscall thuần + unhook hoàn toàn) → phương pháp 2-of-3 **không khả dụng**; chỉ còn telemetry Sysmon một phần.

## 4.21. Mở rộng tương lai phương pháp

Ba hướng mở rộng **ngoài phạm vi luận văn hiện tại** nhưng bám Chương 4:

1. **ETW Threat Intelligence provider** — thay/đi cùng Frida, giảm E4/E6; vẫn map về cùng equivalence class [4].
2. **ML trên chuỗi primitive** — embedding API sequence thay rule classifier; cần dataset gán nhãn lớn hơn 31 test.
3. **Anti-evasion E5 port** — tích hợp patch timing từ Sap4Sec artifact để so sánh công bằng recall với [4] trên Paper-Subset.

Các hướng này không invalidate phương pháp hiện tại — chúng bổ sung lớp vận hành và phạm vi đối thủ.

## 4.22. Giám sát mạng hậu injection

Sau khi finding đạt score ≥ 70, phương pháp kích hoạt **network watch** trên `target_pid` trong 300 giây (đồng bộ cửa sổ correlator). Sysmon E3 (NetworkConnect) được lọc: chỉ lưu connection khởi phát từ PID victim. Mục tiêu: bắt **beacon** sau khi payload chạy trong tiến trình hợp pháp — bổ sung giá trị điều tra cho analyst, không thay thế bước phát hiện 2-of-3.

Heuristic `is_external_beacon_candidate` đánh dấu IP/hostname ngoài RFC1918. Đây là extension lab, không có trong paper [4]. Module `network.py` và test `test_network_watch.py` xác nhận chỉ connection trong cửa sổ watch mới được correlate — tránh flood log từ toàn hệ thống.

## 4.23. Tóm tắt chương

Chương 4 trình bày phương pháp tăng cường phát hiện process injection: kế thừa lõi operational primitive và quy tắc 2-of-3 của [4] để chống né tránh biến thể API (E1) và gộp bước (E2); bổ sung memory congruence và temporal ordering dưới dạng phát biểu hình thức và pseudo-code; mở rộng pipeline provenance file (E3) và telemetry kép Sysmon–Frida (E4). Scoring và classifier rule-based xếp hạng finding cho analyst. Module anti-sandbox (E5) của [4] **không nằm trong phương pháp hiện thực** — hạn chế được thảo luận ở Chương 6 và 7. Chương 5 mô tả hiện thực các module tương ứng trong artifact Noirlycan.

---

# CHƯƠNG 5. THIẾT KẾ VÀ HIỆN THỰC HỆ THỐNG NOIRLYCAN

Chương này mô tả kiến trúc và hiện thực artifact **Noirlycan Telemetry** — prototype phục vụ phòng lab Windows 10/11 cô lập, triển khai phương pháp Chương 4. Hệ thống được tổ chức theo mô hình phân lớp: thu thập (collectors), xử lý (correlator, triage, classifier), lưu trữ (JSONL, SQLite), và trình bày (dashboard Django). Mọi thiết kế bám sát paper [4] ở tầng correlator; các module provenance và dashboard là đóng góp engineering của luận văn. **Module anti-evasion (E5) của [4] không được hiện thực** — file `kernel/analysis/evasion.py` chỉ ghi nhận tín hiệu, không patch timing hay môi trường sandbox.

---

## 5.1. Kiến trúc tổng thể

Sau giai đoạn refactor, codebase Noirlycan tổ chức theo **Clean Architecture** (Uncle Bob) và có thể triển khai **monolith** (mặc định lab) hoặc **microservices** (Docker). **Lõi correlator 2-of-3 của [4] không đổi** — chỉ tách boundary module cho dễ kiểm soát, test và mở rộng. Chi tiết: `docs/clean-architecture-plan.md`.

### 5.1.1. Sơ đồ Clean Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  Presentation                                                    │
│  cli.py · services/dashboard/ (Django REST + WebSocket)          │
│  services/storage/api.py · services/analysis/api.py              │
├──────────────────────────────────────────────────────────────────┤
│  Application                                                     │
│  collector_runtime · analysis_queue · reclassify · upload_finalize│
├──────────────────────────────────────────────────────────────────┤
│  Domain (kernel/) — không phụ thuộc framework/I/O               │
│  entities/models · analysis/primitives · analysis/injection_graph│
│  classification/technique_classifier · classification/api_manifest│
├──────────────────────────────────────────────────────────────────┤
│  Infrastructure                                                  │
│  collector: sysmon · frida_manager · file_watch · triage         │
│  storage: log_store · analysis_db · atomic_io                    │
│  analysis/domain: correlation · session_analytics · batch_runner  │
└──────────────────────────────────────────────────────────────────┘
```

**Quy tắc phụ thuộc:** Presentation → Application → Domain ← Infrastructure. Layer `kernel/` không import Django, Frida hay win32evtlog.

### 5.1.2. Bốn microservice và chế độ triển khai

**Bảng 5.1.** Service boundary

| Service | Vai trò | Port | Entry point |
|---------|---------|------|-------------|
| **collector** | Sysmon + Frida + file-drop trên Windows VM | 8782 (health) | `noirlycan-telemetry run` |
| **storage** | Ghi/đọc JSONL, SQLite uploads | 8780 | `noirlycan-storage` |
| **analysis** | Correlator, reclassify, corpus | 8781 | `noirlycan-analysis` |
| **dashboard** | UI analyst | 8765 | `noirlycan-telemetry dashboard` |

| Mode | Mô tả | Khi dùng |
|------|-------|----------|
| **Monolith** | `run` + `dashboard` in-process, ghi trực tiếp `logs/` | Dev lab, demo luận văn |
| **Microservices** | `docker compose up` — storage + analysis + dashboard; collector native trên VM | Tách scale, kiểm soát từng service |

Wire format giữa service: `contracts/events.py` (`TelemetryEnvelope`) — tương thích JSONL session.

### 5.1.3. Luồng runtime monolith (`noirlycan-telemetry run`)

1. `cli.py` (composition root) khởi tạo `Correlator`, `JsonlWriter`, `SysmonPoller`, `FridaInjectionMonitor`, `FileDropWatcher`.
2. Vòng lặp: Sysmon batch → correlator; file watcher → triage → correlator; drain Frida → correlator.
3. `Finding` ghi `logs/session-*.jsonl`; dashboard tail cùng volume.

### 5.1.4. Module map (đường dẫn sau refactor)

**Bảng 5.2.** Ánh xạ module — trách nhiệm

| Thành phần | Đường dẫn trong repo | Vai trò |
|------------|----------------------|---------|
| CLI | `cli.py` | Composition root, subcommand |
| Correlator | `services/analysis/domain/correlation.py` | 2-of-3, scoring, network watch |
| Primitives | `kernel/analysis/primitives.py` | `operational_kind_count`, `analyze_execution` |
| Classifier | `kernel/classification/technique_classifier.py` | Rule → `InjectionTechnique` |
| API manifest | `kernel/classification/api_manifest.py` | `PAPER_API_CLASSES` [4] |
| Models | `kernel/entities/models.py` | `Finding`, `MemoryPrimitive`, … |
| Collector loop | `services/collector/application/collector_runtime.py` | JsonlWriter, drain |
| Frida | `services/collector/infrastructure/frida_manager.py` | Attach/spawn, bridge |
| Hooks | `frida_hooks/windows_injection_hooks.js` | Interceptor user-mode |
| Sysmon | `services/collector/infrastructure/sysmon.py` | Kernel event poll |
| File watch | `services/collector/infrastructure/file_watch.py` | Drop scanner |
| Triage | `services/collector/infrastructure/triage.py` | Static analysis |
| Log store | `services/storage/infrastructure/log_store.py` | JSONL I/O |
| Analysis DB | `services/storage/infrastructure/analysis_db.py` | SQLite cache |
| Dashboard | `services/dashboard/` | Django + Daphne + WebSocket |
| Evasion log | `kernel/analysis/evasion.py` | Ghi signal E5/E6 (không patch) |

Package: `src/noirlycan_telemetry/`, cài `pip install -e .[dev]`.

---

## 5.2. Giao diện dòng lệnh (`cli.py`)

### 5.2.1. Subcommand

`build_parser()` định nghĩa:

| Lệnh | Mục đích |
|------|----------|
| `run` | Vòng lặp collector đầy đủ (Sysmon + file watch + Frida) |
| `spawn` | Spawn mẫu dưới Frida từ entry (giảm miss E6/E4 attach trễ) |
| `triage` | Static triage một file |
| `dashboard` | Khởi Django server |
| `batch` | Chạy nhiều mẫu tuần tự, báo cáo JSON |
| `compare` | So sánh với VirusTotal (tùy chọn API key) |
| `corpus` | Thống kê aggregate trên nhiều session JSONL |
| `reclassify` | Chạy lại classifier trên log cũ |

### 5.2.2. `command_run` — orchestration

Tham số quan trọng:

- `--watch-sysmon`: bật `SysmonPoller` (cần quyền đọc Event Log).
- `--watch-path`: thêm thư mục file drop (mặc định: repo root, `D:\`, `D:\thesis`, Downloads, Desktop).
- `--attach-pid` / `--auto-attach-new-processes`: Frida attach thủ công hoặc theo Sysmon E1.
- `--minimum-score`: ngưỡng finding (mặc định 50).
- `--jsonl`: đường dẫn session log.

Luồng xử lý file mới:

1. `FileDropWatcher.drain()` → `FileEvent`.
2. Thread pool `_TRiage_EXECUTOR` gọi `triage_file` → làm giàu SHA256, PE, entropy, signature.
3. `correlator.add_file(enriched)`.
4. Nếu PE executable: `enqueue_analysis` spawn dưới Frida (hàng đợi `analysis_queue.py`).

Heartbeat collector ghi `logs/.runtime.json` để dashboard biết trạng thái online.

### 5.2.3. Tích hợp classifier config

`ensure_classifier_config()` tạo `.classifier_rules.json` — cho phép chỉnh `minimum_score`, `minimum_operational_kinds`, custom rules mà không sửa code. `Correlator.reload_rules_config()` hot-reload khi file thay đổi.

---

## 5.3. Vòng lặp collector (`services/collector/application/collector_runtime.py`)

### 5.3.1. JsonlWriter

Ghi từng dòng JSON `{"type": event_type, "value": ...}` — type gồm: `file`, `sysmon`, `primitive`, `finding`, `network`, `frida_raw`, `evasion`. Flush mỗi 32 dòng giảm I/O. Dashboard và `reclassify` đọc cùng format.

### 5.3.2. Xử lý Sysmon batch

`process_sysmon_batch()`:

- `FileEvent` → handler tùy chỉnh hoặc `correlator.add_file`.
- `ProcessEvent` → `correlator.add_process`; nếu `auto_attach` và `should_auto_attach()` → `safe_attach(monitor, pid)`.
- `NetworkConnectionEvent` → `handle_network_event` (chỉ lưu nếu PID trong network watch).
- `TelemetryEvent` generic (E8/E10 raw) → ghi JSONL cho phân tích sau.

`should_auto_attach`: bỏ qua binary system32 không có parent lạ; chấp nhận `.exe/.dll/.scr/.com` từ nguồn đáng ngờ.

### 5.3.3. Drain Frida

`drain_frida()` xử lý queue không blocking:

1. `evasion` signal → in cảnh báo, **không** correlate (E5/E6 awareness only).
2. `frida_process` → `add_process`, auto-attach con.
3. `memory_primitive` → `add_primitive` → findings.

`print_finding()` in severity, technique, execution_confirmed, recursive chain, network watch — phục vụ lab không cần dashboard.

---

## 5.4. Lớp Frida (`services/collector/infrastructure/frida_manager.py` + hooks)

### 5.4.1. FridaInjectionMonitor

- `load_default_hook_script()`: đọc `windows_injection_hooks.js` qua `importlib.resources`.
- `attach(pid)`: `frida.attach` → `create_script` → `script.load`; một session/script mỗi PID.
- `_on_message`: parse JSON payload, đẩy `FridaRuntimeEvent` vào `queue.Queue`.

Chuyển đổi:

- `runtime_event_to_primitive()`: map `allocate|write|execute|context_read` → `MemoryPrimitive`.
- `runtime_event_to_process()`: spawn notification từ hook.
- Observation-only (`remote_read`, TXF hint) → `api_observation`, không vào 2-of-3.

### 5.4.2. Thiết kế hook JavaScript

File `windows_injection_hooks.js` (~1900 dòng) cấu trúc:

1. **Helper:** `ptrToNumber`, `ntSuccess`, `readAnsiString`, `protectionToString`.
2. **Dynamic resolve:** hook `GetProcAddress` / `LdrGetProcedureAddress` — khi target ∈ `DYNAMIC_INJECTION_APIS`, attach lazy hook.
3. **Per-API handler:** đọc args/retval, trích `baseAddress`, `NumberOfBytes`, `lpStartAddress`, `CONTEXT.Rip`.
4. **Emit:** `send({type: "memory_primitive", kind, api, actor_pid, target_pid, address, size, details})`.

**Fix D1:** `readInstructionPointerFromContext` cho `SetThreadContext` / `NtSetContextThread` — đặt `address = Rip` trên primitive EXECUTE.

**Alias Zw*:** manifest và hook dùng tên canonical; stub Zw chuyển tiếp tới Nt.

Coverage test: `test_hook_manifest_coverage.py`, `test_api_coverage.py` đối chiếu manifest ↔ hook.

### 5.4.3. Hạn chế hiện thực

Frida chạy **user-mode** trong target — malware E4/E6 có thể né. Luận văn bổ sung Sysmon (mục 5.6) và khuyến nghị `spawn` mode; **không** có anti-Frida countermeasure.

---

## 5.5. Correlation engine (`services/analysis/domain/correlation.py`)

### 5.5.1. Cấu trúc trạng thái

Lớp `Correlator` duy trì:

| Trường | Kiểu | Mục đích |
|--------|------|----------|
| `files_by_path` | `dict[str, FileEvent]` | Provenance E3 |
| `processes_by_pid` | `dict[int, ProcessEvent]` | Lineage, CREATE_SUSPENDED |
| `primitives` | `deque[MemoryPrimitive]` | Expiration FIFO |
| `_chain_buckets` | `dict[(actor, target), list]` | Nhóm primitive theo chuỗi |
| `_reported_chain_scores` | `dict` | Chỉ báo cáo khi score tăng |
| `_network_watch_until` | `dict[pid, datetime]` | Hậu injection 300s |
| `_injection_graph` | `InjectionGraph` | Recursive chain |

Cửa sổ mặc định **300 giây** — đồ bộ với paper batch window và network watch.

### 5.5.2. State machine đánh giá chuỗi

```
                    add_primitive
                         │
                         ▼
              ┌─────────────────────┐
              │  enrich + bucket    │
              └──────────┬──────────┘
                         │
                         ▼
              ┌─────────────────────┐
     no ──────│ |K| ≥ 2 operational?│──────► (idle)
              └──────────┬──────────┘
                         │ yes
                         ▼
              ┌─────────────────────┐
     no ──────│  temporal OK?       │──────► discard
              └──────────┬──────────┘
                         │ yes
                         ▼
              ┌─────────────────────┐
     no ──────│  congruence OK?     │──────► discard
              └──────────┬──────────┘
                         │ yes
                         ▼
              ┌─────────────────────┐
     no ──────│  score ≥ min?       │──────► discard
              └──────────┬──────────┘
                         │ yes
                         ▼
              ┌─────────────────────┐
     no ──────│  score > previous?  │──────► discard (duplicate)
              └──────────┬──────────┘
                         │ yes
                         ▼
              apply_classification
              injection_graph.add_finding
              emit Finding
              [score≥70 → network_watch]
```

### 5.5.3. Execution analysis

Module `kernel/analysis/primitives.py` (`analyze_execution`) tách **execution transfer** (`ResumeThread`, `CreateRemoteThread`, …) khỏi **context read** (`GetThreadContext`). Finding có W+A nhưng không có transfer API → title *"Probable injection staging chain"*, `execution_confirmed = false`, score cap 75 nếu `missing_execution_transfer`.

### 5.5.4. Injection graph

`kernel/analysis/injection_graph.py` — `InjectionGraph.add_finding()` nối finding theo quan hệ actor(target trước) → target mới, set `is_recursive`, `chain_depth`. Chưa có metric prevalence 2% như [4] — chỉ hiển thị dashboard.

---

## 5.6. Sysmon, file watch, triage

### 5.6.1. `services/collector/infrastructure/sysmon.py`

- Channel: `Microsoft-Windows-Sysmon/Operational`.
- `SysmonPoller.poll_once()`: đọc event mới qua `win32evtlog` (Windows only).
- Parser XML → model: E1 ProcessCreate, E3 NetworkConnect, E11 FileCreate, E15 FileCreateStreamHash, E8/E10 → TelemetryEvent.

Config lab: `configs/sysmon-noirlycan.xml` — bật ImageLoad, ProcessAccess, CreateRemoteThread, FileCreate, NetworkConnect với filter phù hợp lab.

Graceful degradation: nếu Sysmon unavailable, CLI in hint cài đặt/quyền và tiếp tục Frida-only.

### 5.6.2. `services/collector/infrastructure/file_watch.py`

`FileDropWatcher` poll không đệ quy (recursive reserved):

- Bootstrap: snapshot mtime toàn file interesting trong watch paths.
- `drain()`: file mới hoặc modified → `FileEvent(creator_image="file-scanner")`.
- `is_interesting_path`: suffix `.exe`, `.dll`, `.ps1`, `.js`, …

Bổ sung Sysmon E11 khi process tạo file; watcher bắt drop ngoài event (copy thủ công, mount nhanh).

### 5.6.3. `services/collector/infrastructure/triage.py`

`FileTriage` dataclass + `triage_file()`:

- SHA256 streaming 1 MB chunks;
- Entropy Shannon;
- PE detection, optional `pefile` imports;
- Authenticode qua subprocess;
- Rule scoring: unsigned + temp path + high entropy → `suspicious_reasons`.

Kết quả merge vào `FileEvent` trước `add_file` — feeding scoring provenance (+10/+5/+10/+5).

---

## 5.7. Technique classifier (`kernel/classification/technique_classifier.py`)

### 5.7.1. Enum và pipeline

`InjectionTechnique` — 21+ giá trị từ `section_mapping_injection` tới `poolparty`, `mockingjay`, `process_ghosting`, …

`classify_finding()`:

1. Load `ClassifierRulesConfig` (gates, confidence override).
2. `evaluate_custom_rules` (phase `before_builtin`).
3. Chuỗi if-rule theo specificity giảm dần (instrumentation callback, ghosting, doppelgänging, …).
4. `_confidence_from_kinds`: HIGH nếu 3 primitive + execution confirmed.

`apply_classification()` gắn `finding.technique`, `technique_confidence`, `technique_rationale`.

### 5.7.2. Custom rules

Dashboard và `.classifier_rules.json` cho phép analyst thêm rule JSON — `kernel/classification/custom_rule_engine.py` parse điều kiện API/kind/evidence. Phục vụ lab mà không rebuild code.

---

## 5.8. Dashboard analyst (`services/dashboard/`)

### 5.8.1. Kiến trúc Django

- `server.py` / `run_dashboard`: khởi ASGI (HTTP + WebSocket).
- `views.py`: REST-like endpoints — sessions list, session detail, uploads, classifier config, collector start/stop.
- `consumers.py` + `live_hub.py`: WebSocket broadcast finding mới (`ws_broadcast`).
- `jet_dashboard.py`: tích hợp Django Jet (nếu bật) cho admin-style UI.

Static assets: `dashboard.js`, `dashboard.css`, `i18n.js` (Vi/En).

### 5.8.2. Tính năng chính

| Tab / chức năng | Mô tả |
|-----------------|-------|
| Overview | Số finding, severity, session metadata |
| Findings | Bảng finding, filter score/technique, drill-down primitive |
| Network | Kết nối Sysmon E3 trong network watch window |
| Primitives | Timeline API theo PID |
| Sessions | Chọn JSONL, export, reclassify |
| Uploads | Upload sample → queue → spawn Frida → báo cáo |
| Classifier rules | Sửa JSON rules live |
| Collector control | Start/stop `run` subprocess, heartbeat |

`AnalysisDatabase` (SQLite) lưu upload metadata, trạng thái queue, liên kết session report.

### 5.8.3. Live sync

Khi collector ghi finding mới, `live_sync` tail JSONL hoặc nhận signal → `broadcast_refresh` tới WebSocket clients — analyst không cần reload trang.

---

## 5.9. Mô hình dữ liệu (`kernel/entities/models.py`)

Các dataclass immutable (frozen):

- `MemoryPrimitive`: kind, actor/target PID+image, address, size, api, details dict.
- `FileEvent`, `ProcessEvent`, `NetworkConnectionEvent`.
- `Finding`: primitives tuple, score, evidence, technique fields, `related_file`, injection chain.

Enum `PrimitiveKind`: ALLOCATE, WRITE, EXECUTE, CONTEXT_READ.

JSON serialization qua `collector_runtime.jsonable()` — datetime ISO8601.

---

## 5.10. Tái lập thí nghiệm (reproducibility)

### 5.10.1. Artifact công bố

Theo Phụ lục C:

1. Clone repo NoirlycanThesis.
2. VM Windows 10/11, Python 3.11+, `uv sync` hoặc `pip install -e .`.
3. Cài Sysmon với `configs/sysmon-noirlycan.xml`.
4. Cài Frida (`pip install frida frida-tools`).
5. Chạy `noirlycan-telemetry run --watch-sysmon --auto-attach-new-processes`.
6. Dashboard: `noirlycan-telemetry dashboard`.

### 5.10.2. Microservices (Docker Compose)

`docker-compose.yml` khởi động `storage-api` (:8780), `analysis-api` (:8781), `dashboard-api` (:8765) với volume chung `./logs`. Collector (Frida/Sysmon) **vẫn chạy native trên Windows VM** — không container hóa vì phụ thuộc kernel hook và Frida attach.

```bash
docker compose up --build
# Dashboard: http://127.0.0.1:8765
```

Biến môi trường: `NOIRLYCAN_STORAGE_URL`, `NOIRLYCAN_ANALYSIS_URL` cho dashboard proxy tới storage/analysis khi tách service.

### 5.10.3. Test tự động

```bash
uv run pytest tests/test_correlation.py tests/test_ired_team_classifier.py
```

31 test xác nhận methodology + classifier (Chương 6). Toàn bộ suite `tests/` gồm thêm dashboard, sysmon parser, log_store (~80 test).

### 5.10.4. Deviation đã biết (audit)

| ID | Mô tả | Trạng thái repo |
|----|-------|-----------------|
| D1 | Execute address | Đã fix SetThreadContext Rip; ResumeThread vẫn thiếu |
| D2 | Read ∈ write | Đã tách `remote_read` |
| D3 | Temporal | Đã fix write-after-execute |
| D4 | Anti-evasion E5 | **Chưa** — `kernel/analysis/evasion.py` log only |
| D5 | Ghosting enum | Đã thêm, phụ thuộc hook precursor |

---

## 5.11. Hàng đợi phân tích và batch

Module: `services/collector/application/analysis_queue.py`, `services/analysis/domain/batch_runner.py`.

### 5.11.1. Analysis queue

Khi file drop được triage là PE executable, `enqueue_analysis(logs_dir, path)` thêm vào `analysis_queue.json` (atomic write qua `atomic_io.py`). Collector `drain_analysis_queue()`:

1. Pop pending entry.
2. `FridaInjectionMonitor` spawn process (`frida.spawn` + `resume`) thay vì attach muộn.
3. Ghi session riêng hoặc merge JSONL tùy cấu hình.

Cơ chế này giảm **miss primitive đầu** (E6) so với chỉ `--auto-attach` sau Sysmon E1.

### 5.11.2. Batch runner

`noirlycan-telemetry batch --manifest samples.jsonl`:

- Đọc danh sách đường dẫn mẫu + metadata expected technique.
- Với mỗi mẫu: spawn dưới Frida, timeout, thu JSONL.
- `write_batch_report()` tổng hợp finding count, max score, technique — phục vụ PoC-Bench tương lai.

## 5.12. Chi tiết hook Frida theo nhóm API

**Bảng 5.2.** Hook handler — trích `windows_injection_hooks.js`

| Nhóm API | Handler chính | Trường extract |
|----------|---------------|----------------|
| VirtualAlloc(Ex) | onEnter/onLeave | baseAddress, regionSize, flProtect |
| NtAllocateVirtualMemory | onLeave NT success | *BaseAddress, RegionSize |
| WriteProcessMemory | onEnter | lpBaseAddress, nSize |
| NtMapViewOfSection | onEnter | BaseAddress, ViewSize, InheritDisposition |
| CreateRemoteThread(Ex) | onEnter | lpStartAddress, lpParameter |
| NtCreateThreadEx | onEnter | StartRoutine, Argument |
| SetThreadContext | onEnter | lpContext → Rip | 
| GetThreadContext | onEnter | lpContext pointer → details |
| QueueUserAPC / NtQueueApcThread* | onEnter | ApcRoutine, ApcArgument |
| ResumeThread / NtResumeThread | onEnter | hThread → target PID resolve |
| LoadLibrary* / LdrLoadDll | onEnter | lpLibFileName |
| OpenProcess / NtOpenProcess | observation | access mask flags |
| NtCreateSection | onLeave | SectionHandle |
| Dynamic GetProcAddress | onLeave | attach lazy hook |

Mỗi handler gọi `emitObservation` cho API phụ trợ (OpenProcess) hoặc `emitPrimitive` cho operational kind. `hookedAddresses` Set tránh double-hook cùng địa chỉ export.

### 5.12.1. Resolve PID victim

Cross-process injection cần `target_pid` chính xác:

- Tham số `hProcess` / `ProcessHandle` → `GetProcessId`.
- Fallback: thread handle → `GetProcessIdOfThread`.
- Self: `Process.id` Frida khi handle pseudo current process.

Sai PID làm lệch bucket correlator — test `test_resolves_target_image_from_child_process` kiểm tra enrich từ ProcessEvent khi hook thiếu image.

## 5.13. Sysmon — ánh xạ Event ID

**Bảng 5.3.** Event ID dùng trong Noirlycan

| EID | Tên | Model output | Vai trò E3/E4 |
|-----|-----|--------------|---------------|
| 1 | ProcessCreate | ProcessEvent | Lineage, CREATE_SUSPENDED flags |
| 3 | NetworkConnect | NetworkConnectionEvent | Network watch post-finding |
| 7 | ImageLoad | TelemetryEvent | Module stomping context (raw) |
| 8 | CreateRemoteThread | TelemetryEvent | E4 fallback — thread create kernel |
| 10 | ProcessAccess | TelemetryEvent | E4 — OpenProcess cross-process |
| 11 | FileCreate | FileEvent | Provenance E3 |
| 15 | FileCreateStreamHash | FileEvent | Alternate data stream drop |

Parser `parse_sysmon_xml` tách namespace XML Sysmon chuẩn Microsoft. Unit test `test_sysmon_files.py` dùng fixture XML — không cần Windows khi CI.

## 5.14. Dashboard — endpoint và luồng upload

### 5.14.1. API chính (`views.py`)

| Route | Method | Chức năng |
|-------|--------|-----------|
| `/` | GET | SPA index.html |
| `/api/sessions` | GET | Liệt kê JSONL sessions |
| `/api/sessions/<id>` | GET | Chi tiết finding + primitive |
| `/api/uploads` | GET/POST | Quản lý upload sample |
| `/api/collector/start` | POST | Spawn `noirlycan-telemetry run` |
| `/api/collector/status` | GET | Heartbeat `.runtime.json` |
| `/api/classifier/rules` | GET/PUT | CRUD `.classifier_rules.json` |
| `/api/corpus` | GET | `analyze_corpus()` aggregate |
| `/ws/live` | WebSocket | Push refresh |

### 5.14.2. Luồng upload mẫu

```
Analyst upload EXE → SHA256 dedupe (AnalysisDatabase)
  → stored_path → enqueue_analysis
  → collector spawn Frida
  → JSONL findings
  → build_upload_report → dashboard "done — view report"
```

Upload không thực thi payload trên host analyst — chỉ trên VM lab có collector.

## 5.15. Lưu trữ và tái phân loại

- `log_store.py`: `new_session_log_path()`, `aggregate_logs()`, `session_detail()`.
- `reclassify.py`: đọc JSONL cũ, chạy lại `apply_classification` + scoring rules mới — hữu ích khi cập nhật classifier không cần re-run mẫu.
- `analysis_db.py`: SQLite `uploads`, `sessions` — dashboard query nhanh.

## 5.16. Cấu hình và phụ thuộc

| Thành phần | Phụ thuộc | Ghi chú |
|------------|-----------|---------|
| Core | Python 3.11+, stdlib | |
| Frida | `frida`, `frida-tools` | Windows lab |
| Sysmon | pywin32, Sysmon driver | Optional graceful degrade |
| Triage PE | `pefile` optional | Import API scan |
| Dashboard | Django 4+, channels | ASGI WebSocket |
| Test | pytest | 31+ methodology tests |

File `pyproject.toml` khai báo entry point `noirlycan-telemetry = noirlycan_telemetry.cli:main`.

## 5.17. Sequence: một vòng poll collector

```
CLI run loop:
  1. file_watcher.drain() → triage async → correlator.add_file
  2. process_sysmon_batch() → add_process / add_file / network
  3. drain_frida() → add_primitive → findings → jsonl
  4. drain_analysis_queue() → spawn pending samples
  5. touch_collector_heartbeat()
  6. sleep(poll_interval)
```

Đồng bộ single-threaded cho correlator; triage dùng `ThreadPoolExecutor` tránh block poll Sysmon.

## 5.19. Module phụ trợ

| Module | Vai trò |
|--------|---------|
| `process_resolve.py` | Windows API PID → image path khi Sysmon/Frida thiếu |
| `injection_graph.py` | Đồ thị finding nối actor→target, recursive chain |
| `payload_classifier.py` | Shellcode vs PE trong buffer (entropy, MZ header) |
| `kernel/analysis/evasion.py` | **Chỉ log** signal E5/E6 — không bypass |
| `sandbox_compare.py` | So sánh VT (optional) — ngoài core |
| `session_analytics.py` | Corpus stats trên nhiều JSONL |
| `classifier_config.py` | Load/save `.classifier_rules.json` |
| `custom_rule_engine.py` | DSL rule tùy chỉnh dashboard |
| `collector_launcher.py` | PID file, start/stop subprocess từ dashboard |

Các module này không thay đổi quy tắc 2-of-3; chúng enrich finding và vận hành lab.

## 5.20. Bảo mật và đạo đức triển khai

- Mẫu phân tích **chỉ** trong VM cô lập — không phát tán payload thật.
- Dashboard upload lưu local SQLite — không cloud mặc định.
- PoC loader (Phụ lục D) chỉ MessageBox — không weaponized exploit.
- JSONL có thể chứa path nhạy cảm — analyst tự bảo vệ log.

## 5.21. Tóm tắt chương

Chương 5 trình bày hiện thực Noirlycan: kiến trúc phân lớp từ hook Frida và Sysmon kernel tới correlator 2-of-3, scoring, classifier; CLI và collector runtime điều phối pipeline real-time; file watch và triage mở rộng provenance chống E3; dashboard Django hỗ trợ điều tra. Hệ thống **không** tích hợp anti-sandbox [4] (E5). Chương 6 đánh giá hiệu quả trên bộ test và case study section-mapping.

---

# CHƯƠNG 6. ĐÁNH GIÁ THỰC NGHIỆM

Chương này đánh giá mức độ đạt mục tiêu *tăng cường phát hiện mã độc dưới các hình thức né tránh* thông qua artifact Noirlycan, căn cứ phương pháp [4]. Phạm vi đánh giá **cố ý loại trừ E5** (né sandbox/VM): module anti-evasion của [4] — được tác giả chứng minh tăng recall ~21,2 % trên subset injection — **không được hiện thực** trong luận văn. Do đó, luận văn **không** so sánh recall với paper trên cùng dataset 56.340 mẫu và **không** claim số liệu prevalence 16,5 % hay 21,2 % của [4]. Thay vào đó, đánh giá tập trung: (1) kiểm chứng quy tắc 2-of-3 và biến thể E1/E2 qua test tổng hợp; (2) case study section-mapping — biến thể dominant trong [4]; (3) đánh giá định tính provenance E3; (4) phân tích thiết kế telemetry kép E4; (5) protocol Frida fidelity (E6 liên quan).

---

## 6.1. Câu hỏi nghiên cứu đánh giá (RQ1–RQ5)

**Bảng 6.1.** Câu hỏi đánh giá và ánh xạ nhóm né tránh

| ID | Câu hỏi | Nhóm né tránh | Tiêu chí thành công |
|----|---------|---------------|---------------------|
| **RQ1** | Hiện thực [4] có phát hiện biến thể API (E1) và gộp bước (E2) không? | E1, E2 | Test correlation pass; section-mapping score ≥ 70 |
| **RQ2** | Telemetry kép Sysmon+Frida có bổ sung khi Frida miss (E4)? | E4 | Thiết kế + config E8/E10; case thiếu số liệu syscall thuần |
| **RQ3** | Pipeline provenance có gắn file-drop với injection (E3)? | E3 | Finding chứa `related_file`, metadata triage |
| **RQ4** | Classifier có nhận diện kỹ thuật né tránh hiện đại? | E1, E2 | 20 test classifier pass; đúng technique label |
| **RQ5** | Frida có đủ trung thực (fidelity) cho kết luận khoa học? | E6 | Protocol `frida-fidelity.md`; drop-rate trên VM |

**RQ không áp dụng cho E5:** né sandbox/VM cần module anti-evasion [4] §6 — **out-of-scope**. Số liệu ablation của [4] được trích dẫn là **upper bound** lý thuyết, không phải kết quả luận văn.

---

## 6.2. Môi trường và phương pháp đo

### 6.2.1. Môi trường thí nghiệm

| Thành phần | Cấu hình |
|------------|----------|
| OS | Windows 10/11 x64, VM cô lập |
| Sysmon | v15.x, config `configs/sysmon-noirlycan.xml` |
| Frida | Python package `frida` + `windows_injection_hooks.js` |
| Collector | `noirlycan-telemetry` 0.x, Python 3.11 |
| Test runner | `uv run pytest` hoặc `python -m pytest` |

Ground truth trên unit test: **do tác giả luận văn gắn nhãn** — primitive và kỹ thuật kỳ vọng được mô tả trực tiếp trong assertion. Đây là mối đe dọa *internal validity* (mục 6.6).

### 6.2.2. Loại đánh giá

1. **Unit test tổng hợp** — mô phỏng chuỗi API/primitive không cần chạy malware thật.
2. **Case study có cấu trúc** — section-mapping tương đương *neurevt* [4].
3. **Case study mở rộng** — `test_aes_loader_chain_upgrades_to_critical` mô phỏng loader lab thực.
4. **Baseline signature** — rule cố định A→W→E API names so với correlator 2-of-3.
5. **Đánh giá định tính** — provenance, dashboard (RQ3).
6. **Protocol fidelity** — benchmark Frida (RQ5), kết quả điền trên VM.

Dataset PoC-Bench (5 loader) và Paper-Subset (100 mẫu Sap4Sec) nêu trong outline — **chưa hoàn thiện** cho luận văn bản này; kết quả định lượng chính dựa trên 31 test methodology.

---

## 6.3. Bộ test methodology (31 test)

### 6.3.1. Cấu trúc bộ test

Hai file cốt lõi:

```bash
uv run pytest tests/test_correlation.py tests/test_ired_team_classifier.py -v
```

Kết quả: **31 passed, 0 failed**.

**Bảng 6.2.** Phân bổ test

| File | Số test | Phạm vi |
|------|---------|---------|
| `test_correlation.py` | 11 | 2-of-3, congruence, temporal, scoring, provenance |
| `test_ired_team_classifier.py` | 20 | Phân loại kỹ thuật biến thể |
| **Tổng** | **31** | RQ1, RQ4 |

### 6.3.2. Chi tiết `test_correlation.py` (11 test)

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

### 6.3.3. Chi tiết `test_ired_team_classifier.py` (20 test — trích)

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

Toàn bộ 20 test **pass** — RQ4 đạt trên tập rule synthetic.

---

## 6.4. Case study: Section-mapping (E2) — biến thể *neurevt*

### 6.4.1. Bối cảnh [4]

Paper [4] §3.5 và case study *neurevt* mô tả biến thể Process Hollowing dominant: thay `VirtualAllocEx` + `WriteProcessMemory` bằng `NtCreateSection` + `NtMapViewOfSection` (remote map executable). Execute qua `SetThreadContext` + `ResumeThread`. Đây là ví dụ điển hình **E2 — gộp bước allocate/write**.

### 6.4.2. Thiết lập test

Test `test_detects_section_mapping_write_execute_chain` mô phỏng:

1. **File drop:** `loader.exe` trong Temp, unsigned, entropy 7,2.
2. **Process:** PID 1337, `CREATE_SUSPENDED`, parent explorer.
3. **Primitive W:** `NtMapViewOfSection` → `msedge.exe` PID 4242, address 0x200000, protection EXECUTE_READWRITE.
4. **Primitive E:** `ResumeThread`, address None.

### 6.4.3. Kết quả

**Bảng 6.3.** Kết quả case study section-mapping

| Chỉ số | Giá trị |
|--------|---------|
| Số finding | 1 |
| Score | ≥ 70 (HIGH) |
| `related_file` | `...\loader.exe` |
| `evidence.section_mapping` | true |
| Primitive kinds | write, execute |
| Baseline signature A→W→E | **FAIL** (thiếu VirtualAllocEx, WriteProcessMemory) |
| Correlator 2-of-3 | **PASS** |

Kết luận: phương pháp [4] hiện thực trong Noirlycan **phát hiện được** biến thể dominant mà rule signature cố định bỏ sót — trực tiếp phục vụ RQ1 và mục tiêu chống E2.

### 6.4.4. Case study mở rộng — AES loader lab

`test_aes_loader_chain_upgrades_to_critical` mô phỏng chuỗi thực tế từ loader `aes_decrypt_loader.exe` → Edge:

- Nhiều `NtWriteVirtualMemory`, `NtMapViewOfSection`, `GetThreadContext`, `SetThreadContext`.
- Score tăng dần: staging < 70 → sau execute **≥ 85 (CRITICAL)**.
- Technique: `process_hollowing_section`, `execution_confirmed: true`.

Chứng minh correlator **upgrade** finding khi primitive mới làm tăng score — phù hợp vận hành real-time.

---

## 6.5. Đánh giá theo từng RQ

### 6.5.1. RQ1 — E1/E2 (methodology [4])

**Kết luận: ĐẠT.**

Bằng chứng:

- 11/11 test correlation pass.
- Quy tắc 2-of-3, congruence, temporal khớp audit `docs/audit-and-threat-model.md` (✅ cho các mục 2.1–2.6 sau fix D1–D3).
- Section-mapping score ≥ 70.

Hạn chế: test synthetic; chưa chạy 100 mẫu Sap4Sec trên VM (kế hoạch PoC-Bench).

### 6.5.2. RQ2 — E4 (telemetry kép)

**Kết luận: MỘT PHẦN — thiết kế đạt, số liệu syscall thuần chưa đủ.**

**Bảng 6.4.** Đánh giá E4

| Tiêu chí | Trạng thái | Ghi chú |
|----------|------------|---------|
| Sysmon E8 CreateRemoteThread trong config | ✅ | Kernel callback |
| Sysmon E10 ProcessAccess | ✅ | OpenProcess cross-process |
| Parser ghi TelemetryEvent raw | ✅ | JSONL |
| Thí nghiệm A/B: có/không Frida + sample syscall | ❌ Chưa | Cần driver `frida-fidelity` + sample unhooked |
| Congruence khi chỉ Sysmon | ❌ Không | Thiếu address — đúng thiết kế |

Luận văn claim **phòng thủ sâu** (defense-in-depth), không claim thay thế Frida bằng Sysmon cho 2-of-3.

### 6.5.3. RQ3 — E3 (provenance)

**Kết luận: MỘT PHẦN — đạt trên test và thiết kế pipeline.**

Bằng chứng:

- `test_detects_section_mapping_write_execute_chain`: `related_file` khớp loader.
- `test_resolves_target_image_from_child_process`: lineage process.
- Pipeline: FileDropWatcher / Sysmon E11 → triage → `add_process(created_from_file)` → scoring +10.

Chưa có metric định lượng *thời gian FileCreate → Finding* trên N mẫu thật — đề xuất cho bản mở rộng.

### 6.5.4. RQ4 — Classifier

**Kết luận: ĐẠT trên tập 20 test.**

- Bao phủ kỹ thuật [4]: hollowing, APC, DLL, reflective, doppelgänging.
- Mở rộng: PoolParty, Ghosting precursor, instrumentation callback.
- **Chưa** có precision/recall trên ground-truth dataset 12 kỹ thuật paper — classifier đánh giá bằng test rule-level.

### 6.5.5. RQ5 — Frida fidelity

**Kết luận: CHƯA HOÀN TẤT — protocol sẵn, bảng kết quả VM cần điền.**

Protocol `docs/experiments/frida-fidelity.md` định nghĩa:

- Driver spawn mẫu benign + injection PoC;
- Đo số primitive Frida vs ground-truth hook count;
- Drop-rate = missed / expected.

Giả định M5 (audit): overhead Frida chấp nhận được cho lab; **chưa** publish bảng số trong luận văn bản này.

---

## 6.6. So sánh với baseline signature

### 6.6.1. Baseline định nghĩa

**Baseline Σ:** detector rule-based yêu cầu quan sát **lần lượt** ba API:

$$\texttt{VirtualAllocEx} \rightarrow \texttt{WriteProcessMemory} \rightarrow \texttt{CreateRemoteThread}$$

trên cùng `(actor, target)` trong cửa sổ thời gian (không có equivalence class, không 2-of-3).

### 6.6.2. Kết quả so sánh

**Bảng 6.5.** Baseline signature vs Noirlycan correlator

| Kịch bản | Baseline Σ | Noirlycan 2-of-3 | Ghi chú |
|----------|------------|------------------|---------|
| Classic DLL (test) | PASS | PASS | Tương đương |
| Section-mapping W+E | **FAIL** | **PASS** | E2 né signature |
| APC `NtQueueApcThreadEx` | **FAIL** | PASS (classifier) | E1 API variant |
| NtMapViewOfSection + Resume | **FAIL** | **PASS** | Dominant [4] |
| Chỉ WriteProcessMemory | FAIL | FAIL | Cả hai đúng (FP tránh) |
| WRITE + EXECUTE unrelated mem | FAIL | FAIL | Congruence |

Noirlycan **strictly dominates** baseline trên các biến thể E1/E2 trong bảng — cốt lõi lập luận *tăng cường phát hiện dưới né tránh*.

---

## 6.7. So sánh với paper [4]

**Bảng 6.6.** Đối chiếu phạm vi [4] vs luận văn

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

**Trung thực khoa học:** Recall trên malware thật trong lab **có thể thấp hơn** [4] vì thiếu E5 — malware phát hiện VM có thể **không inject**, và Noirlycan sẽ không có finding. Đây không phải lỗi implementation 2-of-3 mà là **gap phạm vi** đã khai báo Chương 3.

---

## 6.8. Tổng hợp kết quả theo nhóm né tránh

**Bảng 6.7.** Tổng hợp đánh giá E1–E6

| Nhóm | Tiêu chí đo | Kết quả | Trạng thái |
|------|-------------|---------|------------|
| **E1** | Equivalence + hook coverage | 31 test pass; manifest ↔ hooks | **Đạt** |
| **E2** | 2-of-3 section-mapping | score ≥ 70; baseline FAIL | **Đạt** |
| **E3** | Provenance linkage | Test + pipeline; chưa metric N mẫu | **Một phần** |
| **E4** | Sysmon fallback | Config + thiết kế; thiếu benchmark syscall | **Một phần** |
| **E5** | Anti-sandbox | Không module | **Ngoài phạm vi** |
| **E6** | Anti-Frida | `spawn` + evasion log; fidelity pending | **Hạn chế** |

**Bảng 6.8.** Tóm tắt RQ

| RQ | Kết luận |
|----|----------|
| RQ1 | ✅ Đạt |
| RQ2 | ⚠️ Một phần |
| RQ3 | ⚠️ Một phần |
| RQ4 | ✅ Đạt (synthetic) |
| RQ5 | ⏳ Protocol có, số liệu pending |

---

## 6.9. Mối đe dọa với validity

### 6.9.1. Internal validity

- Ground truth test do tác giả viết — rủi ro bias nhưng phù hợp kiểm chứng specification [4].
- Một số edge case (ResumeThread không address) vẫn làm congruence suy yếu (D1 partial).

### 6.9.2. External validity

- Chỉ Windows 10/11 user-mode; không Windows Server, không kernel injection.
- Không E5 → không generalize recall malware anti-VM như [4].
- Lab cô lập — không đại diện enterprise EDR.

### 6.9.3. Construct validity

- Frida thay đổi timing — có thể ảnh hưởng race APC; fidelity benchmark (RQ5) nhằm đo mức này.
- Score 0–100 là heuristic lab, **không** calibrated trên FP/FN thực tế lớn.

### 6.9.4. Conclusion validity

Luận văn **không** claim:

- Thay thế sandbox/EDR thương mại;
- Số liệu thống kê [4];
- Phát hiện đầy đủ dưới E5/E6/kernel.

Luận văn **có thể** claim (với evidence Chương 6):

- Hiện thực có kiểm chứng 2-of-3 + equivalence [4] trên Windows lab;
- Tăng cường so với baseline signature trên E1/E2;
- Extension provenance và telemetry kép cho E3/E4 ở mức thiết kế + test.

---

## 6.10. Hạn chế và hướng bổ sung

1. **E5:** Tích hợp subset anti-evasion [4] (timing patch, env check) — ưu tiên hướng phát triển Kết luận.
2. **PoC-Bench:** Năm loader (section-map, shellcode, APC, reflective, hollowing) chạy trên VM với JSONL ground truth.
3. **Paper-Subset:** 100 mẫu Sap4Sec — đo agreement với log paper.
4. **E4 benchmark:** Sample direct-syscall so session Frida on/off.
5. **RQ5:** Hoàn thiện bảng drop-rate Frida trên VM Windows.

---

## 6.11. Phân tích chi tiết kết quả scoring

**Bảng 6.9.** Phân rã điểm case study section-mapping (ước lượng từ `_score`)

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

Test assertion `findings[0].score >= 70` — không yêu cầu CRITICAL (85) vì thiếu full context hijack như `test_aes_loader_chain_upgrades_to_critical`.

## 6.12. Classifier — ma trận kỹ thuật đã kiểm (20 test)

**Bảng 6.10.** Kết quả phân loại rule-based (tất cả PASS)

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

Không có test riêng cho **E5** — classifier không chạy nếu sample không inject.

## 6.13. Đánh giá E5 — thừa nhận hạn chế (bắt buộc)

Paper [4] §6 mô tả module anti-evasion tích hợp trong sandbox QEMU:

- Patch timing (`Sleep`, `GetTickCount`) để né delay-based detection.
- Che giấu artifact VM (registry, MAC, process list).
- Ablation: **+21,2 %** mẫu injection được phát hiện nhờ anti-evasion so với sandbox thuần.

Noirlycan **`kernel/analysis/evasion.py`** chỉ phát hiện và log signal (vd. `IsDebuggerPresent`, `NtQueryInformationProcess`) — **không** patch, **không** fake environment. Do đó:

1. Malware E5 trong lab VM có thể **thoát sớm** → zero primitive → zero finding.
2. Luận văn **không thể** replicate số liệu 16,5 % prevalence hay 21,2 % sandbox gap.
3. RQ đánh giá **cố ý bỏ qua E5** — không phải oversight mà ranh giới đề tài (Chương 3 §3.6).

Hướng phát triển: port subset anti-evasion Sap4Sec hoặc ETW-only mode — nêu ở Kết luận.

## 6.14. Đánh giá định tính dashboard và JSONL

Trên session lab thực (không nằm trong CI Linux):

- JSONL chứa đủ chuỗi `file` → `sysmon` (E1) → `primitive` → `finding`.
- Dashboard tab Findings hiển thị `related_file.path`, SHA256, technique badge.
- Export JSONL phục vụ lưu trữ evidence — reproducibility Phụ lục C.

Đây bổ sung RQ3 ở mức **qualitative acceptance** cho luận văn thạc sĩ.

## 6.15. Công thức metric (định nghĩa cho mở rộng tương lai)

Khi PoC-Bench hoàn thiện, sẽ áp dụng:

$$\mathrm{Precision} = \frac{TP}{TP + FP}, \quad \mathrm{Recall} = \frac{TP}{TP + FN}$$

$$\mathrm{F1} = \frac{2 \cdot \mathrm{Precision} \cdot \mathrm{Recall}}{\mathrm{Precision} + \mathrm{Recall}}$$

- **TP:** finding score ≥ threshold, ground truth injection = true.
- **FP:** finding, ground truth benign.
- **FN:** không finding, ground truth injection.

Hiện tại chỉ có TP synthetic trong 31 test (không FP/FN corpus). Luận văn **trung thực** không điền số Precision/Recall giả.

## 6.16. Tóm tắt chương

Chương 6 đánh giá Noirlycan theo RQ1–RQ5: **31 test tự động pass** (`test_correlation.py` + `test_ired_team_classifier.py`) xác nhận methodology [4] chống E1/E2; case study **section-mapping** đạt score ≥ 70 và vượt baseline signature; classifier pass 20 test biến thể hiện đại (RQ4). Provenance E3 và telemetry kép E4 đạt **một phần** — pipeline và test có, metric quy mô chưa đủ. **E5 (anti-sandbox) không triển khai** — hạn chế then chốt so với [4], recall lab không so sánh được 21,2 % sandbox miss. Frida fidelity (RQ5) còn protocol. Kết quả phù hợp luận văn thạc sĩ *tăng cường phát hiện dưới E1–E4* với ranh giới claim rõ ràng; thảo luận sâu hơn ở Chương 7.

---

# CHƯƠNG 7. THẢO LUẬN

Chương này tổng hợp ý nghĩa khoa học và thực tiễn của luận văn *Tăng cường phát hiện mã độc dưới các hình thức né tránh*, đặt kết quả Chương 6 trong bối cảnh công trình căn cứ Di Pietro et al. (ASIA CCS 2025) [4] và khảo sát Chương 2. Trọng tâm thảo luận là **phạm vi tăng cường thực sự đạt được** (E1–E4), **khoảng cách có chủ ý** so với paper (E5, quy mô 56.340 mẫu), và **ranh giới claim** phục vụ hội đồng bảo vệ. Luận văn không trình bày kết quả như phát minh phương pháp detection mới; định vị là *Replication + Extension Study* trên endpoint lab Windows.

---

## 7.1. Tổng hợp ý nghĩa khoa học đối với đề tài

### 7.1.1. Câu hỏi nghiên cứu và câu trả lời

Luận văn đặt câu hỏi trung tâm: *Trong phòng lab Windows, có thể tăng cường phát hiện process injection khi malware chủ động né rule cứng, né hook user-mode và che nguồn gốc hay không?* Kết quả Chương 6 trả lời **có, trong phạm vi E1–E4**, bằng cách kết hợp ba yếu tố:

1. **Phương pháp [4]** — abstraction *operational primitive* (allocate, write, execute) chịu biến thể API (E1) và gộp/ẩn bước (E2) nhờ quy tắc 2-of-3, memory congruence và temporal ordering.
2. **Kiến trúc telemetry kép** — Frida (chi tiết đối số user-mode) ∪ Sysmon (kernel callback) giảm false negative khi hook bị né (E4), với *graceful degradation* đã formal hóa ở Bảng 3.9 (Chương 3).
3. **Pipeline provenance** — liên kết Sysmon Event 11 (FileCreate) → static triage → ProcessCreate lineage → Finding injection, đối trọng né attribution (E3) mà paper [4] không mô hình hóa end-to-end trên endpoint.

Điểm then chốt: luận văn **không phát minh** thuật toán phát hiện mới thay [4]. Đóng góp nằm ở **tăng cường thực nghiện có kiểm chứng** (31 test pass), **mở rộng ngữ cảnh vận hành lab**, và **tài liệu hóa threat model formal** cho từng nhóm né tránh E1–E6.

### 7.1.2. Vị trí so với số liệu quy mô lớn của [4]

Hai con số **16,5 %** (prevalence injection) và **21,2 %** (sandbox miss do né tránh) thuộc **paper [4]**, đo trên corpus 56.340 mẫu với sandbox QEMU và module anti-evasion tích hợp. Luận văn **trích dẫn** hai con số làm động lực chọn đề tài và baseline tham chiếu (Chương Mở đầu, Chương 2 §2.6.4), **không claim** đã tái lập trên cùng điều kiện thí nghiệm.

**Bảng 7.1.** Phân tách vai trò số liệu [4] và kết quả luận văn

| Chỉ số | Nguồn | Vai trò trong luận văn | Claim luận văn |
|--------|-------|------------------------|----------------|
| ~16,5 % prevalence injection | [4], RQ1 | Chứng minh injection đáng nghiên cứu | Trích dẫn; không tái lập |
| 21,2 % sandbox miss | [4], RQ3 | Chứng minh E5 làm giảm recall | Trích dẫn; không so sánh recall Noirlycan |
| 2-of-3 framework | [4], RQ2 | Căn cứ phương pháp | **Replication** có test |
| Anti-evasion ablation | [4], §6 | Giải thích vì sao sandbox miss | **Out-of-scope** hiện thực |

Sự phân tách này là yêu cầu **trung thực khoa học** (Chương 3 §3.11): tránh inflation claim bằng số liệu không thuộc artifact luận văn.

### 7.1.3. Replication versus extension

**Bảng 7.2.** Phân loại đóng góp theo loại nghiên cứu

| Thành phần | Loại | Căn cứ |
|------------|------|--------|
| 2-of-3 + equivalence class + congruence + temporal | Replication [4] | `services/analysis/domain/correlation.py`, 11 test correlation |
| Section-mapping (*neurevt*-class) | Replication validation | `test_detects_section_mapping_write_execute_chain` |
| Audit D1/D2/D3 và fix | Methodology validation | `docs/audit-and-threat-model.md` |
| Sysmon ∪ Frida architecture | Extension (E4) | Bảng 3.9, config `sysmon-noirlycan.xml` |
| File provenance pipeline | Extension (E3) | `file_watch.py`, `test_detects_section_mapping_*` |
| Taxonomy 21+ enum | Extension (beyond paper §4) | `kernel/classification/technique_classifier.py`, 20 test |
| Dashboard + JSONL | Engineering artifact | `services/dashboard/`, reproducibility |
| Anti-evasion E5 | **Không có** | `kernel/analysis/evasion.py` ghi signal only |

---

## 7.2. Thảo luận theo từng nhóm né tránh

### 7.2.1. E1 — Biến thể API

E1 là hình thức né tránh **phổ biến nhất** trong thực tế vì chi phí triển khai thấp: thay `CreateRemoteThread` bằng `NtCreateThreadEx`, hoặc Win32 bằng Native export tương đương, đủ để rule Sigma/EDR viết cho tên hàm cụ thể thất bại.

Kết quả Chương 6 (31 test pass, case classic DLL injection với NT API) cho thấy **equivalence class** [4] giải quyết đúng vấn đề mà signature `VirtualAllocEx → WriteProcessMemory → CreateRemoteThread` không xử lý được. Baseline signature trong test (`test_signature_baseline_misses_nt_api_variant`) minh họa trực tiếp: rule khớp tên Win32 **miss** biến thể NT trong khi correlator 2-of-3 **detect**.

**Hạn chế còn lại:** malware có thể dùng API hiếm chưa có trong manifest `PAPER_API_CLASSES` hoặc `IRED_TEAM_API_CLASSES`. Cập nhật manifest định kỳ theo MITRE ATT&CK [9] và iRed.team là nhu cầu **vận hành**, không phải defect khoa học của phương pháp. Luận văn khai báo M3 (Chương 3): API ngoài class → FN có thể xảy ra.

**Liên hệ [4]:** paper đã chứng minh E1 trên quy mô dataset; luận văn **xác nhận hiện thực** trên Frida hooks, không mở rộng lý thuyết.

### 7.2.2. E2 — Gộp và ẩn bước

Quy tắc **2-of-3** là đóng góp trực tiếp của [4] cho E2: malware gộp allocate và write qua `NtCreateSection` + `NtMapViewOfSection`, hoặc bỏ allocate (Mockingjay — chỉ W+E vào vùng RWX có sẵn), vẫn đủ điều kiện phát hiện nếu còn ≥2 primitive khác loại trên cùng vùng nhớ.

Case study ***neurevt*** (paper §3.5) — biến thể **section-mapping hollowing** dominant trong family đa kỹ thuật của dataset [4] — được Noirlycan phát hiện trong test tổng hợp với score ≥ 70. Đây là bằng chứng mạnh nhất cho **validity construct** của replication: pattern W+E cross-process vào `msedge.exe` khớp mô tả paper, dù **không** chạy lại sample *neurevt* gốc từ corpus 56k.

**Mockingjay và PoolParty** — khai thác vùng RWX hoặc thread pool có sẵn — có rule classifier riêng; 20 test `test_ired_team_classifier.py` pass. Tuy nhiên, luận văn **chưa có đánh giá trên malware thật** cho hai kỹ thuật này; PoC-Bench (Phụ lục D) là hướng bổ sung bắt buộc trước bảo vệ nếu hội đồng hỏi precision thực tế.

**Temporal ordering (D3):** test `test_rejects_write_after_execute_temporal_order` xác nhận fix deviation — WRITE sau EXECUTE bị reject. Điều này củng cố tính nhất quán methodology so với paper §3.4.

### 7.2.3. E3 — Né attribution

E3 là đóng góp **độc lập** so với [4]. Trong điều tra sự cố, analyst thường thấy injection vào `msedge.exe` hoặc `explorer.exe` mà không biết file nào khởi động chuỗi. Paper batch sandbox bắt đầu từ process đã chạy; **file-drop → spawn → inject** — pattern phổ biến trên endpoint thật — không được mô hình hóa provenance end-to-end.

Pipeline Noirlycan:

```
Event 11 (FileCreate) → triage (SHA256, PE, entropy, Authenticode)
    → Event 1 (ProcessCreate, parent/child)
    → Frida primitives → Finding.related_file
```

Test `test_detects_section_mapping_write_execute_chain` và `test_resolves_target_image_from_child_process` xác nhận liên kết **định tính**. Giá trị forensic: giảm thời gian truy ngược từ Finding tới artifact trên đĩa — metric đề xuất trong outline (thời gian FileCreate → Finding) chưa điền số trên VM.

**Giới hạn E3:**

- Payload packed/encrypted (C5) che static triage — hash/entropy không đủ, runtime primitive vẫn cần.
- **Memory-only loader** (không ghi đĩa) không kích hoạt Event 11 — provenance file vô hiệu; phụ thuộc hoàn toàn Frida + Sysmon E1 lineage.
- Parent PID spoofing — Sysmon E1 có thể bị lừa; luận văn không claim chống spoofing đầy đủ.

### 7.2.4. E4 — Né hook user-mode

Ma trận tin cậy telemetry (Chương 3, Bảng 3.9) là điểm thảo luận quan trọng nhất về *tăng cường* so với single-layer Frida hoặc single-layer sandbox tracer của [4].

Khi malware **direct syscall** hoặc **unhook** `ntdll.dll` (O1/O2):

| Lớp | Trạng thái | Hệ quả |
|-----|------------|--------|
| Frida export hook | Miss toàn bộ | Mất address/size → congruence yếu |
| Sysmon Event 8 (CreateRemoteThread) | Vẫn fire (kernel ETW TI) | Fallback EXECUTE coarse |
| Sysmon Event 10 (ProcessAccess) | Vẫn fire | Fallback access pattern |
| Correlator | Degraded mode | Finding có thể đạt ngưỡng thấp hơn; classifier kém chi tiết |

Đây là **graceful degradation** — recall giảm, **không về zero** — và là đóng góp kiến trúc luận văn so với paper (một lớp tracer QEMU). Tuy nhiên, luận văn **thiếu benchmark định lượng E4**: chưa có session so sánh loader direct-syscall thuần với Frida on/off và đo tỷ lệ chain vẫn phát hiện. Hội đồng có thể hỏi *"bao nhiêu % chain vẫn detect khi Frida miss?"* — cần thí nghiệm bổ sung (Chương 6 §6.10, Kiến nghị Kết luận).

**ETW Threat Intelligence** (Chương 1 §1.8.6): Sysmon Event 8 đã tận dụng provider này; hướng phát triển là thu thập thêm syscall args từ kernel thay Frida — giảm phụ thuộc M5.

### 7.2.5. E5 — Né sandbox (hạn chế lớn nhất)

Paper [4] định lượng: **21,2 %** mẫu injection bị sandbox phổ biến bỏ sót khi thiếu anti-evasion — malware phát hiện VM/timing/env rồi **không thực hiện** injection, không phải né rule sau khi đã inject. Module anti-evasion paper (patch timing, fake environment) là thành phần **không thể tách rời** khi trả lời RQ3 [4].

Luận văn **không triển khai** module tương đương. `kernel/analysis/evasion.py` chỉ **ghi signal** (`IsDebuggerPresent`, `NtQueryInformationProcess`, …) — không bypass. Hệ quả:

1. Malware E5 trong lab VM có thể thoát sớm → log trống → zero finding.
2. Recall lab **không so sánh được** với recall paper trên cùng corpus.
3. Tên đề tài rộng (*"các hình thức né tránh"*) **rộng hơn** phạm vi hiện thực (E1–E4).

**Cách trình bày với hội đồng:** đề tài tập trung né tránh **ở tầng triển khai injection và instrumentation** (E1–E4), không phải né tránh **môi trường phân tích** (E5). Số liệu 21,2 % là **động lực** chọn [4] và **upper bound lý thuyết** cho recall nếu có anti-evasion, **không phải** kết quả Noirlycan. Đây là ranh giới đã formal hóa ở O7 (Chương 3) và claim cấm §3.11.2.

### 7.2.6. E6 — Anti-instrumentation

Frida inject **agent** vào process target — surface tấn công lớn hơn custom tracer trong QEMU của [4] (malware không “thấy” Frida trong cùng process space theo cách tương tự). E6 bao gồm: scan `frida-agent`, pipe, port 27042, timing do hook, INT3 breakpoint.

Luận văn mitigates **một phần** qua `spawn` mode (attach trước entrypoint — giảm T2 late attach) và auto-attach victim sau injection đệ quy. **Không** triển khai stealth agent hay anti-anti-Frida (O5 out-of-scope).

Recall trên malware anti-analysis thực tế có thể **thấp hơn đáng kể** so với 31 test synthetic. Giả định M5 (Frida fidelity) và protocol Phụ lục E là điều kiện cần trước khi claim kết luận phụ thuộc Frida granularity.

**Bảng 7.3.** Tóm tắt thảo luận E1–E6

| Nhóm | Mức tăng cường | Evidence chính | Hạn chế còn lại |
|------|----------------|----------------|-----------------|
| E1 | Cao | 31 test; NT API variant | API ngoài manifest |
| E2 | Cao | Section-mapping ≥70; classifier 20 test | Mockingjay/PoolParty chưa malware thật |
| E3 | Trung bình–cao | Provenance test; pipeline E11→E1 | Memory-only; packed file |
| E4 | Trung bình (thiết kế) | Bảng 3.9; Sysmon config | Thiếu benchmark syscall thuần |
| E5 | **Không** | Trích dẫn [4] 21,2 % | Không anti-evasion module |
| E6 | Thấp | spawn; limitation doc | Anti-Frida chủ động (O5) |

---

## 7.3. So sánh với các hướng tiếp cận khác

### 7.3.1. Signature và rule API (Sigma, YARA behavior)

**Ưu điểm:** triển khai nhanh trong SOC, latency thấp, giải thích dễ cho analyst junior.

**Nhược điểm:** thua E1 (đổi tên API) và E2 (gộp bước) — đúng kết luận paper [4] về false negative trên malware đa hình. Test baseline signature trong repo minh họa cụ thể.

**Vị trí Noirlycan:** không thay thế rule production — phục vụ **nghiên cứu, đào tạo, và audit** nơi cần hiểu *tại sao* rule fail và primitive abstraction hoạt động. Có thể export Finding sang Sigma rule thủ công sau analyst review.

### 7.3.2. Behavior graph (Starink et al. [12])

Starink dùng đồ thị hành vi đầy đủ với ràng buộc *same buffer* chặt hơn. Chi phí graph matching cao hơn; khó scale endpoint cá nhân. [4] đơn giản hóa thành stream rule 2-of-3 — lựa chọn luận văn bám [4] vì cân bằng tốt hơn giữa độ tổng quát và chi phí triển khai lab (Chương 2, Bảng 2.2).

### 7.3.3. EDR thương mại

Microsoft Defender, Elastic Defend, CrowdStrike Falcon kết hợp kernel driver, ML, cloud correlation — vượt xa phạm vi luận văn. Rule và model **đóng nguồn** — không audit equivalence class hay ablation E5 công khai.

**Giá trị Noirlycan:** mã nguồn mở, threat model minh bạch, tái lập [4] cho giảng dạy và thesis. Sysmon [10] được chọn vì driver ký Microsoft và schema event công khai — phổ biến trong forensic community Việt Nam và quốc tế.

### 7.3.4. Sandbox động (Cuckoo, Hatching Triage)

Paper [4] so sánh trực tiếp và chứng minh **21,2 % miss** trên injection khi thiếu anti-evasion. Sandbox cloud mạnh về quy mô batch nhưng yếu E5 nếu không có countermeasure tương đương Bluepill/paper.

Noirlycan bổ sung **quan sát endpoint real-time** trong lab cô lập — use case khác: điều tra sự cố có phạm vi hẹp, không cạnh tranh quy mô 56k mẫu. Hai hướng **bổ trợ** nhau: sandbox prevalence study [4] + endpoint lab replication/extension.

**Bảng 7.4.** So sánh tổng hợp hướng tiếp cận

| Tiêu chí | Signature | [4] QEMU batch | Sandbox cloud | EDR | Noirlycan |
|----------|-----------|----------------|---------------|-----|-----------|
| Chống E1 | Yếu | Mạnh | Yếu–TB | Khá–Mạnh | Mạnh (replication) |
| Chống E2 | Yếu | Mạnh | Yếu | Khá | Mạnh (replication) |
| Chống E3 provenance | TB | Yếu | TB | Khá | **Extension** |
| Chống E4 | Yếu | TB (tracer) | TB | Mạnh | TB (Sysmon fallback) |
| Chống E5 | TB | **Mạnh** (anti-evasion) | Yếu→21,2% miss | Khá | **Không** |
| Mở nguồn / audit | Có (Sigma) | Artifact [11] | Một phần | Không | **Có** |
| Real-time endpoint | Có | Không | Không | Có | **Có (lab)** |

---

## 7.4. Độ tin cậy của kết quả thực nghiệm

### 7.4.1. Internal validity

Ground truth trên 31 test do **tác giả luận văn gắn nhãn** — phù hợp kiểm chứng *specification* [4] (correlator implement đúng quy tắc paper), nhưng **yếu** về đại diện malware thật. Rủi ro bias: test có thể unconsciously favor implementation hiện tại.

**Giảm thiểu:** audit độc lập code-vs-paper phát hiện D1/D2/D3; test regression sau fix; hướng Paper-Subset 100 mẫu Sap4Sec [11] và PoC-Bench (Chương 6 §6.10).

### 7.4.2. External validity

Chỉ **Windows 10/11 client x64**, lab VM cô lập. Không Windows Server, ARM, enterprise fleet với EDR đa agent. Kết luận **không khái quát hóa** sang production deployment hay prevalence toàn cầu.

Malware dataset [4] giai đoạn 2017–2023 — kỹ thuật 2024+ (một số biến thể PoolParty phức tạp) có rule classifier nhưng **chưa evaluate** trên corpus.

### 7.4.3. Construct validity

- **M1 (ba primitive):** không cover kernel injection (O3) — construct đúng trong phạm vi user-mode đã khai báo.
- **M4 (memory congruence):** deviation D1 (execute thiếu address) đã fix một phần qua Rip/`lpStartAddress`; edge case `ResumeThread` không context vẫn suy yếu congruence.
- **M5 (Frida fidelity):** protocol `docs/experiments/frida-fidelity.md` có; **số liệu drop-rate chưa điền** — mọi claim phụ thuộc Frida args phải gắn nhãn *conditional on M5*.

Frida overhead thay đổi timing — có thể ảnh hưởng race APC hiếm; không đo đầy đủ trong luận văn hiện tại.

### 7.4.4. Conclusion validity

Luận văn **không** rút ra kết luận vượt evidence:

| Không claim | Có thể claim (Chương 6) |
|-------------|-------------------------|
| Prevalence 16,5 % / miss 21,2 % | 31 test pass; section-mapping ≥70 |
| Precision/recall trên corpus lớn | Vượt baseline signature trên E1/E2 (test) |
| Chống E5 toàn diện | Provenance + telemetry kép (thiết kế + test định tính) |
| Thay EDR/sandbox production | Replication [4] trên Windows lab |

---

## 7.5. Ý nghĩa thực tiễn

### 7.5.1. Phòng lab an ninh mạng giáo dục

Hệ thống Noirlycan phù hợp triển khai tại khoa CNTT — Trường Đại học Công nghệ (UET) và các đơn vị tương tự — với các use case:

- **Giảng dạy** MITRE T1055 [9]: sinh viên chạy loader PoC an toàn (MessageBox), quan sát primitive và so sánh với rule Sigma cứng.
- **Thực hành điều tra số:** correlate file drop với injection trong sự cố lab có phạm vi hẹp.
- **Thesis replication:** sinh viên sau có thể fork artifact, chạy subset Sap4Sec, mở rộng anti-evasion E5.

### 7.5.2. Giới hạn triển khai production

**Không khuyến nghị** deploy như EDR production thiếu: authentication dashboard, scale multi-host, signature update pipeline, hardening chống O4/O5, và SLA. Noirlycan là **research prototype** với JSONL export — analyst review bắt buộc trước hành động.

### 7.5.3. Tích hợp workflow SOC (tương lai)

Finding JSONL có thể ingest vào SIEM (Elasticsearch, Splunk) qua parser tùy chỉnh — ngoài phạm vi luận văn nhưng là hướng mở rộng thực tế cho lab chuyển dần sang vận hành.

---

## 7.6. Đạo đức nghiên cứu

Luận văn tuân thủ nguyên tắc nghiên cứu mã độc có trách nhiệm:

1. **Cô lập:** mẫu chỉ chạy trong VM **không kết nối** mạng sản xuất; snapshot revert sau session.
2. **PoC an toàn:** loader tự xây dùng MessageBox hoặc payload vô hại — không weaponized exploit.
3. **Không phát tán:** không redistribute hash/mẫu malware thật từ dataset [11] trong artifact công khai luận văn.
4. **Trích dẫn:** [4] và Sap4Sec/process-injection [11] đúng license và DOI công bố.
5. **Transparency:** threat model và limitation E5/E6 công khai — không che giấu recall gap so với paper.

---

## 7.7. Giải thích tên đề tài versus phạm vi hiện thực

Tên đề tài *Tăng cường phát hiện mã độc dưới các hình thức né tránh* mang nghĩa rộng — bao gồm cả E5 (sandbox/VM). Phạm vi hiện thực **cố ý thu hẹp** E1–E4 vì:

- Module anti-evasion [4] là engineering effort riêng (QEMU timing patch, env fingerprint) vượt phạm vi thesis thạc sĹ một năm.
- Replication lõi [4] + extension lab đã đủ đóng góp nếu trung thực về E5.

Luận văn coi E5 là **hướng phát triển bắt buộc** (Kết luận §4), không phải thất bại im lặng — paper đã chứng minh 21,2 % gap là real và measurable.

---

## 7.8. Hướng phát triển

**Bảng 7.5.** Lộ trình ưu tiên hướng phát triển

| Ưu tiên | Hướng | Đối phó | Nguồn / ghi chú |
|---------|-------|---------|-----------------|
| **Cao** | Anti-evasion subset | E5 | Artifact [11], paper §6 |
| **Cao** | Benchmark direct-syscall loader | E4 | PoC + session Frida on/off |
| **Cao** | Frida fidelity benchmark (M5) | E6, construct | `docs/experiments/frida-fidelity.md` |
| **Trung** | ETW TI provider trực tiếp | E4 | Thay/bổ sung Frida args |
| **Trung** | PoC-Bench + Paper-Subset 100 | E1, E2 validity | Sap4Sec [11] |
| **Trung** | Fix D1/D3 hoàn chỉnh | Congruence/temporal | Hooks + correlator |
| **Thấp** | ML classifier trên primitive sequence | E1 edge | Thay rule `technique_classifier` |
| **Thấp** | Cross-host correlation | Multi-stage | `injection_graph.py` mở rộng |

**Tương lai gần (6–12 tháng):** hoàn thiện M5 + PoC-Bench → claim conditional mạnh hơn trước publication follow-up.

**Trung hạn:** port subset anti-evasion → mới có thể nói “tăng cường dưới E5” với evidence.

**Dài hạn:** kernel ETW thay Frida hoàn toàn — giảm E6, tăng tin cậy E4.

---

## 7.9. Bài học cho nghiên cứu replication

Luận văn rút ra ba bài học cho các replication study an ninh mạng:

1. **Audit code-vs-paper trước khi claim** — D1/D2/D3 cho thấy implementation “gần đúng” vẫn có thể sai diễn giải khoa học (congruence bypass, read lẫn write).
2. **Tách số liệu paper và số liệu thesis** — prevalence 16,5 %/21,2 % là của [4], không của Noirlycan.
3. **Extension phải map threat model** — provenance và Sysmon fallback có giá trị khi gắn E3/E4 cụ thể, không marketing chung chung.

---

## 7.10. Tóm tắt chương

Chương 7 đã thảo luận ý nghĩa khoa học và thực tiễn của luận văn *Tăng cường phát hiện mã độc dưới các hình thức né tránh*: luận văn **tăng cường có căn cứ** phát hiện dưới **E1–E4** thông qua replication [4], kiến trúc Sysmon ∪ Frida, và pipeline provenance; **chưa** tăng cường dưới **E5** như paper khi có anti-evasion module. Số liệu 16,5 % và 21,2 % [4] là động lực và baseline tham chiếu, không phải kết quả luận văn. So với signature, behavior graph [12], sandbox và EDR, Noirlycan chiếm vị trí **công cụ lab mở, audit được, real-time endpoint**. Hạn chế internal/external/construct validity đã được khai báo; hướng phát triển ưu tiên anti-evasion E5, benchmark E4, và Frida fidelity M5. Luận văn định vị trung thực là **Replication + Extension Study** với Di Pietro et al. [4] là xương sống lý luận — phù hợp yêu cầu trung thực khoa học luận văn thạc sĩ UET.

---

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

---

# TÀI LIỆU THAM KHẢO

## Tiếng Việt

1. Bộ Thông tin và Truyền thông (2007), *Báo cáo tổng kết công tác năm 2007 và chương trình công tác năm 2008*, Hà Nội.

2. Trường Đại học Công nghệ — ĐHQGHN (2012), *Yêu cầu trình bày luận văn thạc sĩ*, Công văn số 139/ĐT ngày 12/04/2012, Hà Nội.

## Tiếng Anh

3. Barabosch, J., et al. (2017), "Analysis of Malware Behavior in Windows Processes", *Proceedings of the DIMVA Conference*, pp. 1-15.

4. Di Pietro, G., D'Elia, D. C., Querzoni, L. (2025), "Can You Run My Code? A Close Look at Process Injection in Windows Malware", *Proceedings of the 20th ACM Asia Conference on Computer and Communications Security (ASIA CCS '25)*, Hanoi, Vietnam, pp. 1-15. DOI: 10.1145/3708821.3736206.

5. Frida (2024), *Dynamic Instrumentation Toolkit — Documentation*, https://frida.re/docs/.

6. Hosseini, M., Antoniou, G. (2023), "A Survey of Sandbox Evasion Techniques in Windows Malware", *Computers & Security*, 130, pp. 103-118.

7. Klein, S., et al. (2017), "Process Injection Techniques in Windows Malware", *Proceedings of USENIX Security Symposium*, pp. 401-416.

8. Korkin, A. (2022), "Anti-Analysis Techniques in Modern Malware", *Journal of Computer Virology and Hacking Techniques*, 18(2), pp. 89-104.

9. MITRE ATT&CK (2024), *Technique T1055: Process Injection*, https://attack.mitre.org/techniques/T1055/.

10. Microsoft (2023), *Sysmon for Windows — Sysinternals Documentation*, https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon.

11. Sap4Sec (2025), *process-injection — Artifact repository for ASIA CCS 2025 paper*, https://github.com/Sap4Sec/process-injection.

12. Starink, T., et al. (2023), "Behavior Graphs for Malware Detection", *IEEE Transactions on Information Forensics and Security*, 18, pp. 2345-2360.

13. Co, P. V. (2026), *Noirlycan Thesis Telemetry Prototype — Source code and documentation*, Repository NoirlycanThesis, https://github.com/ *(điền URL chính thức khi công bố)*.

---

# PHỤ LỤC

## Phụ lục A. Danh mục API equivalence class (chống né tránh E1)

*Nguồn:* `src/noirlycan_telemetry/kernel/classification/api_manifest.py` — `PAPER_API_CLASSES` căn cứ [4].

### A.1. Lớp allocate

| API | Ghi chú né tránh |
|-----|------------------|
| VirtualAllocEx, VirtualAllocExNuma | Win32 classic |
| NtAllocateVirtualMemory | NT thay Win32 (E1) |
| VirtualProtectEx, NtProtectVirtualMemory | Re-protect RW→RX (E2) |
| NtCreateSection, CreateFileMappingA/W | Section-based (E2) |
| MapViewOfFile, MapViewOfFileEx | Local/remote map |

### A.2. Lớp write

| API | Ghi chú |
|-----|---------|
| WriteProcessMemory, NtWriteVirtualMemory | Classic write |
| NtMapViewOfSection | Gộp write+allocate (E2) |
| RtlCopyMemory, CopyMemory | Copy local/remote |

### A.3. Lớp execute

| API | Ghi chú |
|-----|---------|
| CreateRemoteThread(Ex), NtCreateThreadEx | Thread creation (E1) |
| RtlCreateUserThread | NT variant |
| QueueUserAPC, NtQueueApcThread(Ex) | APC injection |
| SetThreadContext, NtSetContextThread | Thread hijack |
| ResumeThread, NtResumeThread | Hollowing resume |
| LoadLibraryA/W, LdrLoadDll | DLL injection |

### A.4. Lớp observation (không tính 2-of-3)

ReadProcessMemory, NtReadVirtualMemory — phục vụ reflective heuristic, không inflate write count.

---

## Phụ lục B. Cấu hình Sysmon phòng lab

**File:** `configs/sysmon-noirlycan.xml`

**Event ID và vai trò chống né tránh:**

| Event ID | Tên | Chống |
|----------|-----|-------|
| 1 | ProcessCreate | E3 lineage, CREATE_SUSPENDED |
| 3 | NetworkConnect | Hậu kiểm beacon |
| 7 | ImageLoad | Reflective vs LoadLibrary |
| 8 | CreateRemoteThread | E4 fallback |
| 10 | ProcessAccess | E4 cross-process handle |
| 11 | FileCreate | E3 provenance |
| 15 | FileCreateStreamHash | ADS drop |

**Cài đặt:**

```powershell
cd D:\thesis\NoirlycanThesis
.\Sysmon\Sysmon64.exe -accepteula -i .\configs\sysmon-noirlycan.xml
```

---

## Phụ lục C. Hướng dẫn tái lập thí nghiệm

### C.1. Yêu cầu phần cứng và phần mềm

- VM Windows 10/11 64-bit, 4 vCPU, 8 GB RAM, snapshot sạch.
- Python 3.11+, Git, Sysmon 64-bit (thư mục `Sysmon/`).
- Frida: `pip install frida frida-tools` (ghi version vào log).

### C.2. Cài đặt Noirlycan

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .[dev]
```

### C.3. Chạy thí nghiệm có kiểm soát (spawn — chống E6)

```powershell
noirlycan-telemetry spawn --watch-sysmon -- C:\Lab\loader.exe
```

### C.4. Chạy file-drop (chống E3)

```powershell
noirlycan-telemetry run --watch-sysmon --auto-attach-new-processes
# Copy sample vào thư mục watch
```

### C.5. Dashboard

```powershell
noirlycan-telemetry dashboard --port 8765
# http://127.0.0.1:8765
```

### C.6. Kiểm thử tự động

```powershell
uv run pytest tests/test_correlation.py tests/test_ired_team_classifier.py -v
```

### C.7. Ghi chú reproducibility

Ghi vào luận văn: SHA256 VM image, phiên bản Frida, ngày chạy, đường dẫn `logs/session-*.jsonl`.

---

## Phụ lục D. Thiết kế PoC-Bench (loader an toàn)

| ID | Kỹ thuật | Né tránh mục tiêu | API điển hình |
|----|----------|-------------------|---------------|
| L1 | Section-mapping | E1, E2 | NtCreateSection, NtMapViewOfSection, ResumeThread |
| L2 | Shellcode remote thread | E1 | VirtualAllocEx, WriteProcessMemory, CreateRemoteThread |
| L3 | APC injection | E2 | VirtualAllocEx, WriteProcessMemory, QueueUserAPC |
| L4 | Reflective DLL | E1, E3 | Manual map, không LoadLibrary |
| L5 | Classic hollowing | E2 | CREATE_SUSPENDED, SetThreadContext, ResumeThread |

Payload: MessageBox only — không shellcode weaponized. Ground truth do tác giả gắn nhãn.

---

## Phụ lục E. Protocol đánh giá Frida fidelity (M5)

**Giả thuyết H₀:** Frida drop > 1 % API call dưới tải trung bình.

**Driver:** `tests/manual/frida_fidelity_driver.py`

**Quy trình:**

1. Baseline: `python -m tests.manual.frida_fidelity_driver 1000`
2. Frida: `noirlycan-telemetry spawn -- python -m tests.manual.frida_fidelity_driver 1000`
3. So sánh `driver_count` vs event JSONL.
4. Lặp N = 100, 1000, 10000; mỗi N chạy 3 lần.

**Tiêu chí bác bỏ H₀:** drop-rate trung bình < 1 %.

*(Bảng kết quả điền sau khi chạy trên VM lab.)*

---

## Phụ lục F. Mẫu cấu trúc finding JSONL

```json
{
  "type": "finding",
  "severity": "high",
  "score": 75,
  "actor_pid": 4321,
  "target_pid": 5678,
  "technique": "process_hollowing_section",
  "evidence": {
    "cross_process": true,
    "section_mapping": true,
    "related_file": "C:\\Users\\Lab\\Downloads\\sample.exe"
  },
  "primitives": ["allocate", "write", "execute"]
}
```

Trường `related_file` thể hiện đóng góp chống **E3** — liên kết injection với nguồn file.
