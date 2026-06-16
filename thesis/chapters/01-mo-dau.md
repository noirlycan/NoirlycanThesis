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

### 1.3.3. Giả thuyết nghiên cứu

Theo phương pháp khoa học [14], đề tài phải được phát biểu dưới dạng **giả thuyết có thể kiểm chứng** (*well-posed*), quy định thí nghiệm và tiêu chí chấp nhận/bác bỏ. Luận văn thạc sĩ định vị là **nghiên cứu ứng dụng** — hiện thực và mở rộng phương pháp [4] trên lab Windows, không phát minh lý thuyết detection mới — nên các giả thuyết nhắm **kiểm chứng phạm vi mở rộng** và **giới hạn ứng dụng** của [4] trên endpoint [14], [15].

**Bảng 1.3.** Giả thuyết nghiên cứu và cách kiểm chứng

| ID | Giả thuyết | Kiểm chứng (Chương 6) | Kết quả sơ bộ |
|----|------------|------------------------|---------------|
| **H1** | Phương pháp 2-of-3 + equivalence class [4] phát hiện được chuỗi injection khi malware dùng biến thể API (E1) | Unit test correlation; so baseline signature | **Chấp nhận** (31 test pass) |
| **H2** | Quy tắc 2-of-3 phát hiện injection khi malware gộp/ẩn bước (E2), ví dụ section-mapping | `test_detects_section_mapping_write_execute_chain` | **Chấp nhận** (score ≥ 70) |
| **H3** | Pipeline provenance file → process → finding tăng khả năng truy vết nguồn gốc (E3) | Case study file-drop; trường `related_file` | **Chấp nhận một phần** (định tính) |
| **H4** | Telemetry kép Sysmon ∪ Frida giảm false negative khi Frida bị né (E4) | Thiết kế E8/E10; benchmark syscall thuần | **Chưa đủ số liệu** |
| **H5** | Frida hook trung thực ≥ 99 % call dưới tải lab (M5) | Protocol `frida-fidelity.md` | **Chưa chạy trên VM** |

Giả thuyết **H0 (đối chứng)** cho H5: drop-rate Frida ≥ 1 % — bác bỏ H0 thì được dùng Frida trong kết luận khoa học.

**Giả thuyết loại trừ (không kiểm chứng trong luận văn):** Module anti-evasion [4] làm tăng recall trên malware né sandbox (E5). Luận văn **không đặt giả thuyết thí nghiệm** cho E5 vì out-of-scope hiện thực; chỉ trích dẫn số liệu 21,2 % của [4] làm động lực nghiên cứu.

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

### 1.4.4. Đối tượng độc giả và động cơ chọn đề tài

**Đối tượng độc giả** (theo [15]): (1) hội đồng luận văn thạc sĩ ngành CNTT/An toàn thông tin; (2) nhà nghiên cứu và sinh viên phòng lab malware tại các trường đại học; (3) kỹ sư SOC/DFIR cần hiểu *tại sao* rule signature API fail trước biến thể injection. Luận văn giả định độc giả đã biết Windows cơ bản, MITRE ATT&CK, và khái niệm process/thread — không giải thích từ đầu về hệ điều hành.

**Động cơ chọn đề tài:** *(Học viên điền cá nhân — ví dụ: kinh nghiệm lab malware tại UET; paper ASIA CCS 2025 tổ chức tại Hà Nội; khoảng trống giữa nghiên cứu quy mô lớn [4] và công cụ lab thực hành tại Việt Nam.)*

**Tính khả thi** [14]: dữ liệu cơ bản có sẵn (artifact Sap4Sec [11], repo Noirlycan, VM Windows); phương pháp [4] công khai; công cụ Sysmon/Frida miễn phí; thời gian phù hợp khung luận văn thạc sĩ (~12 tuần outline).

## 1.5. Phương pháp nghiên cứu

Luận văn kết hợp năm phương pháp bổ trợ nhau:

**1. Nghiên cứu tài liệu.** Khảo sát có hệ thống công trình nền tảng: Di Pietro et al. [4] (căn cứ chính); Klein et al. [7] (ba bước allocate/write/execute); Starink et al. [12] (behavior graph, memory congruence); khảo sát né tránh sandbox [6], anti-analysis [8]; MITRE ATT&CK T1055 [9]; tài liệu Sysmon [10] và Frida [5]; artifact Sap4Sec/process-injection [11].

**2. Phân tích threat model.** Chuyển hóa `docs/audit-and-threat-model.md` thành Chương 3 formal: tài sản (A1–A3), năng lực đối thủ (C1–C7), out-of-scope (O1–O7), giả định môi trường (E1–E6 trong threat model — khác với nhóm né tránh E1–E6), giả định phương pháp (M1–M6), ma trận threat T1–T9.

**3. Thiết kế và hiện thực hệ thống.** Áp dụng phương pháp [4] vào kiến trúc Noirlycan (Chương 5–6): `kernel/classification/api_manifest.py` (equivalence classes), `windows_injection_hooks.js` (Frida), `services/analysis/domain/correlation.py` (2-of-3 engine), `kernel/classification/technique_classifier.py` (21+ kỹ thuật), `file_watch.py` + static triage (provenance extension). Đối chiếu implementation với paper qua audit doc — ghi nhận deviation (D1–D8) và fix có chọn lọc.

**4. Thực nghiệm và đánh giá.** (a) Unit test correlation (31+ case); (b) PoC-Bench loader tự viết; (c) subset 100 mẫu artifact paper; (d) Benign-Baseline 50 chương trình hợp pháp; (e) Frida fidelity protocol — so sánh event Frida với ground truth. Metrics: precision, recall, F1; thời gian provenance; drop-rate Frida.

**5. Thảo luận và phản biện khoa học.** Phân tích hạn chế construct validity (Frida overhead), external validity (chỉ Windows 10/11 lab), và deviation so với paper. Không che giấu E5 out-of-scope hay inflation recall do thiếu anti-evasion.

**Bảng 1.4.** Ánh xạ phương pháp nghiên cứu với câu hỏi đánh giá (Chương 6)

| Phương pháp | Câu hỏi / Giả thuyết phục vụ |
|-------------|------------------------------|
| Audit code-vs-paper | RQ1 / H1, H2: Implementation có khớp artifact [4]? |
| PoC-Bench + Paper-Subset | RQ2: Phát hiện được loader biến thể? |
| Provenance pipeline | RQ3 / H3: Extension E3 có giá trị forensic? |
| Frida fidelity | RQ5 / H5: Frida đủ trung thực cho kết luận? |
| Telemetry kép | RQ2 / H4: Sysmon bổ sung khi E4? |

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
