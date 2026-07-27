# BÁO CÁO SEMINAR LUẬN VÁN THẠC SĨ

**Đề tài:** Tăng cường phát hiện mã độc trước các kĩ thuật né tránh
**Hệ thống:** Noirlycan Telemetry (agent Windows + backend FastAPI + dashboard React)
**Thời lượng trình bày:** ~30 phút (kèm demo live)

---

## Tóm tắt

Process injection (MITRE ATT&CK T1055) là hành vi then chốt giúp malware Windows né signature và che attribution. Công trình của Di Pietro, D'Elia và Querzoni tại ASIA CCS 2025 [4] đã phân tích 56.340 mẫu, ước lượng khoảng 16,5% có injection, và chỉ ra rằng 21,2% trường hợp bị sandbox bỏ sót khi thiếu chống né tránh; paper đề xuất phát hiện dựa trên ba operational primitive — allocate, write, execute — theo quy tắc ít nhất hai trên ba, kèm memory range congruence và temporal ordering. Tuy nhiên phương pháp đó được triển khai trên sandbox batch, chưa có pipeline endpoint lab chạy gần thời gian thực kèm provenance file.

Luận văn hiện thực và mở rộng phương pháp trong [4] thành hệ thống Noirlycan, chạy trên Windows 10/11 VM cô lập, kết hợp Frida hooks ở user-mode, Sysmon ở kernel telemetry, một correlator và một console web. Kết quả chính gồm 31 unit test pass (11 cho correlation, 20 cho classifier); case study section-mapping và AES-loader đạt finding score lần lượt trên 70 và trên 85; một pipeline hoàn chỉnh từ file-drop qua triage tới finding; và một dashboard real-time phục vụ lab. Giả thuyết H1 và H2 được chấp nhận, H3 đạt một phần, còn H4 và H5 chưa đủ số liệu trên VM để kết luận. Luận văn không tái lập quy mô thống kê 56 nghìn mẫu hay tỷ lệ 21,2% — đó là motivation lấy từ [4], không phải kết quả đo được của Noirlycan.

**Từ khóa:** process injection, operational primitive, né tránh mã độc, Sysmon, Frida, ASIA CCS 2025.

---

## 1. Mở đầu — Vấn đề và câu hỏi nghiên cứu

### 1.1. Bối cảnh

Malware Windows hiện đại không chỉ né signature tĩnh mà còn né phát hiện động, thông qua sáu nhóm kĩ thuật: thay biến thể API (E1), gộp bước trong chuỗi inject (E2), inject vào tiến trình hợp pháp để che nguồn (E3), gọi direct syscall hoặc unhook `ntdll` để bỏ qua hook user-mode (E4), phát hiện sandbox/VM rồi không thực thi payload (E5), và chống Frida hoặc debugger (E6) [4], [6], [8], [9].

Process injection cho phép payload chạy dưới danh nghĩa một process uy tín như `explorer.exe` hoặc một binary đã ký, khiến rule EDR dạng "`CreateRemoteThread` + `WriteProcessMemory`" dễ bỏ sót khi malware chuyển sang dùng NT API hoặc section mapping [4], [7].

Công trình *Can You Run My Code?* trình bày tại ASIA CCS 2025 ở Hà Nội [4] là căn cứ khoa học chính của luận văn. Trên một dataset lớn, paper báo cáo khoảng 16,5% mẫu có injection — cho thấy injection vẫn phổ biến trong giai đoạn 2017–2023 — và 21,2% trường hợp bị sandbox bỏ sót do thiếu chống né tránh, đồng thời ghi nhận process hollowing và section-mapping là các biến thể E1+E2 phổ biến nhất. Từ đó, paper đề xuất abstraction operational primitive cùng quy tắc 2-of-3 không phụ thuộc tên hàm cụ thể [4], [7], [12]. Tuy nhiên, paper chạy trên sandbox QEMU batch với custom API tracer, chưa có một triển khai endpoint lab Windows kết hợp file-drop loader, Sysmon, Frida và giao diện phân tích real-time.

### 1.2. Câu hỏi nghiên cứu

Câu hỏi trung tâm của luận văn là làm thế nào hiện thực hóa và mở rộng phương pháp 2-of-3 của [4] trên endpoint lab Windows 10/11, trong bối cảnh malware né tránh theo các nhóm E1–E4, với đánh giá có kiểm chứng và ranh giới claim khoa học rõ ràng.

### 1.3. Phạm vi

Luận văn xử lý bốn nhóm né tránh trong phạm vi của mình. E1, tức biến thể API, được xử lý trực tiếp. E2, tức gộp hoặc ẩn bước như trong section-mapping, cũng nằm trong phạm vi xử lý. E3, tức che attribution, được xử lý như một phần mở rộng về provenance. E4, tức né hook user-mode, được xử lý một phần thông qua Sysmon fallback. Ngược lại, ba nội dung nằm ngoài phạm vi luận văn là: E5, tức anti-sandbox/VM, vốn là một module riêng của paper gốc; việc tái lập tỉ lệ prevalence 16,5% hay tỉ lệ miss 21,2% trên một corpus riêng của Noirlycan; và việc thay thế các giải pháp EDR production cùng kernel injection hay ETW-TI đầy đủ.

---

## 2. Cơ sở lý thuyết và công trình nền

### 2.1. Ba operational primitive

Mọi kỹ thuật injection cổ điển đều có thể mô tả bằng ba thao tác ngữ nghĩa [4], [7]: allocate, tức chuẩn bị vùng nhớ có thể thực thi trong process đích; write, tức ghi hoặc map payload vào vùng đó; và execute, tức kích hoạt luồng thực thi thông qua remote thread, APC, hoặc cặp `SetThreadContext` cùng `ResumeThread`.

### 2.2. Quy tắc phát hiện của paper [4]

Phương pháp của paper gồm bốn thành phần phối hợp. Equivalence class gom các API như `VirtualAllocEx`, `NtAllocateVirtualMemory`, `NtMapViewOfSection` về cùng nhóm allocate, và áp dụng tương tự cho write và execute. Quy tắc từ hai trên ba yêu cầu cùng cặp `(actor_pid, target_pid)` có ít nhất hai loại primitive khác nhau mới được coi là nghi injection. Memory congruence yêu cầu các primitive liên quan cùng nằm trên một vùng địa chỉ, nhằm chống false positive [12]. Temporal ordering yêu cầu thứ tự allocate rồi write rồi execute, nhưng vẫn cho phép gộp bước để phù hợp với E2.

### 2.3. Khoảng trống luận văn lấp đầy

Paper [4] mạnh về mặt thống kê quy mô lớn và về module anti-evasion sandbox. Luận văn bổ sung bốn điểm mà paper chưa cover đầy đủ: một pipeline endpoint chạy real-time thay vì phân tích batch hậu kỳ; khả năng xác định file provenance thông qua Sysmon EID 11 kết hợp static triage, từ đó liên kết file-drop với chuỗi injection để xử lý E3; telemetry kép kết hợp Frida và Sysmon khi hook user-mode bị né để xử lý E4; và một console lab xây bằng FastAPI cùng React phục vụ giảng dạy và tái lập phương pháp của [4] tại Việt Nam [13].

---

## 3. Phương pháp và thiết kế hệ thống Noirlycan

### 3.1. Threat model — sáu nhóm né tránh E1–E6

Luận văn tổ chức threat model theo sáu nhóm né tránh, mỗi nhóm ứng với một cơ chế xử lý và một mức kết quả sơ bộ khác nhau trong Noirlycan. E1, tức biến thể API, được xử lý bằng equivalence class kết hợp quy tắc 2-of-3 và đã đạt được, tương ứng giả thuyết H1. E2, tức gộp bước như section-mapping, được xử lý bằng quy tắc 2-of-3 trên primitive ngữ nghĩa và cũng đã đạt, tương ứng H2. E3, tức che attribution, được xử lý bằng file watch, Sysmon lineage và trường `related_file`, nhưng mới đạt một phần, tương ứng H3. E4, tức direct syscall hoặc unhook, có Sysmon E8/E10 làm fallback nhưng mới đạt một phần vì H4 chưa được benchmark. E5, tức né sandbox/VM, hiện chỉ ghi nhận tín hiệu chứ chưa có module anti-evasion, nên nằm ngoài phạm vi. E6, tức anti-Frida, được xử lý bằng chế độ spawn nhưng vẫn còn hạn chế. Chi tiết formal của threat model được trình bày tại [`docs/audit-and-threat-model.md`](../../docs/audit-and-threat-model.md).

### 3.2. Pipeline phát hiện

Pipeline bắt đầu từ một file drop được ghi nhận qua EID 11 hoặc file watcher, qua bước static triage tính SHA256, nhận diện PE, entropy và chữ ký. Khi process được tạo (Sysmon E1), Frida tự động attach và bắt đầu ghi nhận memory primitive. Các primitive này được đưa vào correlator để áp quy tắc 2-of-3 cùng congruence và temporal ordering, từ đó sinh ra finding và được technique classifier gán nhãn. Sau một finding CRITICAL, hệ thống mở một cửa sổ theo dõi mạng dài 5 phút dựa trên Sysmon E3, và toàn bộ kết quả được hiển thị trên dashboard ở các tab Findings, File drops và Network. Lõi correlator nằm tại [`src/noirlycan_core/analysis/domain/correlation.py`](../../src/noirlycan_core/analysis/domain/correlation.py).

### 3.3. Kiến trúc triển khai

Hệ thống được triển khai thành ba đơn vị phối hợp qua HTTP. Trên Windows VM, package `noirlycan_agent` đóng vai trò collector, chạy Frida hooks, poll Sysmon, theo dõi file và gửi dữ liệu remote ingest về `noirlycan_backend` tại cổng 8888. Backend là một REST API FastAPI phụ trách auth, agents, rules, findings, file-drops và overview, lưu dữ liệu bằng SQLite. Phía analyst tương tác qua `dashboard-ui`, một console React chạy ở cổng 5173 dev, với các tab Overview, Findings, Agents, Rules, File drops và Network. Cấu hình Sysmon dùng cho lab được đặt tại [`configs/sysmon-noirlycan.xml`](../../configs/sysmon-noirlycan.xml), bao gồm các EID 1, 3, 7, 8, 10, 11 và CreateRemoteThread.

### 3.4. Mục tiêu nghiên cứu RO1–RO5

Luận văn đặt ra năm mục tiêu nghiên cứu. RO1, hiện thực lõi phương pháp của [4] trên Frida và correlator, đã đạt. RO2, telemetry kép giữa Sysmon và Frida để xử lý E4, mới đạt một phần. RO3, pipeline provenance từ file tới finding để xử lý E3, cũng mới đạt một phần. RO4, đánh giá các biến thể injection qua một PoC-Bench, đạt một phần với 31 test nhưng bench quy mô lớn chưa hoàn tất. RO5, xây dựng threat model cùng ranh giới claim rõ ràng, đã đạt.

---

## 4. Thực nghiệm

### 4.1. Môi trường lab

Môi trường thực nghiệm gồm một máy phân tích chạy macOS hoặc Linux, với backend tại cổng 8888 và dashboard tại cổng 5173, cùng một máy nạn nhân là Windows 10/11 x64 VM cô lập có snapshot. Instrumentation gồm Frida với script `windows_injection_hooks.js`, và Sysmon phiên bản 15 với cấu hình lab riêng. Agent được khởi động bằng lệnh `noirlycan-agent run --watch-sysmon --auto-attach-new-processes`, còn dữ liệu được lưu dưới dạng session JSONL kết hợp SQLite tại `logs/noirlycan.db`.

### 4.2. Phương pháp đánh giá đã thực hiện

Đánh giá được thực hiện theo ba hướng. Thứ nhất là 31 unit test chạy bằng pytest, gồm 11 test cho correlation kiểm tra quy tắc 2-of-3, congruence, temporal, các biến thể NT API, section-mapping và AES-loader; cùng 20 test cho classifier bao phủ hơn 21 kỹ thuật injection như PoolParty, Mockingjay và hollowing. Các test này chạy trên CI/Linux, kiểm chứng logic của correlator độc lập với runtime Frida/Sysmon.

Thứ hai là case study synthetic, gồm ba trường hợp. Case section-mapping theo kiểu Neurevt-class được kỳ vọng đạt finding từ 70 điểm trở lên trong khi baseline signature phải fail, và kết quả thực tế đã pass thông qua test `test_detects_section_mapping_write_execute_chain`. Case AES decrypt loader — một công cụ PoC do tác giả tự viết để tái hiện chuỗi section-mapping/context-transfer, không phải mã độc in-the-wild — được kỳ vọng upgrade lên CRITICAL từ 85 điểm trở lên, và đã pass qua test `test_aes_loader_chain_upgrades_to_critical`. Case baseline theo chuỗi `VirtualAllocEx→WPM→CRT` được kỳ vọng fail trên section-mapping, và kết quả đúng như thiết kế.

Thứ ba là đánh giá định tính trên VM: khi một file được drop, hệ thống lần lượt đưa qua tab File drops, tự động triage, Frida attach và cuối cùng nhóm thành Finding theo actor và target; sau một finding CRITICAL, hệ thống mở network watch 5 phút dựa trên Sysmon E3 để tìm beacon candidate nếu destination nằm ngoài dải private. Cần lưu ý bước này phụ thuộc vào việc Sysmon đang chạy trên VM, đây là một điều kiện vận hành chứ không phải một unit test.

### 4.3. Chưa hoàn thành

Một số hạng mục vẫn cần được ghi rõ là chưa hoàn thành tại thời điểm seminar: PoC-Bench trên 5 loader chạy trực tiếp trên VM; Paper-Subset khoảng 100 mẫu từ Sap4Sec [11]; các chỉ số precision, recall và F1 trên corpus có ground truth; benchmark về Frida fidelity để đo drop-rate phục vụ H5; và benchmark loader dùng direct-syscall để phục vụ H4.

---

## 5. Kết quả

### 5.1. Tóm tắt mục tiêu và giả thuyết

Xét theo từng mục tiêu, RO1 đã đạt với evidence là `correlation.py` cùng 11 test tương ứng. RO2 mới đạt một phần, có Sysmon E1/E8/E10/E11 nhưng còn thiếu benchmark A/B cho syscall. RO3 cũng đạt một phần, với `file_watch.py`, triage và trường `related_file` trong finding, nhưng cần thêm dữ liệu. RO4 đạt một phần với 31 test nhưng PoC-Bench đầy đủ chưa hoàn tất. RO5 đã đạt nhờ threat model E1–E6 cùng audit doc đi kèm.

Về giả thuyết, H1 ứng với E1 đã được chấp nhận nhờ các test NT API pass. H2 ứng với E2 cũng được chấp nhận nhờ section-mapping đạt score từ 70 trở lên. H3 ứng với E3 mới đạt một phần vì đã có pipeline provenance nhưng chưa có corpus đánh giá attribution evasion. H4 ứng với E4 chưa đủ số liệu do thiếu benchmark syscall. H5 về Frida fidelity chưa được kiểm chứng vì protocol đã có nhưng bảng drop-rate vẫn còn trống.

### 5.2. So sánh với baseline signature

Một rule naive theo kiểu `VirtualAllocEx` cộng `WriteProcessMemory` cộng `CreateRemoteThread` sẽ bỏ sót các trường hợp section-mapping thuộc nhóm E1+E2, vì malware trong case lab dùng `NtMapViewOfSection` kết hợp `SetThreadContext` và `ResumeThread`. Ngược lại, correlator của Noirlycan phát hiện được nhờ equivalence class và quy tắc 2-of-3 — đúng như motivation ban đầu của [4].

### 5.3. Minh họa luồng lab

Luồng xử lý một case study diễn ra theo trình tự sau. Đầu tiên, một loader `.exe` mới — do tác giả tự viết để mô phỏng kĩ thuật injection, không phải mã độc thu thập từ nguồn ngoài — được copy vào thư mục theo dõi như `D:\` hoặc `Downloads`. Agent kết hợp file scanner và Sysmon EID 11 để triage rồi ghi nhận ProcessCreate. Frida attach vào loader và thu được các primitive `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtMapViewOfSection` và `SetThreadContext`. Correlator nhận diện pattern `process_hollowing_section`, tính score 100 và gán severity CRITICAL. Trên dashboard, tab Findings nhóm actor là loader với target là process bị inject, còn tab File drops liên kết ngược lại tới file nguồn. Khi Sysmon hoạt động ổn định, EID 1 bổ sung thêm tên target, và tab Network ghi nhận destination IP cùng port nếu có beacon xuất hiện trong cửa sổ theo dõi 5 phút.

---

## 6. Thảo luận — Ý nghĩa và hạn chế

### 6.1. Ý nghĩa khoa học

Luận văn xác nhận rằng phương pháp 2-of-3 của [4] triển khai được trên một endpoint lab thực, chứ không chỉ trên sandbox batch như bản gốc. Luận văn cũng mở rộng ngữ cảnh sang file provenance để xử lý E3 và telemetry kép để xử lý E4 — những hướng mà paper gốc chưa cover đầy đủ. Cuối cùng, việc formal hóa threat model E1–E6 giúp trình bày trung thực, tách rõ phần replication, phần extension và phần out-of-scope.

### 6.2. Ý nghĩa thực tiễn

Hệ thống là một công cụ mã nguồn mở phục vụ giảng dạy DFIR và phân tích mã độc tại UET, giúp sinh viên và nghiên cứu viên tái lập phương pháp của [4] mà không cần sandbox đóng hay EDR thương mại. Dashboard real-time cho phép quan sát chuỗi injection, file-drop và network beacon chỉ trong vài giây, phù hợp cho việc trình diễn trực tiếp trong seminar.

### 6.3. Hạn chế

Luận văn cần nêu rõ năm hạn chế mang tính trung thực khoa học. Một là chưa replicate quy mô 56.340 mẫu — tỉ lệ 16,5% và 21,2% là số liệu của [4], không phải kết quả của Noirlycan. Hai là E5 nằm ngoài phạm vi, vì quy tắc 2-of-3 chỉ hoạt động khi malware thực sự inject, còn khi malware né sandbox thì sẽ không có primitive nào để correlate. Ba là Frida chỉ hoạt động ở user-mode nên direct syscall theo kiểu Hell's Gate có thể bỏ qua hook; Sysmon bù được một phần nhưng chưa có benchmark đầy đủ. Bốn là classifier chưa có số liệu precision/recall trên corpus, nên một số kỹ thuật hiếm có thể bị gán nhãn sai khi telemetry không đầy đủ. Năm là hệ thống phụ thuộc vào việc vận hành VM: nếu Sysmon service gặp sự cố, hệ thống sẽ mất lineage từ E1 và mất luôn khả năng theo dõi mạng.

### 6.4. Hướng mở rộng

Luận văn xác định năm hướng mở rộng gắn với từng mục tiêu còn dang dở: chạy PoC-Bench kết hợp tập con Sap4Sec để hoàn thiện RO4 cùng precision/recall; đo Frida fidelity trên VM Windows để kiểm chứng H5; thử nghiệm loader dùng direct-syscall theo kiểu A/B để kiểm chứng H4; xây dựng module anti-evasion dựa trên [11] nhằm tiến gần hơn tới recall của paper gốc; và ứng dụng ETW-TI để giải quyết đồng thời E4 và E6 ở mức kernel.

---

## 7. Kết luận

Luận văn đã tăng cường phát hiện mã độc dưới các kĩ thuật né tránh E1–E4 thông qua bốn việc chính: hiện thực có kiểm chứng phương pháp operational primitive kết hợp quy tắc 2-of-3 của Di Pietro và cộng sự [4] trên một Windows lab thực, với 31 test pass; bổ sung telemetry kernel qua Sysmon cùng pipeline file provenance để phù hợp ngữ cảnh endpoint thực; xây dựng một console lab real-time bằng FastAPI và React phục vụ thí nghiệm và trình bày seminar; và thừa nhận rõ ràng rằng E5 cùng quy mô thống kê của [4] nằm ngoài phạm vi luận văn, nhằm tránh over-claim.

Process injection vẫn là hành vi then chốt trong mã độc hiện đại, và paper [4] đã chứng minh rằng sandbox thiếu anti-evasion bỏ sót một tỉ lệ đáng kể các trường hợp này. Noirlycan không thay thế nghiên cứu quy mô đó, nhưng cung cấp một artifact tái lập và mở rộng phù hợp với mục tiêu của một luận văn thạc sĩ: có căn cứ lý luận, có hiện thực, có đánh giá về mặt phương pháp, và có ranh giới claim rõ ràng.

---

## Tài liệu tham khảo (rút gọn)

[4] Di Pietro, G., D'Elia, D. C., Querzoni, L. (2025). *Can You Run My Code?* ASIA CCS '25. DOI: 10.1145/3708821.3736206.

[5] Frida — Dynamic Instrumentation Toolkit. https://frida.re/docs/

[7] Klein, S., et al. (2017). Process Injection Techniques in Windows Malware. USENIX Security.

[9] MITRE ATT&CK T1055 — Process Injection.

[10] Microsoft Sysmon Documentation.

[11] Sap4Sec/process-injection — Artifact ASIA CCS 2025.

[12] Starink, T., et al. (2023). Behavior Graphs for Malware Detection. IEEE TIFS.

[13] NoirlycanThesis — Repository mã nguồn luận văn.

[16] Nguyễn Việt Hà (2012). Một số gợi ý về trình bày luận văn (IMRAD).

---

*Bản báo cáo seminar — rút gọn từ luận ván đầy đủ trong `thesis/`. Cập nhật kiến trúc FastAPI/React theo codebase hiện tại.*
