---
title: "Tăng cường phát hiện mã độc trước các kĩ thuật né tránh"
subtitle: "Báo cáo tóm lược luận văn thạc sĩ"
author: "Phan Văn Cơ"
date: "2026"
lang: vi-VN
---

# TĂNG CƯỜNG PHÁT HIỆN MÃ ĐỘC TRƯỚC CÁC KĨ THUẬT NÉ TRÁNH

**BÁO CÁO TÓM LƯỢC LUẬN VĂN THẠC SĨ**

**Học viên:** Phan Văn Cơ
**Chuyên ngành:** An toàn thông tin
**Cán bộ hướng dẫn:** [Chức danh, họ tên cán bộ hướng dẫn]
**Đơn vị đào tạo:** Trường Đại học Công nghệ, Đại học Quốc gia Hà Nội
**Hệ thống được xây dựng:** Noirlycan Telemetry
**Môi trường thực nghiệm:** Windows 10/11 VM cô lập

\newpage

## TÓM TẮT

Mã độc Windows hiện đại thường không bộc lộ toàn bộ chức năng trong chính tiến trình ban đầu, mà giải mã payload trong bộ nhớ, ghi payload sang một tiến trình khác rồi chuyển luồng thực thi sang vùng nhớ vừa được chuẩn bị. Nhóm hành vi này được MITRE ATT&CK xếp vào kĩ thuật process injection (T1055). Việc chạy mã dưới tên một tiến trình hợp pháp giúp mã độc giảm hiệu quả của các cơ chế phát hiện chỉ dựa trên chữ ký tệp, tên API cố định hoặc nguồn gốc tiến trình, và đó cũng là lý do luận văn chọn hướng nghiên cứu tăng cường phát hiện trước các biến thể né tránh liên quan đến process injection.

Căn cứ khoa học chính của luận văn là công trình của Di Pietro, D'Elia và Querzoni tại ASIA CCS 2025 [4], trong đó injection được biểu diễn bằng ba thao tác ngữ nghĩa gọi là *operational primitive*: cấp phát vùng nhớ (allocate), ghi hoặc ánh xạ payload (write), và chuyển thực thi (execute). Thay vì yêu cầu khớp đúng một chuỗi API cụ thể, phương pháp này phát hiện injection khi quan sát được ít nhất hai trong ba loại primitive trên cùng một quan hệ tiến trình, đồng thời kiểm tra thêm tính liên quan về vùng nhớ và thứ tự thời gian giữa các thao tác. Trên nền tảng đó, luận văn xây dựng hệ thống Noirlycan Telemetry, gồm agent chạy trên Windows, backend FastAPI, cơ sở dữ liệu và dashboard React. Agent kết hợp hai nguồn telemetry bổ sung cho nhau: Frida cung cấp thông tin chi tiết về lời gọi API và tham số tại user mode, còn Sysmon cung cấp dữ liệu cấp hệ thống về tạo tiến trình, tạo tệp, truy cập tiến trình và kết nối mạng. Correlator hợp nhất các sự kiện thành chuỗi actor–target, ánh xạ API về primitive, tính điểm và tạo finding.

Kết quả thực nghiệm hiện tại vẫn được giới hạn ở **một loader do tác giả tự viết**, nhưng loader đã được chạy lặp lại dưới nhiều bản sao tên tệp trên hai agent. Dữ liệu mới kéo về từ máy Windows ghi nhận rõ actor `aes_decrypt_loader - Copy (6).exe` (PID 13272) và target `msedge.exe` (PID 22964), thay cho target `unknown` ở lần ghi hình cũ. Correlator quan sát đủ ba operational primitive, gán score 100 và tạo finding CRITICAL với evidence `cross_process`, `section_mapping`, `has_context_read` và `execution_confirmed`. Trong môi trường VM cô lập, loader không bị Windows Defender và Kaspersky chặn trong các run quan sát. Finding phản ánh kết quả của rule correlation chứ không phải xác nhận độc lập rằng mọi API đã thành công hay payload chắc chắn đã thực thi; kết quả cho thấy telemetry hành vi có thể bổ sung cho lớp antivirus dựa trên tệp và chữ ký chứ không thay thế hoàn toàn lớp đó.

Pipeline network đã có dữ liệu end-to-end từ bộ quan sát TCP table. Sau finding, dashboard ghi nhận 20 bản ghi của hai target PID tới `192.168.0.104` trên cổng 80 và 443. Tất cả đều ở trạng thái `tcp/SYN_SENT`; do đó dữ liệu chỉ chứng minh **các nỗ lực kết nối outbound sau injection**, chưa chứng minh TCP handshake thành công, callback hay beacon C2. Hướng tiếp theo là kiểm chứng WFP 5156/5157 và Sysmon EID 3, enrich process image/hostname, phân tích chu kỳ và xác nhận destination bằng ground truth. Song song đó, hệ thống cần thử nghiệm trên nhiều loader thực sự khác nhau thay vì chỉ chạy lại nhiều bản sao của cùng một loader.

**Từ khóa:** mã độc né tránh, process injection, operational primitive, Frida, Sysmon, telemetry, behavioral detection, Noirlycan.

---

## TUYÊN BỐ VỀ PHẠM VI VÀ TÍNH NGUYÊN BẢN

Báo cáo này được viết lại bằng diễn giải của tác giả dựa trên mã nguồn Noirlycan, dữ liệu thực nghiệm và các tài liệu được trích dẫn; các khái niệm hoặc số liệu lấy từ công trình khác đều được ghi rõ nguồn. Đặc biệt cần nhấn mạnh rằng quy mô 56.340 mẫu, tỉ lệ injection khoảng 16,5% và tỉ lệ sandbox bỏ sót 21,2% là kết quả của Di Pietro và cộng sự [4], không phải kết quả đo được của Noirlycan.

Các kết luận thực nghiệm của luận văn chỉ áp dụng cho cấu hình lab đã mô tả. Việc loader không bị Defender và Kaspersky chặn là quan sát trên một công cụ PoC tự viết, tại một thời điểm thử nghiệm cụ thể, không được diễn giải thành khả năng vượt qua mọi phiên bản hoặc mọi cấu hình antivirus, và cũng không nên diễn giải thành nhận định về năng lực chống mã độc thật của hai hãng này — một binary tùy biến, chưa từng xuất hiện trước đó vốn dễ thiếu signature hơn một mẫu mã độc phổ biến. Tương tự, một finding CRITICAL chứng minh hệ thống đã phát hiện được case thử nghiệm, nhưng chưa đủ để suy ra precision, recall hoặc hiệu quả trên quần thể mã độc lớn.

\newpage

## MỤC LỤC NỘI DUNG

Báo cáo được tổ chức thành mười phần: mở đầu và vấn đề nghiên cứu; cơ sở lý thuyết và công trình liên quan; phương pháp tăng cường phát hiện; thiết kế và hiện thực Noirlycan; thiết kế rule và cơ chế ra quyết định; thực nghiệm và kết quả; thảo luận, giới hạn và tính hợp lệ; hướng phát triển; kết luận; và cuối cùng là tài liệu tham khảo cùng phụ lục.

\newpage

# 1. MỞ ĐẦU VÀ VẤN ĐỀ NGHIÊN CỨU

## 1.1. Bối cảnh

Phát hiện mã độc truyền thống thường bắt đầu từ tệp: hash, chữ ký, cấu trúc PE, chuỗi kí tự hoặc mẫu byte. Cách tiếp cận này vẫn quan trọng nhưng gặp khó khăn khi đối tượng sử dụng packing, mã hóa payload, sinh biến thể hoặc chỉ khôi phục mã độc trong bộ nhớ; khi payload không tồn tại ở dạng rõ trên đĩa, thông tin tĩnh có thể không đủ để đưa ra quyết định.

Process injection làm vấn đề phức tạp hơn. Thay vì tạo một tiến trình mang tên đáng ngờ, loader có thể mở một tiến trình hợp pháp, chuẩn bị vùng nhớ trong tiến trình đó, ghi payload và điều khiển thread thực thi payload. Từ góc nhìn người dùng, hành vi sau cùng có thể xuất hiện dưới tên trình duyệt hoặc tiến trình hệ thống; từ góc nhìn phòng thủ, nguồn gốc thật của hành vi bị che khuất.

Khó khăn này thể hiện rõ khi so sánh với cách viết rule cổ điển. Một rule API cổ điển có thể yêu cầu đúng chuỗi `VirtualAllocEx → WriteProcessMemory → CreateRemoteThread`. Rule này dễ hiểu nhưng phụ thuộc cú pháp: khi loader thay `VirtualAllocEx` bằng `NtAllocateVirtualMemory`, thay thao tác ghi bằng `NtMapViewOfSection`, hoặc thay remote thread bằng `SetThreadContext` và `ResumeThread`, chuỗi API không còn giống mẫu ban đầu dù mục đích ngữ nghĩa vẫn là chuẩn bị, đưa và chạy mã trong tiến trình đích. Vấn đề nghiên cứu vì vậy không chỉ là hook thêm nhiều API, mà là tìm một biểu diễn ít phụ thuộc vào tên hàm và có khả năng hợp nhất nhiều nguồn quan sát. Luận văn lựa chọn abstraction operational primitive và triển khai trên một endpoint Windows thật trong lab.

## 1.2. Câu hỏi nghiên cứu

Câu hỏi trung tâm của luận văn là: làm thế nào tăng cường khả năng phát hiện process injection khi mã độc thay đổi API, gộp các bước, che nguồn gốc tiến trình hoặc né hook user mode, trong một hệ thống lab có thể quan sát và tái lập?

Câu hỏi này được cụ thể hóa thành năm mục tiêu nghiên cứu. RO1 là hiện thực phương pháp primitive và quy tắc 2-of-3, hiện đã đạt. RO2 là kết hợp Frida và Sysmon để tăng độ bao phủ, hiện mới đạt một phần. RO3 là liên kết file drop, tiến trình và finding, cũng mới đạt một phần. RO4 là thử nghiệm trên các biến thể injection, hiện đạt một phần vì mới có một loader thực. RO5 là xác định rõ threat model và ranh giới kết luận, mục tiêu này đã đạt được.

## 1.3. Giả thuyết nghiên cứu

Luận văn đặt ra năm giả thuyết song hành với năm mục tiêu trên. H1 cho rằng ánh xạ nhiều API về cùng primitive giúp phát hiện được biến thể đổi API. H2 cho rằng quy tắc 2-of-3 giúp nhận diện chuỗi section mapping dù một bước cổ điển bị gộp hoặc không quan sát được. H3 cho rằng file và process provenance giúp giải thích nguồn của chuỗi injection. H4 cho rằng Sysmon có thể bổ sung lineage và tín hiệu phụ trợ khi hook Frida bị né, tuy khả năng tự tạo primitive hoặc finding độc lập từ Sysmon vẫn cần được phát triển và kiểm chứng thêm. H5 cho rằng Frida cung cấp telemetry đủ ổn định cho lab Windows.

Kết quả mới tiếp tục hỗ trợ H1 và H2. H3 được củng cố trên các run mới vì finding đã liên kết được đường dẫn loader với target image `msedge.exe`; tuy nhiên cần kiểm tra thêm trên loader khác trước khi kết luận tổng quát. H4 chưa có benchmark direct syscall để kiểm chứng. H5 chưa có phép đo drop rate có hệ thống.

## 1.4. Đóng góp

Luận văn có bốn đóng góp chính. Đóng góp thứ nhất là chuyển phương pháp trong [4] từ mô hình phân tích batch sang pipeline endpoint gần thời gian thực. Đóng góp thứ hai là kết hợp telemetry user mode và system telemetry, qua đó tách vai trò: Frida quan sát chi tiết lời gọi, còn Sysmon và TCP table bổ sung lineage, file và network; WFP mới ở mức implementation chưa được log thực nghiệm xác nhận. Đóng góp thứ ba là xây dựng console có thể giải thích finding bằng actor, target, API chain, destination quan sát được và evidence tags. Đóng góp cuối cùng là công khai giới hạn của hệ thống: chưa đánh giá trên corpus lớn, connection mới chỉ được quan sát ở trạng thái SYN_SENT và mới có một loader duy nhất được chạy lặp lại.

## 1.5. Phạm vi

Luận văn tập trung vào process injection trên Windows 10/11 x64 trong VM cô lập. Các kĩ thuật né tránh liên quan được phân thành sáu nhóm E1–E6, mỗi nhóm ứng với một mức độ xử lý khác nhau trong Noirlycan. E1, tức thay biến thể API Win32/NT, được xử lý bằng equivalence class. E2, tức gộp hoặc ẩn bước injection, được xử lý bằng quy tắc 2-of-3. E3, tức che nguồn gốc bằng tiến trình hợp pháp, mới đạt một phần thông qua provenance. E4, tức direct syscall hoặc unhook, hiện được Sysmon enrich process và cung cấp tín hiệu phụ trợ, nhưng chưa tạo primitive thay Frida và chưa có benchmark. E5, tức phát hiện sandbox và không chạy payload, nằm ngoài phạm vi hiện thực của luận văn. E6, tức anti-Frida hoặc anti-debug, được ghi nhận như một giới hạn của hệ thống.

\newpage

# 2. CƠ SỞ LÝ THUYẾT VÀ CÔNG TRÌNH LIÊN QUAN

## 2.1. Process injection

Một chuỗi injection có hai vai trò: actor là tiến trình thực hiện thao tác, còn target là tiến trình nhận vùng nhớ hoặc luồng thực thi bị điều khiển. Quan hệ actor–target quan trọng hơn tên tệp đơn lẻ, vì cùng một API có thể hợp pháp trong self-process nhưng đáng chú ý khi thao tác sang PID khác.

Các kĩ thuật injection khác nhau chủ yếu ở cách chuẩn bị memory, chuyển payload và kích hoạt execution: classic remote-thread injection dùng cấp phát, ghi và tạo thread; process hollowing tạo tiến trình suspended rồi thay hoặc ánh xạ image; APC injection xếp callback vào hàng đợi APC; thread execution hijacking sửa context của thread đang tồn tại. Dù khác nhau về API cụ thể, tất cả các kĩ thuật này đều có thể quy về ba primitive nói trên.

## 2.2. Operational primitive

Allocate mô tả việc chuẩn bị vùng nhớ hoặc section có thể chứa mã, gồm các API như `VirtualAllocEx`, `NtAllocateVirtualMemory`, `NtCreateSection` và một số API protection/mapping tùy ngữ cảnh. Write mô tả việc đưa nội dung vào address space đích; `WriteProcessMemory` và `NtWriteVirtualMemory` là trường hợp rõ ràng, còn `NtMapViewOfSection` được xem là thao tác đưa nội dung thông qua section mapping. Execute mô tả việc chuyển CPU tới payload, thông qua các cơ chế như tạo thread mới, queue APC, sửa context và resume thread.

Việc ánh xạ API về primitive mang lại hai lợi ích. Thứ nhất, rule không bị khóa vào một tên hàm cụ thể. Thứ hai, dashboard có thể giải thích hành vi ở mức ngữ nghĩa trước khi gán nhãn kĩ thuật cụ thể.

## 2.3. Quy tắc 2-of-3

Phương pháp [4] cho phép đưa ra finding khi có ít nhất hai loại operational primitive khác nhau trong cùng chain, vì quy tắc này phản ánh thực tế rằng telemetry có thể thiếu một bước hoặc một API thực hiện đồng thời nhiều chức năng. Tuy nhiên, chỉ đếm hai loại primitive là chưa đủ để kết luận, nên Noirlycan còn áp dụng thêm các điều kiện: cùng cặp `(actor_pid, target_pid)`; nằm trong cửa sổ thời gian; thứ tự hành vi hợp lí; có ít nhất một quan hệ overlap phù hợp giữa các range khi dữ liệu địa chỉ cho phép; và điểm evidence đạt ngưỡng quy định. Các điều kiện bổ sung này nhằm giảm false positive từ những lời gọi memory rời rạc, không liên quan tới nhau.

## 2.4. Memory congruence và temporal ordering

Memory congruence trong implementation hiện là một heuristic mềm: correlator tìm ít nhất một cặp primitive khác loại có range giao nhau, còn khi có quá ít primitive chứa address/size thì hàm có nhánh fallback để không loại toàn bộ chain vì thiếu dữ liệu. Phiên bản hiện tại chưa correlate `section_handle` end-to-end, nên congruence giúp giảm một phần ghép sai nhưng không chứng minh mọi primitive cùng thao tác trên chính xác một vùng nhớ.

Temporal ordering kiểm tra thứ tự thời gian giữa các thao tác. Một chain điển hình có write trước execute; với section mapping, allocate và write có thể không tách biệt rõ nên thuật toán cho phép một số biến thể, nhưng vẫn không ghép tùy ý các event cách nhau quá xa về thời gian.

## 2.5. Công trình nền

Klein và cộng sự [7] cung cấp cách nhìn injection qua các thao tác nền tảng, còn Starink và cộng sự [12] nhấn mạnh quan hệ vùng nhớ và behavior graph. Di Pietro và cộng sự [4] xây dựng phương pháp 2-of-3 và đánh giá trên 56.340 mẫu malware Windows giai đoạn 2017–2023, báo cáo khoảng 16,5% mẫu có injection và chỉ ra 21,2% trường hợp liên quan bị sandbox bỏ sót khi thiếu chống né tránh.

Những con số này giải thích tính cần thiết của nghiên cứu nhưng không được dùng làm kết quả của luận văn, vì Noirlycan không tái lập corpus hay module anti-evasion của paper. Đóng góp của Noirlycan nằm ở triển khai endpoint, telemetry kép, provenance và dashboard.

\newpage

# 3. PHƯƠNG PHÁP TĂNG CƯỜNG PHÁT HIỆN

## 3.1. Tổng quan pipeline

Pipeline phát hiện của Noirlycan bắt đầu từ một file mới xuất hiện hoặc một sự kiện tạo tiến trình, đi qua bước static triage và xác định provenance. Từ đó, hai nguồn dữ liệu Frida hooks và Sysmon Operational cùng chảy vào một bước chuẩn hóa domain event chung. Các event được nhóm theo cặp actor_pid và target_pid, sau đó lần lượt đi qua các gate 2-of-3, temporal và congruence trước khi tới bước scoring và classification. Kết quả cuối cùng là một finding kèm cửa sổ theo dõi mạng, được lưu qua FastAPI vào SQLite/JSONL và hiển thị trên React.

Điểm quan trọng của thiết kế này là pipeline không coi một API đơn lẻ là bằng chứng kết luận: event đầu vào được chuẩn hóa, tích lũy và đánh giá trong ngữ cảnh chain. Cách tổ chức theo tầng như vậy tạo khả năng thay sensor mà không phải thay toàn bộ logic phát hiện.

## 3.2. Frida: cơ chế và lí do sử dụng

Frida là framework dynamic instrumentation. Trên Windows, một session Frida gắn với PID và nạp script JavaScript vào process mục tiêu; script dùng interceptor để chặn điểm vào hoặc ra của các export trong `ntdll.dll`, `kernel32.dll` và các module liên quan. Callback đọc tham số hàm và gửi message ra agent Python. Cần lưu ý rằng một số handler phát event tại `onLeave` sau khi kiểm tra giá trị trả về, trong khi một số handler khác lại phát ngay tại `onEnter`; do đó không phải mọi event đều chứng minh lời gọi đã thành công.

Trong Noirlycan, `FridaInjectionMonitor` quản lí session theo PID, còn hook script được ghép từ runtime và handlers. Policy từ server được nhúng vào biến `__NOIRLYCAN_CONFIG__`, nhờ đó agent biết nhóm API allocate, write và execute cần cài hook. Ví dụ, handler của `NtWriteVirtualMemory` đọc process handle, địa chỉ đích và kích thước; handler `NtMapViewOfSection` đọc section handle, target process, base address, view size và protection; handler `NtCreateThreadEx` hoặc `SetThreadContext` phát event execute. Agent chuyển các message này thành `MemoryPrimitive`.

Frida được lựa chọn vì bốn lí do: không cần tự viết kernel driver cho prototype; quan sát được tham số API chi tiết phục vụ congruence; có thể attach hoặc spawn process trong môi trường lab; và phù hợp để hiển thị API chain có khả năng giải thích. Tuy vậy, giới hạn của Frida nằm ở vị trí user mode: nếu malware tự thực hiện syscall và bỏ qua export đã hook, interceptor có thể không thấy lời gọi, và malware cũng có thể phát hiện artifact của Frida. Vì vậy luận văn không xem Frida là nguồn telemetry duy nhất.

## 3.3. Sysmon: cơ chế và lí do sử dụng

Sysmon gồm driver và service của Microsoft Sysinternals. Sau khi cài bằng cấu hình XML, Sysmon ghi các event thỏa filter vào kênh `Microsoft-Windows-Sysmon/Operational`; Noirlycan đọc event qua `pywin32`, duy trì cursor bằng `EventRecordID`, render XML rồi chuyển sang model nội bộ.

Cấu hình lab hiện dùng sáu loại event chính. ProcessCreate (EID 1) cung cấp PID, image, command line và parent. NetworkConnect (EID 3) cung cấp IP, hostname và port đích. ImageLoad (EID 7) theo dõi việc nạp `ntdll`/`kernel32`. CreateRemoteThread (EID 8) cho tín hiệu remote thread. ProcessAccess (EID 10) ghi nhận quyền truy cập tiến trình nhạy cảm. FileCreate (EID 11) phục vụ provenance file drop.

Sysmon giải quyết các khoảng trống mà Frida không thuận lợi: file xuất hiện trước khi chạy, process lineage, tín hiệu remote thread/process access và kết nối mạng. Trong code hiện tại, EID 8 và EID 10 được parse thành `TelemetryEvent` để enrich source/target process và giữ tín hiệu phụ trợ, nhưng chúng chưa được chuyển thành allocate/write/execute primitive và chưa tự tạo finding khi Frida bị né. Sysmon cũng không cung cấp đầy đủ address/size cho mọi thao tác memory nên chưa thể thay Frida trong correlation.

## 3.4. Telemetry kép

Frida và Sysmon được thiết kế theo quan hệ bổ sung cho nhau theo từng câu hỏi điều tra. Frida trả lời API nào được gọi cùng địa chỉ và kích thước nào. Sysmon EID 1 trả lời process nào tạo process nào. Sysmon EID 11 kết hợp file watcher trả lời file nào vừa xuất hiện. Sysmon EID 8/10 trả lời có remote thread hoặc process access hay không. Sysmon EID 3 trả lời target kết nối tới đâu sau injection.

Tuy nhiên, mô hình này không bảo đảm chống direct syscall. EID 8/10 hiện giúp enrich quan hệ process và lưu tín hiệu quan sát, nhưng pipeline chưa ánh xạ chúng thành primitive để làm fallback detection. Vì vậy RO2 và H4 chỉ đạt một phần, và cần một bước hiện thực bổ sung trước khi có thể tuyên bố Sysmon bù được finding do Frida bỏ sót.

## 3.5. Provenance

File watcher và EID 11 ghi nhận file mới trong thư mục theo dõi; static triage tính hash, nhận diện PE, chữ kí và entropy nếu có; ProcessCreate liên kết image với PID. Correlator sau đó tìm file liên quan trực tiếp, file tạo process hoặc file của parent, và kết quả được đưa vào trường `related_file` cùng evidence.

Trong case lab, đường dẫn loader vẫn xuất hiện trong finding dưới dạng `C:\Users\Public\Downloads\aes_decrypt_loader - Copy.exe`. Tuy nhiên tab File drops của session chụp màn hình lại hiển thị 0, nên báo cáo coi provenance là đạt một phần thay vì tuyên bố pipeline đã hoàn chỉnh.

\newpage

# 4. THIẾT KẾ VÀ HIỆN THỰC NOIRLYCAN

## 4.1. Kiến trúc

Noirlycan gồm ba tầng phối hợp với nhau. Trên Windows VM, noirlycan-agent chạy Frida hooks, Sysmon poller và file watcher, gửi dữ liệu qua HTTP tới FastAPI backend đặt tại server lab; backend chịu trách nhiệm ingest và áp rule, lưu trữ bằng SQLite và JSONL, đồng thời theo dõi heartbeat agent. Phía analyst tương tác qua React dashboard, gọi API để hiển thị các tab Overview, Findings, Activity, Network và Rules.

Agent thực hiện thu thập và chuẩn hóa tối thiểu; correlation có thể chạy gần collector hoặc trên dữ liệu session tùy mode. Backend quản lí đăng nhập, agent, ruleset, finding và tổng hợp KPI, còn dashboard tập trung vào giải thích kết quả cho người phân tích.

## 4.2. Các module chính

Hệ thống được chia thành các module với trách nhiệm rõ ràng. `frida_manager.py` đảm nhiệm attach, reload policy và nhận message từ Frida. `frida_hook_catalog.py` là danh mục API hook được tổ chức theo primitive. `handlers.js` đọc tham số API và emit event tại phía script Frida. `sysmon.py` poll, parse XML và map EID sang model nội bộ. `correlation.py` bucket chain, chạy các gate, tính score và tạo finding. `technique_classifier.py` gán nhãn kĩ thuật cho finding đã tạo. `ruleset.py` giữ policy mặc định và cấu hình hiển thị trên console. Các route FastAPI xử lý ingest, agents, rules và findings, còn React dashboard trình bày KPI và evidence cho người dùng cuối.

## 4.3. Agent policy và đồng bộ rule

Ruleset trên console được chuyển thành `AgentPolicy`, bao gồm phiên bản, số primitive tối thiểu, cờ congruence/temporal, cửa sổ capture, network watch, auto-attach, watched folders, allowlist và ngưỡng severity. Khi policy thay đổi, agent tải phiên bản mới; Frida có thể biên dịch lại script hook và reattach session đang hoạt động, còn cửa sổ correlator cũng được cập nhật theo `capture_minutes`. Cách thiết kế này cho phép thử nghiệm rule mà không phải build lại toàn hệ thống.

## 4.4. Lưu trữ và giao diện

JSONL giữ event theo session để kiểm tra và tái phân loại, trong khi SQLite phục vụ truy vấn console. Dashboard tại `http://127.0.0.1:8080` gồm sáu tab chính: Overview trình bày KPI và finding nổi bật; Findings trình bày actor–target cùng evidence và API chain; Activity trình bày timeline primitive; Network trình bày connection hậu finding; Rules trình bày policy và thresholds; còn Agents trình bày endpoint, heartbeat, token và trạng thái.

## 4.5. Môi trường lab

Môi trường thực nghiệm gồm một server đặt trên macOS host với backend tại `172.16.239.1:8888`, và một endpoint là Windows 10/11 x64 VM tại `172.16.239.140` chạy agent có tên `vm01` với hai sensor Frida và Sysmon. Thư mục được theo dõi gồm `D:\` và `C:\Users\Public\Downloads`, nơi loader `aes_decrypt_loader - Copy.exe` — do tác giả tự phát triển để mô phỏng kĩ thuật injection, không phải mã độc thu thập từ nguồn ngoài — đã được chạy thử nghiệm. Môi trường được cô lập và sử dụng snapshot; công cụ thử nghiệm chỉ phục vụ nghiên cứu phòng thủ.

## 4.6. Luồng dữ liệu của một event

Để làm rõ cơ chế hệ thống, có thể theo dõi vòng đời của một lời gọi `NtMapViewOfSection`. Khi loader gọi API này, handler Frida chạy `onEnter`, lưu section handle, process handle, con trỏ base address, kích thước view và protection. Sau khi hàm trả về thành công, `onLeave` đọc giá trị cuối cùng tại các con trỏ và phát message loại write; tuy nhiên cách kiểm tra thành công này chỉ đúng cho các handler có logic `onLeave`, còn `NtWriteVirtualMemory`, `SetThreadContext` và `ResumeThread` trong phiên bản hiện tại có thể emit ngay tại `onEnter`.

Agent Python nhận message, chuẩn hóa timestamp, actor PID và target PID, tạo event dưới dạng `MemoryPrimitive` và đưa vào correlator. Correlator enrich image từ process cache, Sysmon ProcessCreate, spawn hint hoặc Windows process resolver, sau đó thêm event vào bucket mang khóa `(actor_pid, target_pid)`. Mỗi lần bucket nhận event mới, correlator đánh giá lại chain: nếu chưa đủ primitive, event tiếp tục được giữ; nếu đã đủ, temporal ordering và congruence được kiểm tra, và chỉ sau các gate này hệ thống mới tính score và classification. Finding được ghi JSONL/SQLite và gửi về backend; dashboard không tự suy diễn từ API thô mà chỉ trình bày kết quả đã được correlation engine tạo ra.

Luồng xử lý này giải thích hai thuộc tính quan trọng của Noirlycan. Thứ nhất, hệ thống có trạng thái, nghĩa là một event mới có thể nâng score của một chain đã tồn tại từ trước. Thứ hai, dữ liệu được tách tầng rõ ràng: sensor thu thập, domain model chuẩn hóa, correlator ra quyết định và giao diện chỉ giải thích kết quả. Việc tách tầng này giúp kiểm thử phần lõi mà không cần chạy malware trong mọi unit test.

## 4.7. Quản lí thời gian, PID và chất lượng dữ liệu

PID trên Windows có thể được tái sử dụng, nên nếu chỉ dựa vào PID mà không xét thời gian tạo process, một network event muộn có thể bị gắn sai vào process khác. Prototype hiện sử dụng timestamp và cửa sổ capture để giảm rủi ro này, nhưng hướng hoàn thiện cần ưu tiên `ProcessGuid` của Sysmon cho liên kết bền vững hơn.

Timestamp từ Frida và Sysmon phải được chuẩn hóa về UTC trước khi correlation. Event đến trễ vẫn có thể được sắp xếp theo timestamp domain, nhưng nếu vượt capture window sẽ bị loại; capture quá ngắn làm giảm recall khi loader ngủ, còn capture quá dài lại tăng nguy cơ ghép nhầm, nên tham số này cần đo thực nghiệm thay vì chọn tùy ý.

Chất lượng finding phụ thuộc các trường target PID, target image, address, size và protection. Hệ thống cho phép một số trường rỗng để không mất toàn bộ event, nhưng confidence phải giảm khi thiếu execution transfer hoặc congruence. Đây là nguyên tắc suy luận theo mức bằng chứng, thay vì biến dữ liệu thiếu thành kết luận chắc chắn.

\newpage

# 5. THIẾT KẾ RULE VÀ CƠ CHẾ RA QUYẾT ĐỊNH

## 5.1. Phân biệt rule thu thập và rule phát hiện

Sysmon rule quyết định sự kiện nào được ghi vào Event Log, còn detection rule quyết định khi nào các sự kiện đã có tạo thành finding. Nếu filter Sysmon quá rộng, log sẽ nhiễu và tốn tài nguyên; nếu quá hẹp, dữ liệu cần thiết có thể bị mất trước khi correlator kịp xử lí.

## 5.2. Nguyên tắc rule Sysmon

Cấu hình hiện tại ghi toàn bộ ProcessCreate để duy trì lineage. FileCreate chỉ giữ các đuôi có khả năng thực thi hoặc script như `.exe`, `.dll`, `.scr`, `.ps1`, `.js`, `.vbs`, `.hta`, `.bat` và `.cmd`. ImageLoad tập trung vào `ntdll.dll` và `kernel32.dll`. ProcessAccess chỉ giữ một số `GrantedAccess` nhạy cảm, còn NetworkConnect loại localhost để giảm nhiễu.

Việc cấu hình rule Sysmon tuân theo năm nguyên tắc cơ bản: bắt đầu từ mục tiêu điều tra thay vì bật mọi event vô điều kiện; giữ đủ field cần thiết cho liên kết PID, file và thời gian; loại trừ những nguồn nhiễu có thể giải thích được như loopback; thử nghiệm trên workload sạch trước khi áp dụng cho malware; và version hóa cấu hình cùng với mã nguồn.

## 5.3. Equivalence class

Danh sách API được tổ chức theo ba nhóm primitive. Nhóm allocate gồm `VirtualAllocEx`, `NtAllocateVirtualMemory`, `NtCreateSection` và `NtProtectVirtualMemory`. Nhóm write gồm `WriteProcessMemory`, `NtWriteVirtualMemory`, `NtMapViewOfSection`, `NtUnmapViewOfSection` và `RtlCopyMemory`. Nhóm execute gồm `CreateRemoteThread`, `NtCreateThreadEx`, `QueueUserAPC`, `SetThreadContext` và `ResumeThread`. Một API chỉ được tính theo nghĩa mà handler phát ra; các API đọc như `NtReadVirtualMemory` thuộc về observation/context và không được dùng để thỏa quy tắc 2-of-3.

## 5.4. Correlation gate

Trước khi tính điểm, một chain phải vượt qua sáu cổng kiểm tra: số loại operational primitive phải đạt `min_primitives` (lab dùng ngưỡng 2); các event phải thuộc cùng bucket actor–target; temporal consistency phải hợp lệ nếu policy bật; heuristic memory congruence phải hợp lệ nếu policy bật, với yêu cầu ít nhất một overlap liên-kind khi đủ range và có fallback khi thiếu địa chỉ; event phải còn nằm trong capture window; và cuối cùng, chain không được vi phạm policy same-process/cross-process. Các cổng này cùng nhau làm giảm khả năng một API đơn lẻ hoặc các event không liên quan tạo ra finding sai.

## 5.5. Scoring thực thi

Hàm `_score()` trong correlator cộng điểm dựa trên evidence thực tế quan sát được. Nếu chain có write và execute với execution đã confirmed, điểm được cộng thêm 45; nếu chỉ có ít nhất hai loại primitive, điểm cộng thêm 35; nếu đủ cả allocate, write và execute với execution confirmed, cộng thêm 20. Ngoài ra, tính chất cross-process cộng thêm 15 điểm; sự hiện diện của API section cộng 10 điểm; có executable protection cộng 10 điểm; actor được tạo ở trạng thái suspended cộng 15 điểm; có related file cộng 10 điểm; file là PE cộng 5 điểm; file unsigned cộng 10 điểm; và entropy từ 7 trở lên cộng thêm 5 điểm.

Nếu thiếu execution transfer, score bị giới hạn ở mức thấp, và pattern giống installer resume một process hợp lệ cũng bị cap để tránh false positive. Với cùng một chain, hệ thống chỉ báo lại khi score mới cao hơn score trước đó, nhằm tránh spam finding trùng lặp.

Ngưỡng phân loại severity trong policy lab hiện tại là MEDIUM từ 30 điểm, HIGH từ 55 điểm và CRITICAL từ 80 điểm. Khi hệ thống không có `AgentPolicy` cụ thể, correlator sẽ dùng ngưỡng fallback là MEDIUM 50, HIGH 70 và CRITICAL 85. Cần lưu ý rằng bảng "score weights" hiển thị trên UI chỉ là biểu diễn của policy, còn logic `_score()` nêu trên mới thực sự là scoring đang thực thi.

## 5.6. Named chain và classification

Tệp `ruleset.py` khai báo một số named chain phục vụ policy và giao diện, gồm section-mapping loader theo chuỗi `NtCreateSection → NtMapViewOfSection → SetThreadContext`; classic hollowing theo chuỗi mapping/unmap rồi sửa context và resume; remote-thread theo chuỗi allocate, write rồi `CreateRemoteThread`; APC injection theo chuỗi allocate, write rồi `QueueUserAPC`; và thread hijacking theo chuỗi write, `SetThreadContext` rồi `ResumeThread`.

Tuy nhiên các khai báo này không tự chứng minh rằng classifier đã match đúng một chain nào đó; correlator gọi một classifier riêng sau khi finding đã được tạo. Ngoài ra cần lưu ý rằng hook `NtCreateSection` gán target là PID hiện tại, trong khi `NtMapViewOfSection` và context operation có thể nhắm PID nạn nhân; vì bucket được khóa theo `(actor_pid, target_pid)`, ba API trên không mặc nhiên nằm trong cùng một bucket cross-process. Evidence `section_mapping` của finding trong case lab có thể đến từ chính `NtMapViewOfSection`.

## 5.7. Network watch

Khi score đạt ít nhất 70 và có target PID, correlator mở một cửa sổ theo dõi mạng, mặc định kéo dài 5 phút. Ngoài Sysmon EID 3, phiên bản mới bổ sung `TcpWatchPoller`, dùng `GetExtendedTcpTable` để quan sát cả socket `SYN_SENT` lẫn `ESTABLISHED`, và `WfpPoller` dự kiến đọc Security Event 5156/5157 khi WFP audit được bật. Chỉ event thuộc PID trong network-watch window mới được ghi. Trong log hiện tại, nguồn duy nhất được kiểm chứng là `tcp_table`: dashboard hiển thị 20 bản ghi của hai target PID tới `192.168.0.104:80/443`, đều `SYN_SENT` và `succeeded=false`; toàn bộ log mới có 62 record cùng loại. Pipeline vì vậy mới được xác nhận ở mức phát hiện connection attempt, chưa có bằng chứng handshake thành công hoặc WFP/Sysmon corroboration.

\newpage

# 6. THỰC NGHIỆM VÀ KẾT QUẢ

## 6.1. Phạm vi dữ liệu thực nghiệm

Tại thời điểm viết báo cáo, lab vẫn chỉ có một loader tự viết để tái hiện chuỗi section-mapping/context-transfer, không phải malware in-the-wild. Tuy nhiên, loader đã được chạy lặp lại dưới các tên bản sao `(2)` đến `(6)` trên hai agent `winVM01` và `vm02`. Dashboard hợp nhất dữ liệu thành 10 finding/chain, gồm 7 CRITICAL và 3 HIGH. Đây là kiểm tra độ lặp lại của cùng một implementation, **không phải sáu loader độc lập** và chưa phải benchmark đa kĩ thuật.

## 6.2. Quy trình

VM được khôi phục về trạng thái lab, các agent `winVM01` và `vm02` đăng kí với backend. Loader được đưa vào watched folder và chạy nhiều lần; Frida attach vào tiến trình và phát event memory. Khi finding đạt ngưỡng, correlator mở network-watch cho target PID, còn TCP-table poller ghi nhận connection attempt. Backend nhận dữ liệu, lưu JSONL/SQLite và dashboard hiển thị finding cùng destination. Ảnh trong báo cáo được chụp lại từ dữ liệu sau khi `git pull`.

## 6.3. Kết quả tổng quan

![Hình 1 — Tổng quan KPI và finding CRITICAL](images/01-overview.png)

*Hình 1. Overview sau khi nạp log mới: hai agent, 10 finding/chain, 7 CRITICAL; finding mới nhất liên kết loader PID 13272 với `msedge.exe` PID 22964 và destination `192.168.0.104:443`.*

Tại thời điểm chụp lại, dashboard hiển thị 2 agent, 10 finding, 7 CRITICAL, 10 injection chain, 30 file drop và 20 network observation. Biểu đồ primitive tích lũy ghi 1.734 allocate, 127 write và 438 execute. Những số này là tổng event của nhiều run; chúng không tương ứng với số loader khác nhau. Con số 20 network observation không phải 20 máy chủ C2 hay 20 handshake thành công.

## 6.4. Finding

![Hình 2 — Finding actor–target và evidence](images/02-findings.png)

*Hình 2. Finding mới cho thấy quan hệ `aes_decrypt_loader - Copy (6).exe` (PID 13272) → `msedge.exe` (PID 22964), score 100, cùng evidence tags và API chain.*

Finding mới nhất có tiêu đề "Probable process injection chain", severity CRITICAL và score 100. Actor là `aes_decrypt_loader - Copy (6).exe` mang PID 13272; target đã được enrich thành `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe` mang PID 22964. Evidence gồm `section_mapping`, `cross_process`, `execution_confirmed`, `has_context_read` và `executable_protection`.

So với ảnh cũ, target image đã được khôi phục từ spawn/process metadata, giúp provenance actor→target rõ hơn. Tag `execution_confirmed` vẫn chỉ là nhãn tương quan ngữ nghĩa do correlator gán, không chứng minh rằng OS-call đã trả về thành công hoặc payload thực tế đã chạy.

![Hình 3 — Chi tiết finding sau khi mở cảnh báo](images/07-finding-detail.png)

*Hình 3. Modal chi tiết được mở bằng cách chọn “Probable process injection chain”; giao diện trình bày score 100, actor/target, technique `process_hollowing_section`, confidence, payload và evidence đã dùng để ra quyết định.*

![Hình 4 — API chain và network evidence trong finding](images/08-finding-detail-evidence.png)

*Hình 4. Phần dưới của modal hiển thị API chain và 18 network observation gắn với target PID 22964. Trạng thái `NOT EST.` biểu thị socket được quan sát ở `SYN_SENT`, không phải kết nối C2 thành công.*

## 6.5. Phân tích API chain

Chuỗi API quan sát được gồm `NtAllocateVirtualMemory` ở nhóm allocate; `NtWriteVirtualMemory` xuất hiện nhiều lần cùng `NtMapViewOfSection` ở nhóm write/mapping; `GetThreadContext` và `NtGetContextThread` ở nhóm context; và `SetThreadContext`, `ResumeThread` ở nhóm execute. Danh sách lời gọi này cho thấy loader không dùng mẫu Win32 cổ điển: `NtMapViewOfSection` là tín hiệu section mapping, còn việc quan sát các lời gọi đọc/sửa context và resume thread phù hợp pattern thread execution hijacking hoặc một biến thể hollowing.

Vì một số hook emit tại `onEnter` và hiện chưa có ground truth về target, báo cáo chỉ dừng ở kết luận rằng đã quan sát chuỗi lời gọi tương ứng với section-mapping và context-transfer, chứ không khẳng định payload chắc chắn đã thực thi hay gán một nhãn malware family tuyệt đối.

## 6.6. Activity

![Hình 5 — Timeline primitive](images/03-activity.png)

*Hình 5. Activity stream trình bày các event quan sát trong session. Danh sách toàn session không được dùng như thứ tự duy nhất của chain đã vượt temporal gate.*

Tab Activity giải thích dữ liệu đầu vào của finding: `NtWriteVirtualMemory` và `NtMapViewOfSection` được map thành write primitive, còn `SetThreadContext` và `ResumeThread` được map thành execute-transfer event; cờ `cross_process=true` cho biết target PID khác actor PID. Chuỗi event này đủ điều kiện correlation và scoring của hệ thống, nhưng không phải bằng chứng độc lập rằng từng lời gọi đã thành công hoặc payload đã thực sự chạy.

## 6.7. Network

![Hình 6 — Network connection attempt sau finding](images/04-network.png)

*Hình 6. Tab Network ghi nhận 20 connection observation từ hai target PID tới `192.168.0.104` trên cổng 80/443; toàn bộ ở trạng thái `tcp/SYN_SENT` và được hiển thị `NOT EST.`.*

Dữ liệu mới chứng minh process đích đã tạo connection attempt tới `192.168.0.104:80` và `192.168.0.104:443`. Nguồn `TCP_TABLE` quan sát socket ở thời điểm `SYN_SENT`; dashboard hiển thị 0 succeeded và 20 `FAIL`, dù `SYN_SENT` chính xác hơn nên được hiểu là chưa hoàn tất tại thời điểm quan sát. Sự lặp lại gợi ý retry định kì, nhưng chưa đủ để gọi là callback hay beacon vì không có `ESTABLISHED`, hostname, payload mạng hoặc WFP/Sysmon event đối chứng.

## 6.8. Rules và agent

![Hình 7 — Policy correlation](images/05-rules-correlation.png)

*Hình 7. Rules tab: 2-of-3, capture window, network watch và danh sách primitive.*

![Hình 8 — Agent vm01](images/06-agents.png)

*Hình 8. Hai agent `winVM01` và `vm02` đã gửi dữ liệu; đều Offline tại thời điểm chụp vì đây là dữ liệu session đã hoàn tất.*

Trạng thái offline được giữ nguyên để phản ánh đúng thời điểm chụp; dữ liệu finding, file và network đã được lưu trong session trước đó. Khi demo live cần khởi động lại agent, nhưng báo cáo có thể dùng ảnh và JSONL làm bằng chứng tái lập.

## 6.9. Unit test

Logic phần lõi có 31 test được dùng làm bằng chứng bổ sung, gồm 11 test cho correlation và 20 test cho classifier. Hai test tiêu biểu là `test_detects_section_mapping_write_execute_chain`, yêu cầu score đạt ít nhất 70, và `test_aes_loader_chain_upgrades_to_critical`, mô phỏng chuỗi loader → Edge và yêu cầu score đạt ít nhất 85. Các unit test này chứng minh correctness của logic trên input được kiểm soát, nhưng không đo được khả năng sensor thu thập đầy đủ mọi event trong VM và cũng không thay thế cho precision/recall đo trên corpus thực tế.

## 6.10. So sánh

Trong case lab, Defender và Kaspersky không chặn loader do đây là quan sát cụ thể của một run, trên một công cụ PoC tự viết chưa từng xuất hiện trước đó nên khó có signature sẵn — điểm đáng chú ý ở đây không phải là "AV thương mại yếu", mà là một rule Win32 cố định có khả năng bỏ sót vì chain của loader dùng NT API, section mapping và context thay vì API cổ điển. Ngược lại, cách tiếp cận primitive của Noirlycan đưa ra kết quả CRITICAL nhờ gom API về mức ngữ nghĩa rồi correlate, bất kể tên hàm cụ thể là gì. Kết quả này cho thấy vai trò bổ sung của behavioral telemetry khi rule cứng theo tên API bị né, nhưng không chứng minh Noirlycan tốt hơn toàn diện so với antivirus, vì AV thương mại còn nhiều lớp sensor khác và ở đây mới chỉ một công cụ thử nghiệm được chạy.

## 6.11. Đánh giá theo mục tiêu và giả thuyết

Xét theo từng mục tiêu, RO1/H1 và H2 tiếp tục được hỗ trợ qua nhiều run lặp lại. RO2/H4 vẫn đạt một phần vì chưa benchmark direct syscall; network mới kiểm chứng đường TCP table, chưa kiểm chứng WFP. RO3/H3 được cải thiện rõ vì related file, actor image và target `msedge.exe` đã liên kết được trong finding. RO4 vẫn chỉ đạt một phần: 31 test và nhiều run của **một loader** chưa phải benchmark đa loader. H5 chưa đủ căn cứ vì chưa đo drop rate. RO5 đạt vì báo cáo tách rõ finding, connection attempt và số liệu paper.

Cách đánh giá theo ma trận này tránh lối đánh giá nhị phân: module tồn tại không đồng nghĩa mục tiêu đã hoàn tất. Network hiện đã vượt mốc “không có dữ liệu” nhờ quan sát TCP table, nhưng vẫn chỉ đạt một phần vì mọi socket đều SYN_SENT/FAIL, chưa có WFP/Sysmon corroboration và chưa xác nhận callback server thực sự trả lời.

## 6.12. Dữ liệu cần bổ sung cho lần đánh giá tiếp theo

Để việc đánh giá lần sau có cơ sở vững hơn, mỗi run nên xuất một gói bằng chứng đầy đủ gồm hash loader, phiên bản AV, timestamp bắt đầu và kết thúc, ProcessGuid của actor và target, event Frida thô, event Sysmon XML liên quan, finding JSON và network connection. Gói bằng chứng này giúp kiểm tra lại kết luận mà không phụ thuộc hoàn toàn vào ảnh chụp dashboard.

Song song đó, mỗi loader thử nghiệm cần có một bảng ground truth ghi rõ kĩ thuật dự kiến, ví dụ section mapping; actor image và PID; target image và PID; các primitive dự kiến gồm allocate, write, execute; các API dự kiến như `NtCreateSection`, `NtMapViewOfSection`; hành vi network callback nếu có, gồm hostname, IP, port, hoặc ghi rõ "không có"; kết quả của AV, tức blocked, allowed hay quarantined; và cuối cùng là kết quả của Noirlycan gồm severity, score và latency. Khi có đầy đủ dữ liệu này trên nhiều loader và cả trên workload sạch, luận văn mới có thể tính confusion matrix và thảo luận precision/recall một cách có cơ sở.

\newpage

# 7. THẢO LUẬN, GIỚI HẠN VÀ TÍNH HỢP LỆ

## 7.1. Trả lời câu hỏi nghiên cứu

Luận văn đã chứng minh về mặt hiện thực rằng phương pháp primitive có thể chạy trên endpoint lab và tạo ra finding giải thích được. Equivalence class giải quyết vấn đề né tránh E1 ở mức rule; quy tắc 2-of-3 cùng cơ chế section mapping hỗ trợ giải quyết E2; còn provenance và telemetry kép hiện mới đạt một phần.

## 7.2. Ý nghĩa khoa học

Noirlycan không đề xuất thay thế phương pháp [4], mà giá trị của luận văn nằm ở việc tái lập có điều chỉnh và đưa phương pháp vào một hệ thống vận hành gồm agent, backend và console. Báo cáo tách rõ ba loại đóng góp: replication gồm operational primitive và quy tắc 2-of-3; extension gồm provenance, Sysmon, TCP-table/WFP watch, policy live và dashboard; future work gồm xác nhận callback thành công, benchmark direct syscall và thử nghiệm trên nhiều loader độc lập.

## 7.3. Ý nghĩa thực tiễn

Console giúp người phân tích đi từ cảnh báo tới evidence cụ thể. Thay vì chỉ nói "malicious" một cách chung chung, finding cho biết actor, target, primitive và cả API chain đã dẫn tới kết luận đó. Mô hình này phù hợp cho giảng dạy DFIR, phục vụ nghiên cứu về T1055 và hỗ trợ phát triển rule trong môi trường lab.

## 7.4. Giới hạn

Luận văn hiện còn một số giới hạn. Về quy mô mẫu, nhiều lần chạy và nhiều tên bản sao vẫn chỉ đại diện cho một loader tự viết, không đại diện toàn bộ taxonomy injection. Về antivirus, quan sát bypass phụ thuộc phiên bản, cấu hình và thời điểm, đồng thời binary tùy biến dễ thiếu signature hơn malware phổ biến. Về network, hệ thống đã xác định destination `192.168.0.104:80/443` nhưng chỉ từ TCP table ở trạng thái SYN_SENT; chưa có handshake thành công, hostname, WFP 5156 hay Sysmon EID 3 đối chứng nên chưa thể xác nhận beacon C2 hoạt động. Target image đã được enrich thành `msedge.exe` trên run mới, nhưng agent vẫn Offline tại thời điểm chụp. Direct syscall/anti-Frida, precision/recall trên corpus và E5 anti-sandbox vẫn chưa được giải quyết.

## 7.5. Threats to validity

Về internal validity, finding phụ thuộc policy và trình tự event; unit test không loại trừ lỗi sensor. Các bản ghi TCP_TABLE có thể là nhiều lần poll của connection attempt tái xuất hiện, nên không được đồng nhất trực tiếp với số callback logic. Về external validity, kết quả không tự động tổng quát sang loader khác hay endpoint production. Về construct validity, "bypass AV" chỉ nghĩa là không bị chặn trong run; nhãn "BEACON" trên UI chỉ là candidate sau finding. Về conclusion validity, báo cáo không dùng 20 network record để suy ra 20 beacon hoặc một kết nối C2 thành công.

## 7.6. Đạo đức và an toàn thực nghiệm

Process injection là chủ đề lưỡng dụng. Mã nguồn sensor, rule và dữ liệu phòng thủ được trình bày nhằm phục vụ mục đích phát hiện; báo cáo không cung cấp payload, hạ tầng C2 hay hướng dẫn triển khai mã độc ngoài phạm vi lab. Loader dùng trong thực nghiệm do chính tác giả viết để tái hiện kĩ thuật section-mapping/context-transfer đã công bố trong tài liệu, không phải mã độc thật được thu thập hay tải về từ nguồn ngoài; lựa chọn này giúp loại bỏ hoàn toàn rủi ro liên quan đến việc lưu trữ, vận chuyển hay vô tình phát tán mã độc thật trong quá trình nghiên cứu. Loader chỉ được chạy trong VM cô lập, có snapshot và giới hạn kết nối mạng.

Khi hoàn thiện kiểm thử network, callback phải trỏ tới hạ tầng do người nghiên cứu kiểm soát, không sử dụng máy chủ công cộng không được phép. Log có thể chứa đường dẫn người dùng, hostname và IP nên cần được xử lí như dữ liệu nhạy cảm, còn token của agent xuất hiện trong ảnh hoặc phụ lục phải được rút gọn hay thu hồi sau khi demo.

## 7.7. Kiểm soát tính nguyên bản của báo cáo

Báo cáo sử dụng ba nguyên tắc để tránh đạo văn. Thứ nhất, khái niệm và số liệu lấy từ tài liệu khác được dẫn nguồn ngay tại phần sử dụng. Thứ hai, phần mô tả Frida, Sysmon, scoring và rule được viết lại từ việc đọc mã nguồn Noirlycan thay vì sao chép tài liệu sản phẩm. Thứ ba, kết quả lab được trình bày bằng dữ liệu riêng và ảnh dashboard riêng của tác giả.

Trích dẫn ở đây không chỉ là đặt số tham khảo ở cuối câu. Khi sử dụng đóng góp 2-of-3 của [4], báo cáo nêu rõ đâu là phương pháp được kế thừa và đâu là phần Noirlycan mở rộng thêm. Cách phân biệt replication, extension và future work vừa bảo vệ tính nguyên bản, vừa giúp hội đồng đánh giá đúng phạm vi đóng góp của luận văn.

\newpage

# 8. HƯỚNG PHÁT TRIỂN

## 8.1. Xác nhận và làm giàu beacon callback

Tab Network đã có dữ liệu từ TCP table và trả lời bước đầu rằng process đích thử kết nối tới `192.168.0.104` qua TCP 80/443. Hướng ưu tiên tiếp theo không còn là “làm tab có dữ liệu”, mà là xác nhận callback có thành công hay không, máy đích là thành phần nào trong lab, và chu kỳ retry có thực sự là beacon hay chỉ là connection attempt thất bại.

Kế hoạch thực hiện gồm: xác định vai trò của host `192.168.0.104`; bật WFP Security 5156/5157 và Sysmon EID 3 để đối chứng TCP table; enrich `image`, hostname và ProcessGuid; phân biệt `SYN_SENT`, `ESTABLISHED`, thất bại và timeout; deduplicate snapshot theo socket lifecycle; kiểm thử với server lab chủ động lắng nghe trên 80/443; và lưu first seen, last seen, số attempt cùng khoảng cách giữa các attempt.

Về hiển thị, dashboard cần đổi cách gọi từ “beacon” sang “beacon candidate” khi chưa có đủ bằng chứng; đồng thời tách attempt, success và repeated observation. Chỉ khi có ground truth, chu kỳ ổn định và connection được xác nhận mới gán nhãn beacon. Allowlist cho hạ tầng lab, DNS, proxy và dịch vụ Windows cũng cần được áp dụng trước khi đánh giá false positive.

Kết quả hiện tại đã liên kết finding injection với destination IP/port; kết quả mong đợi tiếp theo là chứng minh vòng đời callback hoàn chỉnh từ lời gọi connect đến handshake và traffic ứng dụng. Chỉ sau bước đó luận văn mới có thể khẳng định beacon callback hoạt động.

## 8.2. Thử nghiệm trên nhiều loader hơn

Hướng thứ hai là mở rộng từ case study sang một benchmark có kiểm soát. Bộ thử nghiệm dự kiến bao trùm bảy nhóm loader: classic remote thread dùng `VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread`; NT remote thread dùng `NtAllocateVirtualMemory`/`NtWriteVirtualMemory`/`NtCreateThreadEx`; section mapping dùng `NtCreateSection`/`NtMapViewOfSection`; process hollowing dùng suspended process, context và resume; APC injection dùng `QueueUserAPC` hoặc kĩ thuật Early Bird; reflective DLL dùng local staging và execute; và direct syscall để đánh giá mức độ mất telemetry của Frida.

Mỗi loader trong bộ thử nghiệm cần có ground truth về actor, target, API dự kiến và hành vi mạng. Thực nghiệm phải được chạy lặp lại, ghi rõ phiên bản Windows, Frida, Sysmon và AV, đồng thời reset snapshot giữa các lần chạy. Các metric cần bổ sung gồm detection rate theo từng loader, time-to-detect, số event Frida hoặc Sysmon bị thiếu, false positive trên workload sạch, precision, recall và F1 khi đã đủ corpus, tỉ lệ enrich được target name, và tỉ lệ xác định được destination callback.

## 8.3. Các hướng bổ sung

Ngoài hai hướng chính trên, luận văn còn xác định thêm một số hướng bổ sung: benchmark direct syscall để kiểm chứng H4; đo Frida fidelity và tỉ lệ event bị mất để kiểm chứng H5; sử dụng ETW hoặc telemetry kernel phù hợp khi có điều kiện; hoàn thiện recursive injection graph theo dạng A→B→C; thêm chức năng export evidence bundle phục vụ DFIR; và kiểm soát chặt quyền auto-kill, mặc định chỉ cảnh báo trong môi trường lab.

\newpage

# 9. KẾT LUẬN

Luận văn đã xây dựng Noirlycan Telemetry nhằm tăng cường phát hiện mã độc trước các kĩ thuật né tránh trong process injection. Phương pháp không phụ thuộc hoàn toàn vào tên API mà quy lời gọi về ba operational primitive allocate, write và execute; correlator áp dụng quy tắc 2-of-3, quan hệ actor–target, temporal ordering, memory congruence và scoring dựa trên evidence.

Frida được sử dụng để quan sát chi tiết API và tham số ở user mode, còn Sysmon bổ sung process lineage, file, network và các tín hiệu phụ trợ về process access/remote thread. Trong implementation hiện tại, EID 8 và EID 10 chưa được chuyển thành primitive để tự thay Frida tạo finding, nên telemetry kép tăng ngữ cảnh giải thích nhưng chưa giải quyết được vấn đề direct syscall hoặc anti-instrumentation.

Case thực nghiệm hiện tại vẫn chỉ gồm một loader tự viết, nhưng nhiều run trên hai agent cho kết quả lặp lại: loader không bị Defender và Kaspersky chặn trong run quan sát; Noirlycan liên kết actor với `msedge.exe`, tạo finding CRITICAL score 100 và mở network watch cho target PID. Kết quả hỗ trợ H1/H2 và củng cố H3 ở mức case study.

Network collection đã xác định được các nỗ lực kết nối outbound tới `192.168.0.104:80/443`, nhưng toàn bộ record đều SYN_SENT nên chưa chứng minh callback hay beacon thành công. Việc chạy lại nhiều bản sao của cùng loader cũng chưa đủ để đánh giá tổng quát. Hai hướng tiếp theo là kiểm chứng bằng WFP/Sysmon và server ground truth, đồng thời thử nghiệm trên nhiều loader/kĩ thuật độc lập. Đây là các bước cần thiết để chuyển Noirlycan từ proof-of-concept sang nền tảng đánh giá định lượng.

\newpage

# 10. TÀI LIỆU THAM KHẢO

[4] G. Di Pietro, D. C. D'Elia, and L. Querzoni, "Can You Run My Code? A Close Look at Process Injection in Windows Malware," *Proceedings of ASIA CCS 2025*, 2025. DOI: 10.1145/3708821.3736206.

[5] Frida, "Dynamic Instrumentation Toolkit," https://frida.re/docs/.

[7] S. Klein et al., "Process Injection Techniques in Windows Malware," *Proceedings of USENIX Security Symposium*, pp. 401–416, 2017.

[9] MITRE ATT&CK, "T1055 — Process Injection," https://attack.mitre.org/techniques/T1055/.

[10] Microsoft Sysinternals, "Sysmon," https://learn.microsoft.com/sysinternals/downloads/sysmon.

[11] Sap4Sec, "Process Injection Artifact," https://github.com/Sap4Sec/process-injection.

[12] T. Starink et al., "Behavior Graphs for Malware Detection," *IEEE Transactions on Information Forensics and Security*, vol. 18, pp. 2345–2360, 2023.

[13] NoirlycanThesis, mã nguồn và tài liệu của luận văn.

\newpage

# PHỤ LỤC A. LỆNH TÁI LẬP LAB

Trên server, lab được khởi động bằng lệnh:

```bash
python scripts/lab_stack.py up --host 0.0.0.0 --backend-port 8888
```

Trên Windows VM, agent được chạy bằng lệnh:

```powershell
noirlycan-agent run `
  --config noirlycan-agent.toml `
  --watch-sysmon `
  --auto-attach-new-processes
```

Sysmon được kiểm tra bằng hai lệnh sau:

```powershell
Get-Service Sysmon64
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 20
```

# PHỤ LỤC B. CHECKLIST THỰC NGHIỆM NHIỀU LOADER

Quy trình thử nghiệm với nhiều loader nên tuân theo trình tự sau: khôi phục snapshot sạch; ghi lại phiên bản Windows, Frida, Sysmon và AV; kiểm tra heartbeat của agent; kiểm tra các EID 1, 3, 8, 10 và 11; chạy workload sạch để làm baseline; copy một loader vào watched folder; ghi hash và ground truth của loader đó; chạy loader trong giới hạn thời gian đã định; xuất event, finding và network connections; và cuối cùng, reset snapshot trước khi chuyển sang loader tiếp theo.

# PHỤ LỤC C. DANH MỤC HÌNH

Báo cáo sử dụng tám hình minh họa lấy từ dashboard: Hình 1 là Overview (`images/01-overview.png`), Hình 2 là Findings (`images/02-findings.png`), Hình 3 là phần đầu modal chi tiết finding (`images/07-finding-detail.png`), Hình 4 là API chain/network evidence trong modal (`images/08-finding-detail-evidence.png`), Hình 5 là Activity (`images/03-activity.png`), Hình 6 là Network (`images/04-network.png`), Hình 7 là Rules (`images/05-rules-correlation.png`), và Hình 8 là Agents (`images/06-agents.png`).

---

*Bản tóm lược được cập nhật từ log ngày 27/07/2026: một loader chạy lặp lại trên hai agent, finding CRITICAL score 100, target `msedge.exe`, và các nỗ lực kết nối outbound tới `192.168.0.104:80/443` ở trạng thái SYN_SENT.*
