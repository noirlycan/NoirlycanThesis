# MỞ ĐẦU

## 1.1. Bối cảnh nghiên cứu

Tiêm mã vào tiến trình là một nhóm kỹ thuật cho phép mã do tác nhân kiểm soát được thực thi trong không gian địa chỉ của tiến trình khác. Việc chỉ nhận diện tên tệp thực thi hoặc một chuỗi API cố định vì thế có thể bỏ qua quan hệ giữa tiến trình khởi phát, vùng nhớ được sửa đổi và điểm bắt đầu thực thi. MITRE ATT&CK xếp các biến thể này trong kỹ thuật T1055 [12]. Với hệ thống giám sát động, khó khăn còn nằm ở chỗ cùng một thao tác có thể được thực hiện qua API Win32, Native API hoặc cơ chế ánh xạ section, trong khi một số mẫu chủ động thay đổi hành vi khi phát hiện môi trường phân tích [6], [7].

Di Pietro và cộng sự khảo sát 56.340 mẫu mã độc Windows thu thập cho giai đoạn 2017–2023 và ghi nhận 16,5 % mẫu có hành vi tiêm mã theo phương pháp quan sát của họ [7]. Trong các trường hợp được phương pháp này xác định, hai công cụ phân tích công khai được đối chiếu bỏ sót trung bình 21,2 %. Ở tập mẫu năm 2019, tỷ lệ quan sát được hành vi tiêm mã là 6,2 % với cấu hình dùng Detours và 11,8 % với cấu hình BluePill có biện pháp đối phó né tránh môi trường phân tích [7]. Các tỷ lệ này là kết quả của công trình được trích dẫn, phụ thuộc tập mẫu và cấu hình thực nghiệm của công trình đó; chúng không phải kết quả đo của luận văn.

Phương pháp của [7] chuyển trọng tâm từ tên API sang ba thao tác cơ bản: chuẩn bị vùng nhớ, đưa mã vào vùng nhớ và chuyển luồng thực thi tới mã đó. Các lời gọi có cùng vai trò được ánh xạ về một thao tác, sau đó chuỗi quan sát được kiểm tra về số loại thao tác, quan hệ vùng nhớ và thứ tự thời gian. Cách biểu diễn này tạo cơ sở để phát hiện một số biến thể vốn không thỏa quy tắc yêu cầu đúng ba tên API cụ thể. Tuy nhiên, khả năng phát hiện còn phụ thuộc vào độ đầy đủ của nguồn sự kiện. Khi cơ chế giám sát ở chế độ người dùng bị vượt qua, việc có quy tắc tương quan phù hợp vẫn chưa đủ để đưa ra kết luận đáng tin cậy.

Luận văn nghiên cứu khả năng áp dụng và giới hạn của phương pháp trên một hệ thống thử nghiệm dành cho máy Windows. Hệ thống Noirlycan kết hợp sự kiện API do Frida thu thập với sự kiện hệ điều hành từ Sysmon, bổ sung quan hệ giữa tệp được tạo, tiến trình khởi chạy và cảnh báo tiêm mã. Phần cốt lõi của nghiên cứu là thiết kế phép tương quan và xác định loại bằng chứng cần thiết cho từng kết luận. Việc xây dựng giao diện và kênh quản lý Agent phục vụ thu thập, truy vết và kiểm tra kết quả trong phòng thí nghiệm; luận văn không dùng sự tồn tại của các thành phần này làm bằng chứng về hiệu quả phát hiện.

Mức đánh giá hiện có tập trung vào kiểm thử quy tắc với dữ liệu tổng hợp và một số kịch bản minh họa. Luận văn trình bày riêng kết quả kiểm thử này, các quan sát trên máy ảo và những phép đo còn thiếu. Do chưa có tập thực nghiệm đủ để tính độ chính xác và độ bao phủ đối với mã độc ngoài thực tế, các kết luận về hiệu quả được giới hạn ở phạm vi đã kiểm chứng.

## 1.2. Nội dung nghiên cứu trong luận văn

### 1.2.1. Phân loại hình thức né tránh trong phạm vi đề tài

Luận văn sử dụng sáu nhóm E1–E6 để phân định cơ chế né tránh, nguồn quan sát và phạm vi đánh giá (Bảng M.1). Đây là cách phân nhóm phục vụ thiết kế thực nghiệm của luận văn, không phải một phân loại có tính bao quát cho mọi hành vi mã độc.

**Bảng M.1.** Hình thức né tránh và cơ chế đối phó của luận văn

| Nhóm | Tên | Mô tả | Cơ chế tăng cường phát hiện | Phạm vi |
|------|-----|-------|----------------------------|---------|
| E1 | Biến thể API | `CreateRemoteThread` → `NtCreateThreadEx`; `VirtualAllocEx` → `NtAllocateVirtualMemory` | Lớp tương đương API + quy tắc 2-of-3 [7] | Trong phạm vi |
| E2 | Gộp/ẩn bước | Section mapping gộp allocate+write; Mockingjay khai thác RWX có sẵn | Quy tắc 2-of-3 (≥2 primitive); classifier section-mapping | Trong phạm vi |
| E3 | Né attribution | Inject vào tiến trình hợp pháp; file-drop loader che nguồn | Sysmon lineage (E1) + file provenance (E11) + static triage | Trong phạm vi (extension) |
| E4 | Né hook user-mode | Direct syscall stub, unhooking `ntdll`, patch ETW/AMSI | Sysmon kernel callback (E8, E10) fallback khi Frida miss | Trong phạm vi (một phần) |
| E5 | Né sandbox/VM | Timing check, env fingerprint, CPUID — malware *không chạy* injection | Paper [7] có anti-evasion (BluePill); ablation 6,2 % → 11,8 % | **Ngoài phạm vi hiện thực** |
| E6 | Né instrumentation | Anti-Frida, anti-debug, phát hiện agent rồi abort | `spawn` mode; khai báo limitation; ưu tiên Sysmon fallback | Hạn chế |

**E5**: rule 2-of-3 chỉ bắt khi malware *thực sự* phát primitive; nếu từ chối thực thi thì rule không có gì để đánh giá. Luận văn **không hiện thực** anti-evasion; Noirlycan chỉ *ghi nhận* tín hiệu (`extensions/evasion.py`). Hệ quả: prevalence/recall **không** so sánh trực tiếp với các số liệu 16,5 %/21,2 % của paper.

**E4** chỉ được khảo sát một phần. Khi lời gọi bỏ qua điểm hook của Frida, các sự kiện Sysmon như CreateRemoteThread (Event 8) và ProcessAccess (Event 10) có thể cung cấp bằng chứng bổ sung nếu thao tác tương ứng xảy ra và cấu hình Sysmon ghi nhận được [11]. Những sự kiện này không chứa đầy đủ đối số vùng nhớ của lời gọi API; do đó, sự hiện diện của chúng không tự chứng minh rằng quy tắc tương quan vẫn hoạt động với mọi biến thể direct syscall.

**Bảng M.2.** Mối quan hệ giữa nhóm né tránh và kỹ thuật injection điển hình

| Kỹ thuật injection | E1 | E2 | E3 | E4 | E5 | E6 |
|--------------------|----|----|----|----|----|-----|
| Classic Remote Thread | ✓ | | ✓ | ✓ | | |
| Section-mapping / Hollowing | ✓ | ✓ | ✓ | ✓ | | |
| APC / Early Bird | | ✓ | ✓ | ✓ | | |
| Reflective DLL | ✓ | | ✓ | ✓ | | ✓ |
| Process Ghosting/Herpaderping | ✓ | ✓ | ✓ | ✓ | | |
| PoolParty / Mockingjay | | ✓ | ✓ | ✓ | | |

Một kỹ thuật có thể đồng thời làm thay đổi chuỗi API và che nguồn gốc tiến trình. Do đó, kết quả của từng cơ chế phát hiện cần được đánh giá trên đúng lớp bằng chứng mà cơ chế đó sử dụng.

## 1.3. Mục tiêu nghiên cứu

### 1.3.1. Mục tiêu tổng quát

Tăng cường phát hiện mã độc Windows dùng process injection và né tránh E1–E4 trong lab Windows 10/11, căn cứ operational primitive và 2-of-3 [7], qua hiện thực và mở rộng có kiểm chứng trên Noirlycan.

### 1.3.2. Mục tiêu cụ thể

**RO1 — Hiện thực hóa lõi phương pháp [7].** Xây bộ quy tắc gồm: ba operational primitive; lớp tương đương API theo `PAPER_API_CLASSES` [14]; 2-of-3 trên cùng `(actor_pid, target_pid)`; memory range congruence; temporal ordering. Tiêu chí: unit test khớp case section-mapping (Neurevt) trong [7] §3.5.

**RO2 — Telemetry kép chống E4.** Pipeline **Sysmon ∪ Frida**: Frida cung cấp đối số API cho congruence; Sysmon kernel (Event 1, 7, 8, 10, 11) fallback khi user-mode hook bị bypass.

**RO3 — Pipeline provenance chống E3.** Mở rộng [7]: Sysmon Event 11 (FileCreate) → static triage (SHA256, PE header, entropy, Authenticode) → ProcessCreate lineage → Finding, giúp truy ngược về file nguồn.

**RO4 — Đánh giá trên các biến thể tiêm mã.** Kiểm tra quy tắc bằng chuỗi sự kiện tổng hợp có nhãn kỳ vọng và đối chiếu với một baseline chỉ nhận diện chuỗi API cố định. Thực nghiệm trên loader và tập mẫu độc lập được thiết kế để bổ sung phép đo precision, recall và F1 khi có đủ dữ liệu; các chỉ số này không được suy ra từ kiểm thử đơn vị.

**RO5 — Threat model và ranh giới claim.** Formal hóa đối thủ (C1–C7), out-of-scope (O1–O7), giả định (M1–M6), ma trận E1–E6 ↔ mitigation.

### 1.3.3. Giả thuyết nghiên cứu

Luận văn định vị là **nghiên cứu ứng dụng** — giả thuyết nhắm **kiểm chứng phạm vi mở rộng** và **giới hạn ứng dụng** của [7] [2], [4].

**Bảng M.3.** Giả thuyết nghiên cứu và cách kiểm chứng

| ID | Giả thuyết | Kiểm chứng | Kết quả sơ bộ |
|----|------------|------------|---------------|
| **H1** | Ánh xạ API và tương quan thao tác vẫn nhận diện được chuỗi khi thay API (E1) | Kiểm thử quy tắc với biến thể API | Được hỗ trợ trên tập kiểm thử tổng hợp |
| **H2** | Quy tắc hai trong ba thao tác nhận diện được chuỗi gộp bước (E2) | Kịch bản section-mapping có nhãn | Được hỗ trợ trên kịch bản kiểm thử |
| **H3** | Liên kết tệp, tiến trình và cảnh báo hỗ trợ truy nguồn (E3) | Kiểm thử liên kết và quan sát giao diện | Được hỗ trợ một phần; chưa đo trên tập độc lập |
| **H4** | Sysmon ∪ Frida giảm FN khi Frida bị né (E4) | Thiết kế E8/E10; benchmark syscall | **Chưa đủ số liệu** |
| **H5** | Tỷ lệ sự kiện Frida thu được đủ cho phép tương quan trong cấu hình thử nghiệm | Quy trình đo fidelity trên máy ảo | Chưa có số liệu để kiểm chứng |

**Loại trừ:** anti-evasion E5 — out-of-scope hiện thực; chỉ trích dẫn kết quả ablation 6,2 %/11,8 % của [7] làm động lực.

## 1.4. Đối tượng và phạm vi nghiên cứu

### 1.4.1. Đối tượng nghiên cứu

- **Mã độc/loader Windows user-mode** dùng process injection kèm né tránh E1–E4.
- **Phương pháp phát hiện** operational primitive, equivalence class, 2-of-3, memory congruence, temporal ordering [7].
- **Hệ thống Noirlycan Telemetry** [13]: collector, Frida hooks, Sysmon poller, correlator, classifier, dashboard.

### 1.4.2. Phạm vi trong luận văn

| Khía cạnh | Trong phạm vi |
|-----------|---------------|
| Hệ điều hành | Windows 10/11 (64-bit), lab VM cô lập |
| Chế độ malware | User-mode; cross-process và self-inject |
| Né tránh | E1, E2, E3 (extension), E4 (fallback Sysmon) |
| Telemetry | Sysmon (config `sysmon-noirlycan.xml`), Frida 16.x, static triage |
| Kỹ thuật injection | Các biến thể được mô hình hóa trong bộ phân loại và kiểm thử; số loại trong mã nguồn không đồng nghĩa số loại đã đánh giá trên mẫu thực |
| Đánh giá | Kiểm thử quy tắc và kịch bản tổng hợp; các bộ PoC-Bench, Paper-Subset, Benign-Baseline và phép đo Frida fidelity thuộc kế hoạch thực nghiệm bổ sung |

### 1.4.3. Phạm vi ngoài luận văn

| Khía cạnh | Ngoài phạm vi | Lý do |
|-----------|---------------|-------|
| E5 — Anti-sandbox/VM | Không hiện thực bypass | Paper [7] có module riêng; vượt phạm vi |
| E6 — Anti-Frida chủ động | Chỉ limitation + spawn | Không ship countermeasure |
| Injection kernel-mode | Không | Sysmon/Frida user-mode không đủ |
| Prevalence 56.340 mẫu | Không tái lập quy mô | Tập trung replication + extension lab |
| EDR thương mại | Không so sánh trực tiếp | Đóng source |
| Windows Server / ARM | Không | Chưa validate ngoài desktop lab |

Luận văn **không** tuyên bố Noirlycan thay thế sandbox [7] hay EDR production.

### 1.4.4. Đối tượng độc giả và động cơ

Đối tượng sử dụng kết quả nghiên cứu là người phân tích mã độc và nhóm phát triển công cụ giám sát trong môi trường thử nghiệm. Bài toán đặt ra từ khoảng cách giữa phương pháp phân tích trên tập mã độc lớn của [7] và nhu cầu quan sát, giải thích từng chuỗi sự kiện trên máy Windows. Các hạn chế của Frida và mức quan sát của Sysmon được xem là biến số của đánh giá, không được mặc định là đã được khắc phục chỉ vì hệ thống kết hợp hai nguồn sự kiện.

## 1.5. Phương pháp nghiên cứu

Phương pháp nghiên cứu bắt đầu từ việc đối chiếu các mô hình tiêm mã, phương pháp phát hiện dựa trên thao tác và nghiên cứu về né tránh phân tích động [6], [7], [10], [15]. Trên cơ sở đó, luận văn xác định năng lực giả định của đối thủ, giới hạn quan sát của từng cảm biến và điều kiện để một chuỗi sự kiện được xem là bằng chứng. Đặc tả này được chuyển thành các hàm chuẩn hóa, tương quan và phân loại trong Noirlycan, rồi kiểm tra bằng những trường hợp dương tính và âm tính có kỳ vọng xác định trước.

Đánh giá được tách thành hai mức. Kiểm thử đơn vị kiểm tra tính nhất quán của hiện thực với đặc tả quy tắc; đối chiếu với baseline API cố định cho biết sự khác biệt trên chính các chuỗi kiểm thử. Đánh giá độ chính xác đối với mã độc thực, độ trung thực của Frida và hiệu quả khi có direct syscall đòi hỏi bộ mẫu cùng dữ liệu gốc độc lập. Khi chưa hoàn tất các phép đo đó, luận văn chỉ nêu quy trình, tiêu chí và bảng ghi kết quả cần thu thập.

**Bảng M.4.** Ánh xạ phương pháp nghiên cứu với câu hỏi đánh giá (Chương 4)

| Phương pháp | Câu hỏi / Giả thuyết phục vụ |
|-------------|------------------------------|
| Audit code-vs-paper | RQ1 / H1, H2 |
| PoC-Bench + Paper-Subset | RQ2 |
| Provenance pipeline | RQ3 / H3 |
| Frida fidelity | RQ5 / H5 |
| Telemetry kép | RQ2 / H4 |

## 1.6. Những đóng góp của luận văn

Đóng góp về phương pháp của luận văn là hiện thực và kiểm tra phép ánh xạ API cùng phép tương quan hai trong ba thao tác theo [7] trong một luồng sự kiện trên máy thử nghiệm. Các trường hợp kiểm thử cho thấy hiện thực xử lý được một số biến thể API và kịch bản section-mapping đã đặc tả. Đây là bằng chứng về hành vi của chương trình trên tập kiểm thử, chưa phải phép đo độ bao phủ mã độc ngoài thực tế.

Đóng góp về hệ thống là tích hợp dữ liệu Frida và Sysmon vào cùng mô hình sự kiện, sau đó liên kết cảnh báo với tệp và tiến trình liên quan. Cách tổ chức này hỗ trợ kiểm tra nguồn gốc bằng chứng và phát lại phiên phân tích. Threat model đi kèm xác định những trường hợp mất quan sát, đặc biệt khi mẫu không thực thi hành vi do phát hiện máy ảo hoặc khi hook ở chế độ người dùng bị vượt qua. Các cơ chế đối phó trong những trường hợp này là hướng nghiên cứu và thực nghiệm tiếp theo, chưa được xem là kết quả đã chứng minh.

**Bảng M.5.** So sánh đóng góp luận văn với paper [7]

| Khía cạnh | Paper [7] | Luận văn (Noirlycan) |
|-----------|-----------|----------------------|
| Quy mô dữ liệu đánh giá | 56.340 mẫu, 2017–2023 | Kiểm thử tổng hợp và kịch bản minh họa; tập mẫu độc lập chưa hoàn tất |
| Môi trường | Batch DBI (BluePill/Pin) | Windows 10/11 lab VM |
| Anti-evasion E5 | Có module tích hợp | **Out-of-scope** |
| File provenance | Không | Extension E3 |
| Telemetry | Trace nội bộ sandbox | Frida + Sysmon + dashboard |
| Phân loại kỹ thuật | 12 kỹ thuật chính | 36 enum + rule catalog |
| Hiện vật nghiên cứu | Sap4Sec/process-injection | Mã nguồn Noirlycan trong kho dự án của luận văn |

Sự khác biệt về môi trường, cảm biến và quy mô mẫu khiến các tỷ lệ thực nghiệm trong [7] không thể chuyển trực tiếp sang Noirlycan. Bảng M.5 chỉ đối chiếu mục tiêu và thành phần được khảo sát.

## 1.7. Bố cục luận văn

Sau phần mở đầu, luận văn trình bày cơ sở lý thuyết, phương pháp nghiên cứu, thiết kế và hiện thực Noirlycan, thực nghiệm, thảo luận kết quả, rồi kết luận. Trình tự này đi từ điều kiện phát hiện tới cơ chế tạo bằng chứng và mức độ mà thực nghiệm hiện có hỗ trợ từng nhận định.

- **Mở đầu** — bối cảnh, E1–E6, RO1–RO5, H1–H5, phạm vi, đóng góp.
- **Chương 1 — Cơ sở lý thuyết** — Windows, injection, primitive, Sysmon, Frida.
- **Chương 2 — Phương pháp** — bài toán, threat model, pipeline 2-of-3 [7], provenance, telemetry kép.
- **Chương 3 — Thiết kế và hiện thực** — Clean Architecture, module Noirlycan, Frida hooks, correlator, dashboard.
- **Chương 4 — Thực nghiệm và so sánh** — môi trường, dữ liệu, kết quả (59 test methodology), case section-mapping, so sánh [7], thảo luận.
- **Kết luận** — xuất xứ, phương pháp, kết quả, hạn chế, hướng tiếp theo [3].

Tài liệu tham khảo được đánh số theo thứ tự trong danh mục và dẫn bằng ngoặc vuông, phù hợp hướng dẫn trình bày của UET [1].
