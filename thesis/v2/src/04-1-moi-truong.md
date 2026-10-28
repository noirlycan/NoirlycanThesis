# Chương 4. XÂY DỰNG HỆ THỐNG NOIRLYCAN

Chương này trình bày quá trình hiện thực hệ thống thử nghiệm Noirlycan, được dùng làm nền tảng cho các thực nghiệm của luận văn. Trọng tâm của chương là các quyết định kỹ thuật liên quan đến tổ chức phần mềm, kênh liên lạc giữa máy thử nghiệm và máy quản trị, cơ chế bảo vệ kênh điều khiển và các biện pháp giảm chi phí vận hành. Phần lõi phân tích, vốn được kế thừa từ [7], chỉ được nhắc lại ở mức cần thiết để giải thích cách các thành phần kết nối với nhau.

## 4.1. Phạm vi và môi trường triển khai

### 4.1.1. Phạm vi của hệ thống thử nghiệm

Hệ thống thử nghiệm được xây dựng cho một phòng thí nghiệm cô lập gồm một máy quản trị và một số ít máy ảo Windows 10/11. Với quy mô này, luận văn không đặt mục tiêu xây dựng một nền tảng có khả năng mở rộng tới hàng nghìn điểm cuối, mà ưu tiên ba yêu cầu: kết quả phải tái lập được, dữ liệu thu thập phải đủ để kiểm chứng phương pháp, và kênh điều khiển giữa máy quản trị với máy thử nghiệm không được trở thành một điểm yếu mới. Yêu cầu thứ ba xuất phát từ đặc thù của bài toán: máy chạy agent cũng chính là máy đang thực thi mẫu cần phân tích, nên mọi dữ liệu do agent gửi lên đều phải được coi là dữ liệu không tin cậy.

Cần phân biệt rõ ba nhóm thành phần được đề cập trong chương này. Nhóm thứ nhất là các thành phần đã được hiện thực và kiểm thử trong mã nguồn, bao gồm agent, máy chủ quản trị, giao diện web và kênh điều khiển có ký số. Nhóm thứ hai là các thành phần đã được thiết kế nhưng chưa hiện thực, tiêu biểu là bộ cảm biến dựa trên ETW Threat Intelligence. Nhóm thứ ba là các hướng mở rộng được đề xuất cho giai đoạn sau, như xác thực hai chiều bằng chứng chỉ (mTLS) và nhật ký kiểm toán bất biến. Bảng 4.1 tóm tắt sự phân biệt này để tránh việc trình bày hệ thống như thể đã hoàn chỉnh ở mọi khía cạnh.

Bảng 4.1. Trạng thái hiện thực của các thành phần

| Thành phần | Trạng thái | Ghi chú |
|---|---|---|
| Agent thu thập (Frida, Sysmon, theo dõi thư mục, theo dõi mạng) | Đã hiện thực | Chạy trên máy ảo Windows |
| Bộ phân tích (lõi phương pháp [7] và phần mở rộng) | Đã hiện thực | Dùng chung cho agent và máy chủ |
| Máy chủ quản trị và giao diện web | Đã hiện thực | FastAPI và React |
| Kênh điều khiển có ký số, xác nhận kết quả lệnh | Đã hiện thực | Ed25519 |
| Cài đặt agent bằng một lệnh | Đã hiện thực | PowerShell |
| Cảm biến ETW Threat Intelligence | Đã thiết kế, chưa hiện thực | Cần ký PPL/ELAM |
| mTLS, nhật ký kiểm toán bất biến | Đề xuất mở rộng | Ngoài phạm vi thử nghiệm |

### 4.1.2. Công nghệ sử dụng và vai trò

Việc lựa chọn công nghệ được dẫn dắt bởi yêu cầu tái lập và bởi môi trường thí nghiệm hiện có, hơn là bởi hiệu năng tối đa. Agent và bộ phân tích được viết bằng Python vì hệ sinh thái này cung cấp sẵn thư viện ràng buộc cho Frida và cho giao diện đọc nhật ký sự kiện của Windows (pywin32), đồng thời cho phép chạy toàn bộ bộ kiểm thử của bộ phân tích trên máy không phải Windows. Hạn chế của lựa chọn này là hiệu năng xử lý một luồng thấp hơn các ngôn ngữ biên dịch; ảnh hưởng của hạn chế đó được giảm bớt bằng các biện pháp trình bày ở mục 4.6, và trong phạm vi vài máy ảo, nó không phải là nút thắt quan sát được.

Máy chủ quản trị sử dụng FastAPI do framework này hỗ trợ khai báo kiểu dữ liệu đầu vào và kiểm tra hợp lệ tự động, một yêu cầu quan trọng khi dữ liệu đến từ máy có thể đã bị mẫu thử chiếm quyền. Dữ liệu được lưu trong SQLite và các tệp JSONL theo phiên. Cách lưu trữ dạng tệp đơn này phù hợp với quy mô phòng thí nghiệm và giúp đóng gói kết quả thực nghiệm dễ dàng, nhưng sẽ cần thay bằng một hệ quản trị cơ sở dữ liệu máy chủ nếu số lượng agent tăng đáng kể. Giao diện web dùng React và được biên dịch thành tệp tĩnh. Bảng 4.2 liệt kê các công nghệ chính cùng vai trò của chúng.

Bảng 4.2. Công nghệ chính và vai trò trong hệ thống

| Công nghệ | Vai trò | Lý do lựa chọn trong phạm vi luận văn |
|---|---|---|
| Python 3.11 | Agent, bộ phân tích, máy chủ | Thư viện Frida và pywin32 có sẵn; kiểm thử chạy được trên mọi nền tảng |
| Frida | Cảm biến ở chế độ người dùng | Cho đối số chi tiết của lời gọi API |
| Sysmon | Cảm biến từ callback nhân | Vẫn ghi nhận sự kiện khi hook người dùng bị vượt qua [15] |
| FastAPI | API của máy chủ quản trị | Kiểm tra hợp lệ dữ liệu đầu vào theo kiểu khai báo |
| SQLite, JSONL | Lưu trữ | Tệp đơn, dễ đóng gói và tái lập |
| React | Giao diện quản trị | Biên dịch thành tệp tĩnh, tách khỏi máy chủ |
| cryptography (Ed25519) | Ký và xác minh lệnh | Chữ ký ngắn, xác minh nhanh |
