## 4.2. Kiến trúc tổng thể

### 4.2.1. Ba đơn vị triển khai

Hệ thống được tổ chức thành ba đơn vị triển khai độc lập, như minh họa trong Hình 4.1. Agent chạy trên từng máy ảo Windows và chịu trách nhiệm thu thập dữ liệu từ các cảm biến, chuyển dữ liệu qua bộ phân tích cục bộ và gửi kết quả về máy chủ. Máy chủ quản trị chạy trên máy của người phân tích, tiếp nhận dữ liệu từ các agent, lưu trữ, cung cấp API cho giao diện và phát lệnh xuống agent. Giao diện web là ứng dụng tĩnh, chỉ giao tiếp với máy chủ qua API.

![Hình 4.1. Ba đơn vị triển khai của hệ thống Noirlycan](figures/fig-4-1-deployment.png)

Bộ phân tích được đặt trong một gói mã nguồn dùng chung, không phụ thuộc vào Frida, vào giao diện nhật ký sự kiện của Windows hay vào framework web. Agent sử dụng gói này để phát hiện theo thời gian thực ngay trên máy ảo, còn máy chủ sử dụng chính gói đó để phân tích lại các phiên đã ghi khi quy tắc thay đổi. Việc dùng chung một bộ phân tích cho cả hai phía bảo đảm rằng kết quả phân tích lại ngoại tuyến nhất quán với kết quả quan sát được khi chạy thực tế, đây là điều kiện cần cho các phép so sánh trước và sau khi sửa quy tắc ở Chương 5.

Một câu hỏi thiết kế đặt ra là có nên tách máy chủ thành nhiều dịch vụ độc lập theo kiến trúc microservices hay không. Kiến trúc này có lợi thế khi các chức năng cần mở rộng độc lập hoặc được phát triển bởi nhiều nhóm khác nhau, nhưng đồng thời làm tăng độ phức tạp triển khai, giám sát và xử lý lỗi giữa các dịch vụ. Với quy mô vài máy ảo và một người vận hành, các lợi thế đó không phát huy, trong khi chi phí vận hành là có thật. Luận văn vì vậy tổ chức máy chủ dưới dạng một ứng dụng nguyên khối có phân chia module rõ ràng, trong đó phần tiếp nhận dữ liệu từ agent được cô lập thành một module riêng để có thể tách thành dịch vụ độc lập khi cần.

### 4.2.2. Tổ chức mã nguồn

Mã nguồn được chia thành bốn gói, mỗi gói tương ứng với một vai trò trong Hình 4.1. Cách chia này phản ánh trực tiếp hai module mà [7] mô tả: module giám sát thu thập dấu vết lời gọi API, và module phân tích diễn giải các dấu vết đó. Bảng 4.3 trình bày vai trò của từng gói.

Bảng 4.3. Tổ chức mã nguồn của hệ thống

| Gói | Vai trò | Thành phần chính |
|---|---|---|
| noirlycan_agent | Module giám sát, chạy trên máy ảo | sensors (Frida, Sysmon, theo dõi thư mục và mạng), runtime (vòng lặp thu thập, kênh liên lạc, xử lý lệnh) |
| noirlycan_core | Module phân tích, không phụ thuộc hệ điều hành | detection (quy tắc của [7]), classification, trace (chuyển đổi dữ liệu cảm biến), storage |
| noirlycan_backend | Máy chủ quản trị | API, xác thực và phân quyền, tiếp nhận dữ liệu agent, ký lệnh |
| noirlycan_dashboard | Phục vụ giao diện | Máy chủ tệp tĩnh cho giao diện React |

Nguyên tắc phụ thuộc giữa các gói được giữ một chiều: agent và máy chủ có thể phụ thuộc vào gói phân tích, nhưng gói phân tích không phụ thuộc ngược lại vào bất kỳ gói nào. Trong quá trình tái cấu trúc, một số phụ thuộc ngược tồn tại trong phiên bản trước đã được loại bỏ, và các hàm chuyển đổi dữ liệu từ cảm biến sang mô hình phân tích được đưa vào gói phân tích. Nhờ đó, việc phân tích lại một phiên đã ghi không đòi hỏi cài đặt Frida.
