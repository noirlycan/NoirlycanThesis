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
