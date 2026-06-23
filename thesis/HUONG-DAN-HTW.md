# Hướng dẫn HTW — Nguyễn Việt Hà (bắt buộc theo GVHD)

Nguồn: `htwthesis.pdf` — *Một số gợi ý về trình bày luận văn, khóa luận*, Nguyễn Việt Hà, Khoa CNTT, Trường Đại học Công nghệ (2012).

Kết hợp với [`HUONG-DAN-VIET-UET.md`](HUONG-DAN-VIET-UET.md) (định dạng nộp) và [`HUONG-DAN-VIET-METHOD.md`](HUONG-DAN-VIET-METHOD.md) (giả thuyết, WritingThesis).

## 1. Cấu trúc IMRAD (5 phần nội dung)

| HTW | File luận văn | Ghi chú |
|-----|---------------|---------|
| **Đặt vấn đề** | `chapters/01-mo-dau.md` | 3 phần: bối cảnh → nội dung NC → bố cục |
| **Cơ sở lý thuyết** | `chapters/02-co-so-ly-thuyet.md` | Chương 1; ngắn (~≤10 trang Word) |
| **Phương pháp** | `chapters/_assembled/03-phuong-phap-htw.md` | Chương 2; gộp threat model + pipeline [4] |
| **Thiết kế & cài đặt** | `chapters/_assembled/04-thiet-ke-htw.md` | Chương 3; định hướng ứng dụng CN |
| **Thực nghiệm & so sánh** | `chapters/_assembled/05-thuc-nghiem-htw.md` | Chương 4; related work **sau** hiện thực |
| **Kết luận** | `ket-luan.md` | Luận ra ý nghĩa, không chỉ tóm tắt việc đã làm |

**Ghép tự động:** `python3 assemble-htw.py` rồi `./build-full.sh`.

## 2. Checklist HTW bắt buộc

### Mở đầu
- [x] Bối cảnh có trích dẫn [4], [6]–[9]
- [x] Mục tiêu, giả thuyết, phạm vi trong “nội dung NC”
- [x] Bố cục 4 chương + IMRAD
- [x] Điền động cơ cá nhân (§1.4.4)

### Cơ sở lý thuyết (Ch 1)
- [x] Kiến thức dùng lại ở chương sau
- [ ] Rút gọn nếu vượt ~10 trang Word (HTW khuyến nghị)

### Phương pháp (Ch 2)
- [x] Định nghĩa bài toán + threat model
- [x] Cách giải: 2-of-3, provenance, telemetry kép
- [x] Phân biệt kế thừa [4] vs đóng góp mới (khởi–thừa–chuyển–kết)
- [x] Ví dụ section-mapping
- [x] Phân tích hạn chế phương pháp (E5 out-of-scope)

### Thiết kế & hiện thực (Ch 3)
- [x] Ngôn ngữ, công cụ, kiến trúc
- [x] Mô tả tái tạo được (reproducible)

### Thực nghiệm (Ch 4)
- [x] Công cụ, môi trường, dữ liệu
- [x] Tổ chức thí nghiệm (pytest, case study)
- [x] Kết quả + ví dụ (section-mapping)
- [x] So sánh với [4] và related work (đầu chương 4)
- [x] Thảo luận / Discussion (cuối chương 4)
- [ ] Benchmark VM: Frida fidelity, PoC-Bench (H4, H5)

### Kết luận
- [x] Xuất xứ bài toán → phương pháp → kết quả → ý nghĩa → hạn chế → hướng tiếp

## 3. Nguyên tắc viết (HTW)

| Nguyên tắc | Áp dụng |
|------------|---------|
| Nói có sách, mách có chứng | Trích dẫn dày ở Mở đầu & Cơ sở LT |
| Informative headings | Tiêu đề chương mô tả nội dung cụ thể |
| One sentence — one meaning | Rút câu dài khi chỉnh Word |
| Không lạm dụng gạch đầu dòng | Mở đầu viết đoạn văn dẫn |
| Hình vẽ lại, không copy ảnh | FigJam / SVG, trích dẫn nguồn |
| Đánh giá định lượng | Metric precision/recall khi có PoC-Bench |
| Tái tạo được | Phụ lục C, config Sysmon |

## 4. Khởi — Thừa — Chuyển — Kết

| Giai đoạn | Trong luận văn |
|-----------|----------------|
| **Khởi** | Mở đầu: injection, né tránh, động lực [4] |
| **Thừa** | Ch 2 § kế thừa [4]; Ch 4 § related work |
| **Chuyển** | Extension E3, E4; artifact Noirlycan |
| **Kết** | Kết luận: tăng cường E1–E4; E5 hướng mở |

## 5. File nguồn (chỉnh sửa modular)

Các file `chapters/03`–`08` vẫn giữ để sửa từng phần; `assemble-htw.py` ghép khi build:

| Nguồn | Vào chương HTW |
|-------|----------------|
| `04-threat-model.md` + `05-phuong-phap.md` | Chương 2 |
| `06-thiet-ke-hien-thuc.md` | Chương 3 |
| `03-cong-trinh-lien-quan.md` + `07-danh-gia.md` + `08-thao-luan.md` | Chương 4 |

---

*Tài liệu tham khảo [16] trong `tai-lieu-tham-khao.md`.*
