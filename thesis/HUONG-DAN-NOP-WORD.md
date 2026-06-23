# Hướng dẫn hoàn thiện file Word sau khi xuất

File chính: **`luan-van-final.docx`** (~36.000 từ → khoảng **75–95 trang** A4 với Times 13pt, giãn 1.2 — đáp ứng yêu cầu UET ~70 trang và HTW đầy đủ nội dung).

## Bộ file nộp

| File | Mục đích |
|------|----------|
| `luan-van-final.docx` | Luận văn đầy đủ |
| `tom-tat-final.docx` | Tóm tắt (in khổ A5, Times 11) |
| `thong-tin-luan-van.docx` | Phụ lục 4 UET |

Tái tạo:

```bash
cd thesis
./export-word.sh
```

## Mở Word — làm ngay (5–10 phút)

1. **Mục lục:** Chuột phải MỤC LỤC → *Cập nhật toàn bộ mục lục*
2. **Số trang:** Chèn → Số trang → căn giữa phía trên đầu trang (UET)
3. **Điền:** Tên GVHD, mã số chuyên ngành trên phụ bìa
4. **Danh mục bảng/hình:** Cập nhật cột Trang trong `danh-muc-bang.md` / `danh-muc-hinh.md` (hoặc dùng *Tham chiếu → Hình ảnh/Bảng* trong Word)
5. **Chèn hình** (có đoạn văn thuyết minh phía trước — HTW):
   - Hình 1.1 — trust boundary (`docs/design/architecture-comparison-template.svg`)
   - Hình 3.1 — kiến trúc Noirlycan (FigJam / `docs/architecture-diagrams.md`)
   - Hình 2.1 / 4.x — pipeline so sánh paper vs Noirlycan
6. **Lưu** → *Cập nhật trường* (F9) để Word ghi đúng số trang

## Định dạng UET (kiểm tra)

- Font: Times New Roman 13
- Giãn dòng: 1.2
- Lề: trên/dưới 2 cm, trái 3 cm, phải 2 cm
- Bảng: đầu đề **trên** bảng; Hình: đầu đề **dưới** hình
- Trích dẫn: `[n]` trong ngoặc vuông

## Nếu vượt 120 trang (giới hạn UET)

Rút gọn trong Word (ưu tiên):

- Chương 1 — gộp bớt mục taxonomy trùng Mở đầu
- Phụ lục A — rút gọn bảng API (giữ tham chiếu file manifest)

## Chưa có trong Word (cần VM Windows)

- Bảng kết quả Frida fidelity (Phụ lục E)
- Số liệu PoC-Bench định lượng — điền sau khi chạy lab
