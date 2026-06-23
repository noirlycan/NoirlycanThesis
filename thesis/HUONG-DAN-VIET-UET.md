# Hướng dẫn trình bày theo UET (Công văn 139/ĐT)

Nguồn: [Yêu cầu trình bày LVTHS — UET](https://uet.vnu.edu.vn/wp-content/uploads/2017/09/Yêu-cầu-trình-bày-LVTHS.pdf) (12/04/2012).

Kết hợp với [`HUONG-DAN-VIET-METHOD.md`](HUONG-DAN-VIET-METHOD.md) (Scientific Methodology + WritingThesis).

## 1. Bố cục bắt buộc (Hình 1 trong Công văn)

| Thứ tự | Phần | File trong repo |
|--------|------|-----------------|
| 1 | Trang bìa (Phụ lục 1, chữ nhũ) | `00-bia-chinh.md` |
| 2 | Trang phụ bìa (Phụ lục 2) | `00-front-matter.md` |
| 3 | Lời cam đoan | `00-front-matter.md` |
| 4 | Mục lục | `01-muc-luc.md` → Word TOC |
| 5 | Danh mục ký hiệu, viết tắt | `02-danh-muc-viet-tat.md` |
| 6 | Danh mục các bảng | `danh-muc-bang.md` |
| 7 | Danh mục các hình | `danh-muc-hinh.md` |
| 8 | **MỞ ĐẦU** | `chapters/01-mo-dau.md` |
| 9 | Chương 1–7 | `chapters/02` … `08` |
| 10 | **KẾT LUẬN** | `ket-luan.md` |
| 11 | Danh mục công trình KH của tác giả | `danh-muc-cong-trinh.md` |
| 12 | Tài liệu tham khảo | `tai-lieu-tham-khao.md` |
| 13 | Phụ lục | `phu-luc.md` |

**Tách riêng khi nộp:** `tom-tat-bia.md` + `tom-tat-luan-van.md` (A5), `thong-tin-luan-van.md` (Phụ lục 4).

## 2. Định dạng Word (§1.1)

| Thông số | Giá trị |
|----------|---------|
| Font | Times New Roman Unicode |
| Cỡ chữ | 13 hoặc 14 |
| Giãn dòng | 1.2 lines |
| Lề | Trên 2cm, dưới 2cm, trái 3cm, phải 2cm |
| Khổ giấy | A4, in một mặt |
| Số trang | Liên tục 1→hết, **chỉ chữ số**, căn giữa **phía trên** đầu trang |
| Khối lượng | ~70 trang (không quá 120) |

**Tóm tắt:** A5, Times 11, tối đa 24 trang hai mặt; **ghi toàn văn kết luận** trong tóm tắt.

## 3. Tiểu mục (§1.2)

- Tối đa 4 cấp: `3.1.2.3`
- Mỗi nhóm phải có **ít nhất 2** tiểu mục cùng cấp (không có `3.1.1` đơn lẻ nếu không có `3.1.2`)

## 4. Bảng, hình, phương trình (§1.3)

| Loại | Quy tắc | Ví dụ trong luận văn |
|------|---------|----------------------|
| Bảng | Đầu đề **phía trên**; số = chương | Bảng 2.4, Bảng M.3 (Mở đầu) |
| Hình | Đầu đề **phía dưới** | Hình 4.1 |
| Trích dẫn trong văn | Nêu rõ số | “(xem Bảng 3.8)” — không viết “bảng dưới đây” |
| Phương trình | Số trong ngoặc đơn, lề phải | (6.1), (6.2) |

## 5. Trích dẫn (§1.5)

- Trong văn: `[n]` hoặc `[n, tr.200-201]` hoặc `[2-5]`
- Danh mục: tách **Tiếng Việt** / **Tiếng Anh**, xếp ABC theo tác giả
- Bài báo: tên trong ngoặc kép; tạp chí *in nghiêng*

## 6. Ghép và xuất Word

```bash
cd thesis
./build-full.sh
pandoc luan-van-day-du.md -o luan-van-day-du.docx \
  --reference-doc=uet-reference.docx   # tạo mẫu Word với lề/font UET một lần
```

Trong Word sau khi import:

1. Áp Heading 1 cho `CHƯƠNG n`, `MỞ ĐẦU`, `KẾT LUẬN`
2. Tham chiếu → Mục lục tự động
3. Cập nhật cột Trang trong `danh-muc-bang.md` / `danh-muc-hinh.md`
4. Chèn hình 1.1, 4.1, 5.1 từ FigJam / SVG
5. Kiểm tra không trùng số bảng giữa Mở đầu (M.x) và Chương 1 (1.x)

## 7. Checklist trước bảo vệ

- [ ] Bìa chữ nhũ + phụ bìa đủ Ngành, Mã số, GVHD
- [ ] Lời cam đoan có ngày, chữ ký
- [ ] Mục lục, danh mục bảng/hình có số trang
- [ ] Tóm tắt A5 có **toàn văn kết luận**
- [ ] Thông tin luận văn (Phụ lục 4) GVHD ký
- [ ] Danh mục công trình KH (hoặc ghi “Chưa có”)
- [ ] Phụ lục không dày hơn phần chính
- [ ] Chạy benchmark VM (H4, H5) nếu còn thời gian
