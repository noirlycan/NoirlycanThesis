# Hướng dẫn viết luận văn theo Scientific Methodology & WritingThesis

Tài liệu này ánh xạ hai nguồn hướng dẫn vào cấu trúc luận văn Noirlycan:

- **Hồ Tú Bảo — *Scientific Methodology*** [14]: giả thuyết, well-posed problem, literature review, tính khả thi.
- ***WritingThesis*** [15]: Introduction → Related work → Methods → Experiments → Discussion & Conclusions.

## 1. Ánh xạ cấu trúc

| WritingThesis | Scientific Methodology | File | UET (139/ĐT) |
|---------------|------------------------|------|--------------|
| Introduction | Vấn đề, motivation, well-posed | `chapters/01-mo-dau.md` | **MỞ ĐẦU** (bảng M.x) |
| Related work | Literature survey + gap | `chapters/03-cong-trinh-lien-quan.md` |
| Background (tùy chọn) | Kiến thức nền | `chapters/02-co-so-ly-thuyet.md` |
| Methods | Giả thuyết, phương pháp, feasibility | `chapters/04-threat-model.md`, `05-phuong-phap.md`, `06-thiet-ke-hien-thuc.md` |
| Experiments & Results | Kiểm chứng giả thuyết | `chapters/07-danh-gia.md` |
| Discussion | Validity, limitations | `chapters/08-thao-luan.md` |
| Conclusions | So sánh literature, future work | `ket-luan.md` | Trước DM công trình KH |

Kết hợp với [`HUONG-DAN-HTW.md`](HUONG-DAN-HTW.md) (Nguyễn Việt Hà — **bắt buộc GVHD**) và [`HUONG-DAN-VIET-UET.md`](HUONG-DAN-VIET-UET.md).
| Abstract | Problem + results + contribution (không outline) | `tom-tat-luan-van.md` |

## 2. Checklist theo Scientific Methodology [14]

| Yêu cầu | Vị trí | Trạng thái |
|---------|--------|------------|
| Vấn đề có ý nghĩa khoa học | Mở đầu §1.1 | ✅ |
| Well-posed problem (phạm vi rõ) | Mở đầu §1.4, Chương 3 | ✅ |
| Giả thuyết H1–H5 có tiêu chí kiểm chứng | Mở đầu §1.3.3, Chương 4 §4.2 | ✅ |
| Literature review có map | Chương 2 §2.12 | ✅ |
| Tính khả thi | Mở đầu §1.4.4, Chương 4 §4.2 | ✅ |
| Kiểm chứng / bác bỏ giả thuyết | Chương 6 §6.16 | ✅ (H4, H5 pending VM) |
| Trung thực hạn chế | Chương 6–7, Kết luận §3 | ✅ |

## 3. Checklist theo WritingThesis [15]

| Phần | Nội dung bắt buộc | File |
|------|-------------------|------|
| Introduction | Target audience, motivation, method summary, thesis structure | `01-mo-dau.md` §1.4.4, §1.7 |
| Abstract | Motivation + approach + **results** + contribution | `tom-tat-luan-van.md` |
| Related work | Central paper [4], comparison table, research gap | `03-cong-trinh-lien-quan.md` |
| Methods | Reproducible pipeline, equations, criteria | `05-phuong-phap.md` |
| Experiments | RQ + hypothesis table, metrics | `07-danh-gia.md` |
| Conclusions | Compare to [4], implications, future work | `ket-luan.md` §6–7 |

## 4. Giả thuyết H1–H5 (tóm tắt)

| ID | Nội dung | Chấp nhận khi |
|----|----------|---------------|
| H1 | 2-of-3 chống E1 | Test correlation pass |
| H2 | 2-of-3 chống E2 | Section-mapping score ≥ 70 |
| H3 | Provenance E3 | Finding có `related_file` |
| H4 | Sysmon bổ sung E4 | Benchmark syscall (pending) |
| H5 | Frida fidelity | Drop-rate < 1 % (pending) |

## 5. Việc học viên cần hoàn thiện trước nộp

1. Điền **động cơ cá nhân** tại Mở đầu §1.4.4.
2. Chạy **Frida fidelity** và **PoC-Bench** trên VM Windows; cập nhật Chương 6.
3. Ghép `.docx` theo format UET [2]; điền họ tên, GVHD.
4. Chèn hình từ FigJam / `docs/architecture-diagrams.md`.

## 6. Lệnh build

```bash
./thesis/build-full.sh
```

Tạo `thesis/luan-van-day-du.md` từ các chương riêng lẻ.
