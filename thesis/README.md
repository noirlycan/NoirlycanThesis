# Luận văn thạc sĩ — Tăng cường phát hiện mã độc dưới các hình thức né tránh

**Tên đề tài (chính thức):** Tăng cường phát hiện mã độc dưới các hình thức né tránh

## Kiến trúc

Tài liệu chi tiết: [`docs/clean-architecture-plan.md`](../docs/clean-architecture-plan.md), [`docs/architecture-diagrams.md`](../docs/architecture-diagrams.md).

Sau refactor, codebase dùng **Clean Architecture** (`kernel/` + `services/`) và hỗ trợ **monolith** hoặc **microservices** (`docker-compose.yml`). Lõi correlator 2-of-3 [4] nằm tại `services/analysis/domain/correlation.py`.

**Format:** [Yêu cầu trình bày LVTHS — UET](https://uet.vnu.edu.vn/wp-content/uploads/2017/09/Yêu-cầu-trình-bày-LVTHS.pdf)

## Trục luận văn

Luận văn xoay quanh **sáu nhóm né tránh** (E1–E6) trong phạm vi process injection Windows:

| Nhóm | Né tránh | Giải pháp trong luận văn |
|------|----------|--------------------------|
| E1 | Biến thể API | Equivalence class + 2-of-3 [4] |
| E2 | Gộp/ẩn bước | Quy tắc 2-of-3 [4] |
| E3 | Che attribution | File provenance + Sysmon lineage |
| E4 | Direct syscall / unhook | Sysmon kernel fallback |
| E5 | Sandbox/VM detection | **Out-of-scope** (paper [4] có anti-evasion) |
| E6 | Anti-Frida | `spawn` mode; limitation |

## Cấu trúc file

| File | Nội dung |
|------|----------|
| `00-front-matter.md` | Bìa, cam đoan, viết tắt |
| `chapters/01-mo-dau.md` | Mở đầu — đề tài né tránh |
| `chapters/02-co-so-ly-thuyet.md` | Chương 1 |
| `chapters/03-cong-trinh-lien-quan.md` | Chương 2 — [4] trung tâm |
| `chapters/04-threat-model.md` | Chương 3 — E1–E6 |
| `chapters/05-phuong-phap.md` | Chương 4 |
| `chapters/06-thiet-ke-hien-thuc.md` | Chương 5 |
| `chapters/07-danh-gia.md` | Chương 6 |
| `chapters/08-thao-luan.md` | Chương 7 |
| `ket-luan.md` | Kết luận |
| `tom-tat-luan-van.md` | Tóm tắt VI/EN |
| `thong-tin-luan-van.md` | Mẫu thông tin UET |

## Bản đầy đủ (đã ghép)

```bash
./build-full.sh   # → thesis/luan-van-day-du.md (~30.000+ từ ≈ 65–75 trang Word)
```

## Ghép → Word

Times New Roman 13pt, giãn dòng 1.2, lề UET. Chèn hình từ FigJam hoặc `docs/design/architecture-comparison-template.svg`.

```bash
pandoc luan-van-day-du.md -o luan-van-day-du.docx
```
