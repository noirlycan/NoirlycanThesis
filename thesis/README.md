# Luận văn thạc sĩ — Tăng cường phát hiện mã độc dưới các hình thức né tránh

**Tên đề tài (chính thức):** Tăng cường phát hiện mã độc dưới các hình thức né tránh

## Kiến trúc

Tài liệu chi tiết: [`docs/clean-architecture-plan.md`](../docs/clean-architecture-plan.md), [`docs/architecture-diagrams.md`](../docs/architecture-diagrams.md).

Sau refactor, codebase dùng **Clean Architecture** (`kernel/` + `services/`) và hỗ trợ **monolith** hoặc **microservices** (`docker-compose.yml`). Lõi correlator 2-of-3 [4] nằm tại `services/analysis/domain/correlation.py`.

## Format

- **HTW (bắt buộc GVHD):** [`HUONG-DAN-HTW.md`](HUONG-DAN-HTW.md) — Nguyễn Việt Hà, IMRAD 4 chương
- **UET:** [`HUONG-DAN-VIET-UET.md`](HUONG-DAN-VIET-UET.md)
- **Phương pháp luận:** [`HUONG-DAN-VIET-METHOD.md`](HUONG-DAN-VIET-METHOD.md)

## Cấu trúc file (HTW + UET)

| File | Nội dung |
|------|----------|
| `chapters/01-mo-dau.md` | Mở đầu — Đặt vấn đề |
| `chapters/02-co-so-ly-thuyet.md` | **Chương 1** Cơ sở lý thuyết |
| `chapters/_assembled/03-phuong-phap-htw.md` | **Chương 2** Phương pháp (auto) |
| `chapters/_assembled/04-thiet-ke-htw.md` | **Chương 3** Thiết kế & hiện thực (auto) |
| `chapters/_assembled/05-thuc-nghiem-htw.md` | **Chương 4** Thực nghiệm & so sánh (auto) |
| `chapters/03`–`08` | Nguồn modular; sửa rồi chạy `assemble-htw.py` |
| `assemble-htw.py` | Ghép chương 2–4 theo HTW |

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

## Bản đầy đủ (đã ghép)

```bash
./build-full.sh   # → thesis/luan-van-day-du.md (~30.000+ từ ≈ 65–75 trang Word)
```

## Ghép → Word

```bash
cd thesis
./export-word.sh   # → luan-van-final.docx (~70+ trang) + tom-tat-final.docx
```

Chi tiết chỉnh sau xuất: [`HUONG-DAN-NOP-WORD.md`](HUONG-DAN-NOP-WORD.md).
