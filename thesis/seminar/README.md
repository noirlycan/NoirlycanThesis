# Tài liệu seminar luận ván (~30 phút)

Bộ tài liệu rút gọn từ luận ván đầy đủ (`thesis/`) phục vụ **seminar với GVHD** — trả lời 4 câu:

1. **Làm gì?** — Hiện thực + mở rộng [4] thành Noirlycan (agent + backend + dashboard)  
2. **Dựa vào đâu?** — Di Pietro et al. ASIA CCS 2025, Klein, Starink, Sysmon, Frida  
3. **Kết quả gì?** — 31 test pass, case study section-mapping/AES-loader, pipeline lab  
4. **Ý nghĩa gì?** — Công cụ lab mở; chống E1/E2; E3/E4 một phần; E5 out-of-scope  

## File

| File | Mục đích |
|------|----------|
| [`bao-cao-seminar.md`](bao-cao-seminar.md) | Bản viết rút gọn ~10 trang |
| [`bao-cao-seminar-chi-tiet.md`](bao-cao-seminar-chi-tiet.md) | **Bản chi tiết** (~15 trang) — có số liệu dashboard :8080 |
| [`slide-noi-dung.md`](slide-noi-dung.md) | 25 slide + ghi chú speaker — copy sang PowerPoint |
| [`demo-script.md`](demo-script.md) | Kịch bản demo live 5–7 phút (Plan A/B/C) |
| [`images/`](images/) | Screenshot dashboard (tự chụp từ lab) |
| [`export-seminar.sh`](export-seminar.sh) | Xuất Word/PDF từ báo cáo (pandoc) |

## Xuất Word / PDF

```bash
cd thesis/seminar
./export-seminar.sh
# → bao-cao-seminar-chi-tiet.docx (mặc định)

./export-seminar.sh bao-cao-seminar.md
# → bao-cao-seminar.docx (bản rút gọn)
```

## Slide PowerPoint

1. Mở [`slide-noi-dung.md`](slide-noi-dung.md)  
2. Copy từng slide (tiêu đề + bullet)  
3. Thêm hình từ [`docs/architecture-diagrams-slide.md`](../../docs/architecture-diagrams-slide.md) và `images/`  

## Demo lab

Xem [`demo-script.md`](demo-script.md). Khởi động nhanh:

```bash
# Mac
python scripts/lab_stack.py up --host 0.0.0.0 --backend-port 8888
```

```powershell
# Windows VM (Admin)
.\scripts\run-lab-agent.ps1 -Server <IP-Mac>:8888 -AgentId vm01 -Token <TOKEN>
```

## Luận ván đầy đủ

```bash
cd thesis
./build-full.sh          # → luan-van-day-du.md
./export-word.sh         # → luan-van-final.docx
```

## Ghi chú

- Kiến trúc trong seminar dùng **FastAPI + React** (không Flask/Django cũ).  
- Số **16,5% / 21,2%** là motivation từ paper [4], không phải kết quả đo lại của Noirlycan.
