# Thí nghiệm: Đánh giá độ trung thực của Frida user-mode hook

**Mục đích:** Cung cấp bằng chứng định lượng cho **assumption M5** trong
[audit-and-threat-model.md](../audit-and-threat-model.md) — *"Frida user-mode
hook chính xác về argument và thứ tự gọi"*. Hội đồng có quyền yêu cầu chứng
minh giả định này; thí nghiệm dưới đây sản sinh số liệu đó.

## 1. Giả thuyết

| H₀ | Frida bỏ sót một tỷ lệ đáng kể (> 1 %) các API call dưới tải nhẹ–trung bình. |
|----|--------------------------------------------------------------------------------|
| H₁ | Frida bắt được ≥ 99 % các call quan tâm, đủ để hỗ trợ kết luận khoa học về 2/3 primitive. |

## 2. Thiết kế thí nghiệm

### 2.1. Biến

| Biến | Vai trò | Giá trị |
|------|---------|---------|
| Số lần lặp `N` | Độc lập | 100, 1 000, 10 000 |
| API quan sát | Cố định | `VirtualAlloc`, `WriteProcessMemory`, `VirtualFree`, `OpenProcess` |
| Process target | Cố định | Python driver (cùng PID, self-inject) |
| Frida mode | Cố định | `spawn` (gắn agent trước khi run) |
| Phần cứng | Cố định | VM Windows 10/11 trong lab, 4 vCPU, 8 GB RAM |
| Phiên bản Frida | Cố định | Ghi lại từ `frida --version` |

### 2.2. Driver

Driver tại
[tests/manual/frida_fidelity_driver.py](../../tests/manual/frida_fidelity_driver.py)
gọi từng API qua `ctypes` và đếm số call thực sự thành công. Output ghi ra
`frida_fidelity_emit.txt`.

Lưu ý: driver self-inject (ghi vào chính process) để loại biến nhiễu do
cross-process race với Sysmon.

### 2.3. Đo

| Đại lượng | Cách tính | Đơn vị |
|-----------|----------|--------|
| `driver_count[api]` | Đếm trực tiếp trong driver | call |
| `frida_count[api]` | `Get-Content logs/session-*.jsonl \| Select-String '"api":"<api>"' \| Measure-Object` | event |
| Drop rate | `1 - frida_count / driver_count` | tỷ lệ |
| Overhead | Δ `elapsed_seconds` giữa run có/không Frida | giây |

## 3. Quy trình thực hiện

1. Khởi động VM lab, snapshot sạch.
2. Cài Frida (`pip install frida frida-tools`).
3. Run **baseline** (không Frida):
   ```powershell
   python -m tests.manual.frida_fidelity_driver 1000
   ```
   Ghi `frida_fidelity_emit.txt` → đây là `driver_count`.
4. Run **dưới Frida**:
   ```powershell
   noirlycan-telemetry spawn -- python -m tests.manual.frida_fidelity_driver 1000
   ```
5. Đếm event trong session JSONL mới sinh ở `logs/`.
6. Lặp với `N = 100, 1 000, 10 000` để có đường cong drop-rate theo tải.
7. Lặp **mỗi N ba lần** để tính trung bình + độ lệch chuẩn.

## 4. Tiêu chí chấp nhận / bác bỏ H₀

- **Bác bỏ H₀** (luận văn có quyền dùng Frida): drop-rate trung bình < 1 %
  với cả 3 giá trị `N`, p-value < 0.05 cho t-test một mẫu so với 1 %.
- **Không bác bỏ H₀**: drop-rate ≥ 1 %. Phải khai báo Frida là *best-effort*
  trong threat model, và bổ sung nguồn (vd. ETW) trước khi báo cáo prevalence.

## 5. Báo cáo kết quả

Bảng kết quả dự kiến (điền sau khi chạy):

| N | Run | driver VirtualAlloc | frida VirtualAlloc | drop % | overhead s |
|---|-----|---------------------|--------------------|--------|------------|
| 100 | 1 | | | | |
| 100 | 2 | | | | |
| 100 | 3 | | | | |
| 1 000 | 1 | | | | |
| … | | | | | |

Lưu báo cáo cuối ở `docs/experiments/frida-fidelity-results.md`.

## 6. Mối đe dọa với validity (Threats to Validity)

| Loại | Đe dọa | Giảm thiểu |
|------|--------|------------|
| Internal | Buffering JSONL có thể trễ count | Flush explicit; chờ 5s sau driver exit |
| Internal | Hook chạy `onLeave` ⇒ early-exit có thể miss event | Đo cả `onEnter`-only nhánh đối chứng |
| External | Kết quả phụ thuộc phiên bản Frida + Windows build | Ghi rõ version trong báo cáo; lặp nếu update |
| Construct | Self-inject không phản ánh cross-process load | Bổ sung run cross-process (driver A gọi sang B) |

## 7. Tiếp theo (nếu kết quả không đạt)

- Chuyển sang **ETW Threat Intelligence provider** (kernel ETW, không bypass được
  bằng direct syscall).
- Hoặc giới hạn scope luận văn ở mức *qualitative case study* thay vì
  *quantitative prevalence study*.
