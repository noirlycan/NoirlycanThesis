# THÔNG TIN VỀ LUẬN VĂN THẠC SĨ

| Mục | Nội dung |
|-----|----------|
| 7. Tên đề tài | **Tăng cường phát hiện mã độc dưới các hình thức né tránh** |
| 11. Tóm tắt kết quả | Hiện thực phương pháp 2-of-3 primitive [4] trên Windows 10/11 (Noirlycan); tăng cường phát hiện dưới né tránh biến thể API (E1), gộp bước (E2), che attribution (E3), né hook (E4) qua telemetry kép Sysmon+Frida và file provenance; 31 test pass; hạn chế E5 (anti-sandbox) chưa triển khai. |
| 12. Ứng dụng | Phòng lab malware, điều tra số, giảng dạy MITRE T1055 và phân tích né tránh. |
| 13. Hướng tiếp theo | Anti-evasion E5 theo [4]; ETW kernel; benchmark E4 direct-syscall. |

---

**Official title (English):** Enhancing Malware Detection Under Evasion Techniques

**Summary:** Validated lab deployment of Di Pietro et al. (ASIA CCS 2025) [4] with dual-layer telemetry and file provenance to strengthen detection under API-variant, step-hiding, attribution-hiding, and hook-bypass evasion (E1–E4).
