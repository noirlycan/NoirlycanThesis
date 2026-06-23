# TÓM TẮT LUẬN VĂN THẠC SĨ

*(Khổ A5, tối đa 24 trang in hai mặt; Times New Roman 11pt — Công văn 139/ĐT UET Phụ lục 3. Bìa tóm tắt tách file `tom-tat-bia.md` khi in.)*

---

## Tiếng Việt

Process injection trên Windows vẫn là hành vi then chốt của mã độc né signature và che attribution. Malware có thể đổi API tương đương (E1), gộp bước operational (E2), inject qua tiến trình hợp pháp (E3), hoặc né hook user-mode bằng direct syscall (E4). Công trình Di Pietro et al. (ASIA CCS 2025) [4] chứng minh trên 56.340 mẫu rằng sandbox thiếu chống né tránh bỏ sót tới 21,2 % mẫu injection, và đề xuất phát hiện dựa trên ba operational primitive với quy tắc 2-of-3 — nhưng chưa cung cấp triển khai real-time trên endpoint lab kèm telemetry kép và provenance file.

Luận văn **hiện thực và mở rộng** phương pháp [4] trong hệ thống **Noirlycan Telemetry** (Frida + Sysmon) trên Windows 10/11 VM cô lập. Đóng góp: replication có kiểm chứng (31 unit test); telemetry kernel bổ sung E4; pipeline file-drop → finding (E3); classifier 21+ kỹ thuật; threat model E1–E6 với ranh giới claim (E5 out-of-scope).

**Kết quả:** H1, H2 chấp nhận; H3 một phần; H4, H5 chưa đủ số liệu VM.

### Kết luận (toàn văn theo yêu cầu UET)

Process injection là hành vi then chốt mà malware Windows dùng để né phát hiện signature và né attribution. Công trình Di Pietro et al. (ASIA CCS 2025) [4] cung cấp nền tảng phương pháp mạnh chống biến thể triển khai (E1, E2) và bằng chứng quy mô lớn về tác động né tránh sandbox (E5 — 21,2 % miss khi thiếu anti-evasion).

Luận văn đã **tăng cường phát hiện mã độc dưới các hình thức né tránh E1–E4** bằng cách: (1) hiện thực có kiểm chứng phương pháp [4] trên Windows 10/11 lab; (2) bổ sung telemetry kernel (Sysmon) khi hook user-mode bị né; (3) mở rộng pipeline file provenance; (4) formal hóa threat model và ranh giới claim khoa học. Đề tài hoàn thành mục tiêu luận văn thạc sĩ với căn cứ lý luận, hiện thực mã nguồn mở, đánh giá methodology và thừa nhận hạn chế E5 trung thực. Hướng mở rộng: anti-evasion module, benchmark E4/H5, PoC-Bench quy mô.

**Từ khóa:** né tránh mã độc, process injection, operational primitive, ASIA CCS 2025, Sysmon, Frida.

---

## English Abstract

**Thesis title:** *Enhancing Malware Detection Under Evasion Techniques*

Windows malware evades detection via API variants (E1), merged steps (E2), attribution hiding (E3), and hook bypass (E4). Di Pietro et al. [4] report 21.2% injection miss without anti-evasion sandboxes and propose 2-of-3 primitive detection — without real-time endpoint deployment.

This thesis implements and extends [4] in **Noirlycan Telemetry** (Frida + Sysmon). Results: H1/H2 accepted (31 tests); H3 partial; H4/H5 pending VM benchmarks.

**Conclusion:** Noirlycan enhances detection under E1–E4 in a validated lab; E5 remains essential future work toward [4]'s recall.

**Keywords:** malware evasion, process injection, operational primitive, Sysmon, Frida.

---

## Danh mục công trình khoa học (cuối tóm tắt — UET)

Chưa có công trình khoa học công bố liên quan trực tiếp đến luận văn tại thời điểm nộp.

---
