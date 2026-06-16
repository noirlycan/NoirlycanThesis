# TÓM TẮT LUẬN VĂN THẠC SĨ

## Tiếng Việt

Luận văn *Tăng cường phát hiện mã độc dưới các hình thức né tránh* nghiên cứu giải pháp phát hiện process injection trên Windows 10/11 trong phòng lab cô lập. Mã độc hiện đại né tránh phát hiện qua nhiều hình thức: đổi API tương đương, gộp hoặc ẩn bước injection, inject vào tiến trình hợp pháp để che nguồn gốc, gọi syscall trực tiếp né hook, hoặc phát hiện sandbox rồi ngừng hành vi độc hại.

Căn cứ khoa học chính là công trình Di Pietro, D'Elia và Querzoni (ASIA CCS 2025) [4], phân tích 56.340 mẫu malware và chứng minh 21,2 % mẫu injection bị sandbox bỏ sót khi thiếu chống né tránh; tác giả đề xuất phát hiện dựa trên ba operational primitive (*allocate*, *write*, *execute*), lớp tương đương API và quy tắc hai trong ba primitive (*2-of-3*) để chịu biến thể triển khai.

Luận văn hiện thực hóa phương pháp [4] trong hệ thống **Noirlycan Telemetry**, kết hợp **Frida** (hook user-mode) và **Sysmon** (telemetry kernel) nhằm tăng cường phát hiện dưới né tránh biến thể API (E1), gộp bước (E2), che attribution qua file-drop (E3), và né hook user-mode (E4). Đóng góp bổ sung gồm pipeline provenance file, static triage, classifier 21+ kỹ thuật injection, dashboard phân tích và threat model theo nhóm né tránh E1–E6.

Kết quả: 31 test tự động pass trên các biến thể injection; case study section-mapping (biến thể dominant trong [4]) phát hiện đúng với score ≥ 70; pipeline file-drop gắn metadata nguồn file với finding. Hạn chế: chưa tích hợp anti-sandbox (E5) như [4]; cần bổ sung benchmark Frida fidelity và PoC-Bench.

**Kết luận:** Luận văn tăng cường phát hiện mã độc dưới né tránh E1–E4 bằng triển khai có kiểm chứng [4] trên endpoint lab; E5 là hướng phát triển tiếp theo.

**Từ khóa:** né tránh mã độc, process injection, operational primitive, ASIA CCS 2025, Sysmon, Frida, file provenance.

---

## English Abstract

**Thesis title:** *Enhancing Malware Detection Under Evasion Techniques*

Windows malware evades detection through API variant swapping, step merging/hiding in injection chains, attribution hiding via legitimate process injection, direct syscalls bypassing user-mode hooks, and sandbox-aware behavior. This thesis addresses evasion groups E1–E4 in an isolated Windows 10/11 laboratory.

The primary scientific foundation is Di Pietro, D'Elia, and Querzoni (ASIA CCS 2025) [4], which reports that 21.2% of injection samples are missed by common sandboxes without anti-evasion, and proposes 2-of-3 operational primitive detection with API equivalence classes.

We implement [4] in **Noirlycan Telemetry**, combining **Frida** and **Sysmon** for defense-in-depth against E1–E4, plus file provenance, static triage, a 21+ technique classifier, and an analyst dashboard. Results: 31 automated tests pass; section-mapping case study (dominant variant in [4]) detected with score ≥ 70; qualitative file-drop provenance linkage. Limitations: no anti-sandbox module (E5) as in [4]; pending fidelity benchmarks.

**Conclusion:** The thesis enhances malware detection under evasion E1–E4 via validated [4] deployment on lab endpoints; E5 remains future work.

**Keywords:** malware evasion, process injection, operational primitive, ASIA CCS 2025, Sysmon, Frida.
