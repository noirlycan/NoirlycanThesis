# CHƯƠNG 6. ĐÁNH GIÁ THỰC NGHIỆM

Chương này đánh giá mức độ đạt mục tiêu *tăng cường phát hiện mã độc trước các kĩ thuật né tránh* thông qua artifact Noirlycan, căn cứ [7]. Phạm vi **cố ý loại trừ E5** (né sandbox/VM): anti-evasion của [7] (BluePill) **không** được hiện thực; luận văn **không** so sánh recall với paper trên dataset 56.340 mẫu. Đánh giá tập trung năm trục: (1) kiểm chứng 2-of-3 và biến thể E1/E2 qua test; (2) case study section-mapping; (3) provenance E3; (4) telemetry kép E4; (5) protocol Frida fidelity (E6).

---

## 6.1. Câu hỏi nghiên cứu đánh giá (RQ1–RQ5)

Mỗi RQ ánh xạ tới một hoặc nhiều nhóm né tránh E1–E6 (Chương 2) và tới một loại bằng chứng khả thi (test, case study, đánh giá thiết kế).

**Bảng 6.1.** Câu hỏi đánh giá và ánh xạ nhóm né tránh

| ID | Câu hỏi | Nhóm né tránh | Tiêu chí thành công |
|----|---------|---------------|---------------------|
| **RQ1** | Hiện thực [7] có phát hiện biến thể API (E1) và gộp bước (E2)? | E1, E2 | Test correlation pass; section-mapping score ≥ 70 |
| **RQ2** | Telemetry kép Sysmon+Frida có bổ sung khi Frida miss (E4)? | E4 | Thiết kế + config E8/E10; case thiếu syscall thuần |
| **RQ3** | Pipeline provenance có gắn file-drop với injection (E3)? | E3 | Finding chứa `related_file`, metadata triage |
| **RQ4** | Classifier có nhận diện kỹ thuật né tránh hiện đại? | E1, E2 | 20 test classifier pass; đúng technique label |
| **RQ5** | Frida có đủ trung thực (fidelity) cho kết luận khoa học? | E6 | Protocol `frida-fidelity.md`; drop-rate trên VM |

**E5 out-of-scope:** cần module anti-evasion [7] §6. Số liệu ablation [7] được trích dẫn là **upper bound** lý thuyết.

---

## 6.2. Môi trường và phương pháp đo

### 6.2.1. Môi trường thí nghiệm

Môi trường đảm bảo tái lập: cấu hình YAML/XML đi kèm mã nguồn, phụ thuộc Python khoá qua `uv.lock`. VM cô lập, snapshot–rollback giữa các lần chạy loader.

| Thành phần | Cấu hình |
|------------|----------|
| OS | Windows 10/11 x64, VM cô lập |
| Sysmon | v15.x, config `configs/sysmon-noirlycan.xml` |
| Frida | Python package `frida` + `frida_hooks/handlers.js` |
| Collector | `noirlycan-agent` 0.3, Python 3.11 |
| Test runner | `uv run pytest` hoặc `python -m pytest` |

Ground truth do tác giả gắn nhãn — rủi ro *internal validity* (xem 6.6); test phát biểu theo *specification* [7] (2-of-3, equivalence class, congruence, temporal), không theo implementation, giảm thiểu lệ thuộc.

### 6.2.2. Loại đánh giá

Sáu loại bằng chứng, từ chặt chẽ tới định tính: (1) Unit test tổng hợp chuỗi API/primitive (CI Linux); (2) Case study section-mapping tương đương *neurevt* [7]; (3) Case study mở rộng `test_aes_loader_chain_upgrades_to_critical`; (4) Baseline signature A→W→E so với correlator 2-of-3; (5) Đánh giá định tính provenance/dashboard (RQ3); (6) Protocol fidelity Frida (RQ5).

Dataset PoC-Bench (5 loader) và Paper-Subset (100 mẫu Sap4Sec) **chưa hoàn thiện**; kết quả định lượng dựa trên 59 test methodology (quy tắc paper 15, correlator 12, execution 5, sensor kernel 7, classifier 20) trong tổng 129 test.

---

## 6.3. Bộ test methodology (59 test)

### 6.3.1. Cấu trúc bộ test

Năm file tách theo trách nhiệm: quy tắc của paper, correlator đầu-cuối, phân biệt execute/context-read, sensor kernel và phân loại kỹ thuật — phản ánh hai tầng phát hiện rồi gán nhãn MITRE.

```bash
uv run --extra full pytest tests/test_paper_rules.py tests/test_correlation.py \
  tests/test_execution_analysis.py tests/test_kernel_sensors.py tests/test_ired_team_classifier.py -v
```

Lần kiểm tra ngày 02/10/2026 ghi nhận 59 kiểm thử thuộc nhóm phương pháp hoàn thành. Khi chạy toàn bộ bộ kiểm thử trong cùng môi trường, kết quả là 131 kiểm thử hoàn thành và 1 kiểm thử được bỏ qua. Hai con số mô tả phạm vi kiểm tra phần mềm khác nhau; chúng không phải chỉ số hiệu quả phát hiện trên tập mã độc.

**Bảng 6.2.** Phân bổ test

| File | Số test | Phạm vi | RQ |
|------|---------|---------|-----|
| `test_paper_rules.py` | 15 | Từng quy tắc của [7] dạng hàm thuần: 2/3, congruence, temporal | RQ1 |
| `test_correlation.py` | 12 | Correlator đầu-cuối: 2-of-3, congruence, temporal, scoring, provenance | RQ1, RQ3 |
| `test_execution_analysis.py` | 5 | Execute thật vs. context-read | RQ1 |
| `test_kernel_sensors.py` | 7 | Sysmon EID 8/10 làm sensor thứ hai, call stack | RQ2 |
| `test_ired_team_classifier.py` | 20 | Phân loại kỹ thuật biến thể | RQ4 |
| **Tổng** | **59** | | |

### 6.3.2. Chi tiết `test_correlation.py` (12 test — trích)

Bộ test bao phủ *positive path* và *negative path*. Test reject quan trọng vì 2-of-3 nhạy: thiếu congruence hoặc temporal sẽ bùng phát FP.

| Test | Mục đích | RQ |
|------|----------|-----|
| `test_requires_two_distinct_primitives` | Một primitive W — **không** finding | RQ1 |
| `test_rejects_unrelated_memory_ranges` | WRITE @0x1000, EXECUTE @0x5000 — reject congruence | RQ1 |
| `test_detects_section_mapping_write_execute_chain` | **E2 section-mapping**, score ≥ 70, related_file | RQ1, RQ3 |
| `test_resolves_target_image_from_child_process` | Resolve `msedge.exe` từ ProcessEvent | RQ3 |
| `test_rejects_write_after_execute_temporal_order` | Fix D3 — WRITE sau EXECUTE reject | RQ1 |
| `test_set_thread_context_with_rip_overlaps_write_buffer` | Fix D1 — Rip trong buffer W | RQ1 |
| `test_detects_classic_dll_injection_chain` | A+W+E, DLL path remote thread | RQ1 |
| `test_nt_allocate_zero_address_skips_congruence_with_write_execute` | Edge NtAllocate address 0 | RQ1 |
| `test_detects_local_shellcode_staging` | Self-inject A+W, local_staging | RQ1 |
| `test_aes_loader_chain_upgrades_to_critical` | Chuỗi lab đầy đủ → CRITICAL, hollowing_section | RQ1, RQ4 |
| `test_read_only_apis_do_not_satisfy_two_of_three` | D2 — read ∉ write class | RQ1 |

### 6.3.3. Chi tiết `test_ired_team_classifier.py` (20 test — trích)

Hai mươi test biên soạn theo *ired.team* và ATT&CK, gồm biến thể chi tiết (PoolParty, Process Ghosting) lẫn cổ điển (DLL injection, thread hijack), tránh over-fit.

| Test (rút gọn) | Kỹ thuật kỳ vọng |
|----------------|-------------------|
| `test_early_bird_apc_classification` | `early_bird_apc_injection` |
| `test_local_alertable_wake_classification` | `local_apc_injection` |
| `test_poolparty_tp_work_classification` | `poolparty` |
| `test_process_ghosting_precursor_classification` | `process_ghosting` |
| `test_thread_hijack_classification` | `thread_hijack` |
| `test_reflective_dll_classification` | `reflective_dll_injection` |
| `test_section_mapping_classification` | `section_mapping_injection` |
| `test_propagate_injection_classification` | `propagate_injection` |
| `test_instrumentation_callback_classification` | `instrumentation_callback` |
| … | (10 test bổ sung APC, fiber, window, doppelgänging, …) |

20 test **pass** — RQ4 đạt trên tập rule synthetic; không tương đương precision/recall trên malware thực (xem 6.9).

---

## 6.4. Case study: Section-mapping (E2) — biến thể *neurevt*

### 6.4.1. Bối cảnh [7]

Paper [7] §3.5 (case study *neurevt*) mô tả biến thể Process Hollowing dominant: thay `VirtualAllocEx` + `WriteProcessMemory`, malware mở section bằng `NtCreateSection` rồi map vào process đích bằng `NtMapViewOfSection` với `PAGE_EXECUTE_READWRITE`; thực thi qua `SetThreadContext` + `ResumeThread` trên thread `CREATE_SUSPENDED`. Đây là **E2 — gộp bước allocate/write**: một `NtMapViewOfSection` thay hai bước, né signature đếm đủ ba API.

### 6.4.2. Thiết lập test

Test `test_detects_section_mapping_write_execute_chain` mô phỏng:

1. **File drop:** `loader.exe` trong Temp, unsigned, entropy 7,2.
2. **Process:** PID 1337, cờ `CREATE_SUSPENDED`, parent `explorer.exe`.
3. **Primitive W:** `NtMapViewOfSection` → target `msedge.exe` PID 4242, address 0x200000, `PAGE_EXECUTE_READWRITE`.
4. **Primitive E:** `ResumeThread`, address None — yêu cầu correlator kế thừa target từ context.

### 6.4.3. Kết quả

**Bảng 6.3.** Kết quả case study section-mapping

| Chỉ số | Giá trị |
|--------|---------|
| Số finding | 1 |
| Score | ≥ 70 (HIGH) |
| `related_file` | `...\loader.exe` |
| `evidence.section_mapping` | true |
| Primitive kinds | write, execute |
| Baseline signature A→W→E | **FAIL** (thiếu VirtualAllocEx, WriteProcessMemory) |
| Correlator 2-of-3 | **PASS** |

Noirlycan **phát hiện** biến thể dominant mà rule signature bỏ sót — phục vụ RQ1, chống E2. Metadata (`related_file`, `evidence.section_mapping`) đủ để analyst phục dựng câu chuyện tấn công.

### 6.4.4. Case study mở rộng — AES loader lab

`test_aes_loader_chain_upgrades_to_critical` mô phỏng chuỗi từ `aes_decrypt_loader.exe` → Edge với `NtWriteVirtualMemory`, `NtMapViewOfSection`, `GetThreadContext`, `SetThreadContext` đan xen (pattern shellcode AES). Score tăng dần: staging dưới 70, sau execute xác nhận finding **upgrade ≥ 85 (CRITICAL)**; technique `process_hollowing_section`, `execution_confirmed: true`. Correlator **upgrade** finding khi primitive mới tăng score thay vì tạo finding rời rạc — phù hợp real-time, giảm alert fatigue.

---

## 6.5. Đánh giá theo từng RQ

### 6.5.1. RQ1 — E1/E2 (methodology [7])

Mười hai kiểm thử trong `test_correlation.py` hoàn thành, bao gồm các điều kiện hai trong ba thao tác, đồng quy vùng nhớ và thứ tự thời gian. Kịch bản section-mapping đạt ngưỡng cảnh báo đã đặt trong kiểm thử. RQ1 vì thế có bằng chứng ở mức tính đúng của hiện thực với các ca tổng hợp; kết quả chưa cho biết recall trên mẫu mã độc độc lập.

### 6.5.2. RQ2 — E4 (telemetry kép)

**MỘT PHẦN — thiết kế đạt, số liệu syscall thuần chưa đủ.**

**Bảng 6.4.** Đánh giá E4

| Tiêu chí | Trạng thái | Ghi chú |
|----------|------------|---------|
| Sysmon E8 CreateRemoteThread trong config | ✅ | Kernel callback |
| Sysmon E10 ProcessAccess | ✅ | OpenProcess cross-process |
| Parser ghi TelemetryEvent raw | ✅ | JSONL |
| Thí nghiệm A/B Frida + sample syscall | ❌ | Cần driver `frida-fidelity` + sample unhooked |
| Congruence khi chỉ Sysmon | ❌ | Thiếu address — đúng thiết kế |

Luận văn claim **defense-in-depth**, không thay Frida bằng Sysmon cho 2-of-3. Sysmon E10/E8 cho tín hiệu cross-process nhưng không có địa chỉ buffer; vai trò *backstop* khi Frida bị né.

### 6.5.3. RQ3 — E3 (provenance)

**MỘT PHẦN.** `test_detects_section_mapping_write_execute_chain`: `related_file` khớp loader; `test_resolves_target_image_from_child_process`: lineage qua ProcessEvent. Pipeline FileDropWatcher / Sysmon E11 → triage → `add_process(created_from_file)` → scoring +10. Chưa có metric *thời gian FileCreate → Finding* trên N mẫu thật.

### 6.5.4. RQ4 — Classifier

**ĐẠT trên 20 test.** Bao phủ kỹ thuật [7] (hollowing, APC, DLL, reflective, doppelgänging); mở rộng PoolParty, Ghosting, instrumentation callback. Chưa có precision/recall trên ground-truth dataset.

### 6.5.5. RQ5 — Frida fidelity

Quy trình đo độ trung thực của Frida đã được mô tả trong `docs/experiments/frida-fidelity.md`, nhưng bảng kết quả trên máy ảo Windows chưa được hoàn tất. Phép đo dự kiến so sánh số thao tác do Frida ghi nhận với nguồn tham chiếu có kiểm tra thủ công theo từng họ API. Chưa có căn cứ để kết luận về tỷ lệ bỏ sót hoặc mức chi phí của Frida trong cấu hình này.

---

## 6.6. So sánh với baseline signature

### 6.6.1. Baseline định nghĩa

**Baseline Σ:** detector rule-based quan sát **lần lượt** ba API trên cùng `(actor, target)` trong cửa sổ thời gian, không equivalence class, không 2-of-3:

$$\texttt{VirtualAllocEx} \rightarrow \texttt{WriteProcessMemory} \rightarrow \texttt{CreateRemoteThread}$$

Đây là baseline có chủ đích đơn giản, dùng để cô lập tác động của việc thay đổi tên API và số bước trong chuỗi. Nó không đại diện cho khả năng của một sản phẩm SIEM hoặc EDR cụ thể.

### 6.6.2. Kết quả so sánh

**Bảng 6.5.** Baseline signature vs Noirlycan correlator

| Kịch bản | Baseline Σ | Noirlycan 2-of-3 | Ghi chú |
|----------|------------|------------------|---------|
| Classic DLL (test) | PASS | PASS | Tương đương |
| Section-mapping W+E | **FAIL** | **PASS** | E2 né signature |
| APC `NtQueueApcThreadEx` | **FAIL** | PASS (classifier) | E1 API variant |
| NtMapViewOfSection + Resume | **FAIL** | **PASS** | Dominant [7] |
| Chỉ WriteProcessMemory | FAIL | FAIL | Cả hai đúng (FP tránh) |
| WRITE + EXECUTE unrelated mem | FAIL | FAIL | Congruence |

Trên những chuỗi tổng hợp trong Bảng 6.5, bộ tương quan tạo cảnh báo ở các biến thể không thỏa chuỗi ba API của baseline. Hai trường hợp âm tính cho thấy cả hai quy tắc đều không tạo cảnh báo theo nhãn kỳ vọng của bộ kiểm thử. Bảng này chưa cung cấp ước lượng độ đặc hiệu trên phần mềm hợp pháp ngoài tập kiểm thử.

---

## 6.7. So sánh với paper [7]

**Bảng 6.6.** Đối chiếu phạm vi [7] vs luận văn

| Khía cạnh | Di Pietro et al. [7] | Luận văn Noirlycan |
|-----------|----------------------|---------------------|
| Quy mô dataset | 56.340 mẫu | Unit test + case study |
| Prevalence injection | ~16,5 % | Không đo |
| Công cụ công khai bỏ sót | 21,2 % trung bình (VT 24,0 %, CAPE 18,3 %) | Không đo |
| Anti-evasion E5 | Có trong môi trường nghiên cứu | Chưa hiện thực |
| 2-of-3 + congruence + temporal | Được đánh giá trên tập mẫu của [7] | Đã kiểm thử bằng chuỗi tổng hợp |
| Phân loại kỹ thuật | Có kết quả trên tập mẫu của [7] | Dựa trên quy tắc; chưa có chỉ số trên tập mẫu độc lập |
| Giám sát trên máy thử nghiệm | Phân tích theo phiên | Có luồng sự kiện trong phòng thí nghiệm |
| Liên kết tệp nguồn | Không phải trọng tâm công trình | Có mô hình provenance và kiểm thử liên kết |
| Giao diện phân tích | Không phải trọng tâm công trình | Có giao diện xem sự kiện và cảnh báo |
| Chuỗi tiêm nhiều tầng | Có số liệu trong [7] | Có cấu trúc đồ thị; chưa đo tỷ lệ |

Recall malware thật **có thể thấp hơn** [7] vì thiếu E5 (malware phát hiện VM có thể không inject) — **gap phạm vi** đã khai báo (Chương 3). Luận văn mở rộng [7] ở ba điểm: endpoint real-time, provenance E3, dashboard.

---

## 6.8. Tổng hợp kết quả theo nhóm né tránh

**Bảng 6.7.** Tổng hợp đánh giá E1–E6

| Nhóm | Tiêu chí đo | Kết quả | Trạng thái |
|------|-------------|---------|------------|
| **E1** | Ánh xạ API và phạm vi hook | Kiểm thử quy tắc đã qua; chưa đo độ bao phủ trên mẫu độc lập | Được hỗ trợ ở mức kiểm thử |
| **E2** | Kịch bản section-mapping | Cảnh báo xuất hiện trên chuỗi tổng hợp; baseline không nhận diện | Được hỗ trợ ở mức kịch bản |
| **E3** | Provenance linkage | Test + pipeline; chưa metric N mẫu | **Một phần** |
| **E4** | Sysmon fallback | Config + thiết kế; thiếu benchmark syscall | **Một phần** |
| **E5** | Anti-sandbox | Không module | **Ngoài phạm vi** |
| **E6** | Anti-Frida | `spawn` + evasion log; fidelity pending | **Hạn chế** |

**Bảng 6.8.** Tóm tắt RQ

| RQ | Kết luận |
|----|----------|
| RQ1 | Có bằng chứng trên tập kiểm thử tổng hợp |
| RQ2 | Có thiết kế và kiểm thử thành phần; thiếu phép đo đối chứng |
| RQ3 | Có kiểm thử liên kết; thiếu tập nhãn độc lập |
| RQ4 | Có kết quả phân loại trên ca kiểm thử tổng hợp |
| RQ5 | Có quy trình đo; chưa có số liệu |

---

## 6.9. Mối đe dọa với validity

### 6.9.1. Internal validity

Ground truth do tác giả viết — rủi ro confirmation bias, nhưng phù hợp mục đích kiểm chứng specification [7]. Edge case ResumeThread không address làm congruence suy yếu (D1 partial); giảm thiểu bằng kế thừa target qua context process.

### 6.9.2. External validity

Chỉ Windows 10/11 user-mode; không Server, không kernel injection. Không E5 → không generalize recall malware anti-VM. FP rate trên enterprise có thể khác.

### 6.9.3. Construct validity

Frida thay đổi timing — có thể ảnh hưởng race condition trong APC injection; fidelity benchmark (RQ5) đo mức ảnh hưởng. Score 0–100 là heuristic lab, chưa calibrated trên FP/FN quy mô lớn; ngưỡng HIGH/CRITICAL có thể cần điều chỉnh thực địa.

### 6.9.4. Conclusion validity

**Không** claim: thay thế sandbox/EDR thương mại; số liệu [7] trên 56.340 mẫu; phát hiện đầy đủ dưới E5/E6/kernel.

Kết quả hiện có hỗ trợ nhận định rằng hiện thực của phép ánh xạ API và quy tắc hai trong ba thao tác xử lý các ca kiểm thử đã đặc tả. Sự khác biệt với baseline chỉ áp dụng cho tập ca đối chứng trong chương này. Provenance và kết hợp hai nguồn sự kiện đã được hiện thực, song hiệu quả của chúng trên tập mã độc độc lập vẫn cần được đo.

---

## 6.10. Hạn chế và hướng bổ sung

Theo thứ tự ưu tiên triển khai:

1. **E5:** Tích hợp subset anti-evasion [7] (timing patch, env check, masking artifact VM).
2. **PoC-Bench:** Năm loader (section-map, shellcode, APC, reflective, hollowing) chạy trên VM với JSONL ground truth.
3. **Paper-Subset:** 100 mẫu Sap4Sec — đo agreement với log paper.
4. **E4 benchmark:** Sample direct-syscall so session Frida on/off.
5. **RQ5:** Hoàn thiện bảng drop-rate Frida trên VM Windows.

---

## 6.11. Phân tích chi tiết kết quả scoring

**Bảng 6.9.** Phân rã điểm case study section-mapping (ước lượng từ `_score`)

| Thành phần | Điểm cộng |
|------------|-----------|
| W + E + execution_confirmed | +45 |
| cross_process | +15 |
| section_mapping (NtMapViewOfSection) | +10 |
| executable_protection | +10 |
| CREATE_SUSPENDED | +15 |
| related_file | +10 |
| PE + unsigned | +5 +10 |
| **Tổng (cap 100)** | **≥ 70** |

Assertion `score >= 70` — không yêu cầu CRITICAL (85) vì thiếu full context hijack. Phản ánh *graded severity*: HIGH cho bằng chứng đủ alert; CRITICAL chỉ cho chuỗi đủ A/W/E và context overlap.

## 6.12. Classifier — ma trận kỹ thuật đã kiểm (20 test)

**Bảng 6.10.** Kết quả phân loại rule-based (tất cả PASS)

| # | Kỹ thuật test | Nhóm né tránh liên quan |
|---|---------------|-------------------------|
| 1 | early_bird_apc_injection | E2 — APC thay CRT |
| 2 | local_apc_injection | E2 — alertable wake |
| 3 | apc_injection | E1 — NtQueueApcThread |
| 4 | poolparty | E1 — threadpool API |
| 5 | process_ghosting | E2 — file delete transacted |
| 6 | process_doppelganging | E2 — TxF section |
| 7 | thread_hijack | E2 — context read/set |
| 8 | reflective_dll_injection | E1 — manual map |
| 9 | dll_injection | E1 — NT thread |
| 10 | section_mapping_injection | E2 — dominant [7] |
| 11 | shellcode_injection | E2 — local RWX |
| 12 | module_stomping | E2 — overwrite .text |
| 13 | hook_injection | E1 — SetWindowsHookEx |
| 14 | fiber_injection | E1 — fiber API |
| 15 | extra_window_memory_injection | E1 — window long |
| 16 | propagate_injection | Multi-stage |
| 17 | instrumentation_callback | E4-adjacent |
| 18 | process_hollowing_section | E2 — [7] dominant |
| 19 | process_hollowing_classic | E2 — unmap + write |
| 20 | pe_injection / entrypoint | E2 — patch EP |

Không có test E5 — classifier không có cơ hội chạy nếu sample không inject.

## 6.13. Đánh giá E5 — thừa nhận hạn chế (bắt buộc)

Paper [7] (§3.3, §5.1) dựa vào các biện pháp anti-evasion có sẵn của BluePill. Ablation so với bản Detours không có anti-evasion trên tập 2019: **6,2 %** mẫu lộ injection so với **11,8 %** của BluePill.

Noirlycan **`extensions/evasion.py`** chỉ phát hiện và log signal (`IsDebuggerPresent`, `NtQueryInformationProcess` với `ProcessDebugPort`) — **không** patch giá trị trả về. Do đó: (1) malware E5 trong VM có thể **thoát sớm** → zero finding; (2) không replicate được 16,5 % prevalence hay kết quả ablation anti-evasion; (3) RQ **cố ý bỏ qua E5** (Chương 3 §3.6).

Hướng phát triển: port subset anti-evasion Sap4Sec hoặc chế độ ETW-only giảm dấu vết Frida.

## 6.14. Đánh giá định tính dashboard và JSONL

Trên session lab thực: JSONL chứa đủ chuỗi `file` → `sysmon` → `primitive` → `finding`, replay offline; dashboard Findings hiển thị `related_file.path`, SHA256, technique badge — analyst nắm tình huống dưới 30 giây; export JSONL phục vụ lưu trữ evidence (Phụ lục C). Bổ sung RQ3 ở mức *qualitative acceptance*; đánh giá định lượng cần khảo sát người dùng — vượt phạm vi. Các hình từ Hình 6.1 đến Hình 6.8 dưới đây minh họa giao diện dashboard trên session lab thực với loader `aes_decrypt_loader` tiêm vào `msedge.exe` (agent `winVM01`).

Hình 6.1 thể hiện màn hình Overview: KPI toàn fleet (2 agent, 10 finding trong đó 7 CRITICAL, 10 injection chain, 30 file drop, 20 network observation), finding CRITICAL mới nhất kèm API chain đầy đủ (allocate → write → context_read → execute) và phân bố injection primitive theo quy tắc 2-of-3 [7].

![Hình 6.1. Màn hình Overview — KPI toàn fleet, finding CRITICAL và phân bố injection primitive](seminar/images/01-overview.png){width=14.5cm}

Hình 6.2 liệt kê danh sách finding theo agent: mỗi dòng gồm đường dẫn loader (`C:\Users\Public\Downloads\aes_decrypt_loader*.exe`), tiến trình đích `msedge.exe`, mức severity và thời điểm phát hiện — hỗ trợ triage theo trình tự thời gian.

![Hình 6.2. Tab Findings — danh sách finding loader → target theo thời gian](seminar/images/02-findings.png){width=12.5cm}

Khi chọn một finding, Hình 6.3 hiển thị chi tiết chuỗi tiêm: score, badge kỹ thuật (`section_mapping`, `cross_process`), số primitive quan sát được so với ngưỡng 2-of-3, cùng timeline API. Tab Evidence (Hình 6.4) liệt kê bằng chứng thô đối chiếu được với JSONL xuất ra — bảo đảm tính truy vết (chain-of-evidence) cho phân tích forensic E3.

![Hình 6.3. Chi tiết finding — score, badge kỹ thuật và timeline API chain](seminar/images/07-finding-detail.png){width=14.5cm}

![Hình 6.4. Chi tiết finding, tab Evidence — bằng chứng thô đối chiếu JSONL](seminar/images/08-finding-detail-evidence.png){width=14.5cm}

Hình 6.5 (tab Activity) là dòng sự kiện hợp nhất Frida và Sysmon theo thời gian. Hình 6.6 (tab Network) thể hiện các quan sát mạng sau cảnh báo: giao diện ghi nhận 20 bản ghi ở trạng thái `SYN_SENT` từ hai PID đích tới `192.168.0.104:80/443`, lấy từ bảng TCP. Các bản ghi này chỉ chứng minh rằng có nỗ lực thiết lập kết nối trong phiên minh họa; riêng trạng thái `SYN_SENT` chưa đủ để kết luận có kênh điều khiển đã hoạt động.

![Hình 6.5. Tab Activity — dòng sự kiện hợp nhất Frida + Sysmon](seminar/images/03-activity.png){width=14.5cm}

![Hình 6.6. Tab Network — network observation hậu-finding từ PID đích (post-injection watch)](seminar/images/04-network.png){width=13.5cm}

Hình 6.7 thể hiện cấu hình quy tắc correlation 2-of-3 [7] trên dashboard (equivalence class API, ngưỡng primitive); Hình 6.8 là màn hình quản trị agent (`winVM01`) với trạng thái policy đồng bộ Frida + Sysmon.

![Hình 6.7. Tab Rules — quy tắc correlation 2-of-3 và equivalence class API](seminar/images/05-rules-correlation.png){width=14.5cm}

![Hình 6.8. Tab Agents — trạng thái agent winVM01 và policy Frida + Sysmon](seminar/images/06-agents.png){width=14.5cm}

## 6.15. Công thức metric (định nghĩa cho mở rộng tương lai)

$$\mathrm{Precision} = \frac{TP}{TP + FP}, \quad \mathrm{Recall} = \frac{TP}{TP + FN}$$

$$\mathrm{F1} = \frac{2 \cdot \mathrm{Precision} \cdot \mathrm{Recall}}{\mathrm{Precision} + \mathrm{Recall}}$$

**TP:** finding score ≥ threshold, ground truth injection = true. **FP:** finding trên sample benign. **FN:** không sinh finding trên sample injection. Hiện chỉ có TP synthetic trong 59 test methodology (không có FP/FN corpus); không điền số Precision/Recall giả.

## 6.16. Kiểm chứng giả thuyết H1–H5

**Bảng 6.11.** Kết quả kiểm chứng giả thuyết (theo [2], [4])

| Giả thuyết | Kết luận | Bằng chứng | Ghi chú |
|------------|----------|------------|---------|
| **H1** | Được hỗ trợ trên tập kiểm thử | Ca biến thể Native API trong bộ kiểm thử | Chưa ước lượng recall trên tập độc lập |
| **H2** | Được hỗ trợ trên kịch bản | Ca `test_detects_section_mapping_write_execute_chain` | Kịch bản do tác giả xây dựng |
| **H3** | Được hỗ trợ một phần | Kiểm thử liên kết tệp và cảnh báo | Chưa đo sai lệch liên kết ở quy mô lớn |
| **H4** | **Chưa đủ số liệu** | Config Sysmon E8/E10; thiết kế Bảng 3.9 | Cần loader direct-syscall |
| **H5** | **Chưa kiểm chứng** | Protocol Phụ lục E | Chờ benchmark VM Windows |

Các kết quả về H1–H3 mô tả tính đúng của hiện thực trên ca đã xác định. H4–H5 cần dữ liệu đối chứng trên máy ảo trước khi đánh giá mức cải thiện do bổ sung Sysmon hoặc khả năng quan sát của Frida.

## 6.17. Tóm tắt chương

Chương 6 đánh giá Noirlycan theo RQ1–RQ5 và **kiểm chứng H1–H5**: **59 test methodology pass** xác nhận methodology [7] chống E1/E2 (**H1, H2 chấp nhận**); case study **section-mapping** đạt score ≥ 70, vượt baseline; classifier pass 20 test biến thể (RQ4). Provenance E3 (**H3 một phần**) và telemetry kép E4 (**H4 chưa đủ số liệu**). **E5 không triển khai** — recall lab không so sánh được với 21,2 %. Frida fidelity (**H5 chưa kiểm chứng**) ở mức protocol. Kết quả phù hợp luận văn thạc sĩ *tăng cường phát hiện dưới E1–E4*; định hướng tiếp theo ở Chương 7.
