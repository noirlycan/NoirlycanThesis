# CHƯƠNG 6. ĐÁNH GIÁ THỰC NGHIỆM

Chương này đánh giá mức độ đạt mục tiêu *tăng cường phát hiện mã độc dưới các hình thức né tránh* thông qua artifact Noirlycan, căn cứ phương pháp [4]. Phạm vi đánh giá **cố ý loại trừ E5** (né sandbox/VM): module anti-evasion của [4] — được tác giả chứng minh tăng recall ~21,2 % trên subset injection — **không được hiện thực** trong luận văn. Do đó, luận văn **không** so sánh recall với paper trên cùng dataset 56.340 mẫu và **không** claim số liệu prevalence 16,5 % hay 21,2 % của [4]. Thay vào đó, đánh giá tập trung: (1) kiểm chứng quy tắc 2-of-3 và biến thể E1/E2 qua test tổng hợp; (2) case study section-mapping — biến thể dominant trong [4]; (3) đánh giá định tính provenance E3; (4) phân tích thiết kế telemetry kép E4; (5) protocol Frida fidelity (E6 liên quan).

---

## 6.1. Câu hỏi nghiên cứu đánh giá (RQ1–RQ5)

**Bảng 6.1.** Câu hỏi đánh giá và ánh xạ nhóm né tránh

| ID | Câu hỏi | Nhóm né tránh | Tiêu chí thành công |
|----|---------|---------------|---------------------|
| **RQ1** | Hiện thực [4] có phát hiện biến thể API (E1) và gộp bước (E2) không? | E1, E2 | Test correlation pass; section-mapping score ≥ 70 |
| **RQ2** | Telemetry kép Sysmon+Frida có bổ sung khi Frida miss (E4)? | E4 | Thiết kế + config E8/E10; case thiếu số liệu syscall thuần |
| **RQ3** | Pipeline provenance có gắn file-drop với injection (E3)? | E3 | Finding chứa `related_file`, metadata triage |
| **RQ4** | Classifier có nhận diện kỹ thuật né tránh hiện đại? | E1, E2 | 20 test classifier pass; đúng technique label |
| **RQ5** | Frida có đủ trung thực (fidelity) cho kết luận khoa học? | E6 | Protocol `frida-fidelity.md`; drop-rate trên VM |

**RQ không áp dụng cho E5:** né sandbox/VM cần module anti-evasion [4] §6 — **out-of-scope**. Số liệu ablation của [4] được trích dẫn là **upper bound** lý thuyết, không phải kết quả luận văn.

---

## 6.2. Môi trường và phương pháp đo

### 6.2.1. Môi trường thí nghiệm

| Thành phần | Cấu hình |
|------------|----------|
| OS | Windows 10/11 x64, VM cô lập |
| Sysmon | v15.x, config `configs/sysmon-noirlycan.xml` |
| Frida | Python package `frida` + `windows_injection_hooks.js` |
| Collector | `noirlycan-telemetry` 0.x, Python 3.11 |
| Test runner | `uv run pytest` hoặc `python -m pytest` |

Ground truth trên unit test: **do tác giả luận văn gắn nhãn** — primitive và kỹ thuật kỳ vọng được mô tả trực tiếp trong assertion. Đây là mối đe dọa *internal validity* (mục 6.6).

### 6.2.2. Loại đánh giá

1. **Unit test tổng hợp** — mô phỏng chuỗi API/primitive không cần chạy malware thật.
2. **Case study có cấu trúc** — section-mapping tương đương *neurevt* [4].
3. **Case study mở rộng** — `test_aes_loader_chain_upgrades_to_critical` mô phỏng loader lab thực.
4. **Baseline signature** — rule cố định A→W→E API names so với correlator 2-of-3.
5. **Đánh giá định tính** — provenance, dashboard (RQ3).
6. **Protocol fidelity** — benchmark Frida (RQ5), kết quả điền trên VM.

Dataset PoC-Bench (5 loader) và Paper-Subset (100 mẫu Sap4Sec) nêu trong outline — **chưa hoàn thiện** cho luận văn bản này; kết quả định lượng chính dựa trên 31 test methodology.

---

## 6.3. Bộ test methodology (31 test)

### 6.3.1. Cấu trúc bộ test

Hai file cốt lõi:

```bash
uv run pytest tests/test_correlation.py tests/test_ired_team_classifier.py -v
```

Kết quả: **31 passed, 0 failed**.

**Bảng 6.2.** Phân bổ test

| File | Số test | Phạm vi |
|------|---------|---------|
| `test_correlation.py` | 11 | 2-of-3, congruence, temporal, scoring, provenance |
| `test_ired_team_classifier.py` | 20 | Phân loại kỹ thuật biến thể |
| **Tổng** | **31** | RQ1, RQ4 |

### 6.3.2. Chi tiết `test_correlation.py` (11 test)

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

Toàn bộ 20 test **pass** — RQ4 đạt trên tập rule synthetic.

---

## 6.4. Case study: Section-mapping (E2) — biến thể *neurevt*

### 6.4.1. Bối cảnh [4]

Paper [4] §3.5 và case study *neurevt* mô tả biến thể Process Hollowing dominant: thay `VirtualAllocEx` + `WriteProcessMemory` bằng `NtCreateSection` + `NtMapViewOfSection` (remote map executable). Execute qua `SetThreadContext` + `ResumeThread`. Đây là ví dụ điển hình **E2 — gộp bước allocate/write**.

### 6.4.2. Thiết lập test

Test `test_detects_section_mapping_write_execute_chain` mô phỏng:

1. **File drop:** `loader.exe` trong Temp, unsigned, entropy 7,2.
2. **Process:** PID 1337, `CREATE_SUSPENDED`, parent explorer.
3. **Primitive W:** `NtMapViewOfSection` → `msedge.exe` PID 4242, address 0x200000, protection EXECUTE_READWRITE.
4. **Primitive E:** `ResumeThread`, address None.

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

Kết luận: phương pháp [4] hiện thực trong Noirlycan **phát hiện được** biến thể dominant mà rule signature cố định bỏ sót — trực tiếp phục vụ RQ1 và mục tiêu chống E2.

### 6.4.4. Case study mở rộng — AES loader lab

`test_aes_loader_chain_upgrades_to_critical` mô phỏng chuỗi thực tế từ loader `aes_decrypt_loader.exe` → Edge:

- Nhiều `NtWriteVirtualMemory`, `NtMapViewOfSection`, `GetThreadContext`, `SetThreadContext`.
- Score tăng dần: staging < 70 → sau execute **≥ 85 (CRITICAL)**.
- Technique: `process_hollowing_section`, `execution_confirmed: true`.

Chứng minh correlator **upgrade** finding khi primitive mới làm tăng score — phù hợp vận hành real-time.

---

## 6.5. Đánh giá theo từng RQ

### 6.5.1. RQ1 — E1/E2 (methodology [4])

**Kết luận: ĐẠT.**

Bằng chứng:

- 11/11 test correlation pass.
- Quy tắc 2-of-3, congruence, temporal khớp audit `docs/audit-and-threat-model.md` (✅ cho các mục 2.1–2.6 sau fix D1–D3).
- Section-mapping score ≥ 70.

Hạn chế: test synthetic; chưa chạy 100 mẫu Sap4Sec trên VM (kế hoạch PoC-Bench).

### 6.5.2. RQ2 — E4 (telemetry kép)

**Kết luận: MỘT PHẦN — thiết kế đạt, số liệu syscall thuần chưa đủ.**

**Bảng 6.4.** Đánh giá E4

| Tiêu chí | Trạng thái | Ghi chú |
|----------|------------|---------|
| Sysmon E8 CreateRemoteThread trong config | ✅ | Kernel callback |
| Sysmon E10 ProcessAccess | ✅ | OpenProcess cross-process |
| Parser ghi TelemetryEvent raw | ✅ | JSONL |
| Thí nghiệm A/B: có/không Frida + sample syscall | ❌ Chưa | Cần driver `frida-fidelity` + sample unhooked |
| Congruence khi chỉ Sysmon | ❌ Không | Thiếu address — đúng thiết kế |

Luận văn claim **phòng thủ sâu** (defense-in-depth), không claim thay thế Frida bằng Sysmon cho 2-of-3.

### 6.5.3. RQ3 — E3 (provenance)

**Kết luận: MỘT PHẦN — đạt trên test và thiết kế pipeline.**

Bằng chứng:

- `test_detects_section_mapping_write_execute_chain`: `related_file` khớp loader.
- `test_resolves_target_image_from_child_process`: lineage process.
- Pipeline: FileDropWatcher / Sysmon E11 → triage → `add_process(created_from_file)` → scoring +10.

Chưa có metric định lượng *thời gian FileCreate → Finding* trên N mẫu thật — đề xuất cho bản mở rộng.

### 6.5.4. RQ4 — Classifier

**Kết luận: ĐẠT trên tập 20 test.**

- Bao phủ kỹ thuật [4]: hollowing, APC, DLL, reflective, doppelgänging.
- Mở rộng: PoolParty, Ghosting precursor, instrumentation callback.
- **Chưa** có precision/recall trên ground-truth dataset 12 kỹ thuật paper — classifier đánh giá bằng test rule-level.

### 6.5.5. RQ5 — Frida fidelity

**Kết luận: CHƯA HOÀN TẤT — protocol sẵn, bảng kết quả VM cần điền.**

Protocol `docs/experiments/frida-fidelity.md` định nghĩa:

- Driver spawn mẫu benign + injection PoC;
- Đo số primitive Frida vs ground-truth hook count;
- Drop-rate = missed / expected.

Giả định M5 (audit): overhead Frida chấp nhận được cho lab; **chưa** publish bảng số trong luận văn bản này.

---

## 6.6. So sánh với baseline signature

### 6.6.1. Baseline định nghĩa

**Baseline Σ:** detector rule-based yêu cầu quan sát **lần lượt** ba API:

$$\texttt{VirtualAllocEx} \rightarrow \texttt{WriteProcessMemory} \rightarrow \texttt{CreateRemoteThread}$$

trên cùng `(actor, target)` trong cửa sổ thời gian (không có equivalence class, không 2-of-3).

### 6.6.2. Kết quả so sánh

**Bảng 6.5.** Baseline signature vs Noirlycan correlator

| Kịch bản | Baseline Σ | Noirlycan 2-of-3 | Ghi chú |
|----------|------------|------------------|---------|
| Classic DLL (test) | PASS | PASS | Tương đương |
| Section-mapping W+E | **FAIL** | **PASS** | E2 né signature |
| APC `NtQueueApcThreadEx` | **FAIL** | PASS (classifier) | E1 API variant |
| NtMapViewOfSection + Resume | **FAIL** | **PASS** | Dominant [4] |
| Chỉ WriteProcessMemory | FAIL | FAIL | Cả hai đúng (FP tránh) |
| WRITE + EXECUTE unrelated mem | FAIL | FAIL | Congruence |

Noirlycan **strictly dominates** baseline trên các biến thể E1/E2 trong bảng — cốt lõi lập luận *tăng cường phát hiện dưới né tránh*.

---

## 6.7. So sánh với paper [4]

**Bảng 6.6.** Đối chiếu phạm vi [4] vs luận văn

| Khía cạnh | Di Pietro et al. [4] | Luận văn Noirlycan |
|-----------|----------------------|---------------------|
| Quy mô dataset | 56.340 mẫu | Unit test + case study |
| Prevalence injection | ~16,5 % | Không đo |
| Sandbox miss rate | 21,2 % (với anti-evasion) | Không đo |
| Anti-evasion E5 | ✅ Tích hợp | ❌ **Không hiện thực** |
| 2-of-3 + congruence + temporal | ✅ | ✅ (31 test) |
| Phân loại 12+ kỹ thuật | ✅ Có metric | ✅ Rule-based, chưa metric dataset |
| Endpoint real-time | ❌ | ✅ |
| File provenance E3 | ❌ | ✅ |
| Dashboard analyst | ❌ | ✅ |
| Recursive chain 2 % | ✅ Báo cáo | ⚠️ Graph only |

**Trung thực khoa học:** Recall trên malware thật trong lab **có thể thấp hơn** [4] vì thiếu E5 — malware phát hiện VM có thể **không inject**, và Noirlycan sẽ không có finding. Đây không phải lỗi implementation 2-of-3 mà là **gap phạm vi** đã khai báo Chương 3.

---

## 6.8. Tổng hợp kết quả theo nhóm né tránh

**Bảng 6.7.** Tổng hợp đánh giá E1–E6

| Nhóm | Tiêu chí đo | Kết quả | Trạng thái |
|------|-------------|---------|------------|
| **E1** | Equivalence + hook coverage | 31 test pass; manifest ↔ hooks | **Đạt** |
| **E2** | 2-of-3 section-mapping | score ≥ 70; baseline FAIL | **Đạt** |
| **E3** | Provenance linkage | Test + pipeline; chưa metric N mẫu | **Một phần** |
| **E4** | Sysmon fallback | Config + thiết kế; thiếu benchmark syscall | **Một phần** |
| **E5** | Anti-sandbox | Không module | **Ngoài phạm vi** |
| **E6** | Anti-Frida | `spawn` + evasion log; fidelity pending | **Hạn chế** |

**Bảng 6.8.** Tóm tắt RQ

| RQ | Kết luận |
|----|----------|
| RQ1 | ✅ Đạt |
| RQ2 | ⚠️ Một phần |
| RQ3 | ⚠️ Một phần |
| RQ4 | ✅ Đạt (synthetic) |
| RQ5 | ⏳ Protocol có, số liệu pending |

---

## 6.9. Mối đe dọa với validity

### 6.9.1. Internal validity

- Ground truth test do tác giả viết — rủi ro bias nhưng phù hợp kiểm chứng specification [4].
- Một số edge case (ResumeThread không address) vẫn làm congruence suy yếu (D1 partial).

### 6.9.2. External validity

- Chỉ Windows 10/11 user-mode; không Windows Server, không kernel injection.
- Không E5 → không generalize recall malware anti-VM như [4].
- Lab cô lập — không đại diện enterprise EDR.

### 6.9.3. Construct validity

- Frida thay đổi timing — có thể ảnh hưởng race APC; fidelity benchmark (RQ5) nhằm đo mức này.
- Score 0–100 là heuristic lab, **không** calibrated trên FP/FN thực tế lớn.

### 6.9.4. Conclusion validity

Luận văn **không** claim:

- Thay thế sandbox/EDR thương mại;
- Số liệu thống kê [4];
- Phát hiện đầy đủ dưới E5/E6/kernel.

Luận văn **có thể** claim (với evidence Chương 6):

- Hiện thực có kiểm chứng 2-of-3 + equivalence [4] trên Windows lab;
- Tăng cường so với baseline signature trên E1/E2;
- Extension provenance và telemetry kép cho E3/E4 ở mức thiết kế + test.

---

## 6.10. Hạn chế và hướng bổ sung

1. **E5:** Tích hợp subset anti-evasion [4] (timing patch, env check) — ưu tiên hướng phát triển Kết luận.
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

Test assertion `findings[0].score >= 70` — không yêu cầu CRITICAL (85) vì thiếu full context hijack như `test_aes_loader_chain_upgrades_to_critical`.

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
| 10 | section_mapping_injection | E2 — dominant [4] |
| 11 | shellcode_injection | E2 — local RWX |
| 12 | module_stomping | E2 — overwrite .text |
| 13 | hook_injection | E1 — SetWindowsHookEx |
| 14 | fiber_injection | E1 — fiber API |
| 15 | extra_window_memory_injection | E1 — window long |
| 16 | propagate_injection | Multi-stage |
| 17 | instrumentation_callback | E4-adjacent |
| 18 | process_hollowing_section | E2 — [4] dominant |
| 19 | process_hollowing_classic | E2 — unmap + write |
| 20 | pe_injection / entrypoint | E2 — patch EP |

Không có test riêng cho **E5** — classifier không chạy nếu sample không inject.

## 6.13. Đánh giá E5 — thừa nhận hạn chế (bắt buộc)

Paper [4] §6 mô tả module anti-evasion tích hợp trong sandbox QEMU:

- Patch timing (`Sleep`, `GetTickCount`) để né delay-based detection.
- Che giấu artifact VM (registry, MAC, process list).
- Ablation: **+21,2 %** mẫu injection được phát hiện nhờ anti-evasion so với sandbox thuần.

Noirlycan **`kernel/analysis/evasion.py`** chỉ phát hiện và log signal (vd. `IsDebuggerPresent`, `NtQueryInformationProcess`) — **không** patch, **không** fake environment. Do đó:

1. Malware E5 trong lab VM có thể **thoát sớm** → zero primitive → zero finding.
2. Luận văn **không thể** replicate số liệu 16,5 % prevalence hay 21,2 % sandbox gap.
3. RQ đánh giá **cố ý bỏ qua E5** — không phải oversight mà ranh giới đề tài (Chương 3 §3.6).

Hướng phát triển: port subset anti-evasion Sap4Sec hoặc ETW-only mode — nêu ở Kết luận.

## 6.14. Đánh giá định tính dashboard và JSONL

Trên session lab thực (không nằm trong CI Linux):

- JSONL chứa đủ chuỗi `file` → `sysmon` (E1) → `primitive` → `finding`.
- Dashboard tab Findings hiển thị `related_file.path`, SHA256, technique badge.
- Export JSONL phục vụ lưu trữ evidence — reproducibility Phụ lục C.

Đây bổ sung RQ3 ở mức **qualitative acceptance** cho luận văn thạc sĩ.

## 6.15. Công thức metric (định nghĩa cho mở rộng tương lai)

Khi PoC-Bench hoàn thiện, sẽ áp dụng:

$$\mathrm{Precision} = \frac{TP}{TP + FP}, \quad \mathrm{Recall} = \frac{TP}{TP + FN}$$

$$\mathrm{F1} = \frac{2 \cdot \mathrm{Precision} \cdot \mathrm{Recall}}{\mathrm{Precision} + \mathrm{Recall}}$$

- **TP:** finding score ≥ threshold, ground truth injection = true.
- **FP:** finding, ground truth benign.
- **FN:** không finding, ground truth injection.

Hiện tại chỉ có TP synthetic trong 31 test (không FP/FN corpus). Luận văn **trung thực** không điền số Precision/Recall giả.

## 6.16. Tóm tắt chương

Chương 6 đánh giá Noirlycan theo RQ1–RQ5: **31 test tự động pass** (`test_correlation.py` + `test_ired_team_classifier.py`) xác nhận methodology [4] chống E1/E2; case study **section-mapping** đạt score ≥ 70 và vượt baseline signature; classifier pass 20 test biến thể hiện đại (RQ4). Provenance E3 và telemetry kép E4 đạt **một phần** — pipeline và test có, metric quy mô chưa đủ. **E5 (anti-sandbox) không triển khai** — hạn chế then chốt so với [4], recall lab không so sánh được 21,2 % sandbox miss. Frida fidelity (RQ5) còn protocol. Kết quả phù hợp luận văn thạc sĩ *tăng cường phát hiện dưới E1–E4* với ranh giới claim rõ ràng; thảo luận sâu hơn ở Chương 7.
