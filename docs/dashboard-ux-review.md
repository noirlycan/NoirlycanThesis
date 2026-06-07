# Dashboard UX Review — Noirlycan Telemetry

**Phạm vi đánh giá:** [src/noirlycan_telemetry/dashboard/](../src/noirlycan_telemetry/dashboard/) — HTML (378 LOC), CSS (651 LOC), JS (996 LOC), Flask app (118 LOC).

**Mục tiêu:** Đề xuất cải tiến UI/UX phù hợp với một **research lab tool dùng cho luận văn**, không phải production EDR. Ưu tiên ROI cho: (a) workflow phân tích thực tế, (b) demo trước hội đồng + screenshot trong thesis, (c) công thái học cho người dùng đọc dashboard lâu.

---

## 0. Đánh giá chung

### Điểm mạnh hiện có

- **Visual coherence tốt.** Palette dark navy + cyan/blue accent, font pairing IBM Plex Mono ↔ Space Grotesk hợp lý cho công cụ telemetry.
- **Có 8 tab chia rõ chức năng** (Overview / Findings / Network / Primitives / Files / Events / Chains / Sessions).
- **Modal drill-down** cho từng finding với evidence + API chain + primitive table + related network.
- **Empty state** trên mọi bảng — không bị "bảng trắng" khó chịu.
- **`prefers-reduced-motion`** + **media query 900px** — đã quan tâm accessibility cơ bản.
- **Auto-refresh + Apply filters** — không block UI khi đang phân tích.
- **Runtime toggle** cho watch folder / auto API analysis — không cần restart collector.

### Đánh giá tổng thể

Trên thang research-tool, dashboard hiện ở mức **B+** — đủ dùng cho thesis, screenshot lên luận văn không xấu. Để lên **A**, cần xử lý ~6 vấn đề có tác động lớn (P0–P1) liệt kê dưới.

---

## 1. Vấn đề P0 — ảnh hưởng workflow phân tích

### 1.1. Search không debounce — phải bấm "Apply filters"

**Vấn đề:** [index.html:42-43](../src/noirlycan_telemetry/dashboard/templates/index.html) có input search và severity/PID/type, nhưng JS yêu cầu nhấn nút **Apply filters** (hoặc Enter). Workflow của analyst là *gõ → xem ngay*, không phải *gõ → nhớ bấm nút*.

**Đề xuất:**
- `input` event với `setTimeout` 200ms (debounce) → tự apply.
- Giữ nút Apply nhưng cho phép Ctrl/Cmd+Enter từ bất kỳ filter field nào.
- Hiển thị "X of Y filtered" để analyst biết bộ lọc đang active.

**Lý do:** Khảo sát log thường lặp lại — gõ → xem → sửa từ khóa. Bấm nút giữa mỗi vòng làm chậm cognitive flow.

### 1.2. Auto-refresh 1s quá agressive

**Vấn đề:** Auto-refresh interval 1 giây ([index.html:73](../src/noirlycan_telemetry/dashboard/templates/index.html)) gây UI flicker khi đọc bảng dài. Chart re-render mỗi giây làm mắt mỏi.

**Đề xuất:**
- Đổi default thành 5s.
- Cho phép chọn 1s / 5s / 30s / off qua dropdown thay vì checkbox.
- Khi user đang scroll hoặc focus vào một row, **pause refresh** (mượn ý tưởng từ Grafana).
- Thay full re-render bằng **incremental update**: chỉ append row mới ở top, highlight ngắn 500ms (animation `prefers-reduced-motion` aware).

**Lý do:** Khi viết luận văn, bạn sẽ chụp screenshot. Refresh 1s khiến không screenshot được trạng thái ổn định.

### 1.3. Thiếu deep link / URL state

**Vấn đề:** Mọi state (tab active, log đã chọn, filter, finding đang mở modal) chỉ lưu in-memory. Reload trang mất sạch. Không share được link "tab Findings của session X có filter severity=critical".

**Đề xuất:**
- Sync state vào `location.hash` hoặc `URLSearchParams`:
  ```
  /#tab=findings&log=session-2026-06-08.jsonl&severity=critical&pid=1337
  ```
- `popstate` listener để back button hoạt động.
- Khi mở modal: thêm `&finding=<id>` → link copy được, paste vào browser khác mở đúng finding đó.

**Lý do:** Trong defense buổi bảo vệ, hội đồng có thể hỏi *"cho xem lại finding lúc nãy"* — bạn paste URL từ slide vào browser là xong. Cũng cho phép screenshot kèm URL bar trong thesis.

### 1.4. Không có "active log" persistent indicator

**Vấn đề:** Sau khi chọn log từ dropdown, dễ quên đang xem log nào khi scroll xuống bảng. Chỉ có `<span id="active-log-label">no log selected</span>` trong tab Findings, không có sticky reminder.

**Đề xuất:**
- Sticky breadcrumb dưới header: `Session › session-2026-06-08-1042.jsonl · 1432 events · 4 findings`.
- Click vào breadcrumb → mở dropdown chọn session khác.
- Đổi browser title theo session đang chọn: `Noirlycan · session-2026-06-08`.

**Lý do:** Phân tích nhiều session liền tay, sự nhầm session là lỗi forensic nghiêm trọng.

---

## 2. Vấn đề P1 — cải thiện đáng kể nhưng không chặn

### 2.1. Severity chỉ có color, thiếu icon

**Vấn đề:** Color-coding severity là chuẩn, nhưng 4–8 % nam giới Việt Nam bị mù màu đỏ-xanh (deuteranopia/protanopia). Critical (rose) vs High (amber) khó phân biệt với người mù màu.

**Đề xuất:**
- Thêm icon Unicode đơn giản (không cần icon font): `▲ CRITICAL`, `▴ HIGH`, `● MEDIUM`, `○ LOW`.
- Hoặc dùng shape badge: pill cho critical, square cho high, diamond cho medium.

**Lý do:** Hội đồng có thể có người mù màu. Cũng thuận tiện khi screenshot in đen trắng.

### 2.2. Score column chỉ là số

**Vấn đề:** Bảng Findings có cột Score (0–100), hiển thị chỉ "85". Không có scale, không thấy threshold (50 = report, 70 = network watch, 85 = critical).

**Đề xuất:**
- Mini progress bar dài 60px sau số:
  ```
  85 [███████░░░]
  ```
- Threshold markers ở 50/70/85 trên bar (vạch mờ).
- Hover tooltip hiện scoring breakdown từ `evidence` (cross_process +15, section_mapping +10, ...).

**Lý do:** Analyst thấy "85" không biết là gần critical hay xa. Visual scale giải quyết ngay.

### 2.3. Bảng không sort được

**Vấn đề:** Không thấy click-to-sort trên header. Tables hardcode order theo time desc (giả định).

**Đề xuất:**
- Click header → sort asc/desc. Indicator `↑/↓` cạnh tên column.
- Đặc biệt cần sort cho: Score, Time, Severity, Target PID.
- Multi-column sort không cần (over-engineer cho thesis).

### 2.4. Bảng dài không virtualized

**Vấn đề:** Một session có thể có ~10k primitive event. JS render toàn bộ vào `<tbody>` → scroll lag.

**Đề xuất:**
- **Pagination đơn giản**: 100 rows/page, nút prev/next. Không cần virtual scrolling (over-engineer).
- Hoặc giới hạn "show last N events" với dropdown N = 100 / 500 / all.

**Lý do:** Trong demo, dashboard lag là điểm trừ thấy ngay.

### 2.5. Modal evidence là pre block raw JSON

**Vấn đề:** [index.html:362](../src/noirlycan_telemetry/dashboard/templates/index.html) hiện `<pre id="modal-evidence" class="code-block">` — dump JSON raw. Khó đọc.

**Đề xuất:**
- Parse evidence object thành **key-value cards**: mỗi flag (cross_process, section_mapping, create_suspended, executable_protection, technique, technique_confidence, technique_rationale) là một card có icon + giá trị.
- Còn các trường không nhận diện được mới fallback về JSON `<pre>`.

### 2.6. Chains tab thiếu visualisation

**Vấn đề:** Tab Chains là bảng phẳng (Depth / Recursive / PID path / Images / Techniques). Chain A→B→C đệ quy là visual concept, bảng làm khó hình dung.

**Đề xuất:**
- Mỗi chain render thành **horizontal flow diagram** đơn giản:
  ```
  [explorer.exe 1024] ─► [loader.exe 1337] ─► [msedge.exe 4242]
                              └─► technique: process_hollowing_section
  ```
- Dùng CSS flexbox + chevron Unicode `▶`, không cần thư viện vẽ graph.
- Recursive chain highlight bằng loop arrow.

**Lý do:** Recursive chain (~2% paper) là điểm bán hàng của luận văn — phải show đẹp.

---

## 3. Polish P2 — nice to have

### 3.1. Keyboard navigation

- `J/K` để scroll qua finding tiếp/trước (kiểu Gmail).
- `O` hoặc Enter để mở modal finding đang focus.
- `Esc` đóng modal (chuẩn dialog browser nên đã có sẵn — verify).
- `1–8` chuyển tab (số tương ứng).
- `/` focus search.
- `?` hiện popup phím tắt.

### 3.2. Annotation / tagging finding

Cho phép analyst add note ngắn lên một finding ("FP, do explorer.exe restart"). Lưu localStorage hoặc append vào session sidecar JSON. Cực kỳ hữu ích cho lab workflow.

### 3.3. Diff session

Chọn 2 session từ dropdown → "Compare" → bảng diff số liệu (findings, primitives, technique distribution) giữa 2 lần chạy. Dùng cho ablation experiment.

### 3.4. Export per-tab

Nút Export hiện chỉ xuất JSONL session đầy đủ. Bổ sung:
- Export tab hiện tại ra CSV (chuẩn excel).
- Export Findings tab → bảng cho thesis (Markdown table hoặc LaTeX `tabular`).
- Export Chains tab → DOT/Mermaid code (paste vào draw.io / thesis).

### 3.5. Timezone indicator

Time column hiện không có timezone. Thêm `(local)` hoặc `(UTC)` bên cạnh "Time" header. Quan trọng vì Sysmon log UTC còn JS `new Date()` local.

### 3.6. Charts hide-series

Chart.js cho phép click legend toggle series. Verify đã enable; nếu chưa thì bật. Phòng trường hợp một severity dominate làm các severity khác không thấy.

### 3.7. Loading skeleton

Khi `applyFilters()` đang fetch, tables có thể flash empty trước khi render. Thêm class `.loading` với shimmer animation (CSS-only, 10 LOC) để cảm giác smooth hơn.

### 3.8. "Pin" finding

Cho phép pin 1–3 finding lên top của tab Findings. Phòng cho phiên demo: analyst pin xong, scroll thoải mái, không sợ mất finding quan trọng.

---

## 4. Đặc thù cho luận văn

### 4.1. Demo mode / "thesis screenshot mode"

Thêm toggle (URL `?demo=1` hoặc nút trong settings):

- Ẩn các filter chip ít dùng để screenshot gọn.
- Tăng font size 10%.
- Hiện overlay watermark "Noirlycan — Luận văn thạc sĩ, Phan Vinh Co, 2026" góc dưới.
- Disable auto-refresh để screenshot ổn định.

Một toggle, ~30 LOC CSS. Đáng giá cho 70 trang thesis có ~15 screenshot dashboard.

### 4.2. Print stylesheet

`@media print` rule:
- Ẩn backdrop animation, gradient.
- Hidden tabs khác (chỉ in tab hiện tại).
- Background trắng, text đen, border xám.
- Page break sau mỗi panel.

Cho phép `Cmd+P → Save as PDF` chèn vào appendix luận văn.

### 4.3. "Telemetry layer" badge per primitive

Theo audit §3.8, mỗi primitive đến từ Frida (user-mode) hoặc Sysmon (kernel-mode). Hiển thị badge nhỏ cạnh API name:
- `[U]` cho Frida user-mode
- `[K]` cho Sysmon kernel-mode

Khớp với *Telemetry Layer Trust Matrix* trong threat model. Hội đồng sẽ nhìn vào dashboard và hiểu ngay defense-in-depth design.

### 4.4. Citation chip

Trên technique badge (ví dụ `process_hollowing_section`), tooltip hiển thị citation gốc:
- *"Section mapping variant of Process Hollowing — Di Pietro et al. (ASIA CCS 2025), §3.5"*

Giúp luận văn screenshot có context khoa học ngay trong UI.

---

## 5. Ưu tiên triển khai

Nếu thời gian hạn chế (luận văn còn nhiều việc khác), thứ tự đầu tư:

| Ưu tiên | Item | ROI |
|---|---|---|
| 🥇 | 1.1 Debounce search | Cải thiện workflow ngay, ~20 LOC |
| 🥇 | 1.3 URL state | Defense vs hội đồng + screenshot có URL |
| 🥇 | 4.1 Demo mode | Đẹp screenshot cho 70 trang thesis |
| 🥈 | 1.4 Sticky session badge | Tránh nhầm session |
| 🥈 | 2.1 Severity icon | Accessibility |
| 🥈 | 2.2 Score progress bar | Visual clarity ngay |
| 🥈 | 2.6 Chains visualization | Bán hàng recursive chain |
| 🥉 | 1.2 Auto-refresh 5s + incremental | Smoother demo |
| 🥉 | 2.4 Pagination | Tránh lag demo |
| 🥉 | 4.3 Telemetry layer badge | Khớp với threat model |
| 🆗 | Còn lại | Nếu có thời gian |

Tổng effort 🥇+🥈 ≈ **1.5–2 ngày dev** cho một dashboard đạt mức screenshot-ready cho thesis.

---

## 6. Anti-recommendations (không nên làm)

Một số ý dễ rơi vào trap, mình **không khuyến nghị** cho thesis scope:

| Ý tưởng | Lý do bỏ |
|---|---|
| Migrate sang React/Vue framework | Hiện Flask + vanilla JS đã đủ. Migrate tốn 1–2 tuần, không tăng giá trị khoa học. |
| Add real-time WebSocket | Polling 5s đã đủ cho thesis demo. WS thêm complexity, ít ROI. |
| Dark/light theme toggle | Dashboard là tool đêm-ngày dùng dưới ánh đèn neon — dark là đúng. Light không tăng giá trị. |
| Mobile-first responsive | Không ai phân tích malware trên iPhone. 900px breakpoint hiện có là đủ. |
| User authentication | Lab tool local. Auth làm phức tạp setup cho người chấm thesis. |
| i18n (English/Vietnamese toggle) | Thesis Việt + dashboard English là chuẩn. Toggle là over-engineer. |
| Heatmap calendar / forensic timeline view | Đẹp nhưng tốn 1 tuần xây, không trong scope luận văn. Để Future Work. |
| ML-based anomaly highlight | Out of scope (luận văn là replication, không phải ML paper). |

---

## 7. Kết luận

Dashboard hiện đã đủ cho thesis defense ở mức B+. 3 việc P0 (search debounce, URL state, demo mode) đẩy lên A- ngay với ~1 ngày dev. Tránh sa đà vào framework rewrite hoặc feature creep — thời gian quý hơn dành cho viết luận văn và xây PoC benchmark.

Nếu bạn ok một subset của review này, mình implement luôn. Không thì để đây như checklist cho bạn tự làm sau.
