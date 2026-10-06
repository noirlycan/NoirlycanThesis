# Changelog

## 0.3.0 — 2026-10-02 (branch `refactor/paper-aligned-core`)

Tái cấu trúc toàn bộ theo hai module của Di Pietro et al. (ASIA CCS '25, Figure 1):
**monitoring module** (agent, sensor) và **analysis module** (detector giữ nguyên quy tắc
của paper). Bản đồ chi tiết: [`docs/code-map.md`](docs/code-map.md).

Kiểm chứng: 127 test (126 pass, 1 skip), lint sạch (`ruff --select F,E9`), mọi module import
được, replay 20 session thật trong `logs/` qua code cũ và mới sau mỗi bước, chạy thử
end-to-end backend + agent thật.

---

### ⚠️ Việc cần làm sau khi nhận bản này

- **Rotate secret đã commit trong lịch sử git:** `logs/.agent_identity.json` (token agent
  `winVM01`) và `logs/noirlycan.db` (enrollment token 2 agent, server token, hash mật khẩu
  3 user) đã nằm trong commit `3752d81` và trên GitHub remote. Regenerate token agent, đổi
  mật khẩu user; cân nhắc xóa khỏi lịch sử git.
- **Đăng nhập:** không còn `admin@lab`/`admin` mặc định. Đặt `NOIRLYCAN_ADMIN_PASSWORD`
  trước lần chạy đầu, hoặc lấy mật khẩu ngẫu nhiên in trên console. Demo:
  `NOIRLYCAN_DEMO_USERS=1`.
- **Agent:** tải lại file config từ tab Agents (có thêm `command_key`). Agent không có key
  sẽ pin key ở lần kết nối đầu (TOFU).
- **Lệnh đổi chỗ:** `noirlycan-backend batch|compare` → `noirlycan-agent batch|compare`.
- **Chương 7:** chạy lại số liệu nếu lấy từ session `session-20260726T175324Z.jsonl`
  (xem "Thay đổi kết quả detection").

---

### Thay đổi kết quả detection

| Thay đổi | Lý do | Ảnh hưởng trên log thật |
|----------|-------|-------------------------|
| Rule temporal miễn trừ đổi quyền vùng nhớ (`VirtualProtect(Ex)`, `NtProtectVirtualMemory`) | Chuỗi `VirtualAllocEx(RW) → WriteProcessMemory → VirtualProtectEx(RX) → CreateRemoteThread` bị loại vì RW→RX bị coi là đảo thứ tự; đổi quyền không tạo buffer mới | 61 → 67 findings, chỉ 1/20 session (`session-20260726T175324Z`) |
| Báo lại chuỗi khi **điểm tăng HOẶC chuỗi thêm bước** (thêm loại primitive / execute vừa xác nhận), thay vì chỉ khi điểm tăng | Điểm chặn ở 100 → bước cuối (thường phân loại chính xác nhất) từng bị nuốt | Không đổi so với bản sửa temporal |
| Bằng chứng kernel cộng điểm (+10 mỗi loại): direct syscall, caller unbacked, hook bypass | Mở rộng bộ lọc return-address của paper (§3.3) bằng call stack do kernel chụp | Không đổi (log hiện có chưa có EID 8; unbacked bị vô hiệu khi Frida gắn vào actor) |

Mọi phần mở rộng chỉ cộng điểm cho chuỗi **đã qua** ba quy tắc của paper.

---

### Analysis module (`noirlycan_core`)

**Cấu trúc mới**

| Cũ | Mới |
|----|-----|
| `kernel/entities/models.py` | `models.py` |
| `kernel/classification/api_manifest.py` | `detection/api_classes.py` |
| `kernel/analysis/primitives.py`, `injection_graph.py` | `detection/` |
| `analysis/domain/correlation.py` (743 dòng) | `detection/correlator.py` + `rules.py` + `scoring.py` + `provenance.py` + `network_watch.py` |
| `kernel/classification/*`, `analysis/domain/classifier_config.py` | `classification/` (`config.py`) |
| `kernel/analysis/evasion.py`, `payload.py`, `network_policy.py` | `extensions/` |
| `analysis/domain/*`, `storage/infrastructure/*` | `analysis/*`, `storage/*` (bỏ lớp thư mục hình thức) |
| parser Frida trong agent | `trace/frida.py` |
| `agent/.../process_resolve.py` | `runtime/process_resolve.py` |

- `detection/rules.py`: ba quy tắc của paper (`has_minimal_core_operations`,
  `has_temporal_consistency`, `has_memory_congruence`) dạng hàm thuần, docstring trích §.
- Core không còn import gì từ agent (trước đây correlator, log_store, reclassify,
  batch_runner, sandbox_compare đều phụ thuộc ngược).
- Xóa các `__init__` dạng `import *` (một trong số đó gây circular import khi import
  `reclassify` đầu tiên).
- Mới: `trace/sysmon.py`, `extensions/kernel_evidence.py`, `runtime/command_signing.py`,
  `models.ProcessAccessEvent`, trường `MemoryPrimitive.source` (`"frida"` | `"sysmon"`).
- `classification/config.py`: thêm `update_classifier_config`, `upsert_custom_rule`,
  `delete_custom_rule` (logic kiểm hợp lệ chuyển từ view Django xuống domain).
- `analysis/reclassify.py`: replay cả Sysmon EID 8/10; giữ `source` của primitive.
- `storage/analysis_db.py`: thêm cột `agent_id`, `agent_path` (migration tự động); gom
  danh sách cột; xóa hàm chỉ dùng cho bản Django.
- `runtime/agent_identity.py`: lưu `command_key`; token mã hóa DPAPI trên Windows.

### Monitoring module (`noirlycan_agent`)

**Cấu trúc mới**

```
sensors/   frida_monitor.py · frida_hook_catalog.py · sysmon.py · file_watch.py · tcp_watch.py · wfp_watch.py
runtime/   collector.py · pipeline.py · file_intake.py · sample_runner.py · event_sink.py
           console_client.py · commands.py · triage.py · analysis_queue.py · policy_sync.py · collector_pid.py
lab/       batch_runner.py · sandbox_compare.py   (chuyển từ core)
```

- `cli.py` 999 dòng, 8 biến global → chỉ còn parser + dispatch (~150 dòng); logic tách vào
  `runtime/collector.py` (vòng lặp), `file_intake.py`, `sample_runner.py`.
- Vòng lặp đọc policy + runtime config **một lần mỗi tick** (trước đây 3–4 lần/giây).
- `event_sink.py`: `JsonlWriter` có khóa (triage chạy đa luồng); `BatchUploader` gửi
  ≤200 sự kiện / 0,5 s từ thread nền thay cho **một HTTP POST đồng bộ mỗi sự kiện** trong
  vòng lặp chính.
- `console_client.py`: chỉ còn HTTP client (hello/heartbeat/goodbye, ingest batch, tải
  sample, báo trạng thái, policy sync, pin key); poll lệnh tối đa 2 s/lần.
- `commands.py`: allowlist `kill`, `sample.run`; verify chữ ký trước khi chạy; `kill` từ
  chối PID 0/4/agent/tiến trình hệ thống và kiểm image hiện tại (chống PID reuse).
- `pipeline.py`: Sysmon EID 8 → primitive, EID 10 → `add_process_access`;
  `feed_primitive` dùng chung cho mọi sensor; in "Kernel evidence" trong finding.
- `sample_runner.py`: nhận `sample.run`, tải về `logs/samples/`, so SHA-256, đưa vào hàng
  đợi, báo spawned/failed kèm đường dẫn.
- `collector_pid.py` (trước là `collector_launcher.py`): bỏ phần khởi động/nâng quyền
  collector từ dashboard Django.
- Sửa `frida_monitor.py`: tham chiếu `_safe_int` sau khi chuyển parser (sẽ gây
  `NameError` khi auto-attach tiến trình con).
- Xóa: `collector/api.py` (health server), `triage_queue.py` (không dùng).

### Console (`noirlycan_backend`, `dashboard-ui`)

**Route mới**

| Route | Chức năng |
|-------|-----------|
| `POST /api/ingest/batch` | Nhận lô sự kiện (≤1000, mỗi sự kiện ≤256 KiB) |
| `/api/samples` (+ `/{id}/run`, `/{id}/report`, `DELETE /{id}`) | Upload `.exe/.dll`/`.jsonl`, gửi tới agent, báo cáo |
| `GET /api/agents/{id}/samples/{n}`, `POST …/status` | Agent tải sample (chỉ khi được giao), báo trạng thái |
| `/api/classifier` (+ `/rules/{id}`, `/custom/{id}`) | Rule phân loại kỹ thuật |
| `/api/analysis/corpus`, `/api/analysis/reclassify/{session}` | Thống kê corpus, replay |

- `ingest.py` viết lại: bắt buộc token riêng của agent + `X-Agent-Id`; gom auth lặp lại;
  giới hạn kích thước trường.
- `api/agent_auth.py`: dependency xác thực agent theo path.
- `console_db.py`: ký lệnh lúc đưa vào hàng đợi; phản hồi agent kèm `command_public_key`;
  `audit()`, `agent_was_sent_sample()`; so mật khẩu bằng `compare_digest`.
- `agent_deploy.py`: file config xuất cho agent có `command_key`.
- `agents.py`: bỏ lệnh legacy `noirlycan-telemetry` và endpoint đổi server token.
- `app.py`: `lifespan` thay `on_event` (deprecated); đăng ký router mới.
- `cli.py`: bỏ `batch`, `compare` (chuyển sang agent).
- React: tab **Samples** (`SamplesView.tsx`), client API tương ứng; bỏ kiểu dữ liệu legacy;
  form đăng nhập không điền sẵn mật khẩu.

### Giao diện (dashboard-ui)

- **Tông pastel** cho cả light và dark: bảng màu tập trung trong `theme.css`; mỗi màu
  severity/primitive có cặp nền nhạt + chữ đậm (`--sev-*-bg` / `--sev-*`), không còn chữ trắng
  trên nền đỏ/cam đặc. Gần 70 mã màu hard-code trong component được thay bằng biến CSS.
- Class dùng chung: `.chip` (`chip-CRITICAL…`, `chip-alloc|write|exec`, `chip-accent`),
  `.btn-danger` (nút Kill pastel), `.chip-x`; nút chính dạng pastel thay gradient đổ bóng.
- Style cho control gốc của trình duyệt: `select`, `input`, `checkbox`, `range`, nút chọn file,
  viền focus.
- **Findings:** chỉ hiện cờ đang bật (bỏ toàn bộ `x=false`), nhãn dễ đọc (`cross process`),
  sửa lỗi đếm "4 / 3 primitives" (từng tính cả `context_read`), đường dẫn rút về tên file
  (đường dẫn đủ trong tooltip), ẩn dòng tóm tắt trùng với tiêu đề dòng con.
- **Overview:** dòng Recent findings một dòng, cột primitive và thanh agent dạng pastel.
- **Rules:** chip API căn trái (trước bị `.badge` đẩy sang phải), chip chuỗi phát hiện pastel.
- **Activity:** bỏ file rác `__PSScriptPolicyTest_*.ps1` và `%TEMP%\frida-*` (lọc chung ở
  `noirlycan_core/runtime/noise.py`, dùng cả ở agent và backend): 30 → 9 file drop trên log
  thật; dòng chi tiết gọn (`sha256 … · entropy 7.90 · by explorer.exe`).
- **Agents:** token rút gọn (`ZpQW…87q`, bấm để copy) thay vì hiện nguyên văn; nút hành động
  xếp ngang; trạng thái dạng chip.
- **Network:** chip nguồn và card post-injection dạng pastel.
- Backend không còn trả tag `x=false` cho nhóm finding.

### Agent: cài đặt một lệnh và hiệu năng

- **Cài một lệnh:** tab Agents có nút **Copy install** — một dòng PowerShell (Admin) trên VM
  tải gói agent từ console, tạo venv, cài Frida/pywin32, cài Sysmon với config lab, ghi
  `C:\Noirlycan\noirlycan-agent.toml`, tạo `run-agent.ps1` và chạy. Endpoint mới (đều yêu cầu
  token của chính agent): `GET /api/agents/{id}/bootstrap.ps1`, `/package.zip` (chỉ gồm
  `noirlycan_core` + `noirlycan_agent`, tự build lại khi code đổi), `/sysmon-config.xml`.
- **Không đọc lại file mỗi tick:** policy, runtime config và classifier config đọc qua
  `runtime/cached_json.py` — chỉ parse lại khi mtime/size đổi.
- **Frida:** chỉ build lại hook script khi version policy đổi.
- **Correlator:** dọn trạng thái cũ (file, handle, mạng) tối đa 1 lần/giây thay vì sau mỗi event.
- **Log nhẹ hơn:** trên log thật, Sysmon EID 10 chiếm 52 % dung lượng và bản sao thô của message
  Frida thêm 20 %. Mặc định không ghi hai loại này nữa (bằng chứng call stack vẫn nằm trong
  evidence của finding); bật lại bằng `--raw-events`.
- **Sửa replay:** `reclassify` từng đếm mỗi primitive hai lần với session cũ (có cả `frida_raw`
  và `primitive`). Primitive gắn vào finding: 613 → 340; số finding, điểm, kỹ thuật không đổi.

### Thesis: tài liệu tham khảo và số liệu

- Viết lại danh sách tài liệu tham khảo theo thông tin thật (đối chiếu bibliography của [7]):
  Klein & Kotler 2019 (Black Hat USA), Starink et al. 2023 (SecureComm), Barabosch et al. 2017
  (Quincy, DIMVA); thay hai nguồn không xác minh được bằng D'Elia et al. 2020 (IEEE TIFS) và
  Galloro et al. 2022 (Computers & Security); bỏ nguồn không liên quan. Đánh số lại toàn bộ
  trích dẫn trong thesis.
- Đồng bộ số test (59 test methodology, tổng 129) và số kỹ thuật (36) ở Mở đầu, Chương 4, 6, 7,
  Kết luận, Tóm tắt, Thông tin luận văn; sửa nốt các câu còn gán 21,2 % cho anti-evasion.
- Sửa đánh số mục trùng/nhảy trong Chương 4.

### Kill process: chỉ TERMINATED khi agent xác nhận

- Trước đây UI đổi sang TERMINATED ngay khi backend nhận lệnh, dù agent chưa kill (hoặc kill
  thất bại). Giờ lệnh kill có trạng thái `pending` → `terminated` / `failed` / `expired`.
- Agent kill xong kiểm tra tiến trình đã thật sự biến mất (liveness không cache, chờ tối đa
  ~1 s) rồi báo `POST /api/agents/{id}/commands/{command_id}/result`; chỉ agent nhận lệnh mới
  báo được.
- UI: `Killing…` khi chờ, `TERMINATED` khi thành công, `Kill failed` / `Kill expired (agent
  offline)` kèm nút **Retry kill**; tự refresh mỗi 2 s khi còn lệnh đang chờ.
- Các bản ghi kill cũ (trước thay đổi này) được giữ trạng thái `terminated` vì không có kết quả
  để đối chiếu.

### Bảo mật

| Vấn đề | Mức | Sửa |
|--------|-----|-----|
| JWT secret mặc định `noirlycan-console-dev-secret` công khai trong repo → ai cũng ký được token Admin | Nghiêm trọng | Secret ngẫu nhiên lưu `logs/.jwt_secret` (0600), hoặc `NOIRLYCAN_CONSOLE_JWT_SECRET` |
| Tài khoản mặc định `admin/admin`, `analyst/analyst`, `viewer/viewer` | Cao | Chỉ tạo `admin@lab` với mật khẩu ngẫu nhiên / env; demo qua `NOIRLYCAN_DEMO_USERS=1` |
| `resolve_log_path` fallback `Path(name)` → `/api/sessions/{name}/export` đọc được file trong CWD backend | Cao | Giới hạn trong `logs/`, bắt buộc `.jsonl` |
| Ingest bằng server token không cần agent id → ghi vào file `body.session` tùy ý | Cao | Bỏ nhánh này; backend tự chọn file session |
| Lệnh `kill` không ký, agent chạy `taskkill /F` | Cao | Ed25519 + agent_id + hạn 10 phút + nonce; allowlist; validator |
| Token agent plaintext trên VM | Trung bình | DPAPI trên Windows |
| Secret và DB trạng thái bị commit | Cao | Bỏ track; bổ sung `.gitignore` — **cần rotate** |

### Xóa

- `noirlycan_dashboard/legacy/` (Django + Channels + Jet, ~3.600 dòng gồm JS) — upload,
  classifier rules, reclassify, corpus đã port sang FastAPI.
- `noirlycan_telemetry/`, `noirlycan_console/` (shim deprecated) và entry point tương ứng.
- `noirlycan_core/storage/api.py`, `analysis/api.py`, `noirlycan_core/contracts/` và
  service `storage-api`/`analysis-api` trong `docker-compose.yml`.
- `Dockerfile` gốc (không dùng); test Django (`test_dashboard_runtime`,
  `test_dashboard_websocket`, `test_upload_api`).

### Build / phụ thuộc

- Package đổi tên `noirlycan-telemetry` → `noirlycan`, version 0.3.0.
- Thêm `cryptography` (ký lệnh), `python-multipart` (upload), `httpx` (test).
- Bỏ extra `dashboard`, `console` (Django, Channels, Daphne, Jet).
- `Dockerfile.backend` cài `.[backend]` (trước đây thiếu FastAPI).
- `.gitignore`: `logs/.jwt_secret`, `.command_signing_key`, `uploads/`, `samples/`,
  `agents/`, `.analysis_queue.json`, `.collector.pid`, `*.egg-info/`.

### Test

- Mới: `test_paper_rules.py` (từng quy tắc paper), `test_kernel_sensors.py` (Sysmon,
  call stack, observer effect, báo lại chuỗi ở trần điểm), `test_agent_runtime.py`
  (batch uploader, writer đa luồng, lệnh ký/giả/hết hạn/replay), `test_samples_api.py`
  (luồng sample, phân quyền agent, path traversal, ingest batch), `conftest.py` (client
  FastAPI).
- Port sang FastAPI: API trong `test_classifier_config.py`.
- Cập nhật: `test_network_watch.py` (test lỗi thời, fail từ trước), `test_api_analysis_session.py`,
  `test_remote_client_policy.py`, `test_collector_pid.py`.

### Tài liệu

- Mới: `docs/code-map.md`, `docs/proposal-kernel-telemetry.md`,
  `docs/proposal-platform-architecture.md`, `CHANGELOG.md`.
- `README.md`, `deploy/README.md`: kiến trúc, đăng nhập, Samples, biến môi trường, CLI,
  giới hạn.
- `docs/clean-architecture-plan.md`: thay bằng ghi chú trỏ sang tài liệu hiện hành.
- **Sửa trích dẫn paper** (đối chiếu PDF) trong thesis và `docs/`:
  - tracer là **BluePill/Intel Pin (DBI)**, không phải "QEMU / custom tracer";
  - **21,2 %** = công cụ công khai bỏ sót (VirusTotal 24,0 %, CAPE 18,3 %); ablation
    anti-evasion là **6,2 % (Detours) vs 11,8 % (BluePill)**; overhead 1,35 %;
  - **RQ1–RQ3** theo nguyên văn paper;
  - khử trùng lặp bằng **vhash + AVClass**, không phải imphash/ssdeep.
- **Chương 6 (Thiết kế & hiện thực) viết lại** theo code hiện tại; các chương khác cập nhật
  đường dẫn code, bỏ mô tả Django; `thesis/luan-van-day-du.md` và `_assembled/` tạo lại.
- Chưa cập nhật: số liệu đánh giá Chương 7 ("31 test", số đếm test).

### Chưa làm (xem các proposal)

- Sensor ETW Threat-Intelligence (cần native + PPL/ELAM).
- Enrollment token ngắn hạn, client cert / mTLS.
- Audit log bất biến (hash chain).
- Giao diện sửa classifier rule (API đã có).
- Xác nhận trên VM giả thuyết observer effect (frame `UNKNOWN` là trampoline Frida).
