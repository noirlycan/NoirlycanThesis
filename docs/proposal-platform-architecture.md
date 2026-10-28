# Đề xuất: áp dụng mô hình Centralized Agent Management vào Noirlycan

**Đi kèm:** [proposal-kernel-telemetry.md](proposal-kernel-telemetry.md) — tài liệu đó
thay lớp sensor; tài liệu này lo phần **quản lý agent + sensor** để việc thay
sensor triển khai được an toàn.

**Nguồn tham khảo:** một template kiến trúc "Microservices + Centralized Agent
Management" (Control Plane / Data Plane, Agent Gateway, enrollment, mTLS,
plugin, artifact ký số, config phân cấp, audit…). Template gốc bị cắt ở mục 28
(*Command Security*); phần đó được hoàn thiện ở §4.4 dưới đây.

---

## 1. Quyết định phạm vi

Template được viết cho fleet production (1k → 1M agent). Noirlycan là lab
luận văn với vài VM. Áp nguyên template (Kafka, Temporal, Keycloak, database per
service, scale 1M agent) sẽ làm loãng trọng tâm luận văn — vốn là **replication
phương pháp của Di Pietro et al.** — và tạo thêm một khối hạ tầng phải bảo vệ
trước hội đồng mà không đóng góp gì cho câu hỏi nghiên cứu.

**Khuyến nghị:** *modular monolith* cho backend + **một ranh giới rõ ràng duy
nhất là Agent Gateway**, và lấy từ template những pattern **phục vụ trực tiếp**
hai mục tiêu:

1. Triển khai và vận hành nhiều sensor (TI, Sysmon, Kernel-Process ETW, Frida)
   như các plugin có cấp tin cậy khác nhau.
2. Làm cho kênh agent ↔ backend **không trở thành điểm yếu** khi agent giữ quyền
   cao hơn (service PPL, kill process).

| Pattern trong template | Quyết định | Lý do |
|------------------------|-----------|-------|
| Control Plane / Data Plane | **Áp dụng** | Đã có sẵn ở dạng backend / agent, chỉ cần gọi tên và vẽ lại ranh giới |
| Agent Gateway tách riêng | **Áp dụng (dạng module)** | Gom auth agent, session, command dispatch về một chỗ; trước mắt chạy chung process với backend |
| Enrollment token ngắn hạn + cert theo agent + mTLS (§26–27) | **Áp dụng** | Lỗ hổng thật của repo hiện tại (§2) |
| Command typed + ký số (§28) | **Áp dụng** | Agent có lệnh `kill`; sắp có service PPL |
| Plugin architecture (§13) | **Áp dụng cho sensor** | Khớp 1:1 với kiến trúc sensor nhiều lớp |
| Artifact ký số + verify (§14) | **Áp dụng gọn** | Bắt buộc khi phân phối binary TI sensor / hook bundle |
| Config phân cấp + versioning (§16) | **Áp dụng gọn** | Đã có `AgentPolicy.version`; thêm tầng group/agent |
| Audit immutable (§23) | **Áp dụng gọn** | Đã có `console_audit_log`, chỉ thiếu tính bất biến |
| Event bus (NATS JetStream) | **Tùy chọn, để sau** | Lợi ích thật chỉ đến khi tách được analysis ra worker riêng |
| Canary / rolling update (§15) | **Bỏ** | Vài VM snapshot, revert snapshot rẻ hơn |
| Database per service, ClickHouse, Kafka | **Bỏ** | Không có tải tương ứng |
| Keycloak / OIDC, Temporal, Workflow engine | **Bỏ** | Over-engineering so với scope; ghi vào Future Work |
| Scale 100k–1M agent | **Bỏ** | Không đo được trong lab, không nên claim |

---

## 2. Hiện trạng repo so với template

| Khía cạnh | Hiện tại | Vấn đề | Mục template |
|-----------|----------|--------|--------------|
| Enrollment | Token tạo lúc register, **dùng mãi**, in nguyên vào `run_command` hiển thị trên UI (`backend/api/routes/agents.py:45-50`); còn có thêm một server token dùng chung (legacy) | Lộ token = mạo danh agent vô thời hạn | §27 |
| Lưu credential trên agent | `.agent_identity.json` chứa token plaintext (`core/runtime/agent_identity.py:58-73`) | Malware trên VM đọc được trực tiếp | §25–26 |
| Xác thực agent | Bearer token so khớp DB (`routes/ingest.py:44-54`) | Không có mTLS, không bind được danh tính vào kênh | §26 |
| Transport | HTTP poll (`hello`/`heartbeat`/`commands`) | Chấp nhận được cho lab; không cần đổi ngay | §8 |
| Command | `{pid, image}` không ký, agent poll rồi chạy `taskkill /F` (`remote_sink.py:328`) | Ai giả được backend hoặc chèn được vào DB là kill được process tùy ý trên VM | §28 |
| Policy | Một ruleset global + cờ `auto_kill` theo agent, `version: int` | Thiếu tầng group, thiếu lịch sử version, thiếu rollback | §16 |
| Sensor | Gắn cứng trong collector (Frida, Sysmon, file watch, WFP) | Không thêm được TI sensor theo cách sạch, không khai báo được trust tier | §13 |
| Phân phối binary | `git clone` + `pip install` trên VM | Không có checksum/chữ ký; với binary PPL thì bắt buộc phải có | §14 |
| Audit | Bảng `console_audit_log` trong SQLite (`console_db.py:187,987`) | Sửa/xóa được; chưa audit login, policy change, enrollment | §23 |

---

## 3. Điểm khác biệt quan trọng so với template: agent chạy trên máy *cố tình bị nhiễm*

Template giả định endpoint đáng tin, agent là "người nhà". Ở Noirlycan, agent
chạy **trên chính VM đang chạy malware**. Hệ quả cho thiết kế — và đây là ý đáng
đưa vào Chương 4 (Threat Model):

1. **Mọi dữ liệu agent gửi lên là input không tin cậy.** Tên process, command
   line, đường dẫn file đều do malware kiểm soát → backend phải giới hạn kích
   thước, validate schema, và dashboard phải escape khi render (XSS qua
   `CommandLine` là kịch bản thật).
2. **Credential của agent phải giả định là có thể bị lộ.** Quyền của một agent
   chỉ được: ghi dữ liệu của chính nó, nhận command của chính nó. Không đọc dữ
   liệu agent khác, không gọi API của analyst. Revoke phải có hiệu lực ngay.
3. **Hướng tin cậy của command là từ backend xuống agent.** Agent phải xác minh
   được command đúng là do backend phát (ký số), còn hiệu lực và chưa từng
   được dùng — vì mạng lab cũng có thể bị malware nghe lén hoặc giả mạo.
4. **Sensor kernel (PPL) là thành phần có quyền cao nhất trên VM** → binary và
   cấu hình của nó chỉ được đến từ artifact đã ký, không bao giờ từ input agent.

---

## 4. Thiết kế đề xuất

### 4.1. Sơ đồ

```
            Analyst (browser)
                  │  HTTPS + session/JWT (RBAC hiện có)
                  ▼
     ┌──────────── noirlycan-backend (modular monolith) ─────────────┐
     │  api/        users · rules · findings · reports · agents      │
     │  agent_gw/   enrollment · mTLS auth · heartbeat · command     │◄── mTLS ──┐
     │              dispatch (ký Ed25519) · ingest (schema-validate) │           │
     │  policy/     global → group → agent, có version + rollback    │           │
     │  artifacts/  manifest + SHA256 + chữ ký cho sensor/hook/rule   │           │
     │  detection/  rules.py + correlator.py (GIỮ NGUYÊN logic paper) │           │
     │  audit/      append-only, hash-chain                           │           │
     │  SQLite (lab) ── có thể đổi PostgreSQL mà không đổi module     │           │
     └────────────────────────────────────────────────────────────────┘           │
                                                                                  │
     ┌──────────── Windows lab VM ────────────────────────────────────┐           │
     │  noirlycan-agent (core runtime)                                 │───────────┘
     │    ├─ sensor: ti        [PPL service, native, tier=kernel]     │
     │    ├─ sensor: sysmon    [tier=kernel]                          │
     │    ├─ sensor: kproc-etw [tier=kernel]                          │
     │    ├─ sensor: frida     [tier=user, chỉ enrichment]            │
     │    ├─ sensor: file-watch / wfp                                  │
     │    └─ executor: allowlist command (kill, set-policy, ...)      │
     └─────────────────────────────────────────────────────────────────┘
```

`agent_gw/` là một package riêng với interface rõ ràng (chỉ nó được import
code xác thực agent), để sau này tách thành process riêng chỉ bằng việc đổi cách
deploy. Đó là phần "microservice-ready" có thể bảo vệ được, mà không phải trả
giá vận hành của microservice thật.

### 4.2. Enrollment và danh tính agent (template §26–27)

```
Analyst bấm "Register"
   → backend tạo enrollment token: TTL 15 phút, dùng một lần, scope = agent_id
Agent lần đầu chạy
   → tự sinh keypair (private key không rời máy; dùng DPAPI/CNG để bảo vệ)
   → gửi CSR + enrollment token
Backend
   → kiểm token (còn hạn, chưa dùng, đúng scope) → đánh dấu đã dùng
   → ký client cert ngắn hạn (vd. 7 ngày, CN = agent_id) bằng CA nội bộ của lab
   → trả về cert + CA cert + public key dùng để verify command
Từ đó về sau
   → mọi kết nối agent ↔ agent_gw đều mTLS; backend lấy agent_id từ cert,
     không lấy từ body request
   → agent tự gia hạn cert trước khi hết hạn; revoke = đưa vào danh sách chặn
     ở agent_gw (lab nhỏ, không cần OCSP)
```

Bỏ: in token vào `run_command` trên UI, server token dùng chung, token
plaintext trong `.agent_identity.json`.

### 4.3. Sensor như plugin (template §13) — nối với tài liệu kernel telemetry

Manifest của mỗi sensor khai báo luôn **cấp tin cậy** mà correlator sẽ dùng:

```json
{
  "name": "ti",
  "version": "0.1.0",
  "platform": ["windows"],
  "kind": "sensor",
  "privilege": "ppl-antimalware-light",
  "trust_tier": "kernel",
  "role": "detection",
  "emits": ["ALLOCATE", "WRITE", "EXECUTE"],
  "fields": ["actor_pid", "target_pid", "address", "size", "protection", "stack"],
  "artifact": { "sha256": "…", "signature": "…", "signer": "noirlycan-lab-release" }
}
```

```json
{
  "name": "frida",
  "trust_tier": "user",
  "role": "enrichment",
  "emits": ["API_SEMANTICS"]
}
```

Quy tắc trong correlator: điều kiện 2/3 chỉ được thỏa bởi primitive từ sensor
`role=detection`. Primitive từ `role=enrichment` chỉ phục vụ phân loại kỹ thuật
và cross-layer differential. Như vậy nguyên tắc *detection ở kernel /
classification được dùng user-mode* (proposal-kernel-telemetry §3.1) được thể
hiện ngay trong dữ liệu, không phải chỉ nằm trong tài liệu.

Bật/tắt sensor theo agent hoặc group từ console → hiện thực luôn các cấu hình
ablation (`Frida-only`, `K1+K2`, `K1+K2+U+C`) mà không phải sửa tay trên VM.

### 4.4. Command security (hoàn thiện template §28)

Nguyên tắc: **server không bao giờ gửi chuỗi lệnh tùy ý**. Agent chỉ thực thi
các command có kiểu được định nghĩa sẵn, có tham số được kiểm, và có chữ ký.

```json
{
  "command_id": "uuid",
  "agent_id": "WIN-LAB01-1a2b3c4d",
  "type": "process.kill",
  "params": { "pid": 4312, "expected_image": "C:\\Users\\lab\\Desktop\\loader.exe" },
  "issued_by": "analyst@lab",
  "issued_at": "2026-10-02T08:00:00Z",
  "expires_at": "2026-10-02T08:02:00Z",
  "nonce": "…",
  "sig": "ed25519(…)"
}
```

Agent kiểm theo thứ tự, sai một bước là từ chối và báo về:

1. Chữ ký hợp lệ với public key nhận được lúc enrollment.
2. `agent_id` đúng là chính nó.
3. Chưa hết hạn; `nonce` chưa từng thấy (chống replay).
4. `type` nằm trong allowlist cục bộ của agent (allowlist build sẵn trong
   agent, không nhận từ server).
5. Tham số qua validator riêng của từng type. Ví dụ `process.kill`: image
   thực tế của PID phải khớp `expected_image` (chống PID reuse), và không bao giờ
   kill process hệ thống hay chính agent/sensor.
6. Thực thi → gửi kết quả có `command_id` → backend ghi audit.

Allowlist ban đầu: `process.kill`, `policy.apply`, `sensor.enable`,
`sensor.disable`, `capture.start`, `capture.stop`. Không có `shell.exec`.

Mọi quyết định có hậu quả (auto-kill, kill thủ công) vẫn do người chịu trách
nhiệm ở phía lab quyết; hệ thống chỉ thực thi lệnh đã được ủy quyền và ghi audit.

### 4.5. Artifact ký số (template §14) — gọn cho lab

- Mỗi artifact (TI sensor + ELAM driver, hook bundle của Frida, ruleset) có
  manifest: `name, version, platform, arch, sha256, size, created_at,
  created_by, signature`.
- Ký bằng một release key riêng, tách khỏi key ký command. Private key không
  được commit vào repo và không nằm trên backend lab; ký offline trên máy của
  tác giả.
- Agent verify chữ ký + SHA256 trước khi cài. TI sensor còn được Windows kiểm
  thêm signer theo cơ chế PPL — đó là hai lớp kiểm độc lập.
- Lưu trữ: thư mục local / MinIO là đủ; không cần S3.

### 4.6. Policy phân cấp (template §16)

`global → group (vd. "ablation-frida-only") → agent`, merge theo key, agent đè
group, group đè global. Mỗi lần lưu tạo một version bất biến (`version`, `hash`,
`author`, `created_at`, `diff`); agent báo lại version đang áp dụng qua
heartbeat → console thấy agent nào lệch version. Rollback = trỏ lại version cũ.

Đặc biệt quan trọng cho luận văn: mỗi finding ghi lại **policy version + bộ
sensor đang bật** lúc phát hiện → kết quả thí nghiệm tái lập được.

### 4.7. Audit (template §23)

Giữ bảng hiện có, thêm:
- Các action còn thiếu: `auth.login`, `auth.logout`, `agent.enroll`,
  `agent.revoke`, `policy.publish`, `sensor.toggle`, `command.issue`,
  `command.result`, `artifact.publish`.
- **Append-only + hash chain:** mỗi bản ghi lưu `prev_hash` và
  `hash = SHA256(prev_hash ‖ bản ghi)`; thêm lệnh `noirlycan-backend audit
  verify` để kiểm toàn chuỗi. Đủ để chứng minh tính bất biến trong lab mà không
  cần ClickHouse/WORM storage.

### 4.8. Transport: giữ HTTP, có đường nâng cấp

Ở quy mô lab, HTTP poll 1–2 giây trên mTLS là đủ, lại dễ debug. Nếu cần push
command gần realtime thì nâng lên **WebSocket trên cùng kết nối mTLS** ở
`agent_gw/` (backend đã có `routes/ws.py` cho dashboard). gRPC streaming / NATS
chỉ đáng làm khi tách analysis ra worker riêng — ghi vào Future Work.

---

## 5. Lộ trình — xếp theo độ phụ thuộc với kế hoạch sensor

| Bước | Việc | Phụ thuộc | Ghi chú |
|------|------|-----------|---------|
| P1 | Manifest sensor + `trust_tier`/`role` + correlator chỉ lấy `role=detection` cho 2/3 | Bước 1–2 của kế hoạch sensor | Cho ra kết quả nghiên cứu sớm nhất |
| P2 | Command typed + ký Ed25519 + nonce/expiry + validator cho `process.kill` | — | Sửa rủi ro hiện hữu (kill không ký) |
| P3 | Enrollment token TTL/single-use, bỏ token khỏi `run_command`, bỏ server token dùng chung | — | |
| P4 | CA lab + client cert + mTLS ở `agent_gw/`; private key bảo vệ bằng DPAPI | P3 | Nên xong trước khi cài TI sensor (PPL) |
| P5 | Artifact manifest + verify trước khi cài | P1 | Bắt buộc trước bước 4 (TI sensor) của kế hoạch sensor |
| P6 | Policy phân cấp + version + ghi policy/sensor set vào finding | P1 | Phục vụ ablation |
| P7 | Audit hash-chain + action còn thiếu | — | |
| P8 | Schema validation + giới hạn kích thước ở ingest; rà escape trên dashboard | — | Hệ quả trực tiếp của §3 |

---

## 6. Cách đưa vào luận văn

- **Chương 4 (Threat Model):** thêm §3 của tài liệu này — agent chạy trên host
  thù địch, dữ liệu agent là untrusted, kênh command phải xác thực.
- **Chương 6 (Thiết kế):** Control/Data plane, Agent Gateway, sensor plugin có
  `trust_tier`, command ký số. Trình bày là *thiết kế để thí nghiệm tái lập
  được và an toàn*, không phải *nền tảng quản lý endpoint*.
- **Chương 7 (Đánh giá):** ablation theo sensor được điều khiển qua policy
  group; mỗi finding gắn policy version.
- **Không claim:** khả năng scale, high availability, hay "sẵn sàng production".
  Template có các mục đó, nhưng lab không đo được.
- **Future Work:** tách `agent_gw`/analysis thành service riêng + NATS
  JetStream, OIDC (Keycloak), rolling update agent.
