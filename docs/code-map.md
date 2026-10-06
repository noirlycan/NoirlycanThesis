# Bản đồ code ↔ paper

Code được tổ chức theo đúng hai module trong Figure 1 của Di Pietro et al.
(ASIA CCS '25, §3.3): **monitoring module** thu trace API trên máy chạy mẫu,
**analysis module** phát hiện rồi phân loại. Paper dùng BluePill/Pin làm
monitoring module và khẳng định phương pháp "can be integrated into any
dynamic analysis system that intercepts API calls" — Noirlycan thay nó bằng
nhiều sensor (Frida + Sysmon) mà không đổi analysis module.

```
noirlycan_agent/                      MONITORING MODULE (Windows lab VM)
  sensors/                            mỗi sensor biến hoạt động OS thành event
    frida_monitor.py, frida_hook_catalog.py   hook user-mode (API + đối số)
    sysmon.py                         kernel callbacks: EID 1/3/7/8/10/11
    file_watch.py                     thư mục thả file
    tcp_watch.py, wfp_watch.py        kết nối mạng sau injection
  frida_hooks/*.js                    hook script
  runtime/
    collector.py                      vòng lặp: đọc policy 1 lần/tick → poll sensor → detector
    pipeline.py                       event sensor → Correlator (feed_primitive)
    file_intake.py                    [mở rộng] file thả xuống → triage → chạy dưới Frida
    sample_runner.py                  spawn sample dưới Frida, sample do console gửi
    event_sink.py                     JSONL cục bộ + upload batch nền lên console
    console_client.py                 HTTP tới console, policy sync, pin khóa ký lệnh
    commands.py                       allowlist lệnh + validator (kill, sample.run)
    triage.py                         triage tĩnh (SHA-256, PE, chữ ký, entropy)
  lab/                                nghiên cứu offline: batch, so sánh Defender/VT

noirlycan_core/                       ANALYSIS MODULE (thuần, không I/O OS)
  models.py                           PrimitiveKind, MemoryPrimitive(source=…), Finding, …
  trace/
    frida.py                          message hook Frida → MemoryPrimitive
    sysmon.py                         EID 8 → EXECUTE primitive; EID 10 → ProcessAccessEvent
  detection/                          phát hiện (§3.1–3.2)
    api_classes.py                    lớp tương đương API (§3.1, Appendix B)
    primitives.py                     execute thật vs. context-read
    rules.py                          3 quy tắc: 2/3, memory congruence, temporal
    correlator.py                     chuỗi (actor, victim) theo cửa sổ thời gian
    injection_graph.py                chuỗi inject đệ quy A→B→C (§3.1)
    scoring.py                        [mở rộng] điểm rủi ro + severity
    provenance.py                     [mở rộng] file thả xuống → lineage tiến trình
    network_watch.py                  [mở rộng] kết nối sau injection
  classification/                     phân loại kỹ thuật (sau phát hiện)
  extensions/
    kernel_evidence.py                [mở rộng] call stack kernel, đối chiếu chéo sensor
    evasion.py, payload.py, network_policy.py
  analysis/                           replay (reclassify), thống kê corpus
  storage/                            JSONL session, SQLite phân tích
  runtime/                            policy, identity (DPAPI), ký lệnh Ed25519, config

noirlycan_backend/                    CONSOLE (máy analyst)
  api/routes/
    ingest.py                         kênh agent: hello/heartbeat/goodbye, ingest batch
    samples.py                        upload sample → lệnh sample.run → báo cáo
    classifier.py, rules.py           rule phân loại kỹ thuật, ruleset phát hiện
    analysis.py                       corpus, reclassify
    findings.py, sessions.py, agents.py, users.py, auth.py, …
  infrastructure/console_db.py        SQLite console (user, agent, lệnh đã ký, audit)
```

Quy ước: những gì có trong paper nằm ở `detection/rules.py`, `api_classes.py`,
`primitives.py`, `correlator.py`, `injection_graph.py`. Mọi thứ đánh dấu
**[mở rộng]** là đóng góp riêng của luận văn và **không bao giờ** biến một chuỗi
đã trượt quy tắc của paper thành finding.

## Luồng xử lý một primitive

```
sensor (Frida hook | Sysmon EID 8)
  → trace/*.py                          MemoryPrimitive(source="frida"|"sysmon")
  → provenance.enrich()                 điền tên image actor/victim
  → gom theo (actor_pid, target_pid), bỏ phần ngoài cửa sổ thời gian
  → rules: has_minimal_core_operations  (≥2/3, CONTEXT_READ không tính)
           has_temporal_consistency     (allocate → write → execute; đổi quyền vùng nhớ được miễn)
           has_memory_congruence        (vùng nhớ giao nhau)
  → scoring.score_chain()               điểm + evidence
  → kernel_evidence()                   direct syscall / caller unbacked / hook bị bypass
  → báo khi điểm tăng HOẶC chuỗi có thêm bước
  → classification.apply_classification()
  → injection_graph.add_finding()       đánh dấu chuỗi đệ quy
  → network_watch.watch(victim)         nếu score ≥ 70
```

## Sensor và độ tin cậy

| Sensor | Privilege | Cho detector | Bị né bởi |
|--------|-----------|--------------|-----------|
| Frida hook | user | ALLOCATE/WRITE/EXECUTE kèm địa chỉ, kích thước, quyền | direct/indirect syscall, unhook, anti-Frida |
| Sysmon EID 8 | kernel | EXECUTE (remote thread); địa chỉ bắt đầu nếu unbacked | đối thủ kernel |
| Sysmon EID 10 | kernel | bằng chứng: quyền handle + call stack | đối thủ kernel |
| ETW Threat-Intelligence | kernel | ALLOCATE/WRITE/EXECUTE kèm địa chỉ | đối thủ kernel — **chưa hiện thực**, xem `proposal-kernel-telemetry.md` |

Observer effect: khi Frida gắn vào actor, trampoline của Frida xuất hiện như
frame `UNKNOWN` trong call stack của Sysmon, nên dấu hiệu "caller unbacked"
chỉ được tính điểm khi actor không bị Frida instrument.

## Kênh console ↔ agent

- Agent xác thực bằng enrollment token riêng (bắt buộc `X-Agent-Id`); token lưu
  bằng DPAPI trên Windows.
- Event gửi theo batch từ thread nền; backend tự chọn file session, không bao
  giờ dùng tên file do agent gửi.
- Lệnh console → agent được ký Ed25519 (`runtime/command_signing.py`); agent
  pin public key từ file config và từ chối lệnh không ký, sai chữ ký, gửi cho
  agent khác, hết hạn (10 phút) hoặc replay. Allowlist: `kill`, `sample.run`.
- `kill` từ chối PID hệ thống/của chính agent và kiểm image hiện tại của PID
  (chống PID reuse).

## Kiểm chứng

- `tests/test_paper_rules.py`: từng quy tắc của paper dưới dạng hàm thuần.
- `tests/test_kernel_sensors.py`: Sysmon làm sensor thứ hai, call stack, observer effect.
- `tests/test_agent_runtime.py`, `tests/test_samples_api.py`: batch upload, lệnh ký, kênh sample.
- Mỗi bước refactor được kiểm bằng cách replay 20 session thật trong `logs/` qua
  code cũ và mới; kết quả khớp, trừ bản sửa temporal (re-protect) có chủ đích.
