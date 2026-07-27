# Kịch bản demo live — Seminar Noirlycan (~5–7 phút)

**Mục tiêu demo:** Cho thầy thấy luồng **file-drop → finding → (optional) network** trên dashboard real-time.

**Thời gian:** 5–7 phút trong tổng 30 phút seminar.

---

## Chuẩn bị trước buổi seminar (checklist)

### Mac / server lab

- [ ] Repo cập nhật, venv active: `pip install -e ".[lab]"`
- [ ] Backend chạy: `noirlycan-backend api --host 0.0.0.0 --port 8888`
- [ ] Dashboard: `cd dashboard-ui && npm run dev -- --host 0.0.0.0`
  - Hoặc: `python scripts/lab_stack.py up`
- [ ] Mở browser: `http://<IP-Mac>:5173` — login `admin@lab` / `admin`
- [ ] Tab **Agents** — agent `vm01` đã register, có token

### Windows VM

- [ ] Python venv + `pip install -e ".[agent]"`
- [ ] Sysmon cài + **Running** (verify: `Get-Service Sysmon64`, `notepad` → có EID 1)
- [ ] Agent Admin:
  ```powershell
  noirlycan-agent run --server <IP-Mac>:8888 --agent-id vm01 --token <TOKEN> --watch-sysmon --auto-attach-new-processes
  ```
- [ ] Dashboard **Agents** → vm01 **online**
- [ ] Loader `.exe` lab sẵn (vd. `aes_decrypt_loader - Copy.exe`) — **chưa** copy vào folder watch

### Folder watch mặc định agent

- `D:\`
- `C:\Users\Public\Downloads`

---

## Plan A — Demo đầy đủ (Sysmon OK)

### Bước 1 — Overview (30 giây)

**Nói:**

> Đây là console Noirlycan: backend FastAPI trên Mac, agent Windows VM gửi telemetry qua HTTP. Overview cho thấy KPI findings, file drops, agent online.

**Làm:**

- Mở tab **Overview**
- Chỉ agent **vm01 online**
- (Nếu có data cũ) nói sẽ demo session mới hoặc filter theo agent

---

### Bước 2 — File drop (1 phút)

**Nói:**

> Luồng bắt đầu từ file: malware thường drop loader xuống disk trước khi inject. Agent watch folder và Sysmon E11 ghi file create.

**Làm:**

1. Trên VM: copy `.exe` **mới** vào `D:\` hoặc `Downloads`
2. Dashboard → tab **File drops**
3. Chỉ dòng file vừa copy: path, hash, triage score

**Kỳ vọng:** File xuất hiện trong vài giây.

---

### Bước 3 — Finding / injection chain (2 phút)

**Nói:**

> Frida auto-attach process mới. Correlator áp quy tắc 2-of-3 từ paper ASIA CCS: allocate, write, execute — không phụ thuộc tên API cố định.

**Làm:**

1. Tab **Findings**
2. Mở nhóm **actor → target** (loader → process bị inject)
3. Chỉ các API: `NtAllocateVirtualMemory`, `NtMapViewOfSection`, `SetThreadContext`…
4. Score (vd. 70–100), technique label (vd. `process_hollowing_section`)
5. **Related file** — liên kết file-drop (E3 provenance)

**Kỳ vọng:**

- Finding severity HIGH/CRITICAL
- Terminal agent in `[+] Frida attached` và finding summary

---

### Bước 4 — Target process name (30 giây)

**Nói:**

> Sysmon EID 1 bổ sung tên process đích; nếu thiếu Sysmon sẽ hiện `unknown (pid …)` — đó là limitation E3/E4 em ghi trong luận văn.

**Làm:**

- Chỉ dòng target: tên `.exe` hoặc `unknown (pid N)`
- Nếu có tên → nhấn Sysmon đã enrich

---

### Bước 5 — Network / beacon (1 phút, optional)

**Nói:**

> Sau finding CRITICAL, agent bật network watch 5 phút trên **target PID** — chỉ Sysmon E3 outbound. Beacon = kết nối ra IP/hostname ngoài private range.

**Làm:**

1. Tab **Network**
2. Nếu loader có outbound: card **BEACON?** + destination `ip:port`
3. Agent terminal: `[NETWORK:BEACON?] PID … -> …`

**Nếu không có network:** nói loader lab không beacon — rule vẫn hoạt động, chỉ không có event.

---

### Bước 6 — Rules (30 giây)

**Nói:**

> Policy có thể chỉnh từ dashboard: min primitives 2-of-3, capture window, network watch duration — agent pull rules khi startup và heartbeat.

**Làm:**

- Tab **Rules** — chỉ min primitives, net watch 5 min

---

### Kết demo Plan A

**Câu chốt:**

> Trong lab vài phút, ta thấy full pipeline: file nguồn → primitive injection → finding có score → (optional) network destination. Đây là extension so với paper chạy batch sandbox.

---

## Plan B — Sysmon hỏng / Frida-only

**Khi nào dùng:** Sysmon service STOP; Event Viewer Operational = 0; agent có `[!] Sysmon unavailable`.

### Điều chỉnh

1. **Bỏ** bước 4 (target name từ Sysmon) và **rút ngắn** bước 5 (network)
2. **Nhấn mạnh:**

> Demo này chỉ Frida user-mode. Paper [4] cũng cần telemetry; em thiết kế Sysmon fallback cho E4 nhưng VM hôm nay Sysmon chưa ghi log — đúng limitation luận văn H4.

3. Vẫn demo: File drops (file watcher) + Findings (Frida primitives)

### Lệnh agent Plan B

```powershell
noirlycan-agent run --server <IP>:8888 --agent-id vm01 --token <TOKEN> --auto-attach-new-processes
# bỏ --watch-sysmon nếu Sysmon chưa cài
```

---

## Plan C — Video backup

Nếu mạng VM ↔ Mac lỗi:

- Quay sẵn 3–4 phút màn hình dashboard + agent terminal
- Lưu `thesis/seminar/images/demo-recording.mp4`
- Seminar: phát video thay live

---

## Lệnh nhanh (tham chiếu)

### Mac — start stack

```bash
cd NoirlycanThesis
source .venv/bin/activate
python scripts/lab_stack.py up --host 0.0.0.0 --backend-port 8888
```

### Windows — agent

```powershell
cd C:\Users\...\NoirlycanThesis
.\.venv\Scripts\Activate.ps1
.\scripts\run-lab-agent.ps1 -Server <IP-Mac>:8888 -AgentId vm01 -Token <TOKEN>
```

### Windows — Sysmon (Admin, trước demo)

```powershell
.\scripts\run-lab-sysmon.ps1
Get-Service Sysmon64
```

---

## Xử lý sự cố nhanh

| Triệu chứng | Xử lý nhanh |
|-------------|-------------|
| Agent offline | Kiểm tra firewall Mac :8888; ping IP |
| File drop không hiện | Bật file-drop watch trên dashboard; copy file **mới** (đổi tên) |
| Không có finding | Chạy loader thủ công; xem agent log Frida attach |
| Target `unknown` | Sysmon chưa Running — nói Plan B limitation |
| Dashboard API lỗi | `vite.config.ts` proxy → đúng IP backend |

---

## Câu hỏi thầy có thể hỏi sau demo

| Câu hỏi | Trả lời ngắn |
|---------|--------------|
| Sao không demo 56k mẫu? | Out-of-scope; em validate methodology + lab artifact |
| Frida bị né syscall? | Sysmon partial; H4 benchmark tương lai |
| FP rate? | Chưa corpus benign; RO4 chưa xong |
| Khác EDR thương mại? | Lab prototype, không production |
