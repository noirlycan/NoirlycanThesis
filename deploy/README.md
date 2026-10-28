# Deploy — 3 đơn vị riêng

```text
┌─────────────────┐     HTTPS/WS      ┌──────────────────┐
│  Windows VM     │ ─── ingest ────► │  backend-api     │
│  noirlycan-agent│     :8765         │  (FastAPI)       │
└─────────────────┘                   └────────┬─────────┘
                                               │
┌─────────────────┐     /api proxy            │
│  Analyst browser│ ◄── dashboard-ui :8080 ────┘
│  (React SPA)    │
└─────────────────┘
```

## 1. Backend API (máy chủ lab)

Chỉ chạy FastAPI — không bundle UI.

```bash
pip install -e .
noirlycan-backend api --host 0.0.0.0 --port 8765
# hoặc
docker compose up backend-api
```

Biến môi trường:

| Biến | Mô tả |
|------|--------|
| `NOIRLYCAN_LOGS_DIR` | Thư mục logs/SQLite |
| `NOIRLYCAN_CORS_ORIGINS` | Origin dashboard, ví dụ `http://localhost:8080` |
| `NOIRLYCAN_AGENT_ARTIFACTS_DIR` | Thư mục lưu bộ cài/bản portable được Admin đăng từ dashboard |

## 2. Dashboard UI (máy chủ hoặc CDN riêng)

```bash
cd dashboard-ui && npm install && npm run build
noirlycan-dashboard serve --host 0.0.0.0 --port 8080
# hoặc production nginx:
docker compose up dashboard-ui
```

Nginx (`deploy/nginx/dashboard.conf`) proxy `/api` → `backend-api:8765`.

Dev local (Vite proxy):

```bash
# terminal 1
noirlycan-backend api --port 8765

# terminal 2
cd dashboard-ui && npm run dev   # http://127.0.0.1:5173 → proxy /api
```

Dashboard trên domain khác backend:

```bash
VITE_API_BASE_URL=https://api.lab.local npm run build
```

## 3. Agent (Windows VM — không container)

Client có thể mở dashboard trên Windows và tải bộ cài tại **Agents → Desktop
Agent (Windows) → Download Windows installer**. Admin đăng file build một lần bằng **Publish
installer**; backend giữ file trong `deploy/agent-artifacts/`. Docker Compose đã
mount thư mục này để bản phát hành được lưu qua các lần restart. Xem
[build và đăng bản Agent](agent/README.md) để tạo `NoirlycanAgentSetup.exe`.

Bộ cài tạo shortcut và mục gỡ cài đặt; Agent chạy bằng quyền Administrator.
Sau khi cài, client nhập server và token từ dòng workstation của mình. Các bước
cài bằng Python dưới đây vẫn dùng được cho môi trường phát triển.

Chỉ cài **agent**, không cài backend/dashboard:

```powershell
pip install -e ".[agent]"
```

Hoặc `.\scripts\install-agent.ps1` — xem [deploy/agent/README.md](agent/README.md).

Dashboard **Agents** → Register → **Copy config** → trên VM:

```powershell
noirlycan-agent run --config C:\Noirlycan\noirlycan-agent.toml --watch-sysmon
```

Máy chủ lab cài backend riêng:

```bash
pip install -e ".[backend]"
noirlycan-backend api --host 0.0.0.0 --port 8765
```

Upload sample: tab **Samples** trên React console (backend gửi sample xuống agent qua lệnh có chữ ký, agent verify SHA-256 trước khi chạy).

Lần chạy đầu, backend tạo `admin@lab` với mật khẩu từ `NOIRLYCAN_ADMIN_PASSWORD` hoặc in ra một mật khẩu ngẫu nhiên. Demo: `NOIRLYCAN_DEMO_USERS=1`.

## Docker Compose

```bash
docker compose up backend-api dashboard-ui
# UI: http://localhost:8080
# API trực tiếp: http://localhost:8765/api/health
```
