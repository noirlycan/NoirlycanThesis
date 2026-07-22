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

```powershell
pip install -e ".[agent]"
noirlycan-agent run --watch-sysmon --server api.lab.local:8765 --token <TOKEN>
```

Token lấy từ dashboard **Agents** hoặc `logs/.runtime.json`.

Legacy Django (upload tab cũ):

```bash
pip install -e ".[dashboard]"
noirlycan-dashboard legacy --port 8766
```

## Docker Compose

```bash
docker compose up backend-api dashboard-ui
# UI: http://localhost:8080
# API trực tiếp: http://localhost:8765/api/health
```

Tương thích cũ: `noirlycan-console console|dashboard` vẫn hoạt động (deprecated).
