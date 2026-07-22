# Dashboard UI — Noirlycan Console

React + Vite frontend for the lab console. Spec: [`design_handoff_noirlycan_console/README.md`](../design_handoff_noirlycan_console/README.md).

## Development

Terminal 1 — backend:

```bash
noirlycan-backend api --host 127.0.0.1 --port 8765
```

Terminal 2 — UI:

```bash
cd dashboard-ui
npm install
npm run dev
```

Open [http://127.0.0.1:5173](http://127.0.0.1:5173). Vite proxies `/api` to the backend.

**Demo login:** `admin@lab` / `admin`

## Production build

```bash
npm run build
cd .. && noirlycan-dashboard serve --host 0.0.0.0 --port 8080
```

Or nginx/Docker — see [`deploy/README.md`](../deploy/README.md).

Build against a remote API:

```bash
VITE_API_BASE_URL=https://api.lab.local npm run build
```

## Windows agent

Register on **Agents** tab, copy config/TOML, then on the VM:

```powershell
noirlycan-agent run --config C:\Noirlycan\noirlycan-agent.toml --watch-sysmon --auto-attach-new-processes
```

See [`deploy/agent/README.md`](../deploy/agent/README.md).
