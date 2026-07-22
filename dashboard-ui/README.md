# Console UI — Noirlycan Telemetry

React + Vite frontend for the lab console described in `design_handoff_noirlycan_console/README.md`.

## Development

```bash
cd dashboard-ui
npm install
npm run dev
```

Vite proxies `/api` to `http://127.0.0.1:8765`. Start the backend first:

```bash
noirlycan-telemetry console
# or
noirlycan-console
```

## Production build

```bash
npm run build
noirlycan-telemetry console
```

FastAPI serves `dashboard-ui/dist` automatically when present.

## Agent on Windows VM

```powershell
noirlycan-telemetry run --server 127.0.0.1:8765 --token <token> --watch-sysmon --auto-attach-new-processes
```

The agent streams JSONL events to the console (`POST /api/ingest`), polls kill commands, and can auto-kill by severity when enabled on the Agents tab.

| Email | Password | Role |
|-------|----------|------|
| admin@lab | admin | Admin |
| analyst@lab | analyst | Analyst |
| viewer@lab | viewer | Viewer |
