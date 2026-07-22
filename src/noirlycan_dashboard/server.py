from __future__ import annotations

import os
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def _default_ui_dist() -> Path:
    env = os.environ.get("NOIRLYCAN_DASHBOARD_UI", "").strip()
    if env:
        path = Path(env).expanduser().resolve()
        if path.is_dir():
            return path
    repo_root = Path(__file__).resolve().parents[2]
    return repo_root / "dashboard-ui" / "dist"


def run_static_dashboard(
    host: str = "127.0.0.1",
    port: int = 8080,
    *,
    ui_dist: Path | str | None = None,
) -> None:
    dist = Path(ui_dist).expanduser().resolve() if ui_dist else _default_ui_dist()
    if not dist.is_dir():
        raise SystemExit(
            f"Dashboard UI not built at {dist}. Run `npm run build` in dashboard-ui/ first."
        )

    class SPAHandler(SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(dist), **kwargs)

        def do_GET(self) -> None:
            requested = self.path.split("?", 1)[0]
            file_path = dist / requested.lstrip("/")
            if requested != "/" and file_path.is_file():
                return super().do_GET()
            self.path = "/index.html"
            return super().do_GET()

    server = ThreadingHTTPServer((host, port), SPAHandler)
    api_hint = os.environ.get("VITE_API_BASE_URL", "").strip() or "(same host via nginx proxy /api)"
    print(f"[+] Noirlycan Dashboard UI: http://{host}:{port}")
    print(f"[+] Static root: {dist}")
    print(f"[+] API base: {api_hint}")
    print("[!] Production: use nginx (deploy/nginx/dashboard.conf) to proxy /api to backend")
    server.serve_forever()
