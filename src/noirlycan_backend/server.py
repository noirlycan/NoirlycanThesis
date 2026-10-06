from __future__ import annotations

import argparse
import os
from pathlib import Path

import uvicorn

from noirlycan_backend.api.app import create_app
from noirlycan_backend.api.deps import reset_runtime_paths, warm_database
from noirlycan_core.storage.log_store import resolve_logs_dir


def _default_ui_dist() -> Path | None:
    env = os.environ.get("NOIRLYCAN_DASHBOARD_UI", "").strip() or os.environ.get("NOIRLYCAN_CONSOLE_UI", "").strip()
    if env:
        path = Path(env).expanduser().resolve()
        return path if path.is_dir() else None
    repo_root = Path(__file__).resolve().parents[2]
    candidate = repo_root / "dashboard-ui" / "dist"
    return candidate if candidate.is_dir() else None


def run_api(
    host: str = "127.0.0.1",
    port: int = 8765,
    logs_dir: Path | str | None = None,
    *,
    ui_dist: Path | str | None = None,
    with_ui: bool = False,
) -> None:
    if logs_dir:
        resolved = reset_runtime_paths(resolve_logs_dir(logs_dir))
    else:
        resolved = reset_runtime_paths()
    warm_database()
    dist: Path | None = None
    if with_ui:
        dist = Path(ui_dist).expanduser().resolve() if ui_dist else _default_ui_dist()
    app = create_app(ui_dist=dist)
    print(f"[+] Logs dir: {resolved}")
    print(f"[+] Noirlycan Backend API: http://{host}:{port}")
    print(f"[+] API health: http://{host}:{port}/api/health")
    print(f"[+] WebSocket live: ws://{host}:{port}/api/ws/live")
    if dist:
        print(f"[!] Bundled UI enabled (dev only): {dist}")
    else:
        print("[+] API-only mode — run dashboard-ui separately")
    uvicorn.run(app, host=host, port=port, log_level="info")


def run_console(*args, **kwargs) -> None:
    """Backward-compatible alias."""
    run_api(*args, **kwargs)


def main() -> None:
    parser = argparse.ArgumentParser(description="Noirlycan Backend API (FastAPI)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--logs-dir", default="")
    parser.add_argument("--with-ui", action="store_true")
    parser.add_argument("--ui-dist", default="")
    args = parser.parse_args()
    run_api(
        host=args.host,
        port=args.port,
        logs_dir=args.logs_dir or None,
        ui_dist=args.ui_dist or None,
        with_ui=args.with_ui,
    )


if __name__ == "__main__":
    main()
