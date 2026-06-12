from __future__ import annotations

import os
from pathlib import Path

from .bootstrap import configure

_STATIC_ASSETS = (
    "dashboard.css",
    "dashboard.js",
    "vendor/chart.umd.js",
)


def _verify_static_assets() -> None:
    static_root = Path(__file__).resolve().parent / "static"
    missing = [name for name in _STATIC_ASSETS if not (static_root / name).is_file()]
    if missing:
        raise RuntimeError(
            "Dashboard static assets missing: "
            + ", ".join(missing)
            + f" (expected under {static_root})"
        )


def run_dashboard(
    host: str = "127.0.0.1",
    port: int = 8765,
    logs_dir: Path | str | None = None,
    *,
    auto_collector: bool | None = None,
    elevate_collector: bool | None = None,
) -> None:
    _verify_static_assets()
    configure(logs_dir)
    from django.conf import settings
    from django.core.management import call_command

    call_command("migrate", run_syncdb=True, verbosity=1, interactive=False)

    from ..log_store import resolve_logs_dir

    resolved_logs = resolve_logs_dir(getattr(settings, "NOIRLYCAN_LOGS_DIR", None) or logs_dir)

    from ..collector_launcher import (
        ensure_collector_running,
        should_auto_start_collector,
        should_elevate_collector,
    )

    launch_auto = should_auto_start_collector() if auto_collector is None else auto_collector
    launch_elevate = should_elevate_collector() if elevate_collector is None else elevate_collector

    if launch_auto:
        launch = ensure_collector_running(
            resolved_logs,
            elevate=launch_elevate,
            wait_seconds=2.0,
        )
        if launch.get("already_running"):
            print("[+] Collector already running (Frida + Sysmon loop)")
        elif launch.get("started"):
            elevated = "yes" if launch.get("elevated") else "no"
            print(f"[+] Auto-started collector in new console (admin elevated={elevated})")
            print(f"    {launch.get('command', '')}")
        elif launch.get("pending"):
            print("[+] Collector launch pending (recent UAC/console request)")
        elif not launch.get("ok"):
            print(
                f"[!] Collector auto-start failed: {launch.get('message') or launch.get('error')}",
                flush=True,
            )
    else:
        print("[+] Auto-collector disabled (--no-auto-collector)")

    print(f"[+] Dashboard (Django + Daphne): http://{host}:{port}")
    print(f"[+] WebSocket live sync: ws://{host}:{port}/ws/dashboard/")
    print(f"[+] Static assets: {settings.BASE_DIR / 'static'}")
    print(f"[+] Reading logs from: {resolved_logs}")
    print("[!] If CSS/JS 404: stop old dashboard processes and restart this command.")

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "noirlycan_telemetry.dashboard.settings")
    from daphne.cli import CommandLineInterface

    CommandLineInterface().run(
        [
            "-b",
            host,
            "-p",
            str(port),
            "noirlycan_telemetry.dashboard.asgi:application",
        ]
    )
