from __future__ import annotations

import threading
import time
from pathlib import Path

from django.conf import settings

from noirlycan_agent.collector.application.analysis_queue import QUEUE_NAME as ANALYSIS_QUEUE_NAME
from noirlycan_core.runtime.config import (
    load_runtime_config,
    resolve_config_path,
    runtime_config_payload,
)
from noirlycan_core.storage.infrastructure.log_store import resolve_logs_dir
from .ws_broadcast import broadcast_refresh, broadcast_runtime

_watcher_lock = threading.Lock()
_watcher_started = False
_last_refresh_broadcast = 0.0
_REFRESH_DEBOUNCE_SEC = 2.0


def ensure_live_sync() -> None:
    global _watcher_started
    with _watcher_lock:
        if _watcher_started:
            return
        _watcher_started = True
        thread = threading.Thread(
            target=_watch_loop,
            name="noirlycan-live-sync",
            daemon=True,
        )
        thread.start()


def _logs_dir() -> Path:
    override = getattr(settings, "NOIRLYCAN_LOGS_DIR", "") or ""
    return resolve_logs_dir(override or None)


def _logs_snapshot(logs_dir: Path) -> dict[str, float]:
    snapshot: dict[str, float] = {}
    for path in logs_dir.glob("*.jsonl"):
        try:
            snapshot[f"jsonl:{path.name}"] = path.stat().st_mtime
        except OSError:
            continue
    for name in (".runtime.json", ANALYSIS_QUEUE_NAME, "noirlycan.db"):
        path = logs_dir / name
        if not path.exists():
            continue
        try:
            snapshot[name] = path.stat().st_mtime
        except OSError:
            continue
    return snapshot


def _watch_loop() -> None:
    global _last_refresh_broadcast
    last_runtime_mtime: float | None = None
    last_log_snapshot: dict[str, float] | None = None

    while True:
        try:
            logs_dir = _logs_dir()
            runtime_path = resolve_config_path(logs_dir)
            runtime_mtime = runtime_path.stat().st_mtime if runtime_path.exists() else 0.0
            if last_runtime_mtime is None or runtime_mtime != last_runtime_mtime:
                last_runtime_mtime = runtime_mtime
                config = load_runtime_config(logs_dir)
                broadcast_runtime(runtime_config_payload(config))

            snapshot = _logs_snapshot(logs_dir)
            if last_log_snapshot is None:
                last_log_snapshot = snapshot
            elif snapshot != last_log_snapshot:
                last_log_snapshot = snapshot
                now = time.monotonic()
                if now - _last_refresh_broadcast >= _REFRESH_DEBOUNCE_SEC:
                    _last_refresh_broadcast = now
                    broadcast_refresh(reason="logs")
        except Exception:
            pass
        time.sleep(1.0)
