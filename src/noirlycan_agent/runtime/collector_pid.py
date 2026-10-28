"""``logs/.collector.pid`` — lets the console host tell whether a local collector is alive."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from noirlycan_core.runtime.config import (
    is_collector_online,
    load_runtime_config,
)
from noirlycan_core.storage.log_store import ensure_logs_dir, resolve_logs_dir

COLLECTOR_PID_NAME = ".collector.pid"


def _pid_path(logs_dir: Path) -> Path:
    return logs_dir / COLLECTOR_PID_NAME


def pid_is_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if sys.platform == "win32":
        import ctypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        STILL_ACTIVE = 259
        handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return False
        try:
            exit_code = ctypes.c_ulong()
            if not ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                return False
            return int(exit_code.value) == STILL_ACTIVE
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def read_collector_pid(logs_dir: Path | str | None = None) -> int | None:
    path = _pid_path(resolve_logs_dir(logs_dir))
    if not path.exists():
        return None
    try:
        value = int(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None
    return value if value > 0 else None


def register_collector_pid(logs_dir: Path | str | None, pid: int) -> None:
    directory = ensure_logs_dir(logs_dir)
    _pid_path(directory).write_text(f"{pid}\n", encoding="utf-8")


def clear_collector_pid(logs_dir: Path | str | None) -> None:
    path = _pid_path(resolve_logs_dir(logs_dir))
    path.unlink(missing_ok=True)


def is_collector_running(logs_dir: Path | str | None = None) -> bool:
    directory = resolve_logs_dir(logs_dir)
    if is_collector_online(load_runtime_config(directory)):
        return True
    pid = read_collector_pid(directory)
    return pid is not None and pid_is_alive(pid)
