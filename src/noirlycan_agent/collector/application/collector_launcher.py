from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from noirlycan_core.runtime.config import (
    is_collector_online,
    load_runtime_config,
)
from noirlycan_core.storage.infrastructure.log_store import (
    ensure_logs_dir,
    find_project_root,
    resolve_logs_dir,
)

COLLECTOR_PID_NAME = ".collector.pid"
COLLECTOR_LAUNCH_NAME = ".collector_launch.json"
LAUNCH_COOLDOWN_SECONDS = 30


def collector_working_dir(logs_dir: Path | str | None = None) -> Path:
    directory = resolve_logs_dir(logs_dir)
    if directory.name == "logs":
        return directory.parent
    return find_project_root()


def _pid_path(logs_dir: Path) -> Path:
    return logs_dir / COLLECTOR_PID_NAME


def _launch_path(logs_dir: Path) -> Path:
    return logs_dir / COLLECTOR_LAUNCH_NAME


def is_windows_admin() -> bool:
    if sys.platform != "win32":
        return False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


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


def _record_launch_attempt(logs_dir: Path, payload: dict[str, Any]) -> None:
    path = _launch_path(logs_dir)
    body = {
        "launched_at": datetime.now(timezone.utc).isoformat(),
        **payload,
    }
    path.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _recent_launch_attempt(logs_dir: Path) -> bool:
    path = _launch_path(logs_dir)
    if not path.exists():
        return False
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        launched_at = datetime.fromisoformat(str(raw.get("launched_at")))
    except (OSError, ValueError, TypeError):
        return False
    if launched_at.tzinfo is None:
        launched_at = launched_at.replace(tzinfo=timezone.utc)
    age = (datetime.now(timezone.utc) - launched_at).total_seconds()
    return age <= LAUNCH_COOLDOWN_SECONDS


def is_collector_running(logs_dir: Path | str | None = None) -> bool:
    directory = resolve_logs_dir(logs_dir)
    if is_collector_online(load_runtime_config(directory)):
        return True
    pid = read_collector_pid(directory)
    return pid is not None and pid_is_alive(pid)


def should_auto_start_collector() -> bool:
    return os.environ.get("NOIRLYCAN_AUTO_COLLECTOR", "1").lower() not in {"0", "false", "no"}


def should_elevate_collector() -> bool:
    if sys.platform != "win32":
        return False
    return os.environ.get("NOIRLYCAN_COLLECTOR_ELEVATE", "1").lower() not in {"0", "false", "no"}


def _collector_command() -> list[str]:
    return [
        "-m",
        "noirlycan_agent.cli",
        "run",
        "--watch-sysmon",
        "--auto-attach-new-processes",
    ]


def _start_windows_elevated(python_exe: str, args: list[str], cwd: Path) -> dict[str, Any]:
    import ctypes

    params = subprocess.list2cmdline(args)
    result = ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        python_exe,
        params,
        str(cwd),
        1,
    )
    if int(result) <= 32:
        return {
            "ok": False,
            "started": False,
            "error": f"elevation_failed_code_{int(result)}",
            "message": "Windows declined or blocked the UAC elevation prompt.",
        }
    return {
        "ok": True,
        "started": True,
        "elevated": True,
        "pid": None,
        "message": "Launched collector in a new elevated console (approve UAC if prompted).",
    }


def start_collector(
    logs_dir: Path | str | None = None,
    *,
    elevate: bool | None = None,
) -> dict[str, Any]:
    directory = ensure_logs_dir(logs_dir)
    cwd = collector_working_dir(directory)
    python_exe = sys.executable
    args = _collector_command()

    if is_collector_running(directory):
        return {
            "ok": True,
            "started": False,
            "already_running": True,
            "collector_online": True,
            "message": "Collector already running.",
        }

    if _recent_launch_attempt(directory):
        return {
            "ok": True,
            "started": False,
            "already_running": False,
            "pending": True,
            "message": "Collector launch already requested recently; waiting for heartbeat.",
        }

    use_elevate = should_elevate_collector() if elevate is None else elevate
    launch_result: dict[str, Any]

    if sys.platform == "win32" and use_elevate and not is_windows_admin():
        launch_result = _start_windows_elevated(python_exe, args, cwd)
    else:
        creationflags = 0
        if sys.platform == "win32":
            creationflags = subprocess.CREATE_NEW_CONSOLE
        process = subprocess.Popen(
            [python_exe, *args],
            cwd=str(cwd),
            creationflags=creationflags,
        )
        launch_result = {
            "ok": True,
            "started": True,
            "elevated": bool(use_elevate and is_windows_admin()),
            "pid": process.pid,
            "message": "Launched collector in a new console window.",
        }

    if launch_result.get("started"):
        _record_launch_attempt(
            directory,
            {
                "cwd": str(cwd),
                "python": python_exe,
                "args": args,
                "elevated": launch_result.get("elevated"),
                "pid": launch_result.get("pid"),
            },
        )

    launch_result.update(
        {
            "collector_online": is_collector_running(directory),
            "cwd": str(cwd),
            "command": subprocess.list2cmdline([python_exe, *args]),
        }
    )
    return launch_result


def ensure_collector_running(
    logs_dir: Path | str | None = None,
    *,
    elevate: bool | None = None,
    wait_seconds: float = 0.0,
) -> dict[str, Any]:
    result = start_collector(logs_dir, elevate=elevate)
    if wait_seconds <= 0 or not result.get("started"):
        return result
    directory = resolve_logs_dir(logs_dir)
    deadline = time.monotonic() + wait_seconds
    while time.monotonic() < deadline:
        if is_collector_running(directory):
            result["collector_online"] = True
            result["message"] = "Collector is online."
            break
        time.sleep(0.25)
    return result
