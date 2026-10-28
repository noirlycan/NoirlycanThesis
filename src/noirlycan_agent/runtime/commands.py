"""Console → agent commands.

The agent never executes free-form instructions. Each command type is in a
fixed allowlist and its parameters go through a validator before anything
happens on the lab VM.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import PureWindowsPath
from typing import Any

from noirlycan_agent.runtime.collector_pid import pid_is_alive
from noirlycan_core.runtime.command_signing import CommandRejected, CommandVerifier
from noirlycan_core.runtime.process_resolve import image_for_pid

# PIDs that must never be killed: System Idle, System, and the agent itself.
_PROTECTED_PIDS = frozenset({0, 4})
_PROTECTED_IMAGES = frozenset(
    {"csrss.exe", "lsass.exe", "services.exe", "smss.exe", "wininit.exe", "winlogon.exe", "sysmon.exe", "sysmon64.exe"}
)
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")


def kill_process(pid: int, *, expected_image: str | None = None) -> bool:
    return terminate(pid, expected_image=expected_image)[0]


def terminate(pid: int, *, expected_image: str | None = None) -> tuple[bool, str]:
    """Terminate ``pid`` unless protected or no longer the process the console meant.

    Returns (ok, reason). ``ok`` is True only once the process is verifiably gone.
    """
    if pid in _PROTECTED_PIDS or pid in {os.getpid(), os.getppid()}:
        return False, "protected pid"
    actual = image_for_pid(pid)
    if actual and PureWindowsPath(actual).name.lower() in _PROTECTED_IMAGES:
        return False, f"system process {PureWindowsPath(actual).name}"
    if expected_image and actual and PureWindowsPath(actual).name.lower() != PureWindowsPath(expected_image).name.lower():
        return False, f"pid now belongs to {PureWindowsPath(actual).name} (pid reuse)"
    if sys.platform == "win32":
        result = subprocess.run(
            ["taskkill", "/PID", str(pid), "/F"], capture_output=True, text=True, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if result.returncode != 0:
            return False, (result.stderr or result.stdout).strip()[:200] or f"taskkill exit {result.returncode}"
    else:
        try:
            os.kill(pid, 15)
        except OSError as exc:
            return False, str(exc)
    return (True, "terminated") if not _pid_exists(pid) else (False, "process still running after kill")


def _pid_exists(pid: int, attempts: int = 10) -> bool:
    """Wait up to ~1 s for the process to disappear; True if it is still alive.

    Uses an uncached liveness check (image lookups are cached and would report
    a killed process as still running).
    """
    import time

    for _ in range(attempts):
        if not pid_is_alive(pid):
            return False
        time.sleep(0.1)
    return True


SampleHandler = Callable[[int, str, str, list[str]], None]
ResultReporter = Callable[[int, bool, str], None]


class CommandDispatcher:
    """Verify, validate and run console commands.

    ``verifier`` returns the current signature verifier (it can appear after
    the first console hello). Without one, every command is refused.
    """

    def __init__(
        self,
        *,
        verifier: Callable[[], CommandVerifier | None],
        on_sample: SampleHandler | None = None,
        report: ResultReporter | None = None,
    ) -> None:
        self._verifier = verifier
        self._report = report
        self._handlers: dict[str, Callable[[dict[str, Any]], None]] = {"kill": self._kill}
        self._on_sample = on_sample
        if on_sample is not None:
            self._handlers["sample.run"] = self._sample_run

    def dispatch(self, commands: list[dict[str, Any]]) -> None:
        for command in commands:
            name = str(command.get("command") or "")
            handler = self._handlers.get(name)
            if handler is None:
                print(f"[!] Ignoring unsupported console command {name!r}", flush=True)
                continue
            verifier = self._verifier()
            try:
                if verifier is None:
                    raise CommandRejected("no pinned command key")
                verifier.verify(command)
                handler(command)
            except (TypeError, ValueError) as exc:  # CommandRejected is a ValueError
                print(f"[!] Rejected console command {name!r}: {exc}", flush=True)

    def _kill(self, command: dict[str, Any]) -> None:
        pid = int(command["pid"])
        if pid <= 0:
            raise ValueError("pid must be positive")
        image = str(command.get("image") or "").strip() or None
        print(f"[+] Kill command from console for {image or 'process'} (PID {pid})", flush=True)
        ok, reason = terminate(pid, expected_image=image)
        print(f"[{'+' if ok else '!'}] Kill PID {pid}: {reason}", flush=True)
        if self._report is not None and command.get("command_id") is not None:
            self._report(int(command["command_id"]), ok, reason)

    def _sample_run(self, command: dict[str, Any]) -> None:
        upload_id = int(command["upload_id"])
        sha256 = str(command.get("sha256") or "")
        if not _SHA256.match(sha256):
            raise ValueError("sha256 must be 64 hex characters")
        filename = PureWindowsPath(str(command.get("filename") or "sample.exe")).name
        if PureWindowsPath(filename).suffix.lower() not in {".exe", ".dll"}:
            raise ValueError("sample must be .exe or .dll")
        argv = [str(part) for part in command.get("argv") or []]
        if any(not part.isdigit() for part in argv):
            raise ValueError("sample argv may only contain a target PID")
        assert self._on_sample is not None
        self._on_sample(upload_id, sha256, filename, argv)
