"""File provenance intake (repo extension): dropped file → static triage → optional API run.

Sources are Sysmon EID 11 and the directory watcher. Each new executable is
triaged once per session (SHA-256, PE, signature, entropy) and either queued
for a run under Frida hooks or only triaged, depending on the console's
runtime settings.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone

from noirlycan_agent.runtime.event_sink import EventSink
from noirlycan_agent.runtime.sample_runner import SampleRunner, is_frida_lab_noise, norm_path
from noirlycan_agent.runtime.triage import FileTriage, is_interesting_path, triage_file
from noirlycan_core.detection.correlator import Correlator
from noirlycan_core.models import FileEvent, ProcessEvent

# Process images that are never worth triaging on a lab VM.
_PROCESS_NOISE_MARKERS = ("\\windows\\", "\\program files", "\\cursor-agent\\", "\\cursor\\", "__psscriptpolicytest_")
_PROCESS_NOISE_SUFFIXES = ("powershell.exe", "python.exe")


@dataclass
class IntakeSettings:
    """Refreshed from the runtime config once per collector tick."""

    auto_api_analysis: bool = False
    auto_static_triage: bool = False


class FileIntake:
    def __init__(self, *, correlator: Correlator, sink: EventSink, runner: SampleRunner) -> None:
        self.correlator = correlator
        self.sink = sink
        self.runner = runner
        self.settings = IntakeSettings()
        self.watch_paths: list[str] = []
        self._triaged: dict[str, str | None] = {}  # normalized path → sha256
        self._pending: set[str] = set()
        self._lock = threading.Lock()
        self._executor: ThreadPoolExecutor | None = None

    # -- entry points -------------------------------------------------------

    def on_file(self, event: FileEvent) -> None:
        if not event.path:
            return
        self.sink.write("file", event)
        self.correlator.add_file(event)
        if not is_interesting_path(event.path) or is_frida_lab_noise(event.path):
            return
        if self.settings.auto_api_analysis and self.runner.logs_dir is not None:
            self._triage_now(event, title="FILE DROP DETECTED")
            if self.runner.schedule_once(event.path):
                self.runner.enqueue(event.path)
                _log(f"[FILE:DROP] {event.path} - queued API hook analysis")
            else:
                _log(f"[FILE:DROP] {event.path} - API analysis already scheduled this session")
        elif self.settings.auto_static_triage:
            self.triage_in_background(event)
        else:
            _log(f"[FILE:DROP] {event.path} - enable auto API analysis or connect the agent with --server")

    def on_process(self, event: ProcessEvent) -> None:
        """Triage the image of a new process that started from a watched folder."""
        if not event.image or _is_process_noise(event.image):
            return
        if self.watch_paths and not _within(event.image, self.watch_paths):
            return
        if self.correlator.files_by_path.get(norm_path(event.image)) is not None:
            return
        self._triage_now(
            FileEvent(
                timestamp=event.timestamp,
                path=event.image,
                creator_pid=event.parent_pid,
                creator_image=event.parent_image,
            ),
            title="SUSPICIOUS PROCESS IMAGE (auto-triage)",
        )

    def triage_path(self, path: str) -> None:
        """Static-only request from the console queue."""
        self.triage_in_background(
            FileEvent(timestamp=datetime.now(timezone.utc), path=path, creator_pid=None, creator_image="console"),
            record=False,
        )

    def triage_in_background(self, event: FileEvent, *, record: bool = False) -> None:
        key = norm_path(event.path)
        if key in self._triaged or key in self._pending:
            return
        self._pending.add(key)
        if record:
            self.sink.write("file", event)
            self.correlator.add_file(event)
        _log(f"[FILE:TRIAGE] Queued static triage for {event.path}")
        self._pool().submit(self._triage_worker, event)

    def shutdown(self) -> None:
        if self._executor is not None:
            self._executor.shutdown(wait=False, cancel_futures=True)
            self._executor = None

    # -- triage -------------------------------------------------------------

    def _triage_worker(self, event: FileEvent) -> None:
        try:
            with self._lock:
                self._triage_now(event, title="FILE DROP DETECTED")
        finally:
            self._pending.discard(norm_path(event.path))

    def _triage_now(self, event: FileEvent, *, title: str) -> FileEvent | None:
        path = event.path
        if not is_interesting_path(path) or is_frida_lab_noise(path):
            return None
        if not _wait_until_stable(path):
            _log(f"[!] Detected {path} but the file is not readable yet")
            return None
        triage = triage_file(path, quick=True)
        key = norm_path(path)
        if key in self._triaged and (triage.sha256 is None or self._triaged[key] == triage.sha256):
            return None  # Same content already triaged this session.
        self.sink.write("triage", triage)
        enriched = FileEvent(
            timestamp=event.timestamp,
            path=path,
            creator_pid=event.creator_pid,
            creator_image=event.creator_image,
            sha256=triage.sha256,
            signed=triage.signed,
            entropy=triage.entropy,
            pe=triage.pe,
        )
        self.sink.write("file", enriched)
        self.correlator.add_file(enriched)
        self._triaged[key] = triage.sha256
        _announce(title, enriched, triage, self.sink)
        return enriched

    def _pool(self) -> ThreadPoolExecutor:
        if self._executor is None:
            self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="file-triage")
        return self._executor


def _wait_until_stable(path: str, attempts: int = 24, delay: float = 0.25) -> bool:
    """Wait until the file exists with the same non-zero size on two consecutive reads."""
    last_size, stable = -1, 0
    for _ in range(attempts):
        try:
            size = os.path.getsize(path)
        except OSError:
            time.sleep(delay)
            continue
        stable = stable + 1 if size > 0 and size == last_size else 0
        if stable >= 2:
            return True
        last_size = size
        time.sleep(delay)
    return os.path.exists(path)


def _within(path: str, directories: list[str]) -> bool:
    target = norm_path(path)
    for directory in directories:
        root = norm_path(directory)
        if target == root or target.startswith(root.rstrip("\\") + "\\"):
            return True
    return False


def _is_process_noise(image: str) -> bool:
    lower = image.lower()
    if not is_interesting_path(image) or is_frida_lab_noise(image):
        return True
    if any(marker in lower for marker in _PROCESS_NOISE_MARKERS):
        return True
    if "\\noirlycan_thesis\\" in lower and "\\.venv\\" in lower:
        return True
    return lower.endswith(_PROCESS_NOISE_SUFFIXES)


def _announce(title: str, event: FileEvent, triage: FileTriage, sink: EventSink) -> None:
    reasons = ", ".join(triage.suspicious_reasons) or "none"
    lines = [
        "",
        "=" * 72,
        f" {title}",
        f" Path: {event.path}",
        f" Creator: {event.creator_image or 'unknown'} (pid={event.creator_pid or '-'})",
        f" Triage score: {triage.score}",
        f" PE: {triage.pe} | Signed: {triage.signed} | Entropy: {triage.entropy}",
        f" SHA256: {triage.sha256 or '-'}",
        f" Reasons: {reasons}",
    ]
    if sink.path is not None:
        lines.append(f" Log: {sink.path}")
    lines.append("=" * 72)
    _log("\n".join(lines))


def _log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)
