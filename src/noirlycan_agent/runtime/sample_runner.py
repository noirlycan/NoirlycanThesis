"""Run samples under Frida hooks ("API analysis") and track which ones already ran."""

from __future__ import annotations

import sys
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from noirlycan_agent.runtime.analysis_queue import drain_analysis_queue, enqueue_analysis
from noirlycan_agent.runtime.console_client import ConsoleClient
from noirlycan_agent.runtime.event_sink import EventSink
from noirlycan_agent.runtime.pipeline import safe_attach
from noirlycan_agent.runtime.triage import is_interesting_path
from noirlycan_agent.sensors.frida_monitor import FridaInjectionMonitor
from noirlycan_core.detection.correlator import Correlator
from noirlycan_core.models import ProcessEvent
from noirlycan_core.runtime.noise import is_noise_path

StaticTriage = Callable[[str], None]


def spawn_under_frida(monitor: FridaInjectionMonitor, argv: list[str]) -> int:
    import frida

    device = frida.get_local_device()
    pid = device.spawn(argv)
    safe_attach(monitor, pid)
    try:
        device.resume(pid)
    except Exception:  # noqa: BLE001 - child gating may already have resumed it
        pass
    return pid


def norm_path(path: str) -> str:
    return str(Path(path)).lower()


def is_frida_lab_noise(path: str) -> bool:
    return is_noise_path(path)


class SampleRunner:
    def __init__(
        self,
        *,
        monitor: FridaInjectionMonitor | None,
        correlator: Correlator,
        sink: EventSink,
        logs_dir: Path | None,
        console: ConsoleClient | None = None,
    ) -> None:
        self.monitor = monitor
        self.correlator = correlator
        self.sink = sink
        self.logs_dir = logs_dir
        self.console = console
        self._scheduled: set[str] = set()
        self._spawned: set[tuple[str, tuple[str, ...]]] = set()

    # -- scheduling ---------------------------------------------------------

    def schedule_once(self, path: str) -> bool:
        """Reserve one automatic run per path for this agent session."""
        key = norm_path(path)
        if key in self._scheduled or any(spawned[0] == key for spawned in self._spawned):
            return False
        self._scheduled.add(key)
        return True

    def enqueue(self, path: str, *, argv: list[str] | None = None, upload_id: int | None = None) -> bool:
        if self.logs_dir is None:
            return False
        return enqueue_analysis(path, self.logs_dir, mode="api", argv=argv, upload_id=upload_id)

    def accept_console_sample(self, upload_id: int, sha256: str, filename: str, argv: list[str]) -> None:
        """Download a console-assigned sample into the agent's sample folder and queue it."""
        if self.console is None or self.logs_dir is None:
            return
        destination = self.logs_dir / "samples" / f"{sha256[:16]}-{filename}"
        try:
            self.console.download_sample(upload_id, destination, sha256)
        except Exception as exc:  # noqa: BLE001
            print(f"[!] Sample {upload_id} download failed: {exc}", file=sys.stderr, flush=True)
            self.console.report_sample_status(upload_id, "failed", error=f"download: {exc}")
            return
        print(f"[+] Sample {upload_id} received ({sha256[:12]}…) -> {destination}", flush=True)
        self.enqueue(str(destination), argv=argv, upload_id=upload_id)

    def process_queue(self, static_triage: StaticTriage) -> None:
        if self.logs_dir is None:
            return
        for request in drain_analysis_queue(self.logs_dir):
            if not is_interesting_path(request.path) or is_frida_lab_noise(request.path):
                continue
            if request.mode == "api":
                self.run(request.path, argv=request.argv, source="console", upload_id=request.upload_id)
            else:
                static_triage(request.path)

    # -- execution ----------------------------------------------------------

    def run(
        self,
        path: str,
        *,
        argv: list[str] | None = None,
        source: str,
        upload_id: int | None = None,
    ) -> bool:
        extra = [part for part in (argv or []) if part.strip()]
        key = (norm_path(path), tuple(extra))
        if key in self._spawned:
            print(f"[!] {path} already ran with these arguments; skipping", file=sys.stderr, flush=True)
            return False
        resolved = str(Path(path).resolve())
        command_line = [resolved, *extra]
        if self.monitor is None:
            return self._failed(resolved, command_line, source, "frida_unavailable", upload_id)
        try:
            pid = spawn_under_frida(self.monitor, command_line)
        except Exception as exc:  # noqa: BLE001
            return self._failed(resolved, command_line, source, str(exc), upload_id)

        timestamp = datetime.now(timezone.utc)
        self._spawned.add(key)
        self.sink.write(
            "api_run",
            {
                "path": resolved,
                "pid": pid,
                "argv": command_line,
                "source": source,
                "status": "started",
                "upload_id": upload_id,
                "timestamp": timestamp.isoformat(),
            },
        )
        process = ProcessEvent(
            timestamp=timestamp,
            pid=pid,
            image=resolved,
            parent_image="noirlycan-api-spawn",
            command_line=" ".join(command_line),
            created_from_file=resolved,
            flags=["api_spawn"],
        )
        self.sink.write("frida_process", process)
        self.correlator.add_process(process)
        if upload_id is not None and self.console is not None:
            self.console.report_sample_status(upload_id, "spawned", agent_path=resolved)
        print(f"[API:RUN] Spawned {' '.join(command_line)} as PID {pid} under Frida hooks", flush=True)
        return True

    def _failed(self, path: str, argv: list[str], source: str, error: str, upload_id: int | None) -> bool:
        print(f"[!] API analysis failed for {path}: {error}", file=sys.stderr, flush=True)
        self.sink.write(
            "api_run",
            {
                "path": path,
                "argv": argv,
                "source": source,
                "status": "failed",
                "error": error,
                "upload_id": upload_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )
        if upload_id is not None and self.console is not None:
            self.console.report_sample_status(upload_id, "failed", agent_path=path, error=error)
        return False
