from __future__ import annotations

import argparse
import dataclasses
import json
import os
import queue
import sys
import time
from pathlib import Path
from typing import Any

from .correlation import Correlator
from .frida_manager import (
    FridaInjectionMonitor,
    FridaUnavailable,
    runtime_event_to_primitive,
    runtime_event_to_process,
)
from .models import FileEvent, Finding, ProcessEvent, TelemetryEvent
from .sysmon import SysmonPoller, SysmonUnavailable
from .triage import is_instrumentation_artifact, is_interesting_path, triage_file


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "triage":
        return command_triage(args)
    if args.command == "run":
        return command_run(args)
    if args.command == "spawn":
        return command_spawn(args)
    parser.print_help()
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="noirlycan-telemetry",
        description="File-to-memory telemetry prototype for Windows 10/11 labs.",
    )
    subparsers = parser.add_subparsers(dest="command")

    triage = subparsers.add_parser("triage", help="Static triage a newly observed file")
    triage.add_argument("path", help="Path to EXE/DLL/script")

    run = subparsers.add_parser("run", help="Run the Sysmon + Frida correlation loop")
    run.add_argument("--watch-sysmon", action="store_true", help="Poll Sysmon Operational log")
    run.add_argument("--attach-pid", action="append", type=int, default=[], help="PID to attach Frida to")
    run.add_argument("--auto-attach-new-processes", action="store_true", help="Attach Frida to new interesting processes observed by Sysmon")
    run.add_argument("--minimum-score", type=int, default=50, help="Minimum finding score")
    run.add_argument("--poll-interval", type=float, default=1.0, help="Sysmon polling interval in seconds")
    run.add_argument("--jsonl", type=Path, help="Optional JSONL output path")

    spawn = subparsers.add_parser("spawn", help="Spawn a sample under Frida, then correlate events")
    spawn.add_argument("argv", nargs=argparse.REMAINDER, help="Command line to spawn under Frida")
    spawn.add_argument("--watch-sysmon", action="store_true", help="Also poll Sysmon while the sample runs")
    spawn.add_argument("--minimum-score", type=int, default=50, help="Minimum finding score")
    spawn.add_argument("--jsonl", type=Path, help="Optional JSONL output path")
    return parser


def command_triage(args: argparse.Namespace) -> int:
    result = triage_file(args.path)
    print(json.dumps(dataclasses.asdict(result), indent=2, sort_keys=True))
    return 0


def command_run(args: argparse.Namespace) -> int:
    correlator = Correlator(minimum_score=args.minimum_score)
    writer = JsonlWriter(args.jsonl)
    monitor = _create_monitor_or_none()
    if monitor is not None:
        for pid in args.attach_pid:
            _safe_attach(monitor, pid)
    sysmon = SysmonPoller() if args.watch_sysmon else None

    try:
        while True:
            if monitor is not None:
                _drain_frida(monitor, correlator, writer)
            if sysmon is not None:
                _process_sysmon_batch(
                    sysmon,
                    correlator,
                    writer,
                    monitor,
                    auto_attach=args.auto_attach_new_processes,
                )
            if monitor is not None:
                _drain_frida(monitor, correlator, writer)
            time.sleep(args.poll_interval)
    except KeyboardInterrupt:
        if monitor is not None:
            monitor.detach_all()
        return 0


def command_spawn(args: argparse.Namespace) -> int:
    spawn_argv = args.argv[1:] if args.argv and args.argv[0] == "--" else args.argv
    if not spawn_argv:
        print("spawn requires a command line after --", file=sys.stderr)
        return 2
    try:
        import frida
    except ImportError:
        print("Install the 'frida' Python package first", file=sys.stderr)
        return 2

    correlator = Correlator(minimum_score=args.minimum_score)
    writer = JsonlWriter(args.jsonl)
    monitor = _create_monitor_or_none()
    if monitor is None:
        return 2

    device = frida.get_local_device()
    pid = device.spawn(spawn_argv)
    _safe_attach(monitor, pid)
    device.resume(pid)
    print(f"[+] Spawned and attached PID {pid}: {' '.join(spawn_argv)}")
    sysmon = SysmonPoller() if args.watch_sysmon else None
    try:
        while True:
            _drain_frida(monitor, correlator, writer)
            if sysmon is not None:
                _process_sysmon_batch(
                    sysmon,
                    correlator,
                    writer,
                    monitor,
                    auto_attach=False,
                )
            _drain_frida(monitor, correlator, writer)
            time.sleep(0.25)
    except KeyboardInterrupt:
        monitor.detach_all()
        return 0


def _create_monitor_or_none() -> FridaInjectionMonitor | None:
    try:
        return FridaInjectionMonitor()
    except FridaUnavailable as exc:
        print(f"[!] Frida unavailable: {exc}", file=sys.stderr)
        return None


def _safe_attach(monitor: FridaInjectionMonitor, pid: int) -> None:
    try:
        monitor.attach(pid)
        print(f"[+] Frida attached to PID {pid}")
    except Exception as exc:
        print(f"[!] Could not attach to PID {pid}: {exc}", file=sys.stderr)


def _process_sysmon_batch(
    sysmon: SysmonPoller,
    correlator: Correlator,
    writer: "JsonlWriter",
    monitor: FridaInjectionMonitor | None,
    auto_attach: bool,
) -> None:
    try:
        events = list(sysmon.poll_once())
    except SysmonUnavailable as exc:
        print(f"[!] Sysmon unavailable: {exc}", file=sys.stderr)
        return
    for event in events:
        writer.write("sysmon", event)
        if isinstance(event, FileEvent):
            _handle_file_event(event, correlator, writer)
        elif isinstance(event, ProcessEvent):
            correlator.add_process(event)
            if auto_attach and monitor is not None and _should_auto_attach(event):
                _safe_attach(monitor, event.pid)
        elif isinstance(event, TelemetryEvent):
            pass


def _handle_file_event(
    event: FileEvent,
    correlator: Correlator,
    writer: "JsonlWriter",
) -> None:
    enriched = event
    if event.path and is_instrumentation_artifact(event.path):
        correlator.add_file(enriched)
        return
    if event.path and is_interesting_path(event.path) and os.path.exists(event.path):
        triage = triage_file(event.path)
        writer.write("triage", triage)
        enriched = FileEvent(
            timestamp=event.timestamp,
            path=event.path,
            creator_pid=event.creator_pid,
            creator_image=event.creator_image,
            sha256=triage.sha256,
            signed=triage.signed,
            entropy=triage.entropy,
            pe=triage.pe,
        )
    correlator.add_file(enriched)


def _drain_frida(
    monitor: FridaInjectionMonitor,
    correlator: Correlator,
    writer: "JsonlWriter",
) -> None:
    while True:
        try:
            runtime_event = monitor.events().get_nowait()
        except queue.Empty:
            return
        writer.write("frida_raw", runtime_event.payload)
        if runtime_event.event_type == "frida_error":
            print(f"[!] Frida script error: {runtime_event.payload.get('description')}", file=sys.stderr)
            stack = runtime_event.payload.get("stack")
            if stack:
                print(stack, file=sys.stderr)
            continue
        if runtime_event.event_type == "agent_loaded":
            print(
                f"[+] Frida agent loaded in PID {runtime_event.payload.get('actor_pid')} "
                f"({runtime_event.payload.get('actor_image')})"
            )
            continue
        process_event = runtime_event_to_process(runtime_event)
        if process_event is not None:
            writer.write("frida_process", process_event)
            correlator.add_process(process_event)
            continue
        primitive = runtime_event_to_primitive(runtime_event)
        if primitive is None:
            continue
        writer.write("primitive", primitive)
        for finding in correlator.add_primitive(primitive):
            writer.write("finding", finding)
            print_finding(finding)


def _should_auto_attach(event: ProcessEvent) -> bool:
    if not event.image:
        return False
    suffix = Path(event.image).suffix.lower()
    if suffix not in {".exe", ".dll", ".scr", ".com"}:
        return False
    image = event.image.lower()
    if "\\windows\\system32\\" in image and not event.parent_image:
        return False
    return True


def print_finding(finding: Finding) -> None:
    print(
        f"[{finding.severity.value.upper()}:{finding.score}] "
        f"{finding.title}: {finding.description}"
    )
    print("  APIs:", ", ".join(sorted({primitive.api for primitive in finding.primitives})))
    if finding.related_file:
        print(f"  Related file: {finding.related_file.path}")


class JsonlWriter:
    def __init__(self, path: Path | None) -> None:
        self.path = path
        self._handle = path.open("a", encoding="utf-8") if path else None

    def write(self, event_type: str, value: Any) -> None:
        if self._handle is None:
            return
        payload = {
            "type": event_type,
            "value": _jsonable(value),
        }
        self._handle.write(json.dumps(payload, sort_keys=True) + "\n")
        self._handle.flush()


def _jsonable(value: Any) -> Any:
    if dataclasses.is_dataclass(value):
        return _jsonable(dataclasses.asdict(value))
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return value


if __name__ == "__main__":
    raise SystemExit(main())
