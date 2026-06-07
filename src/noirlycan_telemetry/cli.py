from __future__ import annotations

import argparse
import atexit
import dataclasses
import json
import os
import queue
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from .correlation import Correlator
from .dashboard.app import run_dashboard
from .frida_manager import (
    FridaInjectionMonitor,
    FridaUnavailable,
    runtime_event_to_primitive,
    runtime_event_to_process,
)
from .file_watch import FileDropWatcher, default_watch_paths
from .log_store import new_session_log_path
from .runtime_config import (
    load_runtime_config,
    mark_collector_stopped,
    save_runtime_config,
    touch_collector_heartbeat,
)
from .models import FileEvent, Finding, NetworkConnectionEvent, ProcessEvent, TelemetryEvent
from .network import is_external_beacon_candidate
from .sysmon import SYSMON_ACCESS_HINT, SYSMON_INSTALL_HINT, SysmonPoller, SysmonUnavailable
from .triage import FileTriage, is_interesting_path, triage_file

_SESSION_TRIAGED_PATHS: set[str] = set()
_SESSION_TRIAGED_SHA: dict[str, str] = {}
_WATCH_PATHS: list[str] = []
_TRIAGE_PENDING: set[str] = set()
_TRIAGE_LOCK = threading.Lock()
_TRIAGE_EXECUTOR: ThreadPoolExecutor | None = None


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "triage":
        return command_triage(args)
    if args.command == "run":
        return command_run(args)
    if args.command == "spawn":
        return command_spawn(args)
    if args.command == "dashboard":
        return command_dashboard(args)
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
    run.add_argument(
        "--no-watch-files",
        action="store_true",
        help="Disable directory polling for dropped executables (on by default for run)",
    )
    run.add_argument(
        "--watch-path",
        action="append",
        default=[],
        help="Extra directory to watch for dropped executables (repeatable). Defaults include repo root, D:\\, D:\\thesis, Downloads, Desktop.",
    )
    run.add_argument("--attach-pid", action="append", type=int, default=[], help="PID to attach Frida to")
    run.add_argument("--auto-attach-new-processes", action="store_true", help="Attach Frida to new interesting processes observed by Sysmon")
    run.add_argument("--minimum-score", type=int, default=50, help="Minimum finding score")
    run.add_argument("--poll-interval", type=float, default=1.0, help="Sysmon polling interval in seconds")
    run.add_argument(
        "--jsonl",
        type=Path,
        help="JSONL output path (default: logs/session-<timestamp>.jsonl)",
    )
    run.add_argument("--no-jsonl", action="store_true", help="Disable JSONL logging")

    spawn = subparsers.add_parser("spawn", help="Spawn a sample under Frida, then correlate events")
    spawn.add_argument("argv", nargs=argparse.REMAINDER, help="Command line to spawn under Frida")
    spawn.add_argument("--watch-sysmon", action="store_true", help="Also poll Sysmon while the sample runs")
    spawn.add_argument("--minimum-score", type=int, default=50, help="Minimum finding score")
    spawn.add_argument(
        "--jsonl",
        type=Path,
        help="JSONL output path (default: logs/session-<timestamp>.jsonl)",
    )
    spawn.add_argument("--no-jsonl", action="store_true", help="Disable JSONL logging")

    dashboard = subparsers.add_parser("dashboard", help="Launch the web statistics dashboard")
    dashboard.add_argument("--host", default="127.0.0.1", help="Dashboard bind host")
    dashboard.add_argument("--port", type=int, default=8765, help="Dashboard bind port")
    dashboard.add_argument("--logs-dir", type=Path, help="Directory containing JSONL session logs")
    return parser


def command_triage(args: argparse.Namespace) -> int:
    result = triage_file(args.path)
    print(json.dumps(dataclasses.asdict(result), indent=2, sort_keys=True))
    return 0


def command_dashboard(args: argparse.Namespace) -> int:
    run_dashboard(host=args.host, port=args.port, logs_dir=args.logs_dir)
    return 0


def command_run(args: argparse.Namespace) -> int:
    global _WATCH_PATHS
    _SESSION_TRIAGED_PATHS.clear()
    _SESSION_TRIAGED_SHA.clear()
    _TRIAGE_PENDING.clear()
    correlator = Correlator(minimum_score=args.minimum_score)
    writer = _create_writer(args)
    monitor = _create_monitor_or_none()
    if monitor is not None:
        for pid in args.attach_pid:
            _safe_attach(monitor, pid)
    logs_dir = _logs_dir_from_writer(writer)
    _init_runtime_config(args, logs_dir)
    sysmon = _create_sysmon_or_none(args.watch_sysmon)
    file_watcher: FileDropWatcher | None = None
    file_watch_active = False
    _WATCH_PATHS: list[str] = []
    if writer.path is not None:
        print(f"[+] Dashboard tab 'File drops' -> session {writer.path.name}", flush=True)
        print("[+] Toggle file-drop watch from dashboard (File drops tab)", flush=True)

    try:
        while True:
            file_watcher, file_watch_active = _sync_file_watcher(
                args,
                file_watcher,
                file_watch_active,
                logs_dir,
            )
            _WATCH_PATHS = file_watcher.paths if file_watcher is not None else []
            touch_collector_heartbeat(
                logs_dir=logs_dir,
                watch_paths=_WATCH_PATHS,
            )
            if file_watcher is not None:
                _process_file_watch_batch(file_watcher, correlator, writer, args, logs_dir)
            if sysmon is not None:
                _process_sysmon_batch(
                    sysmon,
                    correlator,
                    writer,
                    monitor,
                    auto_attach=args.auto_attach_new_processes,
                    args=args,
                    logs_dir=logs_dir,
                )
            if monitor is not None:
                _drain_frida(
                    monitor,
                    correlator,
                    writer,
                    auto_attach=args.auto_attach_new_processes,
                )
            time.sleep(args.poll_interval)
    except KeyboardInterrupt:
        if file_watcher is not None:
            file_watcher.stop()
        mark_collector_stopped(logs_dir)
        if monitor is not None:
            monitor.detach_all()
        _shutdown_triage_executor()
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
    writer = _create_writer(args)
    monitor = _create_monitor_or_none()
    if monitor is None:
        return 2

    device = frida.get_local_device()
    pid = device.spawn(spawn_argv)
    _safe_attach(monitor, pid)
    device.resume(pid)
    print(f"[+] Spawned and attached PID {pid}: {' '.join(spawn_argv)}")
    sysmon = _create_sysmon_or_none(args.watch_sysmon)
    try:
        while True:
            if sysmon is not None:
                _process_sysmon_batch(
                    sysmon,
                    correlator,
                    writer,
                    monitor,
                    auto_attach=False,
                )
            _drain_frida(monitor, correlator, writer, auto_attach=True)
            time.sleep(0.25)
    except KeyboardInterrupt:
        monitor.detach_all()
        return 0


def _create_writer(args: argparse.Namespace) -> "JsonlWriter":
    if getattr(args, "no_jsonl", False):
        return JsonlWriter(None)
    path = args.jsonl or new_session_log_path()
    print(f"[+] Logging to {path}")
    return JsonlWriter(path)


def _logs_dir_from_writer(writer: "JsonlWriter") -> Path | None:
    if writer.path is None:
        return None
    return writer.path.parent


def _init_runtime_config(args: argparse.Namespace, logs_dir: Path | None) -> None:
    if logs_dir is None:
        return
    config = load_runtime_config(logs_dir)
    if getattr(args, "no_watch_files", False):
        config.file_drop_watch_enabled = False
        config.file_drop_watch_locked = True
    elif not config.file_drop_watch_locked:
        config.file_drop_watch_enabled = True
    save_runtime_config(config, logs_dir)


def _file_drop_watch_enabled(args: argparse.Namespace, logs_dir: Path | None) -> bool:
    if getattr(args, "no_watch_files", False):
        return False
    if logs_dir is None:
        return True
    config = load_runtime_config(logs_dir)
    return config.file_drop_watch_enabled


def _create_file_watcher(args: argparse.Namespace) -> FileDropWatcher | None:
    paths = default_watch_paths(args.watch_path)
    if not paths:
        print("[!] No watch paths exist for file-drop monitoring", file=sys.stderr, flush=True)
        return None
    watcher = FileDropWatcher(paths)
    watcher.start()
    print(f"[+] File scanner active on: {', '.join(watcher.paths)}", flush=True)
    print("[+] Copy a NEW .exe to a watched folder to trigger auto-triage", flush=True)
    return watcher


def _sync_file_watcher(
    args: argparse.Namespace,
    watcher: FileDropWatcher | None,
    was_active: bool,
    logs_dir: Path | None,
) -> tuple[FileDropWatcher | None, bool]:
    want_active = _file_drop_watch_enabled(args, logs_dir)
    if want_active and watcher is None:
        watcher = _create_file_watcher(args)
        if watcher is not None and was_active is False:
            print("[+] File drop watch enabled", flush=True)
    elif not want_active and watcher is not None:
        watcher.stop()
        watcher = None
        if was_active:
            print("[+] File drop watch paused (dashboard or CLI)", flush=True)
    return watcher, want_active


def _process_file_watch_batch(
    watcher: FileDropWatcher,
    correlator: Correlator,
    writer: "JsonlWriter",
    args: argparse.Namespace,
    logs_dir: Path | None,
) -> None:
    for event in watcher.drain():
        _handle_file_event(event, correlator, writer, args, logs_dir)


def _create_sysmon_or_none(watch_sysmon: bool) -> SysmonPoller | None:
    if not watch_sysmon:
        return None
    sysmon = SysmonPoller()
    try:
        list(sysmon.poll_once())
    except SysmonUnavailable as exc:
        print(f"[!] Sysmon unavailable: {exc}", file=sys.stderr)
        if "access denied" in str(exc).lower():
            print(f"[!] {SYSMON_ACCESS_HINT}", file=sys.stderr)
        else:
            print(f"[!] {SYSMON_INSTALL_HINT}", file=sys.stderr)
        print("[!] Continuing without Sysmon (Frida-only if attached).", file=sys.stderr)
        return None
    except Exception as exc:
        print(f"[!] Sysmon unavailable: {exc}", file=sys.stderr)
        print(f"[!] {SYSMON_ACCESS_HINT}", file=sys.stderr)
        print("[!] Continuing without Sysmon (Frida-only if attached).", file=sys.stderr)
        return None
    return sysmon


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
    *,
    args: argparse.Namespace | None = None,
    logs_dir: Path | None = None,
) -> None:
    try:
        events = list(sysmon.poll_once())
    except SysmonUnavailable as exc:
        print(f"[!] Sysmon unavailable: {exc}", file=sys.stderr)
        return
    for event in events:
        if isinstance(event, FileEvent):
            _handle_file_event(event, correlator, writer, args=args, logs_dir=logs_dir)
        elif isinstance(event, ProcessEvent):
            writer.write("sysmon", event)
            correlator.add_process(event)
            if auto_attach and monitor is not None and _should_auto_attach(event):
                _safe_attach(monitor, event.pid)
        elif isinstance(event, NetworkConnectionEvent):
            writer.write("sysmon", event)
            _handle_network_event(event, correlator, writer)
        elif isinstance(event, TelemetryEvent):
            writer.write("sysmon", event)


def _is_frida_lab_noise(path: str) -> bool:
    lower = path.lower()
    return "\\temp\\frida-" in lower or "\\appdata\\local\\temp\\frida-" in lower


def _wait_for_file(path: str, attempts: int = 24, delay: float = 0.25) -> bool:
    last_size = -1
    stable_reads = 0
    for _ in range(attempts):
        if not os.path.exists(path):
            time.sleep(delay)
            continue
        try:
            size = os.path.getsize(path)
        except OSError:
            time.sleep(delay)
            continue
        if size > 0 and size == last_size:
            stable_reads += 1
            if stable_reads >= 2:
                return True
        else:
            stable_reads = 0
        last_size = size
        time.sleep(delay)
    return os.path.exists(path)


def _norm_path(path: str) -> str:
    return str(Path(path)).lower()


def _get_triage_executor() -> ThreadPoolExecutor:
    global _TRIAGE_EXECUTOR
    if _TRIAGE_EXECUTOR is None:
        _TRIAGE_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="file-triage")
        atexit.register(_shutdown_triage_executor)
    return _TRIAGE_EXECUTOR


def _shutdown_triage_executor() -> None:
    global _TRIAGE_EXECUTOR
    if _TRIAGE_EXECUTOR is not None:
        _TRIAGE_EXECUTOR.shutdown(wait=False, cancel_futures=True)
        _TRIAGE_EXECUTOR = None


def _remember_triage(path: str, sha256: str | None = None) -> None:
    key = _norm_path(path)
    _SESSION_TRIAGED_PATHS.add(key)
    if sha256:
        _SESSION_TRIAGED_SHA[key] = sha256


def _already_triaged(path: str, sha256: str | None = None) -> bool:
    key = _norm_path(path)
    if key not in _SESSION_TRIAGED_PATHS:
        return False
    if sha256 and _SESSION_TRIAGED_SHA.get(key) != sha256:
        return False
    return True


def _announce_file_event(
    *,
    title: str,
    path: str,
    creator: str | None,
    creator_pid: int | None,
    triage: FileTriage | None,
    log_path: Path | None,
) -> None:
    lines = [
        "",
        "=" * 72,
        f" {title}",
        f" Path: {path}",
        f" Creator: {creator or 'unknown'} (pid={creator_pid or '-'})",
    ]
    if triage is not None:
        reasons = ", ".join(triage.suspicious_reasons) if triage.suspicious_reasons else "none"
        lines.extend(
            [
                f" Triage score: {triage.score}",
                f" PE: {triage.pe} | Signed: {triage.signed} | Entropy: {triage.entropy}",
                f" SHA256: {triage.sha256 or '-'}",
                f" Reasons: {reasons}",
            ]
        )
    if log_path is not None:
        lines.append(f" Log: {log_path}")
        lines.append(" Dashboard: http://127.0.0.1:8765 -> tab 'File drops'")
    lines.append("=" * 72)
    print("\n".join(lines), file=sys.stderr, flush=True)


def _run_triage_for_path(
    path: str,
    *,
    creator_image: str | None,
    creator_pid: int | None,
    timestamp: Any,
    correlator: Correlator,
    writer: "JsonlWriter",
    title: str,
) -> FileEvent | None:
    if not is_interesting_path(path) or _is_frida_lab_noise(path):
        return None
    if not _wait_for_file(path):
        print(f"[!] Detected {path} but file not readable yet", file=sys.stderr, flush=True)
        return None

    triage = triage_file(path, quick=True)
    if _already_triaged(path, triage.sha256):
        return None
    writer.write("triage", triage)
    enriched = FileEvent(
        timestamp=timestamp,
        path=path,
        creator_pid=creator_pid,
        creator_image=creator_image,
        sha256=triage.sha256,
        signed=triage.signed,
        entropy=triage.entropy,
        pe=triage.pe,
    )
    writer.write("file", enriched)
    correlator.add_file(enriched)
    _remember_triage(path, triage.sha256)
    _announce_file_event(
        title=title,
        path=path,
        creator=creator_image,
        creator_pid=creator_pid,
        triage=triage,
        log_path=writer.path,
    )
    return enriched


def _triage_worker(
    event: FileEvent,
    correlator: Correlator,
    writer: "JsonlWriter",
) -> None:
    key = _norm_path(event.path or "")
    try:
        with _TRIAGE_LOCK:
            _run_triage_for_path(
                event.path or "",
                creator_image=event.creator_image,
                creator_pid=event.creator_pid,
                timestamp=event.timestamp,
                correlator=correlator,
                writer=writer,
                title="FILE DROP DETECTED",
            )
    finally:
        _TRIAGE_PENDING.discard(key)


def _handle_file_event(
    event: FileEvent,
    correlator: Correlator,
    writer: "JsonlWriter",
    *,
    args: argparse.Namespace | None = None,
    logs_dir: Path | None = None,
) -> None:
    if not event.path:
        return
    if not is_interesting_path(event.path) or _is_frida_lab_noise(event.path):
        writer.write("file", event)
        correlator.add_file(event)
        return

    if args is not None and not _file_drop_watch_enabled(args, logs_dir):
        writer.write("file", event)
        correlator.add_file(event)
        return

    key = _norm_path(event.path)
    if _already_triaged(event.path) or key in _TRIAGE_PENDING:
        return

    _TRIAGE_PENDING.add(key)
    print(
        f"[FILE:DROP] Detected {event.path} - starting triage...",
        file=sys.stderr,
        flush=True,
    )
    writer.write("file", event)
    correlator.add_file(event)
    _get_triage_executor().submit(_triage_worker, event, correlator, writer)


def _maybe_triage_process_image(
    event: ProcessEvent,
    correlator: Correlator,
    writer: "JsonlWriter",
) -> None:
    if not event.image or _is_process_triage_noise(event):
        return
    if _WATCH_PATHS and not _path_within_watch_dirs(event.image, _WATCH_PATHS):
        return
    if correlator.files_by_path.get(_norm_path(event.image)) is not None:
        return
    _run_triage_for_path(
        event.image,
        creator_image=event.parent_image,
        creator_pid=event.parent_pid,
        timestamp=event.timestamp,
        correlator=correlator,
        writer=writer,
        title="SUSPICIOUS PROCESS IMAGE (auto-triage)",
    )


def _path_within_watch_dirs(path: str, watch_paths: list[str]) -> bool:
    target = _norm_path(path)
    for directory in watch_paths:
        prefix = _norm_path(directory).rstrip("\\") + "\\"
        if target.startswith(prefix) or target == _norm_path(directory):
            return True
    return False


def _is_process_triage_noise(event: ProcessEvent) -> bool:
    if not is_interesting_path(event.image):
        return True
    if _is_frida_lab_noise(event.image):
        return True
    lower = event.image.lower()
    if "\\windows\\" in lower:
        return True
    if "\\program files" in lower:
        return True
    if "\\cursor-agent\\" in lower or "\\cursor\\" in lower:
        return True
    if "\\noirlycan_thesis\\" in lower and "\\.venv\\" in lower:
        return True
    if lower.endswith("powershell.exe") or lower.endswith("python.exe"):
        return True
    if "__psscriptpolicytest_" in lower:
        return True
    return False


def _drain_frida(
    monitor: FridaInjectionMonitor,
    correlator: Correlator,
    writer: "JsonlWriter",
    auto_attach: bool = False,
) -> None:
    while True:
        try:
            runtime_event = monitor.events().get_nowait()
        except queue.Empty:
            return
        writer.write("frida_raw", runtime_event.payload)
        process_event = runtime_event_to_process(runtime_event)
        if process_event is not None:
            writer.write("frida_process", process_event)
            correlator.add_process(process_event)
            if auto_attach and _should_auto_attach(process_event):
                _safe_attach(monitor, process_event.pid)
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


def _handle_network_event(
    event: NetworkConnectionEvent,
    correlator: Correlator,
    writer: "JsonlWriter",
) -> None:
    watched = correlator.add_network_connection(event)
    if watched is None:
        return
    writer.write("network", watched)
    if is_external_beacon_candidate(watched.destination_ip, watched.destination_hostname):
        print(
            f"[NETWORK:BEACON?] PID {watched.pid} "
            f"({watched.image or 'unknown'}) -> {watched.endpoint} "
            f"via {watched.protocol or 'unknown'}"
        )
    else:
        print(
            f"[NETWORK] PID {watched.pid} "
            f"({watched.image or 'unknown'}) -> {watched.endpoint}"
        )


def print_finding(finding: Finding) -> None:
    print(
        f"[{finding.severity.value.upper()}:{finding.score}] "
        f"{finding.title}: {finding.description}"
    )
    print("  APIs:", ", ".join(sorted({primitive.api for primitive in finding.primitives})))
    if finding.related_file:
        print(f"  Related file: {finding.related_file.path}")
    if finding.score >= 70 and finding.target_pid is not None:
        print(
            f"  Network watch enabled for PID {finding.target_pid} "
            f"(5 min, outbound Sysmon EID 3)"
        )


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
