from __future__ import annotations

import argparse
import atexit
import dataclasses
import json
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from noirlycan_core.kernel.entities.models import FileEvent, ProcessEvent
from noirlycan_core.analysis.domain.classifier_config import ensure_classifier_config
from noirlycan_core.analysis.domain.correlation import Correlator
from noirlycan_agent.collector.application.analysis_queue import (
    drain_analysis_queue,
    enqueue_analysis,
)
from noirlycan_agent.collector.application.collector_launcher import (
    clear_collector_pid,
    register_collector_pid,
)
from noirlycan_agent.collector.application.collector_runtime import (
    JsonlWriter,
    create_monitor_or_none as _create_monitor_or_none,
    create_sysmon_or_none as _create_sysmon_or_none,
    drain_frida as _drain_frida,
    drain_tcp_watch as _drain_tcp_watch,
    drain_wfp_watch as _drain_wfp_watch,
    print_finding,
    process_sysmon_batch as _process_sysmon_batch_core,
    safe_attach as _safe_attach,
)
from noirlycan_agent.collector.infrastructure.tcp_watch import TcpWatchPoller
from noirlycan_agent.collector.infrastructure.wfp_watch import WfpPoller, enable_wfp_audit


def _safe_resume(device: Any, pid: int) -> None:
    # When child gating is active (enable_auto_attach), the gating callback
    # races to resume the same pid — whichever resumes first wins and the
    # second call would otherwise raise "invalid operation".
    try:
        device.resume(pid)
    except Exception:
        pass


from noirlycan_agent.collector.application.remote_sink import (
    ConsoleRemoteClient,
    RemoteJsonlWriter,
    drain_agent_commands,
)
from noirlycan_core.runtime.agent_config import apply_agent_config, load_agent_config
from noirlycan_core.runtime.agent_identity import resolve_agent_credentials
from noirlycan_core.runtime.config import (
    load_runtime_config,
    mark_collector_stopped,
    save_runtime_config,
    touch_collector_heartbeat,
)
from noirlycan_agent.collector.application.policy_sync import apply_runtime_policy, resolve_active_policy
from noirlycan_agent.collector.infrastructure.file_watch import FileDropWatcher, default_watch_paths
from noirlycan_agent.collector.infrastructure.frida_manager import FridaInjectionMonitor
from noirlycan_agent.collector.infrastructure.sysmon import SysmonPoller
from noirlycan_agent.collector.infrastructure.triage import (
    FileTriage,
    is_interesting_path,
    triage_file,
)
from noirlycan_core.storage.infrastructure.analysis_db import AnalysisDatabase
from noirlycan_core.storage.infrastructure.log_store import new_session_log_path

_SESSION_TRIAGED_PATHS: set[str] = set()
_SESSION_TRIAGED_SHA: dict[str, str] = {}
_SESSION_API_SCHEDULED: set[str] = set()
_SESSION_API_SPAWNED: set[tuple[str, tuple[str, ...]]] = set()
_WATCH_PATHS: list[str] = []
_TRIAGE_PENDING: set[str] = set()
_TRIAGE_LOCK = threading.Lock()
_TRIAGE_EXECUTOR: ThreadPoolExecutor | None = None


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "config", None) is not None:
        apply_agent_config(args, load_agent_config(args.config))
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
        prog="noirlycan-agent",
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
    run.add_argument("--config", type=Path, help="Agent TOML config exported from dashboard")
    run.add_argument("--server", default="", help="Console endpoint host:port for remote ingest")
    run.add_argument("--token", default="", help="Enrollment token from dashboard (saved in logs/.agent_identity.json)")
    run.add_argument("--agent-id", default="", help="Agent id registered on dashboard (saved in logs/.agent_identity.json)")

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
    spawn.add_argument("--config", type=Path, help="Agent TOML config exported from dashboard")
    spawn.add_argument("--server", default="", help="Console endpoint host:port for remote ingest")
    spawn.add_argument("--token", default="", help="Enrollment token from dashboard (saved in logs/.agent_identity.json)")
    spawn.add_argument("--agent-id", default="", help="Agent id registered on dashboard (saved in logs/.agent_identity.json)")

    return parser


def command_triage(args: argparse.Namespace) -> int:
    result = triage_file(args.path)
    print(json.dumps(dataclasses.asdict(result), indent=2, sort_keys=True))
    return 0



def command_run(args: argparse.Namespace) -> int:
    global _WATCH_PATHS
    _SESSION_TRIAGED_PATHS.clear()
    _SESSION_TRIAGED_SHA.clear()
    _SESSION_API_SCHEDULED.clear()
    _SESSION_API_SPAWNED.clear()
    _TRIAGE_PENDING.clear()
    writer = _create_writer(args)
    remote = _remote_client(writer)
    logs_dir = _logs_dir_from_writer(writer)
    ensure_classifier_config(logs_dir)
    correlator = Correlator(minimum_score=args.minimum_score, logs_dir=logs_dir)
    monitor = _create_monitor_or_none(logs_dir)
    apply_runtime_policy(
        correlator,
        resolve_active_policy(logs_dir, remote.policy if remote else None),
        monitor=monitor,
    )
    if monitor is not None:
        for pid in args.attach_pid:
            _safe_attach(monitor, pid)
    _init_runtime_config(args, logs_dir)
    if logs_dir is not None:
        register_collector_pid(logs_dir, os.getpid())
    sysmon = _create_sysmon_or_none(args.watch_sysmon)
    tcp_poller = TcpWatchPoller()
    wfp_poller: WfpPoller | None = None
    if enable_wfp_audit():
        wfp_poller = WfpPoller()
    file_watcher: FileDropWatcher | None = None
    file_watch_active = False
    _WATCH_PATHS = []
    if writer.path is not None:
        print(f"[+] Dashboard tab 'File drops' -> session {writer.path.name}", flush=True)
        print("[+] Toggle file-drop watch from dashboard (File drops tab)", flush=True)

    try:
        while True:
            apply_runtime_policy(
                correlator,
                resolve_active_policy(logs_dir, remote.policy if remote else None),
                monitor=monitor,
            )
            auto_attach = _effective_auto_attach(args, logs_dir, remote)
            if auto_attach and monitor is not None:
                monitor.enable_auto_attach()
            file_watcher, file_watch_active = _sync_file_watcher(
                args,
                file_watcher,
                file_watch_active,
                logs_dir,
                remote,
            )
            _WATCH_PATHS = file_watcher.paths if file_watcher is not None else []
            touch_collector_heartbeat(
                logs_dir=logs_dir,
                watch_paths=_WATCH_PATHS,
            )
            if file_watcher is not None:
                _process_file_watch_batch(file_watcher, correlator, writer, args, logs_dir, remote)
            _process_analysis_queue(monitor, correlator, writer, args, logs_dir)
            if sysmon is not None:
                _process_sysmon_batch(
                    sysmon,
                    correlator,
                    writer,
                    monitor,
                    auto_attach=auto_attach,
                    args=args,
                    logs_dir=logs_dir,
                )
            if monitor is not None:
                _drain_frida(
                    monitor,
                    correlator,
                    writer,
                    auto_attach=auto_attach,
                )
            _drain_tcp_watch(tcp_poller, correlator, writer)
            if wfp_poller is not None:
                _drain_wfp_watch(wfp_poller, correlator, writer)
            drain_agent_commands(remote)
            if remote is not None:
                remote.heartbeat(watching=", ".join(_WATCH_PATHS))
            interval = 0.2 if correlator.network_watch_pids() else args.poll_interval
            time.sleep(interval)
    except KeyboardInterrupt:
        if remote is not None:
            remote.goodbye()
        if file_watcher is not None:
            file_watcher.stop()
        if logs_dir is not None:
            clear_collector_pid(logs_dir)
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

    writer = _create_writer(args)
    remote = _remote_client(writer)
    logs_dir = _logs_dir_from_writer(writer)
    correlator = Correlator(minimum_score=args.minimum_score, logs_dir=logs_dir)
    monitor = _create_monitor_or_none(logs_dir)
    if monitor is None:
        return 2
    apply_runtime_policy(
        correlator,
        resolve_active_policy(logs_dir, remote.policy if remote else None),
        monitor=monitor,
    )

    device = frida.get_local_device()
    pid = device.spawn(spawn_argv)
    _safe_attach(monitor, pid)
    _safe_resume(device, pid)
    print(f"[+] Spawned and attached PID {pid}: {' '.join(spawn_argv)}")
    sysmon = _create_sysmon_or_none(args.watch_sysmon)
    tcp_poller_spawn = TcpWatchPoller()
    wfp_spawn = WfpPoller() if enable_wfp_audit() else None
    try:
        while True:
            apply_runtime_policy(
                correlator,
                resolve_active_policy(logs_dir, remote.policy if remote else None),
                monitor=monitor,
            )
            if sysmon is not None:
                _process_sysmon_batch(
                    sysmon,
                    correlator,
                    writer,
                    monitor,
                    auto_attach=False,
                )
            _drain_frida(monitor, correlator, writer, auto_attach=True)
            _drain_tcp_watch(tcp_poller_spawn, correlator, writer)
            if wfp_spawn is not None:
                _drain_wfp_watch(wfp_spawn, correlator, writer)
            drain_agent_commands(remote)
            time.sleep(0.25)
    except KeyboardInterrupt:
        monitor.detach_all()
        return 0


def _create_writer(args: argparse.Namespace) -> "JsonlWriter | RemoteJsonlWriter":
    if getattr(args, "no_jsonl", False):
        base = JsonlWriter(None)
    else:
        path = args.jsonl or new_session_log_path()
        print(f"[+] Logging to {path}")
        base = JsonlWriter(path)
    return _attach_remote(args, base)


def _attach_remote(args: argparse.Namespace, writer: JsonlWriter) -> "JsonlWriter | RemoteJsonlWriter":
    server = str(getattr(args, "server", "") or "").strip()
    token = str(getattr(args, "token", "") or "").strip()
    if not server or not token:
        return writer
    mode = "spawn" if getattr(args, "command", "") == "spawn" else "run"
    logs_dir = writer.path.parent if writer.path is not None else None
    explicit_id = str(getattr(args, "agent_id", "") or "").strip() or None
    explicit_token = str(getattr(args, "token", "") or "").strip() or None
    agent_id, saved_token = resolve_agent_credentials(logs_dir, explicit_id, explicit_token)
    token = explicit_token or saved_token or token
    if not token:
        print(
            "[!] Register the agent on the dashboard and pass --agent-id and --token",
            file=sys.stderr,
            flush=True,
        )
    session_name = writer.path.name if writer.path is not None else None
    remote = ConsoleRemoteClient(
        server,
        token,
        agent_id=agent_id,
        session_name=session_name,
        mode=mode,
        logs_dir=writer.path.parent if writer.path is not None else None,
    )
    watching = ", ".join(getattr(args, "watch_path", []) or [])
    try:
        remote.hello(watching=watching)
        print(f"[+] Connected to console {server} as agent {remote.agent_id}", flush=True)
    except Exception as exc:
        print(f"[!] Console hello failed: {exc}", file=sys.stderr, flush=True)
    return RemoteJsonlWriter(writer, remote)


def _remote_client(writer: Any) -> ConsoleRemoteClient | None:
    if isinstance(writer, RemoteJsonlWriter):
        return writer.remote
    return None


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


def _auto_api_analysis_enabled(
    args: argparse.Namespace,
    logs_dir: Path | None,
    remote: ConsoleRemoteClient | None = None,
) -> bool:
    if getattr(args, "no_watch_files", False):
        return False
    if logs_dir is None:
        return False
    config = load_runtime_config(logs_dir)
    if config.auto_api_analysis_enabled:
        return True
    # Fleet agents connected to the console auto-spawn dropped EXEs under Frida hooks.
    return remote is not None


def _auto_static_triage_enabled(args: argparse.Namespace, logs_dir: Path | None) -> bool:
    if getattr(args, "no_watch_files", False):
        return False
    if logs_dir is None:
        return False
    config = load_runtime_config(logs_dir)
    return config.auto_static_triage_enabled


def _effective_auto_attach(
    args: argparse.Namespace,
    logs_dir: Path | None,
    remote: ConsoleRemoteClient | None,
) -> bool:
    if getattr(args, "auto_attach_new_processes", False):
        return True
    policy = resolve_active_policy(logs_dir, remote.policy if remote else None)
    return policy.auto_attach if policy is not None else False


def _policy_watch_paths(
    args: argparse.Namespace,
    logs_dir: Path | None,
    remote: ConsoleRemoteClient | None,
) -> list[str]:
    policy = resolve_active_policy(logs_dir, remote.policy if remote else None)
    if policy and policy.folders:
        existing = [str(Path(item).expanduser().resolve()) for item in policy.folders if Path(item).expanduser().exists()]
        if existing:
            return existing
    return default_watch_paths(args.watch_path)


def _create_file_watcher(paths: list[str]) -> FileDropWatcher | None:
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
    remote: ConsoleRemoteClient | None = None,
) -> tuple[FileDropWatcher | None, bool]:
    want_active = _file_drop_watch_enabled(args, logs_dir)
    if want_active and watcher is None:
        watcher = _create_file_watcher(_policy_watch_paths(args, logs_dir, remote))
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
    remote: ConsoleRemoteClient | None = None,
) -> None:
    for event in watcher.drain():
        _handle_file_event(event, correlator, writer, args=args, logs_dir=logs_dir, remote=remote)


def _process_analysis_queue(
    monitor: FridaInjectionMonitor | None,
    correlator: Correlator,
    writer: "JsonlWriter",
    args: argparse.Namespace,
    logs_dir: Path | None,
) -> None:
    if logs_dir is None:
        return
    for request in drain_analysis_queue(logs_dir):
        if not is_interesting_path(request.path) or _is_frida_lab_noise(request.path):
            continue
        if request.mode == "api":
            _run_api_analysis(
                monitor,
                request.path,
                correlator,
                writer,
                source="dashboard",
                argv=request.argv,
            )
            continue
        event = FileEvent(
            timestamp=datetime.now(timezone.utc),
            path=request.path,
            creator_pid=None,
            creator_image="dashboard",
        )
        _schedule_file_triage(event, correlator, writer, source="dashboard", write_event=False)


def _mark_upload_analysis_spawned(writer: "JsonlWriter", path: str) -> None:
    logs_dir = _logs_dir_from_writer(writer)
    if logs_dir is None:
        return
    session_name = writer.path.name if writer.path is not None else None
    AnalysisDatabase(logs_dir).set_upload_status_for_path(
        path,
        status="spawned",
        session_name=session_name,
    )


def _mark_upload_analysis_failed(
    writer: "JsonlWriter",
    path: str,
    *,
    error: str,
) -> None:
    logs_dir = _logs_dir_from_writer(writer)
    if logs_dir is None:
        return
    AnalysisDatabase(logs_dir).set_upload_status_for_path(
        path,
        status="failed",
        error_message=error,
    )


def _schedule_api_analysis(path: str) -> bool:
    """Reserve one auto API analysis per normalized path for this run session."""
    key = _norm_path(path)
    if key in _SESSION_API_SCHEDULED or any(item[0] == key for item in _SESSION_API_SPAWNED):
        return False
    _SESSION_API_SCHEDULED.add(key)
    return True


def _run_api_analysis(
    monitor: FridaInjectionMonitor | None,
    path: str,
    correlator: Correlator,
    writer: "JsonlWriter",
    *,
    source: str,
    argv: list[str] | None = None,
) -> bool:
    extra_argv = [str(part) for part in (argv or []) if str(part).strip()]
    key = (_norm_path(path), tuple(extra_argv))
    if key in _SESSION_API_SPAWNED:
        print(
            f"[!] API analysis already completed for {path}, skipping duplicate spawn",
            file=sys.stderr,
            flush=True,
        )
        return False
    if monitor is None:
        print(
            f"[!] Cannot run API analysis for {path}: Frida is unavailable",
            file=sys.stderr,
            flush=True,
        )
        _mark_upload_analysis_failed(
            writer,
            path,
            error="frida_unavailable",
        )
        writer.write(
            "api_run",
            {
                "path": path,
                "source": source,
                "status": "failed",
                "error": "frida_unavailable",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )
        return False

    try:
        import frida
    except ImportError:
        print(
            f"[!] Cannot run API analysis for {path}: Frida package not installed",
            file=sys.stderr,
            flush=True,
        )
        return False

    resolved = str(Path(path).resolve())
    spawn_argv = [resolved, *extra_argv]
    try:
        device = frida.get_local_device()
        pid = device.spawn(spawn_argv)
        _safe_attach(monitor, pid)
        _safe_resume(device, pid)
    except Exception as exc:
        print(f"[!] API spawn failed for {path}: {exc}", file=sys.stderr, flush=True)
        _mark_upload_analysis_failed(writer, resolved, error=str(exc))
        writer.write(
            "api_run",
            {
                "path": resolved,
                "argv": spawn_argv,
                "source": source,
                "status": "failed",
                "error": str(exc),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )
        return False

    _mark_upload_analysis_spawned(writer, resolved)
    timestamp = datetime.now(timezone.utc)
    writer.write(
        "api_run",
        {
            "path": resolved,
            "pid": pid,
            "argv": spawn_argv,
            "source": source,
            "status": "started",
            "timestamp": timestamp.isoformat(),
        },
    )
    _SESSION_API_SPAWNED.add(key)
    command_line = " ".join(spawn_argv)
    process_event = ProcessEvent(
        timestamp=timestamp,
        pid=pid,
        image=resolved,
        parent_image="noirlycan-api-spawn",
        parent_pid=None,
        command_line=command_line,
        created_from_file=resolved,
        flags=["api_spawn"],
    )
    writer.write("frida_process", process_event)
    correlator.add_process(process_event)
    print(
        f"[API:RUN] Spawned {command_line} as PID {pid} under Frida injection hooks",
        flush=True,
    )
    return True


def _schedule_file_triage(
    event: FileEvent,
    correlator: Correlator,
    writer: "JsonlWriter",
    *,
    source: str,
    write_event: bool = True,
) -> None:
    if not event.path:
        return
    key = _norm_path(event.path)
    if _already_triaged(event.path) or key in _TRIAGE_PENDING:
        return

    _TRIAGE_PENDING.add(key)
    if source == "dashboard":
        print(
            f"[FILE:TRIAGE] Queued analysis for {event.path} (from dashboard)",
            file=sys.stderr,
            flush=True,
        )
    else:
        print(
            f"[FILE:DROP] Detected {event.path} - starting triage...",
            file=sys.stderr,
            flush=True,
        )
    if write_event:
        writer.write("file", event)
        correlator.add_file(event)
    _get_triage_executor().submit(_triage_worker, event, correlator, writer)


def _process_sysmon_batch(
    sysmon: SysmonPoller,
    correlator: Correlator,
    writer: JsonlWriter,
    monitor: FridaInjectionMonitor | None,
    auto_attach: bool,
    *,
    args: argparse.Namespace | None = None,
    logs_dir: Path | None = None,
) -> None:
    remote = _remote_client(writer)

    def file_handler(event: FileEvent, corr: Correlator, out: JsonlWriter) -> None:
        _handle_file_event(event, corr, out, args=args, logs_dir=logs_dir, remote=remote)

    def process_handler(event: ProcessEvent, corr: Correlator, out: JsonlWriter) -> None:
        _maybe_triage_process_image(event, corr, out)

    _process_sysmon_batch_core(
        sysmon,
        correlator,
        writer,
        monitor,
        auto_attach,
        file_handler=file_handler,
        process_handler=process_handler,
    )


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
    remote: ConsoleRemoteClient | None = None,
) -> None:
    if not event.path:
        return
    if not is_interesting_path(event.path) or _is_frida_lab_noise(event.path):
        writer.write("file", event)
        correlator.add_file(event)
        return

    writer.write("file", event)
    correlator.add_file(event)

    auto_api = args is not None and _auto_api_analysis_enabled(args, logs_dir, remote)
    auto_static = args is not None and _auto_static_triage_enabled(args, logs_dir)
    if auto_api and logs_dir is not None:
        _run_triage_for_path(
            event.path,
            creator_image=event.creator_image,
            creator_pid=event.creator_pid,
            timestamp=event.timestamp,
            correlator=correlator,
            writer=writer,
            title="FILE DROP DETECTED",
        )
        if _schedule_api_analysis(event.path):
            enqueue_analysis(event.path, logs_dir, mode="api")
            print(
                f"[FILE:DROP] Detected {event.path} - queued API hook analysis",
                file=sys.stderr,
                flush=True,
            )
        else:
            print(
                f"[FILE:DROP] Detected {event.path} - API analysis already scheduled for this session",
                file=sys.stderr,
                flush=True,
            )
    elif auto_static:
        _schedule_file_triage(event, correlator, writer, source="auto", write_event=False)
    else:
        print(
            f"[FILE:DROP] Detected {event.path} - enable auto API analysis or connect agent with --server",
            file=sys.stderr,
            flush=True,
        )


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


if __name__ == "__main__":
    raise SystemExit(main())
