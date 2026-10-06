"""The agent's collection loop: poll every sensor, feed the detector, talk to the console."""

from __future__ import annotations

import argparse
import os
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from noirlycan_agent.runtime.collector_pid import clear_collector_pid, register_collector_pid
from noirlycan_agent.runtime.commands import CommandDispatcher, kill_process
from noirlycan_agent.runtime.console_client import ConsoleClient
from noirlycan_agent.runtime.event_sink import BatchUploader, EventSink, JsonlWriter, MirroredWriter
from noirlycan_agent.runtime.file_intake import FileIntake
from noirlycan_agent.runtime.pipeline import (
    create_monitor_or_none,
    create_sysmon_or_none,
    drain_frida,
    drain_tcp_watch,
    drain_wfp_watch,
    process_sysmon_batch,
    safe_attach,
)
from noirlycan_agent.runtime.policy_sync import apply_runtime_policy
from noirlycan_agent.runtime.sample_runner import SampleRunner, spawn_under_frida
from noirlycan_agent.sensors.file_watch import FileDropWatcher, default_watch_paths
from noirlycan_agent.sensors.frida_monitor import FridaInjectionMonitor
from noirlycan_agent.sensors.tcp_watch import TcpWatchPoller
from noirlycan_agent.sensors.wfp_watch import WfpPoller, enable_wfp_audit
from noirlycan_core.classification.config import ensure_classifier_config
from noirlycan_core.detection.correlator import Correlator
from noirlycan_core.models import Finding
from noirlycan_core.runtime.agent_identity import resolve_agent_credentials
from noirlycan_core.runtime.agent_policy import AgentPolicy, load_agent_policy
from noirlycan_core.runtime.config import (
    load_runtime_config,
    mark_collector_stopped,
    save_runtime_config,
    touch_collector_heartbeat,
)
from noirlycan_core.storage.log_store import new_session_log_path

FAST_POLL_SECONDS = 0.2  # While a victim PID is under network watch.


@dataclass
class Tick:
    """Policy and runtime settings read once per loop iteration."""

    policy: AgentPolicy | None
    file_watch: bool
    auto_api_analysis: bool
    auto_static_triage: bool
    auto_attach: bool
    watch_paths: list[str] = field(default_factory=list)


@dataclass
class Agent:
    args: argparse.Namespace
    sink: EventSink
    logs_dir: Path | None
    correlator: Correlator
    monitor: FridaInjectionMonitor | None
    console: ConsoleClient | None
    runner: SampleRunner
    intake: FileIntake
    commands: CommandDispatcher

    def read_tick(self) -> Tick:
        policy = self.console.policy if self.console and self.console.policy else (
            load_agent_policy(self.logs_dir) if self.logs_dir else None
        )
        config = load_runtime_config(self.logs_dir) if self.logs_dir else None
        files_off = bool(getattr(self.args, "no_watch_files", False))
        folders = [str(Path(item).expanduser().resolve()) for item in (policy.folders if policy else []) if Path(item).expanduser().exists()]
        return Tick(
            policy=policy,
            file_watch=not files_off and (config.file_drop_watch_enabled if config else True),
            auto_api_analysis=not files_off and config is not None and (config.auto_api_analysis_enabled or self.console is not None),
            auto_static_triage=not files_off and config is not None and config.auto_static_triage_enabled,
            auto_attach=bool(getattr(self.args, "auto_attach_new_processes", False)) or bool(policy and policy.auto_attach),
            watch_paths=folders or default_watch_paths(getattr(self.args, "watch_path", [])),
        )

    def apply(self, tick: Tick) -> None:
        apply_runtime_policy(self.correlator, tick.policy, monitor=self.monitor)
        self.intake.settings.auto_api_analysis = tick.auto_api_analysis
        self.intake.settings.auto_static_triage = tick.auto_static_triage
        if tick.auto_attach and self.monitor is not None:
            self.monitor.enable_auto_attach()

    def poll_sensors(self, sysmon: Any, network_pollers: list[Any], *, auto_attach: bool) -> None:
        raw = bool(getattr(self.args, "raw_events", False))
        if sysmon is not None:
            process_sysmon_batch(
                sysmon,
                self.correlator,
                self.sink,
                self.monitor,
                auto_attach,
                file_handler=self.intake.on_file,
                process_handler=self.intake.on_process,
                raw_events=raw,
            )
        if self.monitor is not None:
            drain_frida(self.monitor, self.correlator, self.sink, auto_attach=auto_attach, raw_events=raw)
        for poller in network_pollers:
            drain = drain_wfp_watch if isinstance(poller, WfpPoller) else drain_tcp_watch
            drain(poller, self.correlator, self.sink)
        if self.console is not None:
            self.commands.dispatch(self.console.poll_commands())

    def shutdown(self) -> None:
        if self.console is not None:
            self.console.goodbye()
        if self.monitor is not None:
            self.monitor.detach_all()
        self.intake.shutdown()
        self.sink.close()


def build_agent(args: argparse.Namespace, *, mode: str) -> Agent:
    local = JsonlWriter(None if getattr(args, "no_jsonl", False) else (args.jsonl or new_session_log_path()))
    if local.path is not None:
        print(f"[+] Logging to {local.path}")
    logs_dir = local.path.parent if local.path is not None else None
    try:
        console = _connect_console(args, logs_dir, mode=mode)
    except Exception:
        local.close()
        raise
    sink: EventSink = local
    if console is not None:
        sink = MirroredWriter(local, BatchUploader(console.ingest_batch), on_finding=lambda f: _maybe_auto_kill(console, f))

    if logs_dir is not None:
        ensure_classifier_config(logs_dir)
    correlator = Correlator(minimum_score=args.minimum_score, logs_dir=logs_dir)
    monitor = create_monitor_or_none(logs_dir)
    runner = SampleRunner(monitor=monitor, correlator=correlator, sink=sink, logs_dir=logs_dir, console=console)
    return Agent(
        args=args,
        sink=sink,
        logs_dir=logs_dir,
        correlator=correlator,
        monitor=monitor,
        console=console,
        runner=runner,
        intake=FileIntake(correlator=correlator, sink=sink, runner=runner),
        commands=CommandDispatcher(
            verifier=lambda: console.verifier if console else None,
            on_sample=runner.accept_console_sample if console else None,
            report=console.report_command_result if console else None,
        ),
    )


def run_collector(
    args: argparse.Namespace,
    *,
    stop_event: threading.Event | None = None,
    on_ready: Callable[[Agent], None] | None = None,
) -> int:
    """Watch the VM until Ctrl+C or a desktop stop request."""
    stop_event = stop_event or threading.Event()
    agent = build_agent(args, mode="run")
    watcher: FileDropWatcher | None = None
    try:
        agent.apply(agent.read_tick())
        if agent.monitor is not None:
            for pid in args.attach_pid:
                safe_attach(agent.monitor, pid)
        _lock_file_watch_from_cli(args, agent.logs_dir)
        if agent.logs_dir is not None:
            register_collector_pid(agent.logs_dir, os.getpid())
        sysmon = create_sysmon_or_none(args.watch_sysmon)
        network_pollers: list[Any] = [TcpWatchPoller()]
        if enable_wfp_audit():
            network_pollers.append(WfpPoller())
        if on_ready is not None and not stop_event.is_set():
            on_ready(agent)
        while not stop_event.is_set():
            tick = agent.read_tick()
            agent.apply(tick)
            watcher = _sync_watcher(watcher, tick)
            agent.intake.watch_paths = watcher.paths if watcher is not None else []
            touch_collector_heartbeat(logs_dir=agent.logs_dir, watch_paths=agent.intake.watch_paths)
            if watcher is not None:
                for event in watcher.drain():
                    agent.intake.on_file(event)
            agent.runner.process_queue(agent.intake.triage_path)
            agent.poll_sensors(sysmon, network_pollers, auto_attach=tick.auto_attach)
            if agent.console is not None:
                agent.console.heartbeat(watching=", ".join(agent.intake.watch_paths))
            stop_event.wait(FAST_POLL_SECONDS if agent.correlator.network_watch_pids() else args.poll_interval)
    except KeyboardInterrupt:
        pass
    finally:
        if watcher is not None:
            watcher.stop()
        if agent.logs_dir is not None:
            clear_collector_pid(agent.logs_dir)
        mark_collector_stopped(agent.logs_dir)
        agent.shutdown()
    return 0


def run_spawn(args: argparse.Namespace, argv: list[str]) -> int:
    """``noirlycan-agent spawn -- <cmd>``: start one sample under Frida and watch it."""
    agent = build_agent(args, mode="spawn")
    if agent.monitor is None:
        return 2
    agent.apply(agent.read_tick())
    pid = spawn_under_frida(agent.monitor, argv)
    print(f"[+] Spawned and attached PID {pid}: {' '.join(argv)}")
    sysmon = create_sysmon_or_none(args.watch_sysmon)
    network_pollers: list[Any] = [TcpWatchPoller()]
    if enable_wfp_audit():
        network_pollers.append(WfpPoller())
    try:
        while True:
            agent.apply(agent.read_tick())
            agent.poll_sensors(sysmon, network_pollers, auto_attach=True)
            time.sleep(0.25)
    except KeyboardInterrupt:
        agent.shutdown()
        return 0


def _connect_console(args: argparse.Namespace, logs_dir: Path | None, *, mode: str) -> ConsoleClient | None:
    server = str(getattr(args, "server", "") or "").strip()
    explicit_token = str(getattr(args, "token", "") or "").strip() or None
    explicit_id = str(getattr(args, "agent_id", "") or "").strip() or None
    if not server:
        return None
    agent_id, token = resolve_agent_credentials(logs_dir, explicit_id, explicit_token)
    if not token:
        if getattr(args, "require_console", False):
            raise ValueError("Agent token is missing or could not be decrypted; enter the token again.")
        print("[!] Register the agent on the dashboard and pass --agent-id and --token", file=sys.stderr, flush=True)
        return None
    console = ConsoleClient(
        server,
        token,
        agent_id=agent_id,
        mode=mode,
        logs_dir=logs_dir,
        command_key=str(getattr(args, "command_key", "") or "") or None,
    )
    try:
        console.hello(watching=", ".join(getattr(args, "watch_path", []) or []))
        print(f"[+] Connected to console {server} as agent {console.agent_id}", flush=True)
    except Exception as exc:  # noqa: BLE001 - keep collecting locally; events are retried per batch
        if getattr(args, "require_console", False):
            raise
        print(f"[!] Console hello failed: {exc}", file=sys.stderr, flush=True)
    return console


def _maybe_auto_kill(console: ConsoleClient, finding: Any) -> None:
    if not isinstance(finding, Finding) or finding.target_pid is None or finding.target_pid <= 0:
        return
    if console.should_auto_kill(finding.severity.value) and kill_process(
        finding.target_pid, expected_image=finding.target_image
    ):
        print(f"[+] Auto-kill executed for PID {finding.target_pid} ({finding.severity.value})", flush=True)


def _lock_file_watch_from_cli(args: argparse.Namespace, logs_dir: Path | None) -> None:
    """``--no-watch-files`` wins over the console toggle for this run."""
    if logs_dir is None:
        return
    config = load_runtime_config(logs_dir)
    if args.no_watch_files:
        config.file_drop_watch_enabled = False
        config.file_drop_watch_locked = True
    elif not config.file_drop_watch_locked:
        config.file_drop_watch_enabled = True
    save_runtime_config(config, logs_dir)


def _sync_watcher(watcher: FileDropWatcher | None, tick: Tick) -> FileDropWatcher | None:
    if tick.file_watch and watcher is None:
        if not tick.watch_paths:
            print("[!] No watch paths exist for file-drop monitoring", file=sys.stderr, flush=True)
            return None
        watcher = FileDropWatcher(tick.watch_paths)
        watcher.start()
        print(f"[+] File drop watch active on: {', '.join(watcher.paths)}", flush=True)
        return watcher
    if not tick.file_watch and watcher is not None:
        watcher.stop()
        print("[+] File drop watch paused (dashboard or CLI)", flush=True)
        return None
    return watcher
