"""Shared collector loop helpers used by CLI and batch analysis."""

from __future__ import annotations

import dataclasses
import json
import queue
import sys
from pathlib import Path
from typing import Any, Callable

from noirlycan_core.kernel.analysis.evasion import evasion_signal_from_payload
from noirlycan_core.kernel.analysis.network_policy import is_external_beacon_candidate
from noirlycan_core.kernel.entities.models import (
    EvasionSignalEvent,
    FileEvent,
    Finding,
    NetworkConnectionEvent,
    ProcessEvent,
    TelemetryEvent,
)
from noirlycan_core.analysis.domain.correlation import Correlator
from noirlycan_agent.collector.infrastructure.frida_manager import (
    FridaInjectionMonitor,
    FridaUnavailable,
    runtime_event_to_primitive,
    runtime_event_to_process,
)
from noirlycan_agent.collector.infrastructure.sysmon import (
    SYSMON_ACCESS_HINT,
    SYSMON_INSTALL_HINT,
    SysmonPoller,
    SysmonUnavailable,
)


class JsonlWriter:
    def __init__(self, path: Path | None, *, flush_every: int = 32) -> None:
        self.path = path
        self._handle = path.open("a", encoding="utf-8") if path else None
        self._flush_every = max(1, int(flush_every))
        self._pending_writes = 0

    def write(self, event_type: str, value: Any) -> None:
        if self._handle is None:
            return
        payload = {
            "type": event_type,
            "value": jsonable(value),
        }
        self._handle.write(json.dumps(payload, sort_keys=True) + "\n")
        self._pending_writes += 1
        if self._pending_writes >= self._flush_every:
            self._handle.flush()
            self._pending_writes = 0

    def flush(self) -> None:
        if self._handle is None:
            return
        self._handle.flush()
        self._pending_writes = 0

    def close(self) -> None:
        if self._handle is None:
            return
        self.flush()
        self._handle.close()
        self._handle = None


def jsonable(value: Any) -> Any:
    if dataclasses.is_dataclass(value):
        return jsonable(dataclasses.asdict(value))
    if isinstance(value, dict):
        return {str(key): jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [jsonable(item) for item in value]
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return value


def print_finding(finding: Finding) -> None:
    print(
        f"[{finding.severity.value.upper()}:{finding.score}] "
        f"{finding.title}: {finding.description}"
    )
    if finding.technique:
        print(
            f"  Technique: {finding.technique} "
            f"({finding.technique_confidence or 'unknown'} confidence)"
        )
    evidence = finding.evidence or {}
    if evidence.get("payload_kind"):
        print(f"  Payload: {evidence['payload_kind']}")
    if evidence.get("execution_confirmed") is False:
        print("  Execution confirmed: no")
        if evidence.get("context_read_evidence"):
            print(f"  Context read APIs: {', '.join(evidence['context_read_evidence'])}")
        if evidence.get("missing_execution_transfer"):
            print("  Missing execution transfer: yes")
    elif evidence.get("execution_confirmed"):
        print(f"  Execution confirmed: yes ({', '.join(evidence.get('execution_evidence', []))})")
    if finding.is_recursive and finding.injection_chain:
        print(f"  Recursive chain ({finding.chain_depth} hops): {finding.injection_chain}")
    if finding.target_image or finding.target_pid is not None:
        target_label = finding.target_image or "unknown image"
        pid_label = finding.target_pid if finding.target_pid is not None else "-"
        print(f"  Injection target: {target_label} (pid={pid_label})")
    print("  APIs:", ", ".join(sorted({primitive.api for primitive in finding.primitives})))
    if finding.related_file:
        print(f"  Related file: {finding.related_file.path}")
    if finding.score >= 70 and finding.target_pid is not None:
        print(
            f"  Network watch enabled for PID {finding.target_pid} "
            f"(5 min, outbound Sysmon EID 3)"
        )


def create_sysmon_or_none(watch_sysmon: bool) -> SysmonPoller | None:
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


def create_monitor_or_none() -> FridaInjectionMonitor | None:
    try:
        return FridaInjectionMonitor()
    except FridaUnavailable as exc:
        print(f"[!] Frida unavailable: {exc}", file=sys.stderr)
        return None


def safe_attach(monitor: FridaInjectionMonitor, pid: int) -> None:
    try:
        monitor.attach(pid)
        print(f"[+] Frida attached to PID {pid}")
    except Exception as exc:
        print(f"[!] Could not attach to PID {pid}: {exc}", file=sys.stderr)


def should_auto_attach(event: ProcessEvent) -> bool:
    if not event.image:
        return False
    suffix = Path(event.image).suffix.lower()
    if suffix not in {".exe", ".dll", ".scr", ".com"}:
        return False
    image = event.image.lower()
    if "\\windows\\system32\\" in image and not event.parent_image:
        return False
    return True


def handle_network_event(
    event: NetworkConnectionEvent,
    correlator: Correlator,
    writer: JsonlWriter,
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


def runtime_event_to_evasion(runtime_event) -> EvasionSignalEvent | None:
    signal = evasion_signal_from_payload(runtime_event.payload)
    if signal is None:
        return None
    return EvasionSignalEvent(
        timestamp=signal.timestamp,
        kind=signal.kind.value,
        api=signal.api,
        pid=signal.pid,
        image=signal.image,
        details=signal.details,
    )


FileEventHandler = Callable[[FileEvent, Correlator, JsonlWriter], None]
ProcessEventHandler = Callable[[ProcessEvent, Correlator, JsonlWriter], None]


def process_sysmon_batch(
    sysmon: SysmonPoller,
    correlator: Correlator,
    writer: JsonlWriter,
    monitor: FridaInjectionMonitor | None,
    auto_attach: bool,
    *,
    file_handler: FileEventHandler | None = None,
    process_handler: ProcessEventHandler | None = None,
) -> None:
    try:
        events = list(sysmon.poll_once())
    except SysmonUnavailable as exc:
        print(f"[!] Sysmon unavailable: {exc}", file=sys.stderr)
        return
    for event in events:
        if isinstance(event, FileEvent):
            if file_handler is not None:
                file_handler(event, correlator, writer)
            elif event.path:
                writer.write("file", event)
                correlator.add_file(event)
        elif isinstance(event, ProcessEvent):
            writer.write("sysmon", event)
            correlator.add_process(event)
            if process_handler is not None:
                process_handler(event, correlator, writer)
            if auto_attach and monitor is not None and should_auto_attach(event):
                safe_attach(monitor, event.pid)
        elif isinstance(event, NetworkConnectionEvent):
            writer.write("sysmon", event)
            handle_network_event(event, correlator, writer)
        elif isinstance(event, TelemetryEvent):
            writer.write("sysmon", event)


def drain_frida(
    monitor: FridaInjectionMonitor,
    correlator: Correlator,
    writer: JsonlWriter,
    auto_attach: bool = False,
) -> None:
    while True:
        try:
            runtime_event = monitor.events().get_nowait()
        except queue.Empty:
            return
        writer.write("frida_raw", runtime_event.payload)
        evasion_event = runtime_event_to_evasion(runtime_event)
        if evasion_event is not None:
            writer.write("evasion", evasion_event)
            print(
                f"[EVASION:{evasion_event.kind}] PID {evasion_event.pid or '-'} "
                f"({evasion_event.image or 'unknown'}) via {evasion_event.api}",
                flush=True,
            )
            continue
        process_event = runtime_event_to_process(runtime_event)
        if process_event is not None:
            writer.write("frida_process", process_event)
            correlator.add_process(process_event)
            if auto_attach and should_auto_attach(process_event):
                safe_attach(monitor, process_event.pid)
            continue
        primitive = runtime_event_to_primitive(runtime_event)
        if primitive is None:
            continue
        writer.write("primitive", primitive)
        for finding in correlator.add_primitive(primitive):
            writer.write("finding", finding)
            print_finding(finding)
