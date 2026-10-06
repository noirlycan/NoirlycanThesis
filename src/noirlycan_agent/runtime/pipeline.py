"""Sensor events → detector: the per-tick plumbing shared by the collector and batch runs."""

from __future__ import annotations

import queue
import sys
from collections.abc import Callable
from pathlib import Path

from noirlycan_core.extensions.evasion import evasion_signal_from_payload
from noirlycan_core.extensions.network_policy import is_external_beacon_candidate
from noirlycan_core.trace.sysmon import access_from_process_access, primitive_from_remote_thread
from noirlycan_core.models import (
    EvasionSignalEvent,
    MemoryPrimitive,
    FileEvent,
    Finding,
    NetworkConnectionEvent,
    ProcessEvent,
    TelemetryEvent,
)
from noirlycan_core.detection.correlator import Correlator
from noirlycan_core.runtime.agent_policy import load_agent_policy
from noirlycan_agent.sensors.frida_monitor import (
    FridaInjectionMonitor,
    FridaUnavailable,
    runtime_event_to_network,
    runtime_event_to_primitive,
    runtime_event_to_process,
)
from noirlycan_agent.sensors.sysmon import (
    SYSMON_ACCESS_HINT,
    SYSMON_INSTALL_HINT,
    SysmonPoller,
    SysmonUnavailable,
)
from noirlycan_agent.sensors.tcp_watch import TcpWatchPoller
from noirlycan_agent.sensors.wfp_watch import WfpPoller
from noirlycan_agent.runtime.event_sink import EventSink


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
    kernel_flags = [flag for flag in ("direct_syscall", "unbacked_caller", "hook_bypass_suspected") if evidence.get(flag)]
    if kernel_flags:
        print(f"  Kernel evidence: {', '.join(kernel_flags)} (sensors: {', '.join(evidence.get('sensors', []))})")
    if finding.related_file:
        print(f"  Related file: {finding.related_file.path}")
    if finding.score >= 70 and finding.target_pid is not None:
        print(
            f"  Network watch enabled for PID {finding.target_pid} "
            f"(WFP audit + TCP table + Sysmon EID 3)"
        )
    if finding.network_connections:
        print(f"  Network ({len(finding.network_connections)} connections):")
        for conn in finding.network_connections[-5:]:
            status = "OK" if conn.get("succeeded") else "FAIL"
            print(
                f"    -> {conn.get('destination', '?')} "
                f"[{conn.get('protocol', '?')}] {status} "
                f"(via {conn.get('source', '?')})"
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


def create_monitor_or_none(logs_dir: Path | str | None = None) -> FridaInjectionMonitor | None:
    try:
        policy = load_agent_policy(logs_dir)
        return FridaInjectionMonitor(policy=policy)
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
    writer: EventSink,
) -> None:
    watched, enriched_finding = correlator.add_network_connection(event)
    if watched is None:
        return
    writer.write("network", watched)
    if enriched_finding is not None:
        writer.write("finding", enriched_finding)
    policy = correlator.reload_agent_policy()
    beacon_enabled = policy.beacon if policy is not None else True
    allowlist = policy.allowlist if policy is not None else None
    if is_external_beacon_candidate(
        watched.destination_ip,
        watched.destination_hostname,
        enabled=beacon_enabled,
        allowlist=allowlist,
    ):
        print(
            f"[NETWORK:BEACON?] PID {watched.pid} "
            f"({watched.image or 'unknown'}) -> {watched.endpoint} "
            f"via {watched.protocol or 'unknown'}",
            flush=True,
        )
        if enriched_finding is not None:
            print(
                f"  ^ Linked to finding: [{enriched_finding.severity.value.upper()}:{enriched_finding.score}] "
                f"{enriched_finding.actor_image or 'loader'} -> "
                f"{enriched_finding.target_image or 'beacon'} -> "
                f"{watched.endpoint}",
                flush=True,
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


FileEventHandler = Callable[[FileEvent], None]
ProcessEventHandler = Callable[[ProcessEvent], None]

# Rare kernel events worth keeping verbatim. EID 10 (ProcessAccess) is left out:
# it was half of all log bytes on real sessions and only its distilled form
# (ProcessAccessEvent → finding evidence) is needed.
RAW_SYSMON_KINDS = frozenset({"sysmon_eid_8", "sysmon_eid_22", "sysmon_eid_23", "sysmon_eid_26"})


def process_sysmon_batch(
    sysmon: SysmonPoller,
    correlator: Correlator,
    writer: EventSink,
    monitor: FridaInjectionMonitor | None,
    auto_attach: bool,
    *,
    file_handler: FileEventHandler | None = None,
    process_handler: ProcessEventHandler | None = None,
    max_events: int = 200,
    raw_events: bool = False,
) -> int:
    try:
        events = list(sysmon.poll_once(max_events=max_events))
    except SysmonUnavailable as exc:
        print(f"[!] Sysmon unavailable: {exc}", file=sys.stderr)
        return 0
    watched_pids = correlator.network_watch_pids()
    for event in events:
        if isinstance(event, FileEvent):
            if file_handler is not None:
                file_handler(event)
            elif event.path:
                writer.write("file", event)
                correlator.add_file(event)
        elif isinstance(event, ProcessEvent):
            writer.write("sysmon", event)
            correlator.add_process(event)
            if process_handler is not None:
                process_handler(event)
            if auto_attach and monitor is not None and should_auto_attach(event):
                safe_attach(monitor, event.pid)
        elif isinstance(event, NetworkConnectionEvent):
            if event.pid not in watched_pids:
                continue
            handle_network_event(event, correlator, writer)
        elif isinstance(event, TelemetryEvent):
            correlator.note_sysmon_process_ref(event)
            if raw_events or event.kind in RAW_SYSMON_KINDS:
                writer.write("sysmon", event)
            access = access_from_process_access(event)
            if access is not None:
                correlator.add_process_access(access)
            primitive = primitive_from_remote_thread(event)
            if primitive is not None:
                feed_primitive(primitive, correlator, writer)
    return len(events)


def drain_tcp_watch(
    tcp_poller: TcpWatchPoller,
    correlator: Correlator,
    writer: EventSink,
) -> None:
    watched = correlator.network_watch_pids()
    if not watched:
        return
    for event in tcp_poller.poll(watched):
        handle_network_event(event, correlator, writer)


def drain_wfp_watch(
    wfp_poller: WfpPoller,
    correlator: Correlator,
    writer: EventSink,
) -> None:
    watched = correlator.network_watch_pids()
    if not watched:
        return
    for event in wfp_poller.poll(watched):
        handle_network_event(event, correlator, writer)


def drain_frida(
    monitor: FridaInjectionMonitor,
    correlator: Correlator,
    writer: EventSink,
    auto_attach: bool = False,
    raw_events: bool = False,
) -> None:
    while True:
        try:
            runtime_event = monitor.events().get_nowait()
        except queue.Empty:
            return
        if raw_events:
            writer.write("frida_raw", runtime_event.payload)
        if runtime_event.event_type == "hook_ready":
            pid = runtime_event.payload.get("actor_pid", "?")
            net = runtime_event.payload.get("network_hooks", False)
            n_hooks = runtime_event.payload.get("hooked_exports", 0)
            ws2 = runtime_event.payload.get("ws2_32_loaded", False)
            wh = runtime_event.payload.get("winhttp_loaded", False)
            wi = runtime_event.payload.get("wininet_loaded", False)
            mods = []
            if ws2:
                mods.append("ws2_32")
            if wh:
                mods.append("winhttp")
            if wi:
                mods.append("wininet")
            print(
                f"[HOOKS] PID {pid}: {n_hooks} exports hooked, "
                f"network={'OK' if net else 'PENDING'}, "
                f"net modules: {', '.join(mods) or 'none'}",
                flush=True,
            )
            continue
        if runtime_event.event_type == "process_create":
            parent_pid = runtime_event.payload.get("parent_pid")
            try:
                actor_pid = int(parent_pid)
            except (TypeError, ValueError):
                actor_pid = None
            if actor_pid is not None and actor_pid > 0:
                correlator.note_process_create_hint(actor_pid, runtime_event.payload)
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
        network_event = runtime_event_to_network(runtime_event)
        if network_event is not None:
            handle_network_event(network_event, correlator, writer)
            continue
        primitive = runtime_event_to_primitive(runtime_event)
        if primitive is not None:
            feed_primitive(primitive, correlator, writer)


def feed_primitive(primitive: MemoryPrimitive, correlator: Correlator, writer: EventSink) -> None:
    """Log a primitive from any sensor and report the findings it completes."""
    writer.write("primitive", primitive)
    for finding in correlator.add_primitive(primitive):
        writer.write("finding", finding)
        print_finding(finding)
