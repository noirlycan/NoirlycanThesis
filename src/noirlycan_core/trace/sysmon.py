"""Sysmon kernel-callback events → analysis-module models.

Sysmon's driver sees cross-process thread creation and handle opens from
kernel callbacks, so these events survive user-mode unhooking and direct
syscalls that blind the Frida hooks (see docs/proposal-kernel-telemetry.md).
"""

from __future__ import annotations

from noirlycan_core.models import MemoryPrimitive, PrimitiveKind, ProcessAccessEvent, TelemetryEvent

REMOTE_THREAD = "sysmon_eid_8"
PROCESS_ACCESS = "sysmon_eid_10"


def primitive_from_remote_thread(event: TelemetryEvent) -> MemoryPrimitive | None:
    """EID 8 CreateRemoteThread → EXECUTE primitive.

    The start address is used for memory congruence only when it is not inside
    a loaded module: a thread starting in unbacked memory points at the
    injected buffer, while one starting at e.g. kernel32!LoadLibraryW does not.
    """
    if event.kind != REMOTE_THREAD:
        return None
    data = event.data or {}
    actor = _int(data.get("SourceProcessId"))
    target = _int(data.get("TargetProcessId"))
    if actor is None or target is None or actor == target:
        return None
    start = _int(data.get("StartAddress"))
    start_module = str(data.get("StartModule") or "").strip()
    unbacked = start is not None and start_module in {"", "-"}
    return MemoryPrimitive(
        timestamp=event.timestamp,
        kind=PrimitiveKind.EXECUTE,
        actor_pid=actor,
        actor_image=data.get("SourceImage") or None,
        target_pid=target,
        target_image=data.get("TargetImage") or None,
        address=start if unbacked else None,
        size=None,
        api="CreateRemoteThread",
        details={
            "start_address": hex(start) if start is not None else None,
            "start_module": start_module or None,
            "start_function": data.get("StartFunction") or None,
            "new_thread_id": _int(data.get("NewThreadId")),
            "unbacked_start": unbacked,
        },
        source="sysmon",
    )


def access_from_process_access(event: TelemetryEvent) -> ProcessAccessEvent | None:
    if event.kind != PROCESS_ACCESS:
        return None
    data = event.data or {}
    actor = _int(data.get("SourceProcessId"))
    target = _int(data.get("TargetProcessId"))
    access = _int(data.get("GrantedAccess"))
    if actor is None or target is None or access is None or actor == target:
        return None
    return ProcessAccessEvent(
        timestamp=event.timestamp,
        actor_pid=actor,
        target_pid=target,
        granted_access=access,
        call_trace=str(data.get("CallTrace") or ""),
    )


def _int(value: object) -> int | None:
    if value is None:
        return None
    try:
        return int(str(value), 0)
    except ValueError:
        return None
