"""Frida hook messages → monitoring-module events (the trace format).

The JS hooks post one message per intercepted API call. These functions turn
a message into the models the analysis module consumes, so recorded sessions
can be replayed without Frida installed.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from noirlycan_core.models import MemoryPrimitive, NetworkConnectionEvent, PrimitiveKind, ProcessEvent


@dataclass(frozen=True)
class FridaRuntimeEvent:
    event_type: str
    payload: dict[str, Any]


_OBSERVATION_KINDS: dict[str, PrimitiveKind] = {
    "allocate": PrimitiveKind.ALLOCATE,
    "write": PrimitiveKind.WRITE,
    "execute": PrimitiveKind.EXECUTE,
    "context_read": PrimitiveKind.CONTEXT_READ,
}
_OBSERVATION_HINT_KINDS: dict[str, PrimitiveKind] = {
    "txf": PrimitiveKind.WRITE,
    "ghosting": PrimitiveKind.WRITE,
}


def runtime_event_to_primitive(event: FridaRuntimeEvent) -> MemoryPrimitive | None:
    payload = event.payload
    if event.event_type == "api_observation":
        return _observation_to_primitive(payload)
    if event.event_type != "memory_primitive":
        return None
    primitive_kind = _kind_from_payload(payload)
    if primitive_kind is None:
        return None
    timestamp = _parse_timestamp(payload.get("timestamp"))
    return MemoryPrimitive(
        timestamp=timestamp,
        kind=primitive_kind,
        actor_pid=_safe_int(payload.get("actor_pid")) or 0,
        actor_image=payload.get("actor_image"),
        target_pid=_safe_int(payload.get("target_pid")),
        target_image=payload.get("target_image"),
        address=_safe_int(payload.get("address")),
        size=_safe_int(payload.get("size")),
        api=payload.get("api", event.event_type),
        details={key: value for key, value in payload.items() if key not in _BASE_KEYS},
    )


def runtime_event_to_network(event: FridaRuntimeEvent) -> NetworkConnectionEvent | None:
    if event.event_type != "network_connect":
        return None
    payload = event.payload
    pid = _safe_int(payload.get("pid"))
    destination_ip = payload.get("destination_ip")
    if pid is None or not destination_ip:
        return None
    succeeded = payload.get("succeeded")
    return NetworkConnectionEvent(
        timestamp=_parse_timestamp(payload.get("timestamp")),
        pid=pid,
        image=payload.get("image"),
        protocol=payload.get("protocol") or "tcp",
        destination_ip=destination_ip,
        destination_hostname=None,
        destination_port=_safe_int(payload.get("destination_port")),
        initiated=True,
        succeeded=bool(succeeded) if isinstance(succeeded, bool) else None,
        source="frida",
    )


def runtime_event_to_process(event: FridaRuntimeEvent) -> ProcessEvent | None:
    payload = event.payload
    if event.event_type != "process_create":
        return None
    pid = _safe_int(payload.get("pid"))
    if pid is None:
        return None
    flags = payload.get("flags") or []
    if not isinstance(flags, list):
        flags = []
    return ProcessEvent(
        timestamp=_parse_timestamp(payload.get("timestamp")),
        pid=pid,
        image=payload.get("image") or "",
        command_line=payload.get("command_line"),
        parent_pid=_safe_int(payload.get("parent_pid")),
        parent_image=payload.get("parent_image"),
        flags=[str(flag) for flag in flags],
    )


_BASE_KEYS = {
    "type",
    "timestamp",
    "primitive",
    "actor_pid",
    "actor_image",
    "target_pid",
    "target_image",
    "address",
    "size",
    "api",
}


def _observation_to_primitive(payload: dict[str, Any]) -> MemoryPrimitive | None:
    category = str(payload.get("category") or "").strip().lower()
    if category in {"remote_read", "access"}:
        return None
    primitive_kind = _OBSERVATION_KINDS.get(category) or _OBSERVATION_HINT_KINDS.get(category)
    if primitive_kind is None:
        return None
    actor_pid = _safe_int(payload.get("actor_pid")) or 0
    timestamp = _parse_timestamp(payload.get("timestamp"))
    details = {
        key: value
        for key, value in payload.items()
        if key not in _BASE_KEYS and key != "category"
    }
    details.setdefault("observation", True)
    details.setdefault("category", category)
    return MemoryPrimitive(
        timestamp=timestamp,
        kind=primitive_kind,
        actor_pid=actor_pid,
        actor_image=payload.get("actor_image"),
        target_pid=_safe_int(payload.get("target_pid")),
        target_image=payload.get("target_image"),
        address=_safe_int(payload.get("address")),
        size=_safe_int(payload.get("size")),
        api=str(payload.get("api") or "api_observation"),
        details=details,
    )


def _kind_from_payload(payload: dict[str, Any]) -> PrimitiveKind | None:
    value = payload.get("primitive")
    try:
        return PrimitiveKind(value)
    except ValueError:
        return None


def _parse_timestamp(value: Any) -> datetime:
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def _safe_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None
