from __future__ import annotations

import json
import queue
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib.resources import files
from typing import Any, Callable

from noirlycan_telemetry.kernel.entities.models import MemoryPrimitive, PrimitiveKind, ProcessEvent

try:
    import frida
except ImportError:  # pragma: no cover - optional until installed on Windows lab
    frida = None


class FridaUnavailable(RuntimeError):
    """Raised when Frida is not installed or cannot attach."""


@dataclass(frozen=True)
class FridaRuntimeEvent:
    event_type: str
    payload: dict[str, Any]


def load_default_hook_script() -> str:
    hook_path = files("noirlycan_telemetry").joinpath(
        "frida_hooks/windows_injection_hooks.js"
    )
    return hook_path.read_text(encoding="utf-8")


class FridaInjectionMonitor:
    """Small Frida orchestration layer for Windows API telemetry."""

    def __init__(self, script_source: str | None = None) -> None:
        if frida is None:
            raise FridaUnavailable("Install the 'frida' Python package first")
        self.script_source = script_source or load_default_hook_script()
        self._sessions: dict[int, Any] = {}
        self._queue: queue.Queue[FridaRuntimeEvent] = queue.Queue()
        self._lock = threading.Lock()

    def attach(self, pid: int) -> None:
        with self._lock:
            if pid in self._sessions:
                return
            session = frida.attach(pid)
            script = session.create_script(self.script_source)
            script.on("message", self._on_message)
            script.load()
            self._sessions[pid] = (session, script)

    def detach_all(self) -> None:
        with self._lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
        for session, _ in sessions:
            try:
                session.detach()
            except Exception:
                pass

    def events(self) -> queue.Queue[FridaRuntimeEvent]:
        return self._queue

    def drain(self, callback: Callable[[MemoryPrimitive], None]) -> None:
        while True:
            runtime_event = self._queue.get()
            primitive = runtime_event_to_primitive(runtime_event)
            if primitive is not None:
                callback(primitive)

    def _on_message(self, message: dict[str, Any], data: bytes | None) -> None:
        if message.get("type") != "send":
            return
        payload = message.get("payload")
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except json.JSONDecodeError:
                return
        if not isinstance(payload, dict):
            return
        event_type = payload.get("type")
        if not isinstance(event_type, str):
            return
        self._queue.put(FridaRuntimeEvent(event_type=event_type, payload=payload))


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
