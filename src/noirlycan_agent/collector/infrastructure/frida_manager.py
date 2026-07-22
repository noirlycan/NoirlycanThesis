from __future__ import annotations

import json
import queue
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib.resources import files
from typing import Any, Callable

from noirlycan_agent.collector.infrastructure.frida_hook_catalog import build_runtime_config
from noirlycan_core.kernel.entities.models import MemoryPrimitive, PrimitiveKind, ProcessEvent
from noirlycan_core.runtime.agent_policy import AgentPolicy

try:
    import frida
except ImportError:  # pragma: no cover - optional until installed on Windows lab
    frida = None

_HOOK_PARTS = ("runtime.js", "handlers.js")


class FridaUnavailable(RuntimeError):
    """Raised when Frida is not installed or cannot attach."""


@dataclass(frozen=True)
class FridaRuntimeEvent:
    event_type: str
    payload: dict[str, Any]


def _load_hook_part(name: str) -> str:
    path = files("noirlycan_agent").joinpath(f"frida_hooks/{name}")
    return path.read_text(encoding="utf-8")


def load_default_hook_script() -> str:
    """Load the hook runtime without server config (full lab mode)."""
    return build_hook_script(None)


def build_hook_script(policy: AgentPolicy | None = None) -> str:
    """Inject server runtime config, then load runtime + handler modules."""
    config = build_runtime_config(policy)
    preamble = f"globalThis.__NOIRLYCAN_CONFIG__ = {json.dumps(config, sort_keys=True)};\n"
    body = "\n".join(_load_hook_part(part) for part in _HOOK_PARTS)
    return preamble + body


class FridaInjectionMonitor:
    """Small Frida orchestration layer for Windows API telemetry."""

    def __init__(
        self,
        script_source: str | None = None,
        *,
        policy: AgentPolicy | None = None,
    ) -> None:
        if frida is None:
            raise FridaUnavailable("Install the 'frida' Python package first")
        self._policy_version = policy.version if policy else 0
        self.script_source = script_source or build_hook_script(policy)
        self._sessions: dict[int, Any] = {}
        self._queue: queue.Queue[FridaRuntimeEvent] = queue.Queue()
        self._lock = threading.Lock()

    @property
    def policy_version(self) -> int:
        return self._policy_version

    def attach(self, pid: int) -> None:
        with self._lock:
            if pid in self._sessions:
                return
            self._attach_pid(pid)

    def reload_policy(self, policy: AgentPolicy | None) -> bool:
        """Recompile hook script from dashboard policy and reattach active sessions."""
        version = policy.version if policy else 0
        new_source = build_hook_script(policy)
        if version == self._policy_version and new_source == self.script_source:
            return False
        with self._lock:
            pids = list(self._sessions.keys())
            for session, _ in self._sessions.values():
                try:
                    session.detach()
                except Exception:
                    pass
            self._sessions.clear()
            self.script_source = new_source
            self._policy_version = version
            for pid in pids:
                try:
                    self._attach_pid(pid)
                except Exception:
                    pass
        return True

    def _attach_pid(self, pid: int) -> None:
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
