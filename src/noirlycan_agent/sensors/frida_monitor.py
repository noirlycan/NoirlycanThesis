from __future__ import annotations

import json
import queue
import threading
from importlib.resources import files
from typing import Any, Callable

from noirlycan_agent.sensors.frida_hook_catalog import build_runtime_config
from noirlycan_core.models import MemoryPrimitive
from noirlycan_core.runtime.agent_policy import AgentPolicy
from noirlycan_core.trace.frida import (
    FridaRuntimeEvent,
    _safe_int,
    runtime_event_to_network,
    runtime_event_to_primitive,
    runtime_event_to_process,
)

__all__ = [
    "FridaInjectionMonitor",
    "FridaRuntimeEvent",
    "FridaUnavailable",
    "build_hook_script",
    "runtime_event_to_network",
    "runtime_event_to_primitive",
    "runtime_event_to_process",
]

try:
    import frida
except ImportError:  # pragma: no cover - optional until installed on Windows lab
    frida = None

_HOOK_PARTS = ("runtime.js", "handlers.js")


class FridaUnavailable(RuntimeError):
    """Raised when Frida is not installed or cannot attach."""


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

    def enable_auto_attach(self) -> None:
        """No-op kept for cli.py compatibility.

        Session.enable_child_gating() was tried here to reliably catch child
        processes (CreateProcessW arg-parsing and Sysmon poll timing both miss
        cases), but it stalled the loader's own Frida message channel the
        moment a gated child appeared — later hook events (NtMapViewOfSection,
        GetThreadContext, SetThreadContext, ResumeThread) stopped being
        reported even though the underlying Windows APIs kept succeeding.
        Reverted until that's root-caused; auto-attach falls back to the
        existing Sysmon EID1 / CreateProcess*-arg-parsing paths only."""
        return

    def reload_policy(self, policy: AgentPolicy | None) -> bool:
        """Recompile hook script from dashboard policy and reattach active sessions."""
        version = policy.version if policy else 0
        if version == self._policy_version:
            return False  # Same policy version → same script; skip the rebuild.
        new_source = build_hook_script(policy)
        if new_source == self.script_source:
            self._policy_version = version
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
        script.on("message", lambda msg, data, _s=script: self._on_message(msg, data, _s))
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

    def _on_message(self, message: dict[str, Any], data: bytes | None, script: Any = None) -> None:
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
        if event_type == "child_attach_debug":
            reason = payload.get("reason", "?")
            resume_pid = payload.get("resume_target_pid")
            pending = payload.get("pending_pids", [])
            print(
                f"[DEBUG] child attach {reason}: "
                f"resume_pid={resume_pid}, pending={pending}",
                flush=True,
            )
            return
        if event_type == "attach_child_request":
            child_pid = _safe_int(payload.get("child_pid"))
            if child_pid is not None:
                t = threading.Thread(
                    target=self._handle_attach_child,
                    args=(child_pid, script),
                    daemon=True,
                )
                t.start()
            return
        self._queue.put(FridaRuntimeEvent(event_type=event_type, payload=payload))

    def _handle_attach_child(self, child_pid: int, parent_script: Any) -> None:
        with self._lock:
            if child_pid not in self._sessions:
                try:
                    self._attach_pid(child_pid)
                    print(f"[+] Frida auto-attached to child PID {child_pid} (pre-resume sync)")
                except Exception as exc:
                    print(f"[!] Could not auto-attach to child PID {child_pid}: {exc}")
        if parent_script is not None:
            try:
                parent_script.post({"type": "child_attached"})
            except Exception:
                pass
