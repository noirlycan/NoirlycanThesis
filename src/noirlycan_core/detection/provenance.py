"""File → process lineage context (repo extension, not part of the paper).

The paper starts from a running sample. Noirlycan also asks *where the actor
came from*: which file was dropped on disk, which process ran it, and what the
PIDs in a primitive resolve to. This module keeps that short-lived context so
the correlator can attach it to a finding.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import PureWindowsPath

from noirlycan_core.models import FileEvent, MemoryPrimitive, ProcessEvent, TelemetryEvent
from noirlycan_core.runtime.process_resolve import image_for_pid

ImageResolver = Callable[[int], "str | None"]


@dataclass(frozen=True)
class _SpawnHint:
    """A process the actor created before we learned the child PID."""

    timestamp: datetime
    actor_pid: int
    image: str


class ProvenanceTracker:
    def __init__(self, resolve_image: ImageResolver = image_for_pid) -> None:
        self._resolve_image = resolve_image
        self.files_by_path: dict[str, FileEvent] = {}
        self.processes_by_pid: dict[int, ProcessEvent] = {}
        self._image_by_pid: dict[int, str] = {}
        self._spawn_hints: deque[_SpawnHint] = deque()

    # -- ingest -------------------------------------------------------------

    def add_file(self, event: FileEvent) -> None:
        if event.path:
            self.files_by_path[norm_path(event.path)] = event

    def add_process(self, event: ProcessEvent) -> None:
        dropped = self.files_by_path.get(norm_path(event.image))
        if dropped is not None and event.created_from_file is None:
            event = replace(event, created_from_file=dropped.path)
        self.processes_by_pid[event.pid] = event
        if event.image:
            self._image_by_pid[event.pid] = event.image

    def add_process_create_hint(self, actor_pid: int, payload: dict[str, object]) -> datetime | None:
        """Record a Frida ``process_create`` event; returns its timestamp if anything was kept."""
        pid = _safe_int(payload.get("pid"))
        image = _image_from(payload.get("image"), payload.get("command_line"))
        raw_flags = payload.get("flags") or []
        flags = [str(flag) for flag in raw_flags] if isinstance(raw_flags, list) else []
        timestamp = _parse_timestamp(payload.get("timestamp"))
        if pid is not None and pid > 0 and image:
            self.add_process(
                ProcessEvent(
                    timestamp=timestamp,
                    pid=pid,
                    image=image,
                    command_line=str(payload.get("command_line") or "") or None,
                    parent_pid=actor_pid,
                    parent_image=self.image_for(actor_pid),
                    flags=flags,
                )
            )
        elif image:
            self._spawn_hints.append(_SpawnHint(timestamp, actor_pid, image))
        else:
            return None
        return timestamp

    def add_sysmon_process_refs(self, event: TelemetryEvent) -> None:
        """Index source/target PIDs from Sysmon EID 8/10 for later image lookup."""
        data = event.data or {}
        pairs = [
            (_safe_int(data.get("SourceProcessId")), data.get("SourceImage")),
            (_safe_int(data.get("TargetProcessId")), data.get("TargetImage")),
            (_safe_int(data.get("ProcessId")), data.get("Image")),
            (event.pid, event.process_image),
        ]
        for pid, image in pairs:
            path = str(image or "").strip()
            if pid is None or pid <= 0 or not path:
                continue
            self._image_by_pid[pid] = path
            if pid not in self.processes_by_pid:
                self.processes_by_pid[pid] = ProcessEvent(timestamp=event.timestamp, pid=pid, image=path)

    # -- lookup -------------------------------------------------------------

    def enrich(self, primitive: MemoryPrimitive) -> MemoryPrimitive:
        """Fill in actor/target image names the monitoring layer did not know."""
        if primitive.target_pid is not None and not primitive.target_image:
            self._bind_spawn_hint(primitive.actor_pid, primitive.target_pid, primitive.timestamp)
        actor_image = primitive.actor_image or self.image_for(primitive.actor_pid)
        target_image = primitive.target_image or self.image_for(primitive.target_pid)
        if actor_image == primitive.actor_image and target_image == primitive.target_image:
            return primitive
        return replace(primitive, actor_image=actor_image, target_image=target_image)

    def image_for(self, pid: int | None) -> str | None:
        if pid is None:
            return None
        cached = self._image_by_pid.get(pid)
        if cached:
            return cached
        process = self.processes_by_pid.get(pid)
        if process is not None and process.image:
            self._image_by_pid[pid] = process.image
            return process.image
        resolved = self._resolve_image(pid)
        if resolved:
            self._image_by_pid[pid] = resolved
            self.processes_by_pid.setdefault(
                pid, ProcessEvent(timestamp=datetime.now(timezone.utc), pid=pid, image=resolved)
            )
        return resolved or None

    def image_in_chain(
        self,
        pid: int | None,
        primitives: list[MemoryPrimitive],
        process: ProcessEvent | None = None,
    ) -> str | None:
        """Best image name for ``pid``: the known process, then the chain itself, then lookup."""
        if process is not None and process.image:
            return process.image
        if pid is None:
            return None
        for primitive in primitives:
            if primitive.target_pid == pid and primitive.target_image:
                return primitive.target_image
            if primitive.actor_pid == pid and primitive.actor_image:
                return primitive.actor_image
        return self.image_for(pid)

    def dropped_file_for(self, process: ProcessEvent | None) -> FileEvent | None:
        """The on-disk file the process (or its parent) was started from."""
        if process is None:
            return None
        if process.created_from_file:
            return self.files_by_path.get(norm_path(process.created_from_file))
        own = self.files_by_path.get(norm_path(process.image))
        if own is not None:
            return own
        parent = self.processes_by_pid.get(process.parent_pid) if process.parent_pid is not None else None
        return self.files_by_path.get(norm_path(parent.image)) if parent is not None else None

    # -- housekeeping -------------------------------------------------------

    def expire(self, cutoff: datetime) -> None:
        self.files_by_path = {
            path: event for path, event in self.files_by_path.items() if event.timestamp >= cutoff
        }
        while self._spawn_hints and self._spawn_hints[0].timestamp < cutoff:
            self._spawn_hints.popleft()

    def _bind_spawn_hint(self, actor_pid: int, target_pid: int, timestamp: datetime) -> None:
        if target_pid in self._image_by_pid:
            return
        for index in range(len(self._spawn_hints) - 1, -1, -1):
            hint = self._spawn_hints[index]
            if hint.actor_pid != actor_pid or hint.timestamp > timestamp:
                continue
            self._image_by_pid[target_pid] = hint.image
            if target_pid not in self.processes_by_pid:
                self.processes_by_pid[target_pid] = ProcessEvent(
                    timestamp=hint.timestamp,
                    pid=target_pid,
                    image=hint.image,
                    parent_pid=actor_pid,
                    parent_image=self.image_for(actor_pid),
                )
            del self._spawn_hints[index]
            return


def norm_path(path: str) -> str:
    return str(PureWindowsPath(path)).lower()


def _image_from(image: object | None, command_line: object | None) -> str | None:
    """Image path from an explicit value, else the first token of the command line."""
    path = str(image or "").strip()
    if path:
        return path
    line = str(command_line or "").strip()
    if not line:
        return None
    if line.startswith('"'):
        end = line.find('"', 1)
        if end > 1:
            return line[1:end]
    return line.split(" ", 1)[0]


def _parse_timestamp(value: object | None) -> datetime:
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def _safe_int(value: object | None) -> int | None:
    if value is None:
        return None
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return None
