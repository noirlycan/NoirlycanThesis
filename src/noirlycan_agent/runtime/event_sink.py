"""Where agent events go: a local JSONL session log, optionally mirrored to the console.

The console mirror is asynchronous. Events are queued and posted in batches by
a background thread, so a burst of Frida primitives never blocks the
collection loop on network round-trips.
"""

from __future__ import annotations

import dataclasses
import json
import queue
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol


def jsonable(value: Any) -> Any:
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return jsonable(dataclasses.asdict(value))
    if isinstance(value, dict):
        return {str(key): jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [jsonable(item) for item in value]
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return value


class EventSink(Protocol):
    path: Path | None

    def write(self, event_type: str, value: Any) -> None: ...

    def close(self) -> None: ...


class JsonlWriter:
    """Append-only session log; safe to call from triage worker threads."""

    def __init__(self, path: Path | None, *, flush_every: int = 32) -> None:
        self.path = path
        self._handle = path.open("a", encoding="utf-8") if path else None
        self._flush_every = max(1, flush_every)
        self._pending = 0
        self._lock = threading.Lock()

    def write(self, event_type: str, value: Any) -> None:
        if self._handle is None:
            return
        line = json.dumps({"type": event_type, "value": jsonable(value)}, sort_keys=True) + "\n"
        with self._lock:
            self._handle.write(line)
            self._pending += 1
            if self._pending >= self._flush_every:
                self._handle.flush()
                self._pending = 0

    def flush(self) -> None:
        with self._lock:
            if self._handle is not None:
                self._handle.flush()
                self._pending = 0

    def close(self) -> None:
        with self._lock:
            if self._handle is not None:
                self._handle.flush()
                self._handle.close()
                self._handle = None


class BatchUploader:
    """Background thread that ships queued events to the console in batches."""

    def __init__(
        self,
        send: Callable[[list[dict[str, Any]]], None],
        *,
        max_batch: int = 200,
        max_delay: float = 0.5,
        max_queue: int = 50_000,
    ) -> None:
        self._send = send
        self._max_batch = max_batch
        self._max_delay = max_delay
        self._queue: queue.Queue[dict[str, Any] | None] = queue.Queue(maxsize=max_queue)
        self.dropped = 0
        self._thread = threading.Thread(target=self._run, name="console-uploader", daemon=True)
        self._thread.start()

    def submit(self, event: dict[str, Any]) -> None:
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            self.dropped += 1  # The local JSONL still has the event.

    def close(self, timeout: float = 5.0) -> None:
        self._queue.put(None)
        self._thread.join(timeout)

    def _run(self) -> None:
        stopping = False
        while not stopping:
            first = self._queue.get()
            if first is None:
                break
            batch = [first]
            try:
                while len(batch) < self._max_batch:
                    item = self._queue.get(timeout=self._max_delay)
                    if item is None:
                        stopping = True
                        break
                    batch.append(item)
            except queue.Empty:
                pass
            try:
                self._send(batch)
            except Exception as exc:  # noqa: BLE001 - keep collecting even if the console is down
                print(f"[!] Console upload failed ({len(batch)} events): {exc}", flush=True)


class MirroredWriter:
    """Write locally, then queue the same event for the console."""

    def __init__(
        self,
        local: JsonlWriter,
        uploader: BatchUploader,
        *,
        on_finding: Callable[[Any], None] | None = None,
    ) -> None:
        self.local = local
        self.uploader = uploader
        self.on_finding = on_finding

    @property
    def path(self) -> Path | None:
        return self.local.path

    def write(self, event_type: str, value: Any) -> None:
        self.local.write(event_type, value)
        self.uploader.submit({"type": event_type, "value": jsonable(value)})
        if event_type == "finding" and self.on_finding is not None:
            self.on_finding(value)

    def flush(self) -> None:
        self.local.flush()

    def close(self) -> None:
        self.uploader.close()
        self.local.close()
