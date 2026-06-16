from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from noirlycan_telemetry.services.storage.infrastructure.atomic_io import atomic_write_text
from noirlycan_telemetry.services.storage.infrastructure.log_store import default_logs_dir

QUEUE_NAME = ".triage_queue.json"


@dataclass
class TriageQueue:
    pending: list[str] = field(default_factory=list)


def resolve_queue_path(logs_dir: Path | str | None = None) -> Path:
    directory = Path(logs_dir).expanduser().resolve() if logs_dir else default_logs_dir()
    return directory / QUEUE_NAME


def load_triage_queue(logs_dir: Path | str | None = None) -> TriageQueue:
    path = resolve_queue_path(logs_dir)
    if not path.exists():
        return TriageQueue()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return TriageQueue()
    if not isinstance(raw, dict):
        return TriageQueue()
    pending = [str(item) for item in raw.get("pending") or [] if str(item).strip()]
    return TriageQueue(pending=_dedupe_paths(pending))


def save_triage_queue(queue: TriageQueue, logs_dir: Path | str | None = None) -> Path:
    path = resolve_queue_path(logs_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "pending": _dedupe_paths(queue.pending),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return path


def enqueue_triage(path: str, logs_dir: Path | str | None = None) -> bool:
    normalized = str(Path(path))
    if not normalized.strip():
        return False
    queue = load_triage_queue(logs_dir)
    key = normalized.lower()
    if any(existing.lower() == key for existing in queue.pending):
        return False
    queue.pending.append(normalized)
    save_triage_queue(queue, logs_dir)
    return True


def drain_triage_queue(logs_dir: Path | str | None = None) -> list[str]:
    queue = load_triage_queue(logs_dir)
    if not queue.pending:
        return []
    pending = list(queue.pending)
    queue.pending = []
    save_triage_queue(queue, logs_dir)
    return pending


def _dedupe_paths(paths: list[str]) -> list[str]:
    seen: set[str] = set()
    rows: list[str] = []
    for path in paths:
        key = str(Path(path)).lower()
        if key in seen:
            continue
        seen.add(key)
        rows.append(str(Path(path)))
    return rows
