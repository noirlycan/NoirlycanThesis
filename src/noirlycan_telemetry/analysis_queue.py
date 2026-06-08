from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .atomic_io import atomic_write_text
from .log_store import default_logs_dir

QUEUE_NAME = ".analysis_queue.json"
ANALYSIS_MODES = {"api", "static"}


@dataclass
class AnalysisRequest:
    path: str
    mode: str = "api"
    argv: list[str] = field(default_factory=list)


@dataclass
class AnalysisQueue:
    pending: list[AnalysisRequest] = field(default_factory=list)


def resolve_queue_path(logs_dir: Path | str | None = None) -> Path:
    directory = Path(logs_dir).expanduser().resolve() if logs_dir else default_logs_dir()
    return directory / QUEUE_NAME


def _normalize_mode(mode: str | None) -> str:
    normalized = str(mode or "api").strip().lower()
    return normalized if normalized in ANALYSIS_MODES else "api"


def _parse_request(item: object) -> AnalysisRequest | None:
    if isinstance(item, str):
        path = item.strip()
        if path:
            return AnalysisRequest(path=str(Path(path)), mode="api")
        return None
    if isinstance(item, dict):
        path = str(item.get("path") or "").strip()
        if not path:
            return None
        argv_raw = item.get("argv") or []
        argv = [str(part) for part in argv_raw if str(part).strip()] if isinstance(argv_raw, list) else []
        return AnalysisRequest(
            path=str(Path(path)),
            mode=_normalize_mode(item.get("mode")),
            argv=argv,
        )
    return None


def load_analysis_queue(logs_dir: Path | str | None = None) -> AnalysisQueue:
    path = resolve_queue_path(logs_dir)
    if not path.exists():
        return AnalysisQueue()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return AnalysisQueue()
    if not isinstance(raw, dict):
        return AnalysisQueue()

    pending: list[AnalysisRequest] = []
    for item in raw.get("pending") or []:
        request = _parse_request(item)
        if request is not None:
            pending.append(request)
    return AnalysisQueue(pending=_dedupe_requests(pending))


def save_analysis_queue(queue: AnalysisQueue, logs_dir: Path | str | None = None) -> Path:
    path = resolve_queue_path(logs_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "pending": [
            {
                "path": request.path,
                "mode": request.mode,
                "argv": list(request.argv),
            }
            for request in _dedupe_requests(queue.pending)
        ],
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return path


def enqueue_analysis(
    path: str,
    logs_dir: Path | str | None = None,
    *,
    mode: str = "api",
    argv: list[str] | None = None,
) -> bool:
    normalized = str(Path(path))
    if not normalized.strip():
        return False
    request = AnalysisRequest(
        path=normalized,
        mode=_normalize_mode(mode),
        argv=[str(part) for part in (argv or []) if str(part).strip()],
    )
    queue = load_analysis_queue(logs_dir)
    key = (request.path.lower(), request.mode, tuple(request.argv))
    if any(
        (existing.path.lower(), existing.mode, tuple(existing.argv)) == key
        for existing in queue.pending
    ):
        return False
    queue.pending.append(request)
    save_analysis_queue(queue, logs_dir)
    return True


def remove_from_queue(path: str, logs_dir: Path | str | None = None) -> bool:
    normalized = str(Path(path))
    if not normalized.strip():
        return False
    queue = load_analysis_queue(logs_dir)
    key = normalized.lower()
    before = len(queue.pending)
    queue.pending = [request for request in queue.pending if request.path.lower() != key]
    if len(queue.pending) == before:
        return False
    save_analysis_queue(queue, logs_dir)
    return True


def drain_analysis_queue(logs_dir: Path | str | None = None) -> list[AnalysisRequest]:
    queue = load_analysis_queue(logs_dir)
    if not queue.pending:
        return []
    pending = list(queue.pending)
    queue.pending = []
    save_analysis_queue(queue, logs_dir)
    return pending


def _dedupe_requests(requests: list[AnalysisRequest]) -> list[AnalysisRequest]:
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    rows: list[AnalysisRequest] = []
    for request in requests:
        key = (request.path.lower(), request.mode, tuple(request.argv))
        if key in seen:
            continue
        seen.add(key)
        rows.append(request)
    return rows
