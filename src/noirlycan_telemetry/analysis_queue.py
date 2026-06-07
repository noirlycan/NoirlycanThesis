from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .log_store import default_logs_dir

QUEUE_NAME = ".analysis_queue.json"
ANALYSIS_MODES = {"api", "static"}


@dataclass
class AnalysisRequest:
    path: str
    mode: str = "api"


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
        return AnalysisRequest(path=str(Path(path)), mode=_normalize_mode(item.get("mode")))
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
            {"path": request.path, "mode": request.mode}
            for request in _dedupe_requests(queue.pending)
        ],
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temp.replace(path)
    return path


def enqueue_analysis(
    path: str,
    logs_dir: Path | str | None = None,
    *,
    mode: str = "api",
) -> bool:
    normalized = str(Path(path))
    if not normalized.strip():
        return False
    request = AnalysisRequest(path=normalized, mode=_normalize_mode(mode))
    queue = load_analysis_queue(logs_dir)
    key = (request.path.lower(), request.mode)
    if any((existing.path.lower(), existing.mode) == key for existing in queue.pending):
        return False
    queue.pending.append(request)
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
    seen: set[tuple[str, str]] = set()
    rows: list[AnalysisRequest] = []
    for request in requests:
        key = (request.path.lower(), request.mode)
        if key in seen:
            continue
        seen.add(key)
        rows.append(request)
    return rows
