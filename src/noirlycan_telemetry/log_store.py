from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_LOGS_DIR = Path("logs")


def resolve_logs_dir(path: Path | str | None = None) -> Path:
    if path is None:
        return DEFAULT_LOGS_DIR.resolve()
    return Path(path).expanduser().resolve()


def ensure_logs_dir(path: Path | str | None = None) -> Path:
    logs_dir = resolve_logs_dir(path)
    logs_dir.mkdir(parents=True, exist_ok=True)
    return logs_dir


def new_session_log_path(logs_dir: Path | str | None = None) -> Path:
    directory = ensure_logs_dir(logs_dir)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return directory / f"session-{stamp}.jsonl"


def list_log_files(logs_dir: Path | str | None = None) -> list[Path]:
    directory = resolve_logs_dir(logs_dir)
    if not directory.exists():
        return []
    return sorted(
        (
            path
            for path in directory.glob("*.jsonl")
            if path.is_file()
        ),
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            text = line.strip()
            if not text:
                continue
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                payload.setdefault("_line", line_number)
                events.append(payload)
    return events


@dataclass(frozen=True)
class LogSummary:
    name: str
    path: str
    size_bytes: int
    modified_at: str
    event_count: int
    finding_count: int
    critical_count: int
    primitive_count: int


def summarize_log_file(path: Path) -> LogSummary:
    events = read_jsonl(path)
    findings = [event for event in events if event.get("type") == "finding"]
    critical = sum(
        1
        for event in findings
        if str(_nested(event, "value", "severity", default="")).lower() == "critical"
    )
    stat = path.stat()
    return LogSummary(
        name=path.name,
        path=str(path),
        size_bytes=stat.st_size,
        modified_at=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
        event_count=len(events),
        finding_count=len(findings),
        critical_count=critical,
        primitive_count=sum(1 for event in events if event.get("type") == "primitive"),
    )


def aggregate_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    type_counts: Counter[str] = Counter()
    severity_counts: Counter[str] = Counter()
    primitive_kind_counts: Counter[str] = Counter()
    api_counts: Counter[str] = Counter()
    actor_counts: Counter[str] = Counter()
    timeline: Counter[str] = Counter()
    findings: list[dict[str, Any]] = []
    processes: list[dict[str, Any]] = []

    for event in events:
        event_type = str(event.get("type", "unknown"))
        type_counts[event_type] += 1
        value = event.get("value", {})
        if not isinstance(value, dict):
            value = {}

        timestamp = _extract_timestamp(value)
        if timestamp:
            timeline[timestamp[:16]] += 1

        if event_type == "finding":
            severity = str(value.get("severity", "unknown")).lower()
            severity_counts[severity] += 1
            findings.append(_normalize_finding(value, timestamp))
            for primitive in value.get("primitives", []):
                if isinstance(primitive, dict):
                    api = primitive.get("api")
                    if api:
                        api_counts[str(api)] += 1

        if event_type == "primitive":
            kind = str(value.get("kind", "unknown")).lower()
            primitive_kind_counts[kind] += 1
            api = value.get("api")
            if api:
                api_counts[str(api)] += 1
            actor = value.get("actor_image")
            if actor:
                actor_counts[str(actor)] += 1

        if event_type in {"frida_process", "sysmon"} and value.get("pid") and value.get("image"):
            processes.append(
                {
                    "pid": value.get("pid"),
                    "image": value.get("image"),
                    "parent_image": value.get("parent_image"),
                    "command_line": value.get("command_line"),
                    "timestamp": timestamp,
                }
            )

    return {
        "totals": {
            "events": len(events),
            "findings": type_counts.get("finding", 0),
            "primitives": type_counts.get("primitive", 0),
            "sysmon": type_counts.get("sysmon", 0),
            "frida_raw": type_counts.get("frida_raw", 0),
        },
        "event_types": dict(type_counts),
        "severity": dict(severity_counts),
        "primitive_kinds": dict(primitive_kind_counts),
        "top_apis": api_counts.most_common(12),
        "top_actors": actor_counts.most_common(8),
        "timeline": sorted(timeline.items()),
        "recent_findings": sorted(findings, key=lambda item: item.get("timestamp") or "", reverse=True)[:20],
        "recent_processes": sorted(processes, key=lambda item: item.get("timestamp") or "", reverse=True)[:15],
    }


def aggregate_logs(logs_dir: Path | str | None = None, selected: str | None = None) -> dict[str, Any]:
    directory = resolve_logs_dir(logs_dir)
    files = list_log_files(directory)
    summaries = [summarize_log_file(path) for path in files]

    if selected:
        target = directory / selected
        if not target.exists():
            target = Path(selected)
        events = read_jsonl(target) if target.exists() else []
        active = target.name if target.exists() else selected
    elif files:
        events = read_jsonl(files[0])
        active = files[0].name
    else:
        events = []
        active = None

    return {
        "logs_dir": str(directory),
        "active_log": active,
        "files": [summary.__dict__ for summary in summaries],
        "stats": aggregate_events(events),
    }


def _nested(data: dict[str, Any], *keys: str, default: Any = None) -> Any:
    current: Any = data
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key, default)
    return current


def _extract_timestamp(value: dict[str, Any]) -> str | None:
    timestamp = value.get("timestamp")
    if timestamp is None:
        return None
    return str(timestamp)


def _normalize_finding(value: dict[str, Any], timestamp: str | None) -> dict[str, Any]:
    apis = sorted(
        {
            str(primitive.get("api"))
            for primitive in value.get("primitives", [])
            if isinstance(primitive, dict) and primitive.get("api")
        }
    )
    return {
        "timestamp": timestamp,
        "severity": value.get("severity"),
        "score": value.get("score"),
        "title": value.get("title"),
        "description": value.get("description"),
        "actor_pid": value.get("actor_pid"),
        "target_pid": value.get("target_pid"),
        "apis": apis,
        "evidence": value.get("evidence", {}),
    }
