from __future__ import annotations

import json
import os
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .network import is_external_beacon_candidate

_PACKAGE_ROOT = Path(__file__).resolve().parent


def find_project_root() -> Path:
    for candidate in (_PACKAGE_ROOT, *_PACKAGE_ROOT.parents):
        if (candidate / "pyproject.toml").exists():
            return candidate
        if (candidate / "logs").is_dir():
            return candidate
    return Path.cwd()


def default_logs_dir() -> Path:
    override = os.environ.get("NOIRLYCAN_LOGS_DIR", "").strip()
    if override:
        return Path(override).expanduser().resolve()
    return (find_project_root() / "logs").resolve()


def resolve_logs_dir(path: Path | str | None = None) -> Path:
    if path is None:
        return default_logs_dir()
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
    networks_by_pid: dict[int, list[dict[str, Any]]] = {}

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

        if event_type == "network":
            pid = value.get("pid")
            if pid is not None:
                networks_by_pid.setdefault(int(pid), []).append(_normalize_network(value, timestamp))

    deduped_findings = _dedupe_findings(findings)
    deduped_severity: Counter[str] = Counter()
    for finding in deduped_findings:
        target_pid = finding.get("target_pid")
        if target_pid is not None:
            finding["network"] = networks_by_pid.get(int(target_pid), [])
        severity = str(finding.get("severity", "unknown")).lower()
        deduped_severity[severity] += 1

    return {
        "totals": {
            "events": len(events),
            "findings": len(deduped_findings),
            "findings_raw": type_counts.get("finding", 0),
            "primitives": type_counts.get("primitive", 0),
            "sysmon": type_counts.get("sysmon", 0),
            "frida_raw": type_counts.get("frida_raw", 0),
            "network": type_counts.get("network", 0),
        },
        "event_types": dict(type_counts),
        "severity": dict(deduped_severity),
        "primitive_kinds": dict(primitive_kind_counts),
        "top_apis": api_counts.most_common(12),
        "top_actors": actor_counts.most_common(8),
        "timeline": sorted(timeline.items()),
        "recent_findings": deduped_findings[:50],
        "recent_network": _recent_network_events(networks_by_pid),
        "recent_primitives": _extract_primitives(events, limit=50),
        "recent_processes": sorted(processes, key=lambda item: item.get("timestamp") or "", reverse=True)[:15],
    }


def resolve_log_path(logs_dir: Path | str | None, name: str) -> Path | None:
    directory = resolve_logs_dir(logs_dir)
    target = directory / name
    if target.exists() and target.is_file():
        return target
    fallback = Path(name)
    if fallback.exists() and fallback.is_file():
        return fallback.resolve()
    return None


def session_detail(
    name: str,
    logs_dir: Path | str | None = None,
    *,
    severity: str | None = None,
    target_pid: int | None = None,
    query: str | None = None,
    event_type: str | None = None,
    limit: int = 200,
) -> dict[str, Any] | None:
    path = resolve_log_path(logs_dir, name)
    if path is None:
        return None
    events = read_jsonl(path)
    stats = aggregate_events(events)
    filtered_events = _filter_events(
        events,
        severity=severity,
        target_pid=target_pid,
        query=query,
        event_type=event_type,
        limit=limit,
    )
    return {
        "name": path.name,
        "path": str(path),
        "summary": summarize_log_file(path).__dict__,
        "stats": stats,
        "findings": _apply_finding_filters(stats["recent_findings"], severity, target_pid, query),
        "primitives": _extract_primitives(events, target_pid=target_pid, query=query, limit=limit),
        "network": _apply_network_filters(stats["recent_network"], target_pid, query),
        "events": filtered_events,
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


def _dedupe_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    best: dict[tuple[Any, Any], dict[str, Any]] = {}
    for finding in findings:
        key = (finding.get("actor_pid"), finding.get("target_pid"))
        current = best.get(key)
        if current is None or (finding.get("score") or 0) >= (current.get("score") or 0):
            best[key] = finding
    return sorted(best.values(), key=lambda item: item.get("timestamp") or "", reverse=True)


def _normalize_network(value: dict[str, Any], timestamp: str | None) -> dict[str, Any]:
    destination_ip = value.get("destination_ip")
    destination_hostname = value.get("destination_hostname")
    destination_port = value.get("destination_port")
    host = destination_hostname or destination_ip
    endpoint = f"{host}:{destination_port}" if host and destination_port else host
    beacon_candidate = is_external_beacon_candidate(destination_ip, destination_hostname)
    return {
        "timestamp": timestamp,
        "pid": value.get("pid"),
        "image": value.get("image"),
        "protocol": value.get("protocol"),
        "destination_ip": destination_ip,
        "destination_hostname": destination_hostname,
        "destination_port": destination_port,
        "endpoint": endpoint,
        "initiated": value.get("initiated"),
        "beacon_candidate": beacon_candidate,
    }


def _extract_primitives(
    events: list[dict[str, Any]],
    *,
    target_pid: int | None = None,
    query: str | None = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for event in events:
        if event.get("type") != "primitive":
            continue
        value = event.get("value", {})
        if not isinstance(value, dict):
            continue
        row = {
            "timestamp": _extract_timestamp(value),
            "kind": value.get("kind"),
            "api": value.get("api"),
            "actor_pid": value.get("actor_pid"),
            "actor_image": value.get("actor_image"),
            "target_pid": value.get("target_pid"),
            "address": value.get("address"),
            "size": value.get("size"),
            "details": value.get("details", {}),
        }
        if target_pid is not None and row.get("target_pid") != target_pid:
            continue
        if query and not _matches_query(query, row):
            continue
        rows.append(row)
    rows.sort(key=lambda item: item.get("timestamp") or "", reverse=True)
    return rows[:limit]


def _apply_finding_filters(
    findings: list[dict[str, Any]],
    severity: str | None,
    target_pid: int | None,
    query: str | None,
) -> list[dict[str, Any]]:
    rows = findings
    if severity:
        rows = [row for row in rows if str(row.get("severity", "")).lower() == severity.lower()]
    if target_pid is not None:
        rows = [row for row in rows if row.get("target_pid") == target_pid]
    if query:
        rows = [row for row in rows if _matches_query(query, row)]
    return rows


def _apply_network_filters(
    network_rows: list[dict[str, Any]],
    target_pid: int | None,
    query: str | None,
) -> list[dict[str, Any]]:
    rows = network_rows
    if target_pid is not None:
        rows = [row for row in rows if row.get("pid") == target_pid]
    if query:
        rows = [row for row in rows if _matches_query(query, row)]
    return rows


def _filter_events(
    events: list[dict[str, Any]],
    *,
    severity: str | None,
    target_pid: int | None,
    query: str | None,
    event_type: str | None,
    limit: int,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for event in events:
        current_type = str(event.get("type", ""))
        if event_type and current_type != event_type:
            continue
        value = event.get("value", {})
        if not isinstance(value, dict):
            value = {}
        if severity and current_type == "finding":
            if str(value.get("severity", "")).lower() != severity.lower():
                continue
        if target_pid is not None:
            pid_fields = (
                value.get("target_pid"),
                value.get("actor_pid"),
                value.get("pid"),
            )
            if target_pid not in pid_fields:
                continue
        if query and not _matches_query(query, {"type": current_type, **value}):
            continue
        rows.append(event)
    return rows[-limit:]


def _matches_query(query: str, payload: dict[str, Any]) -> bool:
    needle = query.strip().lower()
    if not needle:
        return True
    haystack = json.dumps(payload, default=str).lower()
    return needle in haystack


def _recent_network_events(networks_by_pid: dict[int, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for connections in networks_by_pid.values():
        rows.extend(connections)
    return sorted(rows, key=lambda item: item.get("timestamp") or "", reverse=True)[:20]


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
        "primitives": value.get("primitives", []),
    }
