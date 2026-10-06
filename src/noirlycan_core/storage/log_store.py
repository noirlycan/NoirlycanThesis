from __future__ import annotations

import json
import os
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from noirlycan_core.extensions.evasion import summarize_evasion_signals
from noirlycan_core.detection.injection_graph import chains_from_findings
from noirlycan_core.extensions.network_policy import is_external_beacon_candidate
from noirlycan_core.runtime.process_resolve import (
    image_for_pid as resolve_image_for_pid,
)

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
            if path.is_file() and ".reclassified." not in path.name
        ),
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )


def count_jsonl_lines(path: Path) -> int:
    count = 0
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                count += 1
    return count


def read_jsonl(path: Path, *, after_line: int = 0) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if after_line and line_number <= after_line:
                continue
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


def invalidate_log_cache(path: Path) -> None:
    _summary_cache.pop(str(path.resolve()), None)


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


_summary_cache: dict[str, tuple[float, int, LogSummary]] = {}


def _summary_from_events(path: Path, events: list[dict[str, Any]], *, stat: os.stat_result | None = None) -> LogSummary:
    findings = [event for event in events if event.get("type") == "finding"]
    critical = sum(
        1
        for event in findings
        if str(_nested(event, "value", "severity", default="")).lower() == "critical"
    )
    file_stat = stat or path.stat()
    return LogSummary(
        name=path.name,
        path=str(path),
        size_bytes=file_stat.st_size,
        modified_at=datetime.fromtimestamp(file_stat.st_mtime, tz=timezone.utc).isoformat(),
        event_count=len(events),
        finding_count=len(findings),
        critical_count=critical,
        primitive_count=sum(1 for event in events if event.get("type") == "primitive"),
    )


def summarize_log_file(path: Path) -> LogSummary:
    stat = path.stat()
    cache_key = str(path.resolve())
    cached = _summary_cache.get(cache_key)
    if cached and cached[0] == stat.st_mtime and cached[1] == stat.st_size:
        return cached[2]
    summary = _summary_from_events(path, read_jsonl(path), stat=stat)
    _summary_cache[cache_key] = (stat.st_mtime, stat.st_size, summary)
    return summary


def aggregate_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    type_counts: Counter[str] = Counter()
    severity_counts: Counter[str] = Counter()
    primitive_kind_counts: Counter[str] = Counter()
    api_counts: Counter[str] = Counter()
    actor_counts: Counter[str] = Counter()
    actor_api_counts: dict[str, Counter[str]] = {}
    timeline: Counter[str] = Counter()
    findings: list[dict[str, Any]] = []
    triages: list[dict[str, Any]] = []
    processes: list[dict[str, Any]] = []
    evasion_signals: list[dict[str, Any]] = []
    technique_counts: Counter[str] = Counter()
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
            normalized = _normalize_finding(value, timestamp)
            findings.append(normalized)
            technique = normalized.get("technique")
            if technique:
                technique_counts[str(technique)] += 1
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
                if api:
                    actor_api_counts.setdefault(str(actor), Counter())[str(api)] += 1

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

        if event_type == "triage":
            triages.append(_normalize_triage(value, timestamp))

        if event_type == "file" and value.get("sha256"):
            triages.append(_normalize_file_triage(value, timestamp))

        if event_type == "evasion":
            evasion_signals.append(value)

    _merge_triage_scores(triages)
    process_images = _build_process_image_index(events)
    _enrich_findings_with_process_images(findings, process_images)
    deduped_findings = _dedupe_findings(findings)
    deduped_severity: Counter[str] = Counter()
    for finding in deduped_findings:
        target_pid = finding.get("target_pid")
        if target_pid is not None:
            finding["network"] = networks_by_pid.get(int(target_pid), [])
        severity = str(finding.get("severity", "unknown")).lower()
        deduped_severity[severity] += 1

    injection_chains = chains_from_findings(deduped_findings)
    recursive_chains = [chain for chain in injection_chains if chain.get("is_recursive")]
    return {
        "totals": {
            "events": len(events),
            "findings": len(deduped_findings),
            "findings_raw": type_counts.get("finding", 0),
            "primitives": type_counts.get("primitive", 0),
            "sysmon": type_counts.get("sysmon", 0),
            "frida_raw": type_counts.get("frida_raw", 0),
            "network": type_counts.get("network", 0),
            "triage": type_counts.get("triage", 0),
            "files": type_counts.get("file", 0),
        },
        "event_types": dict(type_counts),
        "severity": dict(deduped_severity),
        "techniques": dict(technique_counts),
        "injection_chains": injection_chains[:20],
        "recursive_chain_count": len(recursive_chains),
        "evasion": summarize_evasion_signals(evasion_signals),
        "primitive_kinds": dict(primitive_kind_counts),
        "top_apis": api_counts.most_common(12),
        "top_actors": [
            {
                "image": image,
                "count": count,
                "apis": actor_api_counts.get(image, Counter()).most_common(6),
            }
            for image, count in actor_counts.most_common(8)
        ],
        "timeline": sorted(timeline.items()),
        "recent_findings": deduped_findings[:50],
        "recent_network": _recent_network_events(networks_by_pid),
        "recent_primitives": _extract_primitives(events, limit=50, process_images=process_images),
        "recent_triages": _dedupe_triages(triages)[:30],
        "pending_file_drops": _extract_pending_file_drops(events)[:30],
        "recent_processes": sorted(processes, key=lambda item: item.get("timestamp") or "", reverse=True)[:15],
    }


def resolve_log_path(logs_dir: Path | str | None, name: str) -> Path | None:
    """Resolve a session name to a ``.jsonl`` file inside the logs directory, or None.

    Names come from HTTP requests, so anything that escapes the logs directory
    or is not a session log is rejected.
    """
    directory = resolve_logs_dir(logs_dir).resolve()
    target = (directory / name).resolve()
    if target.suffix != ".jsonl" or not target.is_relative_to(directory) or not target.is_file():
        return None
    return target


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
        "summary": _summary_from_events(path, events).__dict__,
        "stats": stats,
        "findings": _apply_finding_filters(stats["recent_findings"], severity, target_pid, query),
        "primitives": _extract_primitives(
            events,
            target_pid=target_pid,
            query=query,
            limit=limit,
            process_images=_build_process_image_index(events),
        ),
        "triages": stats["recent_triages"],
        "pending_file_drops": stats["pending_file_drops"],
        "network": _apply_network_filters(stats["recent_network"], target_pid, query),
        "events": filtered_events,
    }


def aggregate_logs(logs_dir: Path | str | None = None, selected: str | None = None) -> dict[str, Any]:
    directory = resolve_logs_dir(logs_dir)
    files = list_log_files(directory)

    active_path: Path | None = None
    events: list[dict[str, Any]] = []
    active: str | None = None

    if selected:
        target = directory / selected
        if not target.exists():
            target = Path(selected)
        if target.exists():
            active_path = target.resolve()
            events = read_jsonl(target)
            active = target.name
        elif files:
            active_path = files[0].resolve()
            events = read_jsonl(files[0])
            active = files[0].name
    elif files:
        active_path = files[0].resolve()
        events = read_jsonl(files[0])
        active = files[0].name

    summaries: list[LogSummary] = []
    for path in files:
        resolved = path.resolve()
        if active_path is not None and resolved == active_path:
            summaries.append(_summary_from_events(path, events))
        else:
            summaries.append(summarize_log_file(path))

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


def _normalize_triage(value: dict[str, Any], timestamp: str | None) -> dict[str, Any]:
    return {
        "timestamp": timestamp,
        "path": value.get("path"),
        "score": value.get("score"),
        "sha256": value.get("sha256"),
        "pe": value.get("pe"),
        "signed": value.get("signed"),
        "entropy": value.get("entropy"),
        "reasons": value.get("suspicious_reasons", []),
    }


def _normalize_file_triage(value: dict[str, Any], timestamp: str | None) -> dict[str, Any]:
    ts = timestamp or _extract_timestamp(value)
    return {
        "timestamp": ts,
        "path": value.get("path"),
        "score": None,
        "sha256": value.get("sha256"),
        "pe": value.get("pe"),
        "signed": value.get("signed"),
        "entropy": value.get("entropy"),
        "reasons": [],
        "creator_image": value.get("creator_image"),
        "creator_pid": value.get("creator_pid"),
    }


def _build_process_image_index(events: list[dict[str, Any]]) -> dict[int, str]:
    images: dict[int, str] = {}
    for event in events:
        event_type = event.get("type")
        value = event.get("value", {})
        if not isinstance(value, dict):
            continue
        if event_type == "frida_raw" and value.get("type") == "process_create":
            pid = value.get("pid")
            image = value.get("image") or _exe_from_command_line(value.get("command_line"))
            if pid is not None and image:
                images[int(pid)] = str(image)
            continue
        if event_type not in {"sysmon", "frida_process", "api_run"}:
            continue
        pid = value.get("pid")
        image = value.get("image")
        if pid is not None and image:
            images[int(pid)] = str(image)
        data = value.get("data")
        if isinstance(data, dict):
            for key_pid, key_image in (
                (data.get("TargetProcessId"), data.get("TargetImage")),
                (data.get("SourceProcessId"), data.get("SourceImage")),
            ):
                if key_pid is not None and key_image:
                    images[int(key_pid)] = str(key_image)
    return images


def _exe_from_command_line(command_line: object | None) -> str | None:
    if command_line is None:
        return None
    line = str(command_line).strip()
    if not line:
        return None
    if line.startswith('"'):
        end = line.find('"', 1)
        if end > 1:
            return line[1:end]
    space = line.find(" ")
    return line if space == -1 else line[:space]


def _resolve_image_from_index(
    pid: int | None,
    process_images: dict[int, str],
    *,
    primitives: list[dict[str, Any]] | None = None,
) -> str | None:
    if pid is None:
        return None
    for primitive in primitives or []:
        if not isinstance(primitive, dict):
            continue
        if primitive.get("target_pid") == pid and primitive.get("target_image"):
            return str(primitive["target_image"])
        if primitive.get("actor_pid") == pid and primitive.get("actor_image"):
            return str(primitive["actor_image"])
    return process_images.get(int(pid))


def _enrich_findings_with_process_images(
    findings: list[dict[str, Any]],
    process_images: dict[int, str],
) -> None:
    for finding in findings:
        primitives = finding.get("primitives") or []
        if not finding.get("actor_image"):
            finding["actor_image"] = _resolve_image_from_index(
                finding.get("actor_pid"),
                process_images,
                primitives=primitives,
            )
        if not finding.get("target_image"):
            finding["target_image"] = _resolve_image_from_index(
                finding.get("target_pid"),
                process_images,
                primitives=primitives,
            )
        if not finding.get("target_image") and finding.get("target_pid") is not None:
            finding["target_image"] = resolve_image_for_pid(int(finding["target_pid"]))
        evidence = finding.setdefault("evidence", {})
        if finding.get("actor_image") and "actor_image" not in evidence:
            evidence["actor_image"] = finding["actor_image"]
        if finding.get("target_image") and "target_image" not in evidence:
            evidence["target_image"] = finding["target_image"]


def _merge_triage_scores(triages: list[dict[str, Any]]) -> None:
    scores: dict[str, Any] = {}
    reasons: dict[str, list[Any]] = {}
    for row in triages:
        path = str(row.get("path") or "").lower()
        if not path:
            continue
        if row.get("score") is not None:
            scores[path] = row.get("score")
        if row.get("reasons"):
            reasons[path] = row.get("reasons")
    for row in triages:
        path = str(row.get("path") or "").lower()
        if not path:
            continue
        if row.get("score") is None and path in scores:
            row["score"] = scores[path]
        if not row.get("reasons") and path in reasons:
            row["reasons"] = reasons[path]


def _extract_pending_file_drops(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    triaged_paths: set[str] = set()
    api_status_by_path: dict[str, str] = {}
    for event in events:
        event_type = event.get("type")
        value = event.get("value", {})
        if not isinstance(value, dict):
            continue
        path = value.get("path")
        if not path:
            continue
        key = str(path).lower()
        if event_type == "triage":
            triaged_paths.add(key)
        if event_type == "file" and value.get("sha256"):
            triaged_paths.add(key)
        if event_type == "api_run":
            api_status_by_path[key] = str(value.get("status") or "started")

    seen: set[str] = set()
    pending: list[dict[str, Any]] = []
    for event in reversed(events):
        if event.get("type") != "file":
            continue
        value = event.get("value", {})
        if not isinstance(value, dict):
            continue
        path = value.get("path")
        if not path:
            continue
        key = str(path).lower()
        if value.get("sha256") or key in triaged_paths or key in seen:
            continue
        seen.add(key)
        api_status = api_status_by_path.get(key, "pending")
        pending.append(
            {
                "timestamp": value.get("timestamp") or _extract_timestamp(value),
                "path": path,
                "creator_image": value.get("creator_image"),
                "creator_pid": value.get("creator_pid"),
                "status": "pending",
                "api_status": api_status,
            }
        )
    return pending


def _dedupe_triages(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: dict[str, dict[str, Any]] = {}
    for row in rows:
        path = str(row.get("path") or "")
        if not path:
            continue
        existing = seen.get(path.lower())
        if existing is None or str(row.get("timestamp") or "") > str(existing.get("timestamp") or ""):
            seen[path.lower()] = row
    return sorted(seen.values(), key=lambda item: item.get("timestamp") or "", reverse=True)


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
        "succeeded": value.get("succeeded"),
        "source": value.get("source"),
        "beacon_candidate": beacon_candidate,
    }


def _extract_primitives(
    events: list[dict[str, Any]],
    *,
    target_pid: int | None = None,
    query: str | None = None,
    limit: int = 50,
    process_images: dict[int, str] | None = None,
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
            "target_image": value.get("target_image"),
            "address": value.get("address"),
            "size": value.get("size"),
            "details": value.get("details", {}),
        }
        if target_pid is not None and row.get("target_pid") != target_pid:
            continue
        if not row.get("actor_image") and process_images is not None:
            row["actor_image"] = _resolve_image_from_index(row.get("actor_pid"), process_images)
        if not row.get("target_image") and process_images is not None:
            row["target_image"] = _resolve_image_from_index(row.get("target_pid"), process_images)
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
    primitives = value.get("primitives", [])
    evidence = value.get("evidence", {})
    actor_image = value.get("actor_image") or evidence.get("actor_image")
    target_image = value.get("target_image") or evidence.get("target_image")
    return {
        "timestamp": timestamp,
        "severity": value.get("severity"),
        "score": value.get("score"),
        "title": value.get("title"),
        "description": value.get("description"),
        "actor_pid": value.get("actor_pid"),
        "actor_image": actor_image,
        "target_pid": value.get("target_pid"),
        "target_image": target_image,
        "technique": value.get("technique") or evidence.get("technique"),
        "technique_confidence": value.get("technique_confidence") or evidence.get("technique_confidence"),
        "payload_kind": evidence.get("payload_kind"),
        "payload_rationale": evidence.get("payload_rationale"),
        "execution_confirmed": evidence.get("execution_confirmed"),
        "execution_evidence": evidence.get("execution_evidence") or [],
        "context_read_evidence": evidence.get("context_read_evidence") or [],
        "missing_execution_transfer": evidence.get("missing_execution_transfer"),
        "chain_depth": value.get("chain_depth") or evidence.get("chain_depth") or 0,
        "is_recursive": bool(value.get("is_recursive") or evidence.get("is_recursive")),
        "injection_chain": value.get("injection_chain") or evidence.get("injection_chain_pids"),
        "apis": apis,
        "evidence": evidence,
        "primitives": primitives,
        "network_connections": value.get("network_connections") or [],
    }
