"""Offline re-correlation and re-classification from stored JSONL sessions."""

from __future__ import annotations

import dataclasses
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from noirlycan_core.kernel.entities.models import FileEvent, MemoryPrimitive, PrimitiveKind, ProcessEvent, Severity
from noirlycan_core.analysis.domain.correlation import Correlator
from noirlycan_core.analysis.domain.session_analytics import analyze_session
from noirlycan_agent.collector.infrastructure.frida_manager import (
    FridaRuntimeEvent,
    runtime_event_to_primitive,
)
from noirlycan_core.storage.infrastructure.log_store import (
    invalidate_log_cache,
    read_jsonl,
    resolve_log_path,
    resolve_logs_dir,
)


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


def primitive_from_jsonl(value: dict[str, Any]) -> MemoryPrimitive | None:
    kind_raw = value.get("kind") or value.get("primitive")
    try:
        kind = PrimitiveKind(str(kind_raw))
    except (TypeError, ValueError):
        return None
    actor_pid = _safe_int(value.get("actor_pid"))
    if actor_pid is None:
        return None
    details = value.get("details") if isinstance(value.get("details"), dict) else {}
    extra = {
        key: item
        for key, item in value.items()
        if key
        not in {
            "timestamp",
            "kind",
            "primitive",
            "actor_pid",
            "actor_image",
            "target_pid",
            "target_image",
            "address",
            "size",
            "api",
            "details",
        }
    }
    merged_details = {**extra, **details}
    return MemoryPrimitive(
        timestamp=_parse_timestamp(value.get("timestamp")),
        kind=kind,
        actor_pid=actor_pid,
        actor_image=value.get("actor_image"),
        target_pid=_safe_int(value.get("target_pid")),
        target_image=value.get("target_image"),
        address=_safe_int(value.get("address")),
        size=_safe_int(value.get("size")),
        api=str(value.get("api") or "unknown"),
        details=merged_details,
    )


def file_event_from_jsonl(value: dict[str, Any]) -> FileEvent | None:
    path = value.get("path")
    if not path:
        return None
    return FileEvent(
        timestamp=_parse_timestamp(value.get("timestamp")),
        path=str(path),
        creator_pid=_safe_int(value.get("creator_pid")),
        creator_image=value.get("creator_image"),
        sha256=value.get("sha256"),
        signed=value.get("signed"),
        entropy=value.get("entropy"),
        pe=value.get("pe"),
    )


def process_event_from_jsonl(value: dict[str, Any]) -> ProcessEvent | None:
    pid = _safe_int(value.get("pid"))
    image = value.get("image")
    if pid is None or not image:
        return None
    flags = value.get("flags") or []
    if not isinstance(flags, list):
        flags = []
    return ProcessEvent(
        timestamp=_parse_timestamp(value.get("timestamp")),
        pid=pid,
        image=str(image),
        command_line=value.get("command_line"),
        parent_pid=_safe_int(value.get("parent_pid")),
        parent_image=value.get("parent_image"),
        created_from_file=value.get("created_from_file"),
        flags=[str(flag) for flag in flags],
    )


def _finding_summary(finding: Any) -> dict[str, Any]:
    payload = dataclasses.asdict(finding)
    payload["severity"] = finding.severity.value if isinstance(finding.severity, Severity) else finding.severity
    primitives = []
    for primitive in finding.primitives:
        item = dataclasses.asdict(primitive)
        item["kind"] = primitive.kind.value
        primitives.append(item)
    payload["primitives"] = primitives
    return payload


WriteMode = str | bool | None


def _resolve_session_path(session_path: Path | str, logs_dir: Path | str | None) -> Path:
    path = Path(session_path).expanduser().resolve()
    if path.is_file():
        return path
    resolved = resolve_log_path(logs_dir, path.name)
    if resolved is None:
        raise FileNotFoundError(f"session log not found: {session_path}")
    return resolved


def write_reclassified_jsonl(
    source_path: Path,
    findings: list[dict[str, Any]],
    *,
    output_path: Path | None = None,
    in_place: bool = False,
) -> Path:
    """Write non-finding events plus regenerated findings to a JSONL file."""
    events = read_jsonl(source_path)
    preserved = [event for event in events if str(event.get("type") or "") != "finding"]
    target = source_path if in_place else (output_path or source_path.with_name(f"{source_path.stem}.reclassified.jsonl"))
    if in_place:
        target = source_path.with_suffix(source_path.suffix + ".tmp")
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8") as handle:
        for event in preserved:
            handle.write(json.dumps(event, sort_keys=True) + "\n")
        for finding in findings:
            payload = {"type": "finding", "value": finding}
            handle.write(json.dumps(payload, sort_keys=True) + "\n")
    if in_place:
        backup = source_path.with_suffix(source_path.suffix + ".bak")
        if backup.exists():
            backup.unlink()
        source_path.replace(backup)
        target.replace(source_path)
        _invalidate_analytics_cache(source_path)
        invalidate_log_cache(source_path)
        return source_path
    _invalidate_analytics_cache(target)
    invalidate_log_cache(target)
    return target


def _invalidate_analytics_cache(path: Path) -> None:
    try:
        from noirlycan_core.storage.infrastructure.analysis_db import AnalysisDatabase

        AnalysisDatabase(path.parent).invalidate_session_analytics_cache(path.name)
    except OSError:
        pass


def reclassify_session(
    session_path: Path | str,
    *,
    logs_dir: Path | str | None = None,
    minimum_score: int = 50,
    write: WriteMode = False,
) -> dict[str, Any]:
    """Replay primitives/processes/files from JSONL through a fresh Correlator."""
    path = _resolve_session_path(session_path, logs_dir)

    events = read_jsonl(path)
    original_findings = sum(1 for event in events if event.get("type") == "finding")
    original_techniques: dict[str, int] = {}
    for event in events:
        if event.get("type") != "finding":
            continue
        value = event.get("value") or {}
        technique = str(value.get("technique") or value.get("evidence", {}).get("technique") or "unclassified")
        original_techniques[technique] = original_techniques.get(technique, 0) + 1

    correlator = Correlator(minimum_score=minimum_score, logs_dir=logs_dir or resolve_logs_dir())
    regenerated: list[dict[str, Any]] = []

    for event in events:
        event_type = str(event.get("type") or "")
        value = event.get("value") or {}
        if not isinstance(value, dict):
            continue

        if event_type == "file":
            file_event = file_event_from_jsonl(value)
            if file_event is not None:
                correlator.add_file(file_event)
            continue

        if event_type in {"sysmon", "frida_process"}:
            process_event = process_event_from_jsonl(value)
            if process_event is not None:
                correlator.add_process(process_event)
            continue

        primitive: MemoryPrimitive | None = None
        if event_type == "primitive":
            primitive = primitive_from_jsonl(value)
        elif event_type == "frida_raw" and isinstance(value, dict):
            payload_type = str(value.get("type") or "")
            runtime_event = FridaRuntimeEvent(event_type=payload_type, payload=value)
            primitive = runtime_event_to_primitive(runtime_event)

        if primitive is None:
            continue
        for finding in correlator.add_primitive(primitive):
            regenerated.append(_finding_summary(finding))

    technique_counts: dict[str, int] = {}
    for finding in regenerated:
        technique = str(finding.get("technique") or "unclassified")
        technique_counts[technique] = technique_counts.get(technique, 0) + 1

    baseline = analyze_session(path)
    write_mode = str(write).strip().lower() if write else ""
    written_path: str | None = None
    if write_mode in {"sidecar", "1", "true", "yes"}:
        destination = write_reclassified_jsonl(path, regenerated, in_place=False)
        written_path = str(destination)
    elif write_mode in {"in_place", "inplace", "replace"}:
        destination = write_reclassified_jsonl(path, regenerated, in_place=True)
        written_path = str(destination)

    return {
        "session": path.name,
        "path": str(path),
        "original_finding_count": original_findings,
        "reclassified_finding_count": len(regenerated),
        "original_techniques": original_techniques,
        "reclassified_techniques": technique_counts,
        "delta_findings": len(regenerated) - original_findings,
        "baseline_stats": baseline,
        "findings": regenerated,
        "written_path": written_path,
    }


def write_reclassified_report(report: dict[str, Any], output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    return output_path
