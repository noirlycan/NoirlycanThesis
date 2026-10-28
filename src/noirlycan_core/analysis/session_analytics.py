"""Aggregate JSONL session metrics for batch runs and thesis reports."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import TYPE_CHECKING, Any

from noirlycan_core.extensions.evasion import summarize_evasion_signals
from noirlycan_core.detection.injection_graph import chains_from_findings
from noirlycan_core.classification.technique_classifier import (
    InjectionTechnique,
    classification_from_dict,
)
from noirlycan_core.storage.log_store import (
    count_jsonl_lines,
    list_log_files,
    read_jsonl,
    resolve_logs_dir,
)

if TYPE_CHECKING:
    from noirlycan_core.storage.analysis_db import AnalysisDatabase


def _empty_session_state() -> dict[str, Any]:
    return {
        "finding_rows": [],
        "evasion_signals": [],
        "events": 0,
        "primitives": 0,
    }


def _apply_events_to_state(state: dict[str, Any], events: list[dict[str, Any]]) -> None:
    for event in events:
        event_type = event.get("type")
        value = event.get("value", {})
        if not isinstance(value, dict):
            value = {}
        state["events"] += 1
        if event_type == "finding":
            state["finding_rows"].append(_normalize_finding_row(value))
        elif event_type == "primitive":
            state["primitives"] += 1
        elif event_type == "evasion":
            state["evasion_signals"].append(value)


def _finalize_session_report(path: Path, state: dict[str, Any]) -> dict[str, Any]:
    findings = list(state.get("finding_rows") or [])
    evasion_signals = list(state.get("evasion_signals") or [])
    primitives = int(state.get("primitives") or 0)
    events = int(state.get("events") or 0)

    technique_counts: Counter[str] = Counter()
    severity_counts: Counter[str] = Counter()
    recursive_findings = 0
    for finding in findings:
        technique = finding.get("technique") or "unclassified"
        technique_counts[str(technique)] += 1
        severity_counts[str(finding.get("severity") or "unknown")] += 1
        if finding.get("is_recursive"):
            recursive_findings += 1

    chains = chains_from_findings(findings)
    recursive_chains = [chain for chain in chains if chain.get("is_recursive")]

    return {
        "session": path.name,
        "path": str(path),
        "events": events,
        "findings": len(findings),
        "primitives": primitives,
        "injection_detected": len(findings) > 0,
        "max_score": max((int(f.get("score") or 0) for f in findings), default=0),
        "severity": dict(severity_counts),
        "techniques": dict(technique_counts),
        "recursive_findings": recursive_findings,
        "injection_chains": chains,
        "recursive_chain_count": len(recursive_chains),
        "max_chain_depth": max((int(c.get("depth") or 0) for c in chains), default=0),
        "evasion": summarize_evasion_signals(evasion_signals),
        "top_findings": findings[:5],
    }


def analyze_session(
    path: Path,
    *,
    database: AnalysisDatabase | None = None,
) -> dict[str, Any]:
    resolved = path.resolve()
    cached_state: dict[str, Any] | None = None
    if database is not None:
        cached_state = database.load_cached_session_state(resolved)

    if cached_state is not None and not cached_state.pop("_incremental", False):
        report = _finalize_session_report(resolved, cached_state)
        cached_state["_lines_processed"] = cached_state.get("_lines_processed") or count_jsonl_lines(resolved)
        return report

    if cached_state is not None:
        after_line = int(cached_state.pop("_lines_processed", 0) or 0)
        state = {
            "finding_rows": list(cached_state.get("finding_rows") or []),
            "evasion_signals": list(cached_state.get("evasion_signals") or []),
            "events": int(cached_state.get("events") or 0),
            "primitives": int(cached_state.get("primitives") or 0),
        }
        new_events = read_jsonl(resolved, after_line=after_line)
        _apply_events_to_state(state, new_events)
    else:
        state = _empty_session_state()
        _apply_events_to_state(state, read_jsonl(resolved))

    state["_lines_processed"] = count_jsonl_lines(resolved)
    if database is not None:
        database.store_cached_session_state(resolved, state)
    return _finalize_session_report(resolved, state)


def analyze_corpus(
    logs_dir: Path | str | None = None,
    *,
    limit: int | None = None,
    database: AnalysisDatabase | None = None,
) -> dict[str, Any]:
    """Aggregate metrics across multiple JSONL session logs (corpus-level view)."""
    directory = resolve_logs_dir(logs_dir)
    paths = list_log_files(directory)
    if limit is not None and limit > 0:
        paths = paths[:limit]
    reports = [analyze_session(path, database=database) for path in paths]
    summary = aggregate_batch_reports(reports)
    summary["logs_dir"] = str(directory)
    summary["session_files"] = [path.name for path in paths]
    return summary


def aggregate_batch_reports(reports: list[dict[str, Any]]) -> dict[str, Any]:
    if not reports:
        return {"samples": 0}
    technique_totals: Counter[str] = Counter()
    severity_totals: Counter[str] = Counter()
    detected = 0
    recursive_samples = 0
    evasive_samples = 0
    chain_depths: list[int] = []

    for report in reports:
        if report.get("injection_detected"):
            detected += 1
        if report.get("recursive_chain_count", 0) > 0 or report.get("recursive_findings", 0) > 0:
            recursive_samples += 1
        if (report.get("evasion") or {}).get("evasive_sample"):
            evasive_samples += 1
        for technique, count in (report.get("techniques") or {}).items():
            technique_totals[str(technique)] += int(count)
        for severity, count in (report.get("severity") or {}).items():
            severity_totals[str(severity)] += int(count)
        if report.get("max_chain_depth"):
            chain_depths.append(int(report["max_chain_depth"]))

    sample_count = len(reports)
    return {
        "samples": sample_count,
        "injection_detected_count": detected,
        "injection_detection_rate": round(detected / sample_count, 4),
        "recursive_sample_count": recursive_samples,
        "recursive_sample_rate": round(recursive_samples / sample_count, 4),
        "evasive_sample_count": evasive_samples,
        "evasive_sample_rate": round(evasive_samples / sample_count, 4),
        "technique_distribution": dict(technique_totals),
        "severity_distribution": dict(severity_totals),
        "avg_max_chain_depth": round(sum(chain_depths) / len(chain_depths), 2) if chain_depths else 0,
        "sessions": reports,
    }


def _normalize_finding_row(value: dict[str, Any]) -> dict[str, Any]:
    evidence = value.get("evidence") or {}
    classification = classification_from_dict(value)
    technique = value.get("technique") or evidence.get("technique")
    if classification is not None:
        technique = classification.technique.value
    return {
        "severity": value.get("severity"),
        "score": value.get("score"),
        "technique": technique or InjectionTechnique.UNCLASSIFIED.value,
        "technique_confidence": value.get("technique_confidence") or evidence.get("technique_confidence"),
        "actor_pid": value.get("actor_pid"),
        "target_pid": value.get("target_pid"),
        "actor_image": value.get("actor_image") or evidence.get("actor_image"),
        "target_image": value.get("target_image") or evidence.get("target_image"),
        "is_recursive": bool(value.get("is_recursive") or evidence.get("is_recursive")),
        "chain_depth": value.get("chain_depth") or evidence.get("chain_depth") or 0,
        "timestamp": value.get("timestamp"),
    }
