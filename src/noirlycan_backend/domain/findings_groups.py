from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any

from noirlycan_core.storage.infrastructure.log_store import (
    aggregate_logs,
    resolve_logs_dir,
    session_detail,
)


def _image_name(value: str | None) -> str:
    if not value:
        return "unknown"
    return Path(str(value)).name


def _finding_key(finding: dict[str, Any]) -> str:
    return str(finding.get("timestamp") or finding.get("id") or id(finding))


def group_findings(
    findings: list[dict[str, Any]],
    *,
    removed: set[str] | None = None,
) -> list[dict[str, Any]]:
    removed = removed or set()
    visible = [f for f in findings if _finding_key(f) not in removed]
    buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for finding in visible:
        target_pid = finding.get("target_pid")
        actor_image = _image_name(finding.get("actor_image"))
        if target_pid is None:
            group_key = f"{actor_image}|disk"
        else:
            target_image = _image_name(finding.get("target_image"))
            group_key = f"{actor_image}|{target_image}|{target_pid}"
        buckets[group_key].append(finding)

    groups: list[dict[str, Any]] = []
    for key, members in buckets.items():
        members_sorted = sorted(
            members,
            key=lambda item: str(item.get("timestamp") or ""),
        )
        top = max(members_sorted, key=lambda item: _severity_rank(item.get("severity")))
        parts = key.split("|")
        actor = parts[0]
        if parts[1] == "disk":
            victim = "disk drop"
            vpid = None
            summary = "Payload staged on disk"
        else:
            victim = parts[1]
            vpid = int(parts[2]) if parts[2].isdigit() else parts[2]
            summary = members_sorted[-1].get("title") or "Injection chain into target process"

        groups.append(
            {
                "key": key,
                "top_severity": str(top.get("severity") or "INFO").upper(),
                "source": actor,
                "victim": victim,
                "vpid": vpid,
                "summary": summary,
                "tags": _collect_tags(members_sorted),
                "count": len(members_sorted),
                "members": [
                    {
                        "key": _finding_key(item),
                        "step": index + 1,
                        "severity": str(item.get("severity") or "INFO").upper(),
                        "title": item.get("title") or item.get("technique") or "Finding",
                        "primitives": item.get("primitive_kinds") or item.get("primitives_count"),
                        "time": item.get("timestamp"),
                        "finding": item,
                    }
                    for index, item in enumerate(members_sorted)
                ],
            }
        )

    rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    groups.sort(key=lambda item: (rank.get(item["top_severity"], 9), -item["count"]))
    return groups


def _severity_rank(severity: object) -> int:
    order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
    return order.get(str(severity or "").upper(), 0)


def _collect_tags(findings: list[dict[str, Any]]) -> list[str]:
    tags: set[str] = set()
    for finding in findings:
        evidence = finding.get("evidence") or {}
        if isinstance(evidence, dict):
            for key, value in evidence.items():
                if value is True:
                    tags.add(f"{key}=true")
                elif value is False:
                    tags.add(f"{key}=false")
        if finding.get("section_mapping"):
            tags.add("section_mapping=true")
        if finding.get("cross_process"):
            tags.add("cross_process=true")
    return sorted(tags)


def load_console_findings(
    logs_dir: Path | str | None = None,
    *,
    session: str | None = None,
    removed: set[str] | None = None,
) -> dict[str, Any]:
    directory = resolve_logs_dir(logs_dir)
    aggregate = aggregate_logs(directory, selected=session)
    active = aggregate.get("active_log")
    stats = aggregate.get("stats") or {}
    findings = list(stats.get("recent_findings") or stats.get("findings") or [])
    if not findings and active:
        detail = session_detail(active, directory)
        if detail:
            findings = list(detail.get("findings") or [])

    groups = group_findings(findings, removed=removed)
    severity_counts = stats.get("severity") or stats.get("severity_counts") or {}
    return {
        "session": active,
        "logs_dir": str(directory),
        "findings": findings,
        "groups": groups,
        "severity_counts": severity_counts,
        "stats": stats,
    }


def overview_payload(
    logs_dir: Path | str | None = None,
    *,
    session: str | None = None,
    removed: set[str] | None = None,
) -> dict[str, Any]:
    bundle = load_console_findings(logs_dir, session=session, removed=removed)
    stats = bundle.get("stats") or {}
    findings = bundle.get("findings") or []
    severity_counts = bundle.get("severity_counts") or {}

    critical = [
        f
        for f in findings
        if str(f.get("severity", "")).lower() == "critical"
        and _finding_key(f) not in (removed or set())
    ]
    chains = stats.get("injection_chains") or []
    triages = stats.get("recent_triages") or stats.get("triages") or []
    networks = stats.get("recent_network") or stats.get("network") or []
    beacons = [n for n in networks if n.get("beacon_candidate") or n.get("is_external")]

    primitive_counts = stats.get("primitive_kinds") or stats.get("primitive_kind_counts") or {}
    recent_events = (
        list(stats.get("recent_primitives") or [])
        + list(stats.get("recent_processes") or [])
    )[:30]
    return {
        "session": bundle.get("session"),
        "logs_dir": bundle.get("logs_dir"),
        "kpis": {
            "findings": len(findings) - len(removed or set()),
            "critical": len(critical),
            "injection_chains": len(chains) or len(
                [g for g in bundle.get("groups") or [] if g.get("vpid") is not None]
            ),
            "file_drops": len(triages),
            "beacons": len(beacons),
        },
        "severity_counts": severity_counts,
        "primitive_kind_counts": primitive_counts,
        "critical_finding": critical[0] if critical else None,
        "groups": bundle.get("groups") or [],
        "recent_events": recent_events,
        "triages": triages,
        "network": networks,
        "beacons": beacons,
        "min_primitives": stats.get("min_primitive_kinds") or 2,
    }
