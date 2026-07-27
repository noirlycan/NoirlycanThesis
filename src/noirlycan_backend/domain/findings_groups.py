from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from noirlycan_core.storage.infrastructure.log_store import (
    aggregate_events,
    aggregate_logs,
    read_jsonl,
    resolve_logs_dir,
    session_detail,
)


def _image_name(value: str | None) -> str:
    if not value:
        return "unknown"
    return Path(str(value)).name


def _victim_label(finding: dict[str, Any]) -> str:
    image = finding.get("target_image")
    if image:
        return _image_name(str(image))
    return "unknown"


def _injection_group_count(groups: list[dict[str, Any]]) -> int:
    return len([group for group in groups if group.get("vpid") is not None])


def _visible_finding_count(groups: list[dict[str, Any]]) -> int:
    return sum(int(group.get("count") or 0) for group in groups)


def _finding_key(finding: dict[str, Any]) -> str:
    return str(finding.get("timestamp") or finding.get("id") or id(finding))


def _matches_agent(finding: dict[str, Any], agent_id: str) -> bool:
    tagged = str(finding.get("agent_id") or "")
    if tagged:
        return tagged == agent_id
    return False


def _tag_agent(finding: dict[str, Any], agent_id: str) -> dict[str, Any]:
    tagged = dict(finding)
    tagged["agent_id"] = agent_id
    return tagged


def _resolve_session_path(logs_dir: Path, session_rel: str) -> Path | None:
    directory = resolve_logs_dir(logs_dir)
    target = directory / session_rel
    if target.exists() and target.is_file():
        return target.resolve()
    fallback = Path(session_rel)
    if fallback.exists() and fallback.is_file():
        return fallback.resolve()
    return None


def _load_session_stats(logs_dir: Path, session_rel: str, agent_id: str) -> dict[str, Any]:
    path = _resolve_session_path(logs_dir, session_rel)
    if path is None:
        return {"findings": [], "stats": {}, "session_rel": session_rel, "agent_id": agent_id}
    events = read_jsonl(path)
    stats = aggregate_events(events)
    findings = [_tag_agent(item, agent_id) for item in stats.get("recent_findings") or []]
    return {
        "findings": findings,
        "stats": stats,
        "session_rel": session_rel,
        "agent_id": agent_id,
        "session_name": path.name,
    }


def file_drop_key(path: str | None) -> str:
    if not path:
        return ""
    text = str(path).strip().replace("\\", "/")
    while "//" in text:
        text = text.replace("//", "/")
    return text.lower()


def _file_drops_for_display(
    stats: dict[str, Any],
    *,
    removed_drops: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Merge completed triages with pending file-drop detections for dashboard lists."""
    hidden = removed_drops or set()
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in stats.get("recent_triages") or []:
        if not isinstance(item, dict):
            continue
        path = str(item.get("path") or "")
        key = file_drop_key(path)
        if not path or key in hidden or key in seen:
            continue
        row = dict(item)
        row["drop_key"] = key
        rows.append(row)
        seen.add(key)
    for pending in stats.get("pending_file_drops") or []:
        if not isinstance(pending, dict):
            continue
        path = str(pending.get("path") or "")
        key = file_drop_key(path)
        if not path or key in hidden or key in seen:
            continue
        rows.append(
            {
                "timestamp": pending.get("timestamp"),
                "path": path,
                "drop_key": key,
                "sha256": pending.get("sha256"),
                "entropy": pending.get("entropy"),
                "signed": pending.get("signed"),
                "creator_image": pending.get("creator_image"),
                "creator_pid": pending.get("creator_pid"),
                "status": pending.get("status") or "pending",
                "api_status": pending.get("api_status"),
            }
        )
        seen.add(key)
    rows.sort(key=lambda item: str(item.get("timestamp") or ""), reverse=True)
    return rows[:30]


def _merge_counters(*items: dict[str, Any] | Counter[str]) -> dict[str, int]:
    merged: Counter[str] = Counter()
    for item in items:
        if not item:
            continue
        merged.update({str(k): int(v) for k, v in dict(item).items()})
    return dict(merged)


def _agent_hostname(agents: list[dict[str, Any]], agent_id: str) -> str:
    for agent in agents:
        if str(agent.get("id")) == agent_id:
            return str(agent.get("display_name") or agent.get("hostname") or agent_id)
    return agent_id


def _agent_ip(agents: list[dict[str, Any]], agent_id: str) -> str:
    for agent in agents:
        if str(agent.get("id")) == agent_id:
            return str(agent.get("ip_address") or "")
    return ""


def group_findings(
    findings: list[dict[str, Any]],
    *,
    removed: set[str] | None = None,
    agent_hostnames: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    removed = removed or set()
    hostnames = agent_hostnames or {}
    deduped: dict[str, dict[str, Any]] = {}
    for f in findings:
        key = _finding_key(f)
        if key in removed:
            continue
        existing = deduped.get(key)
        if existing is None or len(f.get("network_connections") or []) > len(existing.get("network_connections") or []):
            deduped[key] = f
    visible = list(deduped.values())
    buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for finding in visible:
        agent = str(finding.get("agent_id") or "unknown")
        target_pid = finding.get("target_pid")
        actor_image = _image_name(finding.get("actor_image"))
        if target_pid is None:
            group_key = f"{agent}|{actor_image}|disk"
        else:
            target_image = _victim_label(finding)
            group_key = f"{agent}|{actor_image}|{target_image}|{target_pid}"
        buckets[group_key].append(finding)

    groups: list[dict[str, Any]] = []
    for key, members in buckets.items():
        members_sorted = sorted(
            members,
            key=lambda item: str(item.get("timestamp") or ""),
        )
        top = max(members_sorted, key=lambda item: _severity_rank(item.get("severity")))
        parts = key.split("|")
        agent_id = parts[0]
        actor = parts[1]
        if parts[2] == "disk":
            victim = "disk drop"
            vpid = None
            summary = "Payload staged on disk"
        else:
            victim = parts[2]
            vpid = int(parts[3]) if parts[3].isdigit() else parts[3]
            summary = members_sorted[-1].get("title") or "Injection chain into target process"

        groups.append(
            {
                "key": key,
                "agent_id": agent_id,
                "hostname": hostnames.get(agent_id, agent_id),
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
                        "agent_id": str(item.get("agent_id") or agent_id),
                        "hostname": hostnames.get(str(item.get("agent_id") or agent_id), agent_id),
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
    agent_id: str | None = None,
    removed: set[str] | None = None,
    agents: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    directory = resolve_logs_dir(logs_dir)
    stats: dict[str, Any]
    findings: list[dict[str, Any]]
    active: str | None = None

    if agent_id and session:
        bundle = _load_session_stats(directory, session, agent_id)
        findings = list(bundle.get("findings") or [])
        stats = bundle.get("stats") or {}
        active = bundle.get("session_name")
    else:
        aggregate = aggregate_logs(directory, selected=session)
        active = aggregate.get("active_log")
        stats = aggregate.get("stats") or {}
        findings = list(stats.get("recent_findings") or stats.get("findings") or [])
        if not findings and active:
            detail = session_detail(active, directory)
            if detail:
                findings = list(detail.get("findings") or [])
        if agent_id:
            findings = [_tag_agent(f, agent_id) for f in findings if _matches_agent(f, agent_id)]

    hostnames: dict[str, str] = {}
    if agent_id:
        hostnames[agent_id] = _agent_hostname(agents or [], agent_id)
    groups = group_findings(findings, removed=removed, agent_hostnames=hostnames)
    severity_counts = stats.get("severity") or stats.get("severity_counts") or {}
    return {
        "session": active,
        "session_rel": session,
        "agent_id": agent_id,
        "logs_dir": str(directory),
        "findings": findings,
        "groups": groups,
        "severity_counts": severity_counts,
        "stats": stats,
    }


def load_all_agents_findings(
    logs_dir: Path | str | None,
    *,
    agent_sessions: list[dict[str, Any]],
    agents: list[dict[str, Any]],
    removed: set[str] | None = None,
    removed_file_drops: set[str] | None = None,
) -> dict[str, Any]:
    directory = resolve_logs_dir(logs_dir)
    hostnames = {str(agent["id"]): _agent_hostname(agents, str(agent["id"])) for agent in agents}
    registered = set(hostnames)
    all_findings: list[dict[str, Any]] = []
    merged_stats: list[dict[str, Any]] = []
    agent_stats: list[dict[str, Any]] = []

    for row in agent_sessions:
        agent_id = str(row.get("agent_id") or "")
        if agent_id not in registered:
            continue
        session_rel = str(row.get("session_rel") or "")
        if not agent_id or not session_rel:
            continue
        bundle = _load_session_stats(directory, session_rel, agent_id)
        findings = bundle.get("findings") or []
        stats = bundle.get("stats") or {}
        merged_stats.append(stats)
        visible = [f for f in findings if _finding_key(f) not in (removed or set())]
        all_findings.extend(visible)

        severity = stats.get("severity") or {}
        networks = stats.get("recent_network") or []
        triages = _file_drops_for_display(stats, removed_drops=removed_file_drops)
        agent_groups = group_findings(
            visible,
            removed=removed,
            agent_hostnames={agent_id: hostnames.get(agent_id, agent_id)},
        )
        agent_stats.append(
            {
                "agent_id": agent_id,
                "hostname": hostnames.get(agent_id, agent_id),
                "ip_address": _agent_ip(agents, agent_id),
                "session_rel": session_rel,
                "status": next(
                    (str(a.get("status") or "offline") for a in agents if str(a.get("id")) == agent_id),
                    "offline",
                ),
                "findings": _visible_finding_count(agent_groups) or len(visible),
                "critical": int(severity.get("critical", 0)),
                "high": int(severity.get("high", 0)),
                "medium": int(severity.get("medium", 0)),
                "low": int(severity.get("low", 0)),
                "injection_chains": _injection_group_count(agent_groups),
                "file_drops": len(triages),
                "beacons": len(networks),
            }
        )

    groups = group_findings(all_findings, removed=removed, agent_hostnames=hostnames)
    severity_counts = _merge_counters(*(stats.get("severity") or {} for stats in merged_stats))
    primitive_counts = _merge_counters(*(stats.get("primitive_kinds") or {} for stats in merged_stats))

    all_triages: list[dict[str, Any]] = []
    all_network: list[dict[str, Any]] = []
    all_events: list[dict[str, Any]] = []
    all_chains: list[dict[str, Any]] = []
    totals = Counter()
    for stats in merged_stats:
        all_triages.extend(_file_drops_for_display(stats, removed_drops=removed_file_drops))
        all_network.extend(stats.get("recent_network") or [])
        all_events.extend(list(stats.get("recent_primitives") or []) + list(stats.get("recent_processes") or []))
        all_chains.extend(stats.get("injection_chains") or [])
        for key, value in (stats.get("totals") or {}).items():
            totals[key] += int(value)

    agent_stats.sort(key=lambda item: (-item["findings"], item["hostname"]))
    return {
        "session": None,
        "session_rel": None,
        "agent_id": None,
        "scope": "all_agents",
        "logs_dir": str(directory),
        "findings": all_findings,
        "groups": groups,
        "severity_counts": severity_counts,
        "primitive_kind_counts": primitive_counts,
        "stats": {
            "totals": dict(totals),
            "severity": severity_counts,
            "primitive_kinds": primitive_counts,
            "injection_chains": all_chains,
            "recent_triages": all_triages[:30],
            "recent_network": all_network[:50],
            "recent_primitives": all_events[:30],
            "recent_processes": [],
        },
        "agent_stats": agent_stats,
    }


def overview_payload(
    logs_dir: Path | str | None = None,
    *,
    session: str | None = None,
    agent_id: str | None = None,
    removed: set[str] | None = None,
    removed_file_drops: set[str] | None = None,
    agent_sessions: list[dict[str, Any]] | None = None,
    agents: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if agent_id is None and agent_sessions is not None:
        bundle = load_all_agents_findings(
            logs_dir,
            agent_sessions=agent_sessions,
            agents=agents or [],
            removed=removed,
            removed_file_drops=removed_file_drops,
        )
    else:
        bundle = load_console_findings(logs_dir, session=session, agent_id=agent_id, removed=removed)

    stats = bundle.get("stats") or {}
    findings = bundle.get("findings") or []
    severity_counts = bundle.get("severity_counts") or {}

    critical = [
        f
        for f in findings
        if str(f.get("severity", "")).lower() == "critical"
        and _finding_key(f) not in (removed or set())
    ]
    critical.sort(key=lambda item: str(item.get("timestamp") or ""), reverse=True)
    critical_finding = critical[0] if critical else None
    if critical_finding and agent_id is None and bundle.get("agent_stats"):
        hostnames = {row["agent_id"]: row["hostname"] for row in bundle.get("agent_stats") or []}
        aid = str(critical_finding.get("agent_id") or "")
        if aid in hostnames:
            critical_finding = {**critical_finding, "hostname": hostnames[aid]}
    groups = bundle.get("groups") or []
    triages = _file_drops_for_display(stats, removed_drops=removed_file_drops)
    networks = stats.get("recent_network") or stats.get("network") or []

    primitive_counts = bundle.get("primitive_kind_counts") or stats.get("primitive_kinds") or stats.get(
        "primitive_kind_counts"
    ) or {}
    recent_events = (
        list(stats.get("recent_primitives") or [])
        + list(stats.get("recent_processes") or [])
    )[:30]
    registered_agents = len(agents or []) if agent_id is None and agent_sessions is not None else None
    return {
        "session": bundle.get("session"),
        "session_rel": bundle.get("session_rel"),
        "agent_id": agent_id,
        "scope": bundle.get("scope") or ("agent" if agent_id else "session"),
        "logs_dir": bundle.get("logs_dir"),
        "kpis": {
            "findings": _visible_finding_count(groups) or len(findings),
            "critical": len(critical),
            "injection_chains": _injection_group_count(groups),
            "file_drops": len(triages),
            "beacons": len(networks),
            "agents": registered_agents if registered_agents is not None else len(bundle.get("agent_stats") or []),
        },
        "severity_counts": severity_counts,
        "primitive_kind_counts": primitive_counts,
        "critical_finding": critical_finding,
        "groups": bundle.get("groups") or [],
        "agent_stats": bundle.get("agent_stats") or [],
        "recent_events": recent_events,
        "triages": triages,
        "network": networks,
        "beacons": networks,
    }
