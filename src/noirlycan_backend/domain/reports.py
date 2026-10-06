from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def _fmt_time(value: object) -> str:
    if not value:
        return "-"
    return str(value)


def _finding_flow(finding: dict[str, Any]) -> str:
    actor = finding.get("actor_image") or finding.get("source") or "unknown"
    actor_pid = finding.get("actor_pid") or "-"
    target = finding.get("target_image") or finding.get("victim") or "disk"
    target_pid = finding.get("target_pid") or "-"
    flow = f"{actor} (pid {actor_pid}) --> {target} (pid {target_pid})"
    conns = finding.get("network_connections") or finding.get("network") or []
    if conns:
        first = conns[0] if isinstance(conns[0], dict) else {}
        dest = first.get("destination") or first.get("endpoint") or "unknown"
        status = "FAIL" if first.get("succeeded") is False else "OK"
        extra = f" (+{len(conns) - 1})" if len(conns) > 1 else ""
        flow += f" --> {dest} {status}{extra}"
    return flow


def _api_chain(finding: dict[str, Any]) -> list[str]:
    lines: list[str] = []
    primitives = finding.get("primitives") or []
    if isinstance(primitives, list):
        for item in primitives:
            if isinstance(item, dict):
                kind = str(item.get("kind") or item.get("op") or "op")
                api = str(item.get("api") or "unknown")
                detail = str(item.get("detail") or item.get("protection") or "")
                lines.append(f"- **{kind}** `{api}` {detail}".rstrip())
    evidence = finding.get("evidence") or {}
    if not lines and isinstance(evidence, dict):
        apis = evidence.get("apis") or evidence.get("execution_evidence") or []
        for api in apis:
            lines.append(f"- `{api}`")
    return lines or ["- (no API chain recorded)"]


def _tags(finding: dict[str, Any]) -> list[str]:
    tags: list[str] = []
    evidence = finding.get("evidence") or {}
    if isinstance(evidence, dict):
        for key, value in evidence.items():
            if value is True:
                tags.append(f"{key}=true")
    if finding.get("section_mapping"):
        tags.append("section_mapping=true")
    if finding.get("cross_process"):
        tags.append("cross_process=true")
    return tags


def _network_section(finding: dict[str, Any]) -> list[str]:
    conns = finding.get("network_connections") or finding.get("network") or []
    if not conns:
        return []
    lines = ["", f"### Network connections ({len(conns)})", ""]
    lines.append("| # | Destination | Protocol | Port | Result | Source | Time |")
    lines.append("|---|-----------|----------|------|--------|--------|------|")
    for i, conn in enumerate(conns):
        if not isinstance(conn, dict):
            continue
        dest = conn.get("destination") or conn.get("endpoint") or conn.get("destination_ip") or "-"
        proto = conn.get("protocol") or "-"
        port = conn.get("destination_port") or "-"
        succeeded = conn.get("succeeded")
        result = "FAIL" if succeeded is False else "OK" if succeeded is True else "-"
        source = conn.get("source") or "-"
        ts = str(conn.get("timestamp") or "-")
        if len(ts) > 19:
            ts = ts[:19]
        lines.append(f"| {i + 1} | {dest} | {proto} | {port} | {result} | {source} | {ts} |")
    lines.append("")
    return lines


def finding_to_markdown(finding: dict[str, Any]) -> str:
    sev = str(finding.get("severity") or "INFO").upper()
    title = finding.get("title") or finding.get("technique") or "Finding"
    description = finding.get("description") or ""
    evidence = finding.get("evidence") or {}
    technique = finding.get("technique") or evidence.get("technique") or "-"
    confidence = finding.get("technique_confidence") or evidence.get("technique_confidence") or "-"

    lines = [
        f"## [{sev}] {title}",
        "",
    ]
    if description:
        lines.append(f"> {description}")
        lines.append("")

    lines.extend([
        f"- **Time:** {_fmt_time(finding.get('timestamp'))}",
        f"- **Flow:** {_finding_flow(finding)}",
        f"- **Score:** {finding.get('score', '-')}",
        f"- **Technique:** {technique}",
        f"- **Confidence:** {confidence}",
    ])

    payload = evidence.get("payload_kind")
    if payload:
        lines.append(f"- **Payload:** {payload}")

    exec_confirmed = evidence.get("execution_confirmed")
    if exec_confirmed is True:
        exec_evidence = evidence.get("execution_evidence") or []
        lines.append(f"- **Execution confirmed:** yes ({', '.join(exec_evidence)})")
    elif exec_confirmed is False:
        lines.append("- **Execution confirmed:** no")
        ctx = evidence.get("context_read_evidence")
        if ctx:
            lines.append(f"- **Context read APIs:** {', '.join(ctx)}")
        if evidence.get("missing_execution_transfer"):
            lines.append("- **Missing execution transfer:** yes")

    is_recursive = finding.get("is_recursive") or evidence.get("is_recursive")
    chain = finding.get("injection_chain") or evidence.get("injection_chain_pids")
    depth = finding.get("chain_depth") or evidence.get("chain_depth") or 0
    if is_recursive and chain:
        chain_str = " -> ".join(str(pid) for pid in chain)
        lines.append(f"- **Recursive chain:** {depth} hops: {chain_str}")

    tag_list = _tags(finding)
    if tag_list:
        lines.append(f"- **Tags:** {', '.join(f'`{tag}`' for tag in tag_list)}")

    actor_image = finding.get("actor_image") or evidence.get("actor_image") or "-"
    actor_pid = finding.get("actor_pid") or "-"
    target_image = finding.get("target_image") or evidence.get("target_image") or "-"
    target_pid = finding.get("target_pid") or "-"
    lines.extend([
        "",
        "### Process details",
        "",
        "| Role | Image | PID |",
        "|------|-------|-----|",
        f"| Loader (actor) | `{actor_image}` | {actor_pid} |",
        f"| Target (victim) | `{target_image}` | {target_pid} |",
    ])

    lines.extend(["", "### API chain", "", *_api_chain(finding)])
    lines.extend(_network_section(finding))
    lines.append("")
    return "\n".join(lines)


def session_report_markdown(
    *,
    session: str | None,
    findings: list[dict[str, Any]],
    groups: list[dict[str, Any]] | None = None,
) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    header = [
        "# Noirlycan telemetry report",
        "",
        f"- **Generated:** {stamp}",
        f"- **Session:** {session or 'active'}",
        f"- **Findings:** {len(findings)}",
        "",
    ]
    if not findings:
        header.append("_No findings in this export._")
        return "\n".join(header)

    body: list[str] = []
    if groups:
        for group in groups:
            body.append(f"## Group: {group.get('source')} --> {group.get('victim')}")
            body.append("")
            body.append(f"_{group.get('summary')}_")
            body.append("")
            for member in group.get("members") or []:
                finding = member.get("finding") if isinstance(member, dict) else None
                if isinstance(finding, dict):
                    body.append(finding_to_markdown(finding))
    else:
        for finding in findings:
            body.append(finding_to_markdown(finding))

    return "\n".join(header + body)
