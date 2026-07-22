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
    return f"{actor} {actor_pid} ──▶ {target} {target_pid}"


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


def finding_to_markdown(finding: dict[str, Any]) -> str:
    sev = str(finding.get("severity") or "INFO").upper()
    title = finding.get("title") or finding.get("technique") or "Finding"
    lines = [
        f"## [{sev}] {title}",
        "",
        f"- **Time:** {_fmt_time(finding.get('timestamp'))}",
        f"- **Flow:** {_finding_flow(finding)}",
        f"- **Score:** {finding.get('score', '-')}",
        f"- **Technique:** {finding.get('technique') or '-'}",
    ]
    tag_list = _tags(finding)
    if tag_list:
        lines.append(f"- **Tags:** {', '.join(f'`{tag}`' for tag in tag_list)}")
    lines.extend(["", "### API chain", "", *_api_chain(finding), ""])
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
            body.append(f"## Group: {group.get('source')} ──▶ {group.get('victim')}")
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
