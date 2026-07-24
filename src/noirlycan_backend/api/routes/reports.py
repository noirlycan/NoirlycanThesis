from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse

from noirlycan_backend.api.auth import require_permission
from noirlycan_backend.api.deps import get_database, get_logs_dir
from noirlycan_backend.domain.findings_groups import load_console_findings
from noirlycan_backend.domain.reports import finding_to_markdown, session_report_markdown

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/findings.md")
def export_all_findings(
    session: str | None = Query(default=None),
    user: dict[str, Any] = Depends(require_permission("report")),
) -> PlainTextResponse:
    database = get_database()
    removed = database.list_removed_findings()
    bundle = load_console_findings(get_logs_dir(), session=session, removed=removed)
    findings = [
        f
        for f in bundle.get("findings") or []
        if str(f.get("timestamp") or f.get("id") or "") not in removed
    ]
    content = session_report_markdown(
        session=bundle.get("session"),
        findings=findings,
        groups=bundle.get("groups"),
    )
    return PlainTextResponse(content, media_type="text/markdown")


@router.get("/finding/{finding_key}.md")
def export_one_finding(
    finding_key: str,
    session: str | None = Query(default=None),
    user: dict[str, Any] = Depends(require_permission("report")),
) -> PlainTextResponse:
    database = get_database()
    bundle = load_console_findings(get_logs_dir(), session=session, removed=set())
    for finding in bundle.get("findings") or []:
        key = str(finding.get("timestamp") or finding.get("id") or "")
        if key == finding_key:
            return PlainTextResponse(finding_to_markdown(finding), media_type="text/markdown")
    raise HTTPException(status_code=404, detail="Finding not found")
