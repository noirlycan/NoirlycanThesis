from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query

from noirlycan_backend.api.auth import get_current_user, require_permission
from noirlycan_backend.api.deps import get_database, get_logs_dir
from noirlycan_backend.domain.agent_sessions import resolve_console_session
from noirlycan_backend.domain.findings_groups import load_console_findings

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("")
def list_findings(
    session: str | None = Query(default=None),
    agent_id: str | None = Query(default=None),
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    database = get_database()
    removed = database.list_removed_findings()
    agents = database.list_agents()
    session_rel = resolve_console_session(database, session, agent_id)
    payload = load_console_findings(
        get_logs_dir(),
        session=session_rel,
        agent_id=agent_id,
        removed=removed,
        agents=agents,
    )
    payload["killed"] = database.list_killed()
    return payload


@router.delete("/{finding_key}")
def delete_finding(
    finding_key: str,
    user: dict[str, Any] = Depends(require_permission("del")),
) -> dict[str, Any]:
    database = get_database()
    database.remove_finding(finding_key, actor=user.get("email"))
    return {"ok": True, "removed": finding_key}
