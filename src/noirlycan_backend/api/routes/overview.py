from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query

from noirlycan_backend.api.auth import get_current_user
from noirlycan_backend.api.deps import get_database, get_logs_dir
from noirlycan_backend.domain.agent_sessions import resolve_console_session
from noirlycan_backend.domain.findings_groups import overview_payload
from noirlycan_core.runtime.config import (
    is_collector_online,
    load_runtime_config,
)
from noirlycan_core.storage.infrastructure.log_store import list_log_files

router = APIRouter(prefix="/overview", tags=["overview"])


@router.get("")
def get_overview(
    session: str | None = Query(default=None),
    agent_id: str | None = Query(default=None),
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    database = get_database()
    logs_dir = get_logs_dir()
    removed = database.list_removed_findings()
    agents = database.list_agents()
    agent_sessions = database.list_agent_sessions()

    if agent_id:
        session_rel = resolve_console_session(database, session, agent_id)
        payload = overview_payload(
            logs_dir,
            session=session_rel,
            agent_id=agent_id,
            removed=removed,
        )
    else:
        payload = overview_payload(
            logs_dir,
            removed=removed,
            agent_sessions=agent_sessions,
            agents=agents,
        )
    runtime = load_runtime_config(logs_dir)
    payload["collector_online"] = is_collector_online(runtime)
    payload["sessions"] = [path.name for path in list_log_files(logs_dir)]
    payload["agent_sessions"] = agent_sessions
    payload["agents"] = agents
    payload["active_agent_id"] = agent_id or (
        str(payload["agents"][0]["id"]) if payload.get("agents") else None
    )
    payload["killed"] = database.list_killed()
    payload["permissions"] = database.load_role_permissions().get(user["role"], {})
    return payload
