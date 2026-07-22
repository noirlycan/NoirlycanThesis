from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from noirlycan_backend.api.auth import get_current_user, require_permission
from noirlycan_backend.api.deps import get_database, get_logs_dir
from noirlycan_backend.domain.findings_groups import load_console_findings
from noirlycan_backend.domain.reports import finding_to_markdown, session_report_markdown
from noirlycan_backend.infrastructure.live_hub import schedule_broadcast
from noirlycan_core.storage.infrastructure.log_store import ensure_logs_dir, new_session_log_path

router = APIRouter(prefix="/ingest", tags=["ingest"])


class IngestEvent(BaseModel):
    type: str
    value: dict[str, Any] = Field(default_factory=dict)
    session: str | None = None


class AgentHello(BaseModel):
    agent_id: str
    hostname: str
    os_name: str = "Windows"
    mode: str = "run"
    watching: str = ""
    ip_address: str = ""


def _resolve_agent_ip(request: Request, reported: str = "") -> str:
    ip = reported.strip()
    if ip:
        return ip
    if request.client and request.client.host:
        return request.client.host
    return ""


def verify_agent_token(authorization: str | None, database) -> None:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing agent token")
    token = authorization.split(" ", 1)[1].strip()
    if not database.verify_agent_token(token):
        raise HTTPException(status_code=401, detail="Invalid agent token")


def _append_event(session_path, payload: dict[str, Any]) -> None:
    with session_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, ensure_ascii=False) + "\n")


@router.post("")
def ingest_event(
    body: IngestEvent,
    authorization: str | None = Header(default=None),
    x_agent_id: str | None = Header(default=None, alias="X-Agent-Id"),
) -> dict[str, Any]:
    database = get_database()
    verify_agent_token(authorization, database)
    logs_dir = ensure_logs_dir(get_logs_dir())
    agent_id = (x_agent_id or "").strip()
    if agent_id:
        session_rel = database.ensure_agent_session(agent_id)
        session_path = logs_dir / session_rel
        session_name = session_rel
    else:
        session_name = body.session or "agent-live.jsonl"
        session_path = logs_dir / session_name
        if not session_path.exists():
            session_path = new_session_log_path(logs_dir)
            session_name = session_path.name
    payload = {"type": body.type, "value": body.value}
    if agent_id:
        payload["agent_id"] = agent_id
        if isinstance(payload["value"], dict):
            payload["value"]["agent_id"] = agent_id
    _append_event(session_path, payload)
    commands: list[dict[str, Any]] = []
    if agent_id:
        commands = database.pop_agent_commands(agent_id)
    schedule_broadcast(
        {
            "type": "event",
            "session": session_name,
            "event_type": body.type,
        }
    )
    rules_payload = database.rules_payload_for_agent()
    return {"ok": True, "session": session_name, "commands": commands, **rules_payload}


@router.post("/hello")
def agent_hello(
    body: AgentHello,
    request: Request,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    database = get_database()
    verify_agent_token(authorization, database)
    agent = database.upsert_agent(
        body.agent_id,
        hostname=body.hostname,
        os_name=body.os_name,
        mode=body.mode,
        watching=body.watching,
        ip_address=_resolve_agent_ip(request, body.ip_address),
    )
    database.ensure_agent_session(body.agent_id)
    schedule_broadcast({"type": "agent", "agent_id": body.agent_id})
    payload = database.rules_payload_for_agent()
    return {"ok": True, "agent": agent, **payload}
