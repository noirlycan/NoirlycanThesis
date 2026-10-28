"""Agent → console channel: lifecycle (hello / heartbeat / goodbye) and event ingest.

Every call must carry a registered agent's own enrollment token. Events are
appended to that agent's session log; the agent never chooses the file name.
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field

from noirlycan_backend.api.agent_auth import bearer_token
from noirlycan_backend.api.deps import get_database, get_logs_dir
from noirlycan_backend.infrastructure.live_hub import schedule_broadcast
from noirlycan_core.runtime.config import touch_collector_heartbeat
from noirlycan_core.storage.log_store import ensure_logs_dir

MAX_BATCH_EVENTS = 1000
MAX_EVENT_BYTES = 256 * 1024

router = APIRouter(prefix="/ingest", tags=["ingest"])


class IngestEvent(BaseModel):
    type: str = Field(min_length=1, max_length=64)
    value: dict[str, Any] = Field(default_factory=dict)


class IngestBatch(BaseModel):
    events: list[IngestEvent] = Field(max_length=MAX_BATCH_EVENTS)


class AgentHello(BaseModel):
    agent_id: str = Field(min_length=1, max_length=120)
    hostname: str = Field(default="", max_length=255)
    os_name: str = Field(default="Windows", max_length=64)
    mode: str = Field(default="run", max_length=16)
    watching: str = Field(default="", max_length=4096)
    ip_address: str = Field(default="", max_length=64)


def verify_agent_token(authorization: str | None, database, *, agent_id: str | None = None) -> None:
    if not agent_id or database.authenticate_agent(agent_id, bearer_token(authorization)) != "agent":
        raise HTTPException(status_code=401, detail="Invalid agent token")


def header_agent(
    authorization: str | None = Header(default=None),
    x_agent_id: str | None = Header(default=None, alias="X-Agent-Id"),
) -> str:
    agent_id = (x_agent_id or "").strip()
    verify_agent_token(authorization, get_database(), agent_id=agent_id)
    return agent_id


def _hello_agent(body: AgentHello, authorization: str | None = Header(default=None)) -> AgentHello:
    verify_agent_token(authorization, get_database(), agent_id=body.agent_id)
    return body


def _client_ip(request: Request, reported: str = "") -> str:
    if reported.strip():
        return reported.strip()
    host = str(request.client.host) if request.client else ""
    return host.removeprefix("::ffff:")


def _console_reply(agent_id: str) -> dict[str, Any]:
    database = get_database()
    return {"ok": True, "commands": database.pop_agent_commands(agent_id), **database.rules_payload_for_agent()}


def _append(agent_id: str, events: list[IngestEvent]) -> str:
    database = get_database()
    logs_dir = ensure_logs_dir(get_logs_dir())
    session_rel = database.ensure_agent_session(agent_id)
    lines = []
    for event in events:
        value = {**event.value, "agent_id": agent_id}
        line = json.dumps({"type": event.type, "value": value, "agent_id": agent_id}, ensure_ascii=False)
        if len(line) > MAX_EVENT_BYTES:
            continue  # Oversized events come from a hostile or broken agent; drop them.
        lines.append(line + "\n")
    if lines:
        with (logs_dir / session_rel).open("a", encoding="utf-8") as handle:
            handle.writelines(lines)
    touch_collector_heartbeat(logs_dir=logs_dir)
    return session_rel


@router.post("")
def ingest_event(body: IngestEvent, request: Request, agent_id: str = Depends(header_agent)) -> dict[str, Any]:
    return ingest_batch(IngestBatch(events=[body]), request, agent_id)


@router.post("/batch")
def ingest_batch(body: IngestBatch, request: Request, agent_id: str = Depends(header_agent)) -> dict[str, Any]:
    database = get_database()
    database.touch_agent_ip(agent_id, _client_ip(request))
    session = _append(agent_id, body.events)
    for event_type in sorted({event.type for event in body.events}):
        schedule_broadcast({"type": "event", "session": session, "event_type": event_type})
    return {"session": session, **_console_reply(agent_id)}


@router.post("/enrollment")
def resolve_enrollment(authorization: str | None = Header(default=None)) -> dict[str, str]:
    agent_id = get_database().resolve_enrollment_token(bearer_token(authorization))
    if agent_id is None:
        raise HTTPException(status_code=401, detail="Invalid agent token")
    return {"agent_id": agent_id}


@router.post("/hello")
def agent_hello(request: Request, body: AgentHello = Depends(_hello_agent)) -> dict[str, Any]:
    database = get_database()
    agent = database.upsert_agent(
        body.agent_id,
        hostname=body.hostname,
        os_name=body.os_name,
        mode=body.mode,
        watching=body.watching,
        ip_address=_client_ip(request, body.ip_address),
    )
    database.ensure_agent_session(body.agent_id)
    _touch_capture(body.watching)
    schedule_broadcast({"type": "agent", "agent_id": body.agent_id})
    return {"agent": agent, **_console_reply(body.agent_id)}


@router.post("/heartbeat")
def agent_heartbeat(request: Request, body: AgentHello = Depends(_hello_agent)) -> dict[str, Any]:
    get_database().touch_agent_ip(body.agent_id, _client_ip(request, body.ip_address))
    _touch_capture(body.watching)
    schedule_broadcast({"type": "agent", "agent_id": body.agent_id})
    return _console_reply(body.agent_id)


@router.post("/goodbye")
def agent_goodbye(body: AgentHello = Depends(_hello_agent)) -> dict[str, Any]:
    get_database().mark_agent_offline(body.agent_id)
    schedule_broadcast({"type": "agent", "agent_id": body.agent_id})
    return {"ok": True}


def _touch_capture(watching: str) -> None:
    paths = [item.strip() for item in watching.split(",") if item.strip()] or None
    touch_collector_heartbeat(logs_dir=ensure_logs_dir(get_logs_dir()), watch_paths=paths)
