from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from noirlycan_backend.api.auth import get_current_user, require_permission
from noirlycan_backend.api.deps import get_database, get_logs_dir
from noirlycan_backend.api.routes.ingest import verify_agent_token
from noirlycan_backend.domain.findings_groups import load_console_findings
from noirlycan_backend.domain.reports import finding_to_markdown, session_report_markdown
from noirlycan_backend.domain.ruleset import ruleset_to_toml

router = APIRouter(prefix="/agents", tags=["agents"])


class ServerConfigBody(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8765


class KillRequest(BaseModel):
    pid: int = Field(ge=1)
    image: str | None = None


class AutoKillBody(BaseModel):
    enabled: bool


class AutoKillPolicyBody(BaseModel):
    min_severity: str = "CRITICAL"


@router.get("")
def list_agents(user: dict[str, Any] = Depends(require_permission("access"))) -> dict[str, Any]:
    database = get_database()
    server = database.load_server_config()
    ruleset = database.load_ruleset()
    endpoint = f"{server['host']}:{server['port']}"
    token = server["token"]
    run_cmd = (
        f"noirlycan-telemetry run --server {endpoint} --token {token} "
        "--watch-sysmon --auto-attach-new-processes"
    )
    spawn_cmd = (
        f"noirlycan-telemetry spawn --server {endpoint} --token {token} "
        "--watch-sysmon -- C:\\Lab\\loader.exe"
    )
    toml = ruleset_to_toml(ruleset, host=str(server["host"]), port=int(server["port"]), token=str(token))
    return {
        "server": server,
        "agents": database.list_agents(),
        "commands": {"run": run_cmd, "spawn": spawn_cmd},
        "toml": toml,
        "auto_kill_min_severity": ruleset.auto_kill_min_severity,
    }


@router.put("/server")
def save_server(
    body: ServerConfigBody,
    user: dict[str, Any] = Depends(require_permission("access")),
) -> dict[str, Any]:
    database = get_database()
    payload = database.save_server_config(host=body.host, port=body.port)
    return {"ok": True, "server": payload}


@router.post("/server/regenerate-token")
def regenerate_token(user: dict[str, Any] = Depends(require_permission("access"))) -> dict[str, Any]:
    database = get_database()
    token = database.regenerate_token()
    return {"ok": True, "token": token}


@router.put("/policy/auto-kill")
def save_auto_kill_policy(
    body: AutoKillPolicyBody,
    user: dict[str, Any] = Depends(require_permission("access")),
) -> dict[str, Any]:
    database = get_database()
    ruleset = database.load_ruleset()
    ruleset.auto_kill_min_severity = body.min_severity.upper()
    database.save_ruleset(ruleset)
    return {"ok": True, "auto_kill_min_severity": ruleset.auto_kill_min_severity}


@router.post("/{agent_id}/auto-kill")
def set_auto_kill(
    agent_id: str,
    body: AutoKillBody,
    user: dict[str, Any] = Depends(require_permission("access")),
) -> dict[str, Any]:
    database = get_database()
    if not database.set_agent_auto_kill(agent_id, body.enabled):
        raise HTTPException(status_code=404, detail="Agent not found")
    return {"ok": True, "agent_id": agent_id, "auto_kill": body.enabled}


@router.get("/{agent_id}/commands")
def agent_commands(
    agent_id: str,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    database = get_database()
    verify_agent_token(authorization, database)
    return {"commands": database.pop_agent_commands(agent_id)}


@router.post("/{agent_id}/kill")
def kill_process(
    agent_id: str,
    body: KillRequest,
    user: dict[str, Any] = Depends(require_permission("kill")),
) -> dict[str, Any]:
    database = get_database()
    database.record_kill(
        agent_id=agent_id,
        pid=body.pid,
        image=body.image,
        actor=user.get("email"),
    )
    return {
        "ok": True,
        "message": f"Kill command sent → {body.image or 'process'} (PID {body.pid}) on workstation",
        "agent_id": agent_id,
        "pid": body.pid,
    }
