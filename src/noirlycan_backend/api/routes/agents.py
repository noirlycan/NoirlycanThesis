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
from noirlycan_backend.domain.agent_deploy import agent_config_toml
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


class AgentRenameBody(BaseModel):
    display_name: str = Field(min_length=1, max_length=120)


class AgentRegisterBody(BaseModel):
    agent_id: str = Field(min_length=1, max_length=120)
    display_name: str = Field(default="", max_length=120)


def _agent_run_command(server: dict[str, Any], agent: dict[str, Any]) -> str:
    endpoint = f"{server['host']}:{server['port']}"
    token = str(agent.get("enrollment_token") or "")
    agent_id = str(agent.get("id") or "")
    return (
        f"noirlycan-agent run --server {endpoint} --agent-id {agent_id} --token {token} "
        "--watch-sysmon --auto-attach-new-processes"
    )


@router.get("")
def list_agents(user: dict[str, Any] = Depends(require_permission("access"))) -> dict[str, Any]:
    database = get_database()
    server = database.load_server_config()
    ruleset = database.load_ruleset()
    endpoint = f"{server['host']}:{server['port']}"
    agents = database.list_agents()
    for agent in agents:
        agent["run_command"] = _agent_run_command(server, agent)
        agent["config_toml"] = agent_config_toml(server, agent)
    legacy_token = server["token"]
    run_cmd = (
        f"noirlycan-telemetry run --server {endpoint} --token {legacy_token} "
        "--watch-sysmon --auto-attach-new-processes"
    )
    spawn_cmd = (
        f"noirlycan-telemetry spawn --server {endpoint} --token {legacy_token} "
        "--watch-sysmon -- C:\\Lab\\loader.exe"
    )
    toml = ruleset_to_toml(
        ruleset,
        host=str(server["host"]),
        port=int(server["port"]),
        token=str(legacy_token),
    )
    return {
        "server": server,
        "agents": agents,
        "commands": {"run": run_cmd, "spawn": spawn_cmd},
        "toml": toml,
        "auto_kill_min_severity": ruleset.auto_kill_min_severity,
    }


@router.post("/register")
def register_agent(
    body: AgentRegisterBody,
    user: dict[str, Any] = Depends(require_permission("access")),
) -> dict[str, Any]:
    database = get_database()
    try:
        agent = database.create_agent_enrollment(
            body.agent_id,
            display_name=body.display_name,
            actor=user.get("email"),
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    server = database.load_server_config()
    agent["run_command"] = _agent_run_command(server, agent)
    agent["config_toml"] = agent_config_toml(server, agent)
    return {"ok": True, "agent": agent}


@router.post("/{agent_id}/regenerate-token")
def regenerate_agent_enrollment_token(
    agent_id: str,
    user: dict[str, Any] = Depends(require_permission("access")),
) -> dict[str, Any]:
    database = get_database()
    token = database.regenerate_agent_token(agent_id, actor=user.get("email"))
    if token is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    server = database.load_server_config()
    agent = next((item for item in database.list_agents() if item["id"] == agent_id), None)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    agent["run_command"] = _agent_run_command(server, agent)
    return {"ok": True, "agent_id": agent_id, "token": token, "agent": agent}


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


@router.patch("/{agent_id}")
def rename_agent(
    agent_id: str,
    body: AgentRenameBody,
    user: dict[str, Any] = Depends(require_permission("access")),
) -> dict[str, Any]:
    database = get_database()
    if not database.rename_agent(agent_id, body.display_name, actor=user.get("email")):
        raise HTTPException(status_code=404, detail="Agent not found")
    return {"ok": True, "agent_id": agent_id, "display_name": body.display_name.strip()}


@router.delete("/{agent_id}")
def delete_agent(
    agent_id: str,
    user: dict[str, Any] = Depends(require_permission("access")),
) -> dict[str, Any]:
    database = get_database()
    if not database.delete_agent(agent_id, actor=user.get("email")):
        raise HTTPException(status_code=404, detail="Agent not found")
    return {"ok": True, "agent_id": agent_id}


@router.get("/{agent_id}/commands")
def agent_commands(
    agent_id: str,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    database = get_database()
    verify_agent_token(authorization, database, agent_id=agent_id)
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
