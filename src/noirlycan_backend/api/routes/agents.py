from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Response, UploadFile
from fastapi.responses import FileResponse, PlainTextResponse
from starlette.concurrency import run_in_threadpool
from pydantic import BaseModel, Field

from noirlycan_backend.api.auth import require_admin, require_permission
from noirlycan_backend.api.deps import get_database
from noirlycan_backend.api.routes.ingest import verify_agent_token
from noirlycan_backend.api.agent_auth import require_agent
from noirlycan_backend.infrastructure.live_hub import schedule_broadcast
from noirlycan_backend.domain.agent_deploy import (
    ARCHIVE_NAME,
    DESKTOP_EXE_NAME,
    DESKTOP_SETUP_NAME,
    agent_config_toml,
    bootstrap_script,
    build_agent_archive,
    install_command,
    desktop_executable_path,
    agent_download_path,
    agent_publication_path,
    validate_agent_release,
)
from noirlycan_core.storage.analysis_db import sha256_file
from noirlycan_core.storage.log_store import find_project_root

router = APIRouter(prefix="/agents", tags=["agents"])
MAX_AGENT_RELEASE_BYTES = 256 * 1024 * 1024


class ServerConfigBody(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8765


class KillRequest(BaseModel):
    pid: int = Field(ge=1)
    image: str | None = None
    extra_pid: int | None = Field(default=None, ge=1)


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
    agents = database.list_agents()
    for agent in agents:
        agent["run_command"] = _agent_run_command(server, agent)
        agent["install_command"] = install_command(server, agent)
        agent["config_toml"] = agent_config_toml(server, agent, command_key=database.signer.public_key)
    return {
        "server": server,
        "agents": agents,
        "auto_kill_min_severity": database.load_ruleset().auto_kill_min_severity,
        "desktop_available": desktop_executable_path().is_file(),
        "installer_available": agent_download_path("installer").is_file(),
        "can_publish_release": user.get("role") == "Admin",
    }


@router.get("/desktop.exe")
def download_desktop_agent(
    user: dict[str, Any] = Depends(require_permission("access")),
) -> FileResponse:
    path = desktop_executable_path()
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Desktop Agent EXE has not been built or placed on this server")
    return FileResponse(path, filename=DESKTOP_EXE_NAME, media_type="application/octet-stream",
                        headers={"Cache-Control": "no-store"})


@router.get("/setup.exe")
def download_agent_installer(
    user: dict[str, Any] = Depends(require_permission("access")),
) -> FileResponse:
    path = agent_download_path("installer")
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Windows Agent installer is not available yet")
    return FileResponse(path, filename=DESKTOP_SETUP_NAME, media_type="application/octet-stream",
                        headers={"Cache-Control": "no-store"})


@router.post("/desktop/releases/{kind}")
async def publish_desktop_release(
    kind: Literal["portable", "installer"],
    file: UploadFile,
    user: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    destination = agent_publication_path(kind)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    size = 0
    try:
        with tempfile.NamedTemporaryFile(dir=destination.parent, suffix=".upload", delete=False) as handle:
            temporary = Path(handle.name)
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_AGENT_RELEASE_BYTES:
                    raise HTTPException(status_code=413, detail="Agent release exceeds 256 MiB")
                handle.write(chunk)
        try:
            await run_in_threadpool(validate_agent_release, temporary, kind)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        digest = await run_in_threadpool(sha256_file, temporary)
        os.replace(temporary, destination)
        get_database().audit(user.get("email"), "agent.release.publish",
                             {"kind": kind, "sha256": digest, "size_bytes": size})
        return {"ok": True, "filename": destination.name, "sha256": digest, "size_bytes": size}
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        await file.close()


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
    agent["config_toml"] = agent_config_toml(server, agent, command_key=database.signer.public_key)
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
    pids = [body.pid]
    if body.extra_pid and body.extra_pid != body.pid:
        database.record_kill(
            agent_id=agent_id,
            pid=body.extra_pid,
            image=None,
            actor=user.get("email"),
        )
        pids.append(body.extra_pid)
    message = (
        f"Kill queued → {body.image or 'process'} (PID {body.pid}); waiting for the agent to confirm"
        if len(pids) == 1
        else f"Kill queued → PID {' and '.join(str(p) for p in pids)}; waiting for the agent to confirm"
    )
    return {
        "ok": True,
        "message": message,
        "agent_id": agent_id,
        "pid": body.pid,
        "pids": pids,
    }


# -- one-line install for the VM (agent-token authenticated) ---------------


def _agent_row(database, agent_id: str) -> dict[str, Any]:
    agent = next((item for item in database.list_agents() if item["id"] == agent_id), None)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent


@router.get("/{agent_id}/bootstrap.ps1")
def agent_bootstrap(agent_id: str = Depends(require_agent)) -> PlainTextResponse:
    database = get_database()
    script = bootstrap_script(
        database.load_server_config(),
        _agent_row(database, agent_id),
        command_key=database.signer.public_key,
    )
    return PlainTextResponse(script, media_type="text/plain; charset=utf-8")


@router.get("/{agent_id}/package.zip")
def agent_package(agent_id: str = Depends(require_agent)) -> Response:
    return Response(
        build_agent_archive(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{ARCHIVE_NAME}"'},
    )


@router.get("/{agent_id}/sysmon-config.xml")
def agent_sysmon_config(agent_id: str = Depends(require_agent)) -> Response:
    path = find_project_root() / "configs" / "sysmon-noirlycan.xml"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Sysmon config not found on console host")
    return Response(path.read_bytes(), media_type="application/xml")


class CommandResult(BaseModel):
    ok: bool
    detail: str | None = Field(default=None, max_length=300)


@router.post("/{agent_id}/commands/{command_id}/result")
def command_result(
    command_id: int,
    body: CommandResult,
    agent_id: str = Depends(require_agent),
) -> dict[str, Any]:
    """The agent reports how a command ended; a kill shows TERMINATED only after ``ok``."""
    updated = get_database().record_command_result(agent_id, command_id, ok=body.ok, detail=body.detail)
    schedule_broadcast({"type": "kill", "agent_id": agent_id, "command_id": command_id, "ok": body.ok})
    return {"ok": True, "updated": updated}
