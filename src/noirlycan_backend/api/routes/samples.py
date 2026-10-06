"""Sample intake: analysts upload samples, the backend sends them to a lab agent.

Flow
  analyst  POST /api/samples                    store sample (content-addressed)
  analyst  POST /api/samples/{id}/run           queue a ``sample.run`` command for one agent
  agent    GET  /api/agents/{agent}/samples/{id} download (only if that command was issued to it)
  agent    POST /api/agents/{agent}/samples/{id}/status   spawned / failed + agent-side path
  analyst  GET  /api/samples/{id}/report        findings parsed from the agent's session

Uploaded ``.jsonl`` files are session logs from another run; they are parsed
into the analysis database instead of being executed.
"""

from __future__ import annotations

import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from noirlycan_backend.api.agent_auth import require_agent
from noirlycan_backend.api.auth import get_current_user, require_permission
from noirlycan_backend.api.deps import get_database, get_logs_dir
from noirlycan_core.storage.analysis_db import AnalysisDatabase, sha256_file, uploads_dir
from noirlycan_core.storage.upload_finalize import build_upload_report

MAX_UPLOAD_BYTES = 64 * 1024 * 1024
SAMPLE_SUFFIXES = {".exe", ".dll"}
SESSION_SUFFIX = ".jsonl"
ACTIVE_STATUSES = {"queued", "spawned", "running"}

router = APIRouter(tags=["samples"])


class RunRequest(BaseModel):
    agent_id: str
    target_pid: int | None = Field(default=None, ge=1)


class AgentStatus(BaseModel):
    status: str = Field(pattern="^(spawned|failed)$")
    agent_path: str | None = None
    error: str | None = None


def _analysis_db() -> AnalysisDatabase:
    return AnalysisDatabase(get_logs_dir())


def _safe_name(name: str) -> str:
    cleaned = re.sub(r"[^\w.\-]+", "_", Path(name).name).strip("._")
    return cleaned or "sample"


def _get_upload(upload_id: int) -> dict[str, Any]:
    upload = _analysis_db().get_upload(upload_id)
    if upload is None:
        raise HTTPException(status_code=404, detail="Sample not found")
    return upload


async def _store(file: UploadFile, destination: Path) -> int:
    size = 0
    with destination.open("wb") as handle:
        while chunk := await file.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_UPLOAD_BYTES:
                handle.close()
                destination.unlink(missing_ok=True)
                raise HTTPException(status_code=413, detail="File exceeds 64 MiB upload limit")
            handle.write(chunk)
    return size


# -- analyst endpoints ------------------------------------------------------


@router.get("/samples")
def list_samples(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    database = _analysis_db()
    return {"samples": database.list_uploads(limit=200), "parsed_sessions": database.list_parsed_sessions(limit=100)}


@router.post("/samples")
async def upload_sample(
    file: UploadFile,
    user: dict[str, Any] = Depends(require_permission("triage")),
) -> dict[str, Any]:
    original_name = Path(file.filename or "").name
    suffix = Path(original_name).suffix.lower()
    if suffix not in SAMPLE_SUFFIXES | {SESSION_SUFFIX}:
        raise HTTPException(status_code=400, detail="Supported uploads: .exe / .dll samples, .jsonl session logs")

    logs_dir = get_logs_dir()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    destination = uploads_dir(logs_dir) / f"{stamp}-{_safe_name(original_name)}"
    size = await _store(file, destination)
    digest = sha256_file(destination)
    database = _analysis_db()
    console = get_database()

    if suffix == SESSION_SUFFIX:
        session_name = f"upload-{stamp}.jsonl"
        session_path = logs_dir / session_name
        shutil.copy2(destination, session_path)
        upload_id = database.record_upload(
            original_name=original_name,
            stored_path=str(destination.resolve()),
            content_kind="jsonl",
            size_bytes=size,
            sha256=digest,
            status="parsing",
        )
        try:
            parsed = database.ingest_jsonl(session_path, upload_id=upload_id, session_name=session_name)
        except Exception as exc:  # noqa: BLE001 - malformed user file, report and keep the record
            database.update_upload(upload_id, status="failed", error_message=str(exc))
            raise HTTPException(status_code=422, detail=f"Parse failed: {exc}") from exc
        database.update_upload(upload_id, status="parsed", session_name=session_name)
        console.audit(user.get("email"), "session.import", {"upload_id": upload_id, "sha256": digest})
        return {"ok": True, "kind": "jsonl", "upload_id": upload_id, "session_name": session_name, "parsed": parsed}

    upload_id = database.record_upload(
        original_name=original_name,
        stored_path=str(destination.resolve()),
        content_kind="executable",
        size_bytes=size,
        sha256=digest,
        status="uploaded",
    )
    console.audit(user.get("email"), "sample.upload", {"upload_id": upload_id, "sha256": digest, "name": original_name})
    return {"ok": True, "kind": "executable", "upload_id": upload_id, "sha256": digest}


@router.post("/samples/{upload_id}/run")
def run_sample(
    upload_id: int,
    body: RunRequest,
    user: dict[str, Any] = Depends(require_permission("triage")),
) -> dict[str, Any]:
    upload = _get_upload(upload_id)
    if upload["content_kind"] != "executable":
        raise HTTPException(status_code=400, detail="Only executable samples can be run")
    if upload["status"] in ACTIVE_STATUSES:
        raise HTTPException(status_code=409, detail=f"Sample is already {upload['status']}")
    if not Path(upload["stored_path"]).is_file():
        raise HTTPException(status_code=404, detail="Stored sample file is missing")
    console = get_database()
    if not console.agent_exists(body.agent_id):
        raise HTTPException(status_code=404, detail="Agent not found")

    argv = [str(body.target_pid)] if body.target_pid else []
    console.enqueue_agent_command(
        body.agent_id,
        "sample.run",
        {
            "upload_id": upload_id,
            "sha256": upload["sha256"],
            "filename": _safe_name(upload["original_name"]),
            "argv": argv,
        },
    )
    _analysis_db().update_upload(upload_id, status="queued", agent_id=body.agent_id)
    console.audit(user.get("email"), "sample.run", {"upload_id": upload_id, "agent_id": body.agent_id, "argv": argv})
    return {"ok": True, "upload_id": upload_id, "agent_id": body.agent_id, "argv": argv}


@router.delete("/samples/{upload_id}")
def delete_sample(
    upload_id: int,
    user: dict[str, Any] = Depends(require_permission("del")),
) -> dict[str, Any]:
    _get_upload(upload_id)
    if not _analysis_db().delete_upload(upload_id):
        raise HTTPException(status_code=500, detail="Could not delete sample")
    get_database().audit(user.get("email"), "sample.delete", {"upload_id": upload_id})
    return {"ok": True, "upload_id": upload_id}


@router.get("/samples/{upload_id}/report")
def sample_report(upload_id: int, user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    upload = _get_upload(upload_id)
    report = build_upload_report(upload_id, get_logs_dir())
    upload = _analysis_db().get_upload(upload_id) or upload
    if report is None:
        if upload["status"] in ACTIVE_STATUSES:
            return {"ok": False, "pending": True, "upload": upload}
        raise HTTPException(status_code=404, detail="No report for this sample yet")
    return {"ok": True, "upload": upload, "report": report, "live_snapshot": upload["status"] in ACTIVE_STATUSES}


# -- agent endpoints --------------------------------------------------------


@router.get("/agents/{agent_id}/samples/{upload_id}")
def download_sample(upload_id: int, agent_id: str = Depends(require_agent)) -> FileResponse:
    if not get_database().agent_was_sent_sample(agent_id, upload_id):
        raise HTTPException(status_code=403, detail="Sample was not assigned to this agent")
    upload = _get_upload(upload_id)
    path = Path(upload["stored_path"])
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Stored sample file is missing")
    return FileResponse(path, media_type="application/octet-stream", headers={"X-Sample-Sha256": upload["sha256"]})


@router.post("/agents/{agent_id}/samples/{upload_id}/status")
def report_sample_status(
    upload_id: int,
    body: AgentStatus,
    agent_id: str = Depends(require_agent),
) -> dict[str, Any]:
    console = get_database()
    if not console.agent_was_sent_sample(agent_id, upload_id):
        raise HTTPException(status_code=403, detail="Sample was not assigned to this agent")
    _get_upload(upload_id)
    # The session is always resolved server-side; agent input never becomes a path here.
    session = console.ensure_agent_session(agent_id)
    _analysis_db().update_upload(
        upload_id,
        status=body.status,
        error_message=(body.error or "")[:500] or None,
        session_name=session,
        agent_path=(body.agent_path or "")[:1024] or None,
    )
    return {"ok": True}
