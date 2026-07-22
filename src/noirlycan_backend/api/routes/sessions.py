from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse

from noirlycan_backend.api.auth import get_current_user, require_permission
from noirlycan_backend.api.deps import get_logs_dir
from noirlycan_core.storage.infrastructure.log_store import (
    aggregate_logs,
    resolve_log_path,
    session_detail,
)

router = APIRouter(prefix="/sessions", tags=["sessions"])


@router.get("")
def list_sessions(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    payload = aggregate_logs(get_logs_dir())
    return {"sessions": payload.get("files") or [], "active": payload.get("active_log")}


@router.get("/{name}")
def get_session(
    name: str,
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    detail = session_detail(name, get_logs_dir())
    if detail is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return detail


@router.get("/{name}/export")
def export_session(
    name: str,
    user: dict[str, Any] = Depends(require_permission("export")),
) -> FileResponse:
    path = resolve_log_path(get_logs_dir(), name)
    if path is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return FileResponse(path, media_type="application/x-ndjson", filename=path.name)
