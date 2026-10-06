"""Offline analysis over stored sessions: corpus statistics and re-correlation."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query

from noirlycan_backend.api.auth import get_current_user, require_permission
from noirlycan_backend.api.deps import get_logs_dir
from noirlycan_core.analysis.reclassify import reclassify_session
from noirlycan_core.analysis.session_analytics import analyze_corpus
from noirlycan_core.storage.analysis_db import AnalysisDatabase
from noirlycan_core.storage.log_store import resolve_log_path

router = APIRouter(prefix="/analysis", tags=["analysis"])


@router.get("/corpus")
def corpus(
    limit: int | None = Query(default=None, ge=1),
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    logs_dir = get_logs_dir()
    database = AnalysisDatabase(logs_dir)
    payload = analyze_corpus(logs_dir, limit=limit, database=database)
    payload["db_findings"] = database.aggregate_stored_findings()
    return payload


@router.post("/reclassify/{name}")
def reclassify(
    name: str,
    write: Literal["", "sidecar", "in_place"] = "",
    user: dict[str, Any] = Depends(require_permission("rules")),
) -> dict[str, Any]:
    """Replay a stored session through the current detector and classifier."""
    logs_dir = get_logs_dir()
    path = resolve_log_path(logs_dir, name)
    if path is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return reclassify_session(path, logs_dir=logs_dir, write=write or False)
