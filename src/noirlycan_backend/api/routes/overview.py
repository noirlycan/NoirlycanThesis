from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query

from noirlycan_backend.api.auth import get_current_user
from noirlycan_backend.api.deps import get_database, get_logs_dir
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
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    database = get_database()
    logs_dir = get_logs_dir()
    removed = database.list_removed_findings()
    payload = overview_payload(logs_dir, session=session, removed=removed)
    runtime = load_runtime_config(logs_dir)
    payload["collector_online"] = is_collector_online(runtime)
    payload["sessions"] = [path.name for path in list_log_files(logs_dir)]
    payload["killed"] = database.list_killed()
    payload["permissions"] = database.load_role_permissions().get(user["role"], {})
    return payload
