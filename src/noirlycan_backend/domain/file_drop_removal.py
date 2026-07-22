from __future__ import annotations

from typing import Any

from fastapi import HTTPException

from noirlycan_backend.domain.findings_groups import file_drop_key
from noirlycan_backend.infrastructure.console_db import ConsoleDatabase
from noirlycan_backend.infrastructure.live_hub import schedule_broadcast


def remove_file_drop_from_history(
    database: ConsoleDatabase,
    *,
    path: str = "",
    key: str = "",
    actor: str | None = None,
) -> dict[str, Any]:
    drop_key = file_drop_key(key or path)
    if not drop_key:
        raise HTTPException(status_code=400, detail="Invalid file path")
    database.remove_file_drop(drop_key, actor=actor)
    schedule_broadcast({"type": "refresh", "reason": "file_drop_removed"})
    return {"ok": True, "removed": drop_key, "path": path or key}
