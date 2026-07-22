from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from noirlycan_backend.api.auth import require_permission
from noirlycan_backend.api.deps import get_database
from noirlycan_backend.domain.file_drop_removal import remove_file_drop_from_history

router = APIRouter(prefix="/file-drops", tags=["file-drops"])


class RemoveFileDropBody(BaseModel):
    path: str = Field(default="")
    key: str = Field(default="")


@router.post("/remove")
def remove_file_drop(
    body: RemoveFileDropBody,
    user: dict[str, Any] = Depends(require_permission("del")),
) -> dict[str, Any]:
    database = get_database()
    return remove_file_drop_from_history(
        database,
        path=body.path,
        key=body.key,
        actor=user.get("email"),
    )


@router.delete("")
@router.delete("/")
def delete_file_drop(
    path: str = Query(default=""),
    key: str = Query(default=""),
    user: dict[str, Any] = Depends(require_permission("del")),
) -> dict[str, Any]:
    database = get_database()
    return remove_file_drop_from_history(
        database,
        path=path,
        key=key,
        actor=user.get("email"),
    )
