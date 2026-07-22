from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from noirlycan_backend.api.auth import require_permission
from noirlycan_backend.api.deps import get_database, get_logs_dir
from noirlycan_backend.domain.ruleset import Ruleset, ruleset_to_toml

router = APIRouter(prefix="/rules", tags=["rules"])


class RulesetBody(BaseModel):
    rules: dict[str, Any] = Field(default_factory=dict)


@router.get("")
def get_rules(user: dict[str, Any] = Depends(require_permission("rules"))) -> dict[str, Any]:
    database = get_database()
    ruleset = database.load_ruleset()
    return {"rules": ruleset.to_dict(), "saved": True}


@router.put("")
def save_rules(
    body: RulesetBody,
    user: dict[str, Any] = Depends(require_permission("rules")),
) -> dict[str, Any]:
    database = get_database()
    ruleset = Ruleset.from_dict(body.rules)
    database.save_ruleset(ruleset)
    return {"ok": True, "rules": ruleset.to_dict(), "saved": True}


@router.post("/reset")
def reset_rules(user: dict[str, Any] = Depends(require_permission("rules"))) -> dict[str, Any]:
    database = get_database()
    ruleset = Ruleset()
    database.save_ruleset(ruleset)
    return {"ok": True, "rules": ruleset.to_dict(), "saved": True}


@router.get("/export.toml")
def export_toml(user: dict[str, Any] = Depends(require_permission("rules"))) -> PlainTextResponse:
    database = get_database()
    ruleset = database.load_ruleset()
    server = database.load_server_config()
    content = ruleset_to_toml(
        ruleset,
        host=str(server["host"]),
        port=int(server["port"]),
        token=str(server["token"]),
    )
    return PlainTextResponse(content, media_type="text/plain")
