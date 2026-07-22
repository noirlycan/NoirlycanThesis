from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from noirlycan_backend.api.auth import require_permission
from noirlycan_backend.api.deps import get_database, get_logs_dir
from noirlycan_backend.domain.ruleset import Ruleset, ruleset_to_toml
from noirlycan_core.analysis.domain.classifier_config import load_classifier_config
from noirlycan_core.runtime.agent_policy import load_agent_policy

router = APIRouter(prefix="/rules", tags=["rules"])


class RulesetBody(BaseModel):
    rules: dict[str, Any] = Field(default_factory=dict)


def _effective_correlation_rules(ruleset: Ruleset, logs_dir) -> dict[str, Any]:
    """Return ruleset fields aligned with the active correlator policy on disk."""
    payload = ruleset.to_dict()
    policy = load_agent_policy(logs_dir)
    if policy is not None:
        payload["min_primitives"] = policy.min_primitives
        payload["congruence"] = policy.congruence
        payload["temporal"] = policy.temporal
        return payload
    config = load_classifier_config(logs_dir)
    payload["min_primitives"] = config.minimum_operational_kinds
    return payload


@router.get("")
def get_rules(user: dict[str, Any] = Depends(require_permission("rules"))) -> dict[str, Any]:
    database = get_database()
    logs_dir = get_logs_dir()
    ruleset = database.load_ruleset()
    return {
        "rules": _effective_correlation_rules(ruleset, logs_dir),
        "saved": True,
        "version": database.active_ruleset_version(),
    }


@router.put("")
def save_rules(
    body: RulesetBody,
    user: dict[str, Any] = Depends(require_permission("rules")),
) -> dict[str, Any]:
    database = get_database()
    logs_dir = get_logs_dir()
    ruleset = Ruleset.from_dict(body.rules)
    database.save_ruleset(ruleset)
    return {
        "ok": True,
        "rules": _effective_correlation_rules(ruleset, logs_dir),
        "saved": True,
        "version": database.active_ruleset_version(),
    }


@router.post("/reset")
def reset_rules(user: dict[str, Any] = Depends(require_permission("rules"))) -> dict[str, Any]:
    database = get_database()
    logs_dir = get_logs_dir()
    ruleset = Ruleset()
    database.save_ruleset(ruleset)
    return {
        "ok": True,
        "rules": _effective_correlation_rules(ruleset, logs_dir),
        "saved": True,
        "version": database.active_ruleset_version(),
    }


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
