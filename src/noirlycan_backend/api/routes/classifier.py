"""Technique classifier rules (the classification half of the paper's analysis module)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException

from noirlycan_backend.api.auth import get_current_user, require_permission
from noirlycan_backend.api.deps import get_logs_dir
from noirlycan_core.classification.config import (
    ConfigUpdateError,
    classifier_rules_payload,
    delete_custom_rule,
    load_classifier_config,
    save_classifier_config,
    update_classifier_config,
    upsert_custom_rule,
)

router = APIRouter(prefix="/classifier", tags=["classifier"])


def _payload(message: str | None = None) -> dict[str, Any]:
    payload = classifier_rules_payload(get_logs_dir())
    if message:
        payload.update(ok=True, message=message)
    return payload


@router.get("")
def get_classifier(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    return _payload()


@router.put("")
def update_classifier(
    body: dict[str, Any] = Body(default_factory=dict),
    user: dict[str, Any] = Depends(require_permission("rules")),
) -> dict[str, Any]:
    logs_dir = get_logs_dir()
    config = load_classifier_config(logs_dir)
    try:
        update_classifier_config(config, body)
    except ConfigUpdateError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    save_classifier_config(config, logs_dir)
    return _payload("Classifier rules saved. New findings use this config immediately.")


@router.get("/rules/{rule_id}")
def get_rule(rule_id: str, user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    rid = rule_id.strip().lower()
    payload = _payload()
    for source, key in (("builtin", "rules"), ("custom", "custom_rules")):
        for rule in payload.get(key) or []:
            if str(rule.get("id") or "").lower() == rid:
                return {"ok": True, "rule": rule, "source": source}
    raise HTTPException(status_code=404, detail="Rule not found")


@router.put("/custom/{rule_id}")
def save_custom_rule(
    rule_id: str,
    body: dict[str, Any] = Body(default_factory=dict),
    user: dict[str, Any] = Depends(require_permission("rules")),
) -> dict[str, Any]:
    logs_dir = get_logs_dir()
    config = load_classifier_config(logs_dir)
    try:
        rule = upsert_custom_rule(config, rule_id, body)
    except ConfigUpdateError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    save_classifier_config(config, logs_dir)
    return _payload(f"Saved custom rule {rule.id}.")


@router.delete("/custom/{rule_id}")
def remove_custom_rule(
    rule_id: str,
    user: dict[str, Any] = Depends(require_permission("rules")),
) -> dict[str, Any]:
    logs_dir = get_logs_dir()
    config = load_classifier_config(logs_dir)
    if not delete_custom_rule(config, rule_id):
        raise HTTPException(status_code=404, detail="Custom rule not found")
    save_classifier_config(config, logs_dir)
    return _payload(f"Deleted custom rule {rule_id.strip().lower()}.")
