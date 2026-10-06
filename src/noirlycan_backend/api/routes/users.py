from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

from noirlycan_backend.api.auth import get_current_user, require_admin, require_permission
from noirlycan_backend.api.deps import get_database
from noirlycan_backend.domain.email import normalize_lab_email
from noirlycan_backend.domain.permissions import ROLES, role_permissions_payload

router = APIRouter(prefix="/users", tags=["users"])


class ProfileBody(BaseModel):
    display_name: str | None = None
    current_password: str | None = None
    new_password: str | None = None


class MemberBody(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    email: str = Field(min_length=3)
    role: str = "Viewer"
    password: str = Field(min_length=4, max_length=128)

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        return normalize_lab_email(value)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        cleaned = str(value or "").strip()
        if not cleaned:
            raise ValueError("Display name is required")
        return cleaned


class RoleUpdateBody(BaseModel):
    role: str


class PermissionMatrixBody(BaseModel):
    matrix: dict[str, dict[str, bool]]


@router.get("/profile")
def get_profile(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    return {"user": user}


@router.put("/profile")
def update_profile(
    body: ProfileBody,
    user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    database = get_database()
    updated = database.update_profile(
        str(user["email"]),
        display_name=body.display_name,
        new_password=body.new_password,
        current_password=body.current_password,
    )
    if updated is None:
        raise HTTPException(status_code=400, detail="Profile update failed")
    return {"ok": True, "user": updated}


@router.get("/team")
def list_team(user: dict[str, Any] = Depends(require_permission("access"))) -> dict[str, Any]:
    database = get_database()
    return {"team": database.list_team()}


@router.post("/team")
def add_member(
    body: MemberBody,
    user: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    if body.role not in ROLES:
        raise HTTPException(status_code=400, detail=f"Invalid role: {body.role}")
    database = get_database()
    try:
        member = database.add_team_member(
            name=body.name.strip(),
            email=str(body.email).strip(),
            role=body.role,
            password=body.password,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if member is None:
        raise HTTPException(status_code=409, detail="Email already registered")
    return {"ok": True, "member": member}


@router.delete("/team/{email}")
def remove_member(
    email: str,
    user: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    if str(user.get("email", "")).lower() == email.strip().lower():
        raise HTTPException(status_code=400, detail="Cannot remove your own account")
    database = get_database()
    if not database.remove_team_member(email):
        raise HTTPException(status_code=404, detail="Member not found")
    return {"ok": True}


@router.put("/team/{email}/role")
def update_role(
    email: str,
    body: RoleUpdateBody,
    user: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    if body.role not in ROLES:
        raise HTTPException(status_code=400, detail=f"Invalid role: {body.role}")
    if str(user.get("email", "")).lower() == email.strip().lower() and body.role != "Admin":
        raise HTTPException(status_code=400, detail="Cannot change your own admin role")
    database = get_database()
    if not database.update_member_role(email, body.role):
        raise HTTPException(status_code=404, detail="Member not found")
    return {"ok": True}


@router.get("/permissions")
def get_permissions(user: dict[str, Any] = Depends(require_permission("access"))) -> dict[str, Any]:
    database = get_database()
    matrix = database.load_role_permissions()
    return role_permissions_payload(matrix)


@router.put("/permissions")
def save_permissions(
    body: PermissionMatrixBody,
    user: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    database = get_database()
    matrix = database.save_role_permissions(body.matrix)
    return role_permissions_payload(matrix)
