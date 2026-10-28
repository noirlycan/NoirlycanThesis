from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field, field_validator

from noirlycan_backend.api.auth import create_access_token, get_current_user
from noirlycan_backend.api.deps import get_database
from noirlycan_backend.domain.email import normalize_lab_email

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    email: str = Field(min_length=3)
    password: str = Field(min_length=1)

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        return normalize_lab_email(value)


@router.post("/login")
def login(body: LoginRequest) -> dict[str, Any]:
    database = get_database()
    user = database.authenticate(body.email, body.password)
    if user is None:
        return {"ok": False, "error": "Invalid email or password"}
    token = create_access_token(user)
    matrix = database.load_role_permissions()
    return {"ok": True, "token": token, "user": user, "permissions": matrix.get(user["role"], {})}


@router.get("/me")
def me(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    database = get_database()
    matrix = database.load_role_permissions()
    return {"user": user, "permissions": matrix.get(user["role"], {}), "role_permissions": matrix}
