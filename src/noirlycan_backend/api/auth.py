from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

JWT_ALGORITHM = "HS256"
JWT_TTL_HOURS = 12

_bearer = HTTPBearer(auto_error=False)


def _jwt_secret() -> str:
    return os.environ.get("NOIRLYCAN_CONSOLE_JWT_SECRET", "noirlycan-console-dev-secret")


def create_access_token(user: dict[str, Any]) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user["email"],
        "role": user["role"],
        "name": user["name"],
        "initial": user.get("initial"),
        "iat": now,
        "exp": now + timedelta(hours=JWT_TTL_HOURS),
    }
    return jwt.encode(payload, _jwt_secret(), algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> dict[str, Any]:
    try:
        payload = jwt.decode(token, _jwt_secret(), algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        ) from exc
    return payload


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> dict[str, Any]:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    payload = decode_access_token(credentials.credentials)
    return {
        "email": payload.get("sub"),
        "role": payload.get("role"),
        "name": payload.get("name"),
        "initial": payload.get("initial"),
    }


def require_permission(key: str):
    from noirlycan_backend.api.deps import get_database
    from noirlycan_backend.domain.permissions import has_permission

    def _checker(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
        database = get_database()
        matrix = database.load_role_permissions()
        if not has_permission(matrix, str(user.get("role")), key):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Missing permission: {key}")
        return user

    return _checker


def require_admin(user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    if str(user.get("role")) != "Admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required")
    return user
