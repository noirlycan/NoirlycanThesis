from __future__ import annotations

import os
import secrets
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

JWT_ALGORITHM = "HS256"
JWT_TTL_HOURS = 12

_bearer = HTTPBearer(auto_error=False)


JWT_SECRET_FILE = ".jwt_secret"


@lru_cache(maxsize=4)
def _secret_for(logs_dir: str) -> str:
    """Per-install random secret, created on first use (never a value from the repo)."""
    path = Path(logs_dir) / JWT_SECRET_FILE
    if not path.is_file():
        path.write_text(secrets.token_urlsafe(48), encoding="utf-8")
        path.chmod(0o600)
    return path.read_text(encoding="utf-8").strip()


def _jwt_secret() -> str:
    from noirlycan_backend.api.deps import get_logs_dir

    configured = os.environ.get("NOIRLYCAN_CONSOLE_JWT_SECRET", "").strip()
    return configured or _secret_for(str(get_logs_dir()))


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
