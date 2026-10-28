"""Authentication for agent-facing endpoints."""

from __future__ import annotations

from fastapi import Header, HTTPException

from noirlycan_backend.api.deps import get_database


def bearer_token(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        return ""
    return authorization.split(" ", 1)[1].strip()


def require_agent(agent_id: str, authorization: str | None = Header(default=None)) -> str:
    """Path-scoped agent auth: the token must belong to ``agent_id`` and the agent must be registered."""
    database = get_database()
    if database.authenticate_agent(agent_id, bearer_token(authorization)) != "agent":
        raise HTTPException(status_code=401, detail="Invalid agent token")
    return agent_id
