from __future__ import annotations

import re
from pathlib import Path
from typing import Any

DEFAULT_AGENT_SESSION_NAME = "session-live.jsonl"


def sanitize_agent_id(agent_id: str) -> str:
    cleaned = re.sub(r"[^\w\-]+", "_", str(agent_id or "").strip())
    return cleaned[:120] or "agent"


def agent_session_rel(logs_dir: Path, agent_id: str, session_name: str = DEFAULT_AGENT_SESSION_NAME) -> str:
    safe = sanitize_agent_id(agent_id)
    return f"agents/{safe}/{session_name}"


def agent_session_path(
    logs_dir: Path,
    agent_id: str,
    session_name: str = DEFAULT_AGENT_SESSION_NAME,
) -> Path:
    rel = agent_session_rel(logs_dir, agent_id, session_name)
    return logs_dir / rel


def ensure_agent_session_file(logs_dir: Path, agent_id: str) -> tuple[str, Path]:
    path = agent_session_path(logs_dir, agent_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.touch()
    rel = path.relative_to(logs_dir.resolve()).as_posix()
    return rel, path


def resolve_console_session(database: Any, session: str | None, agent_id: str | None) -> str | None:
    if session:
        return session
    return database.resolve_session_for_agent(agent_id)
