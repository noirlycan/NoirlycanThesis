from __future__ import annotations

import json
import re
import socket
import uuid
from datetime import datetime, timezone
from pathlib import Path

from noirlycan_core.storage.infrastructure.atomic_io import atomic_write_text
from noirlycan_core.storage.infrastructure.log_store import resolve_logs_dir

IDENTITY_FILENAME = ".agent_identity.json"


def identity_path(logs_dir: Path | str | None = None) -> Path:
    return resolve_logs_dir(logs_dir) / IDENTITY_FILENAME


def _sanitize_hostname(hostname: str) -> str:
    cleaned = re.sub(r"[^\w\-]+", "-", hostname.strip()).strip("-")
    return cleaned or "agent"


def generate_agent_id() -> str:
    hostname = _sanitize_hostname(socket.gethostname())
    token = uuid.uuid5(
        uuid.NAMESPACE_URL,
        f"noirlycan-agent:{hostname}:{uuid.getnode()}",
    ).hex[:8]
    return f"{hostname}-{token}"


def load_agent_identity(logs_dir: Path | str | None = None) -> str | None:
    path = identity_path(logs_dir)
    if not path.is_file():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(raw, dict):
        return None
    agent_id = str(raw.get("agent_id") or "").strip()
    return agent_id or None


def save_agent_identity(agent_id: str, logs_dir: Path | str | None = None) -> Path:
    directory = resolve_logs_dir(logs_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / IDENTITY_FILENAME
    payload = {
        "agent_id": agent_id.strip(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return path


def resolve_agent_id(logs_dir: Path | str | None, explicit: str | None = None) -> str:
    chosen = str(explicit or "").strip()
    if chosen:
        save_agent_identity(chosen, logs_dir)
        return chosen
    existing = load_agent_identity(logs_dir)
    if existing:
        return existing
    agent_id = generate_agent_id()
    save_agent_identity(agent_id, logs_dir)
    return agent_id
