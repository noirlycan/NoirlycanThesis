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


def load_agent_credentials(logs_dir: Path | str | None = None) -> dict[str, str]:
    path = identity_path(logs_dir)
    if not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(raw, dict):
        return {}
    payload: dict[str, str] = {}
    agent_id = str(raw.get("agent_id") or "").strip()
    token = str(raw.get("token") or "").strip()
    if agent_id:
        payload["agent_id"] = agent_id
    if token:
        payload["token"] = token
    return payload


def load_agent_identity(logs_dir: Path | str | None = None) -> str | None:
    return load_agent_credentials(logs_dir).get("agent_id")


def save_agent_credentials(
    agent_id: str,
    logs_dir: Path | str | None = None,
    *,
    token: str | None = None,
) -> Path:
    directory = resolve_logs_dir(logs_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / IDENTITY_FILENAME
    existing = load_agent_credentials(logs_dir)
    payload = {
        "agent_id": agent_id.strip(),
        "token": str(token or existing.get("token") or "").strip(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return path


def save_agent_identity(agent_id: str, logs_dir: Path | str | None = None) -> Path:
    return save_agent_credentials(agent_id, logs_dir)


def resolve_agent_id(logs_dir: Path | str | None, explicit: str | None = None) -> str:
    agent_id, _token = resolve_agent_credentials(logs_dir, explicit, None)
    return agent_id


def resolve_agent_credentials(
    logs_dir: Path | str | None,
    explicit_id: str | None = None,
    explicit_token: str | None = None,
) -> tuple[str, str]:
    loaded = load_agent_credentials(logs_dir)
    chosen_id = str(explicit_id or loaded.get("agent_id") or "").strip()
    chosen_token = str(explicit_token or loaded.get("token") or "").strip()
    if not chosen_id:
        chosen_id = generate_agent_id()
    if explicit_id or explicit_token or chosen_id != loaded.get("agent_id") or chosen_token != loaded.get("token"):
        save_agent_credentials(chosen_id, logs_dir, token=chosen_token or None)
    return chosen_id, chosen_token
