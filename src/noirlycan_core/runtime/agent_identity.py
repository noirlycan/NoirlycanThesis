"""The agent's identity on disk: ``logs/.agent_identity.json``.

Holds the agent id, its enrollment token and the pinned public key that signs
console commands. On Windows the token is encrypted with DPAPI (bound to the
current user), so a sample reading the file finds no usable bearer token.
"""

from __future__ import annotations

import base64
import json
import re
import socket
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from noirlycan_core.storage.atomic_io import atomic_write_text
from noirlycan_core.storage.log_store import resolve_logs_dir

IDENTITY_FILENAME = ".agent_identity.json"


def identity_path(logs_dir: Path | str | None = None) -> Path:
    return resolve_logs_dir(logs_dir) / IDENTITY_FILENAME


def generate_agent_id() -> str:
    hostname = re.sub(r"[^\w\-]+", "-", socket.gethostname().strip()).strip("-") or "agent"
    token = uuid.uuid5(uuid.NAMESPACE_URL, f"noirlycan-agent:{hostname}:{uuid.getnode()}").hex[:8]
    return f"{hostname}-{token}"


def load_agent_credentials(logs_dir: Path | str | None = None) -> dict[str, str]:
    path = identity_path(logs_dir)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(raw, dict):
        return {}
    token = _unprotect(str(raw["token_protected"])) if raw.get("token_protected") else str(raw.get("token") or "")
    payload = {
        "agent_id": str(raw.get("agent_id") or "").strip(),
        "token": token.strip(),
        "command_key": str(raw.get("command_key") or "").strip(),
    }
    return {key: value for key, value in payload.items() if value}


def load_agent_identity(logs_dir: Path | str | None = None) -> str | None:
    return load_agent_credentials(logs_dir).get("agent_id")


def save_agent_credentials(
    agent_id: str,
    logs_dir: Path | str | None = None,
    *,
    token: str | None = None,
    command_key: str | None = None,
    require_protection: bool = False,
) -> Path:
    directory = resolve_logs_dir(logs_dir)
    directory.mkdir(parents=True, exist_ok=True)
    existing = load_agent_credentials(directory)
    token_value = str(token or existing.get("token") or "").strip()
    payload: dict[str, str] = {
        "agent_id": agent_id.strip(),
        "command_key": str(command_key or existing.get("command_key") or ""),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    protected = _protect(token_value) if token_value else None
    if token_value and not protected and (require_protection or sys.platform == "win32"):
        raise OSError("Windows DPAPI could not protect the agent token; credentials were not saved.")
    if protected:
        payload["token_protected"] = protected
    else:
        payload["token"] = token_value
    path = directory / IDENTITY_FILENAME
    atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return path


def save_agent_identity(agent_id: str, logs_dir: Path | str | None = None) -> Path:
    return save_agent_credentials(agent_id, logs_dir)


def resolve_agent_id(logs_dir: Path | str | None, explicit: str | None = None) -> str:
    return resolve_agent_credentials(logs_dir, explicit, None)[0]


def resolve_agent_credentials(
    logs_dir: Path | str | None,
    explicit_id: str | None = None,
    explicit_token: str | None = None,
) -> tuple[str, str]:
    """Explicit values win and are saved; otherwise use what is on disk."""
    loaded = load_agent_credentials(logs_dir)
    agent_id = str(explicit_id or loaded.get("agent_id") or "").strip() or generate_agent_id()
    token = str(explicit_token or loaded.get("token") or "").strip()
    if agent_id != loaded.get("agent_id") or token != loaded.get("token", ""):
        save_agent_credentials(agent_id, logs_dir, token=token or None)
    return agent_id, token


# -- DPAPI ------------------------------------------------------------------


def _protect(secret: str) -> str | None:
    if sys.platform != "win32":
        return None
    blob = _dpapi(secret.encode("utf-8"), protect=True)
    return base64.b64encode(blob).decode("ascii") if blob is not None else None


def _unprotect(value: str) -> str:
    blob = _dpapi(base64.b64decode(value), protect=False) if sys.platform == "win32" else None
    return blob.decode("utf-8") if blob is not None else ""


def _dpapi(data: bytes, *, protect: bool) -> bytes | None:
    import ctypes
    from ctypes import wintypes

    class Blob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    buffer = ctypes.create_string_buffer(data, len(data))
    source = Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))
    result = Blob()
    call = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    if not call(ctypes.byref(source), None, None, None, None, 0, ctypes.byref(result)):
        return None
    try:
        return ctypes.string_at(result.pbData, result.cbData)
    finally:
        kernel32.LocalFree(result.pbData)
