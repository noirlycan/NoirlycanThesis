from __future__ import annotations

import os
from pathlib import Path

from noirlycan_backend.infrastructure.console_db import ConsoleDatabase
from noirlycan_core.storage.log_store import ensure_logs_dir, find_project_root


def _resolved_logs_dir() -> Path:
    override = os.environ.get("NOIRLYCAN_LOGS_DIR", "").strip()
    if override:
        path = Path(override).expanduser()
        if not path.is_absolute():
            path = find_project_root() / path
        return ensure_logs_dir(path.resolve())
    return ensure_logs_dir(find_project_root() / "logs")


def get_logs_dir() -> Path:
    return _resolved_logs_dir()


_database: ConsoleDatabase | None = None


def get_database() -> ConsoleDatabase:
    global _database
    if _database is None:
        _database = ConsoleDatabase(get_logs_dir())
    return _database


def reset_runtime_paths(logs_dir: Path | str | None = None) -> Path:
    """Pin logs directory for this process and rebuild cached handles."""
    global _database

    if _database is not None:
        _database.close()
        _database = None

    if logs_dir is not None:
        path = Path(logs_dir).expanduser()
        if not path.is_absolute():
            path = find_project_root() / path
        resolved = ensure_logs_dir(path.resolve())
    else:
        resolved = _resolved_logs_dir()

    os.environ["NOIRLYCAN_LOGS_DIR"] = str(resolved)
    return resolved


def warm_database() -> ConsoleDatabase:
    database = get_database()
    database.list_removed_findings()
    return database
