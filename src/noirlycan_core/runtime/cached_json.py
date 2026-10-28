"""Read a JSON file only when it changed on disk.

The agent re-reads policy and runtime config every loop tick; parsing them
each time is wasted work, so loaders cache by (mtime, size).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

_cache: dict[str, tuple[tuple[float, int], Any]] = {}


def load_json_cached(path: Path) -> Any | None:
    """Parsed JSON for ``path``, or None if missing/invalid. Cached until the file changes."""
    key = str(path)
    try:
        stat = os.stat(path)
    except OSError:
        _cache.pop(key, None)
        return None
    signature = (stat.st_mtime, stat.st_size)
    cached = _cache.get(key)
    if cached is not None and cached[0] == signature:
        return cached[1]
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        value = None
    _cache[key] = (signature, value)
    return value


def invalidate(path: Path) -> None:
    _cache.pop(str(path), None)
