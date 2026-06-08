from __future__ import annotations

from typing import Any

from .live_hub import broadcast_refresh as _broadcast_refresh
from .live_hub import broadcast_runtime as _broadcast_runtime

GROUP_NAME = "noirlycan_dashboard"


def broadcast_runtime(payload: dict[str, Any]) -> None:
    _broadcast_runtime(payload)


def broadcast_refresh(*, reason: str = "logs") -> None:
    _broadcast_refresh(reason=reason)
