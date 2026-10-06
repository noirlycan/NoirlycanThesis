"""Evasion signal model and lightweight anti-analysis telemetry."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class EvasionSignalKind(str, Enum):
    DEBUGGER_CHECK = "debugger_check"
    REMOTE_DEBUGGER = "remote_debugger"
    DEBUG_PORT_QUERY = "debug_port_query"
    TIMING_PROBE = "timing_probe"
    VM_ARTIFACT = "vm_artifact"
    SANDBOX_ARTIFACT = "sandbox_artifact"
    INSTRUMENTATION_PROBE = "instrumentation_probe"


@dataclass(frozen=True)
class EvasionSignal:
    timestamp: datetime
    kind: EvasionSignalKind
    api: str
    pid: int | None
    image: str | None
    details: dict[str, Any] = field(default_factory=dict)


def evasion_signal_from_payload(payload: dict[str, Any]) -> EvasionSignal | None:
    if payload.get("type") != "evasion_signal":
        return None
    kind_raw = payload.get("kind")
    try:
        kind = EvasionSignalKind(str(kind_raw))
    except ValueError:
        return None
    timestamp = _parse_timestamp(payload.get("timestamp"))
    return EvasionSignal(
        timestamp=timestamp,
        kind=kind,
        api=str(payload.get("api") or "unknown"),
        pid=_safe_int(payload.get("pid")),
        image=payload.get("image"),
        details={
            key: value
            for key, value in payload.items()
            if key not in {"type", "kind", "api", "pid", "image", "timestamp"}
        },
    )


def summarize_evasion_signals(signals: list[dict[str, Any]]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    apis: set[str] = set()
    for signal in signals:
        kind = str(signal.get("kind") or "unknown")
        counts[kind] = counts.get(kind, 0) + 1
        api = signal.get("api")
        if api:
            apis.add(str(api))
    return {
        "total": len(signals),
        "by_kind": counts,
        "apis": sorted(apis),
        "evasive_sample": len(signals) > 0,
    }


def _parse_timestamp(value: Any) -> datetime:
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def _safe_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None
