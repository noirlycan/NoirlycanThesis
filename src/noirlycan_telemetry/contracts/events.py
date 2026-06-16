"""Inter-service event contracts (JSONL-compatible)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

EventType = Literal[
    "file",
    "sysmon",
    "primitive",
    "finding",
    "network",
    "frida_raw",
    "evasion",
    "process",
]


@dataclass(frozen=True)
class TelemetryEnvelope:
    """Canonical wire format between collector → storage → analysis → dashboard."""

    type: EventType
    value: dict[str, Any]
    session_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_jsonl_line(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"type": self.type, "value": self.value}
        if self.session_id:
            payload["session_id"] = self.session_id
        if self.metadata:
            payload["metadata"] = self.metadata
        return payload


SERVICE_PORTS = {
    "dashboard": 8765,
    "storage": 8780,
    "analysis": 8781,
    "collector": 8782,
}
