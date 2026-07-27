from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import PureWindowsPath
from typing import Any


class EventSource(str, Enum):
    SYSMON = "sysmon"
    FRIDA = "frida"
    TRIAGE = "triage"


class PrimitiveKind(str, Enum):
    ALLOCATE = "allocate"
    WRITE = "write"
    EXECUTE = "execute"
    CONTEXT_READ = "context_read"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class TelemetryEvent:
    source: EventSource
    kind: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    pid: int | None = None
    process_image: str | None = None
    data: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class FileEvent:
    timestamp: datetime
    path: str
    creator_pid: int | None
    creator_image: str | None
    sha256: str | None = None
    signed: bool | None = None
    entropy: float | None = None
    pe: bool | None = None

    @property
    def suffix(self) -> str:
        return PureWindowsPath(self.path).suffix.lower()


@dataclass(frozen=True)
class ProcessEvent:
    timestamp: datetime
    pid: int
    image: str
    command_line: str | None = None
    parent_pid: int | None = None
    parent_image: str | None = None
    created_from_file: str | None = None
    flags: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class MemoryPrimitive:
    timestamp: datetime
    kind: PrimitiveKind
    actor_pid: int
    actor_image: str | None
    target_pid: int | None
    target_image: str | None
    address: int | None
    size: int | None
    api: str
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def end_address(self) -> int | None:
        if self.address is None or self.size is None:
            return None
        return self.address + max(self.size, 0)


@dataclass(frozen=True)
class NetworkConnectionEvent:
    timestamp: datetime
    pid: int
    image: str | None
    protocol: str | None
    destination_ip: str | None
    destination_hostname: str | None
    destination_port: int | None
    initiated: bool | None = None
    succeeded: bool | None = None
    source: str | None = None

    @property
    def endpoint(self) -> str:
        host = self.destination_hostname or self.destination_ip or "unknown"
        if self.destination_port is not None:
            return f"{host}:{self.destination_port}"
        return host


@dataclass(frozen=True)
class EvasionSignalEvent:
    timestamp: datetime
    kind: str
    api: str
    pid: int | None = None
    image: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Finding:
    timestamp: datetime
    severity: Severity
    title: str
    description: str
    actor_pid: int
    target_pid: int | None
    primitives: tuple[MemoryPrimitive, ...]
    related_file: FileEvent | None = None
    related_process: ProcessEvent | None = None
    actor_image: str | None = None
    target_image: str | None = None
    score: int = 0
    evidence: dict[str, Any] = field(default_factory=dict)
    technique: str | None = None
    technique_confidence: str | None = None
    injection_chain: tuple[int, ...] | None = None
    chain_depth: int = 0
    is_recursive: bool = False
    network_connections: list[dict[str, Any]] = field(default_factory=list)
