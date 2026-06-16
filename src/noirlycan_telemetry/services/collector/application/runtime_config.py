from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from noirlycan_telemetry.services.storage.infrastructure.atomic_io import atomic_write_text
from noirlycan_telemetry.services.storage.infrastructure.log_store import default_logs_dir

CONFIG_NAME = ".runtime.json"
COLLECTOR_STALE_SECONDS = 8
_HEARTBEAT_SAVE_INTERVAL_SECONDS = 2.0
_last_heartbeat_save_monotonic: dict[str, float] = {}


@dataclass
class RuntimeConfig:
    file_drop_watch_enabled: bool = True
    auto_triage_enabled: bool = False  # legacy alias for auto_api_analysis_enabled
    auto_api_analysis_enabled: bool = False
    auto_static_triage_enabled: bool = False
    file_drop_watch_locked: bool = False
    collector_active: bool = False
    last_heartbeat: str | None = None
    watch_paths: list[str] = field(default_factory=list)
    updated_at: str | None = None


def resolve_config_path(logs_dir: Path | str | None = None) -> Path:
    directory = Path(logs_dir).expanduser().resolve() if logs_dir else default_logs_dir()
    return directory / CONFIG_NAME


def load_runtime_config(logs_dir: Path | str | None = None) -> RuntimeConfig:
    path = resolve_config_path(logs_dir)
    if not path.exists():
        return RuntimeConfig()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return RuntimeConfig()
    if not isinstance(raw, dict):
        return RuntimeConfig()
    return RuntimeConfig(
        file_drop_watch_enabled=bool(raw.get("file_drop_watch_enabled", True)),
        auto_triage_enabled=bool(raw.get("auto_triage_enabled", False)),
        auto_api_analysis_enabled=bool(
            raw.get(
                "auto_api_analysis_enabled",
                raw.get("auto_triage_enabled", False),
            )
        ),
        auto_static_triage_enabled=bool(raw.get("auto_static_triage_enabled", False)),
        file_drop_watch_locked=bool(raw.get("file_drop_watch_locked", False)),
        collector_active=bool(raw.get("collector_active", False)),
        last_heartbeat=raw.get("last_heartbeat"),
        watch_paths=[str(item) for item in raw.get("watch_paths") or []],
        updated_at=raw.get("updated_at"),
    )


def save_runtime_config(config: RuntimeConfig, logs_dir: Path | str | None = None) -> Path:
    path = resolve_config_path(logs_dir)
    config.updated_at = datetime.now(timezone.utc).isoformat()
    payload = asdict(config)
    content = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    atomic_write_text(path, content)
    return path


def runtime_config_payload(config: RuntimeConfig) -> dict[str, Any]:
    payload = asdict(config)
    payload["collector_online"] = is_collector_online(config)
    return payload


def is_collector_online(
    config: RuntimeConfig,
    *,
    now: datetime | None = None,
    max_age_seconds: int = COLLECTOR_STALE_SECONDS,
) -> bool:
    if not config.last_heartbeat:
        return False
    try:
        heartbeat = datetime.fromisoformat(config.last_heartbeat)
    except ValueError:
        return False
    if heartbeat.tzinfo is None:
        heartbeat = heartbeat.replace(tzinfo=timezone.utc)
    current = now or datetime.now(timezone.utc)
    age = (current - heartbeat).total_seconds()
    return age <= max_age_seconds


def touch_collector_heartbeat(
    *,
    logs_dir: Path | str | None = None,
    watch_paths: list[str] | None = None,
) -> RuntimeConfig:
    path = resolve_config_path(logs_dir)
    config = load_runtime_config(logs_dir)
    config.collector_active = True
    config.last_heartbeat = datetime.now(timezone.utc).isoformat()
    if watch_paths is not None:
        config.watch_paths = list(watch_paths)

    now = time.monotonic()
    last_save = _last_heartbeat_save_monotonic.get(str(path), 0.0)
    if now - last_save < _HEARTBEAT_SAVE_INTERVAL_SECONDS:
        return config

    try:
        save_runtime_config(config, logs_dir)
        _last_heartbeat_save_monotonic[str(path)] = now
    except OSError:
        # Dashboard/collector can contend on .runtime.json on Windows.
        pass
    return config


def mark_collector_stopped(logs_dir: Path | str | None = None) -> None:
    config = load_runtime_config(logs_dir)
    config.collector_active = False
    try:
        save_runtime_config(config, logs_dir)
    except OSError:
        pass
