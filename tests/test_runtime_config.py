from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from noirlycan_telemetry.services.collector.application.runtime_config import (
    is_collector_online,
    load_runtime_config,
    runtime_config_payload,
    save_runtime_config,
    touch_collector_heartbeat,
)


def test_runtime_config_roundtrip(tmp_path: Path) -> None:
    config = load_runtime_config(tmp_path)
    config.file_drop_watch_enabled = False
    save_runtime_config(config, tmp_path)

    loaded = load_runtime_config(tmp_path)
    assert loaded.file_drop_watch_enabled is False
    assert loaded.updated_at is not None


def test_collector_online_from_heartbeat(tmp_path: Path) -> None:
    touch_collector_heartbeat(logs_dir=tmp_path, watch_paths=["D:\\"])
    payload = runtime_config_payload(load_runtime_config(tmp_path))
    assert payload["collector_online"] is True
    assert payload["watch_paths"] == ["D:\\"]


def test_collector_offline_when_stale(tmp_path: Path) -> None:
    config = load_runtime_config(tmp_path)
    config.last_heartbeat = "2020-01-01T00:00:00+00:00"
    save_runtime_config(config, tmp_path)
    loaded = load_runtime_config(tmp_path)
    assert (
        is_collector_online(
            loaded,
            now=datetime(2020, 1, 1, 0, 1, tzinfo=timezone.utc),
        )
        is False
    )
