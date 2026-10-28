from __future__ import annotations

from pathlib import Path

from noirlycan_agent.runtime.collector_pid import (
    clear_collector_pid,
    is_collector_running,
    read_collector_pid,
    register_collector_pid,
)
from noirlycan_core.runtime.config import touch_collector_heartbeat


def test_register_and_read_collector_pid(tmp_path: Path) -> None:
    register_collector_pid(tmp_path, 4242)
    assert read_collector_pid(tmp_path) == 4242
    clear_collector_pid(tmp_path)
    assert read_collector_pid(tmp_path) is None


def test_is_collector_running_from_heartbeat(tmp_path: Path) -> None:
    touch_collector_heartbeat(logs_dir=tmp_path, watch_paths=["D:\\"])
    assert is_collector_running(tmp_path) is True

