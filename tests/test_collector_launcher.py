from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from noirlycan_agent.collector.application.collector_launcher import (
    clear_collector_pid,
    is_collector_running,
    read_collector_pid,
    register_collector_pid,
    start_collector,
)
from noirlycan_dashboard import make_client
from noirlycan_core.runtime.config import touch_collector_heartbeat


def test_register_and_read_collector_pid(tmp_path: Path) -> None:
    register_collector_pid(tmp_path, 4242)
    assert read_collector_pid(tmp_path) == 4242
    clear_collector_pid(tmp_path)
    assert read_collector_pid(tmp_path) is None


def test_is_collector_running_from_heartbeat(tmp_path: Path) -> None:
    touch_collector_heartbeat(logs_dir=tmp_path, watch_paths=["D:\\"])
    assert is_collector_running(tmp_path) is True


def test_start_collector_skips_when_online(tmp_path: Path) -> None:
    touch_collector_heartbeat(logs_dir=tmp_path, watch_paths=["D:\\"])
    with patch("noirlycan_agent.collector.application.collector_launcher.subprocess.Popen") as popen:
        result = start_collector(tmp_path, elevate=False)
    popen.assert_not_called()
    assert result["already_running"] is True


def test_collector_start_api(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    with patch(
        "noirlycan_dashboard.legacy.views.start_collector",
        return_value={
            "ok": True,
            "started": True,
            "elevated": True,
            "message": "test launch",
            "collector_online": False,
        },
    ) as mocked:
        response = client.post("/api/collector/start")
    assert response.status_code == 200
    payload = response.json()
    assert payload["started"] is True
    mocked.assert_called_once()
