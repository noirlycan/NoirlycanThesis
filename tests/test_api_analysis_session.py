from __future__ import annotations

from noirlycan_telemetry import cli as cli_module


def test_schedule_api_analysis_once_per_session() -> None:
    cli_module._SESSION_API_SCHEDULED.clear()
    cli_module._SESSION_API_SPAWNED.clear()
    path = r"C:\Users\copv\Downloads\sample.exe"

    assert cli_module._schedule_api_analysis(path) is True
    assert cli_module._schedule_api_analysis(path) is False

    cli_module._SESSION_API_SPAWNED.add(cli_module._norm_path(path))
    assert cli_module._schedule_api_analysis(path) is False
