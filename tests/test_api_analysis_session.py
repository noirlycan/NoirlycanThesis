from __future__ import annotations

from pathlib import Path

from noirlycan_agent.runtime.event_sink import JsonlWriter
from noirlycan_agent.runtime.sample_runner import SampleRunner, norm_path
from noirlycan_core.detection.correlator import Correlator


def test_schedule_api_analysis_once_per_session(tmp_path: Path) -> None:
    runner = SampleRunner(monitor=None, correlator=Correlator(), sink=JsonlWriter(None), logs_dir=tmp_path)
    path = r"C:\Users\lab\Downloads\sample.exe"

    assert runner.schedule_once(path) is True
    assert runner.schedule_once(path) is False

    other = r"C:\Users\lab\Downloads\other.exe"
    runner._spawned.add((norm_path(other), ()))
    assert runner.schedule_once(other) is False


def test_run_without_frida_reports_failure(tmp_path: Path) -> None:
    log = tmp_path / "session.jsonl"
    sink = JsonlWriter(log)
    runner = SampleRunner(monitor=None, correlator=Correlator(), sink=sink, logs_dir=tmp_path)
    assert runner.run(str(tmp_path / "sample.exe"), source="test") is False
    sink.close()
    assert '"status": "failed"' in log.read_text()
