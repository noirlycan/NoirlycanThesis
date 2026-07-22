from __future__ import annotations

from pathlib import Path

from noirlycan_agent.collector.application.analysis_queue import (
    drain_analysis_queue,
    enqueue_analysis,
    load_analysis_queue,
)


def test_enqueue_and_drain_api_analysis_queue(tmp_path: Path) -> None:
    assert enqueue_analysis(r"D:\drop_test.exe", tmp_path, mode="api") is True
    assert enqueue_analysis(r"D:\drop_test.exe", tmp_path, mode="api") is False

    queue = load_analysis_queue(tmp_path)
    assert len(queue.pending) == 1
    assert queue.pending[0].mode == "api"

    drained = drain_analysis_queue(tmp_path)
    assert len(drained) == 1
    assert drained[0].path == r"D:\drop_test.exe"
    assert drained[0].mode == "api"
    assert load_analysis_queue(tmp_path).pending == []
