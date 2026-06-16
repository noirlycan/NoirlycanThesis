from __future__ import annotations

import time
from pathlib import Path

from noirlycan_telemetry.services.collector.infrastructure.file_watch import FileDropWatcher, default_watch_paths


def test_default_watch_paths_includes_existing_directories(tmp_path: Path, monkeypatch) -> None:
    thesis = tmp_path / "thesis"
    thesis.mkdir()
    monkeypatch.setattr("noirlycan_telemetry.services.collector.infrastructure.file_watch.Path.home", lambda: tmp_path)
    paths = default_watch_paths([str(thesis)])
    assert str(thesis.resolve()) in paths


def test_file_drop_watcher_detects_new_executable(tmp_path: Path) -> None:
    watch_dir = tmp_path / "drops"
    watch_dir.mkdir()
    watcher = FileDropWatcher([str(watch_dir)])
    watcher.start()
    assert watcher.drain() == []

    dropped = watch_dir / "loader.exe"
    dropped.write_bytes(b"MZ" + b"\x00" * 128)
    time.sleep(0.05)
    events = watcher.drain()
    assert len(events) == 1
    assert events[0].path.endswith("loader.exe")
