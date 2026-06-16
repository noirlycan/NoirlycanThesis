from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from noirlycan_telemetry.kernel.entities.models import FileEvent
from noirlycan_telemetry.services.collector.infrastructure.triage import is_interesting_path
from noirlycan_telemetry.services.storage.infrastructure.log_store import find_project_root


def default_watch_paths(extra: list[str] | None = None) -> list[str]:
    candidates = list(extra or [])
    for path in (
        find_project_root(),
        Path("D:/"),
        Path("D:/thesis"),
        Path.home() / "Downloads",
        Path.home() / "Desktop",
    ):
        resolved = str(path.resolve())
        if path.exists() and resolved not in candidates:
            candidates.append(resolved)
    return candidates


class FileDropWatcher:
    """Poll watch directories for new or modified executables/scripts."""

    def __init__(self, paths: list[str], *, recursive: bool = False) -> None:
        del recursive  # reserved for future use
        self._paths = [Path(path).resolve() for path in paths if Path(path).exists()]
        self._snapshot: dict[str, float] = {}
        self._bootstrapped = False

    @property
    def paths(self) -> list[str]:
        return [str(path) for path in self._paths]

    def start(self) -> None:
        self._bootstrap()

    def reset_baseline(self) -> None:
        self._snapshot.clear()
        self._bootstrap()

    def stop(self) -> None:
        return None

    def drain(self) -> list[FileEvent]:
        if not self._bootstrapped:
            self._bootstrap()
            return []

        events: list[FileEvent] = []
        timestamp = datetime.now(timezone.utc)
        for directory in self._paths:
            events.extend(self._scan_directory(directory, timestamp))
        return events

    def _bootstrap(self) -> None:
        for directory in self._paths:
            for path, mtime in self._iter_interesting_files(directory):
                self._snapshot[path.lower()] = mtime
        self._bootstrapped = True

    def _scan_directory(self, directory: Path, timestamp: datetime) -> list[FileEvent]:
        events: list[FileEvent] = []
        for path, mtime in self._iter_interesting_files(directory):
            key = path.lower()
            previous = self._snapshot.get(key)
            if previous is None:
                events.append(
                    FileEvent(
                        timestamp=timestamp,
                        path=path,
                        creator_pid=None,
                        creator_image="file-scanner",
                    )
                )
                self._snapshot[key] = mtime
            elif mtime > previous:
                events.append(
                    FileEvent(
                        timestamp=timestamp,
                        path=path,
                        creator_pid=None,
                        creator_image="file-scanner",
                    )
                )
                self._snapshot[key] = mtime
        return events

    def _iter_interesting_files(self, directory: Path) -> list[tuple[str, float]]:
        rows: list[tuple[str, float]] = []
        try:
            entries = list(directory.iterdir())
        except OSError:
            return rows
        for entry in entries:
            if not entry.is_file():
                continue
            path = str(entry.resolve())
            if not is_interesting_path(path):
                continue
            try:
                mtime = entry.stat().st_mtime
            except OSError:
                continue
            rows.append((path, mtime))
        return rows
