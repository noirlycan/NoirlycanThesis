"""Post-injection network watch (repo extension, not part of the paper).

After a high-score finding, outbound connections from the victim PID are
collected for a limited time so the analyst can see a possible beacon.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta

from noirlycan_core.models import NetworkConnectionEvent

NETWORK_WATCH_MIN_SCORE = 70
NETWORK_WATCH_SECONDS = 300


class NetworkWatch:
    def __init__(self) -> None:
        self._watch_until: dict[int, datetime] = {}
        self.connections: dict[int, list[NetworkConnectionEvent]] = defaultdict(list)

    def watch(self, pid: int, start: datetime, seconds: int) -> None:
        self._watch_until[pid] = start + timedelta(seconds=seconds)

    def active_pids(self, now: datetime) -> set[int]:
        for pid in [pid for pid, until in self._watch_until.items() if until < now]:
            del self._watch_until[pid]
        return set(self._watch_until)

    def record(self, event: NetworkConnectionEvent) -> bool:
        """Keep the connection if its PID is being watched."""
        if event.pid not in self.active_pids(event.timestamp):
            return False
        self.connections[event.pid].append(event)
        return True

    def expire(self, now: datetime, cutoff: datetime) -> None:
        self.active_pids(now)
        for pid in list(self.connections):
            kept = [connection for connection in self.connections[pid] if connection.timestamp >= cutoff]
            if kept:
                self.connections[pid] = kept
            else:
                del self.connections[pid]
