from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from noirlycan_backend.infrastructure.console_db import AGENT_STALE_SECONDS, ConsoleDatabase


def _touch_agent(database: ConsoleDatabase, agent_id: str, *, when: str) -> None:
    with database._connect() as connection:
        connection.execute(
            """
            INSERT INTO console_agents (
                id, hostname, os_name, mode, watching, last_seen, status, enrolled_at
            ) VALUES (?, ?, 'Windows', 'run', '', ?, 'online', ?)
            ON CONFLICT(id) DO UPDATE SET
                last_seen = excluded.last_seen,
                status = 'online'
            """,
            (agent_id, agent_id, when, when),
        )


def test_mark_stale_agents_offline(tmp_path: Path) -> None:
    database = ConsoleDatabase(tmp_path)
    stale = (datetime.now(timezone.utc) - timedelta(seconds=AGENT_STALE_SECONDS + 5)).isoformat()
    _touch_agent(database, "vm01", when=stale)

    assert database.mark_stale_agents_offline() == 1
    agent = next(item for item in database.list_agents() if item["id"] == "vm01")
    assert agent["status"] == "offline"


def test_mark_agent_offline_on_goodbye(tmp_path: Path) -> None:
    database = ConsoleDatabase(tmp_path)
    now = datetime.now(timezone.utc).isoformat()
    _touch_agent(database, "vm01", when=now)

    assert database.mark_agent_offline("vm01") is True
    agent = next(item for item in database.list_agents() if item["id"] == "vm01")
    assert agent["status"] == "offline"
