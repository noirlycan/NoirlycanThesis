"""SQLite persistence for uploaded samples and parsed JSONL sessions."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from noirlycan_telemetry.services.storage.infrastructure.log_store import (
    aggregate_events,
    count_jsonl_lines,
    read_jsonl,
    resolve_logs_dir,
)


def default_db_path(logs_dir: Path | str | None = None) -> Path:
    return resolve_logs_dir(logs_dir) / "noirlycan.db"


@dataclass(frozen=True)
class UploadRecord:
    id: int
    original_name: str
    stored_path: str
    content_kind: str
    size_bytes: int
    sha256: str
    status: str
    error_message: str | None
    uploaded_at: str
    session_name: str | None


class AnalysisDatabase:
    def __init__(self, logs_dir: Path | str | None = None) -> None:
        self.logs_dir = resolve_logs_dir(logs_dir)
        self.db_path = default_db_path(self.logs_dir)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _init_schema(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS uploads (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    original_name TEXT NOT NULL,
                    stored_path TEXT NOT NULL,
                    content_kind TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    sha256 TEXT NOT NULL,
                    status TEXT NOT NULL,
                    error_message TEXT,
                    uploaded_at TEXT NOT NULL,
                    session_name TEXT
                );

                CREATE TABLE IF NOT EXISTS parsed_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    upload_id INTEGER,
                    session_name TEXT NOT NULL UNIQUE,
                    source_path TEXT NOT NULL,
                    event_count INTEGER NOT NULL DEFAULT 0,
                    finding_count INTEGER NOT NULL DEFAULT 0,
                    primitive_count INTEGER NOT NULL DEFAULT 0,
                    stats_json TEXT NOT NULL,
                    parsed_at TEXT NOT NULL,
                    FOREIGN KEY (upload_id) REFERENCES uploads(id)
                );

                CREATE TABLE IF NOT EXISTS stored_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER NOT NULL,
                    severity TEXT,
                    score INTEGER,
                    technique TEXT,
                    actor_pid INTEGER,
                    target_pid INTEGER,
                    payload_json TEXT NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES parsed_sessions(id)
                );

                CREATE INDEX IF NOT EXISTS idx_uploads_uploaded_at
                    ON uploads(uploaded_at DESC);
                CREATE INDEX IF NOT EXISTS idx_parsed_sessions_name
                    ON parsed_sessions(session_name);
                CREATE INDEX IF NOT EXISTS idx_uploads_stored_path
                    ON uploads(stored_path);
                CREATE INDEX IF NOT EXISTS idx_stored_findings_technique
                    ON stored_findings(technique);

                CREATE TABLE IF NOT EXISTS jsonl_analytics_cache (
                    session_name TEXT PRIMARY KEY,
                    source_path TEXT NOT NULL,
                    mtime REAL NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    lines_processed INTEGER NOT NULL DEFAULT 0,
                    state_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )

    def record_upload(
        self,
        *,
        original_name: str,
        stored_path: str,
        content_kind: str,
        size_bytes: int,
        sha256: str,
        status: str,
        error_message: str | None = None,
        session_name: str | None = None,
    ) -> int:
        uploaded_at = datetime.now(timezone.utc).isoformat()
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO uploads (
                    original_name, stored_path, content_kind, size_bytes, sha256,
                    status, error_message, uploaded_at, session_name
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    original_name,
                    stored_path,
                    content_kind,
                    size_bytes,
                    sha256,
                    status,
                    error_message,
                    uploaded_at,
                    session_name,
                ),
            )
            return int(cursor.lastrowid)

    def update_upload(
        self,
        upload_id: int,
        *,
        status: str,
        error_message: str | None = None,
        session_name: str | None = None,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE uploads
                SET status = ?, error_message = ?, session_name = COALESCE(?, session_name)
                WHERE id = ?
                """,
                (status, error_message, session_name, upload_id),
            )

    def ingest_jsonl(
        self,
        source_path: Path,
        *,
        upload_id: int | None = None,
        session_name: str | None = None,
    ) -> dict[str, Any]:
        events = read_jsonl(source_path)
        stats = aggregate_events(events)
        totals = stats.get("totals") or {}
        parsed_at = datetime.now(timezone.utc).isoformat()
        resolved_name = session_name or source_path.name
        stats_payload = json.dumps(stats, ensure_ascii=False, sort_keys=True)

        with self._connect() as connection:
            existing = connection.execute(
                "SELECT id FROM parsed_sessions WHERE session_name = ?",
                (resolved_name,),
            ).fetchone()
            if existing is not None:
                session_id = int(existing["id"])
                connection.execute(
                    "DELETE FROM stored_findings WHERE session_id = ?",
                    (session_id,),
                )
                connection.execute(
                    """
                    UPDATE parsed_sessions
                    SET upload_id = COALESCE(?, upload_id),
                        source_path = ?,
                        event_count = ?,
                        finding_count = ?,
                        primitive_count = ?,
                        stats_json = ?,
                        parsed_at = ?
                    WHERE id = ?
                    """,
                    (
                        upload_id,
                        str(source_path.resolve()),
                        int(totals.get("events") or 0),
                        int(totals.get("findings") or 0),
                        int(totals.get("primitives") or 0),
                        stats_payload,
                        parsed_at,
                        session_id,
                    ),
                )
            else:
                cursor = connection.execute(
                    """
                    INSERT INTO parsed_sessions (
                        upload_id, session_name, source_path, event_count, finding_count,
                        primitive_count, stats_json, parsed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        upload_id,
                        resolved_name,
                        str(source_path.resolve()),
                        int(totals.get("events") or 0),
                        int(totals.get("findings") or 0),
                        int(totals.get("primitives") or 0),
                        stats_payload,
                        parsed_at,
                    ),
                )
                session_id = int(cursor.lastrowid)
            for finding in stats.get("recent_findings") or []:
                if not isinstance(finding, dict):
                    continue
                connection.execute(
                    """
                    INSERT INTO stored_findings (
                        session_id, severity, score, technique, actor_pid, target_pid, payload_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        session_id,
                        finding.get("severity"),
                        finding.get("score"),
                        finding.get("technique"),
                        finding.get("actor_pid"),
                        finding.get("target_pid"),
                        json.dumps(finding, ensure_ascii=False, sort_keys=True),
                    ),
                )

        return {
            "session_name": resolved_name,
            "event_count": int(totals.get("events") or 0),
            "finding_count": int(totals.get("findings") or 0),
            "primitive_count": int(totals.get("primitives") or 0),
            "parsed_at": parsed_at,
            "stats": stats,
        }

    def get_upload(self, upload_id: int) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT id, original_name, stored_path, content_kind, size_bytes, sha256,
                       status, error_message, uploaded_at, session_name
                FROM uploads
                WHERE id = ?
                """,
                (upload_id,),
            ).fetchone()
        return dict(row) if row is not None else None

    def get_parsed_session_for_upload(self, upload_id: int) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT id, upload_id, session_name, source_path, event_count, finding_count,
                       primitive_count, stats_json, parsed_at
                FROM parsed_sessions
                WHERE upload_id = ?
                ORDER BY parsed_at DESC
                LIMIT 1
                """,
                (upload_id,),
            ).fetchone()
            if row is None:
                return None
            payload = dict(row)
            payload["stats"] = json.loads(payload.pop("stats_json"))
            findings = connection.execute(
                """
                SELECT payload_json FROM stored_findings
                WHERE session_id = ?
                ORDER BY id ASC
                """,
                (payload["id"],),
            ).fetchall()
            payload["findings"] = [
                json.loads(item["payload_json"]) for item in findings if item["payload_json"]
            ]
            return payload

    def clear_parsed_sessions_for_upload(self, upload_id: int) -> None:
        with self._connect() as connection:
            session_rows = connection.execute(
                "SELECT id FROM parsed_sessions WHERE upload_id = ?",
                (upload_id,),
            ).fetchall()
            for row in session_rows:
                connection.execute(
                    "DELETE FROM stored_findings WHERE session_id = ?",
                    (int(row["id"]),),
                )
            connection.execute("DELETE FROM parsed_sessions WHERE upload_id = ?", (upload_id,))

    def delete_upload(self, upload_id: int) -> bool:
        upload = self.get_upload(upload_id)
        if upload is None:
            return False
        self.clear_parsed_sessions_for_upload(upload_id)
        with self._connect() as connection:
            connection.execute("DELETE FROM uploads WHERE id = ?", (upload_id,))

        stored_path = Path(str(upload.get("stored_path") or ""))
        try:
            if stored_path.is_file():
                stored_path.unlink()
        except OSError:
            pass
        return True

    def find_upload_by_stored_path(self, stored_path: str) -> dict[str, Any] | None:
        resolved = str(Path(stored_path).expanduser().resolve())
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT id, original_name, stored_path, content_kind, size_bytes, sha256,
                       status, error_message, uploaded_at, session_name
                FROM uploads
                WHERE stored_path = ?
                LIMIT 1
                """,
                (resolved,),
            ).fetchone()
        return dict(row) if row is not None else None

    def load_cached_session_state(self, path: Path) -> dict[str, Any] | None:
        resolved = path.resolve()
        stat = resolved.stat()
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT mtime, size_bytes, lines_processed, state_json
                FROM jsonl_analytics_cache
                WHERE session_name = ?
                """,
                (resolved.name,),
            ).fetchone()
        if row is None:
            return None
        item = dict(row)
        if (
            float(item["mtime"]) == stat.st_mtime
            and int(item["size_bytes"]) == stat.st_size
        ):
            state = json.loads(item["state_json"])
            state["_lines_processed"] = int(item["lines_processed"])
            return state
        if int(item["size_bytes"]) < stat.st_size and float(item["mtime"]) <= stat.st_mtime:
            state = json.loads(item["state_json"])
            state["_lines_processed"] = int(item["lines_processed"])
            state["_incremental"] = True
            return state
        return None

    def store_cached_session_state(self, path: Path, state: dict[str, Any]) -> None:
        resolved = path.resolve()
        stat = resolved.stat()
        payload = {key: value for key, value in state.items() if not key.startswith("_")}
        lines_processed = int(state.get("_lines_processed") or count_jsonl_lines(resolved))
        updated_at = datetime.now(timezone.utc).isoformat()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO jsonl_analytics_cache (
                    session_name, source_path, mtime, size_bytes, lines_processed, state_json, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(session_name) DO UPDATE SET
                    source_path = excluded.source_path,
                    mtime = excluded.mtime,
                    size_bytes = excluded.size_bytes,
                    lines_processed = excluded.lines_processed,
                    state_json = excluded.state_json,
                    updated_at = excluded.updated_at
                """,
                (
                    resolved.name,
                    str(resolved),
                    stat.st_mtime,
                    stat.st_size,
                    lines_processed,
                    json.dumps(payload, ensure_ascii=False, sort_keys=True),
                    updated_at,
                ),
            )

    def invalidate_session_analytics_cache(self, session_name: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "DELETE FROM jsonl_analytics_cache WHERE session_name = ?",
                (session_name,),
            )

    def aggregate_stored_findings(self, *, limit: int = 500) -> dict[str, Any]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT sf.technique, sf.severity, sf.score, ps.session_name
                FROM stored_findings sf
                JOIN parsed_sessions ps ON ps.id = sf.session_id
                ORDER BY sf.id DESC
                LIMIT ?
                """,
                (max(1, limit),),
            ).fetchall()
        technique_counts: dict[str, int] = {}
        severity_counts: dict[str, int] = {}
        sessions: set[str] = set()
        for row in rows:
            item = dict(row)
            technique = str(item.get("technique") or "unclassified")
            severity = str(item.get("severity") or "unknown")
            technique_counts[technique] = technique_counts.get(technique, 0) + 1
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            if item.get("session_name"):
                sessions.add(str(item["session_name"]))
        return {
            "finding_rows": len(rows),
            "session_count": len(sessions),
            "technique_distribution": technique_counts,
            "severity_distribution": severity_counts,
        }

    def set_upload_status_for_path(
        self,
        stored_path: str,
        *,
        status: str,
        error_message: str | None = None,
        session_name: str | None = None,
    ) -> bool:
        upload = self.find_upload_by_stored_path(stored_path)
        if upload is None:
            return False
        self.update_upload(
            int(upload["id"]),
            status=status,
            error_message=error_message,
            session_name=session_name,
        )
        return True

    def list_uploads(self, *, limit: int = 50) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, original_name, stored_path, content_kind, size_bytes, sha256,
                       status, error_message, uploaded_at, session_name
                FROM uploads
                ORDER BY uploaded_at DESC
                LIMIT ?
                """,
                (max(1, limit),),
            ).fetchall()
        return [dict(row) for row in rows]

    def list_parsed_sessions(self, *, limit: int = 50) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, upload_id, session_name, source_path, event_count, finding_count,
                       primitive_count, parsed_at
                FROM parsed_sessions
                ORDER BY parsed_at DESC
                LIMIT ?
                """,
                (max(1, limit),),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_parsed_session(self, session_name: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT id, upload_id, session_name, source_path, event_count, finding_count,
                       primitive_count, stats_json, parsed_at
                FROM parsed_sessions
                WHERE session_name = ?
                """,
                (session_name,),
            ).fetchone()
            if row is None:
                return None
            payload = dict(row)
            payload["stats"] = json.loads(payload.pop("stats_json"))
            findings = connection.execute(
                """
                SELECT payload_json FROM stored_findings
                WHERE session_id = ?
                ORDER BY id ASC
                """,
                (payload["id"],),
            ).fetchall()
            payload["findings"] = [
                json.loads(item["payload_json"]) for item in findings if item["payload_json"]
            ]
            return payload


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def uploads_dir(logs_dir: Path | str | None = None) -> Path:
    directory = resolve_logs_dir(logs_dir) / "uploads"
    directory.mkdir(parents=True, exist_ok=True)
    return directory
