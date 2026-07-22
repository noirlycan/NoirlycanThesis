from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from noirlycan_backend.domain.permissions import (
    DEFAULT_ROLE_PERMISSIONS,
    normalize_role_permissions,
)
from noirlycan_backend.domain.ruleset import Ruleset
from noirlycan_core.storage.infrastructure.log_store import ensure_logs_dir


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_password(password: str, salt: str) -> str:
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        120_000,
    )
    return digest.hex()


class ConsoleDatabase:
    def __init__(self, logs_dir: Path | str | None = None) -> None:
        self._lock = threading.RLock()
        self._connection: sqlite3.Connection | None = None
        self.logs_dir = ensure_logs_dir(
            Path(logs_dir).expanduser().resolve() if logs_dir is not None else None
        )
        self.db_path = (self.logs_dir / "noirlycan.db").resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()
        self.seed_defaults()

    def close(self) -> None:
        with self._lock:
            if self._connection is not None:
                self._connection.close()
                self._connection = None

    def _ensure_connection(self) -> sqlite3.Connection:
        if self._connection is not None:
            return self._connection

        db_path = self.db_path
        if db_path.exists() and db_path.is_dir():
            raise sqlite3.OperationalError(f"database path is a directory: {db_path}")
        db_path.parent.mkdir(parents=True, exist_ok=True)
        if not os.access(db_path.parent, os.W_OK):
            raise sqlite3.OperationalError(f"logs directory is not writable: {db_path.parent}")
        try:
            connection = sqlite3.connect(str(db_path), timeout=30, check_same_thread=False)
        except sqlite3.OperationalError as exc:
            raise sqlite3.OperationalError(f"{exc} (path={db_path})") from exc
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        self._connection = connection
        return connection

    @contextmanager
    def _connect(self):
        with self._lock:
            connection = self._ensure_connection()
            try:
                yield connection
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def _init_schema(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS console_users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT NOT NULL UNIQUE,
                    display_name TEXT NOT NULL,
                    role TEXT NOT NULL,
                    password_salt TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS console_role_permissions (
                    role TEXT NOT NULL,
                    permission TEXT NOT NULL,
                    allowed INTEGER NOT NULL,
                    PRIMARY KEY (role, permission)
                );

                CREATE TABLE IF NOT EXISTS console_rulesets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    version INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,
                    is_active INTEGER NOT NULL DEFAULT 0,
                    saved_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS console_server_config (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    host TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    token TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS console_agents (
                    id TEXT PRIMARY KEY,
                    hostname TEXT NOT NULL,
                    os_name TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    watching TEXT NOT NULL DEFAULT '',
                    last_seen TEXT,
                    status TEXT NOT NULL DEFAULT 'offline',
                    auto_kill INTEGER NOT NULL DEFAULT 0,
                    enrolled_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS console_removed_findings (
                    finding_key TEXT PRIMARY KEY,
                    removed_by TEXT,
                    removed_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS console_killed_processes (
                    pid INTEGER NOT NULL,
                    agent_id TEXT NOT NULL,
                    image TEXT,
                    killed_at TEXT NOT NULL,
                    PRIMARY KEY (pid, agent_id)
                );

                CREATE TABLE IF NOT EXISTS console_audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    actor TEXT,
                    action TEXT NOT NULL,
                    detail_json TEXT,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS console_agent_commands (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    command TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    created_at TEXT NOT NULL,
                    delivered_at TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_agent_commands_pending
                    ON console_agent_commands(agent_id, status);
                """
            )

    def seed_defaults(self) -> None:
        demo_users = [
            ("admin@lab", "Lab Admin", "Admin", "admin"),
            ("analyst@lab", "Lab Analyst", "Analyst", "analyst"),
            ("viewer@lab", "Lab Viewer", "Viewer", "viewer"),
        ]
        with self._connect() as connection:
            count = connection.execute("SELECT COUNT(*) FROM console_users").fetchone()[0]
            if count == 0:
                now = _utc_now()
                for email, name, role, password in demo_users:
                    salt = secrets.token_hex(16)
                    connection.execute(
                        """
                        INSERT INTO console_users (
                            email, display_name, role, password_salt, password_hash,
                            created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            email,
                            name,
                            role,
                            salt,
                            _hash_password(password, salt),
                            now,
                            now,
                        ),
                    )

            perm_count = connection.execute(
                "SELECT COUNT(*) FROM console_role_permissions"
            ).fetchone()[0]
            if perm_count == 0:
                for role, perms in DEFAULT_ROLE_PERMISSIONS.items():
                    for key, allowed in perms.items():
                        connection.execute(
                            """
                            INSERT INTO console_role_permissions (role, permission, allowed)
                            VALUES (?, ?, ?)
                            """,
                            (role, key, 1 if allowed else 0),
                        )

            rules_count = connection.execute(
                "SELECT COUNT(*) FROM console_rulesets"
            ).fetchone()[0]
            if rules_count == 0:
                payload = Ruleset().to_dict()
                connection.execute(
                    """
                    INSERT INTO console_rulesets (version, payload_json, is_active, saved_at)
                    VALUES (1, ?, 1, ?)
                    """,
                    (json.dumps(payload), _utc_now()),
                )

            server_count = connection.execute(
                "SELECT COUNT(*) FROM console_server_config"
            ).fetchone()[0]
            if server_count == 0:
                connection.execute(
                    """
                    INSERT INTO console_server_config (id, host, port, token, updated_at)
                    VALUES (1, '127.0.0.1', 8765, ?, ?)
                    """,
                    (secrets.token_urlsafe(24), _utc_now()),
                )

    def authenticate(self, email: str, password: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM console_users WHERE lower(email) = lower(?)",
                (email.strip(),),
            ).fetchone()
        if row is None:
            return None
        expected = _hash_password(password, row["password_salt"])
        if expected != row["password_hash"]:
            return None
        return self._user_payload(row)

    def get_user_by_email(self, email: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM console_users WHERE lower(email) = lower(?)",
                (email.strip(),),
            ).fetchone()
        if row is None:
            return None
        return self._user_payload(row)

    def list_team(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT email, display_name, role FROM console_users ORDER BY email"
            ).fetchall()
        return [
            {
                "email": row["email"],
                "name": row["display_name"],
                "role": row["role"],
                "initial": (row["display_name"] or row["email"])[:1].upper(),
            }
            for row in rows
        ]

    def update_profile(
        self,
        email: str,
        *,
        display_name: str | None = None,
        new_password: str | None = None,
        current_password: str | None = None,
    ) -> dict[str, Any] | None:
        user = self.authenticate(email, current_password or "") if new_password else self.get_user_by_email(email)
        if user is None and new_password:
            return None
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM console_users WHERE lower(email) = lower(?)",
                (email.strip(),),
            ).fetchone()
            if row is None:
                return None
            if new_password:
                if not current_password:
                    return None
                if _hash_password(current_password, row["password_salt"]) != row["password_hash"]:
                    return None
                salt = secrets.token_hex(16)
                connection.execute(
                    """
                    UPDATE console_users
                    SET display_name = ?, password_salt = ?, password_hash = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        display_name or row["display_name"],
                        salt,
                        _hash_password(new_password, salt),
                        _utc_now(),
                        row["id"],
                    ),
                )
            elif display_name:
                connection.execute(
                    "UPDATE console_users SET display_name = ?, updated_at = ? WHERE id = ?",
                    (display_name, _utc_now(), row["id"]),
                )
        return self.get_user_by_email(email)

    def add_team_member(self, *, name: str, email: str, role: str, password: str) -> dict[str, Any] | None:
        from noirlycan_backend.domain.permissions import ROLES

        cleaned_email = email.strip()
        cleaned_name = name.strip()
        if not cleaned_name:
            raise ValueError("Display name is required")
        if role not in ROLES:
            raise ValueError(f"Invalid role: {role}")
        salt = secrets.token_hex(16)
        now = _utc_now()
        with self._connect() as connection:
            existing = connection.execute(
                "SELECT 1 FROM console_users WHERE lower(email) = lower(?)",
                (cleaned_email,),
            ).fetchone()
            if existing is not None:
                return None
            connection.execute(
                """
                INSERT INTO console_users (
                    email, display_name, role, password_salt, password_hash,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    cleaned_email,
                    cleaned_name,
                    role,
                    salt,
                    _hash_password(password, salt),
                    now,
                    now,
                ),
            )
        return {"email": cleaned_email, "name": cleaned_name, "role": role}

    def remove_team_member(self, email: str) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                "DELETE FROM console_users WHERE lower(email) = lower(?)",
                (email.strip(),),
            )
            return cursor.rowcount > 0

    def update_member_role(self, email: str, role: str) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE console_users SET role = ?, updated_at = ? WHERE lower(email) = lower(?)",
                (role, _utc_now(), email.strip()),
            )
            return cursor.rowcount > 0

    def load_role_permissions(self) -> dict[str, dict[str, bool]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT role, permission, allowed FROM console_role_permissions"
            ).fetchall()
        raw: dict[str, dict[str, bool]] = {}
        for row in rows:
            raw.setdefault(row["role"], {})[row["permission"]] = bool(row["allowed"])
        return normalize_role_permissions(raw)

    def save_role_permissions(self, matrix: dict[str, dict[str, bool]]) -> dict[str, dict[str, bool]]:
        normalized = normalize_role_permissions(matrix)
        with self._connect() as connection:
            connection.execute("DELETE FROM console_role_permissions")
            for role, perms in normalized.items():
                for key, allowed in perms.items():
                    connection.execute(
                        """
                        INSERT INTO console_role_permissions (role, permission, allowed)
                        VALUES (?, ?, ?)
                        """,
                        (role, key, 1 if allowed else 0),
                    )
        return normalized

    def load_ruleset(self) -> Ruleset:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT payload_json FROM console_rulesets
                WHERE is_active = 1
                ORDER BY version DESC
                LIMIT 1
                """
            ).fetchone()
        if row is None:
            return Ruleset()
        try:
            payload = json.loads(row["payload_json"])
        except json.JSONDecodeError:
            return Ruleset()
        return Ruleset.from_dict(payload)

    def save_ruleset(self, ruleset: Ruleset) -> Ruleset:
        with self._connect() as connection:
            version = connection.execute(
                "SELECT COALESCE(MAX(version), 0) + 1 FROM console_rulesets"
            ).fetchone()[0]
            connection.execute("UPDATE console_rulesets SET is_active = 0")
            connection.execute(
                """
                INSERT INTO console_rulesets (version, payload_json, is_active, saved_at)
                VALUES (?, ?, 1, ?)
                """,
                (version, json.dumps(ruleset.to_dict()), _utc_now()),
            )
        return ruleset

    def load_server_config(self) -> dict[str, Any]:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM console_server_config WHERE id = 1").fetchone()
        if row is None:
            token = secrets.token_urlsafe(24)
            return {"host": "127.0.0.1", "port": 8765, "token": token}
        return {
            "host": row["host"],
            "port": int(row["port"]),
            "token": row["token"],
        }

    def save_server_config(self, *, host: str, port: int, token: str | None = None) -> dict[str, Any]:
        current = self.load_server_config()
        payload = {
            "host": host.strip() or current["host"],
            "port": int(port),
            "token": token or current["token"],
        }
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO console_server_config (id, host, port, token, updated_at)
                VALUES (1, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    host = excluded.host,
                    port = excluded.port,
                    token = excluded.token,
                    updated_at = excluded.updated_at
                """,
                (payload["host"], payload["port"], payload["token"], _utc_now()),
            )
        return payload

    def regenerate_token(self) -> str:
        token = secrets.token_urlsafe(24)
        config = self.load_server_config()
        self.save_server_config(host=config["host"], port=config["port"], token=token)
        return token

    def list_agents(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM console_agents ORDER BY last_seen DESC"
            ).fetchall()
        return [dict(row) | {"auto_kill": bool(row["auto_kill"])} for row in rows]

    def upsert_agent(
        self,
        agent_id: str,
        *,
        hostname: str,
        os_name: str,
        mode: str,
        watching: str = "",
    ) -> dict[str, Any]:
        now = _utc_now()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO console_agents (
                    id, hostname, os_name, mode, watching, last_seen, status, enrolled_at
                ) VALUES (?, ?, ?, ?, ?, ?, 'online', ?)
                ON CONFLICT(id) DO UPDATE SET
                    hostname = excluded.hostname,
                    os_name = excluded.os_name,
                    mode = excluded.mode,
                    watching = excluded.watching,
                    last_seen = excluded.last_seen,
                    status = 'online'
                """,
                (agent_id, hostname, os_name, mode, watching, now, now),
            )
        agents = self.list_agents()
        return next(item for item in agents if item["id"] == agent_id)

    def set_agent_auto_kill(self, agent_id: str, enabled: bool) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE console_agents SET auto_kill = ? WHERE id = ?",
                (1 if enabled else 0, agent_id),
            )
            return cursor.rowcount > 0

    def verify_agent_token(self, token: str) -> bool:
        config = self.load_server_config()
        return secrets.compare_digest(str(config.get("token") or ""), token)

    def list_removed_findings(self) -> set[str]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT finding_key FROM console_removed_findings"
            ).fetchall()
        return {row["finding_key"] for row in rows}

    def remove_finding(self, finding_key: str, *, actor: str | None = None) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO console_removed_findings (finding_key, removed_by, removed_at)
                VALUES (?, ?, ?)
                """,
                (finding_key, actor, _utc_now()),
            )
            self._audit(connection, actor, "finding.remove", {"finding_key": finding_key})

    def record_kill(self, *, agent_id: str, pid: int, image: str | None, actor: str | None) -> None:
        self.enqueue_agent_command(agent_id, "kill", {"pid": pid, "image": image})
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO console_killed_processes (pid, agent_id, image, killed_at)
                VALUES (?, ?, ?, ?)
                """,
                (pid, agent_id, image, _utc_now()),
            )
            self._audit(connection, actor, "process.kill", {"agent_id": agent_id, "pid": pid, "image": image})

    def enqueue_agent_command(self, agent_id: str, command: str, payload: dict[str, Any]) -> int:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO console_agent_commands (agent_id, command, payload_json, status, created_at)
                VALUES (?, ?, ?, 'pending', ?)
                """,
                (agent_id, command, json.dumps(payload), _utc_now()),
            )
            return int(cursor.lastrowid)

    def pop_agent_commands(self, agent_id: str, *, limit: int = 20) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, command, payload_json FROM console_agent_commands
                WHERE agent_id = ? AND status = 'pending'
                ORDER BY id ASC
                LIMIT ?
                """,
                (agent_id, limit),
            ).fetchall()
            ids = [row["id"] for row in rows]
            if ids:
                placeholders = ",".join("?" for _ in ids)
                connection.execute(
                    f"""
                    UPDATE console_agent_commands
                    SET status = 'delivered', delivered_at = ?
                    WHERE id IN ({placeholders})
                    """,
                    (_utc_now(), *ids),
                )
        commands: list[dict[str, Any]] = []
        for row in rows:
            try:
                payload = json.loads(row["payload_json"])
            except json.JSONDecodeError:
                payload = {}
            if not isinstance(payload, dict):
                payload = {}
            commands.append({"command": row["command"], **payload})
        return commands

    def list_killed(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT pid, agent_id, image, killed_at FROM console_killed_processes"
            ).fetchall()
        return [dict(row) for row in rows]

    def _audit(
        self,
        connection: sqlite3.Connection,
        actor: str | None,
        action: str,
        detail: dict[str, Any] | None = None,
    ) -> None:
        connection.execute(
            """
            INSERT INTO console_audit_log (actor, action, detail_json, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (actor, action, json.dumps(detail or {}), _utc_now()),
        )

    @staticmethod
    def _user_payload(row: sqlite3.Row) -> dict[str, Any]:
        name = row["display_name"]
        return {
            "email": row["email"],
            "name": name,
            "role": row["role"],
            "initial": (name or row["email"])[:1].upper(),
        }
