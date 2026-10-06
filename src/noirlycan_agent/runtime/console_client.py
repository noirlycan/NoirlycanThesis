"""HTTP client for the console (backend) as seen from a lab agent."""

from __future__ import annotations

import hashlib
import json
import platform
import socket
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from noirlycan_core.runtime.agent_identity import load_agent_credentials, resolve_agent_credentials, save_agent_credentials
from noirlycan_core.runtime.command_signing import CommandVerifier
from noirlycan_core.runtime.agent_policy import AgentPolicy, apply_ruleset_to_agent, load_agent_policy

SEVERITY_RANK = {"INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}
HEARTBEAT_SECONDS = 5.0
COMMAND_POLL_SECONDS = 2.0
ERROR_LOG_INTERVAL_SECONDS = 60.0


@dataclass
class AutoKillPolicy:
    enabled: bool = False
    min_severity: str = "CRITICAL"

    @classmethod
    def from_policy(cls, policy: AgentPolicy) -> AutoKillPolicy:
        return cls(enabled=policy.auto_kill, min_severity=policy.auto_kill_min_severity)


class ConsoleClient:
    """hello / heartbeat / goodbye, batched ingest, command poll, policy sync, sample transfer."""

    def __init__(
        self,
        server: str,
        token: str,
        *,
        agent_id: str | None = None,
        mode: str = "run",
        timeout: float = 8.0,
        logs_dir: Path | str | None = None,
        command_key: str | None = None,
    ) -> None:
        host = server.strip()
        if not host.startswith(("http://", "https://")):
            host = f"http://{host}"
        self.base_url = host.rstrip("/")
        self.token = token.strip()
        self.mode = mode
        self.timeout = timeout
        self.logs_dir = Path(logs_dir).expanduser().resolve() if logs_dir else None
        self.agent_id = resolve_agent_credentials(self.logs_dir, agent_id, None)[0]
        self.verifier: CommandVerifier | None = None
        self.command_key: str | None = None
        pinned = command_key or load_agent_credentials(self.logs_dir).get("command_key")
        if pinned:
            self._pin(pinned, announce=bool(command_key))
        self.policy = load_agent_policy(self.logs_dir) if self.logs_dir else None
        self.policy_version = self.policy.version if self.policy else 0
        self.auto_kill = AutoKillPolicy.from_policy(self.policy) if self.policy else AutoKillPolicy()
        self.agent_auto_kill = False
        self._commands: list[dict[str, Any]] = []
        self._lock = threading.Lock()  # The uploader thread also absorbs responses.
        self._last_heartbeat = 0.0
        self._last_command_poll = 0.0
        self._last_error_log: dict[str, float] = {}
        self.last_success = 0.0

    # -- lifecycle ----------------------------------------------------------

    def hello(self, *, watching: str = "") -> dict[str, Any]:
        response = self._post("/api/ingest/hello", self._identity(watching))
        self._absorb(response, force_policy=True)
        self._last_heartbeat = time.monotonic()
        return response

    def heartbeat(self, *, watching: str = "", force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self._last_heartbeat < HEARTBEAT_SECONDS:
            return
        self._last_heartbeat = now
        try:
            self._absorb(self._post("/api/ingest/heartbeat", self._identity(watching)))
        except Exception as exc:  # noqa: BLE001
            self._log_error("heartbeat", exc)

    def goodbye(self) -> None:
        try:
            self._post("/api/ingest/goodbye", self._identity(""))
        except Exception as exc:  # noqa: BLE001
            print(f"[!] Console goodbye failed: {exc}", flush=True)

    # -- events and commands ------------------------------------------------

    def ingest_batch(self, events: list[dict[str, Any]]) -> None:
        self._absorb(self._post("/api/ingest/batch", {"events": events}))

    def poll_commands(self) -> list[dict[str, Any]]:
        """Commands piggy-backed on any response, plus a direct poll every few seconds."""
        now = time.monotonic()
        if now - self._last_command_poll >= COMMAND_POLL_SECONDS:
            self._last_command_poll = now
            try:
                self._absorb(self._get(f"/api/agents/{self.agent_id}/commands"))
            except Exception as exc:  # noqa: BLE001
                self._log_error("command poll", exc)
        with self._lock:
            commands, self._commands = self._commands, []
        return commands

    def download_sample(self, upload_id: int, destination: Path, expected_sha256: str) -> Path:
        """Fetch an assigned sample and verify its SHA-256 before it can be executed."""
        request = urllib.request.Request(
            f"{self.base_url}/api/agents/{self.agent_id}/samples/{upload_id}",
            headers=self._headers(),
        )
        digest = hashlib.sha256()
        partial = destination.with_suffix(destination.suffix + ".part")
        destination.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(request, timeout=max(self.timeout, 60)) as response, partial.open("wb") as out:
            while chunk := response.read(1024 * 1024):
                digest.update(chunk)
                out.write(chunk)
        if digest.hexdigest().lower() != expected_sha256.lower():
            partial.unlink(missing_ok=True)
            raise ValueError("sample SHA-256 mismatch")
        partial.replace(destination)
        return destination

    def report_sample_status(self, upload_id: int, status: str, *, agent_path: str | None = None, error: str | None = None) -> None:
        try:
            self._post(
                f"/api/agents/{self.agent_id}/samples/{upload_id}/status",
                {"status": status, "agent_path": agent_path, "error": error},
            )
        except Exception as exc:  # noqa: BLE001
            self._log_error("sample status", exc)

    def report_command_result(self, command_id: int, ok: bool, detail: str | None = None) -> None:
        try:
            self._post(f"/api/agents/{self.agent_id}/commands/{command_id}/result", {"ok": ok, "detail": detail})
        except Exception as exc:  # noqa: BLE001
            self._log_error("command result", exc)

    def should_auto_kill(self, severity: str) -> bool:
        if not (self.agent_auto_kill or self.auto_kill.enabled):
            return False
        threshold = SEVERITY_RANK.get(self.auto_kill.min_severity, 5)
        return SEVERITY_RANK.get(str(severity).upper(), 0) >= threshold

    # -- console responses --------------------------------------------------

    def _absorb(self, response: dict[str, Any] | None, *, force_policy: bool = False) -> None:
        if not isinstance(response, dict):
            return
        commands = response.get("commands")
        if isinstance(commands, list):
            with self._lock:
                self._commands.extend(item for item in commands if isinstance(item, dict))
        agent = response.get("agent")
        if isinstance(agent, dict):
            self.agent_auto_kill = bool(agent.get("auto_kill"))
        offered = response.get("command_public_key")
        if isinstance(offered, str) and offered:
            if self.verifier is None:
                print("[!] No command key in config; pinning the console's key on first use", flush=True)
                self._pin(offered, announce=False)
            elif offered != self.command_key:
                print("[!] Console offered a different command key; keeping the pinned one", flush=True)
        self._apply_policy(response, force=force_policy)

    def _pin(self, public_key: str, *, announce: bool) -> None:
        self.verifier = CommandVerifier(public_key, self.agent_id)
        self.command_key = public_key
        save_agent_credentials(self.agent_id, self.logs_dir, command_key=public_key)
        if announce:
            print("[+] Command signing key pinned from config", flush=True)

    def _apply_policy(self, response: dict[str, Any], *, force: bool = False) -> None:
        rules = response.get("rules")
        if not isinstance(rules, dict):
            return
        version = int(response.get("rules_version") or 0)
        if not force and version <= self.policy_version:
            if self.policy is None:
                self.auto_kill = AutoKillPolicy(
                    enabled=bool(rules.get("auto_kill")),
                    min_severity=str(rules.get("auto_kill_min_severity") or "CRITICAL").upper(),
                )
            return
        try:
            if self.logs_dir is not None:
                self.policy = apply_ruleset_to_agent(self.logs_dir, rules, version=version)
            else:
                self.policy = AgentPolicy.from_ruleset_dict(rules, version=version)
        except Exception as exc:  # noqa: BLE001
            print(f"[!] Policy sync failed: {exc}", flush=True)
            return
        self.policy_version = version
        self.auto_kill = AutoKillPolicy.from_policy(self.policy)
        print(f"[+] Policy synced from console ({'startup' if force else 'update'}, v{version})", flush=True)

    # -- transport ----------------------------------------------------------

    def _identity(self, watching: str) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "hostname": socket.gethostname(),
            "os_name": platform.system() or "Windows",
            "mode": self.mode,
            "watching": watching,
            "ip_address": _local_ip_for(self.base_url),
        }

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Agent-Id": self.agent_id,
        }

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")
        return self._send(urllib.request.Request(f"{self.base_url}{path}", data=body, headers=self._headers(), method="POST"))

    def _get(self, path: str) -> dict[str, Any]:
        return self._send(urllib.request.Request(f"{self.base_url}{path}", headers=self._headers()))

    def _send(self, request: urllib.request.Request) -> dict[str, Any]:
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            raise RuntimeError(exc.read().decode("utf-8", errors="replace") or str(exc)) from exc
        data = json.loads(raw) if raw.strip() else {}
        self.last_success = time.monotonic()
        return data if isinstance(data, dict) else {}

    def _log_error(self, label: str, exc: Exception) -> None:
        now = time.monotonic()
        if now - self._last_error_log.get(label, 0.0) >= ERROR_LOG_INTERVAL_SECONDS:
            self._last_error_log[label] = now
            print(f"[!] Console {label} failed: {exc}", flush=True)


def _local_ip_for(server_url: str) -> str:
    """Source address the OS would use to reach the console (no packet is sent)."""
    parsed = urlparse(server_url)
    host = parsed.hostname or "8.8.8.8"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect((host, port))
            return sock.getsockname()[0]
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return ""
