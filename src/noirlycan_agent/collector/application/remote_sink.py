from __future__ import annotations

import json
import platform
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from noirlycan_core.kernel.entities.models import Finding
from noirlycan_core.runtime.agent_identity import resolve_agent_id
from noirlycan_core.runtime.agent_policy import AgentPolicy, load_agent_policy
from noirlycan_agent.collector.application.collector_runtime import JsonlWriter, jsonable
from noirlycan_agent.collector.application.policy_sync import apply_server_policy


SEVERITY_RANK = {"INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}


from urllib.parse import urlparse


def _local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        pass
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return ""


def _local_ip_for_server(server_url: str) -> str:
    parsed = urlparse(server_url if "://" in server_url else f"http://{server_url}")
    host = parsed.hostname
    if not host:
        return _local_ip()
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect((host, port))
            return sock.getsockname()[0]
    except OSError:
        return _local_ip()


@dataclass
class AgentRuntimePolicy:
    auto_kill: bool = False
    auto_kill_min_severity: str = "CRITICAL"

    @classmethod
    def from_policy(cls, policy: AgentPolicy) -> AgentRuntimePolicy:
        return cls(
            auto_kill=policy.auto_kill,
            auto_kill_min_severity=policy.auto_kill_min_severity,
        )


class ConsoleRemoteClient:
    """Console backend client: hello, ingest, policy sync, and command drain."""

    def __init__(
        self,
        server: str,
        token: str,
        *,
        agent_id: str | None = None,
        session_name: str | None = None,
        mode: str = "run",
        timeout: float = 8.0,
        logs_dir: Path | str | None = None,
    ) -> None:
        host = server.strip()
        if not host.startswith("http://") and not host.startswith("https://"):
            host = f"http://{host}"
        self.base_url = host.rstrip("/")
        self.token = token.strip()
        self.session_name = session_name
        self.mode = mode
        self.timeout = timeout
        self.logs_dir = Path(logs_dir).expanduser().resolve() if logs_dir else None
        self.agent_id = resolve_agent_id(self.logs_dir, agent_id)
        self.policy = load_agent_policy(self.logs_dir) if self.logs_dir else None
        self.policy_version = self.policy.version if self.policy else 0
        self.runtime = AgentRuntimePolicy.from_policy(self.policy) if self.policy else AgentRuntimePolicy()
        self.agent_auto_kill = False
        self._pending_kills: list[dict[str, Any]] = []

    def hello(self, *, watching: str = "") -> dict[str, Any]:
        payload = {
            "agent_id": self.agent_id,
            "hostname": socket.gethostname(),
            "os_name": platform.system() or "Windows",
            "mode": self.mode,
            "watching": watching,
            "ip_address": _local_ip_for_server(self.base_url),
        }
        response = self._post("/api/ingest/hello", payload)
        self._apply_console_response(response)
        return response

    def write(self, event_type: str, value: Any) -> None:
        payload = {
            "type": event_type,
            "value": jsonable(value),
            "session": self.session_name,
        }
        try:
            response = self._post("/api/ingest", payload)
            if isinstance(response, dict):
                session = response.get("session")
                if isinstance(session, str) and session:
                    self.session_name = session
                commands = response.get("commands")
                if isinstance(commands, list):
                    self._pending_kills.extend(item for item in commands if isinstance(item, dict))
                self._apply_console_response(response)
        except Exception as exc:
            print(f"[!] Console ingest failed: {exc}", flush=True)

    def poll_commands(self) -> list[dict[str, Any]]:
        try:
            response = self._get(f"/api/agents/{self.agent_id}/commands")
            commands = response.get("commands") if isinstance(response, dict) else []
            if isinstance(commands, list):
                self._pending_kills.extend(item for item in commands if isinstance(item, dict))
        except Exception:
            pass
        pending = list(self._pending_kills)
        self._pending_kills.clear()
        return pending

    def should_auto_kill(self, severity: str, *, agent_auto_kill: bool = False) -> bool:
        if not agent_auto_kill and not self.runtime.auto_kill:
            return False
        threshold = SEVERITY_RANK.get(self.runtime.auto_kill_min_severity, 5)
        return SEVERITY_RANK.get(str(severity).upper(), 0) >= threshold

    def _apply_console_response(self, response: dict[str, Any] | None) -> None:
        if not isinstance(response, dict):
            return
        agent_raw = response.get("agent")
        if isinstance(agent_raw, dict):
            self.agent_auto_kill = bool(agent_raw.get("auto_kill"))
        rules_raw = response.get("rules")
        version = int(response.get("rules_version") or 0)
        if not isinstance(rules_raw, dict):
            return
        if version > self.policy_version and self.logs_dir is not None:
            try:
                self.policy = apply_server_policy(rules_raw, self.logs_dir, version=version)
                self.policy_version = version
                self.runtime = AgentRuntimePolicy.from_policy(self.policy)
                print(f"[+] Policy synced from console (v{version})", flush=True)
            except Exception as exc:
                print(f"[!] Policy sync failed: {exc}", flush=True)
        elif self.policy is None:
            self.runtime = AgentRuntimePolicy(
                auto_kill=bool(rules_raw.get("auto_kill")),
                auto_kill_min_severity=str(rules_raw.get("auto_kill_min_severity") or "CRITICAL").upper(),
            )

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Agent-Id": self.agent_id,
        }

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=json.dumps(payload).encode("utf-8"),
            headers=self._headers(),
            method="POST",
        )
        return self._read_json(request)

    def _get(self, path: str) -> dict[str, Any]:
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            headers=self._headers(),
            method="GET",
        )
        return self._read_json(request)

    def _read_json(self, request: urllib.request.Request) -> dict[str, Any]:
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(detail or str(exc)) from exc
        if not raw.strip():
            return {}
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}


class RemoteJsonlWriter:
    """Write locally and mirror events to the console."""

    def __init__(self, local: JsonlWriter, remote: ConsoleRemoteClient | None = None) -> None:
        self.local = local
        self.remote = remote

    @property
    def path(self):
        return self.local.path

    def write(self, event_type: str, value: Any) -> None:
        self.local.write(event_type, value)
        if self.remote is not None:
            self.remote.write(event_type, value)
            if event_type == "finding":
                self._maybe_auto_kill(value)

    def _maybe_auto_kill(self, value: Any) -> None:
        if self.remote is None:
            return
        severity = ""
        target_pid: int | None = None
        if isinstance(value, Finding):
            severity = value.severity.value
            target_pid = value.target_pid
        elif isinstance(value, dict):
            severity = str(value.get("severity") or "")
            raw_pid = value.get("target_pid")
            target_pid = int(raw_pid) if raw_pid is not None else None
        if target_pid is None or target_pid <= 0:
            return
        if not self.remote.should_auto_kill(severity, agent_auto_kill=self.remote.agent_auto_kill):
            return
        if kill_process(target_pid):
            print(f"[+] Auto-kill executed for PID {target_pid} ({severity})", flush=True)

    def flush(self) -> None:
        self.local.flush()

    def close(self) -> None:
        self.local.close()


def kill_process(pid: int) -> bool:
    if pid <= 0:
        return False
    if platform.system().lower() == "windows":
        import subprocess

        result = subprocess.run(
            ["taskkill", "/PID", str(pid), "/F"],
            capture_output=True,
            text=True,
            check=False,
        )
        return result.returncode == 0
    import os
    import signal

    try:
        os.kill(pid, signal.SIGTERM)
        return True
    except OSError:
        return False


def drain_agent_commands(remote: ConsoleRemoteClient | None) -> None:
    if remote is None:
        return
    for command in remote.poll_commands():
        if str(command.get("command") or command.get("type")) != "kill":
            continue
        pid = int(command.get("pid") or 0)
        if kill_process(pid):
            print(f"[+] Kill command executed for PID {pid}", flush=True)
        else:
            print(f"[!] Kill command failed for PID {pid}", flush=True)
