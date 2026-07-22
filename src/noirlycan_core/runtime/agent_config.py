from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class AgentConfig:
    server: str = ""
    agent_id: str = ""
    token: str = ""
    watch_sysmon: bool = True
    auto_attach_new_processes: bool = True


def _parse_bool(value: str, default: bool) -> bool:
    text = str(value or "").strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    return default


def _read_tomlish(text: str) -> dict[str, dict[str, str]]:
    sections: dict[str, dict[str, str]] = {}
    current = ""
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1].strip().lower()
            sections.setdefault(current, {})
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        sections.setdefault(current, {})[key.strip().lower()] = value.strip().strip('"').strip("'")
    return sections


def load_agent_config(path: Path | str) -> AgentConfig:
    text = Path(path).expanduser().read_text(encoding="utf-8")
    sections = _read_tomlish(text)
    server = sections.get("server", {})
    run = sections.get("run", {})
    endpoint = str(server.get("endpoint") or server.get("server") or "").strip()
    if not endpoint and server.get("host"):
        port = str(server.get("port") or "8765").strip()
        endpoint = f"{server['host'].strip()}:{port}"
    return AgentConfig(
        server=endpoint,
        agent_id=str(server.get("agent_id") or server.get("id") or "").strip(),
        token=str(server.get("token") or "").strip(),
        watch_sysmon=_parse_bool(run.get("watch_sysmon", "true"), True),
        auto_attach_new_processes=_parse_bool(
            run.get("auto_attach_new_processes", run.get("auto_attach", "true")),
            True,
        ),
    )


def apply_agent_config(args, config: AgentConfig) -> None:
    if config.server and not str(getattr(args, "server", "") or "").strip():
        args.server = config.server
    if config.agent_id and not str(getattr(args, "agent_id", "") or "").strip():
        args.agent_id = config.agent_id
    if config.token and not str(getattr(args, "token", "") or "").strip():
        args.token = config.token
    if config.watch_sysmon and not getattr(args, "watch_sysmon", False):
        args.watch_sysmon = True
    if config.auto_attach_new_processes and not getattr(args, "auto_attach_new_processes", False):
        args.auto_attach_new_processes = True
