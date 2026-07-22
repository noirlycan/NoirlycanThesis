from __future__ import annotations

from typing import Any


def agent_config_toml(server: dict[str, Any], agent: dict[str, Any]) -> str:
    endpoint = f"{server['host']}:{server['port']}"
    agent_id = str(agent.get("id") or "")
    token = str(agent.get("enrollment_token") or "")
    display = str(agent.get("display_name") or agent.get("label") or agent_id)
    return "\n".join(
        [
            "# Noirlycan agent config — copy to VM and run:",
            "#   noirlycan-agent run --config .\\noirlycan-agent.toml --watch-sysmon",
            f"# Workstation: {display}",
            "",
            "[server]",
            f'endpoint = "{endpoint}"',
            f'agent_id = "{agent_id}"',
            f'token = "{token}"',
            "",
            "[run]",
            "watch_sysmon = true",
            "auto_attach_new_processes = true",
            "",
        ]
    )
