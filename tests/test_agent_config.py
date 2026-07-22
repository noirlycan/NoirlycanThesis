from __future__ import annotations

from pathlib import Path

from noirlycan_core.runtime.agent_config import load_agent_config


def test_load_agent_config_toml(tmp_path: Path) -> None:
    path = tmp_path / "noirlycan-agent.toml"
    path.write_text(
        """
[server]
endpoint = "172.16.239.1:8888"
agent_id = "win10-lab"
token = "secret-token"

[run]
watch_sysmon = true
auto_attach_new_processes = true
""".strip(),
        encoding="utf-8",
    )
    config = load_agent_config(path)
    assert config.server == "172.16.239.1:8888"
    assert config.agent_id == "win10-lab"
    assert config.token == "secret-token"
    assert config.watch_sysmon is True
    assert config.auto_attach_new_processes is True
