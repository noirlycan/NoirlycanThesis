"""Frida hook script is driven by dashboard runtime config."""

from __future__ import annotations

import json

from noirlycan_agent.sensors.frida_hook_catalog import build_runtime_config
from noirlycan_agent.sensors.frida_monitor import build_hook_script
from noirlycan_core.runtime.agent_policy import AgentPolicy


def _config_from_script(script: str) -> dict:
    line = script.split("\n", 1)[0]
    return json.loads(line.split("=", 1)[1].strip().rstrip(";"))


def test_build_hook_script_injects_runtime_config() -> None:
    policy = AgentPolicy(
        version=3,
        alloc=["VirtualAllocEx"],
        write=["WriteProcessMemory"],
        exec=["CreateRemoteThread"],
    )
    script = build_hook_script(policy)
    assert script.startswith("globalThis.__NOIRLYCAN_CONFIG__ = ")
    config = _config_from_script(script)
    assert config["version"] == 3
    assert config["policy"]["alloc"] == ["VirtualAllocEx"]
    exports = {item["export"] for item in config["hooks"]}
    assert "VirtualAllocEx" in exports
    assert "CreateProcessW" in exports  # support tier stays enabled
    assert "function hook(" in script
    assert "const API_HANDLERS" in script


def test_build_hook_script_without_policy_enables_full_lab() -> None:
    config = build_runtime_config(None)
    assert config["version"] == 0
    assert config["policy"]["alloc"] == []
    assert len(config["hooks"]) > 100
