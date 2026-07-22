from __future__ import annotations

from pathlib import Path
from typing import Any

from noirlycan_core.analysis.domain.correlation import Correlator
from noirlycan_core.runtime.agent_policy import AgentPolicy, apply_ruleset_to_agent, load_agent_policy
from noirlycan_agent.collector.infrastructure.frida_manager import FridaInjectionMonitor


def apply_server_policy(rules: dict[str, Any], logs_dir: Path | str, *, version: int) -> AgentPolicy:
    """Apply dashboard rules locally when the console pushes a newer version."""
    return apply_ruleset_to_agent(logs_dir, rules, version=version)


def resolve_active_policy(
    logs_dir: Path | str | None,
    remote_policy: AgentPolicy | None = None,
) -> AgentPolicy | None:
    if remote_policy is not None:
        return remote_policy
    if logs_dir is None:
        return None
    return load_agent_policy(logs_dir)


def apply_runtime_policy(
    correlator: Correlator,
    policy: AgentPolicy | None,
    *,
    monitor: FridaInjectionMonitor | None = None,
) -> None:
    """Push dashboard policy into the correlator and Frida hook script."""
    if policy is not None:
        correlator.apply_policy(policy)
    if monitor is not None and monitor.reload_policy(policy):
        version = policy.version if policy is not None else 0
        print(f"[+] Frida hooks synced from console policy (v{version})", flush=True)
