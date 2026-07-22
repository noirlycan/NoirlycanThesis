from __future__ import annotations

from noirlycan_backend.domain.ruleset import Ruleset
from noirlycan_core.runtime.agent_policy import apply_ruleset_to_agent, load_agent_policy
from noirlycan_agent.collector.application.remote_sink import ConsoleRemoteClient


def test_remote_client_without_local_policy_file(tmp_path) -> None:
    client = ConsoleRemoteClient(
        "127.0.0.1:8888",
        "test-token",
        logs_dir=tmp_path,
    )
    assert client.policy is None
    assert client.policy_version == 0


def test_remote_client_force_sync_on_same_version(tmp_path) -> None:
    rules_v2 = Ruleset(min_primitives=3, capture=5).to_dict()
    apply_ruleset_to_agent(tmp_path, rules_v2, version=2)
    client = ConsoleRemoteClient(
        "127.0.0.1:8888",
        "test-token",
        logs_dir=tmp_path,
    )
    assert client.policy is not None
    assert client.policy.min_primitives == 3
    assert client.policy_version == 2

    updated = Ruleset(min_primitives=2, capture=7).to_dict()
    client._apply_console_response(
        {"rules": updated, "rules_version": 2},
        force=True,
    )
    assert client.policy_version == 2
    assert client.policy is not None
    assert client.policy.min_primitives == 2
    assert client.policy.capture_minutes == 7
    reloaded = load_agent_policy(tmp_path)
    assert reloaded is not None
    assert reloaded.min_primitives == 2
