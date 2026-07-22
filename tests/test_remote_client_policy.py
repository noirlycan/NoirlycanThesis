from __future__ import annotations

from noirlycan_agent.collector.application.remote_sink import ConsoleRemoteClient


def test_remote_client_without_local_policy_file(tmp_path) -> None:
    client = ConsoleRemoteClient(
        "127.0.0.1:8888",
        "test-token",
        logs_dir=tmp_path,
    )
    assert client.policy is None
    assert client.policy_version == 0
