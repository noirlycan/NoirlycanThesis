from __future__ import annotations

from pathlib import Path

from noirlycan_core.runtime.agent_identity import (
    load_agent_identity,
    resolve_agent_credentials,
    resolve_agent_id,
)


def test_resolve_agent_id_is_stable_for_same_logs_dir(tmp_path: Path) -> None:
    first = resolve_agent_id(tmp_path, None)
    second = resolve_agent_id(tmp_path, None)
    assert first == second
    assert load_agent_identity(tmp_path) == first


def test_resolve_agent_id_honors_explicit_override(tmp_path: Path) -> None:
    chosen = resolve_agent_id(tmp_path, "lab-vm-win01")
    assert chosen == "lab-vm-win01"
    assert load_agent_identity(tmp_path) == "lab-vm-win01"


def test_resolve_agent_credentials_persists_token(tmp_path: Path) -> None:
    agent_id, token = resolve_agent_credentials(tmp_path, "win10-lab", "secret-token")
    assert agent_id == "win10-lab"
    assert token == "secret-token"
    again_id, again_token = resolve_agent_credentials(tmp_path, None, None)
    assert again_id == "win10-lab"
    assert again_token == "secret-token"
