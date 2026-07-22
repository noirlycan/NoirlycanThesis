from __future__ import annotations

from pathlib import Path

from noirlycan_core.runtime.agent_identity import (
    generate_agent_id,
    load_agent_identity,
    resolve_agent_id,
    save_agent_identity,
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


def test_generate_agent_id_uses_hostname_prefix() -> None:
    agent_id = generate_agent_id()
    assert "-" in agent_id
    assert len(agent_id.split("-")[-1]) == 8
