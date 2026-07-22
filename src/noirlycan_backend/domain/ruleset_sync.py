from __future__ import annotations

from pathlib import Path

from noirlycan_backend.domain.ruleset import Ruleset
from noirlycan_core.runtime.agent_policy import apply_ruleset_to_agent, policy_path


def sync_ruleset_to_classifier(ruleset: Ruleset, logs_dir: Path | str, *, version: int) -> Path:
    """Persist console rules as agent policy + correlator config on the backend logs dir."""
    apply_ruleset_to_agent(logs_dir, ruleset.to_dict(), version=version)
    return policy_path(logs_dir)
