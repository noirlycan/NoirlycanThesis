from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from noirlycan_core.classification.config import (
    ClassifierRulesConfig,
    load_classifier_config,
    save_classifier_config,
)
from noirlycan_core.runtime.cached_json import load_json_cached
from noirlycan_core.storage.atomic_io import atomic_write_text
from noirlycan_core.storage.log_store import resolve_logs_dir

POLICY_FILENAME = ".agent_policy.json"


@dataclass
class AgentPolicy:
    """Runtime detection policy pushed from the console ruleset."""

    version: int = 0
    min_primitives: int = 2
    congruence: bool = True
    temporal: bool = True
    capture_minutes: int = 5
    net_watch_minutes: int = 5
    auto_attach: bool = True
    beacon: bool = True
    auto_kill: bool = False
    auto_kill_min_severity: str = "CRITICAL"
    folders: list[str] = field(default_factory=list)
    allowlist: list[str] = field(default_factory=list)
    alloc: list[str] = field(default_factory=list)
    write: list[str] = field(default_factory=list)
    exec: list[str] = field(default_factory=list)
    chains: list[dict[str, Any]] = field(default_factory=list)
    score_crit: int = 80
    score_high: int = 55
    score_med: int = 30
    score_weights: list[dict[str, Any]] = field(default_factory=list)
    updated_at: str | None = None

    @classmethod
    def from_ruleset_dict(cls, rules: dict[str, Any], *, version: int = 0) -> AgentPolicy:
        score = rules.get("score") if isinstance(rules.get("score"), dict) else {}
        weights = score.get("weights") if isinstance(score.get("weights"), list) else []
        chains = rules.get("chains") if isinstance(rules.get("chains"), list) else []
        return cls(
            version=max(0, int(version)),
            min_primitives=max(2, min(3, int(rules.get("min_primitives", 2)))),
            congruence=bool(rules.get("congruence", True)),
            temporal=bool(rules.get("temporal", True)),
            capture_minutes=max(1, min(8, int(rules.get("capture", 5)))),
            net_watch_minutes=max(1, min(15, int(rules.get("net_watch", 5)))),
            auto_attach=bool(rules.get("auto_attach", True)),
            beacon=bool(rules.get("beacon", True)),
            auto_kill=bool(rules.get("auto_kill", False)),
            auto_kill_min_severity=str(rules.get("auto_kill_min_severity") or "CRITICAL").upper(),
            folders=_str_list(rules.get("folders")),
            allowlist=_str_list(rules.get("allowlist")),
            alloc=_str_list(rules.get("alloc")),
            write=_str_list(rules.get("write")),
            exec=_str_list(rules.get("exec")),
            chains=[dict(item) for item in chains if isinstance(item, dict)],
            score_crit=int(score.get("crit", 80)),
            score_high=int(score.get("high", 55)),
            score_med=int(score.get("med", 30)),
            score_weights=[dict(item) for item in weights if isinstance(item, dict)],
            updated_at=datetime.now(timezone.utc).isoformat(),
        )

    def capture_seconds(self) -> int:
        return self.capture_minutes * 60

    def net_watch_seconds(self) -> int:
        return self.net_watch_minutes * 60

    def to_classifier_config(self, logs_dir: Path | str | None = None) -> ClassifierRulesConfig:
        base = load_classifier_config(logs_dir)
        return ClassifierRulesConfig(
            minimum_score=max(0, min(100, self.score_med)),
            classification_enabled=base.classification_enabled,
            minimum_operational_kinds=self.min_primitives,
            require_cross_process_findings=base.require_cross_process_findings,
            ignore_same_process_findings=base.ignore_same_process_findings,
            disabled_rules=list(base.disabled_rules),
            rule_settings=dict(base.rule_settings),
            custom_rules=list(base.custom_rules),
            updated_at=self.updated_at,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def frida_hook_payload(self) -> dict[str, Any]:
        """JSON injected into the Frida hook script preamble."""
        return {
            "version": self.version,
            "alloc": list(self.alloc),
            "write": list(self.write),
            "exec": list(self.exec),
        }

    @classmethod
    def from_dict(cls, raw: object) -> AgentPolicy | None:
        if not isinstance(raw, dict):
            return None
        policy = cls(
            version=int(raw.get("version", 0)),
            min_primitives=max(2, min(3, int(raw.get("min_primitives", 2)))),
            congruence=bool(raw.get("congruence", True)),
            temporal=bool(raw.get("temporal", True)),
            capture_minutes=max(1, min(8, int(raw.get("capture_minutes", 5)))),
            net_watch_minutes=max(1, min(15, int(raw.get("network_watch_minutes", raw.get("net_watch_minutes", 5))))),
            auto_attach=bool(raw.get("auto_attach", True)),
            beacon=bool(raw.get("beacon", True)),
            auto_kill=bool(raw.get("auto_kill", False)),
            auto_kill_min_severity=str(raw.get("auto_kill_min_severity") or "CRITICAL").upper(),
            folders=_str_list(raw.get("folders")),
            allowlist=_str_list(raw.get("allowlist")),
            alloc=_str_list(raw.get("alloc")),
            write=_str_list(raw.get("write")),
            exec=_str_list(raw.get("exec")),
            chains=[dict(item) for item in raw.get("chains") or [] if isinstance(item, dict)],
            score_crit=int(raw.get("score_crit", 80)),
            score_high=int(raw.get("score_high", 55)),
            score_med=int(raw.get("score_med", 30)),
            score_weights=[dict(item) for item in raw.get("score_weights") or [] if isinstance(item, dict)],
            updated_at=str(raw.get("updated_at") or "") or None,
        )
        return policy


def policy_path(logs_dir: Path | str | None = None) -> Path:
    return resolve_logs_dir(logs_dir) / POLICY_FILENAME


def load_agent_policy(logs_dir: Path | str | None = None) -> AgentPolicy | None:
    raw = load_json_cached(policy_path(logs_dir))
    return AgentPolicy.from_dict(raw) if isinstance(raw, dict) else None


def save_agent_policy(policy: AgentPolicy, logs_dir: Path | str | None = None) -> Path:
    directory = resolve_logs_dir(logs_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / POLICY_FILENAME
    policy.updated_at = datetime.now(timezone.utc).isoformat()
    atomic_write_text(path, json.dumps(policy.to_dict(), indent=2, sort_keys=True) + "\n")
    save_classifier_config(policy.to_classifier_config(logs_dir), logs_dir)
    return path


def apply_ruleset_to_agent(logs_dir: Path | str, rules: dict[str, Any], *, version: int) -> AgentPolicy:
    policy = AgentPolicy.from_ruleset_dict(rules, version=version)
    save_agent_policy(policy, logs_dir)
    return policy


def _str_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]
