from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .atomic_io import atomic_write_text
from .custom_rule_engine import CustomRule, custom_rule_to_dict, parse_custom_rules, technique_choices
from .execution_analysis import operational_kind_count
from .log_store import default_logs_dir
from .models import Finding, PrimitiveKind

CONFIG_NAME = ".classifier_rules.json"

DEFAULT_RULE_SETTINGS: dict[str, Any] = {
    "enabled": True,
    "min_primitive_kinds": 2,
    "require_execution": False,
    "require_cross_process": False,
    "require_same_process": False,
    "min_finding_score": 0,
    "confidence": "",
}


@dataclass
class RuleSettings:
    enabled: bool = True
    min_primitive_kinds: int = 2
    require_execution: bool = False
    require_cross_process: bool = False
    require_same_process: bool = False
    min_finding_score: int = 0
    confidence: str = ""


@dataclass
class ClassifierRulesConfig:
    minimum_score: int = 50
    classification_enabled: bool = True
    minimum_operational_kinds: int = 2
    require_cross_process_findings: bool = False
    ignore_same_process_findings: bool = False
    disabled_rules: list[str] = field(default_factory=list)
    rule_settings: dict[str, RuleSettings] = field(default_factory=dict)
    custom_rules: list[CustomRule] = field(default_factory=list)
    updated_at: str | None = None


def resolve_config_path(logs_dir: Path | str | None = None) -> Path:
    directory = Path(logs_dir).expanduser().resolve() if logs_dir else default_logs_dir()
    return directory / CONFIG_NAME


def _parse_rule_settings(raw: object) -> RuleSettings | None:
    if not isinstance(raw, dict):
        return None
    min_kinds = int(raw.get("min_primitive_kinds", 2))
    min_kinds = max(2, min(3, min_kinds))
    min_score = int(raw.get("min_finding_score", 0))
    return RuleSettings(
        enabled=bool(raw.get("enabled", True)),
        min_primitive_kinds=min_kinds,
        require_execution=bool(raw.get("require_execution", False)),
        require_cross_process=bool(raw.get("require_cross_process", False)),
        require_same_process=bool(raw.get("require_same_process", False)),
        min_finding_score=max(0, min(100, min_score)),
        confidence=str(raw.get("confidence") or "").strip().lower(),
    )


def ensure_classifier_config(logs_dir: Path | str | None = None) -> Path:
    """Create `.classifier_rules.json` with defaults when missing."""
    path = resolve_config_path(logs_dir)
    if not path.exists():
        save_classifier_config(ClassifierRulesConfig(), logs_dir)
    return path


def load_classifier_config(logs_dir: Path | str | None = None) -> ClassifierRulesConfig:
    path = resolve_config_path(logs_dir)
    if not path.exists():
        return ClassifierRulesConfig()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ClassifierRulesConfig()
    if not isinstance(raw, dict):
        return ClassifierRulesConfig()

    disabled = raw.get("disabled_rules") or []
    if not isinstance(disabled, list):
        disabled = []
    minimum_score = max(0, min(100, int(raw.get("minimum_score", 50))))
    minimum_operational_kinds = max(2, min(3, int(raw.get("minimum_operational_kinds", 2))))

    rule_settings: dict[str, RuleSettings] = {}
    raw_rules = raw.get("rule_settings") or {}
    if isinstance(raw_rules, dict):
        for rule_id, payload in raw_rules.items():
            parsed = _parse_rule_settings(payload)
            if parsed is not None and str(rule_id).strip():
                rule_settings[str(rule_id)] = parsed

    custom_rules = parse_custom_rules(raw.get("custom_rules", []))
    if custom_rules is None:
        custom_rules = []

    return ClassifierRulesConfig(
        minimum_score=minimum_score,
        classification_enabled=bool(raw.get("classification_enabled", True)),
        minimum_operational_kinds=minimum_operational_kinds,
        require_cross_process_findings=bool(raw.get("require_cross_process_findings", False)),
        ignore_same_process_findings=bool(raw.get("ignore_same_process_findings", False)),
        disabled_rules=[str(item) for item in disabled if str(item).strip()],
        rule_settings=rule_settings,
        custom_rules=custom_rules,
        updated_at=raw.get("updated_at"),
    )


def save_classifier_config(config: ClassifierRulesConfig, logs_dir: Path | str | None = None) -> Path:
    path = resolve_config_path(logs_dir)
    config.updated_at = datetime.now(timezone.utc).isoformat()
    payload = {
        "minimum_score": config.minimum_score,
        "classification_enabled": config.classification_enabled,
        "minimum_operational_kinds": config.minimum_operational_kinds,
        "require_cross_process_findings": config.require_cross_process_findings,
        "ignore_same_process_findings": config.ignore_same_process_findings,
        "disabled_rules": list(config.disabled_rules),
        "rule_settings": {
            rule_id: asdict(settings) for rule_id, settings in config.rule_settings.items()
        },
        "custom_rules": [custom_rule_to_dict(rule) for rule in config.custom_rules],
        "updated_at": config.updated_at,
    }
    atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return path


def get_rule_settings(rule_id: str, config: ClassifierRulesConfig) -> dict[str, Any]:
    from .technique_classifier import classifier_rule_catalog

    catalog = {item["id"]: item for item in classifier_rule_catalog()}
    merged = dict(DEFAULT_RULE_SETTINGS)
    merged.update(catalog.get(rule_id, {}).get("defaults", {}))
    saved = config.rule_settings.get(rule_id)
    if saved is not None:
        merged.update(asdict(saved))
    if rule_id in config.disabled_rules:
        merged["enabled"] = False
    return merged


def rule_is_enabled(rule_id: str, config: ClassifierRulesConfig) -> bool:
    return bool(get_rule_settings(rule_id, config).get("enabled", True))


def passes_rule_gates(
    rule_id: str,
    finding: Finding,
    kinds: set[PrimitiveKind],
    config: ClassifierRulesConfig,
    *,
    execution_confirmed: bool,
    cross_process: bool,
) -> bool:
    settings = get_rule_settings(rule_id, config)
    if not settings.get("enabled", True):
        return False
    if int(finding.score or 0) < int(settings.get("min_finding_score", 0)):
        return False
    if settings.get("require_execution") and not execution_confirmed:
        return False
    if settings.get("require_cross_process") and not cross_process:
        return False
    same_process = finding.target_pid is None or finding.target_pid == finding.actor_pid
    if settings.get("require_same_process") and not same_process:
        return False
    min_kinds = int(settings.get("min_primitive_kinds", 2))
    if operational_kind_count(kinds) < min_kinds:
        return False
    return True


def confidence_override(rule_id: str, config: ClassifierRulesConfig) -> str | None:
    value = str(get_rule_settings(rule_id, config).get("confidence") or "").strip().lower()
    if value in {"low", "medium", "high"}:
        return value
    return None


def classifier_rules_payload(
    logs_dir: Path | str | None = None,
    *,
    catalog: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    from .technique_classifier import classifier_rule_catalog

    config = load_classifier_config(logs_dir)
    rules = catalog if catalog is not None else classifier_rule_catalog()
    from .builtin_rule_catalog import format_gate_summary, format_rule_match

    enriched: list[dict[str, Any]] = []
    for rule in rules:
        rule_id = str(rule["id"])
        settings = get_rule_settings(rule_id, config)
        merged = {**rule, **settings, "source": "builtin"}
        merged["match_summary"] = format_rule_match(merged)
        merged["gate_summary"] = format_gate_summary(merged)
        enriched.append(merged)
    return {
        "minimum_score": config.minimum_score,
        "classification_enabled": config.classification_enabled,
        "minimum_operational_kinds": config.minimum_operational_kinds,
        "require_cross_process_findings": config.require_cross_process_findings,
        "ignore_same_process_findings": config.ignore_same_process_findings,
        "disabled_rules": list(config.disabled_rules),
        "updated_at": config.updated_at,
        "rules": enriched,
        "custom_rules": [custom_rule_to_dict(rule) for rule in config.custom_rules],
        "techniques": technique_choices(),
    }
