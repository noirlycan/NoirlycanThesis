"""User-defined classifier rules (add / edit / delete via dashboard)."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

from noirlycan_telemetry.kernel.analysis.primitives import operational_kind_count
from noirlycan_telemetry.kernel.classification.technique_classifier import (
    InjectionTechnique,
    TechniqueClassification,
    TechniqueConfidence,
)
from noirlycan_telemetry.kernel.entities.models import Finding, PrimitiveKind

RULE_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{1,63}$")
EVAL_PHASES = {"before_builtin", "after_builtin"}
CONFIDENCE_VALUES = {"", "low", "medium", "high"}
PRIMITIVE_KIND_NAMES = {"allocate", "write", "execute", "context_read"}


@dataclass
class CustomRule:
    id: str
    label: str
    technique: str
    enabled: bool = True
    priority: int = 500
    description: str = ""
    rationale: str = ""
    confidence: str = ""
    min_primitive_kinds: int = 2
    require_execution: bool = False
    require_cross_process: bool = False
    require_same_process: bool = False
    min_finding_score: int = 0
    required_apis: list[str] = field(default_factory=list)
    any_apis: list[str] = field(default_factory=list)
    api_groups: list[list[str]] = field(default_factory=list)
    required_kinds: list[str] = field(default_factory=list)
    require_section_mapping: bool = False
    require_context_read: bool = False
    eval_phase: str = "before_builtin"


def technique_choices() -> list[dict[str, str]]:
    return [
        {"value": item.value, "label": item.value.replace("_", " ")}
        for item in InjectionTechnique
    ]


def _normalize_api_patterns(values: object) -> list[str]:
    if not isinstance(values, list):
        return []
    patterns: list[str] = []
    for item in values:
        text = str(item or "").strip().lower()
        if text:
            patterns.append(text)
    return patterns


def _normalize_api_groups(values: object) -> list[list[str]]:
    if not isinstance(values, list):
        return []
    groups: list[list[str]] = []
    for item in values:
        if isinstance(item, list):
            group = _normalize_api_patterns(item)
            if group:
                groups.append(group)
        elif isinstance(item, str):
            text = str(item).strip().lower()
            if text:
                groups.append([text])
    return groups


def _normalize_kind_names(values: object) -> list[str]:
    if not isinstance(values, list):
        return []
    kinds: list[str] = []
    for item in values:
        text = str(item or "").strip().lower()
        if text in PRIMITIVE_KIND_NAMES:
            kinds.append(text)
    return kinds


def parse_custom_rule(raw: object) -> CustomRule | None:
    if not isinstance(raw, dict):
        return None
    rule_id = str(raw.get("id") or "").strip().lower()
    if not RULE_ID_PATTERN.match(rule_id):
        return None
    label = str(raw.get("label") or rule_id).strip()
    technique = str(raw.get("technique") or InjectionTechnique.UNCLASSIFIED.value).strip().lower()
    try:
        InjectionTechnique(technique)
    except ValueError:
        return None
    try:
        priority = max(0, min(10000, int(raw.get("priority", 500))))
        min_kinds = max(2, min(3, int(raw.get("min_primitive_kinds", 2))))
        min_score = max(0, min(100, int(raw.get("min_finding_score", 0))))
    except (TypeError, ValueError):
        return None
    confidence = str(raw.get("confidence") or "").strip().lower()
    if confidence not in CONFIDENCE_VALUES:
        return None
    eval_phase = str(raw.get("eval_phase") or "before_builtin").strip().lower()
    if eval_phase not in EVAL_PHASES:
        eval_phase = "before_builtin"
    return CustomRule(
        id=rule_id,
        label=label or rule_id,
        technique=technique,
        enabled=bool(raw.get("enabled", True)),
        priority=priority,
        description=str(raw.get("description") or "").strip(),
        rationale=str(raw.get("rationale") or "").strip(),
        confidence=confidence,
        min_primitive_kinds=min_kinds,
        require_execution=bool(raw.get("require_execution", False)),
        require_cross_process=bool(raw.get("require_cross_process", False)),
        require_same_process=bool(raw.get("require_same_process", False)),
        min_finding_score=min_score,
        required_apis=_normalize_api_patterns(raw.get("required_apis")),
        any_apis=_normalize_api_patterns(raw.get("any_apis")),
        api_groups=_normalize_api_groups(raw.get("api_groups")),
        required_kinds=_normalize_kind_names(raw.get("required_kinds")),
        require_section_mapping=bool(raw.get("require_section_mapping", False)),
        require_context_read=bool(raw.get("require_context_read", False)),
        eval_phase=eval_phase,
    )


def parse_custom_rules(raw: object) -> list[CustomRule] | None:
    if raw is None:
        return []
    if not isinstance(raw, list):
        return None
    rules: list[CustomRule] = []
    seen: set[str] = set()
    for item in raw:
        parsed = parse_custom_rule(item)
        if parsed is None:
            return None
        if parsed.id in seen:
            return None
        seen.add(parsed.id)
        rules.append(parsed)
    return rules


def custom_rule_to_dict(rule: CustomRule) -> dict[str, Any]:
    payload = asdict(rule)
    payload["source"] = "custom"
    payload["match_summary"] = format_custom_rule_match(payload)
    payload["gate_summary"] = format_custom_gate_summary(payload)
    return payload


def format_custom_rule_match(rule: dict[str, Any]) -> str:
    groups = rule.get("api_groups") or []
    parts: list[str] = []
    for group in groups:
        if not group:
            continue
        parts.append("(" + " | ".join(str(item) for item in group) + ")")
    if parts:
        summary = " + ".join(parts)
    else:
        required = [str(item) for item in (rule.get("required_apis") or []) if str(item).strip()]
        any_apis = [str(item) for item in (rule.get("any_apis") or []) if str(item).strip()]
        chunks: list[str] = []
        if required:
            chunks.append("all: " + ", ".join(required))
        if any_apis:
            chunks.append("any: " + ", ".join(any_apis))
        summary = "; ".join(chunks) if chunks else "(no API patterns)"
    kinds = [str(item) for item in (rule.get("required_kinds") or []) if str(item).strip()]
    if kinds:
        summary = f"{summary} — kinds: {', '.join(kinds)}"
    signals: list[str] = []
    if rule.get("require_section_mapping"):
        signals.append("section_mapping")
    if rule.get("require_context_read"):
        signals.append("context_read")
    if signals:
        summary = f"{summary} — {', '.join(signals)}"
    return summary


def format_custom_gate_summary(rule: dict[str, Any]) -> str:
    exec_req = "yes" if rule.get("require_execution") else "no"
    cross_req = "yes" if rule.get("require_cross_process") else "no"
    same_req = "yes" if rule.get("require_same_process") else "no"
    min_kinds = rule.get("min_primitive_kinds", 2)
    min_score = rule.get("min_finding_score", 0)
    confidence = str(rule.get("confidence") or "").strip() or "auto"
    return (
        f"Exec={exec_req}, Cross={cross_req}, Same={same_req}, "
        f"Min kinds={min_kinds}, Min score={min_score}, Conf={confidence}"
    )


def _api_matches(patterns: list[str], apis_lower: set[str]) -> bool:
    if not patterns:
        return True
    return all(any(pattern in api for api in apis_lower) for pattern in patterns)


def _any_api_matches(patterns: list[str], apis_lower: set[str]) -> bool:
    if not patterns:
        return True
    return any(any(pattern in api for api in apis_lower) for pattern in patterns)


def _api_groups_match(groups: list[list[str]], apis_lower: set[str]) -> bool:
    if not groups:
        return True
    for group in groups:
        if not any(any(pattern in api for api in apis_lower) for pattern in group):
            return False
    return True


def _kinds_match(required: list[str], kinds: set[PrimitiveKind]) -> bool:
    if not required:
        return True
    present = {kind.value for kind in kinds}
    return all(name in present for name in required)


def passes_custom_rule(
    rule: CustomRule,
    finding: Finding,
    kinds: set[PrimitiveKind],
    *,
    execution_confirmed: bool,
    cross_process: bool,
    apis_lower: set[str],
    evidence: dict[str, Any],
    context_read: bool,
) -> bool:
    if not rule.enabled:
        return False
    if int(finding.score or 0) < int(rule.min_finding_score):
        return False
    if rule.require_execution and not execution_confirmed:
        return False
    if rule.require_cross_process and not cross_process:
        return False
    same_process = finding.target_pid is None or finding.target_pid == finding.actor_pid
    if rule.require_same_process and not same_process:
        return False
    if operational_kind_count(kinds) < int(rule.min_primitive_kinds):
        return False
    if rule.require_section_mapping and not bool(evidence.get("section_mapping")):
        return False
    if rule.require_context_read and not context_read:
        return False
    if rule.api_groups:
        if not _api_groups_match(rule.api_groups, apis_lower):
            return False
    else:
        if not _api_matches(rule.required_apis, apis_lower):
            return False
        if not _any_api_matches(rule.any_apis, apis_lower):
            return False
    if not _kinds_match(rule.required_kinds, kinds):
        return False
    return True


def _confidence_for_rule(rule: CustomRule) -> TechniqueConfidence:
    if rule.confidence in {"low", "medium", "high"}:
        return TechniqueConfidence(rule.confidence)
    return TechniqueConfidence.MEDIUM


def evaluate_custom_rules(
    rules: list[CustomRule],
    finding: Finding,
    *,
    kinds: set[PrimitiveKind],
    apis_lower: set[str],
    evidence: dict[str, Any],
    execution_confirmed: bool,
    cross_process: bool,
    context_read: bool,
    phase: str,
) -> TechniqueClassification | None:
    phase_rules = [rule for rule in rules if rule.eval_phase == phase and rule.enabled]
    phase_rules.sort(key=lambda item: (-item.priority, item.id))
    for rule in phase_rules:
        if not passes_custom_rule(
            rule,
            finding,
            kinds,
            execution_confirmed=execution_confirmed,
            cross_process=cross_process,
            apis_lower=apis_lower,
            evidence=evidence,
            context_read=context_read,
        ):
            continue
        rationale = rule.rationale or rule.description or f"Matched custom rule {rule.label}."
        return TechniqueClassification(
            technique=InjectionTechnique(rule.technique),
            confidence=_confidence_for_rule(rule),
            rationale=rationale,
        )
    return None
