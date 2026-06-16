from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from noirlycan_telemetry.services.analysis.domain.classifier_config import (
    ClassifierRulesConfig,
    RuleSettings,
    classifier_rules_payload,
    load_classifier_config,
    passes_rule_gates,
    save_classifier_config,
)
from noirlycan_telemetry.kernel.classification.custom_rule_engine import CustomRule, parse_custom_rules
from noirlycan_telemetry.kernel.entities.models import MemoryPrimitive, PrimitiveKind, Severity
from noirlycan_telemetry.kernel.classification.technique_classifier import InjectionTechnique, TechniqueConfidence, classify_finding
from noirlycan_telemetry.kernel.entities.models import Finding
from noirlycan_telemetry.services.dashboard import make_client
from noirlycan_telemetry.kernel.classification.technique_classifier import classifier_rule_catalog


def test_classifier_rules_roundtrip(tmp_path: Path) -> None:
    save_classifier_config(
        ClassifierRulesConfig(
            minimum_score=65,
            classification_enabled=True,
            disabled_rules=["shellcode_trinity"],
        ),
        tmp_path,
    )
    loaded = load_classifier_config(tmp_path)
    assert loaded.minimum_score == 65
    assert "shellcode_trinity" in loaded.disabled_rules

    payload = classifier_rules_payload(tmp_path)
    shellcode = next(item for item in payload["rules"] if item["id"] == "shellcode_trinity")
    assert shellcode["enabled"] is False


def test_rules_api_save(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    response = client.post(
        "/api/rules",
        data=json.dumps(
            {
                "minimum_score": 40,
                "classification_enabled": True,
                "rules": [
                    {"id": "shellcode_trinity", "enabled": False},
                    {"id": "classic_dll_injection", "enabled": True},
                ],
            }
        ),
        content_type="application/json",
    )
    assert response.status_code == 200
    body = response.json()
    assert body["minimum_score"] == 40
    disabled = set(body["disabled_rules"])
    assert "shellcode_trinity" in disabled
    assert "classic_dll_injection" not in disabled


def test_rule_catalog_not_empty() -> None:
    catalog = classifier_rule_catalog()
    assert len(catalog) >= 20
    assert any(item["id"] == "shellcode_trinity" for item in catalog)


def test_rule_catalog_exposes_api_match_metadata() -> None:
    catalog = classifier_rule_catalog()
    shellcode = next(item for item in catalog if item["id"] == "shellcode_trinity")
    assert shellcode.get("api_groups")
    assert any("NtAllocateVirtualMemory" in group for group in shellcode["api_groups"])
    assert shellcode["defaults"]["require_cross_process"] is True

    payload = classifier_rules_payload()
    enriched = next(item for item in payload["rules"] if item["id"] == "shellcode_trinity")
    assert "match_summary" in enriched
    assert "NtAllocateVirtualMemory" in enriched["match_summary"]
    assert "gate_summary" in enriched
    assert "Cross=yes" in enriched["gate_summary"]


def test_rules_api_save_per_rule_settings(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    response = client.post(
        "/api/rules",
        data=json.dumps(
            {
                "minimum_operational_kinds": 3,
                "require_cross_process_findings": True,
                "rules": [
                    {
                        "id": "local_alertable_wake",
                        "enabled": True,
                        "min_primitive_kinds": 2,
                        "require_execution": True,
                        "require_same_process": True,
                        "min_finding_score": 40,
                        "confidence": "high",
                    }
                ],
            }
        ),
        content_type="application/json",
    )
    assert response.status_code == 200
    body = response.json()
    assert body["minimum_operational_kinds"] == 3
    assert body["require_cross_process_findings"] is True
    wake = next(item for item in body["rules"] if item["id"] == "local_alertable_wake")
    assert wake["require_execution"] is True
    assert wake["require_same_process"] is True
    assert wake["min_finding_score"] == 40
    assert wake["confidence"] == "high"

    loaded = load_classifier_config(tmp_path)
    assert loaded.minimum_operational_kinds == 3
    assert loaded.require_cross_process_findings is True
    assert loaded.rule_settings["local_alertable_wake"].confidence == "high"


def test_passes_rule_gates_respects_min_kinds() -> None:
    config = ClassifierRulesConfig(
        rule_settings={
            "local_self_inject": RuleSettings(enabled=True, min_primitive_kinds=3, require_same_process=True),
        }
    )
    finding = Finding(
        timestamp=datetime.now(timezone.utc),
        severity=Severity.LOW,
        title="x",
        description="x",
        actor_pid=1,
        target_pid=1,
        primitives=[
            MemoryPrimitive(
                timestamp=datetime.now(timezone.utc),
                kind=PrimitiveKind.ALLOCATE,
                actor_pid=1,
                actor_image="a.exe",
                target_pid=1,
                target_image="a.exe",
                address=0,
                size=0x1000,
                api="NtAllocateVirtualMemory",
                details={},
            ),
            MemoryPrimitive(
                timestamp=datetime.now(timezone.utc),
                kind=PrimitiveKind.EXECUTE,
                actor_pid=1,
                actor_image="a.exe",
                target_pid=1,
                target_image="a.exe",
                address=0,
                size=0x1000,
                api="NtTestAlert",
                details={},
            ),
        ],
        score=50,
        evidence={},
    )
    kinds = {primitive.kind for primitive in finding.primitives}
    assert passes_rule_gates(
        "local_self_inject",
        finding,
        kinds,
        config,
        execution_confirmed=True,
        cross_process=False,
    ) is False


def test_custom_rules_roundtrip(tmp_path: Path) -> None:
    save_classifier_config(
        ClassifierRulesConfig(
            custom_rules=[
                CustomRule(
                    id="edge_staging",
                    label="Edge staging",
                    technique="section_mapping_injection",
                    required_apis=["ntallocatevirtualmemory", "ntwritevirtualmemory"],
                    require_cross_process=True,
                    priority=900,
                )
            ]
        ),
        tmp_path,
    )
    loaded = load_classifier_config(tmp_path)
    assert len(loaded.custom_rules) == 1
    assert loaded.custom_rules[0].id == "edge_staging"

    payload = classifier_rules_payload(tmp_path)
    assert len(payload["custom_rules"]) == 1
    assert payload["techniques"]


def test_custom_rule_api_upsert_and_delete(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    create = client.post(
        "/api/rules/custom/my_lab_rule",
        data=json.dumps(
            {
                "label": "My lab rule",
                "technique": "process_hollowing_section",
                "required_apis": ["ntmapviewofsection", "setthreadcontext"],
                "require_execution": True,
                "require_cross_process": True,
                "priority": 800,
            }
        ),
        content_type="application/json",
    )
    assert create.status_code == 200
    body = create.json()
    assert any(item["id"] == "my_lab_rule" for item in body["custom_rules"])

    delete = client.delete("/api/rules/custom/my_lab_rule")
    assert delete.status_code == 200
    assert body["custom_rules"]
    assert delete.json()["custom_rules"] == []


def test_custom_rule_api_groups_match() -> None:
    config = ClassifierRulesConfig(
        custom_rules=[
            CustomRule(
                id="lab_groups",
                label="Lab grouped APIs",
                technique="process_hollowing_section",
                api_groups=[
                    ["ntallocatevirtualmemory"],
                    ["ntwritevirtualmemory"],
                    ["setthreadcontext", "ntsetcontextthread"],
                ],
                require_cross_process=True,
                require_execution=True,
                priority=1000,
            )
        ]
    )
    finding = Finding(
        timestamp=datetime.now(timezone.utc),
        severity=Severity.HIGH,
        title="test",
        description="test",
        actor_pid=1000,
        target_pid=2000,
        primitives=[
            MemoryPrimitive(
                timestamp=datetime.now(timezone.utc),
                kind=PrimitiveKind.ALLOCATE,
                actor_pid=1000,
                actor_image="injector.exe",
                target_pid=2000,
                target_image="msedge.exe",
                address=None,
                size=0,
                api="NtAllocateVirtualMemory",
                details={},
            ),
            MemoryPrimitive(
                timestamp=datetime.now(timezone.utc),
                kind=PrimitiveKind.WRITE,
                actor_pid=1000,
                actor_image="injector.exe",
                target_pid=2000,
                target_image="msedge.exe",
                address=0x10000,
                size=0x1000,
                api="NtWriteVirtualMemory",
                details={},
            ),
            MemoryPrimitive(
                timestamp=datetime.now(timezone.utc),
                kind=PrimitiveKind.EXECUTE,
                actor_pid=1000,
                actor_image="injector.exe",
                target_pid=2000,
                target_image="msedge.exe",
                address=None,
                size=None,
                api="SetThreadContext",
                details={},
            ),
        ],
        score=90,
        evidence={"cross_process": True, "execution_confirmed": True},
    )
    result = classify_finding(finding, rules_config=config)
    assert result.technique == InjectionTechnique.PROCESS_HOLLOWING_SECTION


def test_rules_detail_api(tmp_path: Path) -> None:
    client = make_client(tmp_path)
    response = client.get("/api/rules/detail/shellcode_trinity")
    assert response.status_code == 200
    body = response.json()
    assert body["source"] == "builtin"
    assert body["rule"]["id"] == "shellcode_trinity"
    assert "match_summary" in body["rule"]


def test_custom_rule_classifies_before_builtin() -> None:
    config = ClassifierRulesConfig(
        custom_rules=[
            CustomRule(
                id="lab_edge",
                label="Lab edge inject",
                technique="thread_hijack",
                required_apis=["ntwritevirtualmemory"],
                any_apis=["setthreadcontext"],
                required_kinds=["write", "execute"],
                require_cross_process=True,
                require_execution=True,
                confidence="high",
                rationale="Custom lab rule matched.",
                priority=1000,
            )
        ]
    )
    finding = Finding(
        timestamp=datetime.now(timezone.utc),
        severity=Severity.HIGH,
        title="test",
        description="test",
        actor_pid=1000,
        target_pid=2000,
        primitives=[
            MemoryPrimitive(
                timestamp=datetime.now(timezone.utc),
                kind=PrimitiveKind.WRITE,
                actor_pid=1000,
                actor_image="injector.exe",
                target_pid=2000,
                target_image="msedge.exe",
                address=0x10000,
                size=0x1000,
                api="NtWriteVirtualMemory",
                details={},
            ),
            MemoryPrimitive(
                timestamp=datetime.now(timezone.utc),
                kind=PrimitiveKind.EXECUTE,
                actor_pid=1000,
                actor_image="injector.exe",
                target_pid=2000,
                target_image="msedge.exe",
                address=0x10000,
                size=0x1000,
                api="SetThreadContext",
                details={},
            ),
        ],
        score=85,
        evidence={"cross_process": True, "execution_confirmed": True},
    )
    result = classify_finding(finding, rules_config=config)
    assert result.technique == InjectionTechnique.THREAD_HIJACK
    assert result.confidence == TechniqueConfidence.HIGH
    assert "Custom lab rule" in result.rationale


def test_parse_custom_rules_rejects_invalid_id() -> None:
    assert parse_custom_rules([{"id": "BAD ID", "label": "x", "technique": "unclassified"}]) is None
