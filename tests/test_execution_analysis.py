from __future__ import annotations

from datetime import datetime, timezone

from noirlycan_core.detection.correlator import Correlator
from noirlycan_core.detection.primitives import (
    analyze_execution,
    is_context_read_api,
    is_execution_transfer_api,
)
from noirlycan_core.models import MemoryPrimitive, PrimitiveKind
from noirlycan_core.classification.technique_classifier import InjectionTechnique, classify_finding


def test_get_thread_context_is_context_read_not_execute() -> None:
    assert is_context_read_api("GetThreadContext")
    assert not is_execution_transfer_api("GetThreadContext")


def test_resume_thread_is_execution_transfer() -> None:
    assert is_execution_transfer_api("ResumeThread")
    assert is_execution_transfer_api("SetThreadContext")


def test_analyze_execution_flags_missing_transfer_for_context_read_only() -> None:
    now = datetime.now(timezone.utc)
    primitives = [
        MemoryPrimitive(
            timestamp=now,
            kind=PrimitiveKind.ALLOCATE,
            actor_pid=1,
            actor_image="loader.exe",
            target_pid=2,
            target_image="msedge.exe",
            address=0x1000,
            size=0x1000,
            api="NtAllocateVirtualMemory",
        ),
        MemoryPrimitive(
            timestamp=now,
            kind=PrimitiveKind.WRITE,
            actor_pid=1,
            actor_image="loader.exe",
            target_pid=2,
            target_image="msedge.exe",
            address=0x1000,
            size=0x1000,
            api="NtMapViewOfSection",
        ),
        MemoryPrimitive(
            timestamp=now,
            kind=PrimitiveKind.CONTEXT_READ,
            actor_pid=1,
            actor_image="loader.exe",
            target_pid=2,
            target_image="msedge.exe",
            address=None,
            size=None,
            api="GetThreadContext",
        ),
    ]
    meta = analyze_execution(primitives)
    assert meta["execution_confirmed"] is False
    assert meta["context_read_evidence"] == ["GetThreadContext"]
    assert meta["missing_execution_transfer"] is True
    assert "execute" not in meta["paper_primitive_kinds"]


def test_staging_finding_with_get_thread_context() -> None:
    now = datetime.now(timezone.utc)
    correlator = Correlator(minimum_score=40)
    correlator.add_primitive(
        MemoryPrimitive(
            timestamp=now,
            kind=PrimitiveKind.ALLOCATE,
            actor_pid=1337,
            actor_image="loader.exe",
            target_pid=4242,
            target_image="msedge.exe",
            address=0x200000,
            size=0x1000,
            api="NtAllocateVirtualMemory",
        )
    )
    correlator.add_primitive(
        MemoryPrimitive(
            timestamp=now,
            kind=PrimitiveKind.WRITE,
            actor_pid=1337,
            actor_image="loader.exe",
            target_pid=4242,
            target_image="msedge.exe",
            address=0x200000,
            size=0x1000,
            api="NtMapViewOfSection",
            details={"protection": "EXECUTE_READWRITE"},
        )
    )
    findings = correlator.add_primitive(
        MemoryPrimitive(
            timestamp=now,
            kind=PrimitiveKind.CONTEXT_READ,
            actor_pid=1337,
            actor_image="loader.exe",
            target_pid=4242,
            target_image="msedge.exe",
            address=None,
            size=None,
            api="GetThreadContext",
        )
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding.title == "Probable injection staging chain"
    assert finding.evidence["execution_confirmed"] is False
    assert finding.evidence["missing_execution_transfer"] is True
    classification = classify_finding(finding)
    assert classification.technique == InjectionTechnique.SECTION_MAPPING_INJECTION


def test_confirmed_execution_with_set_thread_context_and_resume() -> None:
    now = datetime.now(timezone.utc)
    correlator = Correlator(minimum_score=40)
    correlator.add_primitive(
        MemoryPrimitive(
            timestamp=now,
            kind=PrimitiveKind.WRITE,
            actor_pid=1,
            actor_image="loader.exe",
            target_pid=2,
            target_image="msedge.exe",
            address=0x1000,
            size=0x100,
            api="NtMapViewOfSection",
            details={"protection": "EXECUTE_READWRITE"},
        )
    )
    findings = correlator.add_primitive(
        MemoryPrimitive(
            timestamp=now,
            kind=PrimitiveKind.EXECUTE,
            actor_pid=1,
            actor_image="loader.exe",
            target_pid=2,
            target_image="msedge.exe",
            address=None,
            size=None,
            api="SetThreadContext",
        )
    )
    assert len(findings) == 1
    assert findings[0].evidence["execution_confirmed"] is True
    assert "SetThreadContext" in findings[0].evidence["execution_evidence"]

    upgraded = correlator.add_primitive(
        MemoryPrimitive(
            timestamp=now,
            kind=PrimitiveKind.EXECUTE,
            actor_pid=1,
            actor_image="loader.exe",
            target_pid=2,
            target_image="msedge.exe",
            address=None,
            size=None,
            api="ResumeThread",
        )
    )
    assert len(upgraded) == 0
    assert findings[0].evidence["execution_confirmed"] is True
