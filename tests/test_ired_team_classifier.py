from __future__ import annotations

from datetime import datetime, timezone

from noirlycan_telemetry.models import FileEvent, Finding, MemoryPrimitive, PrimitiveKind, Severity
from noirlycan_telemetry.technique_classifier import InjectionTechnique, classify_finding


def _primitive(kind: PrimitiveKind, api: str, *, target_pid: int = 2000) -> MemoryPrimitive:
    return MemoryPrimitive(
        timestamp=datetime.now(timezone.utc),
        kind=kind,
        actor_pid=1000,
        actor_image="C:\\malware\\injector.exe",
        target_pid=target_pid,
        target_image="C:\\Windows\\explorer.exe",
        address=0x10000,
        size=0x1000,
        api=api,
        details={},
    )


def _finding(*primitives: MemoryPrimitive, **evidence: object) -> Finding:
    return Finding(
        timestamp=datetime.now(timezone.utc),
        severity=Severity.HIGH,
        title="test",
        description="test",
        actor_pid=1000,
        target_pid=2000,
        primitives=primitives,
        score=80,
        evidence=dict(evidence),
    )


def test_early_bird_apc_classification() -> None:
    result = classify_finding(
        _finding(
            _primitive(PrimitiveKind.ALLOCATE, "NtAllocateVirtualMemory"),
            _primitive(PrimitiveKind.WRITE, "NtWriteVirtualMemory"),
            _primitive(PrimitiveKind.EXECUTE, "NtQueueApcThreadEx"),
            create_suspended=True,
            cross_process=True,
            execution_confirmed=True,
        )
    )
    assert result.technique == InjectionTechnique.EARLY_BIRD_APC_INJECTION


def test_fiber_local_classification() -> None:
    local = MemoryPrimitive(
        timestamp=datetime.now(timezone.utc),
        kind=PrimitiveKind.EXECUTE,
        actor_pid=1000,
        actor_image="C:\\malware\\injector.exe",
        target_pid=1000,
        target_image="C:\\malware\\injector.exe",
        address=0x10000,
        size=0x1000,
        api="SwitchToFiber",
        details={},
    )
    finding = _finding(local, _primitive(PrimitiveKind.ALLOCATE, "VirtualAlloc", target_pid=1000))
    finding = Finding(
        timestamp=finding.timestamp,
        severity=finding.severity,
        title=finding.title,
        description=finding.description,
        actor_pid=1000,
        target_pid=1000,
        primitives=finding.primitives,
        score=finding.score,
        evidence=finding.evidence,
    )
    result = classify_finding(finding)
    assert result.technique == InjectionTechnique.FIBER_INJECTION


def test_threadpool_wait_classification() -> None:
    result = classify_finding(
        _finding(
            _primitive(PrimitiveKind.WRITE, "NtWriteVirtualMemory"),
            _primitive(PrimitiveKind.EXECUTE, "SetThreadpoolWait"),
            cross_process=True,
            execution_confirmed=True,
        )
    )
    assert result.technique == InjectionTechnique.THREADPOOL_WAIT_INJECTION


def test_reflective_dll_classification() -> None:
    result = classify_finding(
        _finding(
            _primitive(PrimitiveKind.ALLOCATE, "VirtualAllocEx"),
            _primitive(PrimitiveKind.WRITE, "WriteProcessMemory"),
            _primitive(PrimitiveKind.EXECUTE, "NtCreateThreadEx"),
            cross_process=True,
            execution_confirmed=True,
        )
    )
    assert result.technique == InjectionTechnique.REFLECTIVE_DLL_INJECTION


def test_extra_window_memory_classification() -> None:
    result = classify_finding(
        _finding(
            _primitive(PrimitiveKind.WRITE, "SetWindowLongPtrW"),
            _primitive(PrimitiveKind.EXECUTE, "SendMessageW"),
            cross_process=True,
            execution_confirmed=True,
        )
    )
    assert result.technique == InjectionTechnique.EXTRA_WINDOW_MEMORY_INJECTION


def test_process_doppelganging_classification() -> None:
    result = classify_finding(
        _finding(
            _primitive(PrimitiveKind.ALLOCATE, "NtCreateTransaction", target_pid=1000),
            MemoryPrimitive(
                timestamp=datetime.now(timezone.utc),
                kind=PrimitiveKind.EXECUTE,
                actor_pid=1000,
                actor_image="C:\\malware\\injector.exe",
                target_pid=None,
                target_image=None,
                address=None,
                size=None,
                api="CreateProcessW",
                details={},
            ),
            txf_transaction=True,
            cross_process=True,
        )
    )
    assert result.technique == InjectionTechnique.PROCESS_DOPPELGANGING


def test_pe_injection_with_related_file() -> None:
    related = FileEvent(
        timestamp=datetime.now(timezone.utc),
        path="C:\\temp\\payload.exe",
        creator_pid=1000,
        creator_image="C:\\malware\\injector.exe",
        sha256="abc",
        signed=False,
        entropy=6.5,
        pe=True,
    )
    finding = Finding(
        timestamp=datetime.now(timezone.utc),
        severity=Severity.HIGH,
        title="test",
        description="test",
        actor_pid=1000,
        target_pid=2000,
        primitives=[
            _primitive(PrimitiveKind.WRITE, "NtWriteVirtualMemory"),
            _primitive(PrimitiveKind.EXECUTE, "NtCreateThreadEx"),
        ],
        related_file=related,
        score=80,
        evidence={"cross_process": True, "execution_confirmed": True},
    )
    result = classify_finding(finding)
    assert result.technique == InjectionTechnique.PE_INJECTION
