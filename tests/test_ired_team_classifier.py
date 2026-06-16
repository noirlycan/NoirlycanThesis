from __future__ import annotations

from datetime import datetime, timezone

from noirlycan_telemetry.kernel.entities.models import FileEvent, Finding, MemoryPrimitive, PrimitiveKind, Severity
from noirlycan_telemetry.kernel.classification.technique_classifier import (
    InjectionTechnique,
    TechniqueConfidence,
    classify_finding,
)


def _primitive(
    kind: PrimitiveKind,
    api: str,
    *,
    target_pid: int = 2000,
    size: int = 0x1000,
    note: str | None = None,
) -> MemoryPrimitive:
    details: dict[str, object] = {}
    if note is not None:
        details["note"] = note
    return MemoryPrimitive(
        timestamp=datetime.now(timezone.utc),
        kind=kind,
        actor_pid=1000,
        actor_image="C:\\malware\\injector.exe",
        target_pid=target_pid,
        target_image="C:\\Windows\\explorer.exe",
        address=0x10000,
        size=size,
        api=api,
        details=details,
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


def test_local_alertable_wake_classification() -> None:
    local_allocate = MemoryPrimitive(
        timestamp=datetime.now(timezone.utc),
        kind=PrimitiveKind.ALLOCATE,
        actor_pid=4296,
        actor_image="C:\\samples\\aes_decrypt_loader.exe",
        target_pid=4296,
        target_image="C:\\samples\\aes_decrypt_loader.exe",
        address=0x10000,
        size=0x1000,
        api="NtAllocateVirtualMemory",
        details={},
    )
    local_alert = MemoryPrimitive(
        timestamp=datetime.now(timezone.utc),
        kind=PrimitiveKind.EXECUTE,
        actor_pid=4296,
        actor_image="C:\\samples\\aes_decrypt_loader.exe",
        target_pid=4296,
        target_image="C:\\samples\\aes_decrypt_loader.exe",
        address=0x10000,
        size=0x1000,
        api="NtTestAlert",
        details={},
    )
    finding = Finding(
        timestamp=datetime.now(timezone.utc),
        severity=Severity.MEDIUM,
        title="local staging",
        description="allocate + alert",
        actor_pid=4296,
        target_pid=4296,
        primitives=[local_allocate, local_alert],
        score=55,
        evidence={"execution_confirmed": True},
    )
    result = classify_finding(finding)
    assert result.technique == InjectionTechnique.LOCAL_APC_INJECTION


def test_cross_process_staging_classification() -> None:
    result = classify_finding(
        _finding(
            _primitive(PrimitiveKind.ALLOCATE, "NtAllocateVirtualMemory"),
            _primitive(PrimitiveKind.WRITE, "NtWriteVirtualMemory"),
            cross_process=True,
            execution_confirmed=False,
            missing_execution_transfer=True,
        )
    )
    assert result.technique == InjectionTechnique.SECTION_MAPPING_INJECTION
    assert result.confidence == TechniqueConfidence.MEDIUM


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


def test_winrar_like_resume_chain_is_not_reflective_dll() -> None:
    result = classify_finding(
        _finding(
            _primitive(PrimitiveKind.ALLOCATE, "NtAllocateVirtualMemory"),
            _primitive(PrimitiveKind.WRITE, "NtWriteVirtualMemory"),
            _primitive(
                PrimitiveKind.EXECUTE,
                "ResumeThread",
                target_pid=368,
            ),
            cross_process=True,
            execution_confirmed=True,
        )
    )
    assert result.technique == InjectionTechnique.PROCESS_HOLLOWING_CLASSIC
    assert result.technique != InjectionTechnique.REFLECTIVE_DLL_INJECTION


def test_reflective_dll_classification() -> None:
    # Reflective DLL specifically uses memcpy / RtlMoveMemory to copy PE
    # sections locally before mapping — not the WriteProcessMemory trinity,
    # which is canonical shellcode injection. This separation matches
    # iRed.team's distinction between the two techniques.
    result = classify_finding(
        _finding(
            _primitive(PrimitiveKind.ALLOCATE, "VirtualAlloc"),
            _primitive(PrimitiveKind.WRITE, "RtlMoveMemory"),
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


# ---------------------------------------------------------------------------
# Extended technique coverage (Process Ghosting, PROPagate, Enum callback,
# Instrumentation Callback, PoolParty, IAT hooking, Threadless inject,
# Manual mapping). These guard the iRed.team / advanced-techniques expansion.
# ---------------------------------------------------------------------------


def test_process_ghosting_classification() -> None:
    result = classify_finding(
        _finding(
            _primitive(PrimitiveKind.WRITE, "NtSetInformationFile", note="process_ghosting_precursor"),
            _primitive(PrimitiveKind.ALLOCATE, "NtCreateSection"),
            _primitive(PrimitiveKind.WRITE, "NtCreateProcessEx"),
        )
    )
    assert result.technique == InjectionTechnique.PROCESS_GHOSTING


def test_propagate_classification() -> None:
    result = classify_finding(
        _finding(
            _primitive(PrimitiveKind.WRITE, "SetPropW", target_pid=1000, note="propagate"),
            _primitive(PrimitiveKind.EXECUTE, "SendNotifyMessageW", target_pid=1000, note="propagate_trigger"),
        )
    )
    assert result.technique == InjectionTechnique.PROPAGATE_INJECTION


def test_enum_callback_injection_classification() -> None:
    result = classify_finding(
        _finding(
            _primitive(PrimitiveKind.ALLOCATE, "VirtualAlloc", target_pid=1000),
            _primitive(PrimitiveKind.WRITE, "memcpy", target_pid=1000),
            _primitive(PrimitiveKind.EXECUTE, "EnumSystemLocalesA", target_pid=1000, note="enum_callback"),
        )
    )
    assert result.technique == InjectionTechnique.ENUM_CALLBACK_INJECTION


def test_instrumentation_callback_classification() -> None:
    result = classify_finding(
        _finding(
            _primitive(PrimitiveKind.WRITE, "NtWriteVirtualMemory"),
            _primitive(PrimitiveKind.EXECUTE, "NtSetInformationProcess", note="instrumentation_callback"),
        )
    )
    assert result.technique == InjectionTechnique.INSTRUMENTATION_CALLBACK


def test_poolparty_classification() -> None:
    result = classify_finding(
        _finding(
            _primitive(PrimitiveKind.ALLOCATE, "VirtualAllocEx"),
            _primitive(PrimitiveKind.WRITE, "WriteProcessMemory"),
            _primitive(PrimitiveKind.EXECUTE, "TpAllocWork", note="poolparty_alloc"),
        )
    )
    assert result.technique == InjectionTechnique.POOLPARTY


def test_iat_hooking_classification() -> None:
    # No allocate, only remote protect + small (pointer-sized) write.
    result = classify_finding(
        _finding(
            _primitive(PrimitiveKind.ALLOCATE, "VirtualProtectEx"),
            _primitive(PrimitiveKind.WRITE, "WriteProcessMemory", size=8),
        )
    )
    assert result.technique == InjectionTechnique.IAT_HOOKING


def test_threadless_inject_classification() -> None:
    # No alloc, no thread API, larger trampoline write.
    result = classify_finding(
        _finding(
            _primitive(PrimitiveKind.ALLOCATE, "VirtualProtectEx"),
            _primitive(PrimitiveKind.WRITE, "WriteProcessMemory", size=128),
        )
    )
    assert result.technique == InjectionTechnique.THREADLESS_INJECT


def test_manual_mapping_classification() -> None:
    # Three writes (PE sections) + protect + thread, no LoadLibrary.
    result = classify_finding(
        _finding(
            _primitive(PrimitiveKind.ALLOCATE, "VirtualAllocEx"),
            _primitive(PrimitiveKind.WRITE, "WriteProcessMemory"),
            _primitive(PrimitiveKind.WRITE, "WriteProcessMemory"),
            _primitive(PrimitiveKind.WRITE, "WriteProcessMemory"),
            _primitive(PrimitiveKind.ALLOCATE, "VirtualProtectEx"),
            _primitive(PrimitiveKind.EXECUTE, "RtlCreateUserThread"),
            cross_process=True,
            execution_confirmed=True,
        )
    )
    assert result.technique == InjectionTechnique.MANUAL_MAPPING


def test_classic_dll_injection_classified_before_shellcode() -> None:
    remote_buffer = 0x20000
    result = classify_finding(
        _finding(
            MemoryPrimitive(
                timestamp=datetime.now(timezone.utc),
                kind=PrimitiveKind.ALLOCATE,
                actor_pid=1000,
                actor_image="C:\\malware\\injector.exe",
                target_pid=2000,
                target_image="C:\\Windows\\explorer.exe",
                address=remote_buffer,
                size=64,
                api="VirtualAllocEx",
                details={},
            ),
            MemoryPrimitive(
                timestamp=datetime.now(timezone.utc),
                kind=PrimitiveKind.WRITE,
                actor_pid=1000,
                actor_image="C:\\malware\\injector.exe",
                target_pid=2000,
                target_image="C:\\Windows\\explorer.exe",
                address=remote_buffer,
                size=64,
                api="WriteProcessMemory",
                details={},
            ),
            MemoryPrimitive(
                timestamp=datetime.now(timezone.utc),
                kind=PrimitiveKind.EXECUTE,
                actor_pid=1000,
                actor_image="C:\\malware\\injector.exe",
                target_pid=2000,
                target_image="C:\\Windows\\explorer.exe",
                address=0x7FFE00001000,
                size=1,
                api="CreateRemoteThread",
                details={"thread_parameter": hex(remote_buffer)},
            ),
            cross_process=True,
        )
    )
    assert result.technique == InjectionTechnique.DLL_INJECTION


def test_classic_shellcode_not_misclassified_as_reflective() -> None:
    """Regression: VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
    must classify as SHELLCODE_INJECTION, not REFLECTIVE_DLL (reflective is
    the fallback for the same primitives *without* the canonical trinity)."""
    result = classify_finding(
        _finding(
            _primitive(PrimitiveKind.ALLOCATE, "VirtualAllocEx"),
            _primitive(PrimitiveKind.WRITE, "WriteProcessMemory"),
            _primitive(PrimitiveKind.EXECUTE, "CreateRemoteThread"),
            cross_process=True,
        )
    )
    assert result.technique == InjectionTechnique.SHELLCODE_INJECTION
