"""Sysmon kernel-callback events as a second sensor next to Frida."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from noirlycan_core.detection.correlator import Correlator
from noirlycan_core.extensions.kernel_evidence import kernel_evidence, read_call_trace
from noirlycan_core.models import EventSource, MemoryPrimitive, PrimitiveKind, ProcessAccessEvent, TelemetryEvent
from noirlycan_core.trace.sysmon import access_from_process_access, primitive_from_remote_thread

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
NTDLL = r"C:\WINDOWS\SYSTEM32\ntdll.dll+9d4c4"


def _sysmon(kind: str, t: int, **data: str) -> TelemetryEvent:
    return TelemetryEvent(source=EventSource.SYSMON, kind=kind, timestamp=T0 + timedelta(milliseconds=t), data=data)


def _frida(kind: PrimitiveKind, api: str, t: int, address: int, size: int = 0x1000) -> MemoryPrimitive:
    return MemoryPrimitive(
        timestamp=T0 + timedelta(milliseconds=t),
        kind=kind,
        actor_pid=100,
        actor_image="loader.exe",
        target_pid=200,
        target_image="notepad.exe",
        address=address,
        size=size,
        api=api,
        details={"protection": "PAGE_EXECUTE_READWRITE"},
    )


def _remote_thread(t: int, start: str, module: str = "") -> TelemetryEvent:
    return _sysmon(
        "sysmon_eid_8",
        t,
        SourceProcessId="100",
        TargetProcessId="200",
        SourceImage="loader.exe",
        TargetImage="notepad.exe",
        StartAddress=start,
        StartModule=module,
        NewThreadId="4242",
    )


def test_remote_thread_into_unbacked_memory_carries_its_start_address() -> None:
    primitive = primitive_from_remote_thread(_remote_thread(0, "0x1A0000"))
    assert primitive is not None
    assert primitive.kind == PrimitiveKind.EXECUTE and primitive.source == "sysmon"
    assert primitive.address == 0x1A0000
    assert primitive.details["unbacked_start"] is True


def test_remote_thread_into_a_module_does_not_claim_a_buffer_address() -> None:
    primitive = primitive_from_remote_thread(_remote_thread(0, "0x7FF8A0001000", r"C:\Windows\System32\KERNEL32.DLL"))
    assert primitive is not None and primitive.address is None


def test_kernel_thread_completes_a_chain_frida_only_half_saw() -> None:
    """Frida saw allocate + write, the hook missed the thread, the kernel saw it."""
    correlator = Correlator(minimum_score=0, resolve_image=lambda pid: None)
    correlator.add_primitive(_frida(PrimitiveKind.ALLOCATE, "VirtualAllocEx", 0, 0x1A0000))
    correlator.add_primitive(_frida(PrimitiveKind.WRITE, "WriteProcessMemory", 1, 0x1A0000))
    findings = correlator.add_primitive(primitive_from_remote_thread(_remote_thread(2, "0x1A0000")))
    assert findings, "kernel EXECUTE should advance the chain"
    evidence = findings[-1].evidence
    assert evidence["execution_confirmed"] is True
    assert evidence["hook_bypass_suspected"] is True
    assert evidence["sensors"] == ["frida", "sysmon"]


def test_call_trace_verdicts() -> None:
    normal = read_call_trace(f"{NTDLL}|C:\\Windows\\System32\\KERNELBASE.dll+2c13e|C:\\lab\\loader.exe+1234")
    assert normal is not None and not normal.direct_syscall and normal.unbacked_frames == 0
    direct = read_call_trace("C:\\lab\\loader.exe+1f00|UNKNOWN(000001A2B3C4D5E6)")
    assert direct is not None and direct.direct_syscall and direct.unbacked_frames == 1


def test_unbacked_frames_are_ignored_while_frida_is_attached() -> None:
    access = ProcessAccessEvent(T0, 100, 200, 0x1FFFFF, f"{NTDLL}|UNKNOWN(00007FFF8B23372F)")
    frida_chain = [_frida(PrimitiveKind.WRITE, "WriteProcessMemory", 0, 0x1000)]
    bonus, evidence = kernel_evidence(frida_chain, [access])
    assert bonus == 0 and "unbacked_caller" not in evidence
    assert evidence["unbacked_caller_unreliable"] == "frida trampolines"

    kernel_chain = [primitive_from_remote_thread(_remote_thread(0, "0x1A0000"))]
    bonus, evidence = kernel_evidence(kernel_chain, [access])
    assert evidence["unbacked_caller"] is True and bonus > 0


def test_process_access_parsing_and_noise_filter() -> None:
    access = access_from_process_access(
        _sysmon("sysmon_eid_10", 0, SourceProcessId="100", TargetProcessId="200", GrantedAccess="0x1fffff", CallTrace=NTDLL)
    )
    assert access is not None and access.granted_access == 0x1FFFFF
    _, evidence = kernel_evidence([], [ProcessAccessEvent(T0, 100, 200, 0x1000, NTDLL)])
    assert "handle_access" not in evidence  # QUERY_LIMITED_INFORMATION is not an injection right


def test_chain_is_reported_again_when_it_gains_a_step_at_the_score_cap() -> None:
    """Score is capped at 100; a later, more complete step must still be reported."""
    correlator = Correlator(minimum_score=0, resolve_image=lambda pid: None)
    correlator.add_process_access(ProcessAccessEvent(T0, 100, 200, 0x1FFFFF, "C:\\lab\\loader.exe+1|UNKNOWN(1)"))
    first = correlator.add_primitive(_frida(PrimitiveKind.WRITE, "NtMapViewOfSection", 1, 0x1A0000))
    first += correlator.add_primitive(primitive_from_remote_thread(_remote_thread(2, "0x1A0000")))
    assert first
    later = correlator.add_primitive(_frida(PrimitiveKind.ALLOCATE, "NtCreateSection", 0, 0x1A0000))
    assert later, "adding the allocate step is progress even if the score cannot rise"
