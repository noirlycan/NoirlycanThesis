from __future__ import annotations

from datetime import datetime, timedelta, timezone

from noirlycan_telemetry.correlation import Correlator, NETWORK_WATCH_MIN_SCORE
from noirlycan_telemetry.models import MemoryPrimitive, NetworkConnectionEvent, PrimitiveKind
from noirlycan_telemetry.network import is_external_beacon_candidate


def _primitive(kind: PrimitiveKind, api: str, offset_ms: int, address: int | None = 0x200000) -> MemoryPrimitive:
    now = datetime.now(timezone.utc)
    return MemoryPrimitive(
        timestamp=now + timedelta(milliseconds=offset_ms),
        kind=kind,
        actor_pid=100,
        actor_image=r"D:\thesis\aes_decrypt_loader.exe",
        target_pid=200,
        target_image=r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        address=address,
        size=0x1000 if kind == PrimitiveKind.WRITE else None,
        api=api,
        details={"protection": "EXECUTE_READWRITE"} if kind == PrimitiveKind.WRITE else {},
    )


def test_emits_only_highest_score_finding_per_chain() -> None:
    correlator = Correlator(minimum_score=50)
    correlator.add_primitive(_primitive(PrimitiveKind.ALLOCATE, "NtAllocateVirtualMemory", 0))
    correlator.add_primitive(_primitive(PrimitiveKind.WRITE, "NtWriteVirtualMemory", 10))
    first = correlator.add_primitive(_primitive(PrimitiveKind.EXECUTE, "GetThreadContext", 20, address=None))
    second = correlator.add_primitive(_primitive(PrimitiveKind.EXECUTE, "ResumeThread", 30, address=None))

    assert len(first) == 1
    assert len(second) == 0
    assert first[0].score >= NETWORK_WATCH_MIN_SCORE


def test_network_watch_collects_connections_for_target_pid() -> None:
    correlator = Correlator(minimum_score=50)
    correlator.add_primitive(_primitive(PrimitiveKind.ALLOCATE, "NtAllocateVirtualMemory", 0))
    correlator.add_primitive(_primitive(PrimitiveKind.WRITE, "NtMapViewOfSection", 10))
    findings = correlator.add_primitive(
        _primitive(PrimitiveKind.EXECUTE, "ResumeThread", 20, address=None)
    )
    assert findings
    assert findings[0].target_pid == 200

    ignored = correlator.add_network_connection(
        NetworkConnectionEvent(
            timestamp=datetime.now(timezone.utc),
            pid=999,
            image="other.exe",
            protocol="tcp",
            destination_ip="8.8.8.8",
            destination_hostname=None,
            destination_port=443,
        )
    )
    assert ignored is None

    watched = correlator.add_network_connection(
        NetworkConnectionEvent(
            timestamp=datetime.now(timezone.utc),
            pid=200,
            image="msedge.exe",
            protocol="tcp",
            destination_ip="185.199.108.153",
            destination_hostname="c2.example.com",
            destination_port=443,
        )
    )
    assert watched is not None
    assert is_external_beacon_candidate(watched.destination_ip, watched.destination_hostname)
    assert len(correlator.network_connections[200]) == 1
