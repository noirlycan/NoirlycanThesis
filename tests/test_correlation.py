from __future__ import annotations

from datetime import datetime, timedelta, timezone

from noirlycan_telemetry.correlation import Correlator
from noirlycan_telemetry.models import (
    FileEvent,
    MemoryPrimitive,
    PrimitiveKind,
    ProcessEvent,
)


def test_detects_section_mapping_write_execute_chain() -> None:
    now = datetime.now(timezone.utc)
    correlator = Correlator(minimum_score=40)
    correlator.add_file(
        FileEvent(
            timestamp=now,
            path=r"C:\Users\alice\AppData\Local\Temp\loader.exe",
            creator_pid=200,
            creator_image=r"C:\Windows\explorer.exe",
            pe=True,
            signed=False,
            entropy=7.2,
        )
    )
    correlator.add_process(
        ProcessEvent(
            timestamp=now + timedelta(milliseconds=10),
            pid=1337,
            image=r"C:\Users\alice\AppData\Local\Temp\loader.exe",
            parent_pid=200,
            parent_image=r"C:\Windows\explorer.exe",
            flags=["CREATE_SUSPENDED"],
        )
    )
    correlator.add_primitive(
        MemoryPrimitive(
            timestamp=now + timedelta(milliseconds=20),
            kind=PrimitiveKind.WRITE,
            actor_pid=1337,
            actor_image=r"C:\Users\alice\AppData\Local\Temp\loader.exe",
            target_pid=4242,
            target_image=r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            address=0x200000,
            size=0x1000,
            api="NtMapViewOfSection",
            details={"protection": "EXECUTE_READWRITE"},
        )
    )
    findings = correlator.add_primitive(
        MemoryPrimitive(
            timestamp=now + timedelta(milliseconds=30),
            kind=PrimitiveKind.EXECUTE,
            actor_pid=1337,
            actor_image=r"C:\Users\alice\AppData\Local\Temp\loader.exe",
            target_pid=4242,
            target_image=r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            address=None,
            size=None,
            api="ResumeThread",
        )
    )

    assert len(findings) == 1
    assert findings[0].related_file is not None
    assert findings[0].related_file.path.endswith("loader.exe")
    assert findings[0].score >= 70


def test_requires_two_distinct_primitives() -> None:
    now = datetime.now(timezone.utc)
    correlator = Correlator(minimum_score=1)
    findings = correlator.add_primitive(
        MemoryPrimitive(
            timestamp=now,
            kind=PrimitiveKind.WRITE,
            actor_pid=10,
            actor_image="a.exe",
            target_pid=20,
            target_image="b.exe",
            address=0x1000,
            size=0x100,
            api="WriteProcessMemory",
        )
    )

    assert findings == []


def test_rejects_unrelated_memory_ranges() -> None:
    now = datetime.now(timezone.utc)
    correlator = Correlator(minimum_score=1)
    correlator.add_primitive(
        MemoryPrimitive(
            timestamp=now,
            kind=PrimitiveKind.WRITE,
            actor_pid=10,
            actor_image="a.exe",
            target_pid=20,
            target_image="b.exe",
            address=0x1000,
            size=0x100,
            api="WriteProcessMemory",
        )
    )
    findings = correlator.add_primitive(
        MemoryPrimitive(
            timestamp=now + timedelta(milliseconds=1),
            kind=PrimitiveKind.EXECUTE,
            actor_pid=10,
            actor_image="a.exe",
            target_pid=20,
            target_image="b.exe",
            address=0x5000,
            size=1,
            api="CreateRemoteThread",
        )
    )

    assert findings == []


def test_resolves_target_image_from_child_process() -> None:
    now = datetime.now(timezone.utc)
    correlator = Correlator(minimum_score=40)
    correlator.add_process(
        ProcessEvent(
            timestamp=now,
            pid=1337,
            image=r"C:\Lab\loader.exe",
        )
    )
    correlator.add_process(
        ProcessEvent(
            timestamp=now + timedelta(milliseconds=5),
            pid=4242,
            image=r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            parent_pid=1337,
            parent_image=r"C:\Lab\loader.exe",
            flags=["CREATE_SUSPENDED"],
        )
    )
    correlator.add_primitive(
        MemoryPrimitive(
            timestamp=now + timedelta(milliseconds=20),
            kind=PrimitiveKind.WRITE,
            actor_pid=1337,
            actor_image=None,
            target_pid=4242,
            target_image=None,
            address=0x200000,
            size=0x1000,
            api="NtMapViewOfSection",
            details={"protection": "EXECUTE_READWRITE", "cross_process": True},
        )
    )
    findings = correlator.add_primitive(
        MemoryPrimitive(
            timestamp=now + timedelta(milliseconds=30),
            kind=PrimitiveKind.EXECUTE,
            actor_pid=1337,
            actor_image=None,
            target_pid=4242,
            target_image=None,
            address=None,
            size=None,
            api="ResumeThread",
        )
    )

    assert len(findings) == 1
    assert findings[0].target_image is not None
    assert findings[0].target_image.endswith("msedge.exe")
    assert "msedge.exe" in findings[0].description


def test_rejects_write_after_execute_temporal_order() -> None:
    """Paper §3.4 requires allocate → write → execute order.

    A WRITE primitive observed *after* an EXECUTE primitive on the same target
    is a clear ordering violation and must not be reported as a chain. This
    test guards the D3 fix in audit-and-threat-model.md.
    """
    now = datetime.now(timezone.utc)
    correlator = Correlator(minimum_score=1)
    correlator.add_primitive(
        MemoryPrimitive(
            timestamp=now,
            kind=PrimitiveKind.EXECUTE,
            actor_pid=10,
            actor_image="a.exe",
            target_pid=20,
            target_image="b.exe",
            address=0x4000,
            size=1,
            api="CreateRemoteThread",
        )
    )
    findings = correlator.add_primitive(
        MemoryPrimitive(
            timestamp=now + timedelta(milliseconds=5),
            kind=PrimitiveKind.WRITE,
            actor_pid=10,
            actor_image="a.exe",
            target_pid=20,
            target_image="b.exe",
            address=0x4000,
            size=0x100,
            api="WriteProcessMemory",
        )
    )

    assert findings == []


def test_set_thread_context_with_rip_overlaps_write_buffer() -> None:
    """D1 fix: SetThreadContext now carries the new Rip as `address`.

    When the redirect target lands inside the buffer just written, memory
    congruence should connect the WRITE and EXECUTE primitives — this is the
    canonical Process Hollowing signature in the paper.
    """
    now = datetime.now(timezone.utc)
    correlator = Correlator(minimum_score=40)
    correlator.add_process(
        ProcessEvent(
            timestamp=now,
            pid=4242,
            image=r"C:\Program Files\victim.exe",
            parent_pid=1337,
            parent_image=r"C:\Lab\loader.exe",
            flags=["CREATE_SUSPENDED"],
        )
    )
    correlator.add_primitive(
        MemoryPrimitive(
            timestamp=now + timedelta(milliseconds=10),
            kind=PrimitiveKind.WRITE,
            actor_pid=1337,
            actor_image=r"C:\Lab\loader.exe",
            target_pid=4242,
            target_image=r"C:\Program Files\victim.exe",
            address=0x400000,
            size=0x2000,
            api="WriteProcessMemory",
        )
    )
    findings = correlator.add_primitive(
        MemoryPrimitive(
            timestamp=now + timedelta(milliseconds=20),
            kind=PrimitiveKind.EXECUTE,
            actor_pid=1337,
            actor_image=r"C:\Lab\loader.exe",
            target_pid=4242,
            target_image=r"C:\Program Files\victim.exe",
            address=0x400100,  # Rip lands inside the written buffer.
            size=1,
            api="SetThreadContext",
        )
    )

    assert len(findings) == 1
    assert "SetThreadContext" in findings[0].evidence["apis"]


def test_read_only_apis_do_not_satisfy_two_of_three() -> None:
    """D2 fix: NtReadVirtualMemory must not count as a write primitive.

    Before the fix, an actor that allocates + remote-reads (a perfectly normal
    debugger or AV pattern) would already match 2-of-3. After the fix, READ
    is an observation, not a primitive, so this combination is not a chain.
    """
    from noirlycan_telemetry.injection_api_manifest import PAPER_API_CLASSES

    write_class = next(c for c in PAPER_API_CLASSES if c.name == "write")
    assert "NtReadVirtualMemory" not in write_class.apis
    assert "ReadProcessMemory" not in write_class.apis
