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
