from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from noirlycan_backend.domain.agent_sessions import ensure_agent_session_file


def demo_events(*, agent_id: str) -> list[dict[str, Any]]:
    """Representative lab session for dashboard display testing."""
    ts = "2026-07-22T03:50:18.000000+00:00"
    ts2 = "2026-07-22T03:50:19.120000+00:00"
    ts3 = "2026-07-22T03:50:20.440000+00:00"
    ts4 = "2026-07-22T03:50:21.880000+00:00"
    ts5 = "2026-07-22T03:50:23.010000+00:00"

    def wrap(event_type: str, value: dict[str, Any]) -> dict[str, Any]:
        payload = {"type": event_type, "value": value, "agent_id": agent_id}
        if isinstance(value, dict):
            value.setdefault("agent_id", agent_id)
        return payload

    return [
        wrap(
            "primitive",
            {
                "timestamp": ts,
                "kind": "allocate",
                "api": "NtCreateSection",
                "actor_image": r"C:\Lab\loader.exe",
                "actor_pid": 4821,
                "target_pid": 6120,
                "detail": "RWX",
            },
        ),
        wrap(
            "primitive",
            {
                "timestamp": ts2,
                "kind": "write",
                "api": "NtMapViewOfSection",
                "actor_image": r"C:\Lab\loader.exe",
                "actor_pid": 4821,
                "target_pid": 6120,
                "detail": "remote → msedge.exe",
            },
        ),
        wrap(
            "finding",
            {
                "timestamp": ts2,
                "severity": "high",
                "score": 72,
                "title": "Suspended process spawn",
                "description": "Suspended child process observed before remote write.",
                "actor_pid": 4821,
                "actor_image": r"C:\Lab\loader.exe",
                "target_pid": 6120,
                "target_image": r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
                "technique": "process_spawn_inject",
                "evidence": {"cross_process": True, "suspended_spawn": True},
                "primitives": [{"kind": "write", "api": "NtMapViewOfSection"}],
            },
        ),
        wrap(
            "finding",
            {
                "timestamp": ts3,
                "severity": "medium",
                "score": 58,
                "title": "RWX memory in remote process",
                "description": "Remote allocation/write primitives in suspended browser.",
                "actor_pid": 4821,
                "actor_image": r"C:\Lab\loader.exe",
                "target_pid": 6120,
                "target_image": r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
                "technique": "section_mapping_injection",
                "evidence": {"section_mapping": True, "cross_process": True},
                "primitives": [
                    {"kind": "alloc", "api": "NtCreateSection", "detail": "RWX"},
                    {"kind": "write", "api": "NtMapViewOfSection", "detail": "remote → msedge.exe"},
                ],
            },
        ),
        wrap(
            "finding",
            {
                "timestamp": ts4,
                "severity": "critical",
                "score": 96,
                "title": "Probable process injection chain",
                "description": "Section-mapping loader into suspended msedge.exe",
                "actor_pid": 4821,
                "actor_image": r"C:\Lab\loader.exe",
                "target_pid": 6120,
                "target_image": r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
                "technique": "process_hollowing_section",
                "evidence": {
                    "section_mapping": True,
                    "cross_process": True,
                    "suspended_spawn": True,
                },
                "primitives": [
                    {"kind": "alloc", "api": "NtCreateSection", "detail": "RWX"},
                    {"kind": "write", "api": "NtMapViewOfSection", "detail": "remote → msedge.exe"},
                    {"kind": "exec", "api": "SetThreadContext", "detail": "entry = 0x2000"},
                    {"kind": "exec", "api": "ResumeThread", "detail": "payload runs"},
                ],
            },
        ),
        wrap(
            "finding",
            {
                "timestamp": ts5,
                "severity": "low",
                "score": 24,
                "title": "ntdll.dll image load",
                "description": "Benign module load in target after resume.",
                "actor_pid": 4821,
                "actor_image": r"C:\Lab\loader.exe",
                "target_pid": 6120,
                "target_image": r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
                "technique": "unclassified",
                "primitives": [{"kind": "exec", "api": "ResumeThread"}],
            },
        ),
        wrap(
            "triage",
            {
                "timestamp": ts3,
                "path": r"C:\Users\lab\Downloads\payload.bin",
                "sha256": "a1b2c3d4e5f6789012345678901234567890abcd",
                "entropy": 7.4,
                "unsigned": True,
                "signed": False,
                "actor_image": r"C:\Lab\loader.exe",
            },
        ),
        wrap(
            "network",
            {
                "timestamp": ts4,
                "pid": 6120,
                "image": r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
                "destination": "185.12.44.9:443",
                "remote_address": "185.12.44.9:443",
                "protocol": "TLS",
                "connections": 3,
                "classification": "PUBLIC",
                "is_external": True,
                "beacon_candidate": True,
            },
        ),
        wrap(
            "finding",
            {
                "timestamp": ts3,
                "severity": "medium",
                "score": 61,
                "title": "Unsigned PE dropped to disk",
                "description": "Payload staged on disk before injection.",
                "actor_pid": 4821,
                "actor_image": r"C:\Lab\loader.exe",
                "target_pid": None,
                "target_image": None,
                "technique": "pe_injection",
                "evidence": {"unsigned_pe": True},
                "primitives": [],
            },
        ),
    ]


def demo_events_secondary(*, agent_id: str) -> list[dict[str, Any]]:
    """Smaller session for a second lab VM."""
    ts = "2026-07-22T04:10:00.000000+00:00"
    ts2 = "2026-07-22T04:10:05.000000+00:00"

    def wrap(event_type: str, value: dict[str, Any]) -> dict[str, Any]:
        payload = {"type": event_type, "value": value, "agent_id": agent_id}
        if isinstance(value, dict):
            value.setdefault("agent_id", agent_id)
        return payload

    return [
        wrap(
            "finding",
            {
                "timestamp": ts,
                "severity": "high",
                "score": 68,
                "title": "Remote thread creation",
                "description": "CreateRemoteThread into notepad.exe from suspicious parent.",
                "actor_pid": 2204,
                "actor_image": r"C:\Tools\dropper.exe",
                "target_pid": 8891,
                "target_image": r"C:\Windows\System32\notepad.exe",
                "technique": "remote_thread",
                "evidence": {"cross_process": True},
                "primitives": [{"kind": "exec", "api": "CreateRemoteThread"}],
            },
        ),
        wrap(
            "finding",
            {
                "timestamp": ts2,
                "severity": "medium",
                "score": 44,
                "title": "Suspicious memory write",
                "description": "WriteProcessMemory before thread start.",
                "actor_pid": 2204,
                "actor_image": r"C:\Tools\dropper.exe",
                "target_pid": 8891,
                "target_image": r"C:\Windows\System32\notepad.exe",
                "technique": "classic_injection",
                "evidence": {"cross_process": True},
                "primitives": [{"kind": "write", "api": "WriteProcessMemory"}],
            },
        ),
        wrap(
            "network",
            {
                "timestamp": ts2,
                "pid": 8891,
                "image": r"C:\Windows\System32\notepad.exe",
                "destination": "10.0.0.55:8080",
                "remote_address": "10.0.0.55:8080",
                "protocol": "TCP",
                "connections": 1,
                "classification": "PRIVATE",
                "is_external": False,
                "beacon_candidate": False,
            },
        ),
    ]


def write_demo_session(logs_dir: Path, *, agent_id: str, variant: str = "primary") -> tuple[str, Path, int]:
    rel, path = ensure_agent_session_file(logs_dir, agent_id)
    events = demo_events_secondary(agent_id=agent_id) if variant == "secondary" else demo_events(agent_id=agent_id)
    with path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, ensure_ascii=False) + "\n")
    return rel, path, len(events)


def import_jsonl_session(
    logs_dir: Path,
    *,
    agent_id: str,
    source: Path,
) -> tuple[str, Path, int]:
    if not source.is_file():
        raise FileNotFoundError(f"Session file not found: {source}")
    rel, dest = ensure_agent_session_file(logs_dir, agent_id)
    count = 0
    with source.open("r", encoding="utf-8") as src, dest.open("w", encoding="utf-8") as out:
        for line in src:
            text = line.strip()
            if not text:
                continue
            payload = json.loads(text)
            if isinstance(payload, dict):
                payload["agent_id"] = agent_id
                value = payload.get("value")
                if isinstance(value, dict):
                    value["agent_id"] = agent_id
                out.write(json.dumps(payload, ensure_ascii=False) + "\n")
                count += 1
    return rel, dest, count
