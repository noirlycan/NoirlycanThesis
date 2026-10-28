"""Agent runtime pieces that do not need Windows or Frida."""

from __future__ import annotations

import threading
from pathlib import Path

from noirlycan_agent.runtime.commands import CommandDispatcher, kill_process
from noirlycan_agent.runtime.event_sink import BatchUploader, JsonlWriter, MirroredWriter
from noirlycan_core.runtime.command_signing import CommandSigner, CommandVerifier


def test_batch_uploader_groups_events_and_flushes_on_close() -> None:
    batches: list[list[dict]] = []
    uploader = BatchUploader(batches.append, max_batch=50, max_delay=0.05)
    for index in range(120):
        uploader.submit({"type": "primitive", "value": {"n": index}})
    uploader.close()
    assert sum(len(batch) for batch in batches) == 120
    assert all(len(batch) <= 50 for batch in batches)
    assert [event["value"]["n"] for batch in batches for event in batch] == list(range(120))


def test_batch_uploader_survives_console_errors() -> None:
    calls = []

    def flaky(batch: list[dict]) -> None:
        calls.append(len(batch))
        if len(calls) == 1:
            raise RuntimeError("console down")

    uploader = BatchUploader(flaky, max_batch=1, max_delay=0.01)
    uploader.submit({"type": "a", "value": {}})
    uploader.submit({"type": "b", "value": {}})
    uploader.close()
    assert calls == [1, 1]


def test_mirrored_writer_keeps_local_log_and_reports_findings(tmp_path: Path) -> None:
    sent: list[list[dict]] = []
    seen_findings: list[object] = []
    log = tmp_path / "session.jsonl"
    writer = MirroredWriter(
        JsonlWriter(log),
        BatchUploader(sent.append, max_delay=0.01),
        on_finding=seen_findings.append,
    )
    writer.write("primitive", {"api": "WriteProcessMemory"})
    writer.write("finding", {"severity": "high"})
    writer.close()
    assert log.read_text().count("\n") == 2
    assert [event["type"] for batch in sent for event in batch] == ["primitive", "finding"]
    assert seen_findings == [{"severity": "high"}]


def test_jsonl_writer_is_thread_safe(tmp_path: Path) -> None:
    log = tmp_path / "session.jsonl"
    writer = JsonlWriter(log, flush_every=1)
    threads = [
        threading.Thread(target=lambda: [writer.write("triage", {"x": "y" * 200}) for _ in range(200)])
        for _ in range(4)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    writer.close()
    lines = log.read_text().splitlines()
    assert len(lines) == 800
    assert all(line.startswith('{"type": "triage"') for line in lines)


def test_kill_refuses_protected_pids() -> None:
    assert kill_process(0) is False
    assert kill_process(4) is False


def _signer(tmp_path: Path) -> CommandSigner:
    return CommandSigner.load_or_create(tmp_path)


def test_dispatcher_rejects_unknown_and_malformed_commands(tmp_path: Path) -> None:
    signer = _signer(tmp_path)
    verifier = CommandVerifier(signer.public_key, "lab-vm-1")
    received: list[tuple] = []
    dispatcher = CommandDispatcher(verifier=lambda: verifier, on_sample=lambda *args: received.append(args))

    def sample(n: int, **params) -> dict:
        return signer.sign("lab-vm-1", "sample.run", {"upload_id": n, **params}, command_id=n)

    dispatcher.dispatch(
        [
            signer.sign("lab-vm-1", "shell.exec", {"cmd": "whoami"}, command_id=0),
            sample(1, sha256="zz", filename="a.exe", argv=[]),
            sample(2, sha256="a" * 64, filename="a.ps1", argv=[]),
            sample(3, sha256="a" * 64, filename="a.exe", argv=["& calc"]),
            sample(4, sha256="b" * 64, filename="..\\..\\x.exe", argv=["42"]),
        ]
    )
    assert received == [(4, "b" * 64, "x.exe", ["42"])]


def test_dispatcher_refuses_unsigned_forged_expired_and_replayed(tmp_path: Path) -> None:
    signer = _signer(tmp_path)
    verifier = CommandVerifier(signer.public_key, "lab-vm-1")
    received: list[int] = []
    dispatcher = CommandDispatcher(verifier=lambda: verifier, on_sample=lambda n, *rest: received.append(n))
    params = {"sha256": "c" * 64, "filename": "s.exe", "argv": []}

    good = signer.sign("lab-vm-1", "sample.run", {"upload_id": 1, **params}, command_id=1)
    tampered = {**signer.sign("lab-vm-1", "sample.run", {"upload_id": 2, **params}, command_id=2), "upload_id": 99}
    unsigned = {"command": "sample.run", "upload_id": 3, **params}
    other_agent = signer.sign("lab-vm-2", "sample.run", {"upload_id": 4, **params}, command_id=4)
    expired = signer.sign("lab-vm-1", "sample.run", {"upload_id": 5, **params}, command_id=5)
    expired["expires_at"] = "2000-01-01T00:00:00+00:00"  # also breaks the signature; both must fail
    (tmp_path / "attacker").mkdir()
    forged = CommandSigner.load_or_create(tmp_path / "attacker").sign(
        "lab-vm-1", "sample.run", {"upload_id": 6, **params}, command_id=6
    )

    dispatcher.dispatch([good, good, tampered, unsigned, other_agent, expired, forged])
    assert received == [1]  # The second copy of ``good`` is a replay.

    no_key = CommandDispatcher(verifier=lambda: None, on_sample=lambda n, *rest: received.append(n))
    no_key.dispatch([signer.sign("lab-vm-1", "sample.run", {"upload_id": 7, **params}, command_id=7)])
    assert received == [1]


def test_cached_json_reloads_only_when_file_changes(tmp_path: Path) -> None:
    import os
    import time

    from noirlycan_core.runtime.cached_json import load_json_cached

    path = tmp_path / "policy.json"
    path.write_text('{"v": 1}')
    assert load_json_cached(path) == {"v": 1}
    path.write_text('{"v": 2}')
    os.utime(path, (time.time() + 5, time.time() + 5))  # force a different mtime
    assert load_json_cached(path) == {"v": 2}
    path.unlink()
    assert load_json_cached(path) is None


def test_reclassify_does_not_double_count_legacy_raw_events(tmp_path: Path) -> None:
    import json

    from noirlycan_core.analysis.reclassify import reclassify_session

    base = {"actor_pid": 100, "target_pid": 200, "address": "0x10000", "size": 4096, "timestamp": "2026-01-01T00:00:0{}+00:00"}
    prims = [
        {"kind": "allocate", "api": "VirtualAllocEx", **base, "timestamp": base["timestamp"].format(0)},
        {"kind": "write", "api": "WriteProcessMemory", **base, "timestamp": base["timestamp"].format(1)},
        {"kind": "execute", "api": "CreateRemoteThread", **base, "timestamp": base["timestamp"].format(2)},
    ]
    lines = []
    for prim in prims:
        lines.append(json.dumps({"type": "frida_raw", "value": {"type": "memory_primitive", "primitive": prim["kind"], **prim}}))
        lines.append(json.dumps({"type": "primitive", "value": prim}))
    (tmp_path / "session-x.jsonl").write_text("\n".join(lines) + "\n")
    report = reclassify_session(tmp_path / "session-x.jsonl", logs_dir=tmp_path, minimum_score=0)
    assert report["findings"], "chain should be detected"
    assert len(report["findings"][-1]["primitives"]) == 3


def test_dispatcher_reports_kill_outcome(tmp_path: Path) -> None:
    signer = _signer(tmp_path)
    verifier = CommandVerifier(signer.public_key, "lab-vm-1")
    reports: list[tuple] = []
    dispatcher = CommandDispatcher(verifier=lambda: verifier, report=lambda *args: reports.append(args))
    dispatcher.dispatch([signer.sign("lab-vm-1", "kill", {"pid": 4, "image": "System"}, command_id=77)])
    assert reports == [(77, False, "protected pid")]
