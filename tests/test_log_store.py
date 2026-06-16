from __future__ import annotations

import json
from pathlib import Path

from noirlycan_telemetry.services.storage.infrastructure.log_store import (
    _dedupe_findings,
    aggregate_events,
    default_logs_dir,
    find_project_root,
    read_jsonl,
    session_detail,
    summarize_log_file,
)


def test_aggregate_events_counts_findings_and_primitives(tmp_path: Path) -> None:
    log_path = tmp_path / "sample.jsonl"
    log_path.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "type": "primitive",
                        "value": {
                            "timestamp": "2026-06-07T16:26:01.212000+00:00",
                            "kind": "write",
                            "api": "NtWriteVirtualMemory",
                            "actor_image": "D:\\lab\\loader.exe",
                            "actor_pid": 1,
                            "target_pid": 2,
                        },
                    }
                ),
                json.dumps(
                    {
                        "type": "finding",
                        "value": {
                            "timestamp": "2026-06-07T16:26:01.219000+00:00",
                            "severity": "critical",
                            "score": 100,
                            "title": "Probable process injection chain",
                            "description": "loader injected pid 2",
                            "actor_pid": 1,
                            "target_pid": 2,
                            "primitives": [{"api": "NtWriteVirtualMemory", "kind": "write"}],
                        },
                    }
                ),
            ]
        ),
        encoding="utf-8",
    )

    events = read_jsonl(log_path)
    stats = aggregate_events(events)
    summary = summarize_log_file(log_path)

    assert stats["totals"]["events"] == 2
    assert stats["totals"]["findings"] == 1
    assert stats["totals"]["primitives"] == 1
    assert stats["severity"]["critical"] == 1
    assert stats["primitive_kinds"]["write"] == 1
    assert summary.finding_count == 1
    assert summary.critical_count == 1


def test_dedupe_findings_keeps_highest_score_per_target() -> None:
    rows = _dedupe_findings(
        [
            {"actor_pid": 1, "target_pid": 2, "score": 70, "timestamp": "t1"},
            {"actor_pid": 1, "target_pid": 2, "score": 100, "timestamp": "t2"},
            {"actor_pid": 1, "target_pid": 2, "score": 85, "timestamp": "t3"},
        ]
    )
    assert len(rows) == 1
    assert rows[0]["score"] == 100


def test_default_logs_dir_points_to_repo_logs() -> None:
    root = find_project_root()
    logs_dir = default_logs_dir()
    assert (root / "pyproject.toml").exists()
    assert logs_dir == (root / "logs").resolve()


def test_session_detail_filters_by_severity_and_pid(tmp_path: Path) -> None:
    log_path = tmp_path / "session.jsonl"
    log_path.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "type": "finding",
                        "value": {
                            "timestamp": "2026-06-07T16:26:01.219000+00:00",
                            "severity": "critical",
                            "score": 100,
                            "target_pid": 2,
                            "apis": ["NtWriteVirtualMemory"],
                        },
                    }
                ),
                json.dumps(
                    {
                        "type": "finding",
                        "value": {
                            "timestamp": "2026-06-07T16:26:02.219000+00:00",
                            "severity": "high",
                            "score": 70,
                            "target_pid": 3,
                            "apis": ["CreateRemoteThread"],
                        },
                    }
                ),
                json.dumps(
                    {
                        "type": "network",
                        "value": {
                            "timestamp": "2026-06-07T16:26:03.219000+00:00",
                            "pid": 2,
                            "destination_ip": "8.8.8.8",
                            "destination_port": 443,
                            "protocol": "tcp",
                        },
                    }
                ),
            ]
        ),
        encoding="utf-8",
    )

    detail = session_detail("session.jsonl", tmp_path, severity="critical", target_pid=2)
    assert detail is not None
    assert detail["name"] == "session.jsonl"
    assert len(detail["findings"]) == 1
    assert detail["findings"][0]["target_pid"] == 2
    assert len(detail["network"]) == 1
    assert detail["network"][0]["beacon_candidate"] is True


def test_aggregate_events_collects_triage_rows(tmp_path: Path) -> None:
    log_path = tmp_path / "session.jsonl"
    log_path.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "type": "triage",
                        "value": {
                            "path": "D:\\thesis\\aes_decrypt_loader - Copy.exe",
                            "score": 55,
                            "sha256": "abc",
                            "pe": True,
                            "signed": False,
                            "entropy": 6.5,
                            "suspicious_reasons": ["unsigned_pe"],
                        },
                    }
                )
            ]
        ),
        encoding="utf-8",
    )
    events = read_jsonl(log_path)
    stats = aggregate_events(events)
    assert stats["totals"]["triage"] == 1
    assert stats["recent_triages"][0]["path"].endswith("Copy.exe")


def test_pending_file_drops_without_triage(tmp_path: Path) -> None:
    log_path = tmp_path / "drops.jsonl"
    log_path.write_text(
        json.dumps(
            {
                "type": "file",
                "value": {
                    "timestamp": "2026-06-07T18:00:00+00:00",
                    "path": "D:\\drop_pending.exe",
                    "creator_image": "file-scanner",
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    stats = aggregate_events(read_jsonl(log_path))
    assert len(stats["pending_file_drops"]) == 1
    assert stats["pending_file_drops"][0]["path"].endswith("drop_pending.exe")
    assert stats["pending_file_drops"][0]["status"] == "pending"


def test_findings_enriched_with_target_image_from_process_events(tmp_path: Path) -> None:
    log_path = tmp_path / "injection.jsonl"
    log_path.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "type": "frida_process",
                        "value": {
                            "timestamp": "2026-06-07T18:00:00+00:00",
                            "pid": 4242,
                            "image": r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                        },
                    }
                ),
                json.dumps(
                    {
                        "type": "finding",
                        "value": {
                            "timestamp": "2026-06-07T18:00:01+00:00",
                            "severity": "high",
                            "score": 75,
                            "title": "Probable process injection chain",
                            "description": "loader against pid 4242",
                            "actor_pid": 1337,
                            "target_pid": 4242,
                            "primitives": [
                                {
                                    "kind": "write",
                                    "api": "NtMapViewOfSection",
                                    "actor_pid": 1337,
                                    "target_pid": 4242,
                                }
                            ],
                            "evidence": {"cross_process": True},
                        },
                    }
                ),
            ]
        ),
        encoding="utf-8",
    )
    stats = aggregate_events(read_jsonl(log_path))
    assert stats["recent_findings"][0]["target_image"].endswith("msedge.exe")


def test_aggregate_logs_falls_back_when_selected_log_missing(tmp_path: Path) -> None:
    """Regression: stale URL hash (#log=deleted.jsonl) used to return the
    requested name as active_log even though the file did not exist, which
    broke the dashboard dropdown. Now we fall back to the newest existing
    log so the UI always lands on something loadable."""
    real = tmp_path / "session-real.jsonl"
    real.write_text(
        json.dumps({"type": "finding", "value": {"severity": "low"}}) + "\n",
        encoding="utf-8",
    )
    from noirlycan_telemetry.services.storage.infrastructure.log_store import aggregate_logs

    result = aggregate_logs(tmp_path, selected="session-deleted.jsonl")
    assert result["active_log"] == "session-real.jsonl"


def test_aggregate_logs_empty_dir_with_stale_selection_returns_none(
    tmp_path: Path,
) -> None:
    from noirlycan_telemetry.services.storage.infrastructure.log_store import aggregate_logs

    result = aggregate_logs(tmp_path, selected="anything.jsonl")
    assert result["active_log"] is None
    assert result["files"] == []
