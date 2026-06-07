from __future__ import annotations

import json
from pathlib import Path

from noirlycan_telemetry.log_store import aggregate_events, read_jsonl, summarize_log_file


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
