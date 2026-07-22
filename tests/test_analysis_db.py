from __future__ import annotations

import json
from pathlib import Path

from noirlycan_core.storage.infrastructure.analysis_db import AnalysisDatabase, sha256_file


def test_ingest_jsonl_persists_findings(tmp_path: Path) -> None:
    session = tmp_path / "sample.jsonl"
    session.write_text(
        json.dumps(
            {
                "type": "finding",
                "value": {
                    "severity": "high",
                    "score": 80,
                    "technique": "dll_injection",
                    "actor_pid": 10,
                    "target_pid": 20,
                    "primitives": [{"api": "CreateRemoteThread", "kind": "execute"}],
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )

    database = AnalysisDatabase(tmp_path)
    upload_id = database.record_upload(
        original_name="sample.jsonl",
        stored_path=str(session),
        content_kind="jsonl",
        size_bytes=session.stat().st_size,
        sha256=sha256_file(session),
        status="parsing",
    )
    parsed = database.ingest_jsonl(session, upload_id=upload_id, session_name=session.name)

    assert parsed["finding_count"] == 1
    stored = database.get_parsed_session(session.name)
    assert stored is not None
    assert stored["finding_count"] == 1
    assert len(stored["findings"]) == 1
    assert stored["findings"][0]["technique"] == "dll_injection"
