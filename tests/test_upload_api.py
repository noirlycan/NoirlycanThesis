from __future__ import annotations

import json
from pathlib import Path

from django.core.files.uploadedfile import SimpleUploadedFile

from noirlycan_telemetry.services.storage.infrastructure.analysis_db import AnalysisDatabase
from noirlycan_telemetry.services.collector.application.analysis_queue import load_analysis_queue
from noirlycan_telemetry.services.dashboard import make_client


def test_upload_jsonl_parses_into_database(tmp_path: Path) -> None:
    client = make_client(tmp_path)

    payload = (
        json.dumps(
            {
                "type": "primitive",
                "value": {
                    "kind": "write",
                    "api": "WriteProcessMemory",
                    "actor_pid": 1,
                    "target_pid": 2,
                    "timestamp": "2026-06-08T12:00:00+00:00",
                },
            }
        )
        + "\n"
    ).encode("utf-8")

    response = client.post(
        "/api/upload",
        {
            "file": SimpleUploadedFile("lab.jsonl", payload, content_type="application/octet-stream"),
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["kind"] == "jsonl"
    assert body["session_name"].endswith(".jsonl")

    database = AnalysisDatabase(tmp_path)
    uploads = database.list_uploads()
    assert len(uploads) == 1
    assert uploads[0]["status"] == "parsed"
    sessions = database.list_parsed_sessions()
    assert len(sessions) == 1
    assert (tmp_path / body["session_name"]).exists()


def test_upload_executable_does_not_auto_queue(tmp_path: Path) -> None:
    client = make_client(tmp_path)

    response = client.post(
        "/api/upload",
        {
            "file": SimpleUploadedFile(
                "injector.exe",
                b"MZ" + b"\x00" * 64,
                content_type="application/octet-stream",
            ),
            "target_pid": "4242",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["kind"] == "executable"
    assert "run" in body["message"].lower()

    queue = load_analysis_queue(tmp_path)
    assert len(queue.pending) == 0

    database = AnalysisDatabase(tmp_path)
    uploads = database.list_uploads()
    assert len(uploads) == 1
    assert uploads[0]["status"] == "uploaded"


def test_upload_run_and_delete(tmp_path: Path) -> None:
    client = make_client(tmp_path)

    upload_response = client.post(
        "/api/upload",
        {
            "file": SimpleUploadedFile(
                "injector.exe",
                b"MZ" + b"\x00" * 128,
                content_type="application/octet-stream",
            ),
            "target_pid": "4242",
        },
    )
    upload_id = upload_response.json()["upload_id"]

    run_response = client.post(
        f"/api/uploads/{upload_id}/run",
        data=json.dumps({"target_pid": 4242}),
        content_type="application/json",
    )
    assert run_response.status_code == 200
    run_body = run_response.json()
    assert run_body["queued"] is True
    assert run_body["argv"] == ["4242"]

    queue = load_analysis_queue(tmp_path)
    assert len(queue.pending) == 1
    assert queue.pending[0].argv == ["4242"]

    database = AnalysisDatabase(tmp_path)
    assert database.get_upload(upload_id)["status"] == "queued"

    delete_response = client.post(f"/api/uploads/{upload_id}/delete")
    assert delete_response.status_code == 200
    assert database.get_upload(upload_id) is None
    assert load_analysis_queue(tmp_path).pending == []
