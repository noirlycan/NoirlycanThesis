from __future__ import annotations

import json
from pathlib import Path

from noirlycan_dashboard import make_client


def test_runtime_api_toggle(tmp_path: Path) -> None:
    client = make_client(tmp_path)

    response = client.get("/api/runtime")
    assert response.status_code == 200
    payload = response.json()
    assert payload["file_drop_watch_enabled"] is True

    response = client.post(
        "/api/runtime",
        data=json.dumps({"file_drop_watch_enabled": False}),
        content_type="application/json",
    )
    assert response.status_code == 200
    assert response.json()["file_drop_watch_enabled"] is False

    response = client.get("/api/runtime")
    assert response.json()["file_drop_watch_enabled"] is False

    response = client.post(
        "/api/runtime",
        data=json.dumps({"auto_api_analysis_enabled": True}),
        content_type="application/json",
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["auto_api_analysis_enabled"] is True
    assert payload["auto_triage_enabled"] is True


def test_triage_request_api(tmp_path: Path) -> None:
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 64)

    client = make_client(tmp_path)
    response = client.post(
        "/api/triage/request",
        data=json.dumps({"path": str(sample), "mode": "api"}),
        content_type="application/json",
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["queued"] is True
    assert payload["mode"] == "api"
