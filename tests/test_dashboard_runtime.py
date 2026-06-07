from __future__ import annotations

from pathlib import Path

from noirlycan_telemetry.dashboard.app import create_app


def test_runtime_api_toggle(tmp_path: Path) -> None:
    app = create_app(logs_dir=tmp_path)
    client = app.test_client()

    response = client.get("/api/runtime")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["file_drop_watch_enabled"] is True

    response = client.post(
        "/api/runtime",
        json={"file_drop_watch_enabled": False},
    )
    assert response.status_code == 200
    assert response.get_json()["file_drop_watch_enabled"] is False

    response = client.get("/api/runtime")
    assert response.get_json()["file_drop_watch_enabled"] is False

    response = client.post(
        "/api/runtime",
        json={"auto_api_analysis_enabled": True},
    )
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["auto_api_analysis_enabled"] is True
    assert payload["auto_triage_enabled"] is True


def test_triage_request_api(tmp_path: Path) -> None:
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 64)

    app = create_app(logs_dir=tmp_path)
    client = app.test_client()
    response = client.post(
        "/api/triage/request",
        json={"path": str(sample), "mode": "api"},
    )
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["queued"] is True
    assert payload["mode"] == "api"
