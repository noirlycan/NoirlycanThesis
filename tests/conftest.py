from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def api(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """FastAPI test client logged in as the seeded lab admin, with logs in tmp_path."""
    from fastapi.testclient import TestClient

    from noirlycan_backend.api.app import create_app
    from noirlycan_backend.api.deps import reset_runtime_paths

    monkeypatch.setenv("NOIRLYCAN_LOGS_DIR", str(tmp_path))
    monkeypatch.setenv("NOIRLYCAN_ADMIN_PASSWORD", "admin")
    reset_runtime_paths(tmp_path)
    client = TestClient(create_app())
    login = client.post("/api/auth/login", json={"email": "admin@lab", "password": "admin"}).json()
    client.headers["Authorization"] = f"Bearer {login['token']}"
    yield client
    reset_runtime_paths(tmp_path)
