"""Desktop enrollment boundaries and cancellation without a Windows desktop."""

from __future__ import annotations

import queue
import threading
from types import SimpleNamespace

import pytest

from noirlycan_agent.desktop import DesktopLog, normalize_server, server_logs
from noirlycan_core.runtime.agent_identity import identity_path, save_agent_credentials


def test_token_only_enrollment_is_scoped_and_rejects_revoked_tokens(api):
    from noirlycan_backend.api.deps import get_database

    first = api.post("/api/agents/register", json={"agent_id": "desktop-1"}).json()["agent"]
    second = api.post("/api/agents/register", json={"agent_id": "desktop-2"}).json()["agent"]
    token = first["enrollment_token"]

    def resolve(value):
        return api.post("/api/ingest/enrollment", headers={"Authorization": f"Bearer {value}"})

    assert resolve(token).json() == {"agent_id": "desktop-1"}
    assert resolve(second["enrollment_token"]).json() == {"agent_id": "desktop-2"}
    assert resolve(get_database().load_server_config()["token"]).status_code == 401
    assert resolve("wrong-token").status_code == 401
    assert api.post("/api/ingest/enrollment").status_code == 401  # admin token is insufficient
    replacement = get_database().regenerate_agent_token("desktop-1")
    assert resolve(token).status_code == 401
    assert resolve(replacement).json() == {"agent_id": "desktop-1"}


def test_desktop_download_requires_console_permission_and_existing_artifact(api, tmp_path, monkeypatch):
    artifact = tmp_path / "NoirlycanAgent.exe"
    monkeypatch.setenv("NOIRLYCAN_AGENT_EXE", str(artifact))
    assert api.get("/api/agents").json()["desktop_available"] is False
    assert api.get("/api/agents/desktop.exe").status_code == 404
    artifact.write_bytes(b"MZ-build-artifact")
    assert api.get("/api/agents").json()["desktop_available"] is True
    response = api.get("/api/agents/desktop.exe")
    assert response.status_code == 200
    assert response.content == b"MZ-build-artifact"
    assert "NoirlycanAgent.exe" in response.headers["content-disposition"]
    assert api.get("/api/agents/desktop.exe", headers={"Authorization": "Bearer bad-token"}).status_code == 401
    token = api.post("/api/agents/register", json={"agent_id": "desktop-download"}).json()["agent"]["enrollment_token"]
    assert api.get("/api/agents/desktop.exe", headers={"Authorization": "Bearer " + token}).status_code == 401


def test_admin_can_publish_installer_and_client_downloads_exact_artifact(api, tmp_path, monkeypatch):
    from noirlycan_backend.api.routes import agents

    monkeypatch.setenv("NOIRLYCAN_AGENT_ARTIFACTS_DIR", str(tmp_path / "releases"))
    checked = []
    monkeypatch.setattr(agents, "validate_agent_release", lambda path, kind: checked.append((path.read_bytes(), kind)))
    content = b"test-approved-installer-artifact"
    response = api.post("/api/agents/desktop/releases/installer",
                        files={"file": ("../../different-name.exe", content, "application/octet-stream")})
    assert response.status_code == 200, response.text
    assert checked == [(content, "installer")]
    assert response.json()["filename"] == "NoirlycanAgentSetup.exe"
    assert (tmp_path / "releases" / "NoirlycanAgentSetup.exe").read_bytes() == content
    assert api.get("/api/agents").json()["installer_available"] is True
    download = api.get("/api/agents/setup.exe")
    assert download.content == content
    assert download.headers["cache-control"] == "no-store"
    assert not list((tmp_path / "releases").glob("*.upload"))


def test_rejecting_bad_release_preserves_previous_download(api, tmp_path, monkeypatch):
    directory = tmp_path / "releases"
    directory.mkdir()
    published = directory / "NoirlycanAgent.exe"
    published.write_bytes(b"previous-release")
    monkeypatch.setenv("NOIRLYCAN_AGENT_ARTIFACTS_DIR", str(directory))
    response = api.post("/api/agents/desktop/releases/portable",
                        files={"file": ("Agent.exe", b"not-a-windows-executable", "application/octet-stream")})
    assert response.status_code == 400
    assert published.read_bytes() == b"previous-release"
    assert not list(directory.glob("*.upload"))


def test_release_upload_size_limit_cleans_up_partial_file(api, tmp_path, monkeypatch):
    from noirlycan_backend.api.routes import agents

    monkeypatch.setenv("NOIRLYCAN_AGENT_ARTIFACTS_DIR", str(tmp_path / "releases"))
    monkeypatch.setattr(agents, "MAX_AGENT_RELEASE_BYTES", 8)
    response = api.post("/api/agents/desktop/releases/portable",
                        files={"file": ("Agent.exe", b"0123456789", "application/octet-stream")})
    assert response.status_code == 413
    assert not list((tmp_path / "releases").glob("*.upload"))
    assert not (tmp_path / "releases" / "NoirlycanAgent.exe").exists()


def test_only_admin_can_publish_a_binary(api, monkeypatch, tmp_path):
    from noirlycan_backend.api.auth import create_access_token

    monkeypatch.setenv("NOIRLYCAN_AGENT_ARTIFACTS_DIR", str(tmp_path / "releases"))
    token = create_access_token({"email": "viewer@lab", "role": "Viewer", "name": "Viewer"})
    response = api.post("/api/agents/desktop/releases/installer",
                        headers={"Authorization": "Bearer " + token},
                        files={"file": ("Setup.exe", b"ignored", "application/octet-stream")})
    assert response.status_code == 403
    assert not (tmp_path / "releases").exists()


@pytest.mark.parametrize("server", ["", "ftp://host", "http://host:wrong", "http://user:pass@host",
                                   "http://host/api", "http://host?token=secret", "http://bad host"])
def test_reject_invalid_server(server):
    with pytest.raises(ValueError):
        normalize_server(server)


def test_server_credentials_and_logs_are_separate(tmp_path):
    assert normalize_server("  localhost:8000/  ") == "http://localhost:8000"
    assert server_logs(tmp_path, "https://first") != server_logs(tmp_path, "https://second")


def test_desktop_never_saves_token_when_protection_fails(tmp_path, monkeypatch):
    monkeypatch.setattr("noirlycan_core.runtime.agent_identity._protect", lambda _: None)
    with pytest.raises(OSError, match="DPAPI"):
        save_agent_credentials("desktop-1", tmp_path, token="secret", require_protection=True)
    assert not identity_path(tmp_path).exists()


def test_ui_log_redacts_token_and_drops_excess_messages():
    events = queue.Queue(maxsize=1)
    output = DesktopLog(events, "private-token")
    output.write("Error: private-token")
    output.write("overflow")
    assert events.get_nowait() == ("log", "Error: [TOKEN]")


@pytest.mark.parametrize("crash", [False, True])
def test_collector_cancellation_and_errors_always_cleanup(tmp_path, monkeypatch, crash):
    from noirlycan_agent.cli import build_parser
    from noirlycan_agent.runtime import collector

    stop = threading.Event()
    calls = []

    def poll(*args, **kwargs):
        calls.append("poll")
        stop.set()
        if crash:
            raise RuntimeError("sensor failed")

    agent = SimpleNamespace(
        logs_dir=tmp_path, monitor=None, console=None,
        apply=lambda tick: None, read_tick=lambda: SimpleNamespace(auto_attach=False),
        intake=SimpleNamespace(watch_paths=[], triage_path=None),
        runner=SimpleNamespace(process_queue=lambda path: None),
        poll_sensors=poll, shutdown=lambda: calls.append("shutdown"),
        correlator=SimpleNamespace(network_watch_pids=lambda: []),
    )
    monkeypatch.setattr(collector, "build_agent", lambda *args, **kwargs: agent)
    monkeypatch.setattr(collector, "create_sysmon_or_none", lambda _: None)
    monkeypatch.setattr(collector, "enable_wfp_audit", lambda: False)
    monkeypatch.setattr(collector, "_sync_watcher", lambda *args: None)
    monkeypatch.setattr(collector, "touch_collector_heartbeat", lambda **kwargs: None)
    args = build_parser().parse_args(["run", "--poll-interval", "60"])
    if crash:
        with pytest.raises(RuntimeError, match="sensor failed"):
            collector.run_collector(args, stop_event=stop)
    else:
        assert collector.run_collector(args, stop_event=stop) == 0
    assert calls == ["poll", "shutdown"]
    assert not (tmp_path / ".collector.pid").exists()
