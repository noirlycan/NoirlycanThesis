"""Sample intake over the agent command channel, and session path safety."""

from __future__ import annotations

import hashlib
from pathlib import Path

from noirlycan_core.runtime.command_signing import CommandVerifier

SAMPLE = b"MZ" + b"\x00" * 126


def _register(api, agent_id: str) -> str:
    agent = api.post("/api/agents/register", json={"agent_id": agent_id}).json()["agent"]
    return agent["enrollment_token"]


def _upload(api) -> int:
    response = api.post("/api/samples", files={"file": ("loader.exe", SAMPLE, "application/octet-stream")})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["sha256"] == hashlib.sha256(SAMPLE).hexdigest()
    return body["upload_id"]


def test_rejects_unsupported_upload(api) -> None:
    response = api.post("/api/samples", files={"file": ("notes.txt", b"hi", "text/plain")})
    assert response.status_code == 400


def test_sample_run_flow(api) -> None:
    token = _register(api, "lab-vm-1")
    upload_id = _upload(api)

    run = api.post(f"/api/samples/{upload_id}/run", json={"agent_id": "lab-vm-1", "target_pid": 4321})
    assert run.status_code == 200, run.text
    assert run.json()["argv"] == ["4321"]
    assert api.post(f"/api/samples/{upload_id}/run", json={"agent_id": "lab-vm-1"}).status_code == 409

    agent_headers = {"Authorization": f"Bearer {token}"}
    commands = api.get("/api/agents/lab-vm-1/commands", headers=agent_headers).json()["commands"]
    assert len(commands) == 1
    command = commands[0]
    assert {key: command[key] for key in ("command", "upload_id", "sha256", "filename", "argv", "agent_id")} == {
        "command": "sample.run",
        "upload_id": upload_id,
        "sha256": hashlib.sha256(SAMPLE).hexdigest(),
        "filename": "loader.exe",
        "argv": ["4321"],
        "agent_id": "lab-vm-1",
    }
    hello = api.post(
        "/api/ingest/hello", headers=agent_headers, json={"agent_id": "lab-vm-1", "hostname": "VM"}
    ).json()
    CommandVerifier(hello["command_public_key"], "lab-vm-1").verify(command)

    download = api.get(f"/api/agents/lab-vm-1/samples/{upload_id}", headers=agent_headers)
    assert download.status_code == 200
    assert download.content == SAMPLE

    status = api.post(
        f"/api/agents/lab-vm-1/samples/{upload_id}/status",
        headers=agent_headers,
        json={"status": "spawned", "agent_path": r"C:\Noirlycan\samples\loader.exe"},
    )
    assert status.status_code == 200
    sample = next(item for item in api.get("/api/samples").json()["samples"] if item["id"] == upload_id)
    assert sample["status"] == "spawned"
    assert sample["agent_id"] == "lab-vm-1"
    assert sample["session_name"].startswith("agents/")


def test_agent_cannot_fetch_sample_assigned_elsewhere(api) -> None:
    _register(api, "lab-vm-1")
    other_token = _register(api, "lab-vm-2")
    upload_id = _upload(api)
    api.post(f"/api/samples/{upload_id}/run", json={"agent_id": "lab-vm-1"})

    other = {"Authorization": f"Bearer {other_token}"}
    assert api.get(f"/api/agents/lab-vm-2/samples/{upload_id}", headers=other).status_code == 403
    assert api.get(f"/api/agents/lab-vm-1/samples/{upload_id}", headers=other).status_code == 401


def test_session_export_stays_inside_logs_dir(api, tmp_path: Path, monkeypatch) -> None:
    secret = tmp_path.parent / "secret.jsonl"
    secret.write_text('{"type": "x"}\n')
    monkeypatch.chdir(tmp_path.parent)
    assert api.get("/api/sessions/secret.jsonl/export").status_code == 404
    assert api.get("/api/sessions/..%2Fsecret.jsonl/export").status_code == 404


def test_ingest_batch_writes_to_the_agents_own_session(api, tmp_path: Path) -> None:
    token = _register(api, "lab-vm-1")
    headers = {"Authorization": f"Bearer {token}", "X-Agent-Id": "lab-vm-1"}
    events = [{"type": "primitive", "value": {"n": index}} for index in range(3)]
    response = api.post("/api/ingest/batch", headers=headers, json={"events": events})
    assert response.status_code == 200, response.text
    session = response.json()["session"]
    assert session.startswith("agents/")
    assert (tmp_path / session).read_text().count('"type": "primitive"') == 3

    wrong = {"Authorization": f"Bearer {token}", "X-Agent-Id": "someone-else"}
    assert api.post("/api/ingest/batch", headers=wrong, json={"events": events}).status_code == 401


def test_one_line_install_endpoints(api) -> None:
    import io
    import zipfile

    token = _register(api, "lab-vm-9")
    headers = {"Authorization": f"Bearer {token}"}
    agents = api.get("/api/agents").json()["agents"]
    row = next(item for item in agents if item["id"] == "lab-vm-9")
    assert row["install_command"].startswith("irm http://") and "bootstrap.ps1" in row["install_command"]

    script = api.get("/api/agents/lab-vm-9/bootstrap.ps1", headers=headers)
    assert script.status_code == 200
    assert 'agent_id = "lab-vm-9"' in script.text and "command_key = " in script.text
    assert "package.zip" in script.text and "sysmon-config.xml" in script.text
    assert api.get("/api/agents/lab-vm-9/bootstrap.ps1").status_code == 401

    package = api.get("/api/agents/lab-vm-9/package.zip", headers=headers)
    assert package.status_code == 200
    names = zipfile.ZipFile(io.BytesIO(package.content)).namelist()
    assert "noirlycan-agent/pyproject.toml" in names
    assert "noirlycan-agent/src/noirlycan_agent/frida_hooks/handlers.js" in names
    assert "noirlycan-agent/src/noirlycan_core/detection/rules.py" in names
    assert not any("/noirlycan_backend/" in name or "/lab/" in name for name in names)

    sysmon = api.get("/api/agents/lab-vm-9/sysmon-config.xml", headers=headers)
    assert sysmon.status_code == 200 and b"<Sysmon" in sysmon.content


def test_kill_is_terminated_only_after_agent_confirms(api) -> None:
    token = _register(api, "lab-vm-k")
    other = _register(api, "lab-vm-other")
    agent = {"Authorization": f"Bearer {token}"}

    api.post("/api/agents/lab-vm-k/kill", json={"pid": 4242, "image": "msedge.exe"})
    api.post("/api/agents/lab-vm-k/kill", json={"pid": 5151, "image": "notepad.exe"})

    def state(pid: int) -> str:
        rows = api.get("/api/overview").json()["killed"]
        return next(row["status"] for row in rows if row["pid"] == pid)

    assert state(4242) == "pending" and state(5151) == "pending"
    commands = {c["pid"]: c["command_id"] for c in api.get("/api/agents/lab-vm-k/commands", headers=agent).json()["commands"]}

    # Another agent cannot report on this agent's command.
    forged = api.post(
        f"/api/agents/lab-vm-other/commands/{commands[4242]}/result",
        headers={"Authorization": f"Bearer {other}"},
        json={"ok": True},
    )
    assert forged.json()["updated"] is False
    assert state(4242) == "pending"

    ok = api.post(f"/api/agents/lab-vm-k/commands/{commands[4242]}/result", headers=agent, json={"ok": True, "detail": "terminated"})
    assert ok.json()["updated"] is True
    api.post(f"/api/agents/lab-vm-k/commands/{commands[5151]}/result", headers=agent, json={"ok": False, "detail": "access denied"})
    assert state(4242) == "terminated"
    assert state(5151) == "failed"
