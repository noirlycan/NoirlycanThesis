"""Storage microservice — JSONL + SQLite persistence API."""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from noirlycan_telemetry.services.storage.infrastructure.analysis_db import AnalysisDatabase
from noirlycan_telemetry.services.storage.infrastructure.log_store import (
    list_log_files,
    read_jsonl,
    resolve_logs_dir,
    session_detail,
)


def _json_response(handler: BaseHTTPRequestHandler, status: int, payload: dict[str, Any]) -> None:
    body = json.dumps(payload, sort_keys=True).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class StorageHandler(BaseHTTPRequestHandler):
    logs_dir: Path

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        return

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            return _json_response(self, 200, {"status": "ok", "service": "storage"})
        if parsed.path == "/api/sessions":
            sessions = [
                {"name": path.name, "path": str(path)}
                for path in list_log_files(self.logs_dir)
            ]
            return _json_response(self, 200, {"sessions": sessions})
        if parsed.path.startswith("/api/session/"):
            session_name = parsed.path.removeprefix("/api/session/")
            detail = session_detail(self.logs_dir, session_name)
            if detail is None:
                return _json_response(self, 404, {"error": "session not found"})
            return _json_response(self, 200, detail)
        return _json_response(self, 404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path != "/api/events":
            return _json_response(self, 404, {"error": "not found"})
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            return _json_response(self, 400, {"error": "invalid json"})
        session = str(payload.get("session") or "session-remote.jsonl")
        event_type = str(payload.get("type") or "")
        value = payload.get("value")
        if not event_type or value is None:
            return _json_response(self, 400, {"error": "type and value required"})
        target = self.logs_dir / session
        target.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps({"type": event_type, "value": value}, sort_keys=True)
        with target.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        return _json_response(self, 201, {"written": True, "session": session})


def run_storage_api(host: str = "127.0.0.1", port: int = 8780, logs_dir: Path | str | None = None) -> None:
    resolved = resolve_logs_dir(logs_dir)
    StorageHandler.logs_dir = resolved
    server = ThreadingHTTPServer((host, port), StorageHandler)
    print(f"[storage-api] listening on http://{host}:{port} (logs={resolved})")
    server.serve_forever()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Noirlycan storage microservice")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8780)
    parser.add_argument("--logs-dir", default=None)
    args = parser.parse_args(argv)
    run_storage_api(args.host, args.port, args.logs_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
