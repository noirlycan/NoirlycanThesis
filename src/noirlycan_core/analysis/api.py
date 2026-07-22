"""Analysis microservice — correlation + reclassify API."""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from noirlycan_core.analysis.domain.correlation import Correlator
from noirlycan_core.analysis.domain.reclassify import reclassify_session
from noirlycan_core.storage.infrastructure.log_store import resolve_logs_dir


def _json_response(handler: BaseHTTPRequestHandler, status: int, payload: dict[str, Any]) -> None:
    body = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class AnalysisHandler(BaseHTTPRequestHandler):
    logs_dir: Path
    correlator: Correlator

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        return

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            return _json_response(self, 200, {"status": "ok", "service": "analysis"})
        return _json_response(self, 404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            return _json_response(self, 400, {"error": "invalid json"})

        if parsed.path == "/api/reclassify":
            session = str(payload.get("session") or "")
            if not session:
                return _json_response(self, 400, {"error": "session required"})
            session_path = self.logs_dir / session
            if not session_path.is_file():
                return _json_response(self, 404, {"error": "session not found"})
            report = reclassify_session(session_path, logs_dir=self.logs_dir)
            return _json_response(self, 200, {"report": report})

        if parsed.path == "/api/correlate/ping":
            minimum_score = int(payload.get("minimum_score", 50))
            self.correlator.minimum_score = minimum_score
            return _json_response(
                self,
                200,
                {"status": "ready", "minimum_score": self.correlator.minimum_score},
            )

        return _json_response(self, 404, {"error": "not found"})


def run_analysis_api(host: str = "127.0.0.1", port: int = 8781, logs_dir: Path | str | None = None) -> None:
    resolved = resolve_logs_dir(logs_dir)
    AnalysisHandler.logs_dir = resolved
    AnalysisHandler.correlator = Correlator(logs_dir=resolved)
    server = ThreadingHTTPServer((host, port), AnalysisHandler)
    print(f"[analysis-api] listening on http://{host}:{port} (logs={resolved})")
    server.serve_forever()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Noirlycan analysis microservice")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8781)
    parser.add_argument("--logs-dir", default=None)
    args = parser.parse_args(argv)
    run_analysis_api(args.host, args.port, args.logs_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
