"""Collector microservice health endpoint (Windows agent reports here)."""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from noirlycan_core.runtime.config import (
    load_runtime_config,
    runtime_config_payload,
)
from noirlycan_core.storage.infrastructure.log_store import resolve_logs_dir


def _json_response(handler: BaseHTTPRequestHandler, status: int, payload: dict[str, Any]) -> None:
    body = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class CollectorHandler(BaseHTTPRequestHandler):
    logs_dir: str | None = None

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        return

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/health":
            return _json_response(self, 404, {"error": "not found"})
        config = load_runtime_config(self.logs_dir)
        return _json_response(
            self,
            200,
            {"status": "ok", "service": "collector", "runtime": runtime_config_payload(config)},
        )


def run_collector_health(host: str = "127.0.0.1", port: int = 8782, logs_dir: str | None = None) -> None:
    resolved = str(resolve_logs_dir(logs_dir))
    CollectorHandler.logs_dir = resolved
    server = ThreadingHTTPServer((host, port), CollectorHandler)
    print(f"[collector-health] listening on http://{host}:{port}")
    server.serve_forever()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Noirlycan collector health microservice")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8782)
    parser.add_argument("--logs-dir", default=None)
    args = parser.parse_args(argv)
    run_collector_health(args.host, args.port, args.logs_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
