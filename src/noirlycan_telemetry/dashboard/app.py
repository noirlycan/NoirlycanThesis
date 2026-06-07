from __future__ import annotations

from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_file

from ..log_store import aggregate_logs, resolve_log_path, resolve_logs_dir, session_detail
from ..runtime_config import load_runtime_config, runtime_config_payload, save_runtime_config


def create_app(logs_dir: Path | str | None = None) -> Flask:
    package_root = Path(__file__).resolve().parent
    app = Flask(
        __name__,
        template_folder=str(package_root / "templates"),
        static_folder=str(package_root / "static"),
    )
    app.config["LOGS_DIR"] = resolve_logs_dir(logs_dir)

    @app.get("/")
    def index() -> str:
        return render_template("index.html")

    @app.get("/api/overview")
    def overview():
        selected = request.args.get("log")
        payload = aggregate_logs(app.config["LOGS_DIR"], selected=selected)
        return jsonify(payload)

    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok", "logs_dir": str(app.config["LOGS_DIR"])})

    @app.get("/api/runtime")
    def runtime_get():
        config = load_runtime_config(app.config["LOGS_DIR"])
        return jsonify(runtime_config_payload(config))

    @app.post("/api/runtime")
    def runtime_post():
        payload = request.get_json(silent=True) or {}
        config = load_runtime_config(app.config["LOGS_DIR"])
        if config.file_drop_watch_locked:
            return jsonify({"error": "file drop watch is locked by CLI (--no-watch-files)"}), 409
        if "file_drop_watch_enabled" in payload:
            config.file_drop_watch_enabled = bool(payload["file_drop_watch_enabled"])
        save_runtime_config(config, app.config["LOGS_DIR"])
        return jsonify(runtime_config_payload(config))

    @app.get("/api/session/<path:name>")
    def session(name: str):
        severity = request.args.get("severity") or None
        target_pid = request.args.get("pid", type=int)
        query = request.args.get("q") or None
        event_type = request.args.get("type") or None
        limit = request.args.get("limit", default=200, type=int)
        payload = session_detail(
            name,
            app.config["LOGS_DIR"],
            severity=severity,
            target_pid=target_pid,
            query=query,
            event_type=event_type,
            limit=limit,
        )
        if payload is None:
            return jsonify({"error": "session not found"}), 404
        return jsonify(payload)

    @app.get("/api/export/<path:name>")
    def export_session(name: str):
        path = resolve_log_path(app.config["LOGS_DIR"], name)
        if path is None:
            return jsonify({"error": "session not found"}), 404
        return send_file(path, as_attachment=True, download_name=path.name)

    return app


def run_dashboard(host: str = "127.0.0.1", port: int = 8765, logs_dir: Path | str | None = None) -> None:
    app = create_app(logs_dir=logs_dir)
    print(f"[+] Dashboard: http://{host}:{port}")
    print(f"[+] Reading logs from: {app.config['LOGS_DIR']}")
    app.run(host=host, port=port, debug=False, use_reloader=False)
