from __future__ import annotations

from pathlib import Path

from flask import Flask, jsonify, render_template, request

from ..log_store import aggregate_logs, resolve_logs_dir


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

    return app


def run_dashboard(host: str = "127.0.0.1", port: int = 8765, logs_dir: Path | str | None = None) -> None:
    app = create_app(logs_dir=logs_dir)
    print(f"[+] Dashboard: http://{host}:{port}")
    print(f"[+] Reading logs from: {app.config['LOGS_DIR']}")
    app.run(host=host, port=port, debug=False, use_reloader=False)
