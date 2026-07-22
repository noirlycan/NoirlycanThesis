from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from noirlycan_backend.api.deps import reset_runtime_paths, warm_database

from noirlycan_backend.api.routes import (
    agents,
    auth,
    file_drops,
    findings,
    ingest,
    overview,
    reports,
    rules,
    sessions,
    users,
    ws,
)


def _cors_origins() -> list[str]:
    raw = os.environ.get("NOIRLYCAN_CORS_ORIGINS", "").strip()
    if raw:
        return [origin.strip() for origin in raw.split(",") if origin.strip()]
    return [
        "http://127.0.0.1:8080",
        "http://localhost:8080",
        "http://127.0.0.1:5173",
        "http://localhost:5173",
    ]


def create_app(*, ui_dist: Path | None = None) -> FastAPI:
    app = FastAPI(
        title="Noirlycan Backend API",
        version="0.2.0",
        description="Lab backend for process-injection telemetry (ingest, auth, rules, agents)",
    )

    @app.on_event("startup")
    def _startup_database() -> None:
        reset_runtime_paths()
        database = warm_database()
        print(f"[+] Logs dir: {database.logs_dir}")
        print(f"[+] SQLite ready: {database.db_path}")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins(),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(auth.router, prefix="/api")
    app.include_router(overview.router, prefix="/api")
    app.include_router(findings.router, prefix="/api")
    app.include_router(file_drops.router, prefix="/api")
    app.include_router(rules.router, prefix="/api")
    app.include_router(agents.router, prefix="/api")
    app.include_router(users.router, prefix="/api")
    app.include_router(sessions.router, prefix="/api")
    app.include_router(ingest.router, prefix="/api")
    app.include_router(reports.router, prefix="/api")
    app.include_router(ws.router, prefix="/api")

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "backend", "api_version": "0.2.0"}

    if ui_dist and ui_dist.is_dir():
        assets = ui_dist / "assets"
        if assets.is_dir():
            app.mount("/assets", StaticFiles(directory=assets), name="assets")

        @app.get("/{full_path:path}")
        def spa_fallback(full_path: str):
            if full_path.startswith("api/"):
                return {"error": "not found"}
            index = ui_dist / "index.html"
            if index.is_file():
                return FileResponse(index)
            return {"error": "UI not built"}

    return app
