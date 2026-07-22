"""Build per-upload SQLite reports on demand from the live collector JSONL."""

from __future__ import annotations

from pathlib import Path

from noirlycan_core.storage.infrastructure.analysis_db import AnalysisDatabase
from noirlycan_core.storage.infrastructure.log_store import read_jsonl, resolve_logs_dir


def _log_contains_sample(log_path: Path, stored_path: str) -> bool:
    try:
        sample_key = str(Path(stored_path).resolve()).lower()
    except OSError:
        sample_key = str(stored_path).lower()
    if not sample_key:
        return False
    for event in read_jsonl(log_path):
        value = event.get("value")
        if not isinstance(value, dict):
            continue
        if event.get("type") == "api_run":
            if str(value.get("path") or "").lower() == sample_key:
                return True
        if event.get("type") == "finding":
            for field in ("related_file", "target_image", "actor_image"):
                candidate = str(value.get(field) or "").lower()
                if candidate and (candidate == sample_key or sample_key in candidate):
                    return True
    return False


def _resolve_collector_log(
    upload: dict,
    database: AnalysisDatabase,
    logs_dir: Path,
) -> Path | None:
    existing = database.get_parsed_session_for_upload(int(upload["id"]))
    if existing is not None:
        source = str(existing.get("source_path") or "")
        if source:
            path = Path(source)
            if path.is_file():
                return path

    session_name = str(upload.get("session_name") or "")
    if session_name.endswith(".jsonl") and not session_name.startswith("upload-report-"):
        candidate = logs_dir / session_name
        if candidate.is_file():
            return candidate

    stored_path = str(upload.get("stored_path") or "")
    if not stored_path:
        return None

    for path in sorted(logs_dir.glob("session-*.jsonl"), key=lambda item: item.stat().st_mtime, reverse=True):
        if _log_contains_sample(path, stored_path):
            return path
    return None


def build_upload_report(upload_id: int, logs_dir: Path | str | None = None) -> dict | None:
    """Snapshot the current collector log for an upload (no idle timeout)."""
    directory = resolve_logs_dir(logs_dir)
    database = AnalysisDatabase(directory)
    upload = database.get_upload(upload_id)
    if upload is None:
        return None

    stored_path = str(upload.get("stored_path") or "")
    log_path = _resolve_collector_log(upload, database, directory)
    if log_path is None or not stored_path:
        return None
    if not _log_contains_sample(log_path, stored_path):
        return None

    report_name = f"upload-report-{upload_id}"
    database.clear_parsed_sessions_for_upload(upload_id)
    database.ingest_jsonl(
        log_path,
        upload_id=upload_id,
        session_name=report_name,
    )
    status = str(upload.get("status") or "")
    if status in {"spawned", "running", "queued"}:
        database.update_upload(upload_id, status="spawned")
    elif status != "failed":
        database.update_upload(upload_id, status="parsed")

    return database.get_parsed_session_for_upload(upload_id)


def finalize_upload_reports(logs_dir: Path | str | None = None) -> int:
    """Legacy no-op: reports are built on demand via build_upload_report()."""
    return 0
