from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

from django.conf import settings
from django.http import FileResponse, HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import render
from django.utils.text import get_valid_filename
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from ..analysis_db import AnalysisDatabase, sha256_file, uploads_dir
from ..analysis_queue import enqueue_analysis, load_analysis_queue, remove_from_queue
from ..upload_finalize import build_upload_report
from ..log_store import aggregate_logs, resolve_log_path, resolve_logs_dir, session_detail
from ..reclassify import reclassify_session
from ..session_analytics import analyze_corpus
from ..classifier_config import (
    RuleSettings,
    classifier_rules_payload,
    load_classifier_config,
    resolve_config_path,
    save_classifier_config,
)
from ..custom_rule_engine import parse_custom_rule, parse_custom_rules
from ..collector_launcher import is_collector_running, start_collector
from ..runtime_config import (
    is_collector_online,
    load_runtime_config,
    runtime_config_payload,
    save_runtime_config,
)
from .ws_broadcast import broadcast_refresh, broadcast_runtime


def _logs_dir() -> Path:
    override = getattr(settings, "NOIRLYCAN_LOGS_DIR", "") or ""
    return resolve_logs_dir(override or None)


def _database() -> AnalysisDatabase:
    return AnalysisDatabase(_logs_dir())


def _upload_status_label(row: dict, *, collector_online: bool) -> str:
    status = str(row.get("status") or "")
    if status == "parsed":
        return "done — view report"
    if status == "uploaded":
        return "ready — click Run"
    if status == "failed":
        detail = row.get("error_message") or "error"
        return f"failed ({detail})"
    if status == "spawned":
        return "running (Frida hooks)"
    if status == "duplicate":
        return "already queued"
    if status == "queued":
        if not collector_online:
            return "queued — start collector"
        if row.get("in_queue"):
            return "queued — waiting for collector"
        return "queued — processing"
    return status or "-"


def _enrich_uploads(rows: list[dict], logs_dir: Path, collector_online: bool) -> list[dict]:
    pending = {
        str(Path(item.path).resolve()).lower()
        for item in load_analysis_queue(logs_dir).pending
    }
    enriched: list[dict] = []
    for row in rows:
        payload = dict(row)
        stored = str(payload.get("stored_path") or "")
        try:
            path_key = str(Path(stored).resolve()).lower()
        except OSError:
            path_key = stored.lower()
        payload["in_queue"] = path_key in pending
        payload["status_label"] = _upload_status_label(payload, collector_online=collector_online)
        enriched.append(payload)
    return enriched


def _static_asset_version() -> str:
    dashboard_dir = Path(__file__).resolve().parent
    stamps: list[str] = []
    for name in ("dashboard.js", "dashboard.css", "i18n.js"):
        path = dashboard_dir / "static" / name
        if path.is_file():
            stamps.append(str(int(path.stat().st_mtime)))
    template_path = dashboard_dir / "templates" / "index.html"
    if template_path.is_file():
        stamps.append(str(int(template_path.stat().st_mtime)))
    return "-".join(stamps) if stamps else "0"


def index(request: HttpRequest) -> HttpResponse:
    response = render(
        request,
        "index.html",
        {
            "asset_version": _static_asset_version(),
            "template_version": "standalone-v1",
            "title": "Telemetry",
        },
    )
    response["Cache-Control"] = "no-store"
    return response


@require_GET
def health(request: HttpRequest) -> JsonResponse:
    database = _database()
    return JsonResponse(
        {
            "status": "ok",
            "logs_dir": str(_logs_dir()),
            "db_path": str(database.db_path),
        }
    )


@require_GET
def corpus(request: HttpRequest) -> JsonResponse:
    logs_dir = _logs_dir()
    limit_raw = request.GET.get("limit", "").strip()
    limit = int(limit_raw) if limit_raw.isdigit() else None
    database = _database()
    payload = analyze_corpus(logs_dir, limit=limit, database=database)
    payload["classifier_rules_path"] = str(resolve_config_path(logs_dir))
    payload["db_findings"] = database.aggregate_stored_findings()
    return JsonResponse(payload)


@require_http_methods(["GET", "POST"])
def reclassify_session_view(request: HttpRequest, name: str) -> JsonResponse:
    logs_dir = _logs_dir()
    write_mode = (request.GET.get("write") or request.POST.get("write") or "").strip().lower()
    try:
        payload = reclassify_session(
            name,
            logs_dir=logs_dir,
            write=write_mode or False,
        )
        if write_mode:
            database = _database()
            database.invalidate_session_analytics_cache(payload.get("session") or name)
    except FileNotFoundError as exc:
        return JsonResponse({"error": str(exc)}, status=404)
    except OSError as exc:
        return JsonResponse({"error": str(exc)}, status=500)
    return JsonResponse(payload)


@require_GET
def overview(request: HttpRequest) -> JsonResponse:
    selected = request.GET.get("log")
    logs_dir = _logs_dir()
    payload = aggregate_logs(logs_dir, selected=selected)
    database = _database()
    runtime = load_runtime_config(logs_dir)
    collector_online = is_collector_online(runtime)
    payload["db_path"] = str(database.db_path)
    payload["collector_online"] = collector_online
    payload["uploads"] = _enrich_uploads(
        database.list_uploads(limit=30),
        logs_dir,
        collector_online,
    )
    payload["parsed_sessions"] = database.list_parsed_sessions(limit=30)
    payload["classifier_rules_path"] = str(resolve_config_path(logs_dir))
    include_rules = request.GET.get("include_rules", "").lower() in {"1", "true", "yes"}
    if include_rules:
        payload["classifier_rules"] = classifier_rules_payload(logs_dir)
    return JsonResponse(payload)


@require_GET
def list_uploads(request: HttpRequest) -> JsonResponse:
    database = _database()
    return JsonResponse(
        {
            "db_path": str(database.db_path),
            "uploads": database.list_uploads(limit=100),
            "parsed_sessions": database.list_parsed_sessions(limit=100),
        }
    )


@require_GET
def db_session(request: HttpRequest, name: str) -> JsonResponse:
    database = _database()
    payload = database.get_parsed_session(name)
    if payload is None:
        return JsonResponse({"error": "parsed session not found"}, status=404)
    return JsonResponse(payload)


@csrf_exempt
@require_POST
def upload_file(request: HttpRequest) -> JsonResponse:
    uploaded = request.FILES.get("file")
    if uploaded is None or not uploaded.name:
        return JsonResponse({"error": "file is required"}, status=400)

    original_name = Path(uploaded.name).name
    suffix = Path(original_name).suffix.lower()
    if suffix not in {".jsonl", ".exe", ".dll"}:
        return JsonResponse(
            {"error": "supported uploads: .jsonl session logs, .exe / .dll samples"},
            status=400,
        )

    safe_name = get_valid_filename(original_name) or f"upload{suffix}"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    stored_name = f"{stamp}-{safe_name}"
    destination = uploads_dir(_logs_dir()) / stored_name

    with destination.open("wb") as handle:
        for chunk in uploaded.chunks():
            handle.write(chunk)

    size_bytes = destination.stat().st_size
    max_bytes = int(getattr(settings, "NOIRLYCAN_MAX_UPLOAD_BYTES", 64 * 1024 * 1024))
    if size_bytes > max_bytes:
        destination.unlink(missing_ok=True)
        return JsonResponse({"error": "file exceeds 64 MiB upload limit"}, status=413)

    digest = sha256_file(destination)
    database = _database()
    target_pid_raw = request.POST.get("target_pid")
    target_pid = None
    if target_pid_raw:
        try:
            target_pid = int(target_pid_raw)
        except ValueError:
            return JsonResponse({"error": "target_pid must be an integer"}, status=400)
    argv = [str(target_pid)] if target_pid is not None and target_pid > 0 else []

    if suffix == ".jsonl":
        session_name = f"upload-{stamp}.jsonl"
        session_path = _logs_dir() / session_name
        shutil.copy2(destination, session_path)
        upload_id = database.record_upload(
            original_name=original_name,
            stored_path=str(destination.resolve()),
            content_kind="jsonl",
            size_bytes=size_bytes,
            sha256=digest,
            status="parsing",
        )
        try:
            parsed = database.ingest_jsonl(
                session_path,
                upload_id=upload_id,
                session_name=session_name,
            )
            database.update_upload(
                upload_id,
                status="parsed",
                session_name=session_name,
            )
        except Exception as exc:
            database.update_upload(upload_id, status="failed", error_message=str(exc))
            return JsonResponse({"error": f"parse failed: {exc}"}, status=500)

        return JsonResponse(
            {
                "ok": True,
                "kind": "jsonl",
                "upload_id": upload_id,
                "session_name": session_name,
                "stored_path": str(destination.resolve()),
                "db_path": str(database.db_path),
                "parsed": parsed,
                "message": "Session log parsed and stored in database",
            }
        )

    upload_id = database.record_upload(
        original_name=original_name,
        stored_path=str(destination.resolve()),
        content_kind="executable",
        size_bytes=size_bytes,
        sha256=digest,
        status="uploaded",
    )
    return JsonResponse(
        {
            "ok": True,
            "kind": "executable",
            "upload_id": upload_id,
            "stored_path": str(destination.resolve()),
            "db_path": str(database.db_path),
            "argv": argv,
            "message": "Sample saved. Click Run in the uploads table to start analysis.",
        }
    )


@csrf_exempt
@require_POST
def upload_run(request: HttpRequest, upload_id: int) -> JsonResponse:
    logs_dir = _logs_dir()
    database = _database()
    upload = database.get_upload(upload_id)
    if upload is None:
        return JsonResponse({"error": "upload not found"}, status=404)
    if str(upload.get("content_kind") or "") != "executable":
        return JsonResponse({"error": "only executable uploads can be run"}, status=400)

    try:
        body = json.loads(request.body.decode("utf-8") or "{}")
    except json.JSONDecodeError:
        body = {}
    if not isinstance(body, dict):
        body = {}

    argv: list[str] = []
    target_pid = body.get("target_pid")
    if target_pid is not None:
        try:
            pid_value = int(target_pid)
        except (TypeError, ValueError):
            return JsonResponse({"error": "target_pid must be an integer"}, status=400)
        if pid_value > 0:
            argv = [str(pid_value)]

    stored_path = str(upload.get("stored_path") or "")
    if not stored_path or not Path(stored_path).is_file():
        return JsonResponse({"error": "stored sample file is missing"}, status=404)

    status = str(upload.get("status") or "")
    if status in {"queued", "spawned", "running"}:
        return JsonResponse({"error": f"upload is already {status}"}, status=409)

    queued = enqueue_analysis(stored_path, logs_dir, mode="api", argv=argv)
    if queued:
        database.update_upload(upload_id, status="queued", error_message=None, session_name=None)
    else:
        database.update_upload(upload_id, status="duplicate", error_message="already queued")

    runtime = load_runtime_config(logs_dir)
    collector_online = is_collector_online(runtime)
    broadcast_refresh(reason="upload-run")
    return JsonResponse(
        {
            "ok": True,
            "upload_id": upload_id,
            "queued": queued,
            "argv": argv,
            "collector_online": collector_online,
            "message": (
                "Analysis queued. Collector will spawn the sample under Frida hooks."
                if queued and collector_online
                else "Analysis queued. Start the collector to run the sample."
                if queued
                else "Sample is already queued for analysis."
            ),
        }
    )


@csrf_exempt
@require_http_methods(["POST", "DELETE"])
def upload_delete(request: HttpRequest, upload_id: int) -> JsonResponse:
    logs_dir = _logs_dir()
    database = _database()
    upload = database.get_upload(upload_id)
    if upload is None:
        return JsonResponse({"error": "upload not found"}, status=404)

    stored_path = str(upload.get("stored_path") or "")
    if stored_path:
        remove_from_queue(stored_path, logs_dir)

    if not database.delete_upload(upload_id):
        return JsonResponse({"error": "could not delete upload"}, status=500)

    broadcast_refresh(reason="upload-delete")
    return JsonResponse(
        {
            "ok": True,
            "upload_id": upload_id,
            "message": "Upload removed.",
        }
    )


@require_GET
def upload_report(request: HttpRequest, upload_id: int) -> JsonResponse:
    logs_dir = _logs_dir()
    database = _database()
    upload = database.get_upload(upload_id)
    if upload is None:
        return JsonResponse({"error": "upload not found"}, status=404)

    report = build_upload_report(upload_id, logs_dir)
    upload = database.get_upload(upload_id) or upload
    if report is None:
        status = str(upload.get("status") or "")
        if status in {"spawned", "running", "queued"}:
            return JsonResponse(
                {
                    "error": "no telemetry for this sample in the active session yet",
                    "upload": upload,
                    "status": status,
                },
                status=202,
            )
        return JsonResponse({"error": "no report for this upload yet", "upload": upload}, status=404)

    live = str(upload.get("status") or "") in {"spawned", "running", "queued"}
    return JsonResponse(
        {
            "ok": True,
            "upload": upload,
            "report": report,
            "live_snapshot": live,
        }
    )


@require_GET
def classifier_rules(request: HttpRequest) -> JsonResponse:
    logs_dir = _logs_dir()
    payload = classifier_rules_payload(logs_dir)
    payload["config_path"] = str(resolve_config_path(logs_dir))
    return JsonResponse(payload)


@csrf_exempt
@require_http_methods(["GET", "POST"])
def classifier_rules_config(request: HttpRequest) -> JsonResponse:
    logs_dir = _logs_dir()
    if request.method == "GET":
        payload = classifier_rules_payload(logs_dir)
        payload["config_path"] = str(resolve_config_path(logs_dir))
        return JsonResponse(payload)

    try:
        body = json.loads(request.body.decode("utf-8") or "{}")
    except json.JSONDecodeError:
        body = {}
    if not isinstance(body, dict):
        body = {}

    config = load_classifier_config(logs_dir)
    if "minimum_score" in body:
        try:
            config.minimum_score = max(0, min(100, int(body["minimum_score"])))
        except (TypeError, ValueError):
            return JsonResponse({"error": "minimum_score must be an integer 0-100"}, status=400)
    if "classification_enabled" in body:
        config.classification_enabled = bool(body["classification_enabled"])
    if "minimum_operational_kinds" in body:
        try:
            config.minimum_operational_kinds = max(2, min(3, int(body["minimum_operational_kinds"])))
        except (TypeError, ValueError):
            return JsonResponse({"error": "minimum_operational_kinds must be 2 or 3"}, status=400)
    if "require_cross_process_findings" in body:
        config.require_cross_process_findings = bool(body["require_cross_process_findings"])
    if "ignore_same_process_findings" in body:
        config.ignore_same_process_findings = bool(body["ignore_same_process_findings"])
    if "disabled_rules" in body:
        raw = body["disabled_rules"]
        if not isinstance(raw, list):
            return JsonResponse({"error": "disabled_rules must be a list"}, status=400)
        config.disabled_rules = [str(item) for item in raw if str(item).strip()]
    if "rule_settings" in body and isinstance(body["rule_settings"], dict):
        for rule_id, payload in body["rule_settings"].items():
            rid = str(rule_id).strip()
            if not rid or not isinstance(payload, dict):
                continue
            try:
                min_kinds = max(2, min(3, int(payload.get("min_primitive_kinds", 2))))
                min_score = max(0, min(100, int(payload.get("min_finding_score", 0))))
            except (TypeError, ValueError):
                return JsonResponse({"error": f"invalid numeric settings for rule {rid}"}, status=400)
            confidence = str(payload.get("confidence") or "").strip().lower()
            if confidence and confidence not in {"low", "medium", "high"}:
                return JsonResponse({"error": f"confidence for {rid} must be low, medium, high, or empty"}, status=400)
            config.rule_settings[rid] = RuleSettings(
                enabled=bool(payload.get("enabled", True)),
                min_primitive_kinds=min_kinds,
                require_execution=bool(payload.get("require_execution", False)),
                require_cross_process=bool(payload.get("require_cross_process", False)),
                require_same_process=bool(payload.get("require_same_process", False)),
                min_finding_score=min_score,
                confidence=confidence,
            )
    if "rules" in body and isinstance(body["rules"], list):
        disabled: list[str] = []
        for item in body["rules"]:
            if not isinstance(item, dict):
                continue
            rule_id = str(item.get("id") or "").strip()
            if not rule_id:
                continue
            enabled = bool(item.get("enabled", True))
            if not enabled:
                disabled.append(rule_id)
            if any(
                key in item
                for key in (
                    "min_primitive_kinds",
                    "require_execution",
                    "require_cross_process",
                    "require_same_process",
                    "min_finding_score",
                    "confidence",
                )
            ):
                try:
                    min_kinds = max(2, min(3, int(item.get("min_primitive_kinds", 2))))
                    min_score = max(0, min(100, int(item.get("min_finding_score", 0))))
                except (TypeError, ValueError):
                    return JsonResponse({"error": f"invalid numeric settings for rule {rule_id}"}, status=400)
                confidence = str(item.get("confidence") or "").strip().lower()
                if confidence and confidence not in {"low", "medium", "high"}:
                    return JsonResponse(
                        {"error": f"confidence for {rule_id} must be low, medium, high, or empty"},
                        status=400,
                    )
                config.rule_settings[rule_id] = RuleSettings(
                    enabled=enabled,
                    min_primitive_kinds=min_kinds,
                    require_execution=bool(item.get("require_execution", False)),
                    require_cross_process=bool(item.get("require_cross_process", False)),
                    require_same_process=bool(item.get("require_same_process", False)),
                    min_finding_score=min_score,
                    confidence=confidence,
                )
            elif rule_id in config.rule_settings:
                config.rule_settings[rule_id].enabled = enabled
        config.disabled_rules = disabled
    if "custom_rules" in body:
        parsed_custom = parse_custom_rules(body["custom_rules"])
        if parsed_custom is None:
            return JsonResponse({"error": "invalid custom_rules payload"}, status=400)
        config.custom_rules = parsed_custom

    save_classifier_config(config, logs_dir)
    broadcast_refresh(reason="rules")
    payload = classifier_rules_payload(logs_dir)
    payload["config_path"] = str(resolve_config_path(logs_dir))
    payload["ok"] = True
    payload["message"] = "Classifier rules saved. New findings use this config immediately."
    return JsonResponse(payload)


@require_GET
def classifier_rule_detail(request: HttpRequest, rule_id: str) -> JsonResponse:
    logs_dir = _logs_dir()
    rid = str(rule_id or "").strip().lower()
    payload = classifier_rules_payload(logs_dir)
    for rule in payload.get("rules") or []:
        if str(rule.get("id") or "").lower() == rid:
            return JsonResponse({"ok": True, "rule": rule, "source": "builtin"})
    for rule in payload.get("custom_rules") or []:
        if str(rule.get("id") or "").lower() == rid:
            return JsonResponse({"ok": True, "rule": rule, "source": "custom"})
    return JsonResponse({"error": "rule not found"}, status=404)


@csrf_exempt
@require_http_methods(["POST", "DELETE"])
def classifier_custom_rule(request: HttpRequest, rule_id: str) -> JsonResponse:
    logs_dir = _logs_dir()
    config = load_classifier_config(logs_dir)
    rid = str(rule_id or "").strip().lower()

    if request.method == "DELETE":
        before = len(config.custom_rules)
        config.custom_rules = [rule for rule in config.custom_rules if rule.id != rid]
        if len(config.custom_rules) == before:
            return JsonResponse({"error": "custom rule not found"}, status=404)
        save_classifier_config(config, logs_dir)
        broadcast_refresh(reason="rules")
        payload = classifier_rules_payload(logs_dir)
        payload["config_path"] = str(resolve_config_path(logs_dir))
        payload["ok"] = True
        payload["message"] = f"Deleted custom rule {rid}."
        return JsonResponse(payload)

    try:
        body = json.loads(request.body.decode("utf-8") or "{}")
    except json.JSONDecodeError:
        body = {}
    if not isinstance(body, dict):
        body = {}
    body["id"] = rid
    parsed = parse_custom_rule(body)
    if parsed is None:
        return JsonResponse({"error": "invalid custom rule definition"}, status=400)

    replaced = False
    for index, existing in enumerate(config.custom_rules):
        if existing.id == parsed.id:
            config.custom_rules[index] = parsed
            replaced = True
            break
    if not replaced:
        if any(item.id == parsed.id for item in config.custom_rules):
            return JsonResponse({"error": "duplicate custom rule id"}, status=409)
        config.custom_rules.append(parsed)

    save_classifier_config(config, logs_dir)
    broadcast_refresh(reason="rules")
    payload = classifier_rules_payload(logs_dir)
    payload["config_path"] = str(resolve_config_path(logs_dir))
    payload["ok"] = True
    payload["message"] = f"Saved custom rule {parsed.id}."
    return JsonResponse(payload)


@csrf_exempt
@require_POST
def collector_start(request: HttpRequest) -> JsonResponse:
    logs_dir = _logs_dir()
    result = start_collector(logs_dir, elevate=True)
    result["collector_online"] = is_collector_running(logs_dir)
    return JsonResponse(result)


@csrf_exempt
@require_http_methods(["GET", "POST"])
def runtime(request: HttpRequest) -> JsonResponse:
    logs_dir = _logs_dir()
    if request.method == "GET":
        config = load_runtime_config(logs_dir)
        return JsonResponse(runtime_config_payload(config))

    try:
        payload = json.loads(request.body.decode("utf-8") or "{}")
    except json.JSONDecodeError:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}

    config = load_runtime_config(logs_dir)
    if config.file_drop_watch_locked:
        return JsonResponse({"error": "file drop watch is locked by CLI (--no-watch-files)"}, status=409)
    if "file_drop_watch_enabled" in payload:
        config.file_drop_watch_enabled = bool(payload["file_drop_watch_enabled"])
    if "auto_triage_enabled" in payload:
        config.auto_triage_enabled = bool(payload["auto_triage_enabled"])
        config.auto_api_analysis_enabled = config.auto_triage_enabled
    if "auto_api_analysis_enabled" in payload:
        config.auto_api_analysis_enabled = bool(payload["auto_api_analysis_enabled"])
        config.auto_triage_enabled = config.auto_api_analysis_enabled
    if "auto_static_triage_enabled" in payload:
        config.auto_static_triage_enabled = bool(payload["auto_static_triage_enabled"])
    save_runtime_config(config, logs_dir)
    payload = runtime_config_payload(config)
    broadcast_runtime(payload)
    return JsonResponse(payload)


@csrf_exempt
@require_POST
def triage_request(request: HttpRequest) -> JsonResponse:
    try:
        payload = json.loads(request.body.decode("utf-8") or "{}")
    except json.JSONDecodeError:
        payload = {}
    if not isinstance(payload, dict):
        payload = {}

    path = str(payload.get("path") or "").strip()
    mode = str(payload.get("mode") or "api").strip().lower()
    if not path:
        return JsonResponse({"error": "path is required"}, status=400)
    target = Path(path)
    if not target.exists() or not target.is_file():
        return JsonResponse({"error": f"file not found: {path}"}, status=404)

    argv: list[str] = []
    target_pid = payload.get("target_pid")
    if target_pid is not None:
        try:
            pid_value = int(target_pid)
        except (TypeError, ValueError):
            return JsonResponse({"error": "target_pid must be an integer"}, status=400)
        if pid_value > 0:
            argv = [str(pid_value)]

    queued = enqueue_analysis(
        str(target.resolve()),
        _logs_dir(),
        mode=mode,
        argv=argv,
    )
    return JsonResponse(
        {
            "ok": True,
            "path": str(target.resolve()),
            "mode": mode,
            "argv": argv,
            "queued": queued,
            "message": "queued" if queued else "already queued",
        }
    )


@require_GET
def session(request: HttpRequest, name: str) -> JsonResponse:
    severity = request.GET.get("severity") or None
    target_pid_raw = request.GET.get("pid")
    target_pid = int(target_pid_raw) if target_pid_raw else None
    query = request.GET.get("q") or None
    event_type = request.GET.get("type") or None
    limit_raw = request.GET.get("limit", "200")
    try:
        limit = int(limit_raw)
    except ValueError:
        limit = 200

    payload = session_detail(
        name,
        _logs_dir(),
        severity=severity,
        target_pid=target_pid,
        query=query,
        event_type=event_type,
        limit=limit,
    )
    if payload is None:
        return JsonResponse({"error": "session not found"}, status=404)
    return JsonResponse(payload)


@require_GET
def export_session(request: HttpRequest, name: str) -> HttpResponse:
    path = resolve_log_path(_logs_dir(), name)
    if path is None:
        return JsonResponse({"error": "session not found"}, status=404)
    return FileResponse(path.open("rb"), as_attachment=True, filename=path.name)
