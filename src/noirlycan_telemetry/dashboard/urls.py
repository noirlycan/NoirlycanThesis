from __future__ import annotations

from django.conf import settings
from django.urls import path, re_path
from django.views.static import serve

from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("api/health", views.health, name="health"),
    path("api/overview", views.overview, name="overview"),
    path("api/uploads", views.list_uploads, name="uploads"),
    path("api/upload", views.upload_file, name="upload"),
    path("api/uploads/<int:upload_id>/run", views.upload_run, name="upload-run"),
    path("api/uploads/<int:upload_id>/delete", views.upload_delete, name="upload-delete"),
    path("api/uploads/<int:upload_id>/report", views.upload_report, name="upload-report"),
    path("api/db/session/<path:name>", views.db_session, name="db-session"),
    path("api/collector/start", views.collector_start, name="collector-start"),
    path("api/rules", views.classifier_rules_config, name="rules"),
    path("api/rules/catalog", views.classifier_rules, name="rules-catalog"),
    path("api/rules/detail/<slug:rule_id>", views.classifier_rule_detail, name="rules-detail"),
    path("api/rules/custom/<slug:rule_id>", views.classifier_custom_rule, name="rules-custom"),
    path("api/runtime", views.runtime, name="runtime"),
    path("api/triage/request", views.triage_request, name="triage-request"),
    path("api/session/<path:name>", views.session, name="session"),
    path("api/export/<path:name>", views.export_session, name="export"),
]

# Lab dashboard: always expose vendored CSS/JS (Django skips this when DEBUG=False).
_static_root = settings.BASE_DIR / "static"
urlpatterns += [
    re_path(
        r"^static/(?P<path>.*)$",
        serve,
        {"document_root": _static_root},
    ),
]
