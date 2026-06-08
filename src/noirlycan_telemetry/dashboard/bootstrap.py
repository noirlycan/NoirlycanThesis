from __future__ import annotations

import os
from pathlib import Path

import django
from django.conf import settings
from django.test import Client


def configure(logs_dir: Path | str | None = None) -> None:
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "noirlycan_telemetry.dashboard.settings")
    resolved = None
    if logs_dir is not None:
        resolved = str(Path(logs_dir).expanduser().resolve())
        os.environ["NOIRLYCAN_LOGS_DIR"] = resolved
    if not settings.configured:
        django.setup()
    elif resolved is not None:
        settings.NOIRLYCAN_LOGS_DIR = resolved


def make_client(logs_dir: Path | str | None = None) -> Client:
    configure(logs_dir)
    return Client()
