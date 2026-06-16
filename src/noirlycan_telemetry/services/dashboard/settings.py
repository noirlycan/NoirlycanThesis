from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

SECRET_KEY = os.environ.get(
    "NOIRLYCAN_DJANGO_SECRET",
    "noirlycan-lab-only-change-me-in-production",
)
# Local lab dashboard: serve static assets via runserver (opt out with NOIRLYCAN_DJANGO_DEBUG=0).
DEBUG = os.environ.get("NOIRLYCAN_DJANGO_DEBUG", "true").lower() not in {"0", "false", "no"}
ALLOWED_HOSTS = [
    host.strip()
    for host in os.environ.get(
        "NOIRLYCAN_DJANGO_ALLOWED_HOSTS",
        "127.0.0.1,localhost,testserver",
    ).split(",")
    if host.strip()
]

INSTALLED_APPS = [
    "daphne",
    "channels",
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "noirlycan_telemetry.services.dashboard.apps.DashboardConfig",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "noirlycan_telemetry.services.dashboard.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "django.template.context_processors.static",
            ],
        },
    }
]

WSGI_APPLICATION = "noirlycan_telemetry.services.dashboard.wsgi.application"
ASGI_APPLICATION = "noirlycan_telemetry.services.dashboard.asgi.application"

CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels.layers.InMemoryChannelLayer",
    },
}

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "django.sqlite3",
    }
}

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"
STATICFILES_DIRS = [BASE_DIR / "static"]

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

LOGIN_URL = "/admin/login/"
LOGIN_REDIRECT_URL = "/"

NOIRLYCAN_LOGS_DIR = os.environ.get("NOIRLYCAN_LOGS_DIR", "").strip()
NOIRLYCAN_MAX_UPLOAD_BYTES = 64 * 1024 * 1024

FILE_UPLOAD_MAX_MEMORY_SIZE = NOIRLYCAN_MAX_UPLOAD_BYTES
DATA_UPLOAD_MAX_MEMORY_SIZE = NOIRLYCAN_MAX_UPLOAD_BYTES
