from __future__ import annotations

from typing import Any

ROLES = ("Admin", "Analyst", "Viewer")

PERMISSION_KEYS = (
    "dashboards",
    "triage",
    "export",
    "report",
    "del",
    "rules",
    "access",
    "kill",
)

DEFAULT_ROLE_PERMISSIONS: dict[str, dict[str, bool]] = {
    "Admin": {key: True for key in PERMISSION_KEYS},
    "Analyst": {
        "dashboards": True,
        "triage": True,
        "export": True,
        "report": True,
        "del": True,
        "rules": False,
        "access": False,
        "kill": True,
    },
    "Viewer": {
        "dashboards": True,
        "triage": False,
        "export": False,
        "report": False,
        "del": False,
        "rules": False,
        "access": False,
        "kill": False,
    },
}


def normalize_role_permissions(raw: object) -> dict[str, dict[str, bool]]:
    result: dict[str, dict[str, bool]] = {}
    for role in ROLES:
        defaults = dict(DEFAULT_ROLE_PERMISSIONS[role])
        if isinstance(raw, dict) and isinstance(raw.get(role), dict):
            for key in PERMISSION_KEYS:
                if key in raw[role]:
                    defaults[key] = bool(raw[role][key])
        result[role] = defaults
    return result


def role_permissions_payload(matrix: dict[str, dict[str, bool]]) -> dict[str, Any]:
    return {"roles": ROLES, "permissions": PERMISSION_KEYS, "matrix": matrix}


def has_permission(matrix: dict[str, dict[str, bool]], role: str, key: str) -> bool:
    role_perms = matrix.get(role) or DEFAULT_ROLE_PERMISSIONS.get(role) or {}
    return bool(role_perms.get(key, False))
