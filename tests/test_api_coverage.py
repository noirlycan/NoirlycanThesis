from __future__ import annotations

import re
from pathlib import Path

from noirlycan_telemetry.kernel.classification.api_manifest import PAPER_INJECTION_APIS, REPO_REQUIRED_APIS


def _hook_script() -> str:
    path = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "noirlycan_telemetry"
        / "frida_hooks"
        / "windows_injection_hooks.js"
    )
    return path.read_text(encoding="utf-8")


def _is_hooked(script: str, api: str) -> bool:
    if api.startswith("Zw") and _is_hooked(script, f"Nt{api[2:]}"):
        return True

    patterns = (
        f'hook({api}',
        f'hook(kernel32, "{api}"',
        f'hook(ntdll, "{api}"',
        f'hook(shell32, "{api}"',
        f'hook(advapi32, "{api}"',
        f'hook(user32, "{api}"',
        f'"{api}"',
        f'"{api}":',
        f"  {api}:",
        f" {api}:",
    )
    if any(pattern in script for pattern in patterns):
        return True
    return bool(re.search(rf'hook\([^,]+,\s*"{re.escape(api)}"', script))


def test_covers_all_asiaccs_paper_injection_apis() -> None:
    script = _hook_script()
    missing = sorted(api for api in PAPER_INJECTION_APIS if not _is_hooked(script, api))
    assert missing == [], f"Missing ASIA CCS paper APIs in Frida hooks: {missing}"


def test_covers_repo_extensions_beyond_paper() -> None:
    script = _hook_script()
    missing = sorted(api for api in REPO_REQUIRED_APIS if not _is_hooked(script, api))
    assert missing == [], f"Missing required hook coverage: {missing}"
