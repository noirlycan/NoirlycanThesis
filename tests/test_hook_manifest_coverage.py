"""Ensure Frida hook script covers the repo injection API manifest."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

from noirlycan_telemetry.kernel.classification.api_manifest import REPO_REQUIRED_APIS

ROOT = Path(__file__).resolve().parents[1]
JS = ROOT / "src" / "noirlycan_telemetry" / "frida_hooks" / "windows_injection_hooks.js"


def _hooked_apis(js: str) -> set[str]:
    static = set(re.findall(r'hook\([^,]+,\s*"([^"]+)"', js))
    enum_hooks = set(re.findall(r'enumHook\([^,]+,\s*"([^"]+)"', js))
    handlers = set(re.findall(r"^\s+((?:Nt|Zw|Rtl)[A-Za-z]+):\s*\{", js, re.M))
    dynamic_block = js.split("DYNAMIC_INJECTION_APIS")[1].split("]);")[0]
    dynamic = set(re.findall(r'"((?:Nt|Zw|Rtl)[A-Za-z]+)"', dynamic_block))

    hooked = set(static) | set(handlers) | set(enum_hooks)
    for name in handlers:
        if name.startswith("Nt"):
            hooked.add("Zw" + name[2:])
    for name in dynamic:
        if name.startswith("Zw") and f"Nt{name[2:]}" in handlers:
            hooked.add(name)
        elif name in handlers:
            hooked.add(name)
    return hooked


def test_hook_script_covers_manifest() -> None:
    js = JS.read_text(encoding="utf-8")
    hooked = _hooked_apis(js)
    missing = sorted(REPO_REQUIRED_APIS - hooked)
    assert not missing, f"Unhooked manifest APIs: {missing}"


def test_audit_script_reports_full_coverage() -> None:
    script = ROOT / "scripts" / "audit_hook_coverage.py"
    result = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr or result.stdout
    assert "MISSING:" in result.stdout
    missing_section = result.stdout.split("MISSING:", 1)[1].split("DYNAMIC without handler:", 1)[0]
    assert missing_section.strip() == "", result.stdout
