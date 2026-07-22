"""Ensure Frida hook catalog covers the repo injection API manifest."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from noirlycan_agent.collector.infrastructure.frida_hook_catalog import (
    build_runtime_config,
    hook_exports_in_config,
)
from noirlycan_core.kernel.classification.api_manifest import REPO_REQUIRED_APIS

ROOT = Path(__file__).resolve().parents[1]


def test_catalog_covers_manifest_without_policy() -> None:
    exports = hook_exports_in_config(build_runtime_config(None))
    missing = sorted(REPO_REQUIRED_APIS - exports)
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
    missing_section = result.stdout.split("MISSING:", 1)[1].split("dynamic_nt entries:", 1)[0]
    assert missing_section.strip() == "", result.stdout
