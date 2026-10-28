from __future__ import annotations

from noirlycan_agent.sensors.frida_hook_catalog import (
    build_runtime_config,
    hook_exports_in_config,
)
from noirlycan_core.detection.api_classes import PAPER_INJECTION_APIS, REPO_REQUIRED_APIS


def test_covers_all_asiaccs_paper_injection_apis() -> None:
    exports = hook_exports_in_config(build_runtime_config(None))
    missing = sorted(api for api in PAPER_INJECTION_APIS if api not in exports)
    assert missing == [], f"Missing ASIA CCS paper APIs in Frida catalog: {missing}"


def test_covers_repo_extensions_beyond_paper() -> None:
    exports = hook_exports_in_config(build_runtime_config(None))
    missing = sorted(api for api in REPO_REQUIRED_APIS if api not in exports)
    assert missing == [], f"Missing required hook coverage: {missing}"
