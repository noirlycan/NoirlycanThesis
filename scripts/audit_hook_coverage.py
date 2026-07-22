"""Compare injection_api_manifest vs Frida hook catalog coverage."""
from __future__ import annotations

from noirlycan_agent.collector.infrastructure.frida_hook_catalog import (
    NT_HANDLER_EXPORTS,
    build_runtime_config,
    hook_exports_in_config,
)
from noirlycan_core.kernel.classification.api_manifest import REPO_REQUIRED_APIS

config = build_runtime_config(None)
hooked = hook_exports_in_config(config)
missing = sorted(REPO_REQUIRED_APIS - hooked)
dynamic = set(config.get("dynamic_nt") or [])

print(f"manifest APIs: {len(REPO_REQUIRED_APIS)}")
print(f"catalog hooks: {len(config.get('hooks') or [])}")
print(f"NT handler exports: {len(NT_HANDLER_EXPORTS)}")
print(f"dynamic_nt: {len(dynamic)}")
print(f"covered: {len(REPO_REQUIRED_APIS) - len(missing)}")
print()
print("MISSING:")
for item in missing:
    print(f"  - {item}")
print()
print("dynamic_nt entries:")
for item in sorted(dynamic):
    print(f"  - {item}")
