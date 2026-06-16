"""Compare injection_api_manifest vs windows_injection_hooks.js coverage."""
from __future__ import annotations

import re
from pathlib import Path

from noirlycan_telemetry.kernel.classification.api_manifest import REPO_REQUIRED_APIS

ROOT = Path(__file__).resolve().parents[1]
JS = ROOT / "src" / "noirlycan_telemetry" / "frida_hooks" / "windows_injection_hooks.js"
js = JS.read_text(encoding="utf-8")

static = set(re.findall(r'hook\([^,]+,\s*"([^"]+)"', js))
enum_hooks = set(re.findall(r'enumHook\([^,]+,\s*"([^"]+)"', js))
handlers = set(re.findall(r"^\s+((?:Nt|Zw|Rtl)[A-Za-z]+):\s*\{", js, re.M))
dynamic_block = js.split("DYNAMIC_INJECTION_APIS")[1].split("]);")[0]
dynamic = set(re.findall(r'"((?:Nt|Zw)[A-Za-z]+)"', dynamic_block))
zw_alias = {name for name in handlers if name.startswith("Zw")}

hooked = set(static) | set(handlers) | set(zw_alias) | set(enum_hooks)
for name in handlers:
    if name.startswith("Nt"):
        hooked.add("Zw" + name[2:])
for name in dynamic:
    if name.startswith("Zw") and f"Nt{name[2:]}" in handlers:
        hooked.add(name)
    elif name in handlers:
        hooked.add(name)

missing = sorted(REPO_REQUIRED_APIS - hooked)
dynamic_no_handler = sorted(dynamic - handlers - {z for z in dynamic if z.startswith("Zw") and f"Nt{z[2:]}" in handlers})
handlers_not_dynamic = sorted(handlers - dynamic)

print(f"manifest APIs: {len(REPO_REQUIRED_APIS)}")
print(f"static hook(): {len(static)}")
print(f"API_HANDLERS: {len(handlers)}")
print(f"DYNAMIC_INJECTION_APIS: {len(dynamic)}")
print(f"Zw aliases: {len(zw_alias)}")
print(f"covered: {len(REPO_REQUIRED_APIS) - len(missing)}")
print()
print("MISSING:")
for item in missing:
    print(f"  - {item}")
print()
print("DYNAMIC without handler:")
for item in dynamic_no_handler:
    print(f"  - {item}")
print()
print("Handlers not in DYNAMIC (static-only Nt hooks):")
for item in handlers_not_dynamic:
    print(f"  - {item}")
print()
print(f"enumHook registrations: {len(enum_hooks)}")
if enum_hooks:
    print("  ", ", ".join(sorted(enum_hooks)))
