#!/usr/bin/env python3
"""One-off migration: split monolith into noirlycan_core / noirlycan_agent / noirlycan_console."""

from __future__ import annotations

import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"

REPLACEMENTS = [
    ("noirlycan_telemetry.services.console", "noirlycan_backend"),
    ("noirlycan_telemetry.services.dashboard", "noirlycan_dashboard.legacy"),
    ("noirlycan_telemetry.services.collector", "noirlycan_agent.collector"),
    ("noirlycan_telemetry.services.storage", "noirlycan_core.storage"),
    ("noirlycan_telemetry.services.analysis", "noirlycan_core.analysis"),
    ("noirlycan_telemetry.kernel", "noirlycan_core.kernel"),
    ("noirlycan_telemetry.contracts", "noirlycan_core.contracts"),
    ('files("noirlycan_telemetry").joinpath(\n        "frida_hooks/', 'files("noirlycan_agent").joinpath(\n        "frida_hooks/'),
    ('files("noirlycan_telemetry")', 'files("noirlycan_agent")'),
    ("noirlycan_telemetry.frida_hooks", "noirlycan_agent.frida_hooks"),
    ("noirlycan_agent.collector.application.runtime_config", "noirlycan_core.runtime.config"),
    ("from noirlycan_core.runtime.config import", "from noirlycan_core.runtime.config import"),
]

# Fix runtime imports that were collector paths
RUNTIME_IMPORTS = [
    ("noirlycan_agent.collector.application.runtime_config", "noirlycan_core.runtime.config"),
]


def move_tree(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists():
        shutil.rmtree(dst)
    shutil.move(str(src), str(dst))


def ensure_init(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    init = path / "__init__.py"
    if not init.exists():
        init.write_text('"""Noirlycan package."""\n', encoding="utf-8")


def replace_in_file(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    original = text
    for old, new in REPLACEMENTS + RUNTIME_IMPORTS:
        text = text.replace(old, new)
    if text != original:
        path.write_text(text, encoding="utf-8")


def main() -> None:
    legacy = SRC / "noirlycan_telemetry"
    core = SRC / "noirlycan_core"
    agent = SRC / "noirlycan_agent"
    console = SRC / "noirlycan_console"

    ensure_init(core)
    ensure_init(agent)
    ensure_init(console)
    ensure_init(core / "runtime")

    # Move shared core
    move_tree(legacy / "kernel", core / "kernel")
    move_tree(legacy / "contracts", core / "contracts")
    move_tree(legacy / "services" / "storage", core / "storage")
    move_tree(legacy / "services" / "analysis", core / "analysis")

    runtime_src = legacy / "services" / "collector" / "application" / "runtime_config.py"
    shutil.copy2(runtime_src, core / "runtime" / "config.py")
    (core / "runtime" / "__init__.py").write_text(
        'from noirlycan_core.runtime.config import *\n',
        encoding="utf-8",
    )
    runtime_src.unlink(missing_ok=True)

    # Move agent
    move_tree(legacy / "services" / "collector", agent / "collector")
    move_tree(legacy / "frida_hooks", agent / "frida_hooks")

    # Move console backend
    move_tree(legacy / "services" / "console", console / "console")
    move_tree(legacy / "services" / "dashboard", console / "dashboard")

    # Remove empty services dir
    services_dir = legacy / "services"
    if services_dir.exists():
        shutil.rmtree(services_dir, ignore_errors=True)

    # Copy cli for splitting (keep original until new CLIs written)
    shutil.copy2(legacy / "cli.py", agent / "_cli_monolith.py")

    for pattern in ("**/*.py", "**/*.md", "**/*.yml", "**/*.toml", "**/*.js"):
        for path in list(ROOT.glob(pattern)):
            if "scripts/split_packages" in str(path):
                continue
            if path.suffix == ".py" or path.suffix in {".md", ".yml", ".toml"}:
                replace_in_file(path)

    print("Migration file moves complete.")


if __name__ == "__main__":
    main()
