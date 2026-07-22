"""Backward-compatible entry point — delegates to agent, backend, or dashboard."""

from __future__ import annotations

import sys

_AGENT_COMMANDS = frozenset({"run", "spawn", "triage", "health"})
_BACKEND_COMMANDS = frozenset({"api", "batch", "compare", "corpus", "reclassify"})
_DASHBOARD_COMMANDS = frozenset({"serve", "legacy"})
_CONSOLE_COMMANDS = frozenset({"console", "dashboard"})


def main(argv: list[str] | None = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    command = args[0] if args else ""
    if command in _AGENT_COMMANDS:
        from noirlycan_agent.cli import main as agent_main

        return agent_main(args)
    if command in _BACKEND_COMMANDS:
        from noirlycan_backend.cli import main as backend_main

        return backend_main(args)
    if command in _DASHBOARD_COMMANDS:
        from noirlycan_dashboard.cli import main as dashboard_main

        return dashboard_main(args)
    if command in _CONSOLE_COMMANDS or command == "":
        from noirlycan_console.cli import main as console_main

        return console_main(args if args else None)
    from noirlycan_agent.cli import main as agent_main

    return agent_main(args)


if __name__ == "__main__":
    raise SystemExit(main())
