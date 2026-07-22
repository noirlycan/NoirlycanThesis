from __future__ import annotations

import argparse
from pathlib import Path

from noirlycan_dashboard.server import run_static_dashboard


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "serve":
        return command_serve(args)
    if args.command == "legacy":
        return command_legacy(args)
    parser.print_help()
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="noirlycan-dashboard",
        description="Noirlycan dashboard UI (React static) and legacy Django console.",
    )
    subparsers = parser.add_subparsers(dest="command")

    serve = subparsers.add_parser("serve", help="Serve built React dashboard-ui/dist")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    serve.add_argument("--ui-dist", type=Path)

    legacy = subparsers.add_parser("legacy", help="Launch legacy Django dashboard")
    legacy.add_argument("--host", default="127.0.0.1")
    legacy.add_argument("--port", type=int, default=8766)
    legacy.add_argument("--logs-dir", type=Path)
    legacy.add_argument("--no-auto-collector", action="store_true")
    legacy.add_argument("--no-collector-elevate", action="store_true")
    return parser


def command_serve(args: argparse.Namespace) -> int:
    run_static_dashboard(host=args.host, port=args.port, ui_dist=args.ui_dist)
    return 0


def command_legacy(args: argparse.Namespace) -> int:
    from noirlycan_dashboard.legacy.server import run_dashboard

    run_dashboard(
        host=args.host,
        port=args.port,
        logs_dir=args.logs_dir,
        auto_collector=not args.no_auto_collector,
        elevate_collector=not args.no_collector_elevate,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
