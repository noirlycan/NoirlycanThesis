"""Deprecated compatibility wrapper — use noirlycan-backend and noirlycan-dashboard instead."""

from __future__ import annotations

import argparse
import sys
import warnings
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    args_list = list(argv if argv is not None else sys.argv[1:])
    parser = build_parser()
    args = parser.parse_args(args_list)
    if args.command == "console":
        warnings.warn(
            "noirlycan-console console is deprecated; use `noirlycan-backend api`",
            DeprecationWarning,
            stacklevel=2,
        )
        from noirlycan_backend.server import run_api

        run_api(
            host=args.host,
            port=args.port,
            logs_dir=args.logs_dir,
            ui_dist=args.ui_dist,
            with_ui=bool(args.ui_dist) or args.with_ui,
        )
        return 0
    if args.command == "dashboard":
        warnings.warn(
            "noirlycan-console dashboard is deprecated; use `noirlycan-dashboard legacy`",
            DeprecationWarning,
            stacklevel=2,
        )
        from noirlycan_dashboard.legacy.server import run_dashboard

        run_dashboard(
            host=args.host,
            port=args.port,
            logs_dir=args.logs_dir,
            auto_collector=not args.no_auto_collector,
            elevate_collector=not args.no_collector_elevate,
        )
        return 0
    if args.command in {"batch", "compare", "corpus", "reclassify"}:
        from noirlycan_backend.cli import main as backend_main

        return backend_main(args_list)
    parser.print_help()
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="noirlycan-console",
        description="Deprecated wrapper — prefer noirlycan-backend / noirlycan-dashboard.",
    )
    subparsers = parser.add_subparsers(dest="command")

    console = subparsers.add_parser("console", help="[deprecated] Launch backend API")
    console.add_argument("--host", default="127.0.0.1")
    console.add_argument("--port", type=int, default=8765)
    console.add_argument("--logs-dir", type=Path)
    console.add_argument("--ui-dist", type=Path)
    console.add_argument("--with-ui", action="store_true")

    dashboard = subparsers.add_parser("dashboard", help="[deprecated] Launch legacy Django")
    dashboard.add_argument("--host", default="127.0.0.1")
    dashboard.add_argument("--port", type=int, default=8765)
    dashboard.add_argument("--logs-dir", type=Path)
    dashboard.add_argument("--no-auto-collector", action="store_true")
    dashboard.add_argument("--no-collector-elevate", action="store_true")

    for name in ("batch", "compare", "corpus", "reclassify"):
        subparsers.add_parser(name, help=f"[deprecated] Delegates to noirlycan-backend {name}")
    return parser


if __name__ == "__main__":
    raise SystemExit(main())
