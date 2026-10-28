from __future__ import annotations

import argparse
from pathlib import Path

from noirlycan_dashboard.server import run_static_dashboard


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "serve":
        return command_serve(args)
    parser.print_help()
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="noirlycan-dashboard",
        description="Serve the built Noirlycan React console.",
    )
    subparsers = parser.add_subparsers(dest="command")

    serve = subparsers.add_parser("serve", help="Serve built React dashboard-ui/dist")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    serve.add_argument("--ui-dist", type=Path)

    return parser


def command_serve(args: argparse.Namespace) -> int:
    run_static_dashboard(host=args.host, port=args.port, ui_dist=args.ui_dist)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
