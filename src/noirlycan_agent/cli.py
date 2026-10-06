"""``noirlycan-agent``: the lab agent (monitoring module) for a Windows 10/11 VM."""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from pathlib import Path

from noirlycan_core.runtime.agent_config import apply_agent_config, load_agent_config


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "config", None) is not None:
        apply_agent_config(args, load_agent_config(args.config))
    handlers = {
        "run": command_run,
        "spawn": command_spawn,
        "triage": command_triage,
        "batch": command_batch,
        "compare": command_compare,
    }
    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        return 2
    return handler(args)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="noirlycan-agent", description=__doc__)
    subparsers = parser.add_subparsers(dest="command")

    run = subparsers.add_parser("run", help="Watch the VM: Sysmon + Frida + file drops → detector")
    _add_collector_options(run)
    run.add_argument("--no-watch-files", action="store_true", help="Disable the dropped-executable folder watch")
    run.add_argument("--watch-path", action="append", default=[], help="Extra folder to watch (repeatable)")
    run.add_argument("--attach-pid", action="append", type=int, default=[], help="PID to attach Frida to")
    run.add_argument("--auto-attach-new-processes", action="store_true", help="Attach Frida to new processes")
    run.add_argument("--poll-interval", type=float, default=1.0, help="Loop interval in seconds")

    spawn = subparsers.add_parser("spawn", help="Spawn one sample under Frida and watch it")
    _add_collector_options(spawn)
    spawn.add_argument("argv", nargs=argparse.REMAINDER, help="Command line to spawn, after --")

    triage = subparsers.add_parser("triage", help="Static triage of one file")
    triage.add_argument("path")

    batch = subparsers.add_parser("batch", help="Run every EXE in a folder and report findings")
    _add_study_options(batch)
    batch.add_argument("--minimum-score", type=int, default=50)
    batch.add_argument("--watch-sysmon", action="store_true")
    batch.add_argument("--sysmon-only", action="store_true", help="Do not use Frida")

    compare = subparsers.add_parser("compare", help="Compare detection with Defender / VirusTotal")
    _add_study_options(compare)
    compare.add_argument("--defender", action="store_true")
    compare.add_argument("--virustotal", action="store_true", help="Query VirusTotal (needs VT_API_KEY)")
    compare.add_argument("--vt-delay", type=float, default=15.0)
    return parser


def _add_collector_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--watch-sysmon", action="store_true", help="Poll the Sysmon Operational log")
    parser.add_argument("--minimum-score", type=int, default=50, help="Minimum finding score")
    parser.add_argument("--jsonl", type=Path, help="Session log path (default: logs/session-<timestamp>.jsonl)")
    parser.add_argument("--no-jsonl", action="store_true", help="Do not write a session log")
    parser.add_argument("--raw-events", action="store_true", help="Also log raw Frida messages and Sysmon EID 10 (large)")
    parser.add_argument("--config", type=Path, help="Agent TOML exported from the dashboard")
    parser.add_argument("--server", default="", help="Console host:port")
    parser.add_argument("--token", default="", help="Enrollment token from the dashboard")
    parser.add_argument("--agent-id", default="", help="Agent id registered on the dashboard")


def _add_study_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--logs-dir", type=Path)


def command_run(args: argparse.Namespace) -> int:
    from noirlycan_agent.runtime.collector import run_collector

    return run_collector(args)


def command_spawn(args: argparse.Namespace) -> int:
    from noirlycan_agent.runtime.collector import run_spawn

    argv = args.argv[1:] if args.argv and args.argv[0] == "--" else args.argv
    if not argv:
        print("spawn requires a command line after --", file=sys.stderr)
        return 2
    return run_spawn(args, argv)


def command_triage(args: argparse.Namespace) -> int:
    from noirlycan_agent.runtime.triage import triage_file

    print(json.dumps(dataclasses.asdict(triage_file(args.path)), indent=2, sort_keys=True))
    return 0


def command_batch(args: argparse.Namespace) -> int:
    from noirlycan_agent.lab.batch_runner import run_batch, write_batch_report

    report = run_batch(
        args.input,
        timeout_seconds=args.timeout,
        watch_sysmon=args.watch_sysmon,
        minimum_score=args.minimum_score,
        logs_dir=args.logs_dir,
        use_frida=not args.sysmon_only,
        limit=args.limit,
    )
    write_batch_report(report, args.output)
    print(f"[+] Batch report written to {args.output}")
    return 0


def command_compare(args: argparse.Namespace) -> int:
    from noirlycan_agent.lab.batch_runner import write_batch_report
    from noirlycan_agent.lab.sandbox_compare import default_vt_api_key, run_compare_batch

    report = run_compare_batch(
        args.input,
        timeout_seconds=args.timeout,
        use_defender=args.defender,
        use_virustotal=args.virustotal,
        vt_api_key=default_vt_api_key(),
        logs_dir=args.logs_dir,
        limit=args.limit,
        vt_delay_seconds=args.vt_delay,
    )
    write_batch_report(report, args.output)
    print(f"[+] Comparison report written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
