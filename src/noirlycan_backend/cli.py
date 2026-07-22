from __future__ import annotations

import argparse
import json
from pathlib import Path

from noirlycan_core.analysis.domain.batch_runner import run_batch, write_batch_report
from noirlycan_core.analysis.domain.reclassify import reclassify_session, write_reclassified_report
from noirlycan_core.analysis.domain.sandbox_compare import default_vt_api_key, run_compare_batch
from noirlycan_core.analysis.domain.session_analytics import analyze_corpus
from noirlycan_backend.infrastructure.console_db import ConsoleDatabase
from noirlycan_backend.domain.demo_session import import_jsonl_session, write_demo_session
from noirlycan_backend.server import run_api
from noirlycan_core.storage.infrastructure.log_store import ensure_logs_dir, resolve_logs_dir


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "api":
        return command_api(args)
    if args.command == "batch":
        return command_batch(args)
    if args.command == "compare":
        return command_compare(args)
    if args.command == "corpus":
        return command_corpus(args)
    if args.command == "reclassify":
        return command_reclassify(args)
    if args.command == "seed-demo":
        return command_seed_demo(args)
    parser.print_help()
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="noirlycan-backend",
        description="Noirlycan lab API server (FastAPI ingest, auth, rules, agents).",
    )
    subparsers = parser.add_subparsers(dest="command")

    api = subparsers.add_parser("api", help="Launch API-only backend (no bundled UI)")
    api.add_argument("--host", default="127.0.0.1")
    api.add_argument("--port", type=int, default=8765)
    api.add_argument("--logs-dir", type=Path)
    api.add_argument(
        "--with-ui",
        action="store_true",
        help="Also serve built dashboard-ui/dist from this process (dev convenience only)",
    )
    api.add_argument("--ui-dist", type=Path, help="Path to dashboard-ui/dist when using --with-ui")

    batch = subparsers.add_parser("batch", help="Batch analysis over a folder of EXEs")
    batch.add_argument("--input", type=Path, required=True)
    batch.add_argument("--output", type=Path, required=True)
    batch.add_argument("--timeout", type=int, default=120)
    batch.add_argument("--limit", type=int, default=None)
    batch.add_argument("--minimum-score", type=int, default=50)
    batch.add_argument("--watch-sysmon", action="store_true")
    batch.add_argument("--sysmon-only", action="store_true")
    batch.add_argument("--logs-dir", type=Path)

    compare = subparsers.add_parser("compare", help="Compare detection with Defender / VT")
    compare.add_argument("--input", type=Path, required=True)
    compare.add_argument("--output", type=Path, required=True)
    compare.add_argument("--timeout", type=int, default=120)
    compare.add_argument("--limit", type=int, default=None)
    compare.add_argument("--defender", action="store_true")
    compare.add_argument("--virustotal", action="store_true")
    compare.add_argument("--vt-delay", type=float, default=15.0)
    compare.add_argument("--logs-dir", type=Path)

    corpus = subparsers.add_parser("corpus", help="Aggregate metrics across JSONL sessions")
    corpus.add_argument("--logs-dir", type=Path)
    corpus.add_argument("--limit", type=int, default=None)
    corpus.add_argument("--output", type=Path)

    reclassify = subparsers.add_parser("reclassify", help="Re-run classification on a session")
    reclassify.add_argument("session")
    reclassify.add_argument("--logs-dir", type=Path)
    reclassify.add_argument("--minimum-score", type=int, default=50)
    reclassify.add_argument("--output", type=Path)
    reclassify.add_argument("--write", choices=["sidecar", "in_place"])

    seed = subparsers.add_parser("seed-demo", help="Seed a demo agent session for dashboard testing")
    seed.add_argument("--logs-dir", type=Path)
    seed.add_argument("--agent-id", default="lab-vm-win01")
    seed.add_argument("--hostname", default="LAB-VM-WIN01")
    seed.add_argument(
        "--variant",
        choices=["primary", "secondary"],
        default="primary",
        help="Demo fixture set (secondary = smaller second VM session)",
    )
    seed.add_argument(
        "--fleet",
        action="store_true",
        help="Seed lab-vm-win01 + lab-vm-win02 demo sessions for multi-agent overview testing",
    )
    seed.add_argument(
        "--import-file",
        type=Path,
        help="Import an existing JSONL session into the agent log (instead of built-in demo data)",
    )
    return parser


def command_api(args: argparse.Namespace) -> int:
    run_api(
        host=args.host,
        port=args.port,
        logs_dir=args.logs_dir,
        ui_dist=args.ui_dist if args.with_ui else None,
        with_ui=args.with_ui,
    )
    return 0


def command_batch(args: argparse.Namespace) -> int:
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
    print(json.dumps(report, indent=2, sort_keys=True))
    print(f"[+] Batch report written to {args.output}")
    return 0


def command_reclassify(args: argparse.Namespace) -> int:
    report = reclassify_session(
        args.session,
        logs_dir=args.logs_dir,
        minimum_score=args.minimum_score,
        write=args.write or False,
    )
    if args.output is not None:
        write_reclassified_report(report, args.output)
        print(f"[+] Reclassify report written to {args.output}")
    if report.get("written_path"):
        print(f"[+] Reclassified JSONL written to {report['written_path']}")
    print(json.dumps(report, indent=2, sort_keys=True, default=str))
    return 0


def command_corpus(args: argparse.Namespace) -> int:
    from noirlycan_core.storage.infrastructure.analysis_db import AnalysisDatabase

    database = AnalysisDatabase(args.logs_dir) if args.logs_dir else AnalysisDatabase()
    report = analyze_corpus(args.logs_dir, limit=args.limit, database=database)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"[+] Corpus report written to {args.output}")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def command_seed_demo(args: argparse.Namespace) -> int:
    logs_dir = ensure_logs_dir(args.logs_dir)
    database = ConsoleDatabase(logs_dir)

    if args.fleet:
        targets = [
            ("lab-vm-win01", "LAB-VM-WIN01", "primary"),
            ("lab-vm-win02", "LAB-VM-WIN02", "secondary"),
        ]
        for agent_id, hostname, variant in targets:
            rel, path, count = write_demo_session(logs_dir, agent_id=agent_id, variant=variant)
            database.set_agent_session_rel(agent_id, rel)
            database.upsert_agent(
                agent_id,
                hostname=hostname,
                os_name="Windows",
                mode="run",
                watching=r"C:\Lab\loader.exe" if variant == "primary" else r"C:\Tools\dropper.exe",
            )
            print(f"[+] Agent: {agent_id} · {count} events · {rel}")
        print("[+] Fleet demo ready — open Overview for all-agent stats")
        return 0

    agent_id = str(args.agent_id).strip()
    if args.import_file:
        rel, path, count = import_jsonl_session(
            logs_dir,
            agent_id=agent_id,
            source=Path(args.import_file).expanduser().resolve(),
        )
        source_label = args.import_file
    else:
        rel, path, count = write_demo_session(
            logs_dir,
            agent_id=agent_id,
            variant=str(args.variant),
        )
        source_label = f"built-in demo fixtures ({args.variant})"
    database.set_agent_session_rel(agent_id, rel)
    database.upsert_agent(
        agent_id,
        hostname=str(args.hostname),
        os_name="Windows",
        mode="run",
        watching=r"C:\Lab\loader.exe",
    )
    print(f"[+] Agent: {agent_id}")
    print(f"[+] Session: {rel} ({count} events)")
    print(f"[+] Path: {path}")
    print(f"[+] Source: {source_label}")
    print(f"[+] Open dashboard with ?agent_id={agent_id}")
    return 0


def command_compare(args: argparse.Namespace) -> int:
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
    print(json.dumps(report, indent=2, sort_keys=True))
    print(f"[+] Comparison report written to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
