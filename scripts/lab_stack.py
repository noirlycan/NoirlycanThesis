#!/usr/bin/env python3
"""Launch Noirlycan lab processes (backend, dashboard, agent) via subprocess."""

from __future__ import annotations

import argparse
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
_CHILDREN: list[subprocess.Popen[Any]] = []


def _python() -> str:
    return sys.executable


def _npm() -> str:
    npm = shutil.which("npm")
    if not npm:
        raise SystemExit("[!] npm not found on PATH. Install Node.js LTS first.")
    return npm


def _creationflags_new_console() -> int:
    if sys.platform == "win32":
        return subprocess.CREATE_NEW_CONSOLE  # type: ignore[attr-defined]
    return 0


def _spawn(
    args: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    new_console: bool = False,
) -> subprocess.Popen[Any]:
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    kwargs: dict[str, Any] = {
        "cwd": str(cwd or ROOT),
        "env": merged_env,
    }
    if new_console and sys.platform == "win32":
        kwargs["creationflags"] = _creationflags_new_console()
    process = subprocess.Popen(args, **kwargs)
    _CHILDREN.append(process)
    return process


def _terminate_children() -> None:
    for process in list(_CHILDREN):
        if process.poll() is not None:
            continue
        process.terminate()
    deadline = time.monotonic() + 5.0
    for process in list(_CHILDREN):
        if process.poll() is not None:
            continue
        if time.monotonic() >= deadline:
            process.kill()
            continue
        try:
            process.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            process.kill()


def _install_signal_handlers() -> None:
    def _handler(_signum: int, _frame: Any) -> None:
        _terminate_children()
        raise SystemExit(0)

    signal.signal(signal.SIGINT, _handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _handler)


def spawn_backend(*, host: str, port: int, logs_dir: Path | None, new_console: bool) -> subprocess.Popen[Any]:
    args = [
        _python(),
        "-m",
        "noirlycan_backend.cli",
        "api",
        "--host",
        host,
        "--port",
        str(port),
    ]
    if logs_dir is not None:
        args.extend(["--logs-dir", str(logs_dir)])
    print(f"[+] backend: {' '.join(args)}")
    return _spawn(args, cwd=ROOT, new_console=new_console)


def spawn_dashboard(
    *,
    host: str,
    port: int,
    npm_strict_ssl: bool,
    new_console: bool,
) -> subprocess.Popen[Any]:
    env: dict[str, str] = {}
    if not npm_strict_ssl:
        env["npm_config_strict_ssl"] = "false"
    args = [_npm(), "run", "dev", "--", "--host", host, "--port", str(port)]
    print(f"[+] dashboard: {' '.join(args)} (cwd={ROOT / 'dashboard-ui'})")
    return _spawn(args, cwd=ROOT / "dashboard-ui", env=env, new_console=new_console)


def spawn_agent(
    *,
    server: str,
    agent_id: str,
    token: str,
    config: Path | None,
    watch_sysmon: bool,
    auto_attach: bool,
    new_console: bool,
) -> subprocess.Popen[Any]:
    args = [_python(), "-m", "noirlycan_agent.cli", "run"]
    if config is not None:
        args.extend(["--config", str(config)])
    else:
        args.extend(["--server", server, "--agent-id", agent_id, "--token", token])
    if watch_sysmon:
        args.append("--watch-sysmon")
    if auto_attach:
        args.append("--auto-attach-new-processes")
    print(f"[+] agent: {' '.join(args)}")
    return _spawn(args, cwd=ROOT, new_console=new_console)


def spawn_sysmon_install(*, new_console: bool) -> subprocess.Popen[Any]:
    if sys.platform != "win32":
        raise SystemExit("[!] Sysmon install is Windows-only.")
    script = ROOT / "scripts" / "install-sysmon.ps1"
    if not script.exists():
        raise SystemExit(f"[!] Missing {script}")
    args = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(script),
    ]
    print(f"[+] sysmon: {' '.join(args)}")
    return _spawn(args, cwd=ROOT, new_console=new_console)


def _wait_any_failed(processes: list[subprocess.Popen[Any]]) -> int:
    try:
        while True:
            for process in processes:
                code = process.poll()
                if code is not None and code != 0:
                    print(f"[!] process exited with code {code}", file=sys.stderr)
                    _terminate_children()
                    return code
            if all(process.poll() is not None for process in processes):
                return 0
            time.sleep(0.5)
    except KeyboardInterrupt:
        _terminate_children()
        return 0


def cmd_backend(args: argparse.Namespace) -> int:
    process = spawn_backend(
        host=args.host,
        port=args.port,
        logs_dir=args.logs_dir,
        new_console=args.new_console,
    )
    return process.wait()


def cmd_dashboard(args: argparse.Namespace) -> int:
    process = spawn_dashboard(
        host=args.host,
        port=args.port,
        npm_strict_ssl=not args.npm_no_strict_ssl,
        new_console=args.new_console,
    )
    return process.wait()


def cmd_agent(args: argparse.Namespace) -> int:
    if args.config is None and not args.token:
        raise SystemExit("[!] Provide --config or --token (with --server and --agent-id).")
    process = spawn_agent(
        server=args.server,
        agent_id=args.agent_id,
        token=args.token,
        config=args.config,
        watch_sysmon=not args.no_watch_sysmon,
        auto_attach=not args.no_auto_attach,
        new_console=args.new_console,
    )
    return process.wait()


def cmd_sysmon(args: argparse.Namespace) -> int:
    process = spawn_sysmon_install(new_console=args.new_console)
    return process.wait()


def cmd_up(args: argparse.Namespace) -> int:
    _install_signal_handlers()
    backend = spawn_backend(
        host=args.host,
        port=args.backend_port,
        logs_dir=args.logs_dir,
        new_console=args.new_console,
    )
    dashboard = spawn_dashboard(
        host=args.dashboard_host,
        port=args.dashboard_port,
        npm_strict_ssl=not args.npm_no_strict_ssl,
        new_console=args.new_console,
    )
    print("")
    print(f"[+] Backend API:  http://{args.host}:{args.backend_port}/api/health")
    print(f"[+] Dashboard UI: http://{args.dashboard_host}:{args.dashboard_port}")
    print("[+] On Windows VM (Admin), register agent in dashboard then run:")
    print(
        "    python scripts/lab_stack.py agent "
        f"--server {args.host}:{args.backend_port} "
        f"--agent-id {args.agent_id} --token YOUR_TOKEN"
    )
    print("[+] Ctrl+C stops backend and dashboard.")
    print("")
    return _wait_any_failed([backend, dashboard])


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Launch Noirlycan lab stack subprocesses (backend, dashboard, agent).",
    )
    parser.add_argument(
        "--new-console",
        action="store_true",
        help="Windows: open each process in a separate console window.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    backend = sub.add_parser("backend", help="Run noirlycan-backend api")
    backend.add_argument("--host", default="0.0.0.0")
    backend.add_argument("--port", type=int, default=8888)
    backend.add_argument("--logs-dir", type=Path)

    dashboard = sub.add_parser("dashboard", help="Run dashboard-ui via npm run dev")
    dashboard.add_argument("--host", default="0.0.0.0")
    dashboard.add_argument("--port", type=int, default=5173)
    dashboard.add_argument(
        "--npm-no-strict-ssl",
        action="store_true",
        help="Set npm_config_strict_ssl=false (lab VMs with TLS inspection).",
    )

    agent = sub.add_parser("agent", help="Run noirlycan-agent (Windows lab VM)")
    agent.add_argument("--server", default="127.0.0.1:8888")
    agent.add_argument("--agent-id", default="vm01")
    agent.add_argument("--token", default="")
    agent.add_argument("--config", type=Path)
    agent.add_argument("--no-watch-sysmon", action="store_true")
    agent.add_argument("--no-auto-attach", action="store_true")

    sysmon = sub.add_parser("sysmon", help="Run scripts/install-sysmon.ps1 (Windows Admin)")

    up = sub.add_parser("up", help="Start backend + dashboard together")
    up.add_argument("--host", default="0.0.0.0", help="Backend bind host")
    up.add_argument("--backend-port", type=int, default=8888)
    up.add_argument("--dashboard-host", default="0.0.0.0")
    up.add_argument("--dashboard-port", type=int, default=5173)
    up.add_argument("--logs-dir", type=Path)
    up.add_argument("--agent-id", default="vm01")
    up.add_argument("--npm-no-strict-ssl", action="store_true")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "backend":
        return cmd_backend(args)
    if args.command == "dashboard":
        return cmd_dashboard(args)
    if args.command == "agent":
        return cmd_agent(args)
    if args.command == "sysmon":
        return cmd_sysmon(args)
    if args.command == "up":
        return cmd_up(args)
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
