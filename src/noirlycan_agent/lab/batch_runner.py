"""Batch sample analysis for mini-corpus thesis studies."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from noirlycan_core.detection.correlator import Correlator
from noirlycan_core.analysis.session_analytics import aggregate_batch_reports, analyze_session
from noirlycan_agent.runtime.event_sink import JsonlWriter
from noirlycan_agent.runtime.pipeline import (
    create_monitor_or_none,
    create_sysmon_or_none,
    drain_frida,
    process_sysmon_batch,
    safe_attach,
)
from noirlycan_agent.runtime.triage import is_interesting_path
from noirlycan_core.storage.log_store import new_session_log_path


def discover_samples(input_dir: Path) -> list[Path]:
    if not input_dir.exists():
        return []
    samples = [
        path.resolve()
        for path in sorted(input_dir.rglob("*"))
        if path.is_file() and is_interesting_path(str(path)) and path.suffix.lower() == ".exe"
    ]
    return samples


def run_sample_analysis(
    sample_path: Path,
    *,
    timeout_seconds: int = 120,
    watch_sysmon: bool = True,
    minimum_score: int = 50,
    logs_dir: Path | None = None,
    use_frida: bool = True,
) -> dict[str, Any]:
    try:
        import frida
    except ImportError as exc:
        return {"sample": str(sample_path), "error": f"frida unavailable: {exc}"}

    if not sample_path.exists():
        return {"sample": str(sample_path), "error": "file not found"}

    correlator = Correlator(minimum_score=minimum_score, logs_dir=logs_dir)
    log_path = new_session_log_path(logs_dir)
    writer = JsonlWriter(log_path)
    monitor = create_monitor_or_none() if use_frida else None
    sysmon = create_sysmon_or_none(watch_sysmon)

    device = frida.get_local_device()
    pid: int | None = None
    error: str | None = None
    try:
        pid = device.spawn([str(sample_path)])
        if monitor is not None:
            safe_attach(monitor, pid)
        device.resume(pid)
        deadline = time.time() + max(timeout_seconds, 5)
        while time.time() < deadline:
            if sysmon is not None:
                process_sysmon_batch(
                    sysmon,
                    correlator,
                    writer,
                    monitor,
                    auto_attach=use_frida,
                )
            if monitor is not None:
                drain_frida(monitor, correlator, writer, auto_attach=True)
            time.sleep(0.25)
    except Exception as exc:  # pragma: no cover - runtime dependent
        error = str(exc)
    finally:
        writer.close()
        if monitor is not None:
            monitor.detach_all()

    report = analyze_session(log_path)
    report["sample"] = str(sample_path)
    report["spawn_pid"] = pid
    report["timeout_seconds"] = timeout_seconds
    report["watch_sysmon"] = watch_sysmon
    report["use_frida"] = use_frida
    report["ablation_mode"] = "sysmon_only" if not use_frida else "frida_sysmon"
    if error:
        report["error"] = error
    return report


def run_batch(
    input_dir: Path,
    *,
    timeout_seconds: int = 120,
    watch_sysmon: bool = True,
    minimum_score: int = 50,
    logs_dir: Path | None = None,
    use_frida: bool = True,
    limit: int | None = None,
) -> dict[str, Any]:
    samples = discover_samples(input_dir)
    if limit is not None:
        samples = samples[: max(limit, 0)]
    reports: list[dict[str, Any]] = []
    for index, sample in enumerate(samples, start=1):
        print(f"[batch {index}/{len(samples)}] {sample.name}", flush=True)
        reports.append(
            run_sample_analysis(
                sample,
                timeout_seconds=timeout_seconds,
                watch_sysmon=watch_sysmon,
                minimum_score=minimum_score,
                logs_dir=logs_dir,
                use_frida=use_frida,
            )
        )
    summary = aggregate_batch_reports(reports)
    summary["input_dir"] = str(input_dir.resolve())
    summary["timeout_seconds"] = timeout_seconds
    summary["watch_sysmon"] = watch_sysmon
    summary["use_frida"] = use_frida
    return summary


def write_batch_report(report: dict[str, Any], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
