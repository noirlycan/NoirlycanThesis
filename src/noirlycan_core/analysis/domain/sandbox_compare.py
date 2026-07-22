"""Compare Noirlycan results with Defender / VirusTotal (mini study)."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from noirlycan_core.analysis.domain.batch_runner import discover_samples, run_sample_analysis
from noirlycan_agent.collector.infrastructure.triage import sha256_file


def sha256_of(path: Path) -> str | None:
    return sha256_file(str(path))


def defender_scan(path: Path, timeout_seconds: int = 300) -> dict[str, Any]:
    candidates = [
        Path(r"C:\Program Files\Windows Defender\MpCmdRun.exe"),
        Path(r"C:\Program Files (x86)\Windows Defender\MpCmdRun.exe"),
    ]
    mpcmd = next((item for item in candidates if item.exists()), None)
    if mpcmd is None:
        return {"available": False, "detected": None, "detail": "MpCmdRun.exe not found"}

    command = [
        str(mpcmd),
        "-Scan",
        "-ScanType",
        "3",
        "-File",
        str(path),
    ]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"available": True, "detected": None, "detail": str(exc)}

    output = f"{completed.stdout}\n{completed.stderr}".lower()
    detected = any(
        token in output
        for token in (
            "threat",
            "malware",
            "found",
            "detected",
            "virus",
        )
    ) and completed.returncode != 0
    return {
        "available": True,
        "detected": detected,
        "returncode": completed.returncode,
        "detail": (completed.stdout or completed.stderr or "").strip()[:2000],
    }


def virustotal_lookup(sha256: str, api_key: str, timeout_seconds: int = 30) -> dict[str, Any]:
    if not api_key:
        return {"available": False, "detected": None, "detail": "VT_API_KEY not set"}
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    request = urllib.request.Request(
        url,
        headers={
            "x-apikey": api_key,
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {"available": True, "detected": None, "detail": "hash not known to VT"}
        return {"available": True, "detected": None, "detail": f"HTTP {exc.code}"}
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        return {"available": False, "detected": None, "detail": str(exc)}

    stats = (((payload.get("data") or {}).get("attributes") or {}).get("last_analysis_stats") or {})
    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    return {
        "available": True,
        "detected": (malicious + suspicious) > 0,
        "malicious": malicious,
        "suspicious": suspicious,
        "stats": stats,
        "detail": "VT file report",
    }


def compare_sample(
    sample_path: Path,
    *,
    timeout_seconds: int = 120,
    use_defender: bool = True,
    use_virustotal: bool = False,
    vt_api_key: str | None = None,
    logs_dir: Path | None = None,
) -> dict[str, Any]:
    digest = sha256_of(sample_path)
    noirlycan = run_sample_analysis(
        sample_path,
        timeout_seconds=timeout_seconds,
        watch_sysmon=True,
        logs_dir=logs_dir,
        use_frida=True,
    )
    defender = defender_scan(sample_path) if use_defender else {"available": False, "skipped": True}
    virustotal = (
        virustotal_lookup(digest, vt_api_key or "", timeout_seconds=30)
        if use_virustotal and digest
        else {"available": False, "skipped": True}
    )
    noirlycan_detected = bool(noirlycan.get("injection_detected"))
    return {
        "sample": str(sample_path),
        "sha256": digest,
        "noirlycan": {
            "detected": noirlycan_detected,
            "max_score": noirlycan.get("max_score"),
            "techniques": noirlycan.get("techniques"),
            "recursive_chain_count": noirlycan.get("recursive_chain_count"),
            "session": noirlycan.get("session"),
            "evasion": noirlycan.get("evasion"),
        },
        "defender": defender,
        "virustotal": virustotal,
        "gaps": _gap_analysis(noirlycan_detected, defender, virustotal),
    }


def run_compare_batch(
    input_dir: Path,
    *,
    timeout_seconds: int = 120,
    use_defender: bool = True,
    use_virustotal: bool = False,
    vt_api_key: str | None = None,
    logs_dir: Path | None = None,
    limit: int | None = None,
    vt_delay_seconds: float = 15.0,
) -> dict[str, Any]:
    samples = discover_samples(input_dir)
    if limit is not None:
        samples = samples[: max(limit, 0)]
    rows: list[dict[str, Any]] = []
    for index, sample in enumerate(samples, start=1):
        print(f"[compare {index}/{len(samples)}] {sample.name}", flush=True)
        rows.append(
            compare_sample(
                sample,
                timeout_seconds=timeout_seconds,
                use_defender=use_defender,
                use_virustotal=use_virustotal,
                vt_api_key=vt_api_key,
                logs_dir=logs_dir,
            )
        )
        if use_virustotal and index < len(samples):
            time.sleep(max(vt_delay_seconds, 0))
    return summarize_compare(rows, input_dir=input_dir)


def summarize_compare(rows: list[dict[str, Any]], *, input_dir: Path) -> dict[str, Any]:
    total = len(rows)
    noirlycan_hits = sum(1 for row in rows if (row.get("noirlycan") or {}).get("detected"))
    defender_hits = sum(
        1
        for row in rows
        if (row.get("defender") or {}).get("available") and (row.get("defender") or {}).get("detected")
    )
    vt_hits = sum(
        1
        for row in rows
        if (row.get("virustotal") or {}).get("available") and (row.get("virustotal") or {}).get("detected")
    )
    noirlycan_only = sum(1 for row in rows if row.get("gaps") == "noirlycan_only")
    defender_only = sum(1 for row in rows if row.get("gaps") == "defender_only")
    both = sum(1 for row in rows if row.get("gaps") == "both")
    neither = sum(1 for row in rows if row.get("gaps") == "neither")
    return {
        "input_dir": str(input_dir.resolve()),
        "samples": total,
        "noirlycan_detected": noirlycan_hits,
        "defender_detected": defender_hits,
        "virustotal_detected": vt_hits,
        "gap_counts": {
            "noirlycan_only": noirlycan_only,
            "defender_only": defender_only,
            "both": both,
            "neither": neither,
        },
        "rows": rows,
    }


def _gap_analysis(
    noirlycan_detected: bool,
    defender: dict[str, Any],
    virustotal: dict[str, Any],
) -> str:
    defender_detected = bool(defender.get("available") and defender.get("detected"))
    vt_detected = bool(virustotal.get("available") and virustotal.get("detected"))
    external_detected = defender_detected or vt_detected
    if noirlycan_detected and external_detected:
        return "both"
    if noirlycan_detected and not external_detected:
        return "noirlycan_only"
    if not noirlycan_detected and external_detected:
        return "defender_only"
    return "neither"


def default_vt_api_key() -> str:
    return os.environ.get("VT_API_KEY", "").strip()
