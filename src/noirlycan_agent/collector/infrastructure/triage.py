from __future__ import annotations

import hashlib
import math
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

try:
    import pefile
except ImportError:  # pragma: no cover - optional until installed on Windows lab
    pefile = None


EXECUTABLE_SUFFIXES = {
    ".exe",
    ".dll",
    ".scr",
    ".com",
    ".cpl",
    ".ocx",
    ".ps1",
    ".js",
    ".jse",
    ".vbs",
    ".vbe",
    ".hta",
    ".bat",
    ".cmd",
}

SUSPICIOUS_DIRECTORIES = (
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\appdata\\local\\",
    "\\downloads\\",
    "\\users\\public\\",
    "\\programdata\\",
    "\\windows\\temp\\",
    "\\startup\\",
)


@dataclass(frozen=True)
class FileTriage:
    path: str
    sha256: str | None
    pe: bool
    signed: bool | None
    entropy: float | None
    suspicious_reasons: tuple[str, ...]
    score: int


def is_interesting_path(path: str) -> bool:
    return Path(path).suffix.lower() in EXECUTABLE_SUFFIXES


def sha256_file(path: str) -> str | None:
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def shannon_entropy(path: str, max_bytes: int = 1024 * 1024) -> float | None:
    try:
        with open(path, "rb") as handle:
            data = handle.read(max_bytes)
    except OSError:
        return None
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    entropy = 0.0
    length = len(data)
    for count in counts:
        if count:
            probability = count / length
            entropy -= probability * math.log2(probability)
    return entropy


def is_pe_file(path: str) -> bool:
    try:
        with open(path, "rb") as handle:
            return handle.read(2) == b"MZ"
    except OSError:
        return False


def imported_injection_apis(path: str) -> tuple[str, ...]:
    if pefile is None or not is_pe_file(path):
        return ()
    interesting = {
        "VirtualAllocEx",
        "VirtualAllocExNuma",
        "WriteProcessMemory",
        "NtWriteVirtualMemory",
        "CreateRemoteThread",
        "CreateRemoteThreadEx",
        "NtCreateThreadEx",
        "RtlCreateUserThread",
        "NtCreateSection",
        "NtMapViewOfSection",
        "SetThreadContext",
        "NtSetContextThread",
        "QueueUserAPC",
        "NtQueueApcThread",
        "ResumeThread",
        "NtResumeThread",
        "NtUnmapViewOfSection",
    }
    try:
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )
    except Exception:
        return ()

    found: set[str] = set()
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        for imp in entry.imports:
            if not imp.name:
                continue
            name = imp.name.decode("ascii", errors="ignore")
            if name in interesting:
                found.add(name)
    return tuple(sorted(found))


def authenticode_signed(path: str) -> bool | None:
    if os.name != "nt":
        return None
    command = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        (
            "$s = Get-AuthenticodeSignature -LiteralPath $args[0]; "
            "if ($s.Status -eq 'Valid') { 'Valid' } else { $s.Status }"
        ),
        path,
    ]
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    output = completed.stdout.strip()
    if not output:
        return None
    return output == "Valid"


def triage_file(path: str, *, quick: bool = False) -> FileTriage:
    reasons: list[str] = []
    score = 0
    suffix = Path(path).suffix.lower()
    lower_path = path.lower()

    if suffix in EXECUTABLE_SUFFIXES:
        reasons.append(f"executable_or_script_suffix:{suffix}")
        score += 15
    if any(marker in lower_path for marker in SUSPICIOUS_DIRECTORIES):
        reasons.append("user_writable_or_staging_directory")
        score += 20

    pe = is_pe_file(path)
    if pe:
        reasons.append("pe_header")
        score += 10

    entropy = shannon_entropy(path)
    if entropy is not None and entropy >= 7.0:
        reasons.append("high_entropy")
        score += 15

    imports = imported_injection_apis(path)
    if imports:
        reasons.append("imports_injection_apis:" + ",".join(imports[:8]))
        score += min(25, 5 * len(imports))

    signed = None if quick else authenticode_signed(path)
    if signed is False and pe:
        reasons.append("unsigned_pe")
        score += 15

    return FileTriage(
        path=path,
        sha256=sha256_file(path),
        pe=pe,
        signed=signed,
        entropy=entropy,
        suspicious_reasons=tuple(reasons),
        score=score,
    )
