"""Everything the console hands to a Windows VM so one PowerShell line installs the agent.

* ``agent_config_toml``   — the agent's config file (endpoint, id, token, pinned command key).
* ``build_agent_archive`` — a pip-installable zip of just the agent code, built from the
  running backend's own sources (no release step, no git on the VM).
* ``bootstrap_script``    — PowerShell that downloads the archive, creates a venv, installs,
  writes the config, optionally installs Sysmon, and starts the agent.
"""

from __future__ import annotations

import io
import os
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from typing import Any

from noirlycan_core.storage.log_store import find_project_root

ARCHIVE_NAME = "noirlycan-agent.zip"
DESKTOP_EXE_NAME = "NoirlycanAgent.exe"
DESKTOP_SETUP_NAME = "NoirlycanAgentSetup.exe"


def agent_artifact_directory() -> Path:
    configured = os.environ.get("NOIRLYCAN_AGENT_ARTIFACTS_DIR", "").strip()
    return Path(configured).expanduser().resolve() if configured else find_project_root() / "deploy" / "agent-artifacts"


def agent_publication_path(kind: str) -> Path:
    if kind not in {"portable", "installer"}:
        raise ValueError("Unknown agent release kind")
    configured = os.environ.get("NOIRLYCAN_AGENT_EXE" if kind == "portable" else "NOIRLYCAN_AGENT_SETUP", "").strip()
    name = DESKTOP_EXE_NAME if kind == "portable" else DESKTOP_SETUP_NAME
    return Path(configured).expanduser().resolve() if configured else agent_artifact_directory() / name


def agent_download_path(kind: str) -> Path:
    published = agent_publication_path(kind)
    if published.is_file():
        return published
    # Keep locally built dist/ releases usable without publishing them again.
    override = "NOIRLYCAN_AGENT_EXE" if kind == "portable" else "NOIRLYCAN_AGENT_SETUP"
    if not os.environ.get(override, "").strip():
        candidate = find_project_root() / "dist" / published.name
        if candidate.is_file():
            return candidate
    return published


def desktop_executable_path() -> Path:
    return agent_download_path("portable")


def validate_agent_release(path: Path, kind: str) -> None:
    """Validate packaging, not trust or malware status. Only Admin may publish."""
    import pefile

    try:
        with pefile.PE(str(path), fast_load=True) as image:
            allowed = {0x8664} if kind == "portable" else {0x14C, 0x8664}
            if image.FILE_HEADER.Machine not in allowed or image.OPTIONAL_HEADER.Subsystem != 2:
                raise ValueError("Expected a Windows desktop executable (portable Agent must be x64)")
            image.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
            resources = getattr(image, "DIRECTORY_ENTRY_RESOURCE", None)
            if resources is None:
                raise ValueError("The executable has no UAC manifest")
            for resource in resources.entries:
                if resource.id != 24:
                    continue
                for name in resource.directory.entries:
                    for language in name.directory.entries:
                        data = language.data.struct
                        try:
                            manifest = ET.fromstring(image.get_data(data.OffsetToData, data.Size))
                        except ET.ParseError:
                            continue
                        if any(node.tag.rsplit("}", 1)[-1] == "requestedExecutionLevel"
                               and node.attrib.get("level") == "requireAdministrator" for node in manifest.iter()):
                            return
            raise ValueError("The executable must request Administrator through its UAC manifest")
    except (pefile.PEFormatError, AttributeError, IndexError, TypeError) as exc:
        raise ValueError("Not a valid Windows executable") from exc


# Only what the agent needs; the backend and dashboard never leave the console host.
_ARCHIVE_DIRS = ("src/noirlycan_core", "src/noirlycan_agent")
_ARCHIVE_FILES = ("pyproject.toml", "README.md")
_ARCHIVE_SUFFIXES = {".py", ".js", ".toml", ".md"}
_ARCHIVE_SKIP_DIRS = {"__pycache__", "lab"}  # lab/ = batch studies, not needed on a lab VM
# Runtime deps of the ``[agent]`` extra, installed from PyPI before the archive (--no-deps).
AGENT_PIP_DEPS = ("pefile", "cryptography>=42", "frida", "pywin32")

_archive_cache: tuple[tuple[tuple[str, float], ...], bytes] | None = None


def agent_config_toml(server: dict[str, Any], agent: dict[str, Any], *, command_key: str = "") -> str:
    endpoint = f"{server['host']}:{server['port']}"
    agent_id = str(agent.get("id") or "")
    token = str(agent.get("enrollment_token") or "")
    display = str(agent.get("display_name") or agent.get("label") or agent_id)
    return "\n".join(
        [
            "# Noirlycan agent config — copy to VM and run:",
            "#   noirlycan-agent run --config .\\noirlycan-agent.toml --watch-sysmon",
            f"# Workstation: {display}",
            "",
            "[server]",
            f'endpoint = "{endpoint}"',
            f'agent_id = "{agent_id}"',
            f'token = "{token}"',
            "# Public key that signs console commands; the agent refuses anything else.",
            f'command_key = "{command_key}"',
            "",
            "[run]",
            "watch_sysmon = true",
            "auto_attach_new_processes = true",
            "",
        ]
    )


def _archive_members(root: Path) -> list[Path]:
    members = [root / name for name in _ARCHIVE_FILES if (root / name).is_file()]
    for directory in _ARCHIVE_DIRS:
        base = root / directory
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [name for name in dirnames if name not in _ARCHIVE_SKIP_DIRS]
            members.extend(
                Path(dirpath) / name for name in filenames if Path(name).suffix in _ARCHIVE_SUFFIXES
            )
    return sorted(members)


def build_agent_archive(root: Path | None = None) -> bytes:
    """Zip of the agent sources as a pip-installable project. Rebuilt only when a file changed."""
    global _archive_cache
    root = root or find_project_root()
    members = _archive_members(root)
    signature = tuple((str(path.relative_to(root)), path.stat().st_mtime) for path in members)
    if _archive_cache is not None and _archive_cache[0] == signature:
        return _archive_cache[1]
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in members:
            archive.write(path, f"noirlycan-agent/{path.relative_to(root).as_posix()}")
    data = buffer.getvalue()
    _archive_cache = (signature, data)
    return data


def install_command(server: dict[str, Any], agent: dict[str, Any]) -> str:
    """The one line the analyst pastes into an elevated PowerShell on the VM."""
    endpoint = f"{server['host']}:{server['port']}"
    agent_id = str(agent.get("id") or "")
    token = str(agent.get("enrollment_token") or "")
    return (
        f"irm http://{endpoint}/api/agents/{agent_id}/bootstrap.ps1 "
        f"-Headers @{{Authorization='Bearer {token}'}} | iex"
    )


def bootstrap_script(
    server: dict[str, Any],
    agent: dict[str, Any],
    *,
    command_key: str,
    install_dir: str = r"C:\Noirlycan",
) -> str:
    endpoint = f"{server['host']}:{server['port']}"
    agent_id = str(agent.get("id") or "")
    token = str(agent.get("enrollment_token") or "")
    config = agent_config_toml(server, agent, command_key=command_key)
    deps = " ".join(f'"{dep}"' for dep in AGENT_PIP_DEPS)
    # PowerShell here-string: the TOML is embedded verbatim, nothing to escape.
    return f"""# Noirlycan agent bootstrap — generated by the console for agent {agent_id}
# Run in an elevated PowerShell on the lab VM (Sysmon + Event Log need admin).
$ErrorActionPreference = "Stop"
$Root = "{install_dir}"
$Base = "http://{endpoint}"
$Headers = @{{ Authorization = "Bearer {token}" }}
New-Item -ItemType Directory -Force -Path $Root, "$Root\\logs" | Out-Null
Set-Location $Root

$py = Get-Command py -ErrorAction SilentlyContinue
if ($py) {{ $python = "py -3" }} elseif (Get-Command python -ErrorAction SilentlyContinue) {{ $python = "python" }} else {{
  throw "Python 3.10+ is required. Install from https://www.python.org/downloads/windows/ (tick 'Add to PATH'), then run this again."
}}

Write-Host "[1/5] Downloading agent package"
Invoke-WebRequest "$Base/api/agents/{agent_id}/package.zip" -Headers $Headers -OutFile "$Root\\{ARCHIVE_NAME}"
Expand-Archive -Force "$Root\\{ARCHIVE_NAME}" "$Root\\pkg"

Write-Host "[2/5] Creating virtualenv and installing"
if (-not (Test-Path "$Root\\.venv")) {{ Invoke-Expression "$python -m venv `"$Root\\.venv`"" }}
$pip = "$Root\\.venv\\Scripts\\pip.exe"
& $pip install --quiet --upgrade pip
& $pip install --quiet {deps}
& $pip install --quiet --no-deps --force-reinstall "$Root\\pkg\\noirlycan-agent"

Write-Host "[3/5] Writing config"
@'
{config}'@ | Set-Content -Encoding UTF8 "$Root\\noirlycan-agent.toml"

Write-Host "[4/5] Sysmon"
$sysmon = Get-Service Sysmon64 -ErrorAction SilentlyContinue
Invoke-WebRequest "$Base/api/agents/{agent_id}/sysmon-config.xml" -Headers $Headers -OutFile "$Root\\sysmon.xml"
if ($sysmon) {{
  if (Test-Path "$Root\\Sysmon64.exe") {{ & "$Root\\Sysmon64.exe" -c "$Root\\sysmon.xml" | Out-Null }}
  Write-Host "      Sysmon already installed; config refreshed"
}} else {{
  if (-not (Test-Path "$Root\\Sysmon64.exe")) {{
    Write-Host "      Downloading Sysmon64.exe from Microsoft Sysinternals"
    Invoke-WebRequest "https://live.sysinternals.com/Sysmon64.exe" -OutFile "$Root\\Sysmon64.exe"
  }}
  & "$Root\\Sysmon64.exe" -accepteula -i "$Root\\sysmon.xml" | Out-Null
}}

Write-Host "[5/5] Starting agent (Ctrl+C to stop; re-run with:  $Root\\run-agent.ps1)"
@"
Set-Location "$Root"
& "$Root\\.venv\\Scripts\\noirlycan-agent.exe" run --config "$Root\\noirlycan-agent.toml"
"@ | Set-Content -Encoding UTF8 "$Root\\run-agent.ps1"
& "$Root\\run-agent.ps1"
"""
