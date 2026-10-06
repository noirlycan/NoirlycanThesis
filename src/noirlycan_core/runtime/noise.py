"""Files Windows creates on its own that are never a dropped sample."""

from __future__ import annotations

from pathlib import PureWindowsPath

# PowerShell writes and deletes __PSScriptPolicyTest_*.ps1 on every start;
# Frida extracts its agent DLL under %TEMP%\frida-*.
_NOISE_NAME_PREFIXES = ("__psscriptpolicytest_",)
_NOISE_PATH_MARKERS = ("\\temp\\frida-",)


def is_noise_path(path: str) -> bool:
    lower = str(path).lower()
    name = PureWindowsPath(lower).name
    return name.startswith(_NOISE_NAME_PREFIXES) or any(marker in lower for marker in _NOISE_PATH_MARKERS)
