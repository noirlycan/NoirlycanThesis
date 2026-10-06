from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

from noirlycan_core.detection.api_classes import PAPER_API_CLASSES


def _paper_apis(class_name: str, *, fallback: tuple[str, ...]) -> list[str]:
    for item in PAPER_API_CLASSES:
        if item.name == class_name:
            return list(item.apis)
    return list(fallback)


DEFAULT_ALLOC = _paper_apis(
    "allocate",
    fallback=("VirtualAllocEx", "VirtualAllocExNuma", "NtAllocateVirtualMemory", "NtCreateSection"),
)
DEFAULT_WRITE = _paper_apis(
    "write",
    fallback=("WriteProcessMemory", "NtWriteVirtualMemory", "NtMapViewOfSection"),
)
DEFAULT_EXEC = _paper_apis(
    "execute",
    fallback=(
        "CreateRemoteThread",
        "NtCreateThreadEx",
        "QueueUserAPC",
        "SetThreadContext",
        "ResumeThread",
    ),
)

TECHNIQUE_CHOICES = [
    "Process Hollowing (no-unmap)",
    "Process Hollowing",
    "PE Injection",
    "Shellcode Injection",
    "DLL Injection from Disk",
    "APC Injection",
    "Thread Execution Hijacking",
    "Early Bird",
    "Hook Injection",
    "Custom",
]

DEFAULT_SEVERITY_ROWS = [
    {"cond": "3/3 primitives + cross-process", "s": "CRITICAL"},
    {"cond": "2/3 primitives + section mapping", "s": "HIGH"},
    {"cond": "2/3 primitives", "s": "MEDIUM"},
    {"cond": "single primitive / context", "s": "LOW"},
]

DEFAULT_SCORE_WEIGHTS = [
    {"label": "cross_process", "pts": 30},
    {"label": "section_mapping", "pts": 25},
    {"label": "primitive-each", "pts": 15},
    {"label": "suspended-spawn", "pts": 20},
    {"label": "unsigned-PE", "pts": 15},
    {"label": "beacon", "pts": 20},
]

# Named primitive sequences — chain name is shown on matched findings; tech is the technique label.
DEFAULT_CHAINS: list[dict[str, Any]] = [
    {
        "name": "Section-mapping loader",
        "tech": "Process Hollowing (no-unmap)",
        "steps": [
            {"op": "alloc", "api": "NtCreateSection"},
            {"op": "write", "api": "NtMapViewOfSection"},
            {"op": "exec", "api": "SetThreadContext"},
        ],
    },
    {
        "name": "Classic hollowing",
        "tech": "Process Hollowing",
        "steps": [
            {"op": "write", "api": "NtMapViewOfSection"},
            {"op": "exec", "api": "ResumeThread"},
        ],
    },
    {
        "name": "Shellcode remote-thread",
        "tech": "Shellcode Injection",
        "steps": [
            {"op": "alloc", "api": "VirtualAllocEx"},
            {"op": "write", "api": "WriteProcessMemory"},
            {"op": "exec", "api": "CreateRemoteThread"},
        ],
    },
    {
        "name": "PE remote-thread",
        "tech": "PE Injection",
        "steps": [
            {"op": "alloc", "api": "VirtualAllocEx"},
            {"op": "write", "api": "WriteProcessMemory"},
            {"op": "exec", "api": "CreateRemoteThread"},
        ],
    },
    {
        "name": "Nt shellcode thread",
        "tech": "Shellcode Injection",
        "steps": [
            {"op": "alloc", "api": "NtAllocateVirtualMemory"},
            {"op": "write", "api": "NtWriteVirtualMemory"},
            {"op": "exec", "api": "NtCreateThreadEx"},
        ],
    },
    {
        "name": "APC queue inject",
        "tech": "APC Injection",
        "steps": [
            {"op": "alloc", "api": "VirtualAllocEx"},
            {"op": "write", "api": "WriteProcessMemory"},
            {"op": "exec", "api": "QueueUserAPC"},
        ],
    },
    {
        "name": "Early Bird APC",
        "tech": "Early Bird",
        "steps": [
            {"op": "alloc", "api": "NtAllocateVirtualMemory"},
            {"op": "write", "api": "NtWriteVirtualMemory"},
            {"op": "exec", "api": "QueueUserAPC"},
        ],
    },
    {
        "name": "DLL path inject",
        "tech": "DLL Injection from Disk",
        "steps": [
            {"op": "alloc", "api": "VirtualAllocEx"},
            {"op": "write", "api": "WriteProcessMemory"},
            {"op": "exec", "api": "CreateRemoteThread"},
        ],
    },
    {
        "name": "Thread context hijack",
        "tech": "Thread Execution Hijacking",
        "steps": [
            {"op": "write", "api": "WriteProcessMemory"},
            {"op": "exec", "api": "SetThreadContext"},
            {"op": "exec", "api": "ResumeThread"},
        ],
    },
]


@dataclass
class Ruleset:
    alloc: list[str] = field(default_factory=lambda: list(DEFAULT_ALLOC))
    write: list[str] = field(default_factory=lambda: list(DEFAULT_WRITE))
    exec: list[str] = field(default_factory=lambda: list(DEFAULT_EXEC))
    min_primitives: int = 2
    congruence: bool = True
    temporal: bool = True
    capture: int = 5
    net_watch: int = 5
    auto_attach: bool = True
    beacon: bool = True
    folders: list[str] = field(default_factory=lambda: ["D:\\", "C:\\Users\\Public\\Downloads"])
    allowlist: list[str] = field(
        default_factory=lambda: ["10.0.0.0/8", "192.168.0.0/16", "127.0.0.1/32"]
    )
    sev: list[dict[str, str]] = field(default_factory=lambda: list(DEFAULT_SEVERITY_ROWS))
    chains: list[dict[str, Any]] = field(default_factory=lambda: list(DEFAULT_CHAINS))
    score: dict[str, Any] = field(
        default_factory=lambda: {
            "weights": list(DEFAULT_SCORE_WEIGHTS),
            "crit": 80,
            "high": 55,
            "med": 30,
        }
    )
    auto_kill: bool = False
    auto_kill_min_severity: str = "CRITICAL"

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["min_primitives"] = max(2, min(3, int(self.min_primitives)))
        return payload

    @classmethod
    def from_dict(cls, raw: object) -> Ruleset:
        if not isinstance(raw, dict):
            return cls()
        min_primitives = int(raw.get("min_primitives", 2))
        min_primitives = max(2, min(3, min_primitives))
        score_raw = raw.get("score") if isinstance(raw.get("score"), dict) else {}
        return cls(
            alloc=_str_list(raw.get("alloc"), DEFAULT_ALLOC),
            write=_str_list(raw.get("write"), DEFAULT_WRITE),
            exec=_str_list(raw.get("exec"), DEFAULT_EXEC),
            min_primitives=min_primitives,
            congruence=bool(raw.get("congruence", True)),
            temporal=bool(raw.get("temporal", True)),
            capture=max(1, min(8, int(raw.get("capture", 5)))),
            net_watch=max(1, min(15, int(raw.get("net_watch", 5)))),
            auto_attach=bool(raw.get("auto_attach", True)),
            beacon=bool(raw.get("beacon", True)),
            folders=_str_list(raw.get("folders"), ["D:\\", "C:\\Users\\Public\\Downloads"]),
            allowlist=_str_list(
                raw.get("allowlist"),
                ["10.0.0.0/8", "192.168.0.0/16", "127.0.0.1/32"],
            ),
            sev=_dict_list(raw.get("sev"), DEFAULT_SEVERITY_ROWS),
            chains=_dict_list(raw.get("chains"), DEFAULT_CHAINS),
            score={
                "weights": _dict_list(score_raw.get("weights"), DEFAULT_SCORE_WEIGHTS),
                "crit": int(score_raw.get("crit", 80)),
                "high": int(score_raw.get("high", 55)),
                "med": int(score_raw.get("med", 30)),
            },
            auto_kill=bool(raw.get("auto_kill", False)),
            auto_kill_min_severity=str(raw.get("auto_kill_min_severity") or "CRITICAL").upper(),
        )


def _str_list(value: object, fallback: list[str]) -> list[str]:
    if not isinstance(value, list):
        return list(fallback)
    return [str(item).strip() for item in value if str(item).strip()]


def _dict_list(value: object, fallback: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return list(fallback)
    rows: list[dict[str, Any]] = []
    for item in value:
        if isinstance(item, dict):
            rows.append(dict(item))
    return rows or list(fallback)


def ruleset_to_toml(ruleset: Ruleset, *, host: str, port: int, token: str) -> str:
    payload = ruleset.to_dict()
    lines = [
        "[server]",
        f'endpoint = "{host}:{port}"',
        f'token = "{token}"',
        "",
        "[capture]",
        f"window_minutes = {payload['capture']}",
        f"network_watch_minutes = {payload['net_watch']}",
        f"auto_attach = {'true' if payload['auto_attach'] else 'false'}",
        f"min_primitives = {payload['min_primitives']}",
        f"auto_kill = {'true' if payload['auto_kill'] else 'false'}",
        f'auto_kill_min_severity = "{payload["auto_kill_min_severity"]}"',
        "",
        "[watch]",
        "folders = [",
    ]
    for folder in payload["folders"]:
        lines.append(f'  "{folder}",')
    lines.extend(
        [
            "]",
            "",
            "[network]",
            f"flag_non_private = {'true' if payload['beacon'] else 'false'}",
            "allowlist = [",
        ]
    )
    for cidr in payload["allowlist"]:
        lines.append(f'  "{cidr}",')
    lines.append("]")
    return "\n".join(lines) + "\n"


def ruleset_json(ruleset: Ruleset) -> str:
    return json.dumps(ruleset.to_dict(), indent=2, ensure_ascii=False)
