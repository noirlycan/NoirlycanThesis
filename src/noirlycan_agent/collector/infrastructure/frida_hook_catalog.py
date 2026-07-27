"""Single source of truth for Frida hook installation targets."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from noirlycan_core.kernel.classification.api_manifest import (
    IRED_TEAM_API_CLASSES,
    PAPER_API_CLASSES,
    REPO_REQUIRED_APIS,
)
from noirlycan_core.runtime.agent_policy import AgentPolicy

Tier = Literal["support", "primitive"]
Bucket = Literal["alloc", "write", "exec"]

_PRIMITIVE_BUCKETS = frozenset({"allocate", "write", "execute"})
_SUPPORT_PRIMITIVES = frozenset({"process", "access", "resolve", "context_read", "observation"})

_EMPTY_POLICY: dict[str, Any] = {"version": 0, "alloc": [], "write": [], "exec": []}

# Nt/Rtl/Ldr exports resolved dynamically via GetProcAddress / LdrGetProcedureAddress.
DEFAULT_DYNAMIC_NT: frozenset[str] = frozenset(
    {
        "NtAllocateVirtualMemory",
        "NtCreateSection",
        "NtMapViewOfSection",
        "NtWriteVirtualMemory",
        "NtReadVirtualMemory",
        "NtProtectVirtualMemory",
        "NtCreateThread",
        "NtCreateThreadEx",
        "NtSetContextThread",
        "NtGetContextThread",
        "NtResumeThread",
        "NtAlertResumeThread",
        "NtSuspendThread",
        "NtSuspendProcess",
        "NtResumeProcess",
        "NtQueueApcThread",
        "NtQueueApcThreadEx",
        "NtUnmapViewOfSection",
        "NtCreateProcess",
        "NtCreateProcessEx",
        "NtCreateUserProcess",
        "NtOpenProcess",
        "NtOpenThread",
        "NtAddAtom",
        "NtTestAlert",
        "RtlCreateProcessReflection",
        "RtlCreateUserThread",
        "RtlCreateUserProcess",
        "LdrLoadDll",
    }
)

# Custom handler table entries from windows_injection_hooks.js API_HANDLERS plus
# additional Nt/Rtl/Ldr hooks installed with bespoke interceptors.
NT_HANDLER_EXPORTS: frozenset[str] = frozenset(
    {
        "NtAllocateVirtualMemory",
        "NtCreateSection",
        "NtMapViewOfSection",
        "NtWriteVirtualMemory",
        "NtProtectVirtualMemory",
        "NtCreateThreadEx",
        "RtlCreateUserThread",
        "NtQueueApcThread",
        "NtQueueApcThreadEx",
        "NtSetContextThread",
        "NtGetContextThread",
        "NtResumeThread",
        "NtAlertResumeThread",
        "NtUnmapViewOfSection",
        "NtReadVirtualMemory",
        "NtCreateThread",
        "NtSuspendThread",
        "NtSuspendProcess",
        "NtResumeProcess",
        "NtOpenProcess",
        "NtOpenThread",
        "NtAddAtom",
        "NtTestAlert",
        "NtSetInformationFile",
        "NtSetInformationProcess",
        "NtCreateTransaction",
        "NtCommitTransaction",
        "NtRollbackTransaction",
        "RtlCreateProcessReflection",
        "TpAllocWork",
        "TpPostWork",
        "RtlQueueWorkItem",
        "NtSetInformationWorkerFactory",
        "LdrLoadDll",
        "RtlCreateUserProcess",
        "NtCreateProcess",
        "NtCreateProcessEx",
        "NtCreateUserProcess",
    }
)

_KERNEL32_APIS: frozenset[str] = frozenset(
    {
        "ConvertThreadToFiber",
        "CopyMemory",
        "CreateFiber",
        "CreateFileMappingA",
        "CreateFileMappingW",
        "CreateProcessA",
        "CreateProcessW",
        "CreateRemoteThread",
        "CreateRemoteThreadEx",
        "CreateThread",
        "CreateThreadpoolWait",
        "CreateThreadpoolWork",
        "EnumDateFormatsA",
        "EnumDateFormatsW",
        "EnumResourceTypesA",
        "EnumResourceTypesW",
        "EnumSystemLocalesA",
        "EnumSystemLocalesW",
        "EnumUILanguagesW",
        "GetProcAddress",
        "GetThreadContext",
        "GlobalAddAtomA",
        "GlobalAddAtomW",
        "LoadLibraryA",
        "LoadLibraryExA",
        "LoadLibraryExW",
        "LoadLibraryW",
        "MapViewOfFile",
        "MapViewOfFileEx",
        "OpenProcess",
        "OpenThread",
        "QueueUserAPC",
        "ReadProcessMemory",
        "ResumeThread",
        "SetThreadContext",
        "SetThreadpoolWait",
        "SubmitThreadpoolWait",
        "SubmitThreadpoolWork",
        "SuspendThread",
        "SwitchToFiber",
        "VirtualAlloc",
        "VirtualAllocEx",
        "VirtualAllocExNuma",
        "VirtualProtect",
        "VirtualProtectEx",
        "WinExec",
        "WriteProcessMemory",
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "GetTickCount",
        "GetTickCount64",
        "QueryPerformanceCounter",
    }
)

_NTDLL_APIS: frozenset[str] = frozenset(
    {
        "LdrGetProcedureAddress",
        "LdrLoadDll",
        "NtAddAtom",
        "NtAlertResumeThread",
        "NtAllocateVirtualMemory",
        "NtCommitTransaction",
        "NtCreateProcess",
        "NtCreateProcessEx",
        "NtCreateSection",
        "NtCreateThread",
        "NtCreateThreadEx",
        "NtCreateTransaction",
        "NtCreateUserProcess",
        "NtGetContextThread",
        "NtMapViewOfSection",
        "NtOpenProcess",
        "NtOpenThread",
        "NtProtectVirtualMemory",
        "NtQueueApcThread",
        "NtQueueApcThreadEx",
        "NtQueryInformationProcess",
        "NtReadVirtualMemory",
        "NtResumeProcess",
        "NtResumeThread",
        "NtRollbackTransaction",
        "NtSetContextThread",
        "NtSetInformationFile",
        "NtSetInformationProcess",
        "NtSetInformationWorkerFactory",
        "NtSuspendProcess",
        "NtSuspendThread",
        "NtTestAlert",
        "NtUnmapViewOfSection",
        "NtWriteVirtualMemory",
        "RtlCopyMemory",
        "RtlCreateProcessReflection",
        "RtlCreateUserProcess",
        "RtlCreateUserThread",
        "RtlMoveMemory",
        "RtlQueueWorkItem",
        "TpAllocWork",
        "TpPostWork",
        "ZwAlertResumeThread",
        "ZwAllocateVirtualMemory",
        "ZwCreateSection",
        "ZwCreateThreadEx",
        "ZwGetContextThread",
        "ZwMapViewOfSection",
        "ZwOpenProcess",
        "ZwOpenThread",
        "ZwProtectVirtualMemory",
        "ZwQueueApcThread",
        "ZwQueueApcThreadEx",
        "ZwReadVirtualMemory",
        "ZwResumeThread",
        "ZwSetContextThread",
        "ZwSuspendThread",
        "ZwUnmapViewOfSection",
        "ZwWriteVirtualMemory",
    }
)

_USER32_APIS: frozenset[str] = frozenset(
    {
        "EnumChildWindows",
        "EnumDesktopWindows",
        "EnumThreadWindows",
        "EnumWindows",
        "SendMessageA",
        "SendMessageCallbackA",
        "SendMessageCallbackW",
        "SendMessageW",
        "SendNotifyMessageA",
        "SendNotifyMessageW",
        "SetPropA",
        "SetPropW",
        "SetWindowLongA",
        "SetWindowLongPtrA",
        "SetWindowLongPtrW",
        "SetWindowLongW",
        "SetWindowsHookExA",
        "SetWindowsHookExW",
    }
)

_SHELL32_APIS: frozenset[str] = frozenset(
    {
        "ShellExecuteA",
        "ShellExecuteExA",
        "ShellExecuteExW",
        "ShellExecuteW",
    }
)

_ADVAPI32_APIS: frozenset[str] = frozenset(
    {
        "CreateProcessWithTokenW",
        "RegOpenKeyExW",
    }
)


def _module_for_export(export: str) -> str:
    if export in _KERNEL32_APIS:
        return "kernel32"
    if export in _NTDLL_APIS:
        return "ntdll"
    if export in _USER32_APIS:
        return "user32"
    if export in _SHELL32_APIS:
        return "shell32"
    if export in _ADVAPI32_APIS:
        return "advapi32"
    if export == "memcpy":
        return "msvcrt"
    if export.startswith(("Nt", "Zw", "Rtl", "Ldr", "Tp")):
        return "ntdll"
    raise KeyError(f"No module mapping for export {export!r}")


API_MODULES: dict[str, str] = {}
for _export in (
    set(REPO_REQUIRED_APIS)
    | {
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "GetTickCount",
        "GetTickCount64",
        "QueryPerformanceCounter",
        "NtQueryInformationProcess",
        "RegOpenKeyExW",
    }
):
    API_MODULES[_export] = _module_for_export(_export)


@dataclass(frozen=True)
class HookSpec:
    module: str
    export: str
    tier: Tier
    bucket: Bucket | None


def _tier_for_class(primitive: str) -> tuple[Tier, Bucket | None]:
    if primitive in _PRIMITIVE_BUCKETS:
        bucket: Bucket
        if primitive == "allocate":
            bucket = "alloc"
        elif primitive == "write":
            bucket = "write"
        else:
            bucket = "exec"
        return "primitive", bucket
    if primitive in _SUPPORT_PRIMITIVES:
        return "support", None
    raise ValueError(f"Unknown api class primitive {primitive!r}")


def _hooks_from_classes(
    classes: tuple[Any, ...],
) -> tuple[list[HookSpec], dict[str, tuple[Tier, Bucket | None]]]:
    specs: list[HookSpec] = []
    export_tier: dict[str, tuple[Tier, Bucket | None]] = {}
    for api_class in classes:
        tier, bucket = _tier_for_class(api_class.primitive)
        for export in api_class.apis:
            export_tier[export] = (tier, bucket)
            specs.append(
                HookSpec(
                    module=API_MODULES[export],
                    export=export,
                    tier=tier,
                    bucket=bucket,
                )
            )
    return specs, export_tier


_PAPER_HOOKS, _PAPER_EXPORT_TIER = _hooks_from_classes(PAPER_API_CLASSES)
_IRED_HOOKS, _IRED_EXPORT_TIER = _hooks_from_classes(IRED_TEAM_API_CLASSES)
_EXPORT_TIER: dict[str, tuple[Tier, Bucket | None]] = {
    **_PAPER_EXPORT_TIER,
    **_IRED_EXPORT_TIER,
}

ALL_HOOKS: list[HookSpec] = _PAPER_HOOKS + _IRED_HOOKS

EXTRA_HOOKS: list[HookSpec] = [
    HookSpec(module="kernel32", export="VirtualAlloc", tier="primitive", bucket="alloc"),
    HookSpec(module="ntdll", export="RtlMoveMemory", tier="primitive", bucket="write"),
    HookSpec(module="msvcrt", export="memcpy", tier="primitive", bucket="write"),
    HookSpec(module="ucrtbase", export="memcpy", tier="primitive", bucket="write"),
    HookSpec(module="ucrtbased", export="memcpy", tier="primitive", bucket="write"),
    HookSpec(module="kernel32", export="IsDebuggerPresent", tier="support", bucket=None),
    HookSpec(
        module="kernel32",
        export="CheckRemoteDebuggerPresent",
        tier="support",
        bucket=None,
    ),
    HookSpec(module="kernel32", export="GetTickCount", tier="support", bucket=None),
    HookSpec(module="kernel32", export="GetTickCount64", tier="support", bucket=None),
    HookSpec(
        module="kernel32",
        export="QueryPerformanceCounter",
        tier="support",
        bucket=None,
    ),
    HookSpec(
        module="ntdll",
        export="NtQueryInformationProcess",
        tier="support",
        bucket=None,
    ),
    HookSpec(module="advapi32", export="RegOpenKeyExW", tier="support", bucket=None),
    HookSpec(module="ws2_32", export="connect", tier="support", bucket=None),
    HookSpec(module="ws2_32", export="WSAConnect", tier="support", bucket=None),
]

_ZW_ALIAS_HOOKS: list[HookSpec] = []
for _export in sorted(REPO_REQUIRED_APIS):
    if not _export.startswith("Zw"):
        continue
    _nt = "Nt" + _export[2:]
    _tier_info = _EXPORT_TIER.get(_nt)
    if _tier_info is None:
        continue
    _tier, _bucket = _tier_info
    _ZW_ALIAS_HOOKS.append(
        HookSpec(
            module=API_MODULES[_export],
            export=_export,
            tier=_tier,
            bucket=_bucket,
        )
    )


def _catalog_hooks() -> list[HookSpec]:
    seen: set[tuple[str, str]] = set()
    merged: list[HookSpec] = []
    for spec in (*ALL_HOOKS, *EXTRA_HOOKS, *_ZW_ALIAS_HOOKS):
        key = (spec.module, spec.export)
        if key in seen:
            continue
        seen.add(key)
        merged.append(spec)
    return merged


def _normalize_nt(name: str) -> str:
    if name.startswith("Zw"):
        return "Nt" + name[2:]
    return name


def _expand_nt_zw(names: list[str]) -> set[str]:
    expanded: set[str] = set()
    for name in names:
        expanded.add(name)
        if name.startswith("Nt"):
            expanded.add("Zw" + name[2:])
        elif name.startswith("Zw"):
            expanded.add("Nt" + name[2:])
    return expanded


def _is_full_lab(policy: AgentPolicy | None) -> bool:
    if policy is None:
        return True
    return not (policy.alloc or policy.write or policy.exec)


def _policy_payload(policy: AgentPolicy | None) -> dict[str, Any]:
    if policy is None:
        return dict(_EMPTY_POLICY)
    return policy.frida_hook_payload()


def _policy_enabled_exports(policy: AgentPolicy) -> set[str]:
    return _expand_nt_zw(list(policy.alloc) + list(policy.write) + list(policy.exec))


def _hook_enabled(spec: HookSpec, policy: AgentPolicy | None) -> bool:
    if _is_full_lab(policy):
        return True
    if spec.tier == "support":
        return True
    assert policy is not None
    enabled = _policy_enabled_exports(policy)
    normalized = _normalize_nt(spec.export)
    return spec.export in enabled or normalized in enabled


def _dynamic_nt_for_policy(policy: AgentPolicy | None) -> list[str]:
    if _is_full_lab(policy):
        return sorted(DEFAULT_DYNAMIC_NT)
    assert policy is not None
    enabled = _policy_enabled_exports(policy)
    return sorted(
        name
        for name in DEFAULT_DYNAMIC_NT
        if name in enabled or _normalize_nt(name) in enabled
    )


def build_runtime_config(policy: AgentPolicy | None) -> dict[str, Any]:
    """Build the JSON payload consumed by the Frida hook runtime."""
    hooks = [
        {"module": spec.module, "export": spec.export}
        for spec in _catalog_hooks()
        if _hook_enabled(spec, policy)
    ]
    return {
        "version": policy.version if policy is not None else 0,
        "policy": _policy_payload(policy),
        "hooks": hooks,
        "dynamic_nt": _dynamic_nt_for_policy(policy),
    }


def hook_exports_in_config(config: dict[str, Any]) -> set[str]:
    """Return export names from a runtime config (for tests)."""
    hooks = config.get("hooks")
    if not isinstance(hooks, list):
        return set()
    exports: set[str] = set()
    for item in hooks:
        if isinstance(item, dict):
            export = item.get("export")
            if isinstance(export, str):
                exports.add(export)
    return exports
