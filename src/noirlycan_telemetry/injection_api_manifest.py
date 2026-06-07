"""API equivalence classes from ASIA CCS 2025 (Sap4Sec/process-injection).

Reference: Di Pietro, D'Elia, Querzoni — "Can You Run My Code?"
https://doi.org/10.1145/3708821.3736206
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ApiClass:
    name: str
    primitive: str
    apis: tuple[str, ...]


# Three operational primitives from Klein et al. / ASIA CCS §3.
PAPER_API_CLASSES: tuple[ApiClass, ...] = (
    ApiClass(
        "allocate",
        "allocate",
        (
            "VirtualAllocEx",
            "VirtualAllocExNuma",
            "NtAllocateVirtualMemory",
            "VirtualProtectEx",
            "NtProtectVirtualMemory",
            "NtCreateSection",
            "CreateFileMappingA",
            "CreateFileMappingW",
            "MapViewOfFile",
            "MapViewOfFileEx",
        ),
    ),
    ApiClass(
        "write",
        "write",
        (
            "WriteProcessMemory",
            "NtWriteVirtualMemory",
            "NtMapViewOfSection",
            "NtUnmapViewOfSection",
            "ReadProcessMemory",
            "NtReadVirtualMemory",
            "RtlCopyMemory",
            "CopyMemory",
        ),
    ),
    ApiClass(
        "execute",
        "execute",
        (
            "CreateRemoteThread",
            "CreateRemoteThreadEx",
            "NtCreateThreadEx",
            "RtlCreateUserThread",
            "QueueUserAPC",
            "NtQueueApcThread",
            "NtQueueApcThreadEx",
            "SetThreadContext",
            "NtSetContextThread",
            "GetThreadContext",
            "NtGetContextThread",
            "ResumeThread",
            "NtResumeThread",
            "NtAlertResumeThread",
            "SuspendThread",
            "NtSuspendThread",
            "CreateThread",
            "NtCreateThread",
            "NtSuspendProcess",
            "NtResumeProcess",
            "LoadLibraryA",
            "LoadLibraryW",
            "LoadLibraryExA",
            "LoadLibraryExW",
            "LdrLoadDll",
            "SetWindowsHookExA",
            "SetWindowsHookExW",
            "GlobalAddAtomA",
            "GlobalAddAtomW",
            "NtAddAtom",
        ),
    ),
    ApiClass(
        "process_spawn",
        "process",
        (
            "CreateProcessA",
            "CreateProcessW",
            "NtCreateProcess",
            "NtCreateProcessEx",
            "NtCreateUserProcess",
            "RtlCreateUserProcess",
            "CreateProcessWithTokenW",
            "WinExec",
            "ShellExecuteA",
            "ShellExecuteW",
            "ShellExecuteExA",
            "ShellExecuteExW",
        ),
    ),
    ApiClass(
        "process_access",
        "access",
        (
            "OpenProcess",
            "NtOpenProcess",
            "OpenThread",
            "NtOpenThread",
        ),
    ),
    ApiClass(
        "dynamic_resolve",
        "resolve",
        (
            "GetProcAddress",
            "LdrGetProcedureAddress",
        ),
    ),
)

PAPER_INJECTION_APIS: frozenset[str] = frozenset(
    api for api_class in PAPER_API_CLASSES for api in api_class.apis
)

# Extra hooks beyond the paper implementation (Frida lab extensions).
REPO_EXTRA_APIS: frozenset[str] = frozenset(
    {
        "memcpy",
        "RtlMoveMemory",
        "VirtualAlloc",
        "ZwAllocateVirtualMemory",
        "ZwCreateSection",
        "ZwMapViewOfSection",
        "ZwWriteVirtualMemory",
        "ZwProtectVirtualMemory",
        "ZwCreateThreadEx",
        "ZwSetContextThread",
        "ZwResumeThread",
    }
)

REPO_REQUIRED_APIS: frozenset[str] = PAPER_INJECTION_APIS | REPO_EXTRA_APIS
