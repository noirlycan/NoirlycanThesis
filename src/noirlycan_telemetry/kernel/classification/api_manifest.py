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
            "RtlCopyMemory",
            "CopyMemory",
        ),
    ),
    # Read APIs are observation-only — paper §3 does not classify ReadProcessMemory /
    # NtReadVirtualMemory as a write primitive. Kept as a separate class so hooks
    # can still emit them, but they are excluded from the 2-of-3 primitive count.
    ApiClass(
        "remote_read",
        "observation",
        (
            "ReadProcessMemory",
            "NtReadVirtualMemory",
            "ZwReadVirtualMemory",
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
    ApiClass(
        "context_read",
        "context_read",
        (
            "GetThreadContext",
            "NtGetContextThread",
        ),
    ),
)

# iRed.team injection labs — https://www.ired.team/offensive-security/code-injection-process-injection
IRED_TEAM_API_CLASSES: tuple[ApiClass, ...] = (
    ApiClass(
        "fiber_execute",
        "execute",
        (
            "ConvertThreadToFiber",
            "CreateFiber",
            "SwitchToFiber",
        ),
    ),
    ApiClass(
        "threadpool_execute",
        "execute",
        (
            "CreateThreadpoolWait",
            "SetThreadpoolWait",
            "SubmitThreadpoolWait",
            "CreateThreadpoolWork",
            "SubmitThreadpoolWork",
        ),
    ),
    ApiClass(
        "alertable_execute",
        "execute",
        (
            "NtTestAlert",
        ),
    ),
    ApiClass(
        "window_execute",
        "execute",
        (
            "SendMessageA",
            "SendMessageW",
            "SendMessageCallbackA",
            "SendMessageCallbackW",
        ),
    ),
    ApiClass(
        "window_memory",
        "write",
        (
            "SetWindowLongPtrA",
            "SetWindowLongPtrW",
            "SetWindowLongA",
            "SetWindowLongW",
        ),
    ),
    ApiClass(
        "txf_spawn",
        "process",
        (
            "NtCreateTransaction",
            "NtCommitTransaction",
            "NtRollbackTransaction",
            "RtlCreateProcessReflection",
        ),
    ),
    ApiClass(
        "local_protect",
        "allocate",
        (
            "VirtualProtect",
        ),
    ),
    # ---- Advanced techniques (Process Ghosting, PROPagate, EnumXxx callback,
    # InstrumentationCallback, PoolParty). These extend coverage beyond the
    # ASIA CCS 2025 paper but reuse the same allocate/write/execute primitive
    # framework.
    ApiClass(
        "ghosting_disposition",
        "observation",
        (
            "NtSetInformationFile",
        ),
    ),
    ApiClass(
        "instrumentation_callback",
        "execute",
        (
            "NtSetInformationProcess",
        ),
    ),
    ApiClass(
        "propagate_write",
        "write",
        (
            "SetPropA",
            "SetPropW",
        ),
    ),
    ApiClass(
        "propagate_trigger",
        "execute",
        (
            "SendNotifyMessageA",
            "SendNotifyMessageW",
        ),
    ),
    ApiClass(
        "enum_callback_execute",
        "execute",
        (
            "EnumSystemLocalesA",
            "EnumSystemLocalesW",
            "EnumDateFormatsA",
            "EnumDateFormatsW",
            "EnumUILanguagesW",
            "EnumResourceTypesA",
            "EnumResourceTypesW",
            "EnumWindows",
            "EnumChildWindows",
            "EnumDesktopWindows",
            "EnumThreadWindows",
        ),
    ),
    ApiClass(
        "poolparty_execute",
        "execute",
        (
            "TpAllocWork",
            "TpPostWork",
            "RtlQueueWorkItem",
            "NtSetInformationWorkerFactory",
        ),
    ),
)

PAPER_INJECTION_APIS: frozenset[str] = frozenset(
    api for api_class in PAPER_API_CLASSES for api in api_class.apis
)

IRED_TEAM_APIS: frozenset[str] = frozenset(
    api for api_class in IRED_TEAM_API_CLASSES for api in api_class.apis
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
        "ZwReadVirtualMemory",
        "ZwGetContextThread",
        "ZwUnmapViewOfSection",
        "ZwQueueApcThread",
        "ZwQueueApcThreadEx",
        "ZwOpenProcess",
        "ZwOpenThread",
        "ZwSuspendThread",
        "ZwAlertResumeThread",
    }
)

REPO_REQUIRED_APIS: frozenset[str] = PAPER_INJECTION_APIS | IRED_TEAM_APIS | REPO_EXTRA_APIS
