"""iRed.team process injection taxonomy mapped to Noirlycan detection coverage.

Reference: https://www.ired.team/offensive-security/code-injection-process-injection
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class CoverageLevel(str, Enum):
    FULL = "full"  # hooks + classifier rule
    PARTIAL = "partial"  # hooks or heuristic only
    PLANNED = "planned"  # documented, not implemented
    NONE = "none"


@dataclass(frozen=True)
class IredTechnique:
    slug: str
    title: str
    ired_url: str
    key_apis: tuple[str, ...]
    noirlycan_technique: str | None
    coverage: CoverageLevel
    notes: str


# Curated from iRed.team "Code & Process Injection" index and linked labs.
IRED_TECHNIQUES: tuple[IredTechnique, ...] = (
    IredTechnique(
        "classic_shellcode",
        "CreateRemoteThread Shellcode Injection",
        "https://www.ired.team/offensive-security/code-injection-process-injection",
        ("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"),
        "shellcode_injection",
        CoverageLevel.FULL,
        "Paper primitive chain + dedicated classifier rule.",
    ),
    IredTechnique(
        "dll_injection",
        "DLL Injection",
        "https://www.ired.team/offensive-security/code-injection-process-injection",
        ("LoadLibraryA", "LoadLibraryW", "LdrLoadDll", "CreateRemoteThread"),
        "dll_injection",
        CoverageLevel.FULL,
        "Remote LoadLibrary / LdrLoadDll primitives.",
    ),
    IredTechnique(
        "reflective_dll",
        "Reflective DLL Injection",
        "https://www.ired.team/offensive-security/code-injection-process-injection",
        ("VirtualAlloc", "memcpy", "RtlMoveMemory", "NtCreateThreadEx"),
        "reflective_dll_injection",
        CoverageLevel.PARTIAL,
        "Heuristic: remote write + execute without DLL path; no PE parser in memory.",
    ),
    IredTechnique(
        "process_hollowing",
        "Process Hollowing and PE Relocations",
        "https://www.ired.team/offensive-security/code-injection-process-injection/process-hollowing-and-pe-image-relocations",
        ("CreateProcess", "NtUnmapViewOfSection", "NtMapViewOfSection", "SetThreadContext", "ResumeThread"),
        "process_hollowing_section",
        CoverageLevel.FULL,
        "Suspended spawn + section/unmap + execution transfer.",
    ),
    IredTechnique(
        "section_mapping",
        "NtCreateSection + NtMapViewOfSection Code Injection",
        "https://www.ired.team/offensive-security/code-injection-process-injection/ntcreatesection-+-ntmapviewofsection-code-injection",
        ("NtCreateSection", "NtMapViewOfSection", "RtlCreateUserThread"),
        "section_mapping_injection",
        CoverageLevel.FULL,
        "Core paper + iRed lab; staging vs confirmed execution split.",
    ),
    IredTechnique(
        "apc_queue",
        "APC Queue Code Injection",
        "https://www.ired.team/offensive-security/code-injection-process-injection/apc-queue-code-injection",
        ("VirtualAllocEx", "WriteProcessMemory", "QueueUserAPC", "OpenThread"),
        "apc_injection",
        CoverageLevel.FULL,
        "QueueUserAPC / NtQueueApcThread counted as execution transfer.",
    ),
    IredTechnique(
        "early_bird_apc",
        "Early Bird APC Queue Code Injection",
        "https://www.ired.team/offensive-security/code-injection-process-injection",
        ("NtQueueApcThreadEx", "CreateProcess"),
        "early_bird_apc_injection",
        CoverageLevel.FULL,
        "NtQueueApcThreadEx + CREATE_SUSPENDED victim.",
    ),
    IredTechnique(
        "thread_hijack",
        "Injecting to Remote Process via Thread Hijacking",
        "https://www.ired.team/offensive-security/code-injection-process-injection",
        ("SuspendThread", "GetThreadContext", "SetThreadContext", "ResumeThread"),
        "thread_hijack",
        CoverageLevel.FULL,
        "Context read separated from SetThreadContext execute transfer.",
    ),
    IredTechnique(
        "setwindowshookex",
        "SetWindowHookEx Code Injection",
        "https://www.ired.team/offensive-security/code-injection-process-injection",
        ("SetWindowsHookExA", "SetWindowsHookExW"),
        "hook_injection",
        CoverageLevel.FULL,
        "user32 hook installation primitive.",
    ),
    IredTechnique(
        "module_stomping",
        "Module Stomping for Shellcode Injection",
        "https://www.ired.team/offensive-security/code-injection-process-injection",
        ("NtUnmapViewOfSection", "NtWriteVirtualMemory", "NtCreateThreadEx"),
        "module_stomping",
        CoverageLevel.PARTIAL,
        "Unmap + write heuristic; no module name resolution.",
    ),
    IredTechnique(
        "pe_injection",
        "PE Injection: Executing PEs inside Remote Processes",
        "https://www.ired.team/offensive-security/code-injection-process-injection",
        ("WriteProcessMemory", "NtCreateThreadEx", "VirtualAllocEx"),
        "pe_injection",
        CoverageLevel.PARTIAL,
        "Uses static triage PE flag + remote write heuristic.",
    ),
    IredTechnique(
        "entrypoint_patch",
        "AddressOfEntryPoint Code Injection without VirtualAllocEx RWX",
        "https://www.ired.team/offensive-security/code-injection-process-injection",
        ("WriteProcessMemory", "VirtualProtectEx", "ResumeThread"),
        "entrypoint_patching",
        CoverageLevel.PARTIAL,
        "Remote write + protect + resume without fresh allocation.",
    ),
    IredTechnique(
        "fiber",
        "Shellcode Execution through Fibers",
        "https://www.ired.team/offensive-security/code-injection-process-injection",
        ("ConvertThreadToFiber", "CreateFiber", "SwitchToFiber"),
        "fiber_injection",
        CoverageLevel.PARTIAL,
        "Fiber APIs hooked; local and cross-process heuristics.",
    ),
    IredTechnique(
        "threadpool_wait",
        "Shellcode Execution via CreateThreadpoolWait",
        "https://www.ired.team/offensive-security/code-injection-process-injection",
        ("CreateThreadpoolWait", "SetThreadpoolWait"),
        "threadpool_wait_injection",
        CoverageLevel.PARTIAL,
        "Threadpool wait callbacks hooked as execute primitive.",
    ),
    IredTechnique(
        "nt_test_alert",
        "Shellcode Execution with QueueUserAPC and NtTestAlert",
        "https://www.ired.team/offensive-security/code-injection-process-injection",
        ("QueueUserAPC", "NtTestAlert", "SleepEx"),
        "local_apc_injection",
        CoverageLevel.PARTIAL,
        "NtTestAlert hooked; SleepEx observation only (noisy).",
    ),
    IredTechnique(
        "atom_bombing",
        "Atom Bombing (GlobalAddAtom / NtQueueApcThread)",
        "https://www.ired.team/offensive-security/code-injection-process-injection",
        ("GlobalAddAtomA", "NtQueueApcThread"),
        "atom_injection",
        CoverageLevel.PARTIAL,
        "Atom APIs hooked; full atom-table APC chain not reconstructed.",
    ),
    IredTechnique(
        "extra_window_memory",
        "Extra Window Memory Injection",
        "https://www.ired.team/offensive-security/code-injection-process-injection",
        ("SetWindowLongPtrA", "SendMessageA"),
        "extra_window_memory_injection",
        CoverageLevel.PARTIAL,
        "Window long ptr + SendMessage hooks; no GWLP validation.",
    ),
    IredTechnique(
        "process_doppelganging",
        "Process Doppelganging",
        "https://www.ired.team/offensive-security/code-injection-process-injection/process-doppelganging",
        ("NtCreateTransaction", "NtCreateSection", "RtlCreateProcessReflection"),
        "process_doppelganging",
        CoverageLevel.PARTIAL,
        "TxF transaction + reflection APIs observed; no full transacted file graph.",
    ),
    IredTechnique(
        "process_ghosting",
        "Process Ghosting / Herpaderping",
        "https://www.ired.team/offensive-security/code-injection-process-injection",
        ("NtCreateSection", "CreateProcess"),
        "unclassified",
        CoverageLevel.PLANNED,
        "Overlaps section mapping; dedicated ghosting heuristics not implemented.",
    ),
    IredTechnique(
        "dotnet_unmanaged",
        "Injecting .NET Assembly to an Unmanaged Process",
        "https://www.ired.team/offensive-security/code-injection-process-injection",
        ("CLRCreateInstance", "CorBindToRuntime"),
        "unclassified",
        CoverageLevel.NONE,
        "CLR hosting APIs not hooked.",
    ),
    IredTechnique(
        "iat_hooking",
        "Import Address Table (IAT) Hooking",
        "https://www.ired.team/offensive-security/code-injection-process-injection",
        ("WriteProcessMemory", "VirtualProtect"),
        "unclassified",
        CoverageLevel.PLANNED,
        "API hooking lab; overlaps write+execute without IAT-specific logic.",
    ),
)


def coverage_summary() -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in IRED_TECHNIQUES:
        counts[item.coverage.value] = counts.get(item.coverage.value, 0) + 1
    return counts


def techniques_by_coverage(level: CoverageLevel) -> list[IredTechnique]:
    return [item for item in IRED_TECHNIQUES if item.coverage == level]
