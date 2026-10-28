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
        "Process Ghosting",
        "https://www.elastic.co/security-labs/process-ghosting-on-windows",
        (
            "NtSetInformationFile",  # FileDispositionInformation: delete-pending
            "NtCreateSection",
            "NtCreateProcessEx",
        ),
        "process_ghosting",
        CoverageLevel.FULL,
        "Delete-pending file + section + spawn — file is gone before NtCreateProcessEx.",
    ),
    IredTechnique(
        "process_herpaderping",
        "Process Herpaderping",
        "https://github.com/jxy-s/herpaderping",
        (
            "NtCreateSection",
            "WriteFile",  # overwrite source after section creation
            "NtCreateProcessEx",
        ),
        "process_herpaderping",
        CoverageLevel.FULL,
        "Section captured then file is overwritten before process create — image mismatch.",
    ),
    IredTechnique(
        "phantom_dll_hollowing",
        "Phantom DLL Hollowing (TxF)",
        "https://blog.forrest-orr.net/post/malicious-memory-artifacts-part-i-dll-hollowing",
        (
            "NtCreateTransaction",
            "CreateFileTransacted",
            "NtCreateSection",
            "NtMapViewOfSection",
            "NtRollbackTransaction",
        ),
        "phantom_dll_hollowing",
        CoverageLevel.PARTIAL,
        "TxF transactional DLL backing + section map; transacted file content not parsed.",
    ),
    IredTechnique(
        "iat_hooking",
        "Import Address Table (IAT) Hooking",
        "https://www.ired.team/offensive-security/code-injection-process-injection",
        ("WriteProcessMemory", "VirtualProtectEx"),
        "iat_hooking",
        CoverageLevel.FULL,
        "Write inside a remote module's IAT range; flagged when target address lies in known module bounds.",
    ),
    IredTechnique(
        "propagate",
        "PROPagate (SetPropA + SendNotifyMessage)",
        "https://modexp.wordpress.com/2018/08/23/process-injection-propagate/",
        ("SetPropA", "SetPropW", "SendNotifyMessageA", "SendNotifyMessageW"),
        "propagate_injection",
        CoverageLevel.FULL,
        "Window property pointer to shellcode then trigger via SendNotifyMessage.",
    ),
    IredTechnique(
        "manual_mapping",
        "Manual PE Mapping (no LoadLibrary)",
        "https://www.ired.team/offensive-security/code-injection-process-injection",
        ("VirtualAllocEx", "WriteProcessMemory", "VirtualProtectEx", "RtlCreateUserThread"),
        "manual_mapping",
        CoverageLevel.FULL,
        "Cross-process alloc + multiple writes (PE sections) + protect + thread, no LoadLibrary.",
    ),
    IredTechnique(
        "enum_callback",
        "EnumXxx Callback Injection (EnumSystemLocalesA, EnumWindows, EnumChildWindows)",
        "https://modexp.wordpress.com/2019/04/25/seven-non-traditional-windows-process-injection-techniques/",
        (
            "EnumSystemLocalesA",
            "EnumWindows",
            "EnumChildWindows",
            "EnumDateFormatsA",
            "EnumUILanguagesW",
            "EnumResourceNamesW",
        ),
        "enum_callback_injection",
        CoverageLevel.FULL,
        "Callback pointer overlaps a freshly allocated executable buffer.",
    ),
    IredTechnique(
        "kernel_callback_table",
        "KernelCallbackTable Injection (PEB)",
        "https://www.elastic.co/security-labs/finding-truth-in-the-shadows",
        ("NtQueryInformationProcess", "NtWriteVirtualMemory"),
        "kernel_callback_table",
        CoverageLevel.PARTIAL,
        "Overwrite KernelCallbackTable pointer in remote PEB; triggered by user32 messages.",
    ),
    IredTechnique(
        "instrumentation_callback",
        "Instrumentation Callback (NtSetInformationProcess)",
        "https://standa-note.blogspot.com/2015/10/setting-systemwide-instrumentation.html",
        ("NtSetInformationProcess",),
        "instrumentation_callback",
        CoverageLevel.FULL,
        "ProcessInstrumentationCallback class — every syscall return routed to attacker code.",
    ),
    IredTechnique(
        "etw_patching",
        "ETW EventWrite Patching",
        "https://www.mdsec.co.uk/2020/03/hiding-your-net-etw/",
        ("VirtualProtect", "RtlCopyMemory"),
        "etw_patching",
        CoverageLevel.PARTIAL,
        "Self-patch ntdll!EtwEventWrite stub — defensive-evasion, observed via local protect+write to ntdll range.",
    ),
    IredTechnique(
        "amsi_patching",
        "AMSI ScanBuffer Patching",
        "https://www.mdsec.co.uk/2018/06/exploring-powershell-amsi-and-logging-evasion/",
        ("VirtualProtect", "RtlCopyMemory"),
        "amsi_patching",
        CoverageLevel.PARTIAL,
        "Patch amsi.dll!AmsiScanBuffer — local self-write to amsi range.",
    ),
    IredTechnique(
        "mockingjay",
        "Mockingjay (existing RWX in legit DLL)",
        "https://www.securityjoes.com/post/process-mockingjay-echoing-rwx-in-userland-to-achieve-code-execution",
        ("NtMapViewOfSection", "NtCreateThreadEx"),
        "mockingjay",
        CoverageLevel.PARTIAL,
        "Map an existing RWX section from a legitimate signed DLL and execute — no allocate primitive.",
    ),
    IredTechnique(
        "poolparty",
        "PoolParty (Threadpool worker factory)",
        "https://www.safebreach.com/blog/process-injection-using-windows-thread-pools/",
        (
            "TpAllocWork",
            "TpPostWork",
            "NtSetInformationWorkerFactory",
            "RtlQueueWorkItem",
        ),
        "poolparty",
        CoverageLevel.PARTIAL,
        "Remote thread-pool worker factory hijack; SafeBreach 2023 — 8 variants.",
    ),
    IredTechnique(
        "threadless_inject",
        "Threadless Inject (export-trampoline hook)",
        "https://github.com/CCob/ThreadlessInject",
        ("OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "VirtualProtectEx"),
        "threadless_inject",
        CoverageLevel.FULL,
        "Patch a remote DLL export with a near-jmp to shellcode; no remote thread created.",
    ),
    IredTechnique(
        "dotnet_unmanaged",
        "Injecting .NET Assembly to an Unmanaged Process",
        "https://www.ired.team/offensive-security/code-injection-process-injection",
        ("CLRCreateInstance", "CorBindToRuntime", "ICLRMetaHost"),
        "dotnet_clr_hosting",
        CoverageLevel.NONE,
        "CLR hosting APIs not hooked — documented as out-of-scope.",
    ),
    IredTechnique(
        "shims_appinit",
        "AppInit_DLLs / AppCertDLLs (registry)",
        "https://attack.mitre.org/techniques/T1546/010/",
        ("RegSetValueEx",),
        None,
        CoverageLevel.NONE,
        "Registry-based persistence — out of API hook scope; relies on registry telemetry.",
    ),
    IredTechnique(
        "ifeo_debugger",
        "Image File Execution Options Debugger",
        "https://attack.mitre.org/techniques/T1546/012/",
        ("RegSetValueEx",),
        None,
        CoverageLevel.NONE,
        "Registry-based — out of API hook scope.",
    ),
    IredTechnique(
        "com_hijack",
        "COM Hijacking",
        "https://attack.mitre.org/techniques/T1546/015/",
        ("RegSetValueEx",),
        None,
        CoverageLevel.NONE,
        "Registry-based — out of API hook scope.",
    ),
    IredTechnique(
        "dll_search_order",
        "DLL Search Order Hijacking",
        "https://attack.mitre.org/techniques/T1574/001/",
        ("CreateFile", "LoadLibrary"),
        None,
        CoverageLevel.PARTIAL,
        "File-drop telemetry catches the planted DLL; no path-precedence reasoning.",
    ),
    IredTechnique(
        "ghostwriting",
        "GhostWriting (SetThreadContext only)",
        "https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process",
        ("OpenThread", "SetThreadContext"),
        "thread_hijack",
        CoverageLevel.FULL,
        "Subset of thread hijacking — only context manipulation, no remote write. D1 Rip extraction makes it detectable.",
    ),
)


def coverage_summary() -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in IRED_TECHNIQUES:
        counts[item.coverage.value] = counts.get(item.coverage.value, 0) + 1
    return counts


def techniques_by_coverage(level: CoverageLevel) -> list[IredTechnique]:
    return [item for item in IRED_TECHNIQUES if item.coverage == level]
