"""Built-in classifier rule catalog with API match metadata for dashboard/docs."""

from __future__ import annotations

from typing import Any

# Gate defaults when a rule omits explicit ``defaults``:
# Exec/Cross/Same = off, min_primitive_kinds = 2, min_finding_score = 0, confidence = auto.


def _rule(
    rule_id: str,
    *,
    label: str,
    technique: str,
    group: str,
    description: str,
    api_groups: list[list[str]] | None = None,
    signals: list[str] | None = None,
    auto_confidence: str = "by_kinds",
    defaults: dict[str, Any] | None = None,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "id": rule_id,
        "label": label,
        "technique": technique,
        "group": group,
        "description": description,
        "api_groups": api_groups or [],
        "signals": signals or [],
        "auto_confidence": auto_confidence,
    }
    if defaults:
        entry["defaults"] = defaults
    return entry


BUILTIN_RULE_CATALOG: list[dict[str, Any]] = [
    _rule(
        "instrumentation_callback",
        label="Instrumentation callback",
        technique="instrumentation_callback",
        group="extension",
        description="NtSetInformationProcess ProcessInstrumentationCallback.",
        api_groups=[["NtSetInformationProcess"]],
        signals=["hook note: instrumentation_callback"],
        auto_confidence="high",
    ),
    _rule(
        "process_ghosting",
        label="Process ghosting",
        technique="process_ghosting",
        group="extension",
        description="Delete-pending file + section + process create.",
        api_groups=[
            ["NtSetInformationFile"],
            ["NtCreateSection", "ZwCreateSection", "NtCreateProcessEx", "NtCreateUserProcess", "CreateProcessA", "CreateProcessW"],
        ],
        signals=["or hook note: process_ghosting_precursor"],
        auto_confidence="high",
    ),
    _rule(
        "propagate_injection",
        label="PROPagate",
        technique="propagate_injection",
        group="extension",
        description="SetProp + SendNotifyMessage callback execution.",
        api_groups=[["SetPropA", "SetPropW"], ["SendNotifyMessageA", "SendNotifyMessageW"]],
        auto_confidence="high",
    ),
    _rule(
        "enum_callback_injection",
        label="Enum callback",
        technique="enum_callback_injection",
        group="extension",
        description="EnumXxx APIs with allocate/write primitives.",
        api_groups=[["EnumSystemLocalesA", "EnumDateFormatsW", "EnumWindows", "EnumChildWindows", "EnumThreadWindows", "…"]],
        signals=["kinds: allocate or write"],
        auto_confidence="high",
    ),
    _rule(
        "poolparty",
        label="PoolParty",
        technique="poolparty",
        group="extension",
        description="Thread-pool worker factory execution vehicle.",
        api_groups=[["TpAllocWork", "TpPostWork", "RtlQueueWorkItem", "NtSetInformationWorkerFactory"]],
        auto_confidence="by_kinds",
    ),
    _rule(
        "iat_hooking",
        label="IAT hooking",
        technique="iat_hooking",
        group="extension",
        description="Pointer-sized remote write in module IAT range.",
        api_groups=[["VirtualProtectEx", "NtProtectVirtualMemory"], ["WriteProcessMemory", "NtWriteVirtualMemory"]],
        signals=["cross_process", "write size ≤ 16 B", "no VirtualAllocEx/NtAllocateVirtualMemory"],
        auto_confidence="medium",
    ),
    _rule(
        "threadless_inject",
        label="Threadless inject",
        technique="threadless_inject",
        group="extension",
        description="Remote protect/write without remote-thread API.",
        api_groups=[["VirtualProtectEx", "NtProtectVirtualMemory"], ["WriteProcessMemory", "NtWriteVirtualMemory"]],
        signals=["cross_process", "no remote thread/APC/resume APIs"],
        auto_confidence="medium",
    ),
    _rule(
        "local_apc_injection",
        label="Local APC",
        technique="local_apc_injection",
        group="local",
        description="Same-process APC + alertable wake.",
        api_groups=[["QueueUserAPC", "NtQueueApcThread"], ["NtTestAlert"]],
        defaults={"require_same_process": True, "require_execution": True},
        auto_confidence="medium",
    ),
    _rule(
        "local_alertable_wake",
        label="Local alertable wake",
        technique="local_apc_injection",
        group="local",
        description="NtAllocateVirtualMemory + NtTestAlert in same process.",
        api_groups=[["NtAllocateVirtualMemory", "ZwAllocateVirtualMemory", "VirtualAlloc"], ["NtTestAlert"]],
        signals=["same_process", "kind: allocate"],
        defaults={"require_same_process": True, "require_execution": True, "min_primitive_kinds": 2},
        auto_confidence="medium",
    ),
    _rule(
        "local_fiber_injection",
        label="Local fiber",
        technique="fiber_injection",
        group="local",
        description="Fiber APIs in local process.",
        api_groups=[["SwitchToFiber", "CreateFiber", "ConvertThreadToFiber"]],
        defaults={"require_same_process": True},
        auto_confidence="by_kinds",
    ),
    _rule(
        "local_self_inject",
        label="Local self-inject",
        technique="local_self_inject",
        group="local",
        description="Fallback for same-process staging.",
        api_groups=[["(any operational primitives)"]],
        signals=["same_process", "no more specific local rule matched"],
        defaults={"require_same_process": True, "min_primitive_kinds": 3},
        auto_confidence="by_kinds",
    ),
    _rule(
        "classic_dll_injection",
        label="Classic DLL injection",
        technique="dll_injection",
        group="dll",
        description="VirtualAllocEx + WriteProcessMemory + CreateRemoteThread(LoadLibraryW).",
        api_groups=[
            ["VirtualAllocEx", "NtAllocateVirtualMemory", "ZwAllocateVirtualMemory"],
            ["WriteProcessMemory", "NtWriteVirtualMemory", "ZwWriteVirtualMemory"],
            ["CreateRemoteThread", "NtCreateThreadEx", "RtlCreateUserThread"],
        ],
        signals=["cross_process", "thread_parameter inside written buffer"],
        defaults={"require_cross_process": True, "min_primitive_kinds": 3},
        auto_confidence="high",
    ),
    _rule(
        "shellcode_trinity",
        label="Shellcode trinity",
        technique="shellcode_injection",
        group="shellcode",
        description="VirtualAllocEx + WriteProcessMemory + CreateRemoteThread.",
        api_groups=[
            ["VirtualAllocEx", "NtAllocateVirtualMemory", "ZwAllocateVirtualMemory"],
            ["WriteProcessMemory", "NtWriteVirtualMemory", "ZwWriteVirtualMemory"],
            ["CreateRemoteThread", "NtCreateThreadEx", "RtlCreateUserThread", "ZwCreateThreadEx"],
        ],
        defaults={"require_cross_process": True, "require_execution": True, "min_primitive_kinds": 3},
        auto_confidence="high",
    ),
    _rule(
        "process_doppelganging",
        label="Process doppelgänging",
        technique="process_doppelganging",
        group="txf",
        description="Transactional NTFS + process spawn.",
        api_groups=[
            ["NtCreateTransaction", "NtCommitTransaction", "NtRollbackTransaction", "RtlCreateProcessReflection"],
            ["CreateProcessA", "CreateProcessW", "NtCreateUserProcess", "NtCreateProcessEx"],
        ],
        signals=["or evidence: txf_transaction / process_reflection"],
        auto_confidence="medium",
    ),
    _rule(
        "extra_window_memory_injection",
        label="Extra window memory",
        technique="extra_window_memory_injection",
        group="win32",
        description="SetWindowLong + SendMessage trigger.",
        api_groups=[
            ["SetWindowLongPtrA", "SetWindowLongPtrW", "SetWindowLongA", "SetWindowLongW"],
            ["SendMessageA", "SendMessageW", "SendMessageCallbackA", "SendMessageCallbackW"],
        ],
        auto_confidence="medium",
    ),
    _rule(
        "hook_injection",
        label="Hook injection",
        technique="hook_injection",
        group="win32",
        description="SetWindowsHookEx cross-process.",
        api_groups=[["SetWindowsHookExA", "SetWindowsHookExW"]],
        auto_confidence="high",
    ),
    _rule(
        "atom_injection",
        label="Atom injection",
        technique="atom_injection",
        group="win32",
        description="Global/NT atom execute stage.",
        api_groups=[["NtAddAtom", "GlobalAddAtomA", "GlobalAddAtomW"]],
        auto_confidence="medium",
    ),
    _rule(
        "dll_injection_loadlibrary",
        label="DLL load (LoadLibrary)",
        technique="dll_injection",
        group="dll",
        description="Remote LoadLibrary* primitive.",
        api_groups=[["LdrLoadDll", "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW"]],
        signals=["cross_process"],
        auto_confidence="high_if_execute_else_medium",
    ),
    _rule(
        "early_bird_apc_injection",
        label="Early bird APC",
        technique="early_bird_apc_injection",
        group="apc",
        description="NtQueueApcThreadEx into CREATE_SUSPENDED victim.",
        api_groups=[["NtQueueApcThreadEx"]],
        signals=["create_suspended victim"],
        auto_confidence="high",
    ),
    _rule(
        "fiber_injection_cross",
        label="Fiber (cross-process)",
        technique="fiber_injection",
        group="fiber",
        description="Fiber APIs with cross-process primitives.",
        api_groups=[["SwitchToFiber", "CreateFiber"]],
        signals=["cross_process"],
        auto_confidence="by_kinds",
    ),
    _rule(
        "threadpool_wait_injection",
        label="Threadpool wait",
        technique="threadpool_wait_injection",
        group="pool",
        description="Threadpool wait/work callback vehicle.",
        api_groups=[
            ["CreateThreadpoolWait", "SetThreadpoolWait", "SubmitThreadpoolWait", "CreateThreadpoolWork", "SubmitThreadpoolWork"]
        ],
        auto_confidence="by_kinds",
    ),
    _rule(
        "apc_injection",
        label="APC injection",
        technique="apc_injection",
        group="apc",
        description="QueueUserAPC / NtQueueApcThread.",
        api_groups=[["NtQueueApcThread", "NtQueueApcThreadEx", "QueueUserAPC"]],
        auto_confidence="by_kinds",
    ),
    _rule(
        "section_mapping_no_exec",
        label="Section mapping (staging)",
        technique="section_mapping_injection",
        group="section",
        description="Section map without confirmed execution.",
        api_groups=[
            ["NtCreateSection", "NtMapViewOfSection", "ZwCreateSection", "ZwMapViewOfSection", "CreateFileMappingA", "CreateFileMappingW"]
        ],
        signals=["not execution_confirmed", "or evidence: section_mapping"],
        auto_confidence="high_if_context_else_medium",
    ),
    _rule(
        "cross_process_staging",
        label="Cross-process staging",
        technique="section_mapping_injection",
        group="staging",
        description="Remote allocate + write without execution transfer.",
        api_groups=[["NtAllocateVirtualMemory", "VirtualAllocEx", "ZwAllocateVirtualMemory"], ["NtWriteVirtualMemory", "WriteProcessMemory", "ZwWriteVirtualMemory"]],
        signals=["cross_process", "not execution_confirmed", "kinds: allocate + write"],
        defaults={"require_cross_process": True, "min_primitive_kinds": 2},
        auto_confidence="medium",
    ),
    _rule(
        "process_hollowing_section",
        label="Process hollowing (section)",
        technique="process_hollowing_section",
        group="section",
        description="Suspended victim + section + execution.",
        api_groups=[
            ["NtCreateSection", "NtMapViewOfSection", "ZwMapViewOfSection", "NtUnmapViewOfSection", "ZwUnmapViewOfSection"]
        ],
        signals=["execution_confirmed", "create_suspended or NtUnmapViewOfSection"],
        auto_confidence="high",
    ),
    _rule(
        "section_mapping_exec",
        label="Section mapping (exec)",
        technique="process_hollowing_section",
        group="section",
        description="Section mapping with execution transfer.",
        api_groups=[
            ["NtCreateSection", "NtMapViewOfSection", "ZwCreateSection", "ZwMapViewOfSection"]
        ],
        signals=["execution_confirmed"],
        auto_confidence="high",
    ),
    _rule(
        "module_stomping",
        label="Module stomping",
        technique="module_stomping",
        group="unmap",
        description="Remote unmap + write.",
        api_groups=[["NtUnmapViewOfSection"], ["(write primitive)"]],
        signals=["kind: write"],
        auto_confidence="medium",
    ),
    _rule(
        "process_spawn_inject",
        label="Process spawn inject",
        technique="process_spawn_inject",
        group="spawn",
        description="CREATE_SUSPENDED victim + injection.",
        api_groups=[["(injection primitives)"]],
        signals=["create_suspended", "cross_process"],
        auto_confidence="by_kinds",
    ),
    _rule(
        "entrypoint_patching",
        label="Entrypoint patching",
        technique="entrypoint_patching",
        group="pe",
        description="PE + remote protect/write.",
        api_groups=[["VirtualProtectEx", "NtProtectVirtualMemory", "ZwProtectVirtualMemory"]],
        signals=["related PE file", "cross_process", "kind: write"],
        auto_confidence="medium",
    ),
    _rule(
        "pe_injection",
        label="PE injection",
        technique="pe_injection",
        group="pe",
        description="PE file + remote write + execute.",
        api_groups=[["(write + execute primitives)"]],
        signals=["related PE file", "cross_process"],
        auto_confidence="by_kinds",
    ),
    _rule(
        "manual_mapping",
        label="Manual mapping",
        technique="manual_mapping",
        group="pe",
        description="Multi-write manual PE mapping.",
        api_groups=[
            ["VirtualAllocEx", "NtAllocateVirtualMemory"],
            ["WriteProcessMemory", "NtWriteVirtualMemory"],
            ["VirtualProtectEx", "NtProtectVirtualMemory"],
            ["NtCreateThreadEx", "RtlCreateUserThread", "CreateRemoteThread"],
        ],
        signals=["cross_process", "≥3 write primitives", "no LoadLibrary*", "kinds: write + execute"],
        auto_confidence="medium",
    ),
    _rule(
        "reflective_dll_injection",
        label="Reflective DLL",
        technique="reflective_dll_injection",
        group="dll",
        description="Remote write+execute without DLL path.",
        api_groups=[
            ["memcpy", "RtlMoveMemory", "VirtualAlloc", "NtAllocateVirtualMemory"],
            ["WriteProcessMemory", "NtWriteVirtualMemory"],
            ["NtCreateThreadEx", "CreateRemoteThread", "RtlCreateUserThread"],
        ],
        signals=[
            "cross_process",
            "no LoadLibrary*",
            "kinds: write + execute",
            "thread create/APC or memcpy (not ResumeThread-only)",
        ],
        auto_confidence="medium",
    ),
    _rule(
        "thread_hijack",
        label="Thread hijack",
        technique="thread_hijack",
        group="context",
        description="SetThreadContext redirect.",
        api_groups=[["SetThreadContext", "NtSetContextThread", "ZwSetContextThread"]],
        auto_confidence="by_kinds",
    ),
    _rule(
        "process_hollowing_classic",
        label="Process hollowing (classic)",
        technique="process_hollowing_classic",
        group="context",
        description="Suspended process resume after remote write.",
        api_groups=[["ResumeThread", "NtResumeThread", "NtAlertResumeThread", "ZwResumeThread"]],
        signals=["create_suspended", "no SetThreadContext match"],
        auto_confidence="by_kinds",
    ),
]


def format_rule_match(rule: dict[str, Any]) -> str:
    """Human-readable API/signal summary for dashboard."""
    groups = rule.get("api_groups") or []
    parts: list[str] = []
    for group in groups:
        if not group:
            continue
        parts.append("(" + " | ".join(group) + ")")
    summary = " + ".join(parts) if parts else "(no fixed API list)"
    signals = [str(item) for item in (rule.get("signals") or []) if str(item).strip()]
    if signals:
        summary = f"{summary} — {', '.join(signals)}"
    return summary


def format_gate_summary(rule: dict[str, Any]) -> str:
    """Compact default gate line for tooltips."""
    exec_req = "yes" if rule.get("require_execution") else "no"
    cross_req = "yes" if rule.get("require_cross_process") else "no"
    same_req = "yes" if rule.get("require_same_process") else "no"
    min_kinds = rule.get("min_primitive_kinds", 2)
    min_score = rule.get("min_finding_score", 0)
    confidence = str(rule.get("confidence") or "").strip() or str(rule.get("auto_confidence") or "auto")
    return (
        f"Exec={exec_req}, Cross={cross_req}, Same={same_req}, "
        f"Min kinds={min_kinds}, Min score={min_score}, Conf={confidence}"
    )


def classifier_rule_catalog() -> list[dict[str, Any]]:
    return [dict(item) for item in BUILTIN_RULE_CATALOG]
