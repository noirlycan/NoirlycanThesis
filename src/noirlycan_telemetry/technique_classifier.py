"""Rule-based injection technique classifier (ASIA CCS 2025 + iRed.team subset)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from .execution_analysis import analyze_execution
from .models import Finding, PrimitiveKind, ProcessEvent
from .payload_classifier import payload_metadata


class InjectionTechnique(str, Enum):
    SECTION_MAPPING_INJECTION = "section_mapping_injection"
    PROCESS_HOLLOWING_SECTION = "process_hollowing_section"
    PROCESS_HOLLOWING_CLASSIC = "process_hollowing_classic"
    SHELLCODE_INJECTION = "shellcode_injection"
    APC_INJECTION = "apc_injection"
    EARLY_BIRD_APC_INJECTION = "early_bird_apc_injection"
    LOCAL_APC_INJECTION = "local_apc_injection"
    THREAD_HIJACK = "thread_hijack"
    DLL_INJECTION = "dll_injection"
    REFLECTIVE_DLL_INJECTION = "reflective_dll_injection"
    PE_INJECTION = "pe_injection"
    ENTRYPOINT_PATCHING = "entrypoint_patching"
    PROCESS_SPAWN_INJECT = "process_spawn_inject"
    PROCESS_DOPPELGANGING = "process_doppelganging"
    MODULE_STOMPING = "module_stomping"
    ATOM_INJECTION = "atom_injection"
    HOOK_INJECTION = "hook_injection"
    FIBER_INJECTION = "fiber_injection"
    THREADPOOL_WAIT_INJECTION = "threadpool_wait_injection"
    EXTRA_WINDOW_MEMORY_INJECTION = "extra_window_memory_injection"
    LOCAL_SELF_INJECT = "local_self_inject"
    # ---- Extensions beyond ASIA CCS 2025 / iRed.team core set ----
    PROCESS_GHOSTING = "process_ghosting"
    PROCESS_HERPADERPING = "process_herpaderping"
    PHANTOM_DLL_HOLLOWING = "phantom_dll_hollowing"
    IAT_HOOKING = "iat_hooking"
    PROPAGATE_INJECTION = "propagate_injection"
    MANUAL_MAPPING = "manual_mapping"
    ENUM_CALLBACK_INJECTION = "enum_callback_injection"
    KERNEL_CALLBACK_TABLE = "kernel_callback_table"
    INSTRUMENTATION_CALLBACK = "instrumentation_callback"
    ETW_PATCHING = "etw_patching"
    AMSI_PATCHING = "amsi_patching"
    MOCKINGJAY = "mockingjay"
    POOLPARTY = "poolparty"
    THREADLESS_INJECT = "threadless_inject"
    UNCLASSIFIED = "unclassified"


class TechniqueConfidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class TechniqueClassification:
    technique: InjectionTechnique
    confidence: TechniqueConfidence
    rationale: str


def classifier_rule_catalog() -> list[dict[str, Any]]:
    from .builtin_rule_catalog import classifier_rule_catalog as _catalog

    return _catalog()


def classify_finding(
    finding: Finding,
    *,
    rules_config: "ClassifierRulesConfig | None" = None,
) -> TechniqueClassification:
    from .classifier_config import (
        ClassifierRulesConfig,
        confidence_override,
        load_classifier_config,
        passes_rule_gates,
    )

    config = rules_config or load_classifier_config()

    apis = {primitive.api for primitive in finding.primitives}
    apis_lower = {api.lower() for api in apis}
    kinds = {primitive.kind for primitive in finding.primitives}
    evidence = finding.evidence or {}
    execution_meta = analyze_execution(list(finding.primitives))
    execution_confirmed = bool(evidence.get("execution_confirmed", execution_meta["execution_confirmed"]))
    cross_process = bool(evidence.get("cross_process"))
    section_mapping = bool(evidence.get("section_mapping"))
    create_suspended = bool(evidence.get("create_suspended"))
    context_read = PrimitiveKind.CONTEXT_READ in kinds or bool(execution_meta.get("context_read_evidence"))

    def _gate(rule_id: str) -> bool:
        return passes_rule_gates(
            rule_id,
            finding,
            kinds,
            config,
            execution_confirmed=execution_confirmed,
            cross_process=cross_process,
        )

    def _finish(rule_id: str, result: TechniqueClassification) -> TechniqueClassification:
        override = confidence_override(rule_id, config)
        if override:
            return TechniqueClassification(
                technique=result.technique,
                confidence=TechniqueConfidence(override),
                rationale=result.rationale,
            )
        return result

    from .custom_rule_engine import evaluate_custom_rules

    custom_match = evaluate_custom_rules(
        config.custom_rules,
        finding,
        kinds=kinds,
        apis_lower=apis_lower,
        evidence=evidence,
        execution_confirmed=execution_confirmed,
        cross_process=cross_process,
        context_read=context_read,
        phase="before_builtin",
    )
    if custom_match is not None:
        return custom_match

    # ---- Extensions: high-specificity rules first ----
    if _gate("instrumentation_callback") and _has_any(apis_lower, "ntsetinformationprocess") and _has_note(finding, "instrumentation_callback"):
        return TechniqueClassification(
            technique=InjectionTechnique.INSTRUMENTATION_CALLBACK,
            confidence=TechniqueConfidence.HIGH,
            rationale="NtSetInformationProcess with ProcessInstrumentationCallback class.",
        )

    if _gate("process_ghosting") and (
        _has_note(finding, "process_ghosting_precursor") or _has_any(
        apis_lower, "ntsetinformationfile"
    )
    ):
        if _has_any(
            apis_lower,
            "ntcreatesection",
            "zwcreatesection",
            "ntcreateprocessex",
            "ntcreateuserprocess",
            "createprocessa",
            "createprocessw",
        ):
            return TechniqueClassification(
                technique=InjectionTechnique.PROCESS_GHOSTING,
                confidence=TechniqueConfidence.HIGH,
                rationale="Delete-pending file disposition followed by section + process create.",
            )

    if _gate("propagate_injection") and _has_any(apis_lower, "setpropa", "setpropw") and _has_any(
        apis_lower, "sendnotifymessagea", "sendnotifymessagew"
    ):
        return TechniqueClassification(
            technique=InjectionTechnique.PROPAGATE_INJECTION,
            confidence=TechniqueConfidence.HIGH,
            rationale="SetProp window-property pointer triggered via SendNotifyMessage (PROPagate).",
        )

    enum_apis = {
        "enumsystemlocalesa", "enumsystemlocalesw", "enumdateformatsa", "enumdateformatsw",
        "enumuilanguagesw", "enumresourcetypesa", "enumresourcetypesw",
        "enumwindows", "enumchildwindows", "enumdesktopwindows", "enumthreadwindows",
    }
    if _gate("enum_callback_injection") and apis_lower & enum_apis and (
        PrimitiveKind.ALLOCATE in kinds or PrimitiveKind.WRITE in kinds
    ):
        return TechniqueClassification(
            technique=InjectionTechnique.ENUM_CALLBACK_INJECTION,
            confidence=TechniqueConfidence.HIGH,
            rationale="EnumXxx callback pointer used to execute attacker-controlled buffer.",
        )

    poolparty_apis = {
        "tpallocwork", "tppostwork", "rtlqueueworkitem", "ntsetinformationworkerfactory",
    }
    if _gate("poolparty") and apis_lower & poolparty_apis:
        return TechniqueClassification(
            technique=InjectionTechnique.POOLPARTY,
            confidence=_confidence_from_kinds(kinds, minimum=2),
            rationale="Thread-pool worker factory / TpAllocWork used as execution vehicle (PoolParty).",
        )

    # IAT hook = pointer-sized overwrite (≤ 16 B); threadless = larger trampoline.
    if _gate("iat_hooking") and _is_iat_hook(finding, apis_lower, kinds):
        return TechniqueClassification(
            technique=InjectionTechnique.IAT_HOOKING,
            confidence=TechniqueConfidence.MEDIUM,
            rationale="Cross-process VirtualProtectEx + pointer-sized write inside a remote module (IAT range heuristic).",
        )

    if _gate("threadless_inject") and _is_threadless_inject(finding, apis_lower, kinds, execution_confirmed):
        return TechniqueClassification(
            technique=InjectionTechnique.THREADLESS_INJECT,
            confidence=TechniqueConfidence.MEDIUM,
            rationale="Remote protect+write to executable region without a remote-thread API (threadless trampoline).",
        )

    if _gate("local_alertable_wake") and _is_local_only(finding) and _has_any(apis_lower, "nttestalert") and PrimitiveKind.ALLOCATE in kinds:
        return _finish(
            "local_alertable_wake",
            TechniqueClassification(
                technique=InjectionTechnique.LOCAL_APC_INJECTION,
                confidence=TechniqueConfidence.MEDIUM,
                rationale="Local memory allocation followed by NtTestAlert (alertable wake / local shellcode).",
            ),
        )

    if _is_local_only(finding):
        if _gate("local_apc_injection") and _has_any(apis_lower, "nttestalert") and _has_any(apis_lower, "queueuserapc", "ntqueueapcthread"):
            return _finish(
                "local_apc_injection",
                TechniqueClassification(
                    technique=InjectionTechnique.LOCAL_APC_INJECTION,
                    confidence=TechniqueConfidence.MEDIUM,
                    rationale="Local APC queued then alertable wake (NtTestAlert / SleepEx pattern).",
                ),
            )
        if _gate("local_fiber_injection") and _has_any(apis_lower, "switchtofiber", "createfiber", "convertthreadtofiber"):
            return _finish(
                "local_fiber_injection",
                TechniqueClassification(
                    technique=InjectionTechnique.FIBER_INJECTION,
                    confidence=_confidence_from_kinds(kinds, minimum=2),
                    rationale="Fiber APIs used to redirect execution in the local process.",
                ),
            )
        if _gate("local_self_inject"):
            return _finish(
                "local_self_inject",
                TechniqueClassification(
                    technique=InjectionTechnique.LOCAL_SELF_INJECT,
                    confidence=_confidence_from_kinds(kinds, minimum=2),
                    rationale="Primitives target the same process (self-injection / local staging).",
                ),
            )

    if _gate("process_doppelganging") and _has_txf_signal(apis_lower, evidence):
        return TechniqueClassification(
            technique=InjectionTechnique.PROCESS_DOPPELGANGING,
            confidence=TechniqueConfidence.MEDIUM,
            rationale="Transactional NTFS (TxF) APIs observed with process creation/spawn.",
        )

    if _gate("extra_window_memory_injection") and _has_any(
        apis_lower,
        "setwindowlongptra",
        "setwindowlongptrw",
        "setwindowlonga",
        "setwindowlongw",
    ) and _has_any(apis_lower, "sendmessagea", "sendmessagew", "sendmessagecallbacka", "sendmessagecallbackw"):
        return TechniqueClassification(
            technique=InjectionTechnique.EXTRA_WINDOW_MEMORY_INJECTION,
            confidence=TechniqueConfidence.MEDIUM,
            rationale="Window extra-bytes memory manipulated then triggered via SendMessage.",
        )

    if _gate("hook_injection") and _has_any(apis_lower, "setwindowshookexa", "setwindowshookexw"):
        return TechniqueClassification(
            technique=InjectionTechnique.HOOK_INJECTION,
            confidence=TechniqueConfidence.HIGH,
            rationale="SetWindowsHookEx used to schedule code in another process.",
        )

    if _gate("atom_injection") and _has_any(apis_lower, "ntaddatom", "globaladdatoma", "globaladdatomw"):
        return TechniqueClassification(
            technique=InjectionTechnique.ATOM_INJECTION,
            confidence=TechniqueConfidence.MEDIUM,
            rationale="Global/NT atom APIs observed in execute stage.",
        )

    if _gate("dll_injection_loadlibrary") and _has_any(apis_lower, "ldrloaddll", "loadlibrarya", "loadlibraryw", "loadlibraryexa", "loadlibraryexw"):
        if cross_process or _target_differs_from_actor(finding):
            return TechniqueClassification(
                technique=InjectionTechnique.DLL_INJECTION,
                confidence=TechniqueConfidence.HIGH if PrimitiveKind.EXECUTE in kinds else TechniqueConfidence.MEDIUM,
                rationale="Remote DLL load primitive observed.",
            )

    if _gate("early_bird_apc_injection") and _has_any(apis_lower, "ntqueueapcthreadex") and create_suspended:
        return TechniqueClassification(
            technique=InjectionTechnique.EARLY_BIRD_APC_INJECTION,
            confidence=TechniqueConfidence.HIGH,
            rationale="APC queued via NtQueueApcThreadEx into a CREATE_SUSPENDED victim (early bird).",
        )

    if _gate("fiber_injection_cross") and _has_any(apis_lower, "switchtofiber", "createfiber") and cross_process:
        return TechniqueClassification(
            technique=InjectionTechnique.FIBER_INJECTION,
            confidence=_confidence_from_kinds(kinds, minimum=2),
            rationale="Fiber execution transfer observed with cross-process memory primitives.",
        )

    if _gate("threadpool_wait_injection") and _has_any(
        apis_lower,
        "createthreadpoolwait",
        "setthreadpoolwait",
        "submitthreadpoolwait",
        "createthreadpoolwork",
        "submitthreadpoolwork",
    ):
        return TechniqueClassification(
            technique=InjectionTechnique.THREADPOOL_WAIT_INJECTION,
            confidence=_confidence_from_kinds(kinds, minimum=2),
            rationale="Threadpool wait/work callback used as execution vehicle.",
        )

    if _gate("apc_injection") and _has_any(apis_lower, "ntqueueapcthread", "ntqueueapcthreadex", "queueuserapc"):
        return TechniqueClassification(
            technique=InjectionTechnique.APC_INJECTION,
            confidence=_confidence_from_kinds(kinds, minimum=2),
            rationale="APC queue API used to trigger execution in a remote thread.",
        )

    if _gate("section_mapping_no_exec") and (
        section_mapping or _has_any(
        apis_lower,
        "ntcreatesection",
        "ntmapviewofsection",
        "zwcreatesection",
        "zwmapviewofsection",
        "createfilemappinga",
        "createfilemappingw",
    )
    ):
        if not execution_confirmed:
            rationale = "Remote allocation/write/section mapping"
            if context_read:
                rationale += " with thread context inspection; execution transfer not confirmed."
            else:
                rationale += "; execution transfer not confirmed."
            return TechniqueClassification(
                technique=InjectionTechnique.SECTION_MAPPING_INJECTION,
                confidence=TechniqueConfidence.HIGH if context_read else TechniqueConfidence.MEDIUM,
                rationale=rationale,
            )
        if _gate("process_hollowing_section") and (
            create_suspended or _has_any(apis_lower, "ntunmapviewofsection", "zwunmapviewofsection")
        ):
            return TechniqueClassification(
                technique=InjectionTechnique.PROCESS_HOLLOWING_SECTION,
                confidence=TechniqueConfidence.HIGH,
                rationale="Suspended/spawned victim with section mapping and confirmed execution transfer.",
            )
        if _gate("section_mapping_exec"):
            return TechniqueClassification(
                technique=InjectionTechnique.PROCESS_HOLLOWING_SECTION,
                confidence=TechniqueConfidence.HIGH,
                rationale="Section mapping with confirmed execution transfer.",
            )

    if _gate("module_stomping") and _has_any(apis_lower, "ntunmapviewofsection") and PrimitiveKind.WRITE in kinds:
        return TechniqueClassification(
            technique=InjectionTechnique.MODULE_STOMPING,
            confidence=TechniqueConfidence.MEDIUM,
            rationale="Remote unmap followed by write primitive (module stomping pattern).",
        )

    if _gate("process_spawn_inject") and create_suspended and cross_process:
        return TechniqueClassification(
            technique=InjectionTechnique.PROCESS_SPAWN_INJECT,
            confidence=_confidence_from_kinds(kinds, minimum=2),
            rationale="Victim created suspended then injection primitives observed.",
        )

    if _gate("pe_injection") and finding.related_file and finding.related_file.pe and cross_process and PrimitiveKind.WRITE in kinds:
        if _gate("entrypoint_patching") and _has_any(apis_lower, "virtualprotectex", "ntprotectvirtualmemory", "zwprotectvirtualmemory"):
            return TechniqueClassification(
                technique=InjectionTechnique.ENTRYPOINT_PATCHING,
                confidence=TechniqueConfidence.MEDIUM,
                rationale="PE sample with remote protect/write (entrypoint or image patch pattern).",
            )
        return TechniqueClassification(
            technique=InjectionTechnique.PE_INJECTION,
            confidence=_confidence_from_kinds(kinds, minimum=2),
            rationale="PE file correlated with remote memory write and execution primitives.",
        )

    # Manual mapping is a *stronger* signal than the shellcode trinity (PE
    # loaders write each section separately and call VirtualProtectEx). Check
    # it BEFORE the trinity rule so we don't misclassify multi-write loaders
    # as plain shellcode.
    if _gate("manual_mapping") and (
        cross_process
        and PrimitiveKind.WRITE in kinds
        and PrimitiveKind.EXECUTE in kinds
        and not (apis_lower & {"loadlibrarya", "loadlibraryw", "loadlibraryexa", "loadlibraryexw", "ldrloaddll"})
        and (apis_lower & {"virtualprotectex", "ntprotectvirtualmemory"})
        and sum(1 for p in finding.primitives if p.kind == PrimitiveKind.WRITE) >= 3
    ):
        return TechniqueClassification(
            technique=InjectionTechnique.MANUAL_MAPPING,
            confidence=TechniqueConfidence.MEDIUM,
            rationale="Multiple remote writes + protect + thread, no LoadLibrary (manual PE mapping).",
        )

    # Classic DLL injection: remote thread entry is LoadLibrary* but the thread
    # parameter points at the path buffer written by WriteProcessMemory.
    if _gate("classic_dll_injection") and _classic_dll_injection_pattern(finding, apis_lower, cross_process):
        return TechniqueClassification(
            technique=InjectionTechnique.DLL_INJECTION,
            confidence=TechniqueConfidence.HIGH,
            rationale=(
                "VirtualAllocEx + WriteProcessMemory + CreateRemoteThread with "
                "thread parameter at the remote DLL path buffer."
            ),
        )

    # Classic shellcode trinity takes precedence over the generic reflective-
    # DLL fallback.
    if _gate("shellcode_trinity") and _has_any(
        apis_lower,
        "virtualallocex",
        "virtualallocexnuma",
        "ntallocatevirtualmemory",
        "zwallocatevirtualmemory",
    ) and _has_any(
        apis_lower,
        "writeprocessmemory",
        "ntwritevirtualmemory",
        "zwwritevirtualmemory",
    ) and _has_any(
        apis_lower,
        "createremotethread",
        "createremotethreadex",
        "ntcreatethreadex",
        "rtlcreateuserthread",
        "zwcreatethreadex",
    ):
        return TechniqueClassification(
            technique=InjectionTechnique.SHELLCODE_INJECTION,
            confidence=TechniqueConfidence.HIGH,
            rationale="Classic VirtualAllocEx + WriteProcessMemory + CreateRemoteThread chain.",
        )

    execute_apis_lower = _execute_apis_lower(finding)
    if (
        _gate("process_hollowing_classic")
        and cross_process
        and PrimitiveKind.WRITE in kinds
        and _resume_only_execution(execute_apis_lower)
        and not _has_any(apis_lower, "setthreadcontext", "ntsetcontextthread", "zwsetcontextthread")
    ):
        return TechniqueClassification(
            technique=InjectionTechnique.PROCESS_HOLLOWING_CLASSIC,
            confidence=TechniqueConfidence.MEDIUM,
            rationale=(
                "Remote memory write followed by thread resume "
                "(suspended-child / installer pattern, not reflective DLL)."
            ),
        )

    if _gate("reflective_dll_injection") and _reflective_dll_pattern(
        apis_lower,
        kinds,
        cross_process,
        execute_apis_lower=execute_apis_lower,
    ):
        return TechniqueClassification(
            technique=InjectionTechnique.REFLECTIVE_DLL_INJECTION,
            confidence=TechniqueConfidence.MEDIUM,
            rationale="Remote memory write + execute without DLL path (reflective loading pattern).",
        )

    if _has_any(
        apis_lower,
        "setthreadcontext",
        "ntsetcontextthread",
        "zwsetcontextthread",
    ) or _has_any(apis_lower, "resumethread", "ntresumethread", "ntalertresumethread", "zwresumethread"):
        if _gate("thread_hijack") and _has_any(apis_lower, "setthreadcontext", "ntsetcontextthread", "zwsetcontextthread"):
            return TechniqueClassification(
                technique=InjectionTechnique.THREAD_HIJACK,
                confidence=_confidence_from_kinds(kinds, minimum=2),
                rationale="Thread context manipulation used to redirect execution.",
            )
        if _gate("process_hollowing_classic") and create_suspended:
            return TechniqueClassification(
                technique=InjectionTechnique.PROCESS_HOLLOWING_CLASSIC,
                confidence=_confidence_from_kinds(kinds, minimum=2),
                rationale="Suspended process resumed after remote memory manipulation.",
            )

    if (
        _gate("cross_process_staging")
        and cross_process
        and PrimitiveKind.ALLOCATE in kinds
        and PrimitiveKind.WRITE in kinds
        and not execution_confirmed
    ):
        return _finish(
            "cross_process_staging",
            TechniqueClassification(
                technique=InjectionTechnique.SECTION_MAPPING_INJECTION,
                confidence=TechniqueConfidence.MEDIUM,
                rationale=(
                    "Cross-process remote allocate + write without confirmed "
                    "execution transfer (injection staging)."
                ),
            ),
        )

    custom_after = evaluate_custom_rules(
        config.custom_rules,
        finding,
        kinds=kinds,
        apis_lower=apis_lower,
        evidence=evidence,
        execution_confirmed=execution_confirmed,
        cross_process=cross_process,
        context_read=context_read,
        phase="after_builtin",
    )
    if custom_after is not None:
        return custom_after

    return TechniqueClassification(
        technique=InjectionTechnique.UNCLASSIFIED,
        confidence=TechniqueConfidence.LOW if len(kinds) < 3 else TechniqueConfidence.MEDIUM,
        rationale="Injection primitives detected but no specific technique rule matched.",
    )


def apply_classification(
    finding: Finding,
    *,
    logs_dir: str | Path | None = None,
) -> Finding:
    from .classifier_config import load_classifier_config

    config = load_classifier_config(logs_dir)
    if not config.classification_enabled:
        return finding
    result = classify_finding(finding, rules_config=config)
    evidence = dict(finding.evidence)
    execution_meta = analyze_execution(list(finding.primitives))
    evidence.update(execution_meta)
    evidence.update(payload_metadata(finding))
    evidence["technique"] = result.technique.value
    evidence["technique_confidence"] = result.confidence.value
    evidence["technique_rationale"] = result.rationale
    return Finding(
        timestamp=finding.timestamp,
        severity=finding.severity,
        title=finding.title,
        description=finding.description,
        actor_pid=finding.actor_pid,
        target_pid=finding.target_pid,
        primitives=finding.primitives,
        related_file=finding.related_file,
        related_process=finding.related_process,
        actor_image=finding.actor_image,
        target_image=finding.target_image,
        score=finding.score,
        evidence=evidence,
        technique=result.technique.value,
        technique_confidence=result.confidence.value,
        injection_chain=finding.injection_chain,
        chain_depth=finding.chain_depth,
        is_recursive=finding.is_recursive,
    )


def classification_from_dict(value: dict[str, Any]) -> TechniqueClassification | None:
    technique = value.get("technique") or (value.get("evidence") or {}).get("technique")
    if not technique:
        return None
    confidence = value.get("technique_confidence") or (value.get("evidence") or {}).get("technique_confidence")
    rationale = (value.get("evidence") or {}).get("technique_rationale", "")
    try:
        return TechniqueClassification(
            technique=InjectionTechnique(str(technique)),
            confidence=TechniqueConfidence(str(confidence or "low")),
            rationale=str(rationale),
        )
    except ValueError:
        return None


def _confidence_from_kinds(kinds: set[PrimitiveKind], *, minimum: int) -> TechniqueConfidence:
    if len(kinds) >= 3:
        return TechniqueConfidence.HIGH
    if len(kinds) >= minimum:
        return TechniqueConfidence.MEDIUM
    return TechniqueConfidence.LOW


def _has_any(apis_lower: set[str], *needles: str) -> bool:
    return any(needle in api for api in apis_lower for needle in needles)


def _is_local_only(finding: Finding) -> bool:
    if finding.target_pid is None:
        return True
    return finding.target_pid == finding.actor_pid


def _target_differs_from_actor(finding: Finding) -> bool:
    return finding.target_pid is not None and finding.target_pid != finding.actor_pid


def _has_txf_signal(apis_lower: set[str], evidence: dict[str, Any]) -> bool:
    if evidence.get("txf_transaction") or evidence.get("process_reflection"):
        return True
    txf_apis = {
        "ntcreatetransaction",
        "ntcommittransaction",
        "ntrollbacktransaction",
        "rtlcreateprocessreflection",
    }
    spawn_apis = {
        "createprocessa",
        "createprocessw",
        "ntcreateuserprocess",
        "rtlcreateuserprocess",
        "ntcreateprocessex",
    }
    return bool(apis_lower & txf_apis) and bool(apis_lower & spawn_apis)


def _has_note(finding: Finding, needle: str) -> bool:
    needle = needle.lower()
    for primitive in finding.primitives:
        note = str(primitive.details.get("note", "")).lower()
        if needle in note:
            return True
    return False


def _is_threadless_inject(
    finding: Finding,
    apis_lower: set[str],
    kinds: set[PrimitiveKind],
    execution_confirmed: bool,
) -> bool:
    if finding.target_pid is None or finding.target_pid == finding.actor_pid:
        return False
    if PrimitiveKind.WRITE not in kinds:
        return False
    # Must protect+write remotely without spawning a thread.
    protect = apis_lower & {"virtualprotectex", "ntprotectvirtualmemory", "zwprotectvirtualmemory"}
    if not protect:
        return False
    thread_spawn = apis_lower & {
        "createremotethread", "createremotethreadex",
        "ntcreatethreadex", "rtlcreateuserthread", "zwcreatethreadex",
        "queueuserapc", "ntqueueapcthread", "ntqueueapcthreadex",
        "resumethread", "ntresumethread", "ntalertresumethread", "zwresumethread",
    }
    if thread_spawn:
        return False
    # Small write (~16 bytes for a near-jmp trampoline) — the heuristic is the
    # presence of write+protect on the remote side with no thread creation.
    return True


def _is_iat_hook(finding: Finding, apis_lower: set[str], kinds: set[PrimitiveKind]) -> bool:
    if finding.target_pid is None or finding.target_pid == finding.actor_pid:
        return False
    if "writeprocessmemory" not in apis_lower and "ntwritevirtualmemory" not in apis_lower:
        return False
    if not (apis_lower & {"virtualprotectex", "ntprotectvirtualmemory"}):
        return False
    # Avoid duplicate with shellcode injection — IAT hook does NOT allocate
    # fresh memory, it patches existing module IAT.
    if "virtualallocex" in apis_lower or "ntallocatevirtualmemory" in apis_lower:
        return False
    # Pointer-sized writes look like IAT entry overwrites (8 bytes on x64,
    # 4 bytes on x86; allow some slack for adjacent entries).
    for primitive in finding.primitives:
        if primitive.kind == PrimitiveKind.WRITE and primitive.size is not None:
            if primitive.size <= 16:
                return True
    return False


def _classic_dll_injection_pattern(
    finding: Finding,
    apis_lower: set[str],
    cross_process: bool,
) -> bool:
    if not cross_process:
        return False
    if not _has_any(
        apis_lower,
        "virtualallocex",
        "virtualallocexnuma",
        "ntallocatevirtualmemory",
        "zwallocatevirtualmemory",
    ):
        return False
    if not _has_any(
        apis_lower,
        "writeprocessmemory",
        "ntwritevirtualmemory",
        "zwwritevirtualmemory",
    ):
        return False
    if not _has_any(
        apis_lower,
        "createremotethread",
        "createremotethreadex",
        "ntcreatethreadex",
        "rtlcreateuserthread",
        "zwcreatethreadex",
    ):
        return False
    execute_primitives = [p for p in finding.primitives if p.kind == PrimitiveKind.EXECUTE]
    write_primitives = [p for p in finding.primitives if p.kind == PrimitiveKind.WRITE]
    for execute in execute_primitives:
        parameter = _detail_int(execute.details.get("thread_parameter"))
        if parameter is None:
            continue
        for write in write_primitives:
            if write.address is None or write.address == 0:
                continue
            write_size = write.size if write.size is not None and write.size > 0 else 1
            if write.address <= parameter < write.address + write_size:
                return True
    return False


def _detail_int(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value if value != 0 else None
    if isinstance(value, str):
        try:
            parsed = int(value, 0)
        except ValueError:
            return None
        return parsed if parsed != 0 else None
    return None


_RESUME_THREAD_APIS = frozenset(
    {
        "resumethread",
        "ntresumethread",
        "ntalertresumethread",
        "zwresumethread",
    }
)
_REFLECTIVE_THREAD_CREATE_APIS = frozenset(
    {
        "createremotethread",
        "createremotethreadex",
        "ntcreatethreadex",
        "rtlcreateuserthread",
        "zwcreatethreadex",
        "ntcreatethread",
        "queueuserapc",
        "ntqueueapcthread",
        "ntqueueapcthreadex",
    }
)


def _execute_apis_lower(finding: Finding) -> set[str]:
    return {primitive.api.lower() for primitive in finding.primitives if primitive.kind == PrimitiveKind.EXECUTE}


def _resume_only_execution(execute_apis_lower: set[str]) -> bool:
    return bool(execute_apis_lower) and execute_apis_lower <= _RESUME_THREAD_APIS


def _reflective_dll_pattern(
    apis_lower: set[str],
    kinds: set[PrimitiveKind],
    cross_process: bool,
    *,
    execute_apis_lower: set[str],
) -> bool:
    if not cross_process or PrimitiveKind.WRITE not in kinds or PrimitiveKind.EXECUTE not in kinds:
        return False
    if apis_lower & {"loadlibrarya", "loadlibraryw", "loadlibraryexa", "loadlibraryexw", "ldrloaddll"}:
        return False
    # Allocate + WriteProcessMemory + ResumeThread is classic suspended-process
    # transfer (installers, hollowing), not reflective DLL loading.
    if _resume_only_execution(execute_apis_lower):
        return False
    has_local_copy = bool(apis_lower & {"memcpy", "rtlmovememory"})
    has_remote_write = bool(
        apis_lower
        & {
            "writeprocessmemory",
            "ntwritevirtualmemory",
            "zwwritevirtualmemory",
        }
    )
    has_thread_create = bool(apis_lower & _REFLECTIVE_THREAD_CREATE_APIS)
    if has_local_copy:
        return bool(
            apis_lower
            & {
                "virtualalloc",
                "ntallocatevirtualmemory",
                "zwallocatevirtualmemory",
            }
        )
    return has_remote_write and has_thread_create


def process_flags_hint(process: ProcessEvent | None) -> list[str]:
    if process is None:
        return []
    return list(process.flags)
