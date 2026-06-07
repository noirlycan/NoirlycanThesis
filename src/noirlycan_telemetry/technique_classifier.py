"""Rule-based injection technique classifier (ASIA CCS 2025 Appendix A subset)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from .execution_analysis import analyze_execution
from .models import Finding, MemoryPrimitive, PrimitiveKind, ProcessEvent


class InjectionTechnique(str, Enum):
    SECTION_MAPPING_INJECTION = "section_mapping_injection"
    PROCESS_HOLLOWING_SECTION = "process_hollowing_section"
    PROCESS_HOLLOWING_CLASSIC = "process_hollowing_classic"
    SHELLCODE_INJECTION = "shellcode_injection"
    APC_INJECTION = "apc_injection"
    THREAD_HIJACK = "thread_hijack"
    DLL_INJECTION = "dll_injection"
    PROCESS_SPAWN_INJECT = "process_spawn_inject"
    MODULE_STOMPING = "module_stomping"
    ATOM_INJECTION = "atom_injection"
    HOOK_INJECTION = "hook_injection"
    LOCAL_SELF_INJECT = "local_self_inject"
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


def classify_finding(finding: Finding) -> TechniqueClassification:
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

    if _is_local_only(finding):
        return TechniqueClassification(
            technique=InjectionTechnique.LOCAL_SELF_INJECT,
            confidence=_confidence_from_kinds(kinds, minimum=2),
            rationale="Primitives target the same process (self-injection / local staging).",
        )

    if _has_any(apis_lower, "setwindowshookexa", "setwindowshookexw"):
        return TechniqueClassification(
            technique=InjectionTechnique.HOOK_INJECTION,
            confidence=TechniqueConfidence.HIGH,
            rationale="SetWindowsHookEx used to schedule code in another process.",
        )

    if _has_any(apis_lower, "ntaddatom", "globaladdatoma", "globaladdatomw"):
        return TechniqueClassification(
            technique=InjectionTechnique.ATOM_INJECTION,
            confidence=TechniqueConfidence.MEDIUM,
            rationale="Global/NT atom APIs observed in execute stage.",
        )

    if _has_any(apis_lower, "ldrloaddll", "loadlibrarya", "loadlibraryw", "loadlibraryexa", "loadlibraryexw"):
        if cross_process or _target_differs_from_actor(finding):
            return TechniqueClassification(
                technique=InjectionTechnique.DLL_INJECTION,
                confidence=TechniqueConfidence.HIGH if PrimitiveKind.EXECUTE in kinds else TechniqueConfidence.MEDIUM,
                rationale="Remote DLL load primitive observed.",
            )

    if _has_any(apis_lower, "ntqueueapcthread", "ntqueueapcthreadex", "queueuserapc"):
        return TechniqueClassification(
            technique=InjectionTechnique.APC_INJECTION,
            confidence=_confidence_from_kinds(kinds, minimum=2),
            rationale="APC queue API used to trigger execution in a remote thread.",
        )

    if section_mapping or _has_any(
        apis_lower,
        "ntcreatesection",
        "ntmapviewofsection",
        "zwcreatesection",
        "zwmapviewofsection",
        "createfilemappinga",
        "createfilemappingw",
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
        if create_suspended or _has_any(apis_lower, "ntunmapviewofsection", "zwunmapviewofsection"):
            return TechniqueClassification(
                technique=InjectionTechnique.PROCESS_HOLLOWING_SECTION,
                confidence=TechniqueConfidence.HIGH,
                rationale="Suspended/spawned victim with section mapping and confirmed execution transfer.",
            )
        return TechniqueClassification(
            technique=InjectionTechnique.PROCESS_HOLLOWING_SECTION,
            confidence=TechniqueConfidence.HIGH,
            rationale="Section mapping with confirmed execution transfer.",
        )

    if _has_any(apis_lower, "ntunmapviewofsection") and PrimitiveKind.WRITE in kinds:
        return TechniqueClassification(
            technique=InjectionTechnique.MODULE_STOMPING,
            confidence=TechniqueConfidence.MEDIUM,
            rationale="Remote unmap followed by write primitive (module stomping pattern).",
        )

    if create_suspended and cross_process:
        return TechniqueClassification(
            technique=InjectionTechnique.PROCESS_SPAWN_INJECT,
            confidence=_confidence_from_kinds(kinds, minimum=2),
            rationale="Victim created suspended then injection primitives observed.",
        )

    if _has_any(
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

    if _has_any(
        apis_lower,
        "setthreadcontext",
        "ntsetcontextthread",
        "zwsetcontextthread",
    ) or _has_any(apis_lower, "resumethread", "ntresumethread", "ntalertresumethread", "zwresumethread"):
        if _has_any(apis_lower, "setthreadcontext", "ntsetcontextthread", "zwsetcontextthread"):
            return TechniqueClassification(
                technique=InjectionTechnique.THREAD_HIJACK,
                confidence=_confidence_from_kinds(kinds, minimum=2),
                rationale="Thread context manipulation used to redirect execution.",
            )
        if create_suspended:
            return TechniqueClassification(
                technique=InjectionTechnique.PROCESS_HOLLOWING_CLASSIC,
                confidence=_confidence_from_kinds(kinds, minimum=2),
                rationale="Suspended process resumed after remote memory manipulation.",
            )

    return TechniqueClassification(
        technique=InjectionTechnique.UNCLASSIFIED,
        confidence=TechniqueConfidence.LOW if len(kinds) < 3 else TechniqueConfidence.MEDIUM,
        rationale="Injection primitives detected but no specific technique rule matched.",
    )


def apply_classification(finding: Finding) -> Finding:
    result = classify_finding(finding)
    evidence = dict(finding.evidence)
    execution_meta = analyze_execution(list(finding.primitives))
    evidence.update(execution_meta)
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


def process_flags_hint(process: ProcessEvent | None) -> list[str]:
    if process is None:
        return []
    return list(process.flags)
