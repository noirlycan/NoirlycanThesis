"""Risk score and severity for a chain that already passed the paper's rules.

The paper only decides *injection or not* (§3.2). Scoring is a lab extension:
it ranks findings for the analyst and adds provenance context (dropped file,
CREATE_SUSPENDED spawn, executable protection, …). It never turns a chain that
failed the paper's rules into a finding.
"""

from __future__ import annotations

from noirlycan_core.detection.primitives import analyze_execution, operational_kind_count
from noirlycan_core.detection.rules import detail_int
from noirlycan_core.models import FileEvent, MemoryPrimitive, PrimitiveKind, ProcessEvent, Severity
from noirlycan_core.runtime.agent_policy import AgentPolicy

_REMOTE_THREAD_APIS = frozenset(
    {"createremotethread", "createremotethreadex", "ntcreatethreadex", "rtlcreateuserthread"}
)
_RESUME_THREAD_APIS = frozenset(
    {"resumethread", "ntresumethread", "ntalertresumethread", "zwresumethread"}
)
# APIs that make a resume-only chain look like real hollowing, not an installer spawn.
_INJECTION_STRENGTH_APIS = frozenset(
    {
        "ntmapviewofsection",
        "zwmapviewofsection",
        "setthreadcontext",
        "ntsetcontextthread",
        "zwsetcontextthread",
        "getthreadcontext",
        "ntgetcontextthread",
        "zwgetcontextthread",
    }
)
_TRUSTED_TARGET_MARKERS = ("\\program files\\", "\\program files (x86)\\")


def score_chain(
    primitives: list[MemoryPrimitive],
    process: ProcessEvent | None,
    related_file: FileEvent | None,
) -> tuple[int, dict[str, object]]:
    """Return a 0–100 score and the evidence that produced it."""
    kinds = {primitive.kind for primitive in primitives}
    evidence: dict[str, object] = {
        "apis": sorted({primitive.api for primitive in primitives}),
        "primitive_kinds": sorted(kind.value for kind in kinds),
    }
    evidence.update(analyze_execution(primitives))
    execution_confirmed = bool(evidence["execution_confirmed"])
    score = 0

    # Core primitives.
    if PrimitiveKind.WRITE in kinds and PrimitiveKind.EXECUTE in kinds and execution_confirmed:
        score += 45
    elif operational_kind_count(kinds) >= 2:
        score += 35
    if {PrimitiveKind.ALLOCATE, PrimitiveKind.WRITE, PrimitiveKind.EXECUTE} <= kinds and execution_confirmed:
        score += 20
    if PrimitiveKind.CONTEXT_READ in kinds and not execution_confirmed:
        score += 5
        evidence["hijack_prep"] = True
    if evidence["missing_execution_transfer"]:
        score = min(score, 75)

    # Memory and process context.
    has_executable_protection = any(
        "EXECUTE" in primitive.details.get("protection", "").upper() for primitive in primitives
    )
    is_cross_process = any(
        primitive.target_pid and primitive.target_pid != primitive.actor_pid for primitive in primitives
    )
    if is_cross_process:
        score += 15
        evidence["cross_process"] = True
    elif {PrimitiveKind.ALLOCATE, PrimitiveKind.WRITE} <= kinds and has_executable_protection:
        score += 10
        evidence["local_staging"] = True
    if _is_dll_path_remote_thread(primitives):
        score += 5
        evidence["dll_path_remote_thread"] = True
    if any("section" in primitive.api.lower() for primitive in primitives):
        score += 10
        evidence["section_mapping"] = True
    if any(primitive.details.get("txf") for primitive in primitives):
        evidence["txf_transaction"] = True
    if any(primitive.details.get("process_reflection") for primitive in primitives):
        evidence["process_reflection"] = True
    if has_executable_protection:
        score += 10
        evidence["executable_protection"] = True

    # Provenance (repo extension: dropped file → process lineage).
    if process is not None and any(flag.upper() == "CREATE_SUSPENDED" for flag in process.flags):
        score += 15
        evidence["create_suspended"] = True
    if process is not None and process.parent_image:
        evidence["parent_image"] = process.parent_image
    if related_file is not None:
        score += 10
        evidence["related_file"] = related_file.path
        if related_file.pe:
            score += 5
        if related_file.signed is False:
            score += 10
        if related_file.entropy is not None and related_file.entropy >= 7.0:
            score += 5

    # False-positive damping.
    if _is_resume_only_spawn_to_trusted_target(primitives, evidence):
        score = min(score, 50)
        evidence["likely_installer_spawn"] = True
    return min(score, 100), evidence


def severity_for(score: int, policy: AgentPolicy | None = None) -> Severity:
    if policy is None:
        thresholds = (85, 70, 50)
    else:
        thresholds = (policy.score_crit, policy.score_high, policy.score_med)
    critical, high, medium = thresholds
    if score >= critical:
        return Severity.CRITICAL
    if score >= high:
        return Severity.HIGH
    if score >= medium:
        return Severity.MEDIUM
    return Severity.LOW


def describe_chain(
    primitives: list[MemoryPrimitive],
    process: ProcessEvent | None,
    related_file: FileEvent | None,
    *,
    actor_image: str | None = None,
    target_image: str | None = None,
) -> str:
    first = primitives[0]
    actor = actor_image or (process.image if process else None) or f"pid {first.actor_pid}"
    if first.target_pid is None:
        target = target_image or first.target_image or "pid None"
    elif target_image:
        target = f"{target_image} (pid {first.target_pid})"
    else:
        target = f"pid {first.target_pid}"
    kinds = ", ".join(sorted({primitive.kind.value for primitive in primitives}))
    file_part = f" Related file: {related_file.path}." if related_file else ""
    return f"{actor} performed correlated {kinds} primitives against {target}.{file_part}"


def _is_dll_path_remote_thread(primitives: list[MemoryPrimitive]) -> bool:
    """Classic DLL injection: remote thread whose parameter points into a written path buffer."""
    writes = [p for p in primitives if p.kind == PrimitiveKind.WRITE and p.address]
    for execute in primitives:
        if execute.kind != PrimitiveKind.EXECUTE or execute.api.lower() not in _REMOTE_THREAD_APIS:
            continue
        parameter = detail_int(execute.details.get("thread_parameter"))
        if parameter is None:
            continue
        for write in writes:
            size = write.size if write.size and write.size > 0 else 1
            if write.address <= parameter < write.address + size:
                return True
    return False


def _is_resume_only_spawn_to_trusted_target(
    primitives: list[MemoryPrimitive],
    evidence: dict[str, object],
) -> bool:
    """A cross-process chain whose only execute is ResumeThread into Program Files."""
    if not evidence.get("cross_process"):
        return False
    execute_apis = {p.api.lower() for p in primitives if p.kind == PrimitiveKind.EXECUTE}
    if not execute_apis or not execute_apis <= _RESUME_THREAD_APIS:
        return False
    if {p.api.lower() for p in primitives} & _INJECTION_STRENGTH_APIS:
        return False
    return any(
        marker in (primitive.target_image or "").lower()
        for primitive in primitives
        for marker in _TRUSTED_TARGET_MARKERS
    )
