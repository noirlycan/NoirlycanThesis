"""Infer payload shape (PE, shellcode, DLL) from finding primitives and triage."""

from __future__ import annotations

from enum import Enum
from typing import Any

from .models import FileEvent, Finding, PrimitiveKind


class PayloadKind(str, Enum):
    PE_IMAGE = "pe_image"
    PE_HOLLOWING = "pe_hollowing"
    SHELLCODE = "shellcode"
    DLL_PATH = "dll_path"
    REFLECTIVE_DLL = "reflective_dll"
    UNKNOWN = "unknown"


_DLL_LOAD_APIS = frozenset(
    {
        "loadlibrarya",
        "loadlibraryw",
        "loadlibraryexa",
        "loadlibraryexw",
        "ldrloaddll",
    }
)

_SHELLCODE_CHAIN_APIS = frozenset(
    {
        "virtualallocex",
        "virtualallocexnuma",
        "ntallocatevirtualmemory",
        "zwallocatevirtualmemory",
        "writeprocessmemory",
        "ntwritevirtualmemory",
        "zwwritevirtualmemory",
        "createremotethread",
        "createremotethreadex",
        "ntcreatethreadex",
        "rtlcreateuserthread",
        "zwcreatethreadex",
    }
)

_SECTION_CHAIN_APIS = frozenset(
    {
        "ntcreatesection",
        "zwcreatesection",
        "ntmapviewofsection",
        "zwmapviewofsection",
        "createfilemappinga",
        "createfilemappingw",
    }
)


def infer_payload_kind(
    finding: Finding,
    related_file: FileEvent | None = None,
) -> tuple[PayloadKind, str]:
    apis_lower = {primitive.api.lower() for primitive in finding.primitives}
    kinds = {primitive.kind for primitive in finding.primitives}
    evidence = finding.evidence or {}
    cross_process = bool(evidence.get("cross_process"))
    section_mapping = bool(evidence.get("section_mapping"))
    create_suspended = bool(evidence.get("create_suspended"))
    file_event = related_file or finding.related_file

    if apis_lower & _DLL_LOAD_APIS and cross_process:
        modules = [
            primitive.details.get("module")
            for primitive in finding.primitives
            if primitive.details.get("module")
        ]
        if modules:
            return PayloadKind.DLL_PATH, f"Remote DLL load: {modules[0]}"
        return PayloadKind.DLL_PATH, "Remote DLL load primitive without module path."

    has_remote_write = cross_process and PrimitiveKind.WRITE in kinds
    has_execute = PrimitiveKind.EXECUTE in kinds and bool(evidence.get("execution_confirmed"))

    if file_event and file_event.pe and (create_suspended or "ntunmapviewofsection" in apis_lower):
        return PayloadKind.PE_HOLLOWING, "PE file on disk with suspended spawn or unmap (process hollowing)."

    if file_event and file_event.pe and has_remote_write:
        return PayloadKind.PE_IMAGE, "PE sample correlated with remote memory write."

    execute_apis_lower = {primitive.api.lower() for primitive in finding.primitives if primitive.kind == PrimitiveKind.EXECUTE}
    resume_only = bool(execute_apis_lower) and execute_apis_lower <= {
        "resumethread",
        "ntresumethread",
        "ntalertresumethread",
        "zwresumethread",
    }
    reflective_signals = (
        has_remote_write
        and has_execute
        and not resume_only
        and not (apis_lower & _DLL_LOAD_APIS)
        and any(
            primitive.details.get("module") is None
            for primitive in finding.primitives
            if primitive.kind == PrimitiveKind.EXECUTE
        )
    )
    has_thread_create = bool(
        apis_lower
        & {
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
    if reflective_signals and (
        apis_lower & {"memcpy", "rtlmovememory"}
        or has_thread_create
    ):
        return PayloadKind.REFLECTIVE_DLL, "Remote write + thread/APC execute without DLL path (reflective pattern)."
    if has_remote_write and has_execute and resume_only:
        return PayloadKind.PE_IMAGE, "Remote write + thread resume (suspended-process / installer pattern)."

    if section_mapping and not file_event:
        return PayloadKind.SHELLCODE, "Section mapping chain without on-disk PE correlation."

    if len(_SHELLCODE_CHAIN_APIS & apis_lower) >= 3 or (
        cross_process
        and PrimitiveKind.ALLOCATE in kinds
        and PrimitiveKind.WRITE in kinds
        and has_execute
        and not (apis_lower & _SECTION_CHAIN_APIS)
    ):
        return PayloadKind.SHELLCODE, "Classic allocate + write + remote execute (shellcode pattern)."

    if file_event and file_event.pe:
        return PayloadKind.PE_IMAGE, "Related PE file; injection payload type unclear."

    if cross_process and has_remote_write:
        return PayloadKind.SHELLCODE, "Remote memory write without PE correlation (likely shellcode)."

    return PayloadKind.UNKNOWN, "Insufficient static or API evidence to classify payload."


def payload_metadata(
    finding: Finding,
    related_file: FileEvent | None = None,
) -> dict[str, Any]:
    kind, rationale = infer_payload_kind(finding, related_file)
    return {
        "payload_kind": kind.value,
        "payload_rationale": rationale,
    }
