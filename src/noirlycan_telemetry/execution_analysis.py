"""Distinguish real execution transfer from context-read / hijack-prep APIs."""

from __future__ import annotations

from typing import Any

from .models import MemoryPrimitive, PrimitiveKind

# APIs that actually initiate or transfer execution in a target process.
EXECUTION_TRANSFER_APIS: frozenset[str] = frozenset(
    {
        "SetThreadContext",
        "NtSetContextThread",
        "ZwSetContextThread",
        "ResumeThread",
        "NtResumeThread",
        "NtAlertResumeThread",
        "ZwResumeThread",
        "CreateRemoteThread",
        "CreateRemoteThreadEx",
        "NtCreateThreadEx",
        "NtCreateThread",
        "RtlCreateUserThread",
        "ZwCreateThreadEx",
        "QueueUserAPC",
        "NtQueueApcThread",
        "NtQueueApcThreadEx",
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
        "CreateThread",
    }
)

# Read-only thread context inspection — preparation, not execution transfer.
CONTEXT_READ_APIS: frozenset[str] = frozenset(
    {
        "GetThreadContext",
        "NtGetContextThread",
        "ZwGetContextThread",
    }
)


def is_execution_transfer_api(api: str) -> bool:
    normalized = api.strip()
    if normalized in EXECUTION_TRANSFER_APIS:
        return True
    if normalized.startswith("Zw") and f"Nt{normalized[2:]}" in EXECUTION_TRANSFER_APIS:
        return True
    return False


def is_context_read_api(api: str) -> bool:
    normalized = api.strip()
    if normalized in CONTEXT_READ_APIS:
        return True
    if normalized.startswith("Zw") and f"Nt{normalized[2:]}" in CONTEXT_READ_APIS:
        return True
    return False


def analyze_execution(primitives: list[MemoryPrimitive]) -> dict[str, Any]:
    execution_evidence = sorted(
        {primitive.api for primitive in primitives if is_execution_transfer_api(primitive.api)}
    )
    context_read_evidence = sorted(
        {primitive.api for primitive in primitives if is_context_read_api(primitive.api)}
    )
    execution_confirmed = len(execution_evidence) > 0
    missing_execution_transfer = not execution_confirmed and (
        PrimitiveKind.ALLOCATE in {p.kind for p in primitives}
        or PrimitiveKind.WRITE in {p.kind for p in primitives}
        or bool(context_read_evidence)
    )
    paper_kinds = {
        primitive.kind
        for primitive in primitives
        if primitive.kind in {PrimitiveKind.ALLOCATE, PrimitiveKind.WRITE, PrimitiveKind.EXECUTE}
    }
    return {
        "execution_confirmed": execution_confirmed,
        "execution_evidence": execution_evidence,
        "context_read_evidence": context_read_evidence,
        "missing_execution_transfer": missing_execution_transfer,
        "paper_primitive_kinds": sorted(kind.value for kind in paper_kinds),
        "has_context_read": bool(context_read_evidence),
    }


def operational_kind_count(kinds: set[PrimitiveKind]) -> int:
    """Count ASIA CCS paper primitives (allocate / write / real execute only)."""
    paper = {PrimitiveKind.ALLOCATE, PrimitiveKind.WRITE, PrimitiveKind.EXECUTE}
    return len(kinds & paper)
