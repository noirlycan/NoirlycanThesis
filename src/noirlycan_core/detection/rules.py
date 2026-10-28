"""The three validation rules of the paper's analysis module.

Di Pietro, D'Elia, Querzoni — "Can You Run My Code?" (ASIA CCS '25), §3.2:

1. **Minimal core operations** — at least two of the three operational
   primitives (allocate / write / execute) must be observed.
2. **Memory congruence** — the primitives must touch congruent address ranges
   inside the victim; unrelated buffers are discarded as false positives.
3. **Temporal consistency** — allocate precedes write, which precedes execute.
   Steps may combine (section mapping) and allocations may repeat, but a step
   may not move backwards.

Every function here is pure: it takes the primitives of one (actor, victim)
chain and returns a verdict. Scoring and enrichment live elsewhere.
"""

from __future__ import annotations

from collections import defaultdict

from noirlycan_core.detection.primitives import operational_kind_count
from noirlycan_core.models import MemoryPrimitive, PrimitiveKind

MemoryRange = tuple[int, int]

# Changing the protection of an existing region (RW → RX after the payload is
# written) belongs to the allocate class but does not create a new buffer, so
# it is not bound by the allocate-before-write order.
_PROTECTION_CHANGE_APIS = frozenset(
    {"virtualprotect", "virtualprotectex", "ntprotectvirtualmemory", "zwprotectvirtualmemory"}
)

_TEMPORAL_RANK = {
    PrimitiveKind.ALLOCATE: 0,
    PrimitiveKind.WRITE: 1,
    PrimitiveKind.EXECUTE: 3,
}


def has_minimal_core_operations(primitives: list[MemoryPrimitive], minimum: int = 2) -> bool:
    """Rule 1: enough distinct paper primitives (CONTEXT_READ does not count)."""
    return operational_kind_count({primitive.kind for primitive in primitives}) >= minimum


def has_temporal_consistency(primitives: list[MemoryPrimitive]) -> bool:
    """Rule 3: reject an ALLOCATE or WRITE that appears after a later-stage primitive.

    CONTEXT_READ and protection changes are never rejected.
    """
    highest_rank = -1
    for primitive in sorted(primitives, key=lambda item: item.timestamp):
        rank = _TEMPORAL_RANK.get(primitive.kind)
        if rank is None or primitive.api.lower() in _PROTECTION_CHANGE_APIS:
            continue
        if rank < highest_rank and primitive.kind in {PrimitiveKind.ALLOCATE, PrimitiveKind.WRITE}:
            return False
        highest_rank = max(highest_rank, rank)
    return True


def has_memory_congruence(primitives: list[MemoryPrimitive]) -> bool:
    """Rule 2: two primitives of different kinds touch overlapping ranges.

    Practical extensions over the paper, each needed because a user-mode hook
    does not always see the address the paper's tracer sees:

    * ``address == 0`` is treated as missing (failed hook read).
    * ``thread_parameter`` on execute primitives links CreateRemoteThread
      (LoadLibraryW + remote path buffer) to a prior allocate/write.
    * ``context_pointer`` links Get/NtGetContextThread to Set/NtSetContextThread.
    * With fewer than two address-bearing primitives the rule cannot be
      evaluated and passes.
    * If only one kind carries addresses (typically WRITE, because
      NtAllocateVirtualMemory returns no usable base to the hook) but the chain
      already has two operational kinds, the chain is accepted.
    """
    ranges_by_kind: dict[PrimitiveKind, list[list[MemoryRange]]] = defaultdict(list)
    for primitive in primitives:
        ranges = memory_ranges(primitive)
        if ranges:
            ranges_by_kind[primitive.kind].append(ranges)

    if sum(len(groups) for groups in ranges_by_kind.values()) < 2:
        return True

    for left_kind, left_groups in ranges_by_kind.items():
        for right_kind, right_groups in ranges_by_kind.items():
            if left_kind == right_kind:
                continue
            for left in left_groups:
                for right in right_groups:
                    if ranges_overlap(left, right):
                        return True

    kinds = {primitive.kind for primitive in primitives}
    return operational_kind_count(kinds) >= 2 and len(ranges_by_kind) == 1


def memory_ranges(primitive: MemoryPrimitive) -> list[MemoryRange]:
    """Half-open address ranges a primitive touches in the victim."""
    ranges: list[MemoryRange] = []
    if primitive.address:
        size = primitive.size if primitive.size and primitive.size > 0 else 1
        ranges.append((primitive.address, primitive.address + size))
    if primitive.kind == PrimitiveKind.EXECUTE:
        parameter = detail_int(primitive.details.get("thread_parameter"))
        if parameter is not None:
            ranges.append((parameter, parameter + 1))
    pointer = detail_int(primitive.details.get("context_pointer"))
    if pointer is not None:
        ranges.append((pointer, pointer + 1))
    return ranges


def ranges_overlap(left: list[MemoryRange], right: list[MemoryRange]) -> bool:
    return any(
        left_start < right_end and right_start < left_end
        for left_start, left_end in left
        for right_start, right_end in right
    )


def detail_int(value: object) -> int | None:
    """Parse an address-like detail field; 0 and unparsable values mean missing."""
    if isinstance(value, int):
        return value or None
    if isinstance(value, str):
        try:
            return int(value, 0) or None
        except ValueError:
            return None
    return None
