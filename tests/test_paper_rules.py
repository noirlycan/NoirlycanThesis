"""Unit tests for the paper's three validation rules (ASIA CCS '25 §3.2)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from noirlycan_core.detection.rules import (
    has_memory_congruence,
    has_minimal_core_operations,
    has_temporal_consistency,
)
from noirlycan_core.models import MemoryPrimitive, PrimitiveKind

ALLOCATE, WRITE, EXECUTE, CONTEXT_READ = (
    PrimitiveKind.ALLOCATE,
    PrimitiveKind.WRITE,
    PrimitiveKind.EXECUTE,
    PrimitiveKind.CONTEXT_READ,
)
T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _p(
    kind: PrimitiveKind,
    t: int,
    address: int | None = None,
    size: int | None = None,
    api: str | None = None,
    **details,
) -> MemoryPrimitive:
    return MemoryPrimitive(
        timestamp=T0 + timedelta(milliseconds=t),
        kind=kind,
        actor_pid=100,
        actor_image=None,
        target_pid=200,
        target_image=None,
        address=address,
        size=size,
        api=api or kind.value,
        details=details,
    )


# Rule 1 — minimal core operations (2 of 3).

def test_two_distinct_primitives_are_enough() -> None:
    assert has_minimal_core_operations([_p(WRITE, 0), _p(EXECUTE, 1)])


def test_repeated_primitive_of_one_kind_is_not_enough() -> None:
    assert not has_minimal_core_operations([_p(ALLOCATE, 0), _p(ALLOCATE, 1)])


def test_context_read_is_not_a_paper_primitive() -> None:
    assert not has_minimal_core_operations([_p(WRITE, 0), _p(CONTEXT_READ, 1)])


def test_threshold_can_be_raised_to_three() -> None:
    assert not has_minimal_core_operations([_p(WRITE, 0), _p(EXECUTE, 1)], minimum=3)


# Rule 2 — memory congruence.

def test_overlapping_allocate_and_write_are_congruent() -> None:
    assert has_memory_congruence([_p(ALLOCATE, 0, 0x1000, 0x1000), _p(WRITE, 1, 0x1800, 0x10)])


def test_disjoint_buffers_are_rejected() -> None:
    # Paper Figure 3: allocation and write on unrelated ranges are not an injection.
    assert not has_memory_congruence([_p(ALLOCATE, 0, 0xA000, 0x100), _p(WRITE, 1, 0x5C000, 0x100)])


def test_remote_thread_parameter_links_to_written_buffer() -> None:
    chain = [_p(WRITE, 0, 0x3000, 0x40), _p(EXECUTE, 1, 0x7FF0_0000, None, thread_parameter="0x3010")]
    assert has_memory_congruence(chain)


def test_zero_address_counts_as_missing() -> None:
    assert has_memory_congruence([_p(ALLOCATE, 0, 0, 0x1000), _p(WRITE, 1, 0x5000, 0x10)])


# Rule 3 — temporal consistency.

def test_canonical_order_is_accepted() -> None:
    assert has_temporal_consistency([_p(ALLOCATE, 0), _p(WRITE, 1), _p(EXECUTE, 2)])


def test_new_allocation_after_write_is_rejected() -> None:
    assert not has_temporal_consistency([_p(WRITE, 0), _p(EXECUTE, 1), _p(ALLOCATE, 2, api="VirtualAllocEx")])


def test_protection_change_after_write_is_accepted() -> None:
    # Classic shellcode injection: RW allocation, write, flip to RX, remote thread.
    chain = [
        _p(ALLOCATE, 0, api="VirtualAllocEx"),
        _p(WRITE, 1, api="WriteProcessMemory"),
        _p(ALLOCATE, 2, api="VirtualProtectEx"),
        _p(EXECUTE, 3, api="CreateRemoteThread"),
    ]
    assert has_temporal_consistency(chain)


def test_write_after_execute_is_rejected() -> None:
    assert not has_temporal_consistency([_p(EXECUTE, 0), _p(WRITE, 1)])


def test_repeated_allocation_before_write_is_accepted() -> None:
    assert has_temporal_consistency([_p(ALLOCATE, 0), _p(ALLOCATE, 1), _p(WRITE, 2)])


def test_context_read_never_breaks_order() -> None:
    assert has_temporal_consistency([_p(WRITE, 0), _p(CONTEXT_READ, 1), _p(EXECUTE, 2)])


def test_order_uses_timestamps_not_arrival_order() -> None:
    assert has_temporal_consistency([_p(EXECUTE, 2), _p(ALLOCATE, 0), _p(WRITE, 1)])
