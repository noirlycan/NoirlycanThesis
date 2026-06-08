from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path, PureWindowsPath

from .execution_analysis import analyze_execution, operational_kind_count
from .injection_graph import InjectionGraph
from .process_resolve import image_for_pid as resolve_image_for_pid
from .classifier_config import load_classifier_config
from .technique_classifier import apply_classification
from .models import (
    FileEvent,
    Finding,
    MemoryPrimitive,
    NetworkConnectionEvent,
    PrimitiveKind,
    ProcessEvent,
    Severity,
)


NETWORK_WATCH_MIN_SCORE = 70
NETWORK_WATCH_SECONDS = 300


class Correlator:
    """Stateful file/process/injection correlation engine."""

    def __init__(
        self,
        window_seconds: int = 300,
        minimum_score: int = 50,
        logs_dir: str | Path | None = None,
    ) -> None:
        self.window = timedelta(seconds=window_seconds)
        self.minimum_score = minimum_score
        self.logs_dir = logs_dir
        self.files_by_path: dict[str, FileEvent] = {}
        self.processes_by_pid: dict[int, ProcessEvent] = {}
        self.primitives: deque[MemoryPrimitive] = deque()
        self._reported_chain_scores: dict[tuple[int, int | None], int] = {}
        self._network_watch_until: dict[int, datetime] = {}
        self.network_connections: dict[int, list[NetworkConnectionEvent]] = defaultdict(list)
        self._pid_image_cache: dict[int, str] = {}
        self._injection_graph = InjectionGraph()

    def add_file(self, event: FileEvent) -> None:
        if event.path:
            self.files_by_path[_norm_path(event.path)] = event
        self._expire(event.timestamp)

    def add_process(self, event: ProcessEvent) -> None:
        related_file = self.files_by_path.get(_norm_path(event.image))
        if related_file is not None and event.created_from_file is None:
            event = ProcessEvent(
                timestamp=event.timestamp,
                pid=event.pid,
                image=event.image,
                command_line=event.command_line,
                parent_pid=event.parent_pid,
                parent_image=event.parent_image,
                created_from_file=related_file.path,
                flags=event.flags,
            )
        self.processes_by_pid[event.pid] = event
        self._expire(event.timestamp)

    def add_primitive(self, event: MemoryPrimitive) -> list[Finding]:
        enriched = self._enrich_primitive(event)
        self.primitives.append(enriched)
        self._expire(enriched.timestamp)
        return self._find_injection_chains(enriched)

    def add_network_connection(self, event: NetworkConnectionEvent) -> NetworkConnectionEvent | None:
        self._expire(event.timestamp)
        if event.pid not in self._active_network_watch_pids(event.timestamp):
            return None
        self.network_connections[event.pid].append(event)
        return event

    def _find_injection_chains(self, latest: MemoryPrimitive) -> list[Finding]:
        grouped: dict[tuple[int, int | None], list[MemoryPrimitive]] = defaultdict(list)
        for primitive in self.primitives:
            if primitive.actor_pid == latest.actor_pid and primitive.target_pid == latest.target_pid:
                grouped[(primitive.actor_pid, primitive.target_pid)].append(primitive)

        findings: list[Finding] = []
        rules_config = load_classifier_config(self.logs_dir)
        for (actor_pid, target_pid), primitives in grouped.items():
            kinds = {primitive.kind for primitive in primitives}
            if operational_kind_count(kinds) < rules_config.minimum_operational_kinds:
                continue
            if rules_config.ignore_same_process_findings and actor_pid == target_pid:
                continue
            if rules_config.require_cross_process_findings and (
                target_pid is None or target_pid == actor_pid
            ):
                continue
            if not _has_temporal_consistency(primitives):
                continue
            if not _has_memory_congruence(primitives):
                continue

            related_process = self.processes_by_pid.get(actor_pid)
            related_file = self._related_file_for_process(related_process)
            actor_image = self._resolve_process_image(actor_pid, primitives, related_process)
            target_image = self._resolve_process_image(target_pid, primitives, None)
            score, evidence = self._score(primitives, related_process, related_file)
            if actor_image:
                evidence["actor_image"] = actor_image
            if target_image:
                evidence["target_image"] = target_image
            minimum_score = rules_config.minimum_score
            if score < minimum_score:
                continue
            execution_meta = analyze_execution(primitives)
            title = (
                "Probable process injection chain"
                if execution_meta["execution_confirmed"]
                else "Probable injection staging chain"
            )
            chain_key = (actor_pid, target_pid)
            previous_score = self._reported_chain_scores.get(chain_key, 0)
            if score <= previous_score:
                continue
            self._reported_chain_scores[chain_key] = score
            if score >= NETWORK_WATCH_MIN_SCORE and target_pid is not None:
                self._network_watch_until[target_pid] = latest.timestamp + timedelta(
                    seconds=NETWORK_WATCH_SECONDS
                )
            finding = Finding(
                timestamp=latest.timestamp,
                severity=_severity(score),
                title=title,
                description=_describe(
                    primitives,
                    related_process,
                    related_file,
                    actor_image=actor_image,
                    target_image=target_image,
                ),
                actor_pid=actor_pid,
                target_pid=target_pid,
                primitives=tuple(sorted(primitives, key=lambda item: item.timestamp)),
                related_file=related_file,
                related_process=related_process,
                actor_image=actor_image,
                target_image=target_image,
                score=score,
                evidence=evidence,
            )
            finding = apply_classification(finding, logs_dir=self.logs_dir)
            finding = self._injection_graph.add_finding(finding)
            findings.append(finding)
        return findings

    def _active_network_watch_pids(self, now: datetime) -> set[int]:
        expired = [pid for pid, until in self._network_watch_until.items() if until < now]
        for pid in expired:
            del self._network_watch_until[pid]
        return set(self._network_watch_until)

    def _enrich_primitive(self, event: MemoryPrimitive) -> MemoryPrimitive:
        actor_image = event.actor_image or self._image_for_pid(event.actor_pid)
        target_image = event.target_image or self._image_for_pid(event.target_pid)
        if actor_image == event.actor_image and target_image == event.target_image:
            return event
        return replace(event, actor_image=actor_image, target_image=target_image)

    def _image_for_pid(self, pid: int | None) -> str | None:
        if pid is None:
            return None
        cached = self._pid_image_cache.get(pid)
        if cached:
            return cached
        process = self.processes_by_pid.get(pid)
        if process is not None and process.image:
            self._pid_image_cache[pid] = process.image
            return process.image
        resolved = resolve_image_for_pid(pid)
        if resolved:
            self._pid_image_cache[pid] = resolved
            if pid not in self.processes_by_pid:
                self.processes_by_pid[pid] = ProcessEvent(
                    timestamp=now_utc(),
                    pid=pid,
                    image=resolved,
                )
            return resolved
        return None

    def _resolve_process_image(
        self,
        pid: int | None,
        primitives: list[MemoryPrimitive],
        process: ProcessEvent | None,
    ) -> str | None:
        if process is not None and process.image:
            return process.image
        if pid is None:
            return None
        for primitive in primitives:
            if primitive.target_pid == pid and primitive.target_image:
                return primitive.target_image
            if primitive.actor_pid == pid and primitive.actor_image:
                return primitive.actor_image
        return self._image_for_pid(pid)

    def _related_file_for_process(self, process: ProcessEvent | None) -> FileEvent | None:
        if process is None:
            return None
        if process.created_from_file:
            return self.files_by_path.get(_norm_path(process.created_from_file))
        image_event = self.files_by_path.get(_norm_path(process.image))
        if image_event is not None:
            return image_event
        if process.parent_pid is not None:
            parent = self.processes_by_pid.get(process.parent_pid)
            if parent is not None:
                return self.files_by_path.get(_norm_path(parent.image))
        return None

    def _score(
        self,
        primitives: list[MemoryPrimitive],
        process: ProcessEvent | None,
        related_file: FileEvent | None,
    ) -> tuple[int, dict[str, object]]:
        kinds = {primitive.kind for primitive in primitives}
        apis = sorted({primitive.api for primitive in primitives})
        score = 0
        evidence: dict[str, object] = {
            "apis": apis,
            "primitive_kinds": sorted(kind.value for kind in kinds),
        }
        evidence.update(analyze_execution(primitives))

        execution_confirmed = bool(evidence.get("execution_confirmed"))
        if PrimitiveKind.WRITE in kinds and PrimitiveKind.EXECUTE in kinds and execution_confirmed:
            score += 45
        elif operational_kind_count(kinds) >= 2:
            score += 35
        if (
            PrimitiveKind.ALLOCATE in kinds
            and PrimitiveKind.WRITE in kinds
            and PrimitiveKind.EXECUTE in kinds
            and execution_confirmed
        ):
            score += 20
        if PrimitiveKind.CONTEXT_READ in kinds and not execution_confirmed:
            score += 5
            evidence["hijack_prep"] = True
        if evidence.get("missing_execution_transfer"):
            score = min(score, 75)
        has_executable_protection = any(
            primitive.details.get("protection", "").upper().find("EXECUTE") >= 0
            for primitive in primitives
        )
        is_cross_process = any(
            primitive.target_pid and primitive.target_pid != primitive.actor_pid
            for primitive in primitives
        )
        if is_cross_process:
            score += 15
            evidence["cross_process"] = True
        elif (
            PrimitiveKind.ALLOCATE in kinds
            and PrimitiveKind.WRITE in kinds
            and has_executable_protection
        ):
            score += 10
            evidence["local_staging"] = True
        if _dll_path_remote_thread_pattern(primitives):
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
        if _resume_only_spawn_to_trusted_target(primitives, evidence):
            score = min(score, 50)
            evidence["likely_installer_spawn"] = True
        return min(score, 100), evidence

    def _expire(self, now: datetime) -> None:
        cutoff = now - self.window
        while self.primitives and self.primitives[0].timestamp < cutoff:
            self.primitives.popleft()
        self.files_by_path = {
            path: event for path, event in self.files_by_path.items() if event.timestamp >= cutoff
        }
        self._active_network_watch_pids(now)
        for pid, connections in list(self.network_connections.items()):
            self.network_connections[pid] = [
                connection for connection in connections if connection.timestamp >= cutoff
            ]
            if not self.network_connections[pid]:
                del self.network_connections[pid]


_RESUME_THREAD_APIS = frozenset(
    {
        "resumethread",
        "ntresumethread",
        "ntalertresumethread",
        "zwresumethread",
    }
)
_TRUSTED_TARGET_MARKERS = ("\\program files\\", "\\program files (x86)\\")
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


def _resume_only_spawn_to_trusted_target(
    primitives: list[MemoryPrimitive],
    evidence: dict[str, object],
) -> bool:
    if not evidence.get("cross_process"):
        return False
    execute_apis = {primitive.api.lower() for primitive in primitives if primitive.kind == PrimitiveKind.EXECUTE}
    if not execute_apis or not execute_apis <= _RESUME_THREAD_APIS:
        return False
    apis_lower = {primitive.api.lower() for primitive in primitives}
    if apis_lower & _INJECTION_STRENGTH_APIS:
        return False
    for primitive in primitives:
        target = (primitive.target_image or "").lower()
        if any(marker in target for marker in _TRUSTED_TARGET_MARKERS):
            return True
    return False


def _has_temporal_consistency(primitives: list[MemoryPrimitive]) -> bool:
    """Enforce the paper's allocate → write → execute order.

    The paper (ASIA CCS '25 §3.4) requires that, ignoring repeated allocations
    and observation-only events, the operational primitives appear in the
    canonical order. We therefore reject any sequence where an ALLOCATE or
    WRITE primitive appears *after* a primitive of a strictly higher rank.
    CONTEXT_READ is informational and never causes rejection.
    """
    order = {
        PrimitiveKind.ALLOCATE: 0,
        PrimitiveKind.WRITE: 1,
        PrimitiveKind.CONTEXT_READ: 2,
        PrimitiveKind.EXECUTE: 3,
    }
    paper_kinds = {PrimitiveKind.ALLOCATE, PrimitiveKind.WRITE, PrimitiveKind.EXECUTE}
    sorted_primitives = sorted(primitives, key=lambda item: item.timestamp)
    last_paper_rank = -1
    for primitive in sorted_primitives:
        current = order.get(primitive.kind)
        if current is None:
            continue
        if primitive.kind in paper_kinds:
            if current < last_paper_rank and primitive.kind in {
                PrimitiveKind.ALLOCATE,
                PrimitiveKind.WRITE,
            }:
                return False
            last_paper_rank = max(last_paper_rank, current)
    return True


def _has_memory_congruence(primitives: list[MemoryPrimitive]) -> bool:
    """Paper §3.3 memory-range congruence with practical extensions.

    * ``address == 0`` is treated as missing (failed hook read).
    * ``thread_parameter`` on execute primitives links CreateRemoteThread
      (LoadLibraryW + remote path buffer) to a prior allocate/write.
    * ``context_pointer`` links Get/NtGetContextThread to Set/NtSetContextThread.
    * Multiple remote writes without a hook-visible allocator base are still one
      chain when other operational kinds are present (common for NtAllocateVirtualMemory).
    """
    kinds = {primitive.kind for primitive in primitives}
    by_kind: dict[PrimitiveKind, list[list[tuple[int, int]]]] = defaultdict(list)
    linked_primitive_count = 0
    for primitive in primitives:
        ranges = _memory_link_ranges(primitive)
        if not ranges:
            continue
        by_kind[primitive.kind].append(ranges)
        linked_primitive_count += 1

    if linked_primitive_count < 2:
        return True

    for left_kind, left_range_groups in by_kind.items():
        for right_kind, right_range_groups in by_kind.items():
            if left_kind == right_kind:
                continue
            for left_ranges in left_range_groups:
                for right_ranges in right_range_groups:
                    if _any_ranges_overlap(left_ranges, right_ranges):
                        return True

    # NtAllocateVirtualMemory often returns no usable base address from hooks, so
    # only WRITE primitives carry ranges (payload + small pointer patch). Treat
    # that as congruent when the chain already has multiple operational kinds.
    if operational_kind_count(kinds) >= 2 and len(by_kind) == 1:
        return True

    return False


def _memory_link_ranges(primitive: MemoryPrimitive) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    if primitive.address is not None and primitive.address != 0:
        size = primitive.size if primitive.size is not None and primitive.size > 0 else 1
        ranges.append((primitive.address, primitive.address + size))
    if primitive.kind == PrimitiveKind.EXECUTE:
        parameter = _detail_int(primitive.details.get("thread_parameter"))
        if parameter is not None:
            ranges.append((parameter, parameter + 1))
    pointer = _detail_int(primitive.details.get("context_pointer"))
    if pointer is not None:
        ranges.append((pointer, pointer + 1))
    return ranges


def _any_ranges_overlap(
    left_ranges: list[tuple[int, int]],
    right_ranges: list[tuple[int, int]],
) -> bool:
    for left_start, left_end in left_ranges:
        for right_start, right_end in right_ranges:
            if left_start < right_end and right_start < left_end:
                return True
    return False


def _ranges_overlap_or_contain(left: MemoryPrimitive, right: MemoryPrimitive) -> bool:
    return _any_ranges_overlap(_memory_link_ranges(left), _memory_link_ranges(right))


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


def _dll_path_remote_thread_pattern(primitives: list[MemoryPrimitive]) -> bool:
    """Classic DLL injection: CRT start routine + parameter at written path buffer."""
    execute_primitives = [p for p in primitives if p.kind == PrimitiveKind.EXECUTE]
    write_primitives = [p for p in primitives if p.kind == PrimitiveKind.WRITE]
    if not execute_primitives or not write_primitives:
        return False
    remote_thread_apis = {
        "createremotethread",
        "createremotethreadex",
        "ntcreatethreadex",
        "rtlcreateuserthread",
    }
    for execute in execute_primitives:
        if execute.api.lower() not in remote_thread_apis:
            continue
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


def _severity(score: int) -> Severity:
    if score >= 85:
        return Severity.CRITICAL
    if score >= 70:
        return Severity.HIGH
    if score >= 50:
        return Severity.MEDIUM
    return Severity.LOW


def _describe(
    primitives: list[MemoryPrimitive],
    process: ProcessEvent | None,
    related_file: FileEvent | None,
    *,
    actor_image: str | None = None,
    target_image: str | None = None,
) -> str:
    actor = actor_image or (process.image if process else None) or f"pid {primitives[0].actor_pid}"
    target = target_image or primitives[0].target_image or f"pid {primitives[0].target_pid}"
    if primitives[0].target_pid is not None and target_image:
        target = f"{target_image} (pid {primitives[0].target_pid})"
    elif primitives[0].target_pid is not None and not target_image:
        target = f"pid {primitives[0].target_pid}"
    kinds = ", ".join(sorted({primitive.kind.value for primitive in primitives}))
    file_part = f" Related file: {related_file.path}." if related_file else ""
    return f"{actor} performed correlated {kinds} primitives against {target}.{file_part}"


def _norm_path(path: str) -> str:
    return str(PureWindowsPath(path)).lower()


def now_utc() -> datetime:
    return datetime.now(timezone.utc)
