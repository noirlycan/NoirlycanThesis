"""Stateful analysis module: turns a stream of primitives into findings.

Pipeline for every new primitive, following the paper's analysis module
(Di Pietro et al., ASIA CCS '25, §3.2–3.3):

1. group by (actor PID, victim PID) inside a sliding time window;
2. apply the paper's rules (``rules.py``): minimal core operations,
   temporal consistency, memory congruence;
3. only then add lab context: score (``scoring.py``), file provenance
   (``provenance.py``), technique classification, recursive-chain graph and
   post-injection network watch.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from noirlycan_core.classification.config import (
    ClassifierRulesConfig,
    load_classifier_config,
    resolve_config_path,
)
from noirlycan_core.classification.technique_classifier import apply_classification
from noirlycan_core.detection import rules
from noirlycan_core.detection.injection_graph import InjectionGraph
from noirlycan_core.detection.network_watch import (
    NETWORK_WATCH_MIN_SCORE,
    NETWORK_WATCH_SECONDS,
    NetworkWatch,
)
from noirlycan_core.detection.provenance import ImageResolver, ProvenanceTracker
from noirlycan_core.detection.scoring import describe_chain, score_chain, severity_for
from noirlycan_core.extensions.kernel_evidence import kernel_evidence
from noirlycan_core.models import (
    FileEvent,
    Finding,
    MemoryPrimitive,
    NetworkConnectionEvent,
    PrimitiveKind,
    ProcessAccessEvent,
    ProcessEvent,
    TelemetryEvent,
)
from noirlycan_core.runtime.agent_policy import AgentPolicy, load_agent_policy, policy_path
from noirlycan_core.runtime.process_resolve import image_for_pid

__all__ = ["Correlator", "NETWORK_WATCH_MIN_SCORE", "NETWORK_WATCH_SECONDS"]

ChainKey = tuple[int, "int | None"]
MAX_ACCESSES_PER_PAIR = 8
HOUSEKEEPING_INTERVAL = timedelta(seconds=1)


@dataclass(frozen=True)
class _ChainProgress:
    score: int
    kinds: frozenset[PrimitiveKind]
    execution_confirmed: bool

    def advances(self, previous: _ChainProgress) -> bool:
        """Report again on a higher score or a chain that gained a step.

        Score alone is not enough: it is capped at 100, so a chain can reach
        the cap before its final, most specific step arrives.
        """
        return (
            self.score > previous.score
            or self.kinds > previous.kinds
            or (self.execution_confirmed and not previous.execution_confirmed)
        )


class Correlator:
    def __init__(
        self,
        window_seconds: int = 300,
        minimum_score: int = 50,
        logs_dir: str | Path | None = None,
        resolve_image: ImageResolver = image_for_pid,
    ) -> None:
        self.window = timedelta(seconds=window_seconds)
        self.minimum_score = minimum_score
        self.logs_dir = logs_dir
        self.provenance = ProvenanceTracker(resolve_image)
        self.network_watch = NetworkWatch()
        self.primitives: deque[MemoryPrimitive] = deque()
        self._chains: dict[ChainKey, list[MemoryPrimitive]] = defaultdict(list)
        self._accesses: dict[ChainKey, deque[ProcessAccessEvent]] = {}
        self._reported: dict[ChainKey, _ChainProgress] = {}
        self._findings_by_target: dict[int, Finding] = {}
        self._injection_graph = InjectionGraph()
        self._policy: AgentPolicy | None = None
        self._policy_mtime = -1.0
        self._rules_config: ClassifierRulesConfig | None = None
        self._rules_config_mtime = -1.0
        self._last_housekeeping: datetime | None = None

    # -- compatibility views ------------------------------------------------

    @property
    def files_by_path(self) -> dict[str, FileEvent]:
        return self.provenance.files_by_path

    @property
    def network_connections(self) -> dict[int, list[NetworkConnectionEvent]]:
        return self.network_watch.connections

    # -- configuration ------------------------------------------------------

    def reload_agent_policy(self) -> AgentPolicy | None:
        """Re-read ``.agent_policy.json`` when it changed on disk."""
        path = policy_path(self.logs_dir) if self.logs_dir else None
        if path is None or not path.exists():
            self._policy = None
            self._policy_mtime = 0.0
            return None
        mtime = path.stat().st_mtime
        if self._policy is None or mtime != self._policy_mtime:
            self._policy_mtime = mtime
            self.apply_policy(load_agent_policy(self.logs_dir))
        return self._policy

    def apply_policy(self, policy: AgentPolicy | None) -> None:
        self._policy = policy
        if policy is not None:
            self.window = timedelta(seconds=policy.capture_seconds())

    def reload_rules_config(self) -> ClassifierRulesConfig:
        """Re-read ``.classifier_rules.json`` when it changed on disk."""
        path = resolve_config_path(self.logs_dir)
        mtime = path.stat().st_mtime if path.exists() else 0.0
        if self._rules_config is None or mtime != self._rules_config_mtime:
            self._rules_config = load_classifier_config(self.logs_dir)
            self._rules_config_mtime = mtime
        return self._rules_config

    def effective_minimum_score(self, rules_config: ClassifierRulesConfig) -> int:
        return max(self.minimum_score, rules_config.minimum_score)

    # -- ingest -------------------------------------------------------------

    def add_file(self, event: FileEvent) -> None:
        self.provenance.add_file(event)
        self._expire(event.timestamp)

    def add_process(self, event: ProcessEvent) -> None:
        self.provenance.add_process(event)
        self._expire(event.timestamp)

    def note_process_create_hint(self, actor_pid: int, payload: dict[str, object]) -> None:
        timestamp = self.provenance.add_process_create_hint(actor_pid, payload)
        if timestamp is not None:
            self._expire(timestamp)

    def note_sysmon_process_ref(self, event: TelemetryEvent) -> None:
        self.provenance.add_sysmon_process_refs(event)

    def add_primitive(self, event: MemoryPrimitive) -> list[Finding]:
        primitive = self.provenance.enrich(event)
        self.primitives.append(primitive)
        key = (primitive.actor_pid, primitive.target_pid)
        self._chains[key].append(primitive)
        self._expire(primitive.timestamp)
        finding = self._evaluate_chain(key, primitive)
        return [finding] if finding is not None else []

    def add_process_access(self, event: ProcessAccessEvent) -> None:
        """Remember recent kernel-seen handle opens per (actor, victim); evidence only."""
        key = (event.actor_pid, event.target_pid)
        self._accesses.setdefault(key, deque(maxlen=MAX_ACCESSES_PER_PAIR)).append(event)

    def add_network_connection(
        self, event: NetworkConnectionEvent
    ) -> tuple[NetworkConnectionEvent | None, Finding | None]:
        self._expire(event.timestamp)
        if not self.network_watch.record(event):
            return None, None
        finding = self._findings_by_target.get(event.pid)
        if finding is not None:
            finding.network_connections.append(
                {
                    "destination": event.endpoint,
                    "protocol": event.protocol,
                    "succeeded": event.succeeded,
                    "source": event.source,
                    "timestamp": event.timestamp.isoformat() if event.timestamp else None,
                }
            )
        return event, finding

    def network_watch_pids(self, now: datetime | None = None) -> set[int]:
        return self.network_watch.active_pids(now or datetime.now(timezone.utc))

    # -- analysis -----------------------------------------------------------

    def _evaluate_chain(self, key: ChainKey, latest: MemoryPrimitive) -> Finding | None:
        primitives = self._chains.get(key)
        if not primitives:
            return None
        actor_pid, target_pid = key
        policy = self.reload_agent_policy()
        rules_config = self.reload_rules_config()

        if not self._passes_paper_rules(primitives, policy, rules_config):
            return None
        if not _passes_scope_gates(actor_pid, target_pid, rules_config):
            return None

        process = self.provenance.processes_by_pid.get(actor_pid)
        dropped_file = self.provenance.dropped_file_for(process)
        actor_image = self.provenance.image_in_chain(actor_pid, primitives, process)
        target_image = self.provenance.image_in_chain(target_pid, primitives)
        score, evidence = score_chain(primitives, process, dropped_file)
        bonus, kernel = kernel_evidence(primitives, list(self._accesses.get(key, ())))
        score = min(100, score + bonus)
        evidence.update(kernel)
        if actor_image:
            evidence["actor_image"] = actor_image
        if target_image:
            evidence["target_image"] = target_image
        if score < self.effective_minimum_score(rules_config):
            return None
        execution_confirmed = bool(evidence["execution_confirmed"])
        progress = _ChainProgress(score, frozenset(primitive.kind for primitive in primitives), execution_confirmed)
        previous = self._reported.get(key)
        if previous is not None and not progress.advances(previous):
            return None  # Nothing new since this chain was last reported.
        self._reported[key] = progress

        if score >= NETWORK_WATCH_MIN_SCORE and target_pid is not None:
            seconds = policy.net_watch_seconds() if policy else NETWORK_WATCH_SECONDS
            self.network_watch.watch(target_pid, latest.timestamp, seconds)

        finding = Finding(
            timestamp=latest.timestamp,
            severity=severity_for(score, policy),
            title="Probable process injection chain" if execution_confirmed else "Probable injection staging chain",
            description=describe_chain(
                primitives, process, dropped_file, actor_image=actor_image, target_image=target_image
            ),
            actor_pid=actor_pid,
            target_pid=target_pid,
            primitives=tuple(sorted(primitives, key=lambda item: item.timestamp)),
            related_file=dropped_file,
            related_process=process,
            actor_image=actor_image,
            target_image=target_image,
            score=score,
            evidence=evidence,
        )
        finding = apply_classification(finding, logs_dir=self.logs_dir)
        finding = self._injection_graph.add_finding(finding)
        if target_pid is not None:
            self._findings_by_target[target_pid] = finding
        return finding

    @staticmethod
    def _passes_paper_rules(
        primitives: list[MemoryPrimitive],
        policy: AgentPolicy | None,
        rules_config: ClassifierRulesConfig,
    ) -> bool:
        """Paper §3.2. The console policy may raise the 2-of-3 threshold or switch rules off for ablation."""
        minimum = policy.min_primitives if policy is not None else rules_config.minimum_operational_kinds
        check_temporal = policy is None or policy.temporal
        check_congruence = policy is None or policy.congruence
        return (
            rules.has_minimal_core_operations(primitives, minimum)
            and (not check_temporal or rules.has_temporal_consistency(primitives))
            and (not check_congruence or rules.has_memory_congruence(primitives))
        )

    def _expire(self, now: datetime) -> None:
        """Drop state older than the window.

        Primitive expiry is a cheap deque pop per event. The dict/list scans
        (files, handle opens, network) are throttled to once per second — a
        Frida burst can deliver thousands of primitives per second.
        """
        cutoff = now - self.window
        while self.primitives and self.primitives[0].timestamp < cutoff:
            expired = self.primitives.popleft()
            key = (expired.actor_pid, expired.target_pid)
            chain = self._chains.get(key)
            if chain:
                if expired in chain:
                    chain.remove(expired)
                if not chain:
                    del self._chains[key]
        if self._last_housekeeping is not None and (now - self._last_housekeeping) < HOUSEKEEPING_INTERVAL:
            return
        self._last_housekeeping = now
        for key in [key for key, events in self._accesses.items() if events[-1].timestamp < cutoff]:
            del self._accesses[key]
        self.provenance.expire(cutoff)
        self.network_watch.expire(now, cutoff)


def _passes_scope_gates(actor_pid: int, target_pid: int | None, rules_config: ClassifierRulesConfig) -> bool:
    """Optional analyst filters on self-injection (the paper studies cross-process injection)."""
    if rules_config.ignore_same_process_findings and actor_pid == target_pid:
        return False
    if rules_config.require_cross_process_findings and (target_pid is None or target_pid == actor_pid):
        return False
    return True
