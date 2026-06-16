"""Injection chain graph for recursive multi-hop detection (ASIA CCS §3.1)."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

from noirlycan_telemetry.kernel.entities.models import Finding


@dataclass(frozen=True)
class InjectionEdge:
    actor_pid: int
    target_pid: int | None
    actor_image: str | None
    target_image: str | None
    score: int
    technique: str | None
    timestamp: str


@dataclass(frozen=True)
class InjectionChain:
    pids: tuple[int, ...]
    images: tuple[str | None, ...]
    depth: int
    is_recursive: bool
    edges: tuple[InjectionEdge, ...]


class InjectionGraph:
    """Tracks actor→target edges and derives multi-hop chains."""

    def __init__(self) -> None:
        self._edges: list[InjectionEdge] = []
        self._latest_chains: list[InjectionChain] = []

    @property
    def edges(self) -> tuple[InjectionEdge, ...]:
        return tuple(self._edges)

    @property
    def chains(self) -> tuple[InjectionChain, ...]:
        return tuple(self._latest_chains)

    def add_finding(self, finding: Finding) -> Finding:
        if finding.target_pid is None:
            return finding
        edge = InjectionEdge(
            actor_pid=finding.actor_pid,
            target_pid=finding.target_pid,
            actor_image=finding.actor_image,
            target_image=finding.target_image,
            score=finding.score,
            technique=finding.technique,
            timestamp=finding.timestamp.isoformat(),
        )
        self._edges.append(edge)
        self._latest_chains = discover_chains(self._edges)
        chain = _longest_chain_containing_edge(self._latest_chains, edge)
        if chain is None:
            return finding
        evidence = dict(finding.evidence)
        evidence["injection_chain_pids"] = list(chain.pids)
        evidence["injection_chain_images"] = list(chain.images)
        evidence["chain_depth"] = chain.depth
        evidence["is_recursive"] = chain.is_recursive
        return replace(
            finding,
            injection_chain=chain.pids,
            chain_depth=chain.depth,
            is_recursive=chain.is_recursive,
            evidence=evidence,
        )


def discover_chains(edges: list[InjectionEdge] | tuple[InjectionEdge, ...]) -> list[InjectionChain]:
    if not edges:
        return []
    adjacency: dict[int, list[InjectionEdge]] = {}
    outgoing: set[int] = set()
    incoming: set[int] = set()
    for edge in edges:
        if edge.target_pid is None:
            continue
        adjacency.setdefault(edge.actor_pid, []).append(edge)
        outgoing.add(edge.actor_pid)
        incoming.add(edge.target_pid)

    roots = sorted(outgoing - incoming) or sorted(outgoing)
    chains: list[InjectionChain] = []
    seen_signatures: set[tuple[int, ...]] = set()

    for root in roots:
        for chain_edges in _walk(adjacency, root, visited=set()):
            pids = _pid_path(chain_edges)
            if len(pids) < 2:
                continue
            signature = tuple(pids)
            if signature in seen_signatures:
                continue
            seen_signatures.add(signature)
            images = tuple(edge.actor_image for edge in chain_edges) + (chain_edges[-1].target_image,)
            depth = len(chain_edges)
            chains.append(
                InjectionChain(
                    pids=pids,
                    images=images,
                    depth=depth,
                    is_recursive=depth >= 2,
                    edges=tuple(chain_edges),
                )
            )
    chains.sort(key=lambda item: (-item.depth, item.pids[0]))
    return chains


def chains_from_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    edges: list[InjectionEdge] = []
    for finding in findings:
        actor_pid = finding.get("actor_pid")
        target_pid = finding.get("target_pid")
        if actor_pid is None or target_pid is None:
            continue
        edges.append(
            InjectionEdge(
                actor_pid=int(actor_pid),
                target_pid=int(target_pid),
                actor_image=finding.get("actor_image"),
                target_image=finding.get("target_image"),
                score=int(finding.get("score") or 0),
                technique=finding.get("technique"),
                timestamp=str(finding.get("timestamp") or ""),
            )
        )
    return [
        {
            "pids": list(chain.pids),
            "images": list(chain.images),
            "depth": chain.depth,
            "is_recursive": chain.is_recursive,
            "techniques": [edge.technique for edge in chain.edges if edge.technique],
            "scores": [edge.score for edge in chain.edges],
        }
        for chain in discover_chains(edges)
    ]


def _longest_chain_containing_edge(chains: list[InjectionChain], edge: InjectionEdge) -> InjectionChain | None:
    matches = [
        chain
        for chain in chains
        if any(
            item.actor_pid == edge.actor_pid and item.target_pid == edge.target_pid for item in chain.edges
        )
    ]
    if not matches:
        return None
    return max(matches, key=lambda item: item.depth)


def _walk(
    adjacency: dict[int, list[InjectionEdge]],
    start_pid: int,
    visited: set[int],
) -> list[list[InjectionEdge]]:
    if start_pid in visited:
        return []
    visited = set(visited)
    visited.add(start_pid)
    paths: list[list[InjectionEdge]] = [[]]
    for edge in adjacency.get(start_pid, []):
        if edge.target_pid is None:
            continue
        child_paths = _walk(adjacency, edge.target_pid, visited)
        if child_paths:
            for child in child_paths:
                paths.append([edge, *child])
        else:
            paths.append([edge])
    return [path for path in paths if path]


def _pid_path(edges: list[InjectionEdge]) -> tuple[int, ...]:
    if not edges:
        return ()
    pids = [edges[0].actor_pid]
    for edge in edges:
        if edge.target_pid is not None:
            pids.append(edge.target_pid)
    return tuple(pids)
