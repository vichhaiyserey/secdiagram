"""Canonical, deterministic diagram model with layout ranks.

Both renderers and the ``--validate`` quality gate consume this projection of
``Graph`` and ``HighLevelArchitecture``. Inputs are always sorted before the
model is assembled, so repeated analysis of an unchanged repository yields
identical components, relationships, boundaries, and ranks.

Layout algorithm (documented, deterministic):

1. Build the directed component graph and condense strongly connected
   components (cycles) with an iterative Kosaraju pass.
2. Rank each condensation node with the longest-path algorithm over a
   topological (Kahn) order; every member of a cycle shares that rank.
3. Order components by ``(rank, tier_index, group, kind, name, id)``.

Mermaid still owns pixel-level placement; the ranks describe the intended
reading order and are what the quality checks use to spot inversions.
"""

from __future__ import annotations

import heapq
from collections.abc import Iterator
from dataclasses import dataclass, field

from .high_level import HighLevelArchitecture
from .model import Graph, stable_id

TIER_ORDER = ("ingress", "gateway", "services", "data", "external", "platform")
TIER_INDEX = {tier: index for index, tier in enumerate(TIER_ORDER)}

INGRESS_KINDS = frozenset({"route", "endpoint", "api", "page", "http", "controller", "view"})
GATEWAY_KINDS = frozenset({"gateway", "proxy", "middleware", "client"})
DATA_KINDS = frozenset({"database", "cache", "queue", "table", "model", "store", "schema", "topic"})
EXTERNAL_KINDS = frozenset({"external"})
PLATFORM_KINDS = frozenset({"platform"})


def classify_tier(kind: str) -> str:
    """Map a component kind onto one of the canonical architectural tiers."""
    lowered = kind.lower()
    if lowered in INGRESS_KINDS:
        return "ingress"
    if lowered in GATEWAY_KINDS:
        return "gateway"
    if lowered in DATA_KINDS:
        return "data"
    if lowered in EXTERNAL_KINDS:
        return "external"
    if lowered in PLATFORM_KINDS:
        return "platform"
    return "services"


@dataclass(frozen=True, slots=True)
class DiagramComponent:
    id: str
    name: str
    kind: str
    tier: str
    group: str = ""
    source: str = "graph"
    evidence: str = ""

    def sort_key(self) -> tuple[str, int, str, str, str, str]:
        return (
            self.tier,
            TIER_INDEX.get(self.tier, len(TIER_ORDER)),
            self.group,
            self.kind,
            self.name,
            self.id,
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "id": self.id,
            "name": self.name,
            "kind": self.kind,
            "tier": self.tier,
            "group": self.group,
            "source": self.source,
            "evidence": self.evidence,
        }


@dataclass(frozen=True, slots=True)
class DiagramRelationship:
    id: str
    src: str
    dst: str
    kind: str
    label: str = ""
    confidence: float = 1.0

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "src": self.src,
            "dst": self.dst,
            "kind": self.kind,
            "label": self.label,
            "confidence": round(float(self.confidence), 2),
        }


@dataclass(slots=True)
class DiagramModel:
    components: list[DiagramComponent] = field(default_factory=list)
    relationships: list[DiagramRelationship] = field(default_factory=list)
    ranks: dict[str, int] = field(default_factory=dict)
    boundaries: list[str] = field(default_factory=list)
    entry_points: list[str] = field(default_factory=list)
    data_stores: list[str] = field(default_factory=list)
    external_systems: list[str] = field(default_factory=list)

    def by_id(self) -> dict[str, DiagramComponent]:
        return {component.id: component for component in self.components}

    def to_dict(self) -> dict[str, object]:
        return {
            "components": [component.to_dict() for component in self.components],
            "relationships": [relationship.to_dict() for relationship in self.relationships],
            "ranks": {key: self.ranks[key] for key in sorted(self.ranks)},
            "boundaries": list(self.boundaries),
            "entry_points": list(self.entry_points),
            "data_stores": list(self.data_stores),
            "external_systems": list(self.external_systems),
        }


def _relationship(src: str, dst: str, kind: str, label: str = "", confidence: float = 1.0) -> DiagramRelationship:
    return DiagramRelationship(
        id=stable_id("diagram-rel", src, dst, kind),
        src=src,
        dst=dst,
        kind=kind,
        label=label,
        confidence=confidence,
    )


def _dedupe_relationships(relationships: list[DiagramRelationship]) -> list[DiagramRelationship]:
    merged: dict[tuple[str, str, str], DiagramRelationship] = {}
    for relationship in sorted(relationships, key=lambda item: (item.src, item.dst, item.kind, item.id)):
        key = (relationship.src, relationship.dst, relationship.kind)
        current = merged.get(key)
        if current is None:
            merged[key] = relationship
            continue
        if relationship.confidence > current.confidence:
            merged[key] = DiagramRelationship(
                id=current.id,
                src=current.src,
                dst=current.dst,
                kind=current.kind,
                label=current.label or relationship.label,
                confidence=relationship.confidence,
            )
    return [merged[key] for key in sorted(merged)]


def _from_subsystems(
    hla: HighLevelArchitecture,
) -> tuple[list[DiagramComponent], list[DiagramRelationship]]:
    components: dict[str, DiagramComponent] = {}
    for subsystem in sorted(hla.subsystems, key=lambda item: (item.tier, item.kind, item.name, item.id)):
        tier = subsystem.tier if subsystem.tier in TIER_INDEX else classify_tier(subsystem.kind)
        components.setdefault(
            subsystem.id,
            DiagramComponent(
                id=subsystem.id,
                name=subsystem.name,
                kind=subsystem.kind,
                tier=tier,
                source="subsystem",
                evidence=subsystem.path or "",
            ),
        )
    relationships = [
        _relationship(connection.src, connection.dst, "connects", connection.label)
        for connection in hla.connections
        if connection.src in components and connection.dst in components
    ]
    return [components[key] for key in sorted(components)], relationships


def _from_graph(graph: Graph) -> tuple[list[DiagramComponent], list[DiagramRelationship]]:
    components: dict[str, DiagramComponent] = {}
    for node in graph.sorted_nodes():
        components.setdefault(
            node.id,
            DiagramComponent(
                id=node.id,
                name=node.name,
                kind=node.kind,
                tier=classify_tier(node.kind),
                group=node.feature or "",
                source="graph",
                evidence=f"{node.path}:{node.line}" if node.path and node.line else (node.path or ""),
            ),
        )
    relationships = [
        _relationship(edge.src, edge.dst, edge.kind, confidence=edge.confidence)
        for edge in graph.sorted_edges()
        if edge.src in components and edge.dst in components
    ]
    return [components[key] for key in sorted(components)], relationships


def _strongly_connected(
    node_ids: list[str], successors: dict[str, set[str]]
) -> tuple[dict[str, int], list[list[str]]]:
    order: list[str] = []
    visited: set[str] = set()
    for start in node_ids:
        if start in visited:
            continue
        visited.add(start)
        stack: list[tuple[str, Iterator[str]]] = [
            (start, iter(sorted(successors[start])))
        ]
        while stack:
            node, iterator = stack[-1]
            try:
                nxt = next(iterator)
            except StopIteration:
                order.append(node)
                stack.pop()
                continue
            if nxt not in visited:
                visited.add(nxt)
                stack.append((nxt, iter(sorted(successors[nxt]))))

    predecessors: dict[str, list[str]] = {node_id: [] for node_id in node_ids}
    for src, destinations in successors.items():
        for dst in destinations:
            predecessors[dst].append(src)

    component_of: dict[str, int] = {}
    components: list[list[str]] = []
    assigned: set[str] = set()
    for start in reversed(order):
        if start in assigned:
            continue
        members: list[str] = []
        pending = [start]
        assigned.add(start)
        while pending:
            node = pending.pop()
            members.append(node)
            for pred in sorted(predecessors[node]):
                if pred not in assigned:
                    assigned.add(pred)
                    pending.append(pred)
        index = len(components)
        components.append(sorted(members))
        for member in members:
            component_of[member] = index
    return component_of, components


def compute_layout_ranks(node_ids: list[str], edges: list[tuple[str, str]]) -> dict[str, int]:
    """Assign deterministic longest-path ranks, collapsing cycles first."""
    ids = sorted(set(node_ids))
    successors: dict[str, set[str]] = {node_id: set() for node_id in ids}
    for src, dst in edges:
        if src in successors and dst in successors and src != dst:
            successors[src].add(dst)
    component_of, components = _strongly_connected(ids, successors)

    dag: dict[int, set[int]] = {component_index: set() for component_index in range(len(components))}
    for succ_src, succ_dsts in successors.items():
        for succ_dst in succ_dsts:
            src_index = component_of[succ_src]
            dst_index = component_of[succ_dst]
            if src_index != dst_index:
                dag[src_index].add(dst_index)

    indegree: dict[int, int] = {component_index: 0 for component_index in dag}
    for successors_of_component in dag.values():
        for peer in successors_of_component:
            indegree[peer] += 1

    ranks: dict[int, int] = {component_index: 0 for component_index in dag}
    ready: list[int] = [component_index for component_index, degree in indegree.items() if degree == 0]
    heapq.heapify(ready)
    while ready:
        component_index = heapq.heappop(ready)
        for peer in sorted(dag[component_index]):
            ranks[peer] = max(ranks[peer], ranks[component_index] + 1)
            indegree[peer] -= 1
            if indegree[peer] == 0:
                heapq.heappush(ready, peer)

    result: dict[str, int] = {}
    for component_index, members in enumerate(components):
        for member in members:
            result[member] = ranks[component_index]
    return {node_id: result[node_id] for node_id in sorted(result)}


def build_diagram_model(graph: Graph, hla: HighLevelArchitecture | None = None) -> DiagramModel:
    """Project the analysis graph into the canonical, sorted diagram model."""
    if hla is not None and hla.subsystems:
        components, relationships = _from_subsystems(hla)
    else:
        components, relationships = _from_graph(graph)

    relationships = _dedupe_relationships(relationships)
    ranks = compute_layout_ranks(
        [component.id for component in components],
        [(relationship.src, relationship.dst) for relationship in relationships],
    )
    components.sort(key=lambda component: (ranks[component.id], component.sort_key()))
    relationships.sort(
        key=lambda relationship: (
            ranks.get(relationship.src, 0),
            ranks.get(relationship.dst, 0),
            relationship.src,
            relationship.dst,
            relationship.kind,
            relationship.id,
        )
    )

    tiers = {component.tier for component in components}
    boundaries = [tier for tier in TIER_ORDER if tier in tiers]
    entry_points = sorted(component.id for component in components if component.tier == "ingress")
    data_stores = sorted(component.id for component in components if component.tier == "data")
    external_systems = sorted(component.id for component in components if component.tier == "external")
    return DiagramModel(
        components=components,
        relationships=relationships,
        ranks=ranks,
        boundaries=boundaries,
        entry_points=entry_points,
        data_stores=data_stores,
        external_systems=external_systems,
    )
