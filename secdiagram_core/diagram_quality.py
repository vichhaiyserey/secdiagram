"""Deterministic diagram-quality diagnostics for the canonical model.

Every check is pure, deterministic, and reports a stable ``DQnnn`` code so
outputs can be diffed between commits and referenced from CI logs.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass

from .diagram_model import TIER_INDEX, DiagramModel

SEVERITY_ORDER = {"error": 0, "warning": 1, "info": 2}

_NORMALIZE_RE = re.compile(r"[^a-z0-9]+")


@dataclass(frozen=True, slots=True)
class QualityIssue:
    code: str
    severity: str
    message: str
    subjects: tuple[str, ...] = ()
    hint: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
            "subjects": list(self.subjects),
            "hint": self.hint,
        }


def _normalized(name: str) -> str:
    return _NORMALIZE_RE.sub("", name.lower())


def _cycles(model: DiagramModel) -> list[list[str]]:
    successors: dict[str, set[str]] = {component.id: set() for component in model.components}
    for relationship in model.relationships:
        if relationship.src in successors and relationship.dst in successors and relationship.src != relationship.dst:
            successors[relationship.src].add(relationship.dst)

    index = 0
    indexes: dict[str, int] = {}
    lowlink: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    found: list[list[str]] = []

    for start in sorted(successors):
        if start in indexes:
            continue
        work: list[tuple[str, int]] = [(start, 0)]
        while work:
            node, child_index = work[-1]
            if child_index == 0:
                indexes[node] = lowlink[node] = index
                index += 1
                stack.append(node)
                on_stack.add(node)
            children = sorted(successors[node])
            if child_index < len(children):
                work[-1] = (node, child_index + 1)
                child = children[child_index]
                if child not in indexes:
                    work.append((child, 0))
                elif child in on_stack:
                    lowlink[node] = min(lowlink[node], indexes[child])
                continue
            if lowlink[node] == indexes[node]:
                members: list[str] = []
                while True:
                    member = stack.pop()
                    on_stack.discard(member)
                    members.append(member)
                    if member == node:
                        break
                found.append(sorted(members))
            work.pop()
            if work:
                parent = work[-1][0]
                lowlink[parent] = min(lowlink[parent], lowlink[node])
    return sorted(member_list for member_list in found if len(member_list) > 1)


def _is_diagram_box(source: str, kind: str) -> bool:
    if source == "subsystem":
        return True
    return kind not in {"function", "method", "constructor", "nested"}


def analyze_diagram_quality(model: DiagramModel) -> list[QualityIssue]:
    """Return deterministically ordered quality issues for ``model``."""
    issues: list[QualityIssue] = []
    components = model.by_id()
    seen_ids = Counter(component.id for component in model.components)
    duplicates = sorted(component_id for component_id, count in seen_ids.items() if count > 1)
    if duplicates:
        issues.append(
            QualityIssue(
                "DQ001",
                "error",
                "duplicate component identifiers: " + ", ".join(duplicates),
                tuple(duplicates),
                "Component ids must be stable and unique so diagram diffs stay meaningful.",
            )
        )

    labels: dict[tuple[str, str], list[str]] = defaultdict(list)
    for component in model.components:
        if component.source == "subsystem":
            labels[(component.tier, _normalized(component.name))].append(component.id)
    for (tier, _), ids in sorted(labels.items()):
        if len(ids) > 1:
            issues.append(
                QualityIssue(
                    "DQ002",
                    "warning",
                    f"{len(ids)} components in tier '{tier}' share the same label",
                    tuple(sorted(ids)),
                    "Merge duplicates or rename them so readers can tell the boxes apart.",
                )
            )

    degree: dict[str, int] = {component.id: 0 for component in model.components}
    for relationship in model.relationships:
        if relationship.src in degree:
            degree[relationship.src] += 1
        if relationship.dst in degree:
            degree[relationship.dst] += 1
    orphans = sorted(
        component.id
        for component in model.components
        if degree[component.id] == 0
        and component.tier not in {"ingress", "data", "external", "platform"}
        and _is_diagram_box(component.source, component.kind)
    )
    if orphans:
        issues.append(
            QualityIssue(
                "DQ003",
                "warning",
                f"{len(orphans)} component(s) have no relationships",
                tuple(orphans),
                "Orphans are usually dead code or a missing dependency edge.",
            )
        )

    for members in _cycles(model):
        issues.append(
            QualityIssue(
                "DQ004",
                "error",
                "dependency cycle: " + " <-> ".join(members),
                tuple(members),
                "Break the cycle or model one side as an external dependency.",
            )
        )

    self_loops = sorted(
        {
            relationship.src
            for relationship in model.relationships
            if relationship.src == relationship.dst
        }
    )
    if self_loops:
        issues.append(
            QualityIssue(
                "DQ005",
                "warning",
                f"{len(self_loops)} self-referencing relationship(s)",
                tuple(self_loops),
                "Drop self-loops from the diagram; they add visual noise.",
            )
        )

    dangling = sorted(
        {
            f"{relationship.src}->{relationship.dst}"
            for relationship in model.relationships
            if relationship.src not in components or relationship.dst not in components
        }
    )
    if dangling:
        issues.append(
            QualityIssue(
                "DQ006",
                "error",
                f"{len(dangling)} relationship(s) reference missing components",
                tuple(dangling),
                "Rebuild the model; dangling edges indicate a projection bug.",
            )
        )

    rel_counts: dict[tuple[str, str, str], int] = defaultdict(int)
    for relationship in model.relationships:
        rel_counts[(relationship.src, relationship.dst, relationship.kind)] += 1
    duplicates_rel = sorted(f"{src}->{dst} ({kind})" for (src, dst, kind), count in rel_counts.items() if count > 1)
    if duplicates_rel:
        issues.append(
            QualityIssue(
                "DQ007",
                "warning",
                f"{len(duplicates_rel)} duplicated relationship(s)",
                tuple(duplicates_rel),
                "Relationships should be merged so edge counts stay explainable.",
            )
        )

    inversions: list[str] = []
    reverse_pairs = {(relationship.dst, relationship.src) for relationship in model.relationships}
    for relationship in model.relationships:
        src_component = components.get(relationship.src)
        dst_component = components.get(relationship.dst)
        if src_component is None or dst_component is None:
            continue
        src_index = TIER_INDEX.get(src_component.tier, len(TIER_INDEX))
        dst_index = TIER_INDEX.get(dst_component.tier, len(TIER_INDEX))
        if src_index > dst_index and (relationship.src, relationship.dst) not in reverse_pairs:
            inversions.append(f"{relationship.src}->{relationship.dst}")
    inversions = sorted(set(inversions))
    if inversions:
        issues.append(
            QualityIssue(
                "DQ008",
                "info",
                f"{len(inversions)} relationship(s) point against the tier order",
                tuple(inversions),
                "Review whether the edge is real; upward edges make the layout harder to read.",
            )
        )

    rank_skips = [
        relationship
        for relationship in model.relationships
        if abs(model.ranks.get(relationship.src, 0) - model.ranks.get(relationship.dst, 0)) > 1
    ]
    if len(rank_skips) >= 3 and len(rank_skips) * 4 >= len(model.relationships):
        subjects = sorted({f"{item.src}->{item.dst}" for item in rank_skips})
        issues.append(
            QualityIssue(
                "DQ009",
                "warning",
                f"{len(rank_skips)} of {len(model.relationships)} relationships skip rank levels",
                tuple(subjects),
                "Consider grouping intermediate components or using --diagram-direction LR.",
            )
        )

    unlabeled = sorted(
        f"{relationship.src}->{relationship.dst}"
        for relationship in model.relationships
        if not relationship.kind
    )
    if unlabeled:
        issues.append(
            QualityIssue(
                "DQ010",
                "info",
                f"{len(unlabeled)} relationship(s) have no kind",
                tuple(unlabeled),
                "Give edges a kind so the diagram legend is meaningful.",
            )
        )

    unique: dict[tuple[str, tuple[str, ...], str], QualityIssue] = {}
    for issue in issues:
        unique[(issue.code, issue.subjects, issue.message)] = issue
    return [
        unique[key]
        for key in sorted(
            unique,
            key=lambda item: (item[0], SEVERITY_ORDER.get(unique[item].severity, 9), item[1], item[2]),
        )
    ]


def has_errors(issues: list[QualityIssue]) -> bool:
    return any(issue.severity == "error" for issue in issues)


def format_quality_report(issues: list[QualityIssue]) -> list[str]:
    errors = sum(1 for issue in issues if issue.severity == "error")
    warnings = sum(1 for issue in issues if issue.severity == "warning")
    lines = [f"secdiagram: diagram quality: {len(issues)} issue(s) ({errors} error(s), {warnings} warning(s))"]
    for issue in issues:
        subjects = f" [{', '.join(issue.subjects)}]" if issue.subjects else ""
        lines.append(f"  {issue.code} {issue.severity}: {issue.message}{subjects}")
        if issue.hint:
            lines.append(f"    hint: {issue.hint}")
    return lines
