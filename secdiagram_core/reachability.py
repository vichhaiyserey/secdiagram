"""Reachability verification for policy decisions.

A finding may block only when the vulnerable sink (or dependency) is
verifiably reachable from an HTTP, task, CLI, or message entry point. This
module classifies reachability from the taint data the analyzers already
produce; it never invents paths.

Classification values:

* ``externally_reachable`` - flow enters through an anonymous endpoint.
* ``authenticated_reachable`` - flow enters through an authenticated endpoint.
* ``local_reachable`` - flow enters through a task/CLI entry point.
* ``internal_reachable`` - reachable inside the process graph but the entry
  point could not be determined.
* ``unreachable`` - no entry point reaches the sink.
* ``unknown`` - reachability could not be determined.

For injection findings, blocking additionally requires a *complete path*:
source location, propagation hops, and sink location. An incomplete path
yields ``unknown`` and the finding is downgraded to ``review`` or
``informational`` by the policy layer.
"""

from __future__ import annotations

from typing import Any

from .exposure import node_exposure_class
from .model import Finding, Graph, Node

INJECTION_CATEGORIES = frozenset({"sql", "nosql", "command", "code", "deserialization", "template", "path", "network"})

REACHABILITY_STATES = (
    "externally_reachable",
    "authenticated_reachable",
    "local_reachable",
    "internal_reachable",
    "unreachable",
    "unknown",
)

_EXPOSURE_TO_REACHABILITY = {
    "public": "externally_reachable",
    "privileged": "authenticated_reachable",
    "isolated": "local_reachable",
    "internal_high_impact": "internal_reachable",
    "sensitive_data": "unreachable",
    "unknown": "unknown",
}

# Minimum hops for a *complete* injection path: source, at least one
# propagation/call hop, and the sink. A two-hop source->sink is accepted when
# both endpoints are distinct locations.
MIN_COMPLETE_HOPS = 2


def classify_reachability(graph: Graph, finding: Finding) -> str:
    """Classify how a finding's vulnerable sink is reached."""
    if finding.metadata.get("runtime_confirmed") and finding.node_id:
        node = graph.nodes.get(finding.node_id)
        if node is not None:
            # A DAST scanner reached this endpoint over the network, so the
            # runtime observation itself proves external reachability even when
            # the static graph did not classify the endpoint's exposure.
            exposure = node_exposure_class(node)
            if exposure == "privileged":
                return "authenticated_reachable"
            return "externally_reachable"
    flow = _flow_hops(finding)
    if flow:
        entry = _entry_node(graph, flow)
        exposure = node_exposure_class(entry)
        if exposure == "unknown":
            return "internal_reachable"
        return _EXPOSURE_TO_REACHABILITY.get(exposure, "unknown")
    node = graph.nodes.get(finding.node_id or "")
    if node is not None:
        exposure = node_exposure_class(node)
        if exposure == "unknown":
            return "unknown"
        if exposure == "isolated" and node.kind not in {"task", "cli"}:
            # The vulnerable code exists in the process but no entry point
            # reaches it directly and no flow was proven.
            return "internal_reachable"
        return _EXPOSURE_TO_REACHABILITY.get(exposure, "unknown")
    if finding.category in INJECTION_CATEGORIES:
        # An injection sink with no recorded path and no node anchor cannot be
        # verified reachable; the policy layer must not block on it.
        return "unknown"
    return "unknown"


def has_complete_path(finding: Finding) -> bool:
    """True when the finding carries a source, propagation, and sink location."""
    flow = _flow_hops(finding)
    if flow:
        if len(flow) < MIN_COMPLETE_HOPS:
            return False
        first = flow[0]
        last = flow[-1]
        if not _hop_loc(first) or not _hop_loc(last):
            return False
        return len(flow) > 1
    trace = finding.trace
    if len(trace) >= MIN_COMPLETE_HOPS:
        return True
    return False


def sanitizer_assessment(finding: Finding) -> str:
    """Assess whether a sanitizer neutralizes the reported flow.

    The analyzers suppress findings whose flows are fully sanitized for the
    category, so a surviving finding means the path *reached the sink* through
    unsanitized data. Assessments: ``none`` (no sanitizer neutralized the
    flow), ``unknown`` (no flow data).
    """
    if not _flow_hops(finding) and not finding.trace:
        return "unknown"
    return "none"


def _flow_hops(finding: Finding) -> list[dict[str, Any]]:
    hops = finding.metadata.get("flow") or []
    return [hop for hop in hops if isinstance(hop, dict)]


def _hop_loc(hop: dict[str, Any]) -> str | None:
    loc = hop.get("loc")
    if isinstance(loc, str) and loc:
        return loc
    path = hop.get("path")
    line = hop.get("line")
    if isinstance(path, str) and path and isinstance(line, int) and line > 0:
        return f"{path}:{line}"
    return None


def _entry_node(graph: Graph, flow: list[dict[str, Any]]) -> Node | None:
    if not flow:
        return None
    node_id = flow[0].get("node")
    if not isinstance(node_id, str) or not node_id:
        node_id = flow[0].get("node_id")
    if isinstance(node_id, str) and node_id:
        return graph.nodes.get(node_id)
    return None
