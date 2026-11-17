"""Exposure classification for policy decisions.

Separates detection from enforcement: a finding may only block CI when the
vulnerable code sits behind an entry point an attacker can plausibly reach.

Canonical taxonomy (this module is the single source of truth):

* ``public`` - anonymous, internet-facing entry point.
* ``privileged`` - reachable only after authentication or an explicit
  authorization boundary (insiders and signed-up users).
* ``sensitive_data`` - the finding is itself leaked credential material or
  plaintext production configuration; anyone with repository or image access
  has it.
* ``internal_high_impact`` - no direct external entry point, but a proven flow
  from a task/CLI entry point or advisory-verified exploitability makes the
  impact strongly evidenced.
* ``isolated`` - no entry point reaches the vulnerable code.
* ``unknown`` - reachability could not be determined.

Only ``public``, ``privileged``, ``sensitive_data`` and strongly evidenced
``internal_high_impact`` findings are eligible to block (see policy.py).
Everything is deterministic and derived purely from the graph.
"""

from __future__ import annotations

from typing import Any

from .model import Finding, Graph

EXPOSURE_STATES = (
    "public",
    "privileged",
    "sensitive_data",
    "internal_high_impact",
    "isolated",
    "unknown",
)

BLOCK_ELIGIBLE_EXPOSURES = frozenset({"public", "privileged", "sensitive_data", "internal_high_impact"})

SECRET_CATEGORIES = frozenset({"secret"})
# Categories whose findings are application-wide configuration rather than a
# single taint sink; the exposure of the app is the exposure of the finding.
CONFIG_EXPOSURE_CATEGORIES = frozenset({"misconfig", "auth", "tls", "cookie", "cors", "jwt", "csrf"})

# Node attribute markers for admin/debug interfaces detected by the analyzers.
_ADMIN_TITLE_WORDS = ("admin", "debug")


def node_exposure_class(node: Any) -> str:
    """Exposure class of a graph node in the canonical taxonomy.

    Python web frameworks (Flask, FastAPI, Django) do not enforce
    authorization by default: the analyzers tag an HTTP handler
    ``trust_boundary=ingress`` with routes when request-derived data provably
    reaches it, and no auth marker means no recorded authentication boundary,
    so such handlers classify as ``public`` for policy purposes. Explicit
    auth markers (polyglot/Java annotations) always win.
    """
    if node is None:
        return "unknown"
    tags = {str(tag).lower() for tag in node.attrs.get("tags", [])}
    if node.kind in {"task", "cli"}:
        return "isolated"
    is_endpoint = node.kind == "endpoint" or "endpoint" in tags or "route" in tags
    if not is_endpoint:
        return "isolated"
    auth = node.attrs.get("auth")
    if auth == "anonymous":
        return "public"
    if auth in (True, "required") or "auth" in tags or "auth_dependency" in tags:
        return "privileged"
    security_tags = {str(tag).lower() for tag in node.attrs.get("security", [])}
    if (
        node.attrs.get("trust_boundary") == "ingress"
        and node.attrs.get("routes")
        and "source" in security_tags
    ):
        return "public"
    return "unknown"


def classify_exposure(graph: Graph, finding: Finding) -> str:
    """Classify a finding into the canonical exposure taxonomy."""
    category = finding.category
    if category in SECRET_CATEGORIES:
        return "sensitive_data"
    validation = finding.metadata.get("validation") or {}
    if validation.get("known_exploited"):
        # Known exploited in the wild: impact is externally verified even
        # without a static entry point.
        return "internal_high_impact"
    # For tainted findings the exposure is the entry point's, not the sink's.
    node = _flow_entry_node(graph, finding) or graph.nodes.get(finding.node_id or "")
    if node is not None:
        exposure = node_exposure_class(node)
        if exposure in EXPOSURE_STATES:
            return exposure
        return "unknown"
    if finding.trace:
        return "unknown"
    if category in CONFIG_EXPOSURE_CATEGORIES:
        title_lower = finding.title.lower()
        if any(word in title_lower for word in _ADMIN_TITLE_WORDS):
            # Admin/debug surface exists; without an entry point we assume it
            # is behind some boundary.
            return "privileged"
        return "unknown"
    return "unknown"


def _flow_entry_node(graph: Graph, finding: Finding) -> Any:
    """Return the entry node for a finding's recorded taint flow, if any."""
    hops = finding.metadata.get("flow") or []
    if isinstance(hops, list) and hops:
        first = hops[0]
        if isinstance(first, dict):
            node_id = first.get("node") or first.get("node_id")
            if node_id:
                return graph.nodes.get(str(node_id))
    if finding.trace:
        first = finding.trace[0]
        for node in graph.nodes.values():
            if node.path and node.path == first.path and node.line == first.line:
                return node
    return None
