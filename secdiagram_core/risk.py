"""Risk-ranked findings: exposure x impact x evidence x exploit intelligence.

Severity alone answers "how bad is this class of bug"; it does not answer
"what should we fix first". Following risk-based prioritization practice
(CVSS environmental/threat metrics, SSVC "exposure" decisions, CISA KEV), every
finding gets a 0-10 score:

    score = impact x exposure x evidence x confidence x exploit_intel

* **impact** - what an attacker gains from this class of weakness (RCE >
  data breach > account takeover > misconfiguration), CVSS-style 0-10.
* **exposure** - the entry point the tainted data comes from: anonymous
  internet-facing endpoint (1.0), endpoint whose auth could not be determined
  (0.9, assume reachable), authenticated endpoint (0.65 - insiders and any
  signed-up user still reach it), local CLI / scheduled job (0.45), no entry
  point (0.4).
* **evidence** - a proven source-to-sink flow (1.0), a credential committed to
  source (0.95), an unsafe configuration (0.9, impact scaled by the rule's
  severity), a dynamically built query/command without proven input (0.5).
* **confidence** - the rule's own precision.
* **exploit_intel** - x1.2 when a matched advisory is in CISA KEV.

Scores map to priorities: **P0** >= 8.0 (fix now), **P1** >= 6.0, **P2** >= 4.0,
**P3** otherwise. Everything is deterministic and recorded in
``finding.metadata["risk"]`` with the factors that produced it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .exploitability import assess_graph
from .model import Finding, Graph, Node
from .taint_flows import TaintFlow, build_taint_flows

IMPACT: dict[str, float] = {
    "command": 10.0,
    "code": 10.0,
    "deserialization": 9.5,
    "file-inclusion": 9.5,
    "sql": 9.0,
    "jwt": 8.5,
    "auth": 8.5,
    "ssrf": 8.0,
    "secret": 8.0,
    "nosql": 8.0,
    "path": 7.5,
    "xxe": 7.5,
    "prototype-pollution": 7.0,
    "cors": 6.5,
    "xss": 6.0,
    "tls": 6.0,
    "cloud": 6.0,
    "ci": 6.0,
    "supply-chain": 6.0,
    "supply_chain": 6.0,
    "dependency": 6.0,
    "csrf": 5.5,
    "randomness": 5.0,
    "container": 5.0,
    "redirect": 4.5,
    "crypto": 4.5,
    "cookie": 4.0,
    "misconfig": 4.0,
}
SEVERITY_IMPACT = {"critical": 9.0, "high": 7.0, "medium": 5.0, "low": 3.0, "info": 1.0}
EXPOSURE = {"public": 1.0, "unknown": 0.9, "authenticated": 0.65, "local": 0.45, "internal": 0.4}
CONFIG_CATEGORIES = frozenset(
    {"jwt", "cors", "csrf", "cookie", "xxe", "randomness", "misconfig", "tls", "crypto", "container", "cloud",
     "ci", "supply-chain", "supply_chain", "secret", "auth"}
)
INJECTION_CATEGORIES = frozenset({"sql", "nosql", "command", "code", "deserialization", "file-inclusion"})
PRIORITY_BANDS = ((8.0, "P0"), (6.0, "P1"), (4.0, "P2"))
# Configuration/pattern findings carry their rule's severity (e.g. JWT signature
# check off = high, lifetime check off = medium); scale impact accordingly.
SEVERITY_SCALE = {"critical": 1.0, "high": 1.0, "medium": 0.8, "low": 0.6, "info": 0.4}


@dataclass(frozen=True, slots=True)
class RiskScore:
    score: float
    priority: str
    impact: float
    exposure: str
    evidence: str
    entry: str | None
    known_exploited: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "priority": self.priority,
            "impact": self.impact,
            "exposure": self.exposure,
            "evidence": self.evidence,
            "entry": self.entry,
            "known_exploited": self.known_exploited,
        }


def endpoint_exposure(node: Node | None) -> str:
    """Exposure class of an entry node: public | authenticated | unknown | local | internal."""
    if node is None:
        return "internal"
    tags = {str(tag).lower() for tag in node.attrs.get("tags", [])}
    if node.kind in {"task", "cli"}:
        return "local"
    is_endpoint = node.kind == "endpoint" or "endpoint" in tags or "route" in tags
    if not is_endpoint:
        return "internal"
    auth = node.attrs.get("auth")
    if auth == "anonymous":
        return "public"
    if auth in (True, "required") or "auth" in tags or "auth_dependency" in tags:
        return "authenticated"
    return "unknown"


def _priority(score: float) -> str:
    for floor, label in PRIORITY_BANDS:
        if score >= floor:
            return label
    return "P3"


def _known_exploited(finding: Finding) -> bool:
    return bool((finding.metadata.get("validation") or {}).get("known_exploited"))


def score_finding(graph: Graph, finding: Finding, flow: TaintFlow | None) -> RiskScore:
    impact = IMPACT.get(finding.category, SEVERITY_IMPACT.get(finding.severity, 5.0))
    entry: str | None = None
    if flow is not None and flow.node_path:
        entry = flow.node_path[0]
        exposure = endpoint_exposure(graph.nodes.get(entry))
        evidence = "proven-flow"
        evidence_factor = 1.0
    else:
        node = graph.nodes.get(finding.node_id or "")
        node_exposure = endpoint_exposure(node)
        if finding.metadata.get("runtime_confirmed") and node_exposure != "internal":
            # A DAST scanner reached this endpoint at runtime, so risk ranking
            # must not treat an unknown exposure as merely theoretical.
            exposure = "public" if node_exposure == "unknown" else node_exposure
            evidence, evidence_factor = "runtime-observed", 1.0
        elif finding.category == "secret":
            # A credential in source is definitive: anyone with the repo or image has it.
            exposure = "unknown"
            evidence, evidence_factor = "credential-in-source", 0.95
            impact *= SEVERITY_SCALE.get(finding.severity, 0.8)
        elif finding.category in CONFIG_CATEGORIES:
            # Application-wide configuration: reachable wherever the app is.
            exposure = node_exposure if node_exposure in ("public", "authenticated") else "unknown"
            evidence, evidence_factor = "unsafe-configuration", 0.9
            impact *= SEVERITY_SCALE.get(finding.severity, 0.8)
        elif finding.metadata.get("tainted") or finding.trace:
            exposure = node_exposure
            evidence, evidence_factor = "proven-flow", 1.0
        elif finding.category in INJECTION_CATEGORIES:
            exposure = node_exposure
            evidence, evidence_factor = "dynamic-construction", 0.5
        else:
            exposure = node_exposure if node_exposure != "internal" else "unknown"
            evidence, evidence_factor = "pattern", 0.7
            impact *= SEVERITY_SCALE.get(finding.severity, 0.8)
    known_exploited = _known_exploited(finding)
    confidence = 0.7 + 0.3 * max(0.0, min(1.0, float(finding.confidence)))
    raw = impact * EXPOSURE[exposure] * evidence_factor * confidence * (1.2 if known_exploited else 1.0)
    score = round(min(10.0, raw), 1)
    if known_exploited:
        score = max(score, 8.0)
    return RiskScore(
        score=score,
        priority=_priority(score),
        impact=round(impact, 2),
        exposure=exposure,
        evidence=evidence,
        entry=entry,
        known_exploited=known_exploited,
    )


def score_findings(graph: Graph, flows: list[TaintFlow] | None = None) -> list[tuple[Finding, RiskScore]]:
    """Attach ``metadata["risk"]`` to every finding; return them ranked (highest first)."""
    flows = build_taint_flows(graph) if flows is None else flows
    flow_by_finding = {flow.finding.id: flow for flow in flows}
    ranked: list[tuple[Finding, RiskScore]] = []
    for finding in graph.sorted_findings():
        risk = score_finding(graph, finding, flow_by_finding.get(finding.id))
        finding.metadata["risk"] = risk.to_dict()
        ranked.append((finding, risk))
    ranked.sort(key=lambda item: risk_sort_key(item[0]))
    active = [risk for finding, risk in ranked if not finding.baseline]
    graph.meta["risk"] = {
        "model": "impact x exposure x evidence x confidence x exploit_intel (0-10)",
        "by_priority": {label: sum(1 for r in active if r.priority == label) for label in ("P0", "P1", "P2", "P3")},
        "by_exposure": {
            label: sum(1 for r in active if r.exposure == label)
            for label in ("public", "unknown", "authenticated", "local", "internal")
        },
        "top": [finding.id for finding, _ in ranked if not finding.baseline][:10],
    }
    assess_graph(graph, flows)
    return ranked


def risk_sort_key(finding: Finding) -> tuple[Any, ...]:
    """Highest risk first; ties broken deterministically by location."""
    risk = finding.metadata.get("risk") or {}
    location = finding.evidence[0] if finding.evidence else None
    return (
        -float(risk.get("score", 0.0)),
        location.path if location else "",
        location.line if location else 0,
        finding.category,
        finding.id,
    )
