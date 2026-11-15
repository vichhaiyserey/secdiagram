"""Evidence-backed STRIDE threat model per trust boundary.

The model follows the classic data-flow threat-modelling approach (STRIDE per
element/interaction, as used in Microsoft SDL and the Threat Modeling
Manifesto) but is generated from what the analysis actually observed:

* Trust boundaries come from the architecture: Internet -> application entry
  points, application -> data stores, application -> external services,
  application -> host/runtime, and source/supply chain.
* Each STRIDE threat lists the findings that evidence it (with their risk
  priority), a structural signal when one exists (e.g. entry points whose
  authentication could not be determined), or states honestly that the threat
  is *not assessed* by static analysis (repudiation, rate limiting).

"No evidence found" means the relevant rules ran and matched nothing - it is
not a proof of absence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .model import Finding, Graph, stable_id
from .risk import endpoint_exposure

BOUNDARIES: tuple[tuple[str, str, str], ...] = (
    ("internet", "Internet -> Application", "Requests from clients and other callers cross into entry points."),
    ("data", "Application -> Data stores", "Queries and file operations reach databases, caches and disks."),
    ("external", "Application -> External services", "Outbound calls to third-party APIs, cloud metadata and peers."),
    ("host", "Application -> Host / runtime", "Process execution, deserialization and parsers on the host."),
    ("supply", "Source & supply chain", "Code, credentials, dependencies, CI/CD and container images."),
)

# (boundary, STRIDE letter, threat, categories that evidence it, mitigation)
CATALOG: tuple[tuple[str, str, str, frozenset[str], str], ...] = (
    ("internet", "S", "Identity tokens forged, replayed or predicted",
     frozenset({"jwt", "auth", "cookie", "randomness"}),
     "Verify token signatures/expiry, use CSPRNG tokens, HttpOnly+Secure cookies."),
    ("internet", "T", "Requests forged or tampered (CSRF, CORS, client-side injection)",
     frozenset({"csrf", "cors", "xss", "prototype-pollution"}),
     "Keep CSRF protection, restrict CORS origins, encode output, reject polluting keys."),
    ("internet", "R", "Security-relevant actions not attributable",
     frozenset(), "Log authentication, authorization and data-changing events with user and request ids."),
    ("internet", "I", "Sensitive data or internals disclosed to clients",
     frozenset({"misconfig", "redirect", "cors"}),
     "Disable debug pages in production, validate redirects, avoid reflecting origins."),
    ("internet", "D", "Entry points exhausted by request floods or expensive operations",
     frozenset(), "Apply rate limits, request size limits and timeouts at the edge and per endpoint."),
    ("data", "T", "Injection into data stores",
     frozenset({"sql", "nosql"}), "Use parameterized queries and typed filters for every data store call."),
    ("data", "I", "Data store or file contents disclosed",
     frozenset({"sql", "nosql", "path"}), "Parameterize queries; resolve file paths against a fixed base directory."),
    ("external", "S", "Outbound connections to untrusted or spoofed peers",
     frozenset({"tls"}), "Keep TLS certificate verification on; pin or allowlist peers."),
    ("external", "I", "Server-side request forgery to internal services / cloud metadata",
     frozenset({"ssrf"}), "Allowlist outbound hosts, block link-local and private ranges, require IMDSv2."),
    ("external", "T", "Users redirected to attacker-controlled destinations",
     frozenset({"redirect"}), "Redirect only to relative paths or allowlisted hosts."),
    ("host", "E", "Code or command execution on the host",
     frozenset({"command", "code", "deserialization", "file-inclusion"}),
     "Never pass input to shells, evaluators, type-resolving deserializers or include()."),
    ("host", "T", "Arbitrary file read/write or entity resolution",
     frozenset({"path", "xxe"}), "Canonicalize paths under a base dir; disable DTDs/external entities."),
    ("host", "D", "Parser resource exhaustion (entity expansion, deserialization bombs)",
     frozenset({"xxe", "deserialization"}), "Disable DTD processing and cap payload sizes."),
    ("supply", "I", "Credentials committed to source or images",
     frozenset({"secret"}), "Rotate exposed credentials; load secrets from a secret manager."),
    ("supply", "T", "Build, dependency or deployment pipeline tampering",
     frozenset({"ci", "supply-chain", "supply_chain", "dependency"}),
     "Pin actions/images by digest, least-privilege tokens, verify dependencies."),
    ("supply", "E", "Over-privileged containers or cloud resources",
     frozenset({"container", "cloud"}), "Run as non-root, drop capabilities, least-privilege IAM."),
)
STRIDE_NAMES = {
    "S": "Spoofing", "T": "Tampering", "R": "Repudiation",
    "I": "Information disclosure", "D": "Denial of service", "E": "Elevation of privilege",
}
PRIORITY_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}


@dataclass(slots=True)
class Threat:
    id: str
    boundary: str
    stride: str
    title: str
    status: str  # observed | review | no-evidence | not-assessed
    mitigation: str
    finding_ids: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    priority: str | None = None
    max_score: float = 0.0
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "boundary": self.boundary, "stride": self.stride, "title": self.title,
            "status": self.status, "priority": self.priority, "max_score": self.max_score,
            "finding_ids": self.finding_ids, "evidence": self.evidence, "mitigation": self.mitigation,
            "note": self.note,
        }


def _risk(finding: Finding) -> tuple[float, str]:
    risk = finding.metadata.get("risk") or {}
    return float(risk.get("score", 0.0)), str(risk.get("priority", "P3"))


def build_threat_model(graph: Graph) -> list[Threat]:
    """STRIDE threats per trust boundary, evidenced by the graph's findings."""
    active = [f for f in graph.sorted_findings() if not f.baseline]
    endpoints = [n for n in graph.sorted_nodes() if n.kind == "endpoint"]
    exposures = [endpoint_exposure(n) for n in endpoints]
    threats: list[Threat] = []
    for boundary, letter, title, categories, mitigation in CATALOG:
        matched = sorted(
            (f for f in active if f.category in categories),
            key=lambda f: (-_risk(f)[0], f.evidence[0].ref if f.evidence else "", f.id),
        )
        threat = Threat(
            id=stable_id("threat", boundary, letter, title),
            boundary=boundary, stride=letter, title=title, status="no-evidence", mitigation=mitigation,
        )
        if matched:
            threat.status = "observed"
            threat.finding_ids = [f.id for f in matched]
            threat.evidence = [f"{f.title} ({f.evidence[0].ref})" for f in matched[:3] if f.evidence]
            threat.max_score, threat.priority = _risk(matched[0])
        elif not categories:
            threat.status = "not-assessed"
            threat.note = "Not verifiable by static analysis; confirm in design review or runtime testing."
        threats.append(threat)
    # Structural signal: entry points whose authentication is absent or unknown.
    open_count = sum(1 for e in exposures if e in ("public", "unknown"))
    auth_count = sum(1 for e in exposures if e == "authenticated")
    if endpoints:
        reaching = [
            f for f in active
            if (f.metadata.get("risk") or {}).get("exposure") in ("public", "unknown")
            and (f.metadata.get("risk") or {}).get("evidence") == "proven-flow"
        ]
        threat = Threat(
            id=stable_id("threat", "internet", "S", "unauthenticated-entry"),
            boundary="internet", stride="S", title="Entry points reachable without (detected) authentication",
            status="observed" if reaching else ("review" if open_count else "no-evidence"),
            mitigation="Require authentication by default; mark intentionally public routes explicitly.",
            note=f"{open_count} of {len(endpoints)} entry point(s) have no detected auth marker "
            f"({auth_count} authenticated).",
        )
        if reaching:
            reaching.sort(key=lambda f: (-_risk(f)[0], f.id))
            threat.finding_ids = [f.id for f in reaching]
            threat.evidence = [f"{f.title} ({f.evidence[0].ref})" for f in reaching[:3] if f.evidence]
            threat.max_score, threat.priority = _risk(reaching[0])
        threats.insert(0, threat)
    return threats


def summarize_threat_model(graph: Graph, threats: list[Threat]) -> None:
    graph.meta["threat_model"] = {
        "threats": len(threats),
        "observed": sum(1 for t in threats if t.status == "observed"),
        "review": sum(1 for t in threats if t.status == "review"),
        "not_assessed": sum(1 for t in threats if t.status == "not-assessed"),
        "by_boundary": {
            key: sum(1 for t in threats if t.boundary == key and t.status == "observed") for key, _, _ in BOUNDARIES
        },
    }


def _ascii(text: str) -> str:
    return " ".join(str(text).split()).replace("|", "/").encode("ascii", "replace").decode("ascii")


def _boundary_diagram(threats: list[Threat]) -> list[str]:
    worst: dict[str, str] = {}
    counts: dict[str, int] = {}
    for threat in threats:
        if threat.status != "observed" or threat.priority is None:
            continue
        counts[threat.boundary] = counts.get(threat.boundary, 0) + 1
        current = worst.get(threat.boundary)
        if current is None or PRIORITY_ORDER[threat.priority] < PRIORITY_ORDER[current]:
            worst[threat.boundary] = threat.priority
    lines = ["```mermaid", "flowchart LR"]
    lines.append('  client(["Clients / Internet"])')
    lines.append('  app["Application (entry points, services)"]')
    lines.append('  data[("Data stores")]')
    lines.append('  ext[/"External services"/]')
    lines.append('  host{{"Host / runtime"}}')
    lines.append('  supply[["Source & supply chain"]]')
    edges = (("client", "app", "internet"), ("app", "data", "data"), ("app", "ext", "external"),
             ("app", "host", "host"), ("supply", "app", "supply"))
    for src, dst, key in edges:
        label = f"{counts.get(key, 0)} threat(s)" + (f" - worst {worst[key]}" if key in worst else "")
        lines.append(f'  {src} -->|"{label}"| {dst}')
    colors = {"P0": "#dc2626", "P1": "#ea580c", "P2": "#ca8a04", "P3": "#64748b"}
    for index, (_src, _dst, key) in enumerate(edges):
        if key in worst:
            lines.append(f"  linkStyle {index} stroke:{colors[worst[key]]},stroke-width:3px")
    lines.append("```")
    return lines


def render_threat_model(graph: Graph, threats: list[Threat] | None = None) -> str:
    """ASCII Markdown threat model (THREAT_MODEL.md)."""
    threats = build_threat_model(graph) if threats is None else threats
    name = _ascii(graph.meta.get("name") or "repository")
    observed = sum(1 for t in threats if t.status == "observed")
    lines = [f"# Threat model: {name}", ""]
    lines.append(
        "Generated by secdiagram from static evidence (STRIDE per trust boundary). "
        f"**{observed}** of **{len(threats)}** threats are evidenced by findings; priorities come from the "
        "risk model (impact x exposure x evidence x confidence x exploit intel)."
    )
    lines.append("")
    lines.append("Status legend: **observed** = backed by findings; **review** = structural signal to confirm; "
                 "**no evidence** = rules ran and matched nothing (not proof of absence); "
                 "**not assessed** = outside static analysis.")
    lines.append("")
    lines.extend(_boundary_diagram(threats))
    lines.append("")
    status_text = {"observed": "observed", "review": "review", "no-evidence": "no evidence",
                   "not-assessed": "not assessed"}
    for key, title, description in BOUNDARIES:
        group = [t for t in threats if t.boundary == key]
        lines.append(f"## {_ascii(title)}")
        lines.append("")
        lines.append(_ascii(description))
        lines.append("")
        lines.append("| STRIDE | Threat | Status | Priority | Evidence | Mitigation |")
        lines.append("|---|---|---|---|---|---|")
        for threat in sorted(group, key=lambda t: ("STRIDE".index(t.stride), t.title)):
            evidence = "; ".join(f"`{_ascii(e)}`" for e in threat.evidence) or _ascii(threat.note) or "-"
            if threat.evidence and len(threat.finding_ids) > len(threat.evidence):
                evidence += f" (+{len(threat.finding_ids) - len(threat.evidence)} more)"
            elif threat.evidence and threat.note:
                evidence += f" - {_ascii(threat.note)}"
            priority = f"**{threat.priority}** ({threat.max_score})" if threat.priority else "-"
            lines.append(
                f"| {STRIDE_NAMES[threat.stride]} | {_ascii(threat.title)} | {status_text[threat.status]} | "
                f"{priority} | {evidence} | {_ascii(threat.mitigation)} |"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
