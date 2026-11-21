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

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .model import Finding, Graph, Loc, stable_id
from .risk import endpoint_exposure
from .threat_review import attach_threat_records, render_threat_records

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
     frozenset({"sql", "nosql", "ldap", "xpath"}), "Use parameterized queries and typed filters for every data store call."),
    ("data", "I", "Data store or file contents disclosed",
     frozenset({"sql", "nosql", "ldap", "xpath", "path"}), "Parameterize queries; resolve file paths against a fixed base directory."),
    ("external", "S", "Outbound connections to untrusted or spoofed peers",
     frozenset({"tls"}), "Keep TLS certificate verification on; pin or allowlist peers."),
    ("external", "I", "Server-side request forgery to internal services / cloud metadata",
     frozenset({"ssrf"}), "Allowlist outbound hosts, block link-local and private ranges, require IMDSv2."),
    ("external", "T", "Users redirected to attacker-controlled destinations",
     frozenset({"redirect"}), "Redirect only to relative paths or allowlisted hosts."),
    ("host", "E", "Code or command execution on the host",
     frozenset({"command", "code", "template", "deserialization", "file-inclusion"}),
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
    ("internet", "R", "Audit records forged through log injection",
     frozenset({"log"}), "Use structured logging and prevent caller-controlled record delimiters."),
    ("data", "I", "Weak cryptography exposes protected data",
     frozenset({"crypto"}), "Use current cryptographic algorithms appropriate to the protected asset."),
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
    records: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "boundary": self.boundary, "stride": self.stride, "title": self.title,
            "status": self.status, "priority": self.priority, "max_score": self.max_score,
            "finding_ids": self.finding_ids, "evidence": self.evidence, "mitigation": self.mitigation,
            "note": self.note,
            "records": self.records,
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
            # A taint trace does not establish the absence of global authentication.
            status="review" if open_count else "no-evidence",
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
    attach_threat_records(graph, threats)
    for threat in threats:
        if threat.status == "observed" and not threat.records:
            threat.status = "review"
            threat.note = "Matched rule claims have no usable source locations; obtain source evidence before treating them as findings."
    return threats


def summarize_threat_model(graph: Graph, threats: list[Threat]) -> None:
    graph.meta["threat_model"] = {
        "threats": len(threats),
        "observed": sum(1 for t in threats if t.status == "observed"),
        "review": sum(1 for t in threats if t.status == "review"),
        "not_assessed": sum(1 for t in threats if t.status == "not-assessed"),
        "records": sum(len(t.records) for t in threats),
        "by_boundary": {
            key: sum(1 for t in threats if t.boundary == key and t.status == "observed") for key, _, _ in BOUNDARIES
        },
    }


def _ascii(text: str) -> str:
    return " ".join(str(text).split()).replace("|", "/").replace("`", "'").replace("<", "&lt;").encode("ascii", "replace").decode("ascii")


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
    lines.append("Status legend: **observed** = backed by static rule findings, not a confirmed exploit; **review** = structural signal to confirm; "
                 "**no evidence** = no matching active finding in this graph (not proof of absence or scan coverage); "
                 "**not assessed** = outside static analysis.")
    lines.append("")
    lines.extend(["## Actionable observations and review signals", "",
                  "Facts describe analyzer observations. Assessments, assumptions and runtime verification are separate. "
                  "Missing authentication markers do not establish public deployment or an authorization bypass.", "",
                  render_threat_records([record for threat in threats for record in threat.records]) or "No source-backed observations.", "",
                  "## STRIDE coverage overview", "",
                  "The catalog below is coverage context; unmatched categories and unassessed controls are not findings.", ""])
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
        lines.append("| STRIDE | Threat category | Status | Priority | Evidence |")
        lines.append("|---|---|---|---|---|")
        for threat in sorted(group, key=lambda t: ("STRIDE".index(t.stride), t.title)):
            evidence = "; ".join(f"`{_ascii(e)}`" for e in threat.evidence) or _ascii(threat.note) or "-"
            if threat.evidence and len(threat.finding_ids) > len(threat.evidence):
                evidence += f" (+{len(threat.finding_ids) - len(threat.evidence)} more)"
            elif threat.evidence and threat.note:
                evidence += f" - {_ascii(threat.note)}"
            priority = f"**{threat.priority}** ({threat.max_score})" if threat.priority else "-"
            lines.append(
                f"| {STRIDE_NAMES[threat.stride]} | {_ascii(threat.title)} | {status_text[threat.status]} | "
                f"{priority} | {evidence} |"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


# ---------------------------------------------------------------------------
# MITRE ATT&CK evaluation (continuous threat modeling)
# ---------------------------------------------------------------------------
# Architectural rules: a rule fires "observed" when evidence-backed findings
# exist, "review" when only a structural signal exists (e.g. entry points whose
# authentication could not be determined), and "no-evidence" otherwise. As with
# the STRIDE model, "no evidence" is not a proof of absence.


@dataclass(frozen=True, slots=True)
class AttackRule:
    technique: str
    name: str
    tactic: str
    categories: frozenset[str]
    mitigation: str
    missing_mitigation: str
    structural: Callable[[Graph], list[str]] | None = None


@dataclass(slots=True)
class AttackEval:
    technique: str
    name: str
    tactic: str
    status: str  # observed | review | no-evidence
    mitigation: str
    missing_mitigation: str
    finding_ids: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    priority: str | None = None
    max_score: float = 0.0

    @property
    def reference(self) -> str:
        return f"https://attack.mitre.org/techniques/{self.technique}/"

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique": self.technique,
            "name": self.name,
            "tactic": self.tactic,
            "status": self.status,
            "priority": self.priority,
            "max_score": self.max_score,
            "reference": self.reference,
            "finding_ids": self.finding_ids,
            "evidence": self.evidence,
            "mitigation": self.mitigation,
            "missing_mitigation": self.missing_mitigation,
        }


def _structural_public_entrypoints(graph: Graph) -> list[str]:
    """Entry points reachable without a detected authentication marker."""
    signals: list[str] = []
    for node in graph.sorted_nodes():
        if node.kind != "endpoint":
            continue
        exposure = endpoint_exposure(node)
        if exposure not in ("public", "unknown"):
            continue
        loc = node.evidence or Loc(node.path or "", node.line or 0)
        signals.append(f"{loc.ref} endpoint {node.qualname} exposure={exposure}")
    return signals


ATTACK_RULES: tuple[AttackRule, ...] = (
    AttackRule(
        technique="T1190",
        name="Exploit Public-Facing Application",
        tactic="Initial Access",
        categories=frozenset({"sql", "nosql", "command", "code", "deserialization", "file-inclusion", "xss", "path"}),
        mitigation="Authenticate every entry point by default; validate and parameterize all client input; deploy edge protections.",
        missing_mitigation="Entry-point authentication / edge protections not detected on public-facing routes.",
        structural=_structural_public_entrypoints,
    ),
    AttackRule(
        technique="T1040",
        name="Network Sniffing",
        tactic="Credential Access",
        categories=frozenset({"tls"}),
        mitigation="Keep TLS certificate verification enabled end to end; reject cleartext transport for sensitive flows.",
        missing_mitigation="Transport encryption controls not detected (TLS verification findings indicate interceptable traffic).",
    ),
    AttackRule(
        technique="T1078",
        name="Valid Accounts",
        tactic="Privilege Escalation",
        categories=frozenset({"jwt", "auth", "cookie"}),
        mitigation="Verify token signatures and expiry, use CSPRNG session tokens, set HttpOnly+Secure cookie flags.",
        missing_mitigation="Session/identity token hardening not detected.",
    ),
    AttackRule(
        technique="T1552",
        name="Unsecured Credentials",
        tactic="Credential Access",
        categories=frozenset({"secret"}),
        mitigation="Rotate exposed credentials and load secrets from a secret manager at runtime.",
        missing_mitigation="Credentials committed to source or images (no secret-manager usage detected).",
    ),
    AttackRule(
        technique="T1195",
        name="Supply Chain Compromise",
        tactic="Initial Access",
        categories=frozenset({"supply-chain", "supply_chain", "dependency", "ci"}),
        mitigation="Pin actions and images by digest, use least-privilege CI tokens, verify dependencies.",
        missing_mitigation="Build/dependency pipeline integrity controls not detected.",
    ),
    AttackRule(
        technique="T1068",
        name="Exploit for Privilege Escalation",
        tactic="Privilege Escalation",
        categories=frozenset({"container", "cloud"}),
        mitigation="Run containers as non-root, drop capabilities, apply least-privilege IAM roles.",
        missing_mitigation="Over-privileged runtime or cloud roles detected.",
    ),
)

ATTACK_STATUS_TEXT = {"observed": "observed", "review": "review", "no-evidence": "no evidence"}


def attack_status_label(status: str) -> str:
    return ATTACK_STATUS_TEXT.get(status, status)


def evaluate_attack(graph: Graph, findings: list[Finding] | None = None) -> list[AttackEval]:
    """Map evidence-backed findings and architectural signals to ATT&CK techniques.

    Deterministic: rules are evaluated in ``ATTACK_RULES`` order and evidence is
    sorted by risk score, then source location.
    """
    active = [f for f in (findings if findings is not None else graph.sorted_findings()) if not f.baseline]
    evals: list[AttackEval] = []
    for rule in ATTACK_RULES:
        matched = sorted(
            (f for f in active if f.category in rule.categories),
            key=lambda f: (-float((f.metadata.get("risk") or {}).get("score", 0.0)), f.id),
        )
        evaluation = AttackEval(
            technique=rule.technique,
            name=rule.name,
            tactic=rule.tactic,
            status="no-evidence",
            mitigation=rule.mitigation,
            missing_mitigation=rule.missing_mitigation,
        )
        if matched:
            evaluation.status = "observed"
            evaluation.finding_ids = [f.id for f in matched]
            evaluation.evidence = [
                f"{f.title} ({f.evidence[0].ref})" for f in matched[:5] if f.evidence
            ]
            scores = [float((f.metadata.get("risk") or {}).get("score", 0.0)) for f in matched]
            evaluation.max_score = max(scores) if scores else 0.0
            evaluation.priority = min(
                (str((f.metadata.get("risk") or {}).get("priority", "P3")) for f in matched),
                key=lambda p: PRIORITY_ORDER.get(p, 3),
            )
        elif rule.structural is not None:
            signals = rule.structural(graph)
            if signals:
                evaluation.status = "review"
                evaluation.evidence = signals[:10]
                evaluation.max_score = 0.0
        evals.append(evaluation)
    return evals


def summarize_attack(graph: Graph, evals: list[AttackEval]) -> None:
    graph.meta["attack"] = {
        "techniques": len(evals),
        "observed": sum(1 for e in evals if e.status == "observed"),
        "review": sum(1 for e in evals if e.status == "review"),
        "by_tactic": {
            tactic: sum(1 for e in evals if e.tactic == tactic and e.status == "observed")
            for tactic in sorted({e.tactic for e in evals})
        },
    }


# ---------------------------------------------------------------------------
# Audit policy (stdlib-only YAML subset)
# ---------------------------------------------------------------------------
# The policy file is a restricted YAML dialect: nested mappings by indentation,
# lists via "- ", scalar values (string/int/float/bool), and full-line comments.
# Parsing is hand-rolled because secdiagram's core must stay 100% standard
# library, and the dialect is deliberately tiny so results stay deterministic.


@dataclass(frozen=True, slots=True)
class AttackPolicy:
    fail_priorities: tuple[str, ...] = ("P0", "P1")
    min_score: float = 6.0
    techniques: tuple[str, ...] = ()
    ignore_techniques: tuple[str, ...] = ()
    include_review: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "fail_priorities": list(self.fail_priorities),
            "min_score": self.min_score,
            "techniques": list(self.techniques),
            "ignore_techniques": list(self.ignore_techniques),
            "include_review": self.include_review,
        }


def _policy_scalar(text: str) -> Any:
    value = text.strip()
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [_policy_scalar(item) for item in inner.split(",")]
    if value.lower() in ("true", "false"):
        return value.lower() == "true"
    if value.lower() in ("null", "none", "~"):
        return None
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def _parse_policy_yaml(text: str) -> dict[str, Any]:
    """Parse the restricted policy YAML dialect into nested dicts/lists."""
    significant: list[tuple[int, str]] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        significant.append((lineno, raw))
    root: dict[str, Any] = {}
    stack: list[tuple[int, Any]] = [(-1, root)]
    for index, (lineno, raw) in enumerate(significant):
        indent = len(raw) - len(raw.lstrip(" \t"))
        if "\t" in raw[:indent]:
            raise ValueError(f"policy line {lineno}: tabs are not allowed for indentation")
        while len(stack) > 1 and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]
        line = raw.strip()
        if line.startswith("- "):
            if not isinstance(parent, list):
                raise ValueError(f"policy line {lineno}: list item without a list key")
            parent.append(_policy_scalar(line[2:]))
            continue
        if ":" not in line:
            raise ValueError(f"policy line {lineno}: expected 'key: value'")
        key, _, rest = line.partition(":")
        key = key.strip()
        if not key or " " in key:
            raise ValueError(f"policy line {lineno}: invalid key {key!r}")
        rest = rest.strip()
        if rest == "":
            nxt = significant[index + 1] if index + 1 < len(significant) else None
            child_is_list = bool(
                nxt
                and len(nxt[1]) - len(nxt[1].lstrip(" ")) > indent
                and nxt[1].strip().startswith("- ")
            )
            child: Any = [] if child_is_list else {}
            parent[key] = child
            stack.append((indent, child))
        else:
            parent[key] = _policy_scalar(rest)
    return root


def parse_policy(text: str) -> AttackPolicy:
    data = _parse_policy_yaml(text)
    if not isinstance(data, dict):
        raise ValueError("policy root must be a mapping")
    valid_priorities = ("P0", "P1", "P2", "P3")
    fail_priorities = data.get("fail_priorities") or []
    if not isinstance(fail_priorities, list):
        raise ValueError("fail_priorities must be a list")
    for item in fail_priorities:
        if item not in valid_priorities:
            raise ValueError(f"unknown priority {item!r}; expected one of {', '.join(valid_priorities)}")
    min_score = data.get("min_score", 6.0)
    if not isinstance(min_score, (int, float)) or isinstance(min_score, bool) or not 0.0 <= float(min_score) <= 10.0:
        raise ValueError("min_score must be a number between 0.0 and 10.0")
    techniques = data.get("techniques") or []
    ignore = data.get("ignore_techniques") or []
    for name, value in (("techniques", techniques), ("ignore_techniques", ignore)):
        if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
            raise ValueError(f"{name} must be a list of technique ids")
    known = {rule.technique for rule in ATTACK_RULES}
    for value in list(techniques) + list(ignore):
        if value not in known:
            raise ValueError(f"unknown technique {value!r}; known: {', '.join(sorted(known))}")
    include_review = data.get("include_review", False)
    if not isinstance(include_review, bool):
        raise ValueError("include_review must be a boolean")
    return AttackPolicy(
        fail_priorities=tuple(fail_priorities),
        min_score=float(min_score),
        techniques=tuple(techniques),
        ignore_techniques=tuple(ignore),
        include_review=include_review,
    )


DEFAULT_POLICY_YAML = """\
# secdiagram ATT&CK audit policy.
# A technique violates the policy when its status is observed (or review when
# include_review is true), its risk priority is in fail_priorities, and its
# score is at least min_score.
fail_priorities: [P0, P1]
min_score: 6.0
include_review: false
# techniques: []          # empty = evaluate every technique
# ignore_techniques: []   # technique ids to exempt from this gate
"""


def load_policy(path: Path) -> AttackPolicy:
    return parse_policy(path.read_text(encoding="utf-8"))


def policy_violations(evals: list[AttackEval], policy: AttackPolicy) -> list[AttackEval]:
    """Return the evaluations that break the policy, deterministically ordered."""
    allowed = set(policy.techniques) if policy.techniques else {rule.technique for rule in ATTACK_RULES}
    ignored = set(policy.ignore_techniques)
    statuses = {"observed", "review"} if policy.include_review else {"observed"}
    violating: list[AttackEval] = []
    for evaluation in evals:
        if evaluation.technique not in allowed or evaluation.technique in ignored:
            continue
        if evaluation.status not in statuses:
            continue
        if (evaluation.priority or "P3") in policy.fail_priorities or evaluation.max_score >= policy.min_score:
            violating.append(evaluation)
    violating.sort(key=lambda e: (-e.max_score, e.technique))
    return violating


def render_attack_summary(evals: list[AttackEval], policy: AttackPolicy, violating: list[AttackEval]) -> str:
    """Deterministic plain-text audit summary for CI logs."""
    width = 6
    lines = [
        f"ATT&CK audit: {len(evals)} technique(s) evaluated, {len(violating)} violating",
        "",
        "Technique | Tactic | Status | Priority | Score | Missing mitigation | Evidence",
        "---|---|---|---|---|---|---",
    ]
    for evaluation in evals:
        priority = evaluation.priority or "-"
        score = f"{evaluation.max_score:.1f}" if evaluation.max_score else "-"
        evidence = "; ".join(evaluation.evidence) or "-"
        missing = evaluation.missing_mitigation if evaluation.status != "no-evidence" else "-"
        lines.append(
            f"{evaluation.technique.ljust(width)} | {evaluation.tactic} | "
            f"{ATTACK_STATUS_TEXT[evaluation.status]} | {priority} | {score} | {missing} | {evidence}"
        )
    if violating:
        lines.append("")
        lines.append(
            "Policy violation: " + ", ".join(
                f"{e.technique} ({ATTACK_STATUS_TEXT[e.status]}, {e.priority or '-'})"
                for e in violating
            )
        )
        lines.append(
            f"Gate: fail_priorities={','.join(policy.fail_priorities) or 'none'} "
            f"min_score={policy.min_score} include_review={str(policy.include_review).lower()}"
        )
    else:
        lines.append("")
        lines.append("Policy: PASS")
    return "\n".join(lines) + "\n"
