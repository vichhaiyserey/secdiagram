"""High-confidence security policy: separates detection from enforcement.

Detection stays evidence-first in the analyzers; this layer decides what a
finding *does*: block CI, demand review, stay informational, or fall under a
governed, expiring suppression.

A finding may block only when **all** of the following hold:

1. Severity is ``critical`` or ``high``.
2. Decision confidence is at least ``BLOCK_CONFIDENCE_THRESHOLD`` (0.90).
3. Evidence is deterministic or externally verified.
4. The issue is reachable from an exposed or privileged entry point (or is
   itself exposed credential material).
5. No effective compensating control exists.
6. The finding belongs to an approved high-risk category.

If any condition is missing, the finding is downgraded to ``review`` (when
severity is critical/high) or ``informational``. LLM-produced findings can
never block: LLMs are triage aids, not evidence sources.

Modes:

* ``shadow``       - decisions recorded, CI never fails because of them.
* ``report-only``  - decisions recorded and surfaced in reports; CI unchanged.
* ``strict``       - ``block`` decisions fail CI (exit code 2 via --fail-on block).

Everything is deterministic: identical graphs produce identical decisions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .confidence import BLOCK_CONFIDENCE_THRESHOLD, compute_confidence
from .dast_reports import DAST_SOURCES
from .exposure import BLOCK_ELIGIBLE_EXPOSURES, classify_exposure
from .model import Finding, Graph
from .reachability import (
    INJECTION_CATEGORIES,
    classify_reachability,
    has_complete_path,
    sanitizer_assessment,
)

POLICY_VERSION = "1"
POLICY_MODES = ("shadow", "report-only", "strict")
DECISIONS = ("block", "review", "informational", "suppressed", "accepted_risk")

BLOCKING_SEVERITIES = frozenset({"critical", "high"})
# Evidence qualities that count as "deterministic or externally verified".
# LLM-only evidence is deliberately absent.
BLOCK_EVIDENCE_QUALITIES = frozenset(
    {"provider_verified", "externally_verified", "proven_flow", "credential_in_source", "unsafe_configuration"}
)
# Entry-point reachability classes strong enough to consider blocking.
BLOCK_REACHABILITY = frozenset({"externally_reachable", "authenticated_reachable"})
NO_CONTROL_STATUSES = frozenset({"none", "unknown", ""})

# Approved high-risk scope. Everything else is informational until reachability
# and exploitability are proven for that category.
HIGH_RISK_CATEGORIES = frozenset(
    {
        "secret",
        "sql",
        "nosql",
        "command",
        "code",
        "deserialization",
        "template",
        "path",
        "network",
        "dependency",
    }
)

SECRET_REMOVAL_ACTIONS = (
    "Rotate the credential",
    "Remove the secret from source",
    "Retrieve runtime secrets from an approved secret manager",
    "Purge the credential from repository history where required",
)
INJECTION_ACTIONS = (
    "Parameterize the sink or validate input server-side",
    "Add a regression test covering the tainted path",
    "Review sanitizer coverage for this entry point",
)
DEPENDENCY_ACTIONS = (
    "Upgrade the affected package to a fixed version",
    "Confirm the vulnerable code path is not reachable",
    "Pin and monitor the dependency for a fix",
)
RUNTIME_ACTIONS = (
    "Reproduce the runtime finding against the affected endpoint",
    "Fix or validate the affected endpoint and parameter",
    "Add a regression test that covers the observed request",
)


@dataclass(frozen=True, slots=True)
class PolicyResult:
    """The enforcement decision for a single finding."""

    enforcement: str
    policy_reason: str
    confidence_score: float
    reachability: str
    exposure: str
    mitigation_status: str
    evidence_quality: str
    required_actions: tuple[str, ...]


@dataclass(slots=True)
class PolicySummary:
    """Deterministic run-level policy outcome recorded in ``graph.meta``."""

    mode: str
    version: str = POLICY_VERSION
    decisions: dict[str, int] = field(default_factory=dict)
    blocks: list[str] = field(default_factory=list)
    reviews: list[str] = field(default_factory=list)
    suppressed: list[str] = field(default_factory=list)
    reactivated: list[str] = field(default_factory=list)
    llm_blocks: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "version": self.version,
            "decisions": dict(sorted(self.decisions.items())),
            "blocks": list(self.blocks),
            "reviews": list(self.reviews),
            "suppressed": list(self.suppressed),
            "reactivated": list(self.reactivated),
            "llm_blocks": self.llm_blocks,
        }


def _is_llm_sourced(finding: Finding) -> bool:
    return finding.source.startswith("llm") or finding.metadata.get("origin") == "llm"


def _secret_kind(finding: Finding) -> str:
    return str(finding.metadata.get("secret_kind") or "assignment")


def _is_dependency_finding(finding: Finding) -> bool:
    return bool(finding.metadata.get("package") or finding.metadata.get("cves"))


def _is_runtime_confirmed(finding: Finding) -> bool:
    return finding.source in DAST_SOURCES and bool(
        finding.metadata.get("runtime_confirmed")
    )


def _package_in_use(graph: Graph, finding: Finding, dependency_usage: dict[str, Any] | None) -> bool:
    """True when the affected package is imported and reachable from an entry point.

    An unused vulnerable dependency is informational; a used one is reachable
    through the import graph the analyzers already built. When the SCA
    reachability index (``sca.build_dependency_reachability``) is available it
    decides; otherwise a graph lookup for an imported external package node is
    the fallback evidence.
    """
    package = str(finding.metadata.get("package") or "")
    if not package:
        return True
    if dependency_usage:
        from .sca import check_package_reachable

        if check_package_reachable(dependency_usage, package):
            return True
        from .sca import _canonical_pkg_name

        canon = _canonical_pkg_name(package)
        summary = dependency_usage.get(canon)
        if summary is not None and getattr(summary, "imported", False):
            return True
        return False
    for node in graph.nodes.values():
        if node.kind == "external" and package.lower() in node.name.lower():
            return True
    return False


def _evidence_quality(graph: Graph, finding: Finding) -> str:
    if _is_llm_sourced(finding):
        return "llm_only"
    if _is_runtime_confirmed(finding):
        return "externally_verified"
    if finding.category == "secret" and _secret_kind(finding) == "provider_token":
        return "provider_verified"
    validation = finding.metadata.get("validation") or {}
    if validation:
        return "externally_verified"
    if finding.category == "secret":
        return "credential_in_source"
    if finding.trace or finding.metadata.get("flow"):
        return "proven_flow"
    if finding.category in INJECTION_CATEGORIES:
        return "dynamic_construction"
    return "pattern"


def _required_actions(finding: Finding) -> tuple[str, ...]:
    if _is_runtime_confirmed(finding):
        return RUNTIME_ACTIONS
    if finding.category == "secret":
        return SECRET_REMOVAL_ACTIONS
    if _is_dependency_finding(finding):
        return DEPENDENCY_ACTIONS
    if finding.category in INJECTION_CATEGORIES:
        return INJECTION_ACTIONS
    return ()


def _blocking_eligibility(
    graph: Graph,
    finding: Finding,
    exposure: str,
    reachability: str,
    dependency_usage: dict[str, Any] | None = None,
) -> str | None:
    """Return None when the category-specific conditions all hold, else the reason they do not."""
    if _is_runtime_confirmed(finding):
        # A DAST scanner observed the issue against the live endpoint; the
        # remaining gates (severity, confidence, reachability, exposure) still
        # apply.
        return None
    if finding.category == "secret":
        if _secret_kind(finding) != "provider_token":
            return "secret is not a format-verified provider token"
        return None
    if finding.source in {"trivy", "cyclonedx"}:
        return "package-level correlation does not prove the vulnerable code path"
    if _is_dependency_finding(finding):
        validation = finding.metadata.get("validation") or {}
        if not validation.get("known_exploited"):
            return "dependency advisory is not known exploited"
        if not _package_in_use(graph, finding, dependency_usage):
            return "vulnerable dependency is not imported or used"
        return None
    if finding.category in INJECTION_CATEGORIES:
        if not has_complete_path(finding):
            return "source-to-sink path is incomplete"
        if reachability not in BLOCK_REACHABILITY:
            return f"entry point reachability is '{reachability}'"
        if exposure not in ("public", "privileged"):
            return f"exposure is '{exposure}'"
        return None
    return "category is not in the approved high-risk scope"


def evaluate_finding(graph: Graph, finding: Finding, dependency_usage: dict[str, Any] | None = None) -> PolicyResult:
    """Compute the enforcement decision for one finding. Deterministic."""
    exposure = classify_exposure(graph, finding)
    if finding.source in {"trivy", "cyclonedx"}:
        exposure = finding.exposure
        reachability = finding.reachability
    elif finding.category == "secret":
        # A credential in source is exposed to anyone who can read the
        # repository or its built image; no code path is involved, so code
        # reachability does not apply.
        reachability = "externally_reachable"
    else:
        reachability = classify_reachability(graph, finding)
    mitigation = sanitizer_assessment(finding) if finding.category in INJECTION_CATEGORIES else "none"
    evidence_quality = _evidence_quality(graph, finding)
    confidence_score = compute_confidence(
        finding,
        evidence_quality=evidence_quality,
        reachability=reachability,
        exposure=exposure,
        mitigation_status=mitigation,
    )
    required_actions = _required_actions(finding)

    if _is_llm_sourced(finding):
        return PolicyResult(
            enforcement="informational",
            policy_reason="LLM-produced findings are triage aids and never block",
            confidence_score=confidence_score,
            reachability=reachability,
            exposure=exposure,
            mitigation_status=mitigation,
            evidence_quality=evidence_quality,
            required_actions=required_actions,
        )

    reason = _blocking_eligibility(graph, finding, exposure, reachability, dependency_usage)
    if reason is None:
        if finding.severity not in BLOCKING_SEVERITIES:
            reason = f"severity is '{finding.severity}'"
        elif confidence_score < BLOCK_CONFIDENCE_THRESHOLD:
            reason = f"decision confidence {confidence_score} is below {BLOCK_CONFIDENCE_THRESHOLD}"
        elif evidence_quality not in BLOCK_EVIDENCE_QUALITIES:
            reason = f"evidence quality '{evidence_quality}' is not verified"
        elif reachability not in BLOCK_REACHABILITY and exposure not in ("sensitive_data", "internal_high_impact"):
            reason = f"reachability '{reachability}' is not exposed or privileged"
        elif mitigation not in NO_CONTROL_STATUSES:
            reason = f"mitigation status '{mitigation}' indicates a compensating control"
        elif exposure not in BLOCK_ELIGIBLE_EXPOSURES:
            reason = f"exposure '{exposure}' is not blocking-eligible"
        elif (
            finding.category not in HIGH_RISK_CATEGORIES
            and not _is_dependency_finding(finding)
            and not _is_runtime_confirmed(finding)
        ):
            reason = "category is not in the approved high-risk scope"

    if reason is None:
        if finding.category == "secret":
            policy_reason = "Verified provider-specific secret exposed in source"
        elif _is_runtime_confirmed(finding):
            policy_reason = "Runtime-confirmed finding observed at a reachable endpoint"
        elif _is_dependency_finding(finding):
            policy_reason = "Known-exploited vulnerability in a used, reachable dependency"
        else:
            policy_reason = f"Verified reachable {finding.category} finding from an exposed entry point"
        return PolicyResult(
            enforcement="block",
            policy_reason=policy_reason,
            confidence_score=confidence_score,
            reachability=reachability,
            exposure=exposure,
            mitigation_status=mitigation,
            evidence_quality=evidence_quality,
            required_actions=required_actions,
        )

    if finding.severity in BLOCKING_SEVERITIES:
        return PolicyResult(
            enforcement="review",
            policy_reason=f"Blocking withheld: {reason}",
            confidence_score=confidence_score,
            reachability=reachability,
            exposure=exposure,
            mitigation_status=mitigation,
            evidence_quality=evidence_quality,
            required_actions=required_actions,
        )
    return PolicyResult(
        enforcement="informational",
        policy_reason=f"Below review threshold: {reason}",
        confidence_score=confidence_score,
        reachability=reachability,
        exposure=exposure,
        mitigation_status=mitigation,
        evidence_quality=evidence_quality,
        required_actions=required_actions,
    )


def apply_policy(
    graph: Graph,
    mode: str = "shadow",
    active_suppressions: dict[str, dict[str, Any]] | None = None,
    expired_suppressions: dict[str, dict[str, Any]] | None = None,
    dependency_usage: dict[str, Any] | None = None,
) -> PolicySummary:
    """Evaluate every finding, annotate it, and record the summary in ``graph.meta``.

    ``active_suppressions`` maps finding fingerprints to governed-suppression
    entries (see ``baseline.load_suppressions``): matching entries set
    ``enforcement='suppressed'`` and the finding remains visible in reports.
    ``expired_suppressions`` lists entries whose expiry has passed; the
    underlying decision stands and the fingerprint is recorded as reactivated.
    ``dependency_usage`` is the SCA reachability index from ``run_analysis``.
    """
    if mode not in POLICY_MODES:
        raise ValueError(f"unknown policy mode: {mode!r}")
    summary = PolicySummary(mode=mode)
    summary.decisions = {decision: 0 for decision in DECISIONS}
    active_index = active_suppressions or {}
    expired_index = expired_suppressions or {}
    for finding in graph.sorted_findings():
        result = evaluate_finding(graph, finding, dependency_usage)
        enforcement = result.enforcement
        policy_reason = result.policy_reason
        if finding.id in active_index:
            enforcement = "suppressed"
            policy_reason = _suppression_reason(active_index[finding.id])
            summary.suppressed.append(finding.id)
        elif finding.id in expired_index:
            summary.reactivated.append(finding.id)
        finding.enforcement = enforcement
        finding.policy_reason = policy_reason
        finding.confidence_score = result.confidence_score
        finding.reachability = result.reachability
        finding.exposure = result.exposure
        finding.mitigation_status = result.mitigation_status
        finding.evidence_quality = result.evidence_quality
        finding.required_actions = list(result.required_actions)
        risk = finding.metadata.get("risk") or {}
        finding.risk_score = float(risk.get("score", 0.0))
        if enforcement != "suppressed":
            summary.decisions[enforcement] = summary.decisions.get(enforcement, 0) + 1
            if enforcement == "block":
                summary.blocks.append(finding.id)
                if _is_llm_sourced(finding):
                    summary.llm_blocks += 1
            elif enforcement == "review":
                summary.reviews.append(finding.id)
    graph.meta["policy"] = summary.to_dict()
    return summary


def _suppression_reason(suppression: dict[str, Any]) -> str:
    parts = []
    reason = str(suppression.get("reason") or "")
    if reason:
        parts.append(reason)
    ticket = str(suppression.get("ticket") or "")
    if ticket:
        parts.append(f"ticket {ticket}")
    owner = str(suppression.get("owner") or "")
    approver = str(suppression.get("approver") or "")
    if owner or approver:
        parts.append(f"approved by {owner or approver}")
    expires = str(suppression.get("expires") or "")
    if expires:
        parts.append(f"expires {expires}")
    return "Governed suppression: " + "; ".join(parts) if parts else "Governed suppression"
