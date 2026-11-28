"""Canonical finding assessment shared by risk, exploitability, JSON and REST.

The risk and exploitability models answer different questions, but they must
agree on the evidence they expose: the same finding cannot be ``internal`` in
one report and ``isolated`` in another. This module is the single source of
truth for the canonical exposure/reachability values and for the additive
``assessment``, ``rule``, ``provenance`` and ``remediation`` objects.

The objects are deliberately additive. Existing fields keep their meaning and
``schema_version`` stays ``1``; consumers can detect the richer contract through
``schema_features``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .dependency_remediation import dependency_details
from .exposure import EXPOSURE_STATES, classify_exposure
from .model import Finding, Graph
from .reachability import REACHABILITY_STATES, classify_reachability

if TYPE_CHECKING:
    from .taint_flows import TaintFlow

ASSESSMENT_MODEL = "canonical-assessment/v1"
DEPENDENCY_SOURCES = frozenset({"trivy", "cyclonedx"})
DEPENDENCY_CATEGORIES = frozenset({"dependency", "supply-chain", "supply_chain"})
PUBLIC_CLIENT_KINDS = frozenset({"public_client_identifier"})

_LEGACY_EXPOSURE = {
    "public": "public",
    "privileged": "privileged",
    "sensitive_data": "sensitive_data",
    "internal_high_impact": "internal_high_impact",
    "isolated": "isolated",
    "unknown": "unknown",
    "authenticated": "privileged",
    "local": "isolated",
    "internal": "isolated",
}

_LEGACY_REACHABILITY = {
    "externally_reachable": "externally_reachable",
    "authenticated_reachable": "authenticated_reachable",
    "local_reachable": "local_reachable",
    "internal_reachable": "internal_reachable",
    "unreachable": "unreachable",
    "unknown": "unknown",
    "unmapped": "unknown",
    "potentially_reachable": "internal_reachable",
}

_OWASP = {
    "command": ("A05:2025", "A03:2021"),
    "code": ("A05:2025", "A03:2021"),
    "deserialization": ("A08:2025", "A08:2021"),
    "sql": ("A05:2025", "A03:2021"),
    "path": ("A01:2025", "A01:2021"),
    "network": ("A01:2025", "A10:2021"),
    "crypto": ("A04:2025", "A02:2021"),
    "template": ("A05:2025", "A03:2021"),
    "xss": ("A05:2025", "A03:2021"),
    "xxe": ("A05:2025", "A05:2021"),
    "redirect": ("A01:2025", "A01:2021"),
    "auth": ("A07:2025", "A07:2021"),
    "misconfig": ("A02:2025", "A05:2021"),
    "secret": ("A02:2025", "A07:2021"),
    "container": ("A02:2025", "A05:2021"),
    "cloud": ("A02:2025", "A05:2021"),
    "ci": ("A03:2025", "A08:2021"),
    "supply_chain": ("A03:2025", "A06:2021"),
    "supply-chain": ("A03:2025", "A06:2021"),
    "dependency": ("A03:2025", "A06:2021"),
}

_INFORMATION_URI = "https://github.com/vichhaiyserey/secdiagram"


def is_public_client_identifier(finding: Finding) -> bool:
    """True for public client config keys (Firebase API keys and similar)."""
    return str(finding.metadata.get("secret_kind") or "") in PUBLIC_CLIENT_KINDS or bool(
        finding.metadata.get("public_client")
    )


def is_dependency_finding(finding: Finding) -> bool:
    return finding.source in DEPENDENCY_SOURCES or finding.category in DEPENDENCY_CATEGORIES


def canonical_exposure(
    graph: Graph, finding: Finding, flow: TaintFlow | None = None
) -> str:
    """Return the canonical exposure class for a finding."""
    if is_public_client_identifier(finding):
        # A public client identifier is not credential material.
        return "unknown"
    if is_dependency_finding(finding):
        raw = str(finding.exposure or "unknown")
        if raw in EXPOSURE_STATES:
            return raw
        return _LEGACY_EXPOSURE.get(raw, "unknown")
    return classify_exposure(graph, finding)


def canonical_reachability(
    graph: Graph, finding: Finding, flow: TaintFlow | None = None
) -> str:
    """Return the canonical reachability state for a finding."""
    if is_public_client_identifier(finding):
        return "unknown"
    if is_dependency_finding(finding):
        raw = str(finding.reachability or "unmapped")
        if raw in REACHABILITY_STATES:
            return raw
        if raw == "reachable":
            exposure = canonical_exposure(graph, finding, flow)
            if exposure == "public":
                return "externally_reachable"
            if exposure == "privileged":
                return "authenticated_reachable"
            return "internal_reachable"
        if finding.metadata.get("fixed_in_inventory"):
            return "unreachable"
        return _LEGACY_REACHABILITY.get(raw, "unknown")
    return classify_reachability(graph, finding)


def rule_id(finding: Finding) -> str:
    """Stable rule identifier for the finding's detector."""
    explicit = finding.metadata.get("rule_id")
    if explicit:
        return str(explicit)
    return f"{finding.category}:{finding.cwe or 'unknown'}"


def rule_descriptor(finding: Finding) -> dict[str, Any]:
    cwe = finding.cwe
    help_uri = _INFORMATION_URI
    if cwe and "-" in cwe:
        help_uri = f"https://cwe.mitre.org/data/definitions/{cwe.split('-', 1)[1]}.html"
    return {
        "id": rule_id(finding),
        "name": f"secdiagram/{finding.source}/{finding.category}",
        "category": finding.category,
        "cwe": cwe,
        "owasp": list(_OWASP.get(finding.category, ())),
        "help_uri": help_uri,
        "source": finding.source,
    }


def provenance_descriptor(finding: Finding) -> dict[str, Any]:
    validation = finding.metadata.get("validation") or {}
    imported = finding.source != "secdiagram"
    if is_public_client_identifier(finding):
        trust = "public-client-identifier"
    elif validation or finding.metadata.get("runtime_confirmed"):
        trust = "verified"
    elif imported:
        trust = "external-unverified"
    else:
        trust = "heuristic"
    return {
        "source": finding.source,
        "external_id": finding.external_id,
        "report": finding.metadata.get("report"),
        "imported": imported,
        "validated": bool(validation),
        "evidence_quality": finding.evidence_quality,
        "trust": trust,
    }


def _upgrade_commands(finding: Finding) -> list[str]:
    details = dependency_details(finding)
    package = str(details.get("package") or "")
    fixed = str(details.get("fixed_version") or "")
    if not package or not fixed:
        return []
    target = str(details.get("target") or "").lower()
    target_type = str(finding.metadata.get("target_type") or "").lower()
    if target_type in {"pub", "dart", "dart-pub"} or "pubspec" in target:
        return [f"flutter pub upgrade {package}:^{fixed}"]
    if target_type in {"npm", "node-pkg", "yarn"} or "package-lock" in target or "yarn.lock" in target:
        return [f"npm install {package}@{fixed}"]
    if target_type in {"pip", "python-pkg", "poetry"} or "requirements" in target:
        return [f"pip install {package}=={fixed}"]
    if target_type in {"gomod", "go"} or "go.mod" in target:
        return [f"go get {package}@{fixed}"]
    if target_type in {"maven", "jar"} or "pom.xml" in target:
        return [
            "mvn versions:use-dep-version "
            f"-Dincludes={package} -DdepVersion={fixed} -DforceVersion=true"
        ]
    return []


def remediation_descriptor(finding: Finding) -> dict[str, Any]:
    return {
        "summary": finding.recommendation,
        "actions": list(finding.required_actions),
        "commands": _upgrade_commands(finding),
    }


def build_assessment(finding: Finding) -> dict[str, Any]:
    risk = finding.metadata.get("risk") or {}
    exploit = finding.metadata.get("exploitability") or {}
    priority = str(risk.get("priority") or "P3")
    level = str(exploit.get("level") or finding.exploitability or "informational")
    reachability = str(
        exploit.get("reachability") or risk.get("reachability") or finding.reachability or "unknown"
    )
    exposure = str(
        exploit.get("exposure") or risk.get("exposure") or finding.exposure or "unknown"
    )
    blocking = finding.enforcement == "block"
    suppressed = finding.baseline or finding.enforcement == "suppressed"
    return {
        "model": ASSESSMENT_MODEL,
        "priority": priority,
        "score": float(risk.get("score", 0.0)),
        "level": level,
        "impact_class": str(exploit.get("impact_class") or "other"),
        "reachability": reachability,
        "exposure": exposure,
        "evidence": str(risk.get("evidence") or exploit.get("provenance") or "pattern"),
        "provenance": str(exploit.get("provenance") or "pattern"),
        "context": str(exploit.get("context") or "unknown"),
        "confidence": float(finding.confidence_score or finding.confidence),
        "recommended_action": str(exploit.get("recommended_action") or "investigate"),
        "conditions": list(exploit.get("conditions") or []),
        "blocking": blocking,
        "suppressed": suppressed,
        "trust": str(provenance_descriptor(finding)["trust"]),
    }


def annotate_finding(finding: Finding) -> None:
    """Attach the additive assessment objects to a finding."""
    finding.rule = rule_descriptor(finding)
    finding.provenance = provenance_descriptor(finding)
    finding.remediation = remediation_descriptor(finding)
    finding.assessment = build_assessment(finding)


def refresh_assessment(finding: Finding) -> None:
    """Refresh the assessment after policy or baseline decisions change."""
    annotate_finding(finding)
