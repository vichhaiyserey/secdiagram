"""Confidence scoring for policy decisions.

The detector's raw ``finding.confidence`` measures how likely the pattern is
real; the policy needs a *decision* confidence that also accounts for evidence
quality, reachability, exposure, and mitigation. This module composes those
inputs deterministically.

Only findings with ``confidence_score >= BLOCK_CONFIDENCE_THRESHOLD`` (0.90)
are eligible to block, and only when every other policy condition holds.
LLM-produced findings can never reach the threshold here: their evidence
quality is capped and policy.py additionally refuses to block them.
"""

from __future__ import annotations

from .model import Finding

BLOCK_CONFIDENCE_THRESHOLD = 0.90

# Evidence-quality factors applied to the detector's base confidence.
EVIDENCE_FACTORS: dict[str, float] = {
    "provider_verified": 1.0,
    "externally_verified": 1.0,
    "proven_flow": 1.0,
    "unsafe_configuration": 0.92,
    "credential_in_source": 0.95,
    "dynamic_construction": 0.75,
    "pattern": 0.85,
    "llm_only": 0.5,
    "none": 0.8,
}

REACHABILITY_FACTORS: dict[str, float] = {
    "externally_reachable": 1.05,
    "authenticated_reachable": 1.0,
    "local_reachable": 0.95,
    "reachable": 1.0,
    "internal_reachable": 0.9,
    "unreachable": 0.7,
    "unknown": 0.85,
}

EXPOSURE_FACTORS: dict[str, float] = {
    "public": 1.03,
    "privileged": 1.0,
    "sensitive_data": 1.0,
    "internal_high_impact": 0.95,
    "isolated": 0.8,
    "unknown": 0.9,
}

# Findings whose analysis found an active mitigating control.
MITIGATION_FACTORS: dict[str, float] = {
    "none": 1.0,
    "compensating_control": 0.7,
    "sanitized": 0.7,
    "unknown": 0.95,
}

# A complete source-to-sink trace is itself evidence.
TRACE_BONUS = 0.03
TRACE_MISSING_PENALTY = 0.92

# Advisory or multi-tool corroboration recorded by the analyzer.
CORROBORATION_BONUS = 0.03


def compute_confidence(
    finding: Finding,
    *,
    evidence_quality: str,
    reachability: str,
    exposure: str,
    mitigation_status: str,
) -> float:
    """Compose the decision confidence for a finding, deterministically."""
    base = max(0.0, min(1.0, float(finding.confidence)))
    score = base
    score *= EVIDENCE_FACTORS.get(evidence_quality, 0.85)
    score *= REACHABILITY_FACTORS.get(reachability, 0.85)
    score *= EXPOSURE_FACTORS.get(exposure, 0.9)
    score *= MITIGATION_FACTORS.get(mitigation_status, 0.95)
    if finding.trace:
        score *= 1.0 + TRACE_BONUS
    elif finding.category not in {"secret"} and evidence_quality not in {
        "provider_verified",
        "externally_verified",
        "unsafe_configuration",
        "credential_in_source",
    }:
        # Flow findings without a recorded path lose confidence.
        score *= TRACE_MISSING_PENALTY
    validation = finding.metadata.get("validation") or {}
    if validation.get("sources") or finding.metadata.get("advisories"):
        score *= 1.0 + CORROBORATION_BONUS
    return round(max(0.0, min(1.0, score)), 2)
