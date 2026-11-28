"""Shared dependency remediation fields for report formats."""

from typing import Any

from .model import Finding


def dependency_details(finding: Finding) -> dict[str, Any]:
    if finding.source not in {"trivy", "cyclonedx"}:
        return {}
    metadata = finding.metadata
    return {
        "advisory": finding.external_id,
        "package": metadata.get("package"),
        "reported_version": metadata.get("version"),
        "resolved_version": metadata.get("resolved_version"),
        "fixed_version": metadata.get("fixed_version"),
        "fixed_versions": metadata.get("fixed_versions", []),
        "duplicate_records": metadata.get("duplicate_records", 0),
        "target": metadata.get("target") or metadata.get("component_ref"),
        "report": metadata.get("report"),
        "reachability": finding.reachability,
        "disposition": "resolved" if metadata.get("fixed_in_inventory") else "in_triage",
        "dependency_path": metadata.get("dependency_path", []),
        "locations": [location.ref for location in finding.evidence],
        "recommendation": finding.recommendation,
    }
