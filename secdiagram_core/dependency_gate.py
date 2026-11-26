"""Opt-in enforcement from a policy-owner review of an exact source call site."""

from pathlib import Path
from typing import Any

from .dependency_inventory import read_json
from .model import Graph, Loc

IDENTITY = ("target", "package", "version", "advisory")
SITE = ("library", "symbol", "path", "line", "source_sha256")


def reviewed_dependency_violations(graph: Graph, review_path: Path | dict[str, Any]) -> list[dict[str, Any]]:
    document = read_json(review_path) if isinstance(review_path, Path) else review_path
    records = document.get("reviews")
    if document.get("version") != 1 or not isinstance(records, list) or len(records) > 10000:
        raise ValueError("invalid dependency review document")
    reviews = set()
    for record in records:
        if not isinstance(record, dict) or any(
            not isinstance(record.get(key), str) or not record[key]
            for key in (*IDENTITY, *(key for key in SITE if key != "line"))
        ) or type(record.get("line")) is not int or record["line"] < 1:
            raise ValueError("invalid dependency review record")
        reviews.add(tuple(record[key] for key in (*IDENTITY, *SITE)))

    violations = []
    for finding in graph.findings:
        metadata = finding.metadata
        package = graph.nodes.get(finding.node_id or "")
        if (
            finding.source != "trivy" or package is None or finding.baseline
            or package.attrs.get("scope") == "dev" or metadata.get("fixed_in_inventory")
            or finding.severity not in {"high", "critical"}
            or not any(
                advisory.get("source") == "cisa-kev" and advisory.get("known_exploited")
                and advisory.get("cve") == finding.external_id
                for advisory in metadata.get("advisories", [])
            )
            or (metadata.get("risk") or {}).get("score", 0) < 6
        ):
            continue
        key = (metadata["target"], metadata["package"], metadata["version"], finding.external_id)
        for site in metadata.get("direct_symbol_candidates", []):
            if (*key, *(site[field] for field in SITE)) not in reviews:
                continue
            entry = graph.nodes.get(site["entry"])
            if entry is None or entry.kind != "endpoint" or entry.evidence is None:
                continue
            violations.append({
                "finding_id": finding.id,
                "advisory": finding.external_id,
                "package": package.name,
                "version": metadata["version"],
                "symbol": site["symbol"],
                "library": site["library"],
                "path": [entry.id, package.id],
                "evidence": [entry.evidence.to_dict(), Loc(site["path"], site["line"]).to_dict()],
            })
            break
    return sorted(violations, key=lambda item: item["finding_id"])
