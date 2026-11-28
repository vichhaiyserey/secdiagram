"""Normalize dependency evidence from explicitly supplied local JSON reports."""

import re
from pathlib import Path
from typing import Any

from .dependency_inventory import read_json
from .model import SEVERITY_RANK, Finding, Graph, Node, stable_id


def _records(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _string(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return value.encode("utf-8", errors="replace").decode("utf-8")[:1024]


def _stable_version(value: str) -> tuple[int, ...] | None:
    """Compare only unambiguous stable Pub versions from a single advisory."""
    if re.fullmatch(r"(?:0|[1-9][0-9]{0,8})(?:\.(?:0|[1-9][0-9]{0,8})){2}", value):
        return tuple(map(int, value.split(".")))
    return None


def _advisory_id(value: Any) -> str:
    identifier = _string(value).strip()
    if re.fullmatch(r"(?:CVE-[0-9]{4}-[0-9]+|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})", identifier, re.I):
        return identifier.upper() if identifier[:3].lower() == "cve" else "GHSA-" + identifier[5:].lower()
    return identifier


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    groups: dict[str, list[Finding]] = {}
    for finding in findings:
        groups.setdefault(finding.id, []).append(finding)
    merged = []
    for group in groups.values():
        finding = group[0]
        if len(group) > 1:
            finding.severity = max((item.severity for item in group), key=SEVERITY_RANK.__getitem__)
            finding.metadata["duplicate_records"] = len(group) - 1
            fixes = sorted({str(item.metadata.get("fixed_version") or "") for item in group} - {""})
            if finding.source == "trivy":
                finding.metadata["fixed_versions"] = fixes
                finding.metadata["fixed_version"] = fixes[0] if len(fixes) == 1 else ""
                agreed = len(fixes) == 1 and all(item.metadata.get("fixed_in_inventory") for item in group)
                if not agreed and any(item.metadata.get("fixed_in_inventory") for item in group):
                    finding.node_id = None
                    finding.evidence = []
                finding.metadata["fixed_in_inventory"] = agreed
                finding.recommendation = _recommendation(finding.metadata["fixed_version"], agreed)
                if len(fixes) > 1:
                    finding.recommendation = "Review conflicting scanner fixes against the local advisory."
        merged.append(finding)
    return merged


def _recommendation(fixed: str, resolved: bool) -> str:
    if resolved:
        return "Rescan the resolved lockfile to refresh stale scanner evidence."
    if fixed:
        return "Review the reported fix and verify the updated lockfile."
    return "Check the local advisory for a supported fix and review application usage."


def import_reports(
    graph: Graph, trivy: Path | None, sbom: Path | None,
    verified: dict[str, dict[str, Any]] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    summaries = []
    pub_nodes = {
        (node.path, node.name, node.attrs.get("version")): node
        for node in graph.nodes.values()
        if node.kind == "dependency" and node.attrs.get("ecosystem") == "pub"
    }
    resolved_pub = {(path, name): node for (path, name, version), node in pub_nodes.items() if version}
    for source, path in (("trivy", trivy), ("cyclonedx", sbom)):
        supplied = (verified or {}).get(source)
        if supplied is None and path is None:
            continue
        filename = path.name if path is not None else f"bundle/{source}"
        summary: dict[str, Any] = {"source": source, "file": filename, "invalid_records": 0}
        summaries.append(summary)
        try:
            if supplied is not None:
                report = supplied
            else:
                assert path is not None
                report = read_json(path)
        except (OSError, ValueError, RuntimeError):
            summary["invalid_records"] = 1
            continue
        if report.get("bomFormat") == "CycloneDX":
            components = []
            for record in _records(report.get("components")):
                if not isinstance(record, dict) or not _string(record.get("name")):
                    summary["invalid_records"] += 1
                    continue
                components.append({
                    key: _string(record.get(key))
                    for key in ("name", "version", "purl", "type", "bom-ref")
                })
            summary["components"] = sorted(
                components, key=lambda item: (item["purl"], item["name"], item["version"], item["bom-ref"]),
            )
            refs: dict[str, str] = {}
            ambiguous_refs: set[str] = set()
            for component in summary["components"]:
                ref = component["bom-ref"]
                node_id = stable_id("sbom", source, filename, ref, component["purl"], component["name"], component["version"])
                graph.add_node(Node(node_id, "dependency", component["name"],
                                    component["purl"] or component["name"], attrs=component))
                if ref:
                    if ref in refs and refs[ref] != node_id:
                        ambiguous_refs.add(ref)
                    refs[ref] = node_id
            for ref in sorted(ambiguous_refs):
                del refs[ref]
                summary["invalid_records"] += 1
            for relation in _records(report.get("dependencies")):
                if not isinstance(relation, dict) or _string(relation.get("ref")) not in refs:
                    summary["invalid_records"] += 1
                    continue
                for child in sorted({_string(item) for item in _records(relation.get("dependsOn"))}):
                    if child in refs:
                        graph.add_edge(refs[_string(relation["ref"])], refs[child], "depends_on")
            for record in _records(report.get("vulnerabilities")):
                if not isinstance(record, dict) or not _string(record.get("id")):
                    summary["invalid_records"] += 1
                    continue
                advisory = _advisory_id(record["id"])
                ratings = [rating for rating in _records(record.get("ratings")) if isinstance(rating, dict)]
                order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
                severity = max(
                    (_string(rating.get("severity")).lower() for rating in ratings),
                    key=lambda value: order.get(value, 0), default="info",
                )
                for affected in _records(record.get("affects")):
                    ref = _string(affected.get("ref")) if isinstance(affected, dict) else ""
                    affected_node_id = refs.get(ref)
                    if affected_node_id is None:
                        summary["invalid_records"] += 1
                        continue
                    component_node = graph.nodes[affected_node_id]
                    findings.append(Finding(
                        stable_id("cyclonedx", advisory, affected_node_id), "dependency",
                        severity if severity in order else "info",
                        f"{advisory} in {component_node.name}", "Imported SBOM advisory for the referenced component.",
                        node_id=affected_node_id, source="cyclonedx", external_id=advisory,
                        recommendation="Verify the affected component against the local advisory and confirm the fix before upgrading.",
                        reachability="unmapped", exposure="isolated",
                        metadata={"package": component_node.name, "version": component_node.attrs["version"],
                                  "report": filename, "component_ref": ref},
                    ))
            continue
        if source != "trivy" or not isinstance(report.get("Results"), list):
            summary["invalid_records"] += 1
            continue
        for target in report["Results"]:
            if not isinstance(target, dict):
                summary["invalid_records"] += 1
                continue
            for record in _records(target.get("Vulnerabilities")):
                if not isinstance(record, dict):
                    summary["invalid_records"] += 1
                    continue
                advisory = _advisory_id(record.get("VulnerabilityID"))
                name = _string(record.get("PkgName"))
                version = _string(record.get("InstalledVersion"))
                if not advisory or not name:
                    summary["invalid_records"] += 1
                    continue
                severity = _string(record.get("Severity")).lower()
                fixed = _string(record.get("FixedVersion"))
                target_name = _string(target.get("Target"))
                target_class = _string(target.get("Class"))
                target_type = _string(target.get("Type")).lower()
                pub_target = target_class.lower() in {"", "lang-pkgs"} and target_type in {"", "pub", "dart", "dart-pub"}
                node = pub_nodes.get((target_name, name, version)) if version and pub_target else None
                resolved = resolved_pub.get((target_name, name)) if pub_target else None
                observed_version = _stable_version(version)
                fixed_version = _stable_version(fixed)
                resolved_version = _stable_version(resolved.attrs["version"]) if resolved else None
                fixed_in_inventory = bool(
                    node is None and observed_version and fixed_version and resolved_version
                    and observed_version < fixed_version == resolved_version
                )
                if fixed_in_inventory:
                    node = resolved
                findings.append(Finding(
                    stable_id("trivy", advisory, name, version, target_name, target_class.lower(), target_type),
                    "dependency", severity if severity in {"critical", "high", "medium", "low"} else "info",
                    f"{advisory} in {name}", "Imported dependency advisory without proven reachability.",
                    source="trivy", external_id=advisory, node_id=node.id if node else None,
                    evidence=[node.evidence] if node and node.evidence else [],
                    recommendation=_recommendation(fixed, fixed_in_inventory),
                    reachability="unmapped", exposure="isolated",
                    metadata={"package": name, "cves": [advisory], "version": version, "fixed_version": fixed,
                              "target": target_name, "target_type": target_type, "report": filename,
                              "fixed_in_inventory": fixed_in_inventory,
                              "resolved_version": resolved.attrs["version"] if resolved else ""},
                ))
    if summaries:
        graph.meta["dependency_reports"] = summaries
    return dedupe_findings(findings)
