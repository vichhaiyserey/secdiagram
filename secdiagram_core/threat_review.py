"""Source-backed threat records and offline, versioned snapshot comparisons.

This module never reads source snippets: evidence is location/rule metadata, so
credentials detected by a rule are not copied into another report.
"""

from __future__ import annotations

import json
import math
import re
from collections import defaultdict
from pathlib import Path
from typing import TYPE_CHECKING, Any

from . import __version__
from .model import Finding, Graph, Loc, Node, stable_id
from .risk import endpoint_exposure
from .taint_flows import build_taint_flows

if TYPE_CHECKING:
    from .threat_model import Threat

SNAPSHOT_KIND = "secdiagram-threat-model"
MAX_SNAPSHOT_BYTES = 32 * 1024 * 1024


def _locations(locations: list[Loc]) -> list[dict[str, Any]]:
    return [
        {"path": path, "line": line, "col": col}
        for path, line, col in sorted(
            {
                (loc.path.replace("\\", "/"), loc.line, loc.col)
                for loc in locations
                if loc.path and loc.line > 0
            }
        )
    ]


def _asset(node: Node) -> dict[str, Any]:
    return {
        "id": node.id,
        "kind": node.kind,
        "name": node.qualname,
        "path": (node.path or "").replace("\\", "/"),
    }


def _route(node: Node) -> str:
    routes = sorted(
        {
            f"{str(route.get('method') or 'HTTP').upper()} {route['path']}"
            for route in node.attrs.get("routes", [])
            if isinstance(route, dict) and route.get("path")
        }
    )
    return ", ".join(routes) or node.qualname


def _verification(finding: Finding, refs: str) -> list[str]:
    steps = [
        f"Inspect the cited {finding.category} rule and source locations ({refs}) and confirm its preconditions."
    ]
    if finding.category == "secret":
        steps.extend(
            [
                "Determine whether the detected value is a real credential or a placeholder using approved credential inventory; do not expose it in logs or reports.",
                "If valid, revoke/rotate it and verify access with the old credential is denied; add a scanner regression using dummy values.",
            ]
        )
    elif finding.category in {
        "ci",
        "supply-chain",
        "supply_chain",
        "dependency",
        "container",
        "cloud",
    }:
        steps.extend(
            [
                "Compare the cited dependency, workflow or infrastructure setting with the effective deployed version and permissions.",
                "Verify the applicable patched version, immutable reference or least-privilege setting and add a configuration regression check.",
            ]
        )
    elif finding.category in {
        "tls",
        "crypto",
        "jwt",
        "cookie",
        "cors",
        "csrf",
        "randomness",
        "misconfig",
        "auth",
    }:
        steps.extend(
            [
                "Confirm the effective runtime security configuration and any inherited or gateway controls for the cited asset.",
                "In an authorized environment, test the reported insecure configuration against its secure alternative and add a regression asserting the expected rejection or protection.",
            ]
        )
    else:
        steps.extend(
            [
                "Trace caller-controlled values and existing validation, authorization and sanitization to the affected operation.",
                "In an authorized test environment, add a regression case for the reported condition and verify the expected rejection or safe behavior.",
            ]
        )
    return steps


def attach_threat_records(graph: Graph, threats: list[Threat]) -> None:
    """Attach individual observations; never infer authorization failure from missing markers."""
    findings = {finding.id: finding for finding in graph.sorted_findings() if not finding.baseline}
    flows = {flow.finding.id: flow for flow in build_taint_flows(graph, deduplicate=False)}
    for threat in threats:
        threat.records = []
        occurrences: dict[str, int] = defaultdict(int)
        auth_review = threat.id == stable_id("threat", "internet", "S", "unauthenticated-entry")
        for finding_id in sorted(
            [] if auth_review else threat.finding_ids,
            key=lambda fid: (
                tuple((loc.path, loc.line, loc.col) for loc in findings[fid].evidence),
                fid,
            ),
        ):
            finding = findings[finding_id]
            flow = flows.get(finding_id)
            locations = _locations(
                finding.evidence + finding.trace + ([h.loc for h in flow.hops] if flow else [])
            )
            if not locations:
                # An imported claim without a location cannot become a source-backed threat.
                continue
            node = graph.nodes.get(finding.node_id or "")
            components = {nid for nid in (flow.node_path if flow else []) if nid in graph.nodes}
            if node:
                components.add(node.id)
            assets = [_asset(graph.nodes[nid]) for nid in sorted(components)]
            if not assets:
                assets = [
                    {
                        "id": stable_id("asset", loc["path"]),
                        "kind": "file",
                        "name": loc["path"],
                        "path": loc["path"],
                    }
                    for loc in locations
                ]
                assets = list({a["id"]: a for a in assets}.values())
            anchor = stable_id(
                threat.id,
                finding.source,
                finding.category,
                str(finding.metadata.get("rule_id") or finding.external_id or finding.title),
                locations[0]["path"],
                node.qualname if node else "",
            )
            occurrences[anchor] += 1
            risk = finding.metadata.get("risk") or {}
            evidence_refs = ", ".join(f"{loc['path']}:{loc['line']}" for loc in locations)
            facts = [f"Static rule {finding.category} reported {finding.title} at {evidence_refs}."]
            data_flows = [flow.to_dict()] if flow else []
            for data_flow in data_flows:
                for hop in data_flow["hops"]:
                    if hop["node"] not in graph.nodes:
                        hop["node"] = None
                    hop["loc"] = hop["loc"].replace("\\", "/")
            limitations = ["Runtime exploitability and deployment exposure have not been verified."]
            if flow:
                facts.append(
                    "The analyzer recorded a source-to-sink trace; hop roles and locations are attached."
                )
                limitations.append(
                    "Static traces do not prove a feasible runtime path or bypass of mitigations."
                )
            else:
                limitations.append("No source-to-sink data flow was resolved for this observation.")
            if not node:
                limitations.append(
                    "Component ownership is unresolved; affected source files are listed as assets."
                )
            threat.records.append(
                {
                    "id": stable_id("threat-record", anchor, str(occurrences[anchor])),
                    "catalog_id": threat.id,
                    "boundary": threat.boundary,
                    "stride": threat.stride,
                    "title": finding.title,
                    "status": "observed",
                    "finding_ids": [finding.id],
                    "severity": finding.severity,
                    "confidence": round(max(0.0, min(1.0, finding.confidence)), 2),
                    "exploitability": finding.exploitability
                    or ("static-flow" if flow else "unverified"),
                    "exploitability_score": round(float(finding.exploitability_score), 2),
                    "priority": risk.get("priority"),
                    "risk_score": risk.get("score", 0.0),
                    "components": sorted(components),
                    "affected_assets": assets,
                    "data_flows": data_flows,
                    "evidence": locations,
                    "facts": facts,
                    "assessment": f"Potential {threat.title.lower()}; confirm the rule's preconditions and actual impact.",
                    "assumptions": limitations,
                    "recommendation": finding.recommendation or threat.mitigation,
                    "verification": _verification(finding, evidence_refs),
                }
            )
        if not auth_review:
            threat.records.sort(key=lambda record: record["id"])
            continue
        # One review record per route-owning endpoint, including routes with no SAST finding.
        for node in graph.sorted_nodes():
            exposure = endpoint_exposure(node)
            if (
                node.kind != "endpoint"
                or exposure not in {"public", "unknown"}
                or not node.evidence
                or node.evidence.line < 1
            ):
                continue
            route = _route(node)
            evidence = _locations([node.evidence])
            ref = f"{evidence[0]['path']}:{evidence[0]['line']}"
            fact = (
                f"Route {route} has an explicit anonymous-access marker"
                if exposure == "public"
                else f"Route {route} has no detected authentication marker"
            )
            fact += f"; see {ref}."
            threat.records.append(
                {
                    "id": stable_id(
                        "threat-record",
                        "auth-review",
                        (node.path or "").replace("\\", "/"),
                        node.qualname,
                        route,
                    ),
                    "catalog_id": threat.id,
                    "boundary": "internet",
                    "stride": "S",
                    "title": fact,
                    "status": "review",
                    "finding_ids": [],
                    "severity": "info",
                    "confidence": 0.5,
                    "exploitability": "unverified",
                    "priority": None,
                    "risk_score": 0.0,
                    "components": [node.id],
                    "affected_assets": [_asset(node)],
                    "data_flows": [],
                    "evidence": evidence,
                    "facts": [fact],
                    "assessment": "Authentication requirements need review; this is not a confirmed authorization bypass.",
                    "assumptions": [
                        "Authentication may be enforced by global middleware, a gateway or a custom control that static analysis did not recognize.",
                        "Internet reachability and the sensitivity of the operation are not established by route detection.",
                    ],
                    "recommendation": f"Confirm the intended access policy for {route}; enforce authentication and authorization if access should be restricted.",
                    "verification": [
                        f"Inspect {ref} and inherited/global middleware for {route}.",
                        f"Test {route} with no credentials and insufficient privileges in an authorized environment; compare responses with its documented access policy.",
                    ],
                }
            )
        threat.records.sort(key=lambda record: record["id"])


def threat_analysis_context(graph: Graph) -> dict[str, Any]:
    return {
        key: graph.meta[key]
        for key in (
            "analysis",
            "security_baseline",
            "finding_confidence_floor",
            "config_hash",
            "security_enabled",
            "include",
            "exclude",
            "files_discovered",
            "files_parsed",
            "files_skipped",
            "skipped_samples",
            "languages",
            "unsupported_security_languages",
            "diagnostics",
            "plugin_errors",
            "external_reports",
            "workspace_analysis",
        )
        if key in graph.meta
    }


def build_threat_snapshot(graph: Graph, threats: list[Threat]) -> dict[str, Any]:
    """Keep review evidence separate from coverage and unassessed catalog entries."""
    active = [f for f in graph.sorted_findings() if not f.baseline]
    represented = {fid for t in threats for r in t.records for fid in r["finding_ids"]}
    return {
        "kind": SNAPSHOT_KIND,
        "schema_version": 1,
        "tool": {"name": "secdiagram", "version": __version__},
        "repository": {
            "name": graph.meta.get("name", "repository"),
            "commit": graph.meta.get("commit"),
            "branch": graph.meta.get("branch"),
            "dirty": graph.meta.get("dirty"),
        },
        "analysis": threat_analysis_context(graph),
        "unrepresented_findings": sorted(f.id for f in active if f.id not in represented),
        "coverage": [
            {
                "id": t.id,
                "boundary": t.boundary,
                "stride": t.stride,
                "title": t.title,
                "status": t.status,
                "record_count": len(t.records),
            }
            for t in sorted(threats, key=lambda t: t.id)
        ],
        "threats": sorted(
            [record for threat in threats for record in threat.records], key=lambda r: r["id"]
        ),
        "limitations": [
            "Static observations and review signals are not confirmed exploits.",
            "Missing, suppressed, skipped or unsupported code is not evidence of safety.",
            "Record identity uses rule, source path, owning symbol and occurrence order; moves/renames or repeated identical rules may appear as removals/additions or changed pairings.",
        ],
    }


def render_snapshot(snapshot: dict[str, Any]) -> str:
    return json.dumps(snapshot, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n"


def load_threat_snapshot(path: Path) -> dict[str, Any]:
    """Bound input and reject malformed/duplicate records instead of reporting a false clean diff."""
    with path.open("rb") as handle:
        raw = handle.read(MAX_SNAPSHOT_BYTES + 1)
    if len(raw) > MAX_SNAPSHOT_BYTES:
        raise ValueError(
            f"snapshot exceeds {MAX_SNAPSHOT_BYTES} bytes; use a smaller threat snapshot"
        )

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    def invalid_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON constant: {value}")

    payload = json.loads(raw, object_pairs_hook=unique_object, parse_constant=invalid_constant)
    validate_snapshot(payload)
    return payload


def validate_snapshot(payload: Any) -> None:
    if (
        not isinstance(payload, dict)
        or payload.get("kind") != SNAPSHOT_KIND
        or type(payload.get("schema_version")) is not int
        or payload["schema_version"] != 1
    ):
        raise ValueError("expected a secdiagram threat-model snapshot with schema_version 1")
    for field, expected in (
        ("tool", dict),
        ("repository", dict),
        ("analysis", dict),
        ("coverage", list),
        ("threats", list),
        ("limitations", list),
        ("unrepresented_findings", list),
    ):
        if not isinstance(payload.get(field), expected):
            raise ValueError(f"snapshot {field} has an invalid or missing value")
    if payload["tool"].get("name") != "secdiagram" or not isinstance(
        payload["tool"].get("version"), str
    ):
        raise ValueError("invalid snapshot tool version")
    for field in ("unrepresented_findings", "limitations"):
        if any(not isinstance(value, str) for value in payload[field]):
            raise ValueError(f"invalid snapshot {field}")
    catalog: dict[str, dict[str, Any]] = {}
    for item in payload["coverage"]:
        if not isinstance(item, dict) or any(
            not isinstance(item.get(key), str)
            for key in ("id", "boundary", "stride", "title", "status")
        ):
            raise ValueError("invalid threat coverage entry")
        if not re.fullmatch(r"[0-9a-f]{12}", item["id"]) or item["id"] in catalog:
            raise ValueError("invalid or duplicate threat coverage identity")
        if (
            item["status"] not in {"observed", "review", "no-evidence", "not-assessed"}
            or type(item.get("record_count")) is not int
            or item["record_count"] < 0
        ):
            raise ValueError("invalid threat coverage status or count")
        catalog[item["id"]] = item
    counts: dict[str, int] = defaultdict(int)
    seen: set[str] = set()
    for record in payload["threats"]:
        if not isinstance(record, dict):
            raise ValueError("snapshot threats must be objects")
        for field in (
            "id",
            "catalog_id",
            "boundary",
            "stride",
            "title",
            "status",
            "severity",
            "exploitability",
            "assessment",
            "recommendation",
        ):
            if not isinstance(record.get(field), str) or not record[field].strip():
                raise ValueError(f"threat record requires a nonempty {field}")
        if record["id"] in seen:
            raise ValueError(f"duplicate threat record id: {record['id']}")
        seen.add(record["id"])
        if any(not re.fullmatch(r"[0-9a-f]{12}", record[key]) for key in ("id", "catalog_id")):
            raise ValueError("invalid threat record identity")
        if (
            record["stride"] not in "STRIDE"
            or len(record["stride"]) != 1
            or record["status"] not in {"observed", "review"}
        ):
            raise ValueError("invalid threat classification or status")
        if record["boundary"] not in {"internet", "data", "external", "host", "supply"}:
            raise ValueError("invalid threat boundary")
        parent = catalog.get(record["catalog_id"])
        if not parent or any(parent[field] != record[field] for field in ("stride", "boundary")):
            raise ValueError("threat record has no matching coverage classification")
        counts[record["catalog_id"]] += 1
        if record["severity"] not in {"critical", "high", "medium", "low", "info"} or record[
            "exploitability"
        ] not in {"unverified", "static-flow", "likely", "plausible", "unlikely", "informational"}:
            raise ValueError("invalid severity or exploitability")
        for field in ("confidence", "risk_score"):
            value = record.get(field)
            if (
                not isinstance(value, (int, float))
                or isinstance(value, bool)
                or not 0 <= value <= (1 if field == "confidence" else 10)
                or not math.isfinite(value)
            ):
                raise ValueError(f"invalid threat {field}")
        for field in ("facts", "assumptions", "verification", "components", "finding_ids"):
            if not isinstance(record.get(field), list) or any(
                not isinstance(v, str) or not v.strip() for v in record[field]
            ):
                raise ValueError(f"invalid threat {field}")
        for field in ("evidence", "affected_assets", "data_flows"):
            if not isinstance(record.get(field), list) or any(
                not isinstance(v, dict) for v in record[field]
            ):
                raise ValueError(f"invalid threat {field}")
        if "priority" not in record or record["priority"] not in (None, "P0", "P1", "P2", "P3"):
            raise ValueError("invalid threat priority")
        if (
            not record["facts"]
            or not record["verification"]
            or not record["evidence"]
            or not record["affected_assets"]
        ):
            raise ValueError("threat record is missing actionable evidence or verification")
        for loc in record["evidence"]:
            if (
                not isinstance(loc.get("path"), str)
                or not loc["path"].strip()
                or type(loc.get("line")) is not int
                or loc["line"] < 1
            ):
                raise ValueError("invalid threat evidence location")
        for asset in record["affected_assets"]:
            if any(not isinstance(asset.get(key), str) for key in ("id", "kind", "name", "path")):
                raise ValueError("invalid affected asset")
        for flow in record["data_flows"]:
            if not isinstance(flow.get("hops"), list) or not flow["hops"]:
                raise ValueError("invalid static data flow")
            for hop in flow["hops"]:
                if (
                    not isinstance(hop, dict)
                    or "node" not in hop
                    or not isinstance(hop.get("loc"), str)
                    or not isinstance(hop.get("role"), str)
                    or (hop.get("node") is not None and not isinstance(hop["node"], str))
                ):
                    raise ValueError("invalid static data-flow hop")
    if any(counts[key] != entry["record_count"] for key, entry in catalog.items()):
        raise ValueError("threat coverage counts do not match records")


def diff_threat_snapshots(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """Retain both sides and exact changed fields; removal does not imply remediation."""
    validate_snapshot(before)
    validate_snapshot(after)
    old = {record["id"]: record for record in before["threats"]}
    new = {record["id"]: record for record in after["threats"]}
    changed = []
    for key in sorted(old.keys() & new.keys()):
        fields = sorted(
            field
            for field in old[key].keys() | new[key].keys()
            if old[key].get(field) != new[key].get(field)
        )
        if fields:
            changed.append({"id": key, "fields": fields, "before": old[key], "after": new[key]})
    return {
        "kind": "secdiagram-threat-model-diff",
        "schema_version": 1,
        "before": before["repository"],
        "after": after["repository"],
        "added": [new[key] for key in sorted(new.keys() - old.keys())],
        "removed": [old[key] for key in sorted(old.keys() - new.keys())],
        "changed": changed,
        "unchanged": sum(old[key] == new[key] for key in old.keys() & new.keys()),
        "context_changes": {
            field: {"before": before[field], "after": after[field]}
            for field in ("tool", "analysis", "coverage", "limitations", "unrepresented_findings")
            if before[field] != after[field]
        },
        "note": "Removed records are absent from this snapshot, not proven fixed. Compare analysis coverage, filters and suppressions before concluding remediation.",
    }


def _text(value: Any) -> str:
    text = (
        " ".join(str(value).split())
        .replace("`", "'")
        .replace("|", "/")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .encode("ascii", "replace")
        .decode("ascii")
    )
    return re.sub(r"([\\*_[\]#!])", r"\\\1", text)


def render_threat_records(records: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    for record in sorted(records, key=lambda r: r["id"]):
        lines.extend(
            [
                f"### {_text(record['title'])}",
                "",
                f"Record: `{record['id']}`; STRIDE: {record['stride']}; boundary: {record['boundary']}; status: {record['status']}; severity: {record['severity']}; confidence: {record['confidence']}; exploitability: {record['exploitability']}; priority: {record['priority'] or 'unrated'}; risk: {record['risk_score']}/10.",
                "",
            ]
        )
        for label, value in (
            ("Facts", "; ".join(record["facts"])),
            ("Assessment", record["assessment"]),
            ("Assumptions / limits", "; ".join(record["assumptions"])),
            (
                "Affected assets",
                "; ".join(
                    f"{a['name']} ({a['id']}, {a['path']})" for a in record["affected_assets"]
                ),
            ),
            ("Components", ", ".join(record["components"]) or "unresolved"),
            ("Finding IDs", ", ".join(record["finding_ids"]) or "structural review signal"),
            ("Evidence", "; ".join(f"{loc['path']}:{loc['line']}" for loc in record["evidence"])),
            ("Recommendation", record["recommendation"]),
        ):
            lines.extend([f"**{label}:** {_text(value)}", ""])
        for flow in record["data_flows"]:
            lines.extend(
                [
                    "**Static data flow:** "
                    + " -> ".join(
                        _text(
                            f"{hop['role']} {hop['loc']} ({hop['node'] or 'unresolved component'})"
                        )
                        for hop in flow["hops"]
                    ),
                    "",
                ]
            )
        if not record["data_flows"]:
            lines.extend(["**Data flow:** unresolved; no trace attached.", ""])
        lines.append("**Verification:**")
        lines.append("")
        lines.extend(
            f"{index}. {_text(step)}" for index, step in enumerate(record["verification"], 1)
        )
        lines.append("")
    return "\n".join(lines)


def render_threat_diff(diff: dict[str, Any]) -> str:
    lines = [
        "# Threat-model diff",
        "",
        f"Added: {len(diff['added'])}; removed: {len(diff['removed'])}; changed: {len(diff['changed'])}; unchanged: {diff['unchanged']}.",
        "",
        diff["note"],
        "",
    ]
    for side in ("before", "after"):
        repository = diff[side]
        lines.extend(
            [
                f"**{side.capitalize()}:** {_text(repository.get('name', 'repository'))} @ {_text(repository.get('commit') or 'revision unavailable')}",
                "",
            ]
        )
    if diff["context_changes"]:
        lines.extend(
            [
                "## Analysis context changed",
                "",
                "Compare coverage/configuration before interpreting removals.",
                "",
                "```json",
                render_snapshot(diff["context_changes"]).rstrip(),
                "```",
                "",
            ]
        )
    for label in ("added", "removed"):
        lines.extend(
            [f"## {label.capitalize()}", "", render_threat_records(diff[label]) or "None.\n", ""]
        )
    lines.extend(["## Changed", ""])
    for change in diff["changed"]:
        lines.extend(
            [
                f"### `{change['id']}`",
                "",
                "Changed fields: " + _text(", ".join(change["fields"])),
                "",
                "```json",
                render_snapshot(
                    {
                        field: {
                            "before": change["before"].get(field),
                            "after": change["after"].get(field),
                        }
                        for field in change["fields"]
                    }
                ).rstrip(),
                "```",
                "",
                "#### Before",
                "",
                render_threat_records([change["before"]]),
                "#### After",
                "",
                render_threat_records([change["after"]]),
            ]
        )
    return "\n".join(lines).rstrip() + "\n"
