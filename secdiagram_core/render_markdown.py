"""Grounded Markdown architecture report with file:line citations."""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Any

from . import __version__
from .features import feature_for_path
from .model import Edge, Graph, Node
from .risk import risk_sort_key
from .taint_flows import build_taint_flows, render_taint_mermaid


def _esc(text: Any) -> str:
    return " ".join(str(text).split()).replace("|", "\\|")


def _ref(node: Node) -> str:
    if node.path and node.line:
        return f"`{node.path}:{node.line}`"
    if node.path:
        return f"`{node.path}`"
    return "`" + _esc(node.qualname) + "`"


def _edge_ref(edge: Edge) -> str:
    if edge.evidence:
        return f"`{edge.evidence[0].ref}`"
    return ""


def _doc_line(node: Node) -> str:
    if not node.doc:
        return ""
    first = " ".join(node.doc.split())
    if len(first) > 120:
        first = first[:117] + "..."
    return first


def _feature_stats(nodes: list[Node]) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for node in nodes:
        counts[node.kind] += 1
    return counts


def _flows(graph: Graph, endpoints: list[Node], node_by_id: dict[str, Node], limit: int = 6) -> list[str]:
    outgoing: dict[str, list[Edge]] = defaultdict(list)
    for edge in graph.edges:
        if edge.kind in {"calls", "instantiates"} and edge.confidence >= 0.5:
            outgoing[edge.src].append(edge)
    for edges in outgoing.values():
        edges.sort(key=lambda e: (e.kind, e.dst))

    lines: list[str] = []
    for endpoint in endpoints:
        found: list[str] = []
        queue: deque[tuple[str, list[str], set[str]]] = deque([(endpoint.id, [endpoint.name], {endpoint.id})])
        while queue and len(found) < limit:
            current, path, seen = queue.popleft()
            for edge in outgoing.get(current, []):
                target = node_by_id.get(edge.dst)
                if target is None or target.id in seen:
                    continue
                next_path = path + [target.name]
                found.append(" -> ".join(next_path) + "  " + _edge_ref(edge))
                if len(next_path) < 3:
                    queue.append((target.id, next_path, seen | {target.id}))
        if found:
            lines.append(f"- **{_esc(endpoint.qualname)}** ({_ref(endpoint)})")
            for flow in sorted(set(found)):
                lines.append(f"  - {flow}")
        else:
            lines.append(f"- **{_esc(endpoint.qualname)}** ({_ref(endpoint)}) - no resolved outgoing calls")
    return lines


_POLYGLOT_LABELS = (
    ("csharp", "C#"), ("javascript", "JavaScript"), ("typescript", "TypeScript"), ("php", "PHP"), ("go", "Go"),
    ("rust", "Rust"),
)


def _indexed_sources_text(meta: dict[str, Any]) -> str:
    parts = [f"**{meta.get('python_files', 0)}** Python", f"**{meta.get('java_files', 0)}** Java"]
    polyglot = meta.get("polyglot_files") or {}
    parts.extend(f"**{polyglot[key]}** {label}" for key, label in _POLYGLOT_LABELS if polyglot.get(key))
    return (", ".join(parts[:-1]) + " and " + parts[-1] + " sources") if len(parts) > 1 else parts[0]


def _fix_first_section(graph: Graph, limit: int = 10) -> list[str]:
    """Top findings by risk (impact x exposure x evidence x confidence x exploit intel)."""
    ranked = [
        finding for finding in sorted(graph.findings, key=risk_sort_key)
        if not finding.baseline and finding.metadata.get("risk")
    ]
    if not ranked:
        return []
    counts = (graph.meta.get("risk") or {}).get("by_priority") or {}
    summary = ", ".join(f"{label}: {counts.get(label, 0)}" for label in ("P0", "P1", "P2", "P3"))
    out = ["## Fix first (risk-ranked)", ""]
    out.append(
        f"Priorities from impact x exposure x evidence x confidence x exploit intel (0-10). {summary}. "
        "P0 >= 8 fix now, P1 >= 6, P2 >= 4."
    )
    out.append("")
    out.append("| Priority | Score | Finding | Exposure | Evidence | Location |")
    out.append("|---|---|---|---|---|---|")
    for finding in ranked[:limit]:
        risk = finding.metadata["risk"]
        ref = f"`{finding.evidence[0].ref}`" if finding.evidence else "-"
        row = (
            f"| **{risk['priority']}** | {risk['score']} | {_esc(finding.title)} ({_esc(finding.cwe or finding.category)}) | "
            f"{_esc(risk['exposure'])} | {_esc(risk['evidence'])} | {ref} |"
        )
        out.append(row.encode("ascii", "replace").decode("ascii"))
    out.append("")
    return out


def _attack_paths_section(graph: Graph, limit: int = 10) -> list[str]:
    """Attack paths: request input -> functions on the path -> vulnerable sink."""
    flows = [flow for flow in build_taint_flows(graph) if not flow.finding.baseline]
    if not flows:
        return []
    out = ["## Attack paths (taint flows)", ""]
    cross = sum(1 for flow in flows if flow.interprocedural)
    entries = len({flow.node_path[0] for flow in flows if flow.node_path})
    out.append(
        f"**{len(flows)}** source-to-sink flow(s) from **{entries}** entry point(s); "
        f"**{cross}** cross function or file boundaries. Each path is evidence-backed "
        "(`path:line` per hop) and drawn in `diagram-taint.mmd`."
    )
    out.append("")
    for number, flow in enumerate(flows[:limit], start=1):
        finding = flow.finding
        hops = []
        for node_id in flow.node_path:
            node = graph.nodes.get(node_id)
            if node is None:
                continue
            routes = node.attrs.get("routes") or []
            label = f"{routes[0].get('method', '').upper()} {routes[0].get('path', '')}" if routes else node.name
            hops.append(f"`{_esc(label)}`")
        sink = finding.evidence[0].ref if finding.evidence else flow.hops[-1].loc.ref
        hops.append(f"**{_esc(finding.title)}** ({_esc(finding.cwe or finding.category)}) at `{_esc(sink)}`")
        risk = finding.metadata.get("risk") or {}
        label = f"{risk['priority']} {risk['score']}" if "priority" in risk else finding.severity
        line = f"{number}. **{_esc(label)}** - " + " -> ".join(hops)
        out.append(line.encode("ascii", "replace").decode("ascii"))
    if len(flows) > limit:
        out.append(f"\n_{len(flows) - limit} more flow(s) in `graph.json` (`findings[].metadata.flow`)._")
    out.append("")
    out.append("```mermaid")
    out.append(render_taint_mermaid(graph, flows, max_flows=15, ascii_only=True).rstrip())
    out.append("```")
    out.append("")
    return out


def _policy_section(graph: Graph, policy: dict[str, Any]) -> list[str]:
    """Enforcement-policy decisions: what blocks, what needs review, what is exempt."""
    mode = str(policy.get("mode") or "")
    decisions = policy.get("decisions") or {}
    blocks = policy.get("blocks") or []
    suppressed = policy.get("suppressed") or []
    reactivated = policy.get("reactivated") or []
    out = ["## Enforcement policy", ""]
    bits = [f"{key}: {value}" for key, value in sorted(decisions.items()) if value]
    header = f"Mode **{mode}**. Decisions: " + (", ".join(bits) or "none") + "."
    if mode == "shadow":
        header += " Shadow mode: decisions are recorded but CI is not affected."
    out.append(header)
    out.append("")
    if blocks:
        out.append("| Finding | Policy reason | Confidence | Reachability | Exposure | Required actions |")
        out.append("|---|---|---|---|---|---|")
        by_id = {finding.id: finding for finding in graph.findings}
        for finding_id in blocks:
            finding = by_id.get(finding_id)
            if finding is None:
                continue
            actions = "; ".join(finding.required_actions) if finding.required_actions else "-"
            out.append(
                f"| {_esc(finding.title)} | {_esc(finding.policy_reason)} | {finding.confidence_score} | "
                f"{_esc(finding.reachability)} | {_esc(finding.exposure)} | {_esc(actions)} |"
            )
        out.append("")
    if suppressed:
        out.append(f"Suppressed by governed exception: **{len(suppressed)}** finding(s) (still listed above and in `graph.json`).")
        out.append("")
    if reactivated:
        out.append(f"Reactivated after suppression expiry: **{len(reactivated)}** finding(s).")
        out.append("")
    return out


def render_markdown(
    graph: Graph,
    meta: dict[str, Any] | None = None,
    high_level_mermaid: str | None = None,
) -> str:
    graph.dedupe_edges()
    meta = dict(meta or {})
    nodes = graph.sorted_nodes()
    node_by_id = {node.id: node for node in nodes}

    lines: list[str] = []
    name = meta.get("name") or "repository"
    lines.append(f"# Architecture: {_esc(name)}")
    lines.append("")
    commit = meta.get("commit")
    branch = meta.get("branch")
    bits = [f"generated by **secdiagram {__version__}**", "deterministic static analysis"]
    if branch:
        bits.append(f"branch `{branch}`")
    if commit:
        bits.append(f"commit `{commit}`")
    if meta.get("dirty"):
        bits.append("working tree dirty")
    lines.append("> " + " | ".join(bits))
    lines.append("")
    lines.append(
        f"**{len(graph.nodes)}** nodes | **{len(graph.edges)}** edges | "
        f"**{len(graph.features)}** features | **{len(graph.findings)}** security findings"
    )
    baseline_info = meta.get("security_baseline") or {}
    if baseline_info:
        lines.append("")
        lines.append(
            f"Baseline `{baseline_info.get('file', 'security.baseline.json')}` suppresses "
            f"**{baseline_info.get('known', 0)}** known finding(s); findings below and in "
            f"`security.sarif` cover the **{baseline_info.get('new', 0)}** new one(s) only."
        )
    lines.append("")

    if high_level_mermaid:
        lines.append("## System architecture overview (high-level)")
        lines.append("")
        lines.append("```mermaid")
        lines.append(high_level_mermaid.strip())
        lines.append("```")
        lines.append("")

    lines.append(
        "Every claim below is derived from the Python AST. Edges carry a confidence score and "
        "a `path:line` citation; unresolved dynamic calls are counted, not guessed."
    )
    lines.append("")

    lines.append("## Feature map")
    lines.append("")
    lines.append("| Feature | Modules | Classes | Functions | Endpoints | Findings |")
    lines.append("|---|---:|---:|---:|---:|---:|")
    findings_by_feature: dict[str, int] = defaultdict(int)
    for finding in graph.findings:
        if finding.baseline:
            continue
        node = node_by_id.get(finding.node_id or "")
        if node and node.feature:
            findings_by_feature[node.feature] += 1
        elif finding.evidence:
            findings_by_feature[feature_for_path(finding.evidence[0].path)] += 1
    for feature in sorted(graph.features, key=lambda f: f.name):
        feature_nodes = [node_by_id[node_id] for node_id in feature.nodes if node_id in node_by_id]
        counts = _feature_stats(feature_nodes)
        lines.append(
            f"| {_esc(feature.name)} | {counts['module']} | {counts['class']} | "
            f"{counts['function'] + counts['method']} | {counts['endpoint']} | "
            f"{findings_by_feature.get(feature.name, 0)} |"
        )
    lines.append("")

    lines.append("## Features")
    lines.append("")
    for feature in sorted(graph.features, key=lambda f: f.name):
        feature_nodes = [node_by_id[node_id] for node_id in feature.nodes if node_id in node_by_id]
        if not feature_nodes:
            continue
        lines.append(f"### {_esc(feature.name)}")
        lines.append("")
        lines.append(feature.description)
        lines.append("")
        if feature.files:
            shown = feature.files[:12]
            suffix = f" (+{len(feature.files) - len(shown)} more)" if len(feature.files) > len(shown) else ""
            lines.append("Files: " + ", ".join(f"`{path}`" for path in shown) + suffix)
            lines.append("")

        endpoints = sorted(
            [node for node in feature_nodes if node.kind in {"endpoint", "task", "cli"}],
            key=lambda n: n.qualname,
        )
        if endpoints:
            lines.append("Entrypoints:")
            lines.append("")
            for node in endpoints:
                routes = node.attrs.get("routes") or []
                route_text = ""
                if routes:
                    route_text = " " + ", ".join(
                        f"`{route.get('method', '')} {route.get('path', '')}`".strip() for route in routes
                    )
                auth = " auth" if node.attrs.get("auth") else ""
                lines.append(f"- `{_esc(node.qualname)}`{route_text} - {_ref(node)}{auth}")
            lines.append("")

        classes = sorted([node for node in feature_nodes if node.kind == "class"], key=lambda n: n.qualname)
        if classes:
            lines.append("Key classes:")
            lines.append("")
            for node in classes[:10]:
                doc = _doc_line(node)
                suffix = f" - {_esc(doc)}" if doc else ""
                lines.append(f"- `{_esc(node.name)}` ({_ref(node)}){suffix}")
            if len(classes) > 10:
                lines.append(f"- ... {len(classes) - 10} more")
            lines.append("")

        modules = sorted([node for node in feature_nodes if node.kind == "module"], key=lambda n: n.qualname)
        if modules:
            lines.append("Modules: " + ", ".join(f"`{_esc(node.name)}`" for node in modules[:20]))
            if len(modules) > 20:
                lines[-1] += f" ... (+{len(modules) - 20})"
            lines.append("")

    endpoint_nodes = sorted([node for node in nodes if node.kind == "endpoint"], key=lambda n: n.qualname)
    if endpoint_nodes:
        lines.append("## Key call flows")
        lines.append("")
        lines.append("Resolved call chains up to two hops from each endpoint (confidence >= 0.5).")
        lines.append("")
        lines.extend(_flows(graph, endpoint_nodes, node_by_id))
        lines.append("")

    external = sorted([node for node in nodes if node.kind == "external"], key=lambda n: n.name)
    if external:
        incoming: dict[str, int] = defaultdict(int)
        for edge in graph.edges:
            if edge.kind in {"imports", "calls", "instantiates"}:
                incoming[edge.dst] += 1
        lines.append("## External dependencies")
        lines.append("")
        lines.append("| Package | Incoming edges | Symbols observed |")
        lines.append("|---|---:|---|")
        for node in external:
            symbols = node.attrs.get("symbols") or []
            symbol_text = ", ".join(f"`{_esc(s)}`" for s in symbols[:6])
            if len(symbols) > 6:
                symbol_text += f" (+{len(symbols) - 6})"
            lines.append(f"| `{_esc(node.name)}` | {incoming.get(node.id, 0)} | {symbol_text or '-'} |")
        lines.append("")

    infra = sorted(
        [node for node in nodes if node.kind in {"infra", "workflow", "service"}],
        key=lambda n: (n.kind, n.qualname),
    )
    if infra:
        lines.append("## Infrastructure artifacts")
        lines.append("")
        lines.append("| Artifact | Kind | Path |")
        lines.append("|---|---|---|")
        for node in infra:
            lines.append(f"| {_esc(node.name)} | {_esc(node.kind)} | {_ref(node)} |")
        lines.append("")

    lines.extend(_fix_first_section(graph))

    policy = meta.get("policy") or {}
    if graph.findings:
        new_findings = [finding for finding in graph.sorted_findings() if not finding.baseline]
        policy_active = bool(policy.get("mode"))
        if baseline_info and not new_findings:
            lines.append("## Security review")
            lines.append("")
            lines.append(
                f"All findings are covered by the baseline (`{baseline_info.get('file', 'security.baseline.json')}`); "
                "nothing new to review. Regenerate the baseline with `--create-baseline` after triaging."
            )
            lines.append("")
        elif new_findings:
            lines.append("## Security review")
            lines.append("")
            lines.append(
                "These are evidence-backed review prompts, not confirmed vulnerabilities. "
                "Tainted findings rise to critical; risky patterns without taint remain review items."
            )
            lines.append("")
            if policy_active:
                lines.append("| Severity | Enforcement | Confidence | Exposure | Category | CWE | Evidence | Taint path | Finding | Recommendation |")
                lines.append("|---|---|---|---|---|---|---|---|---|---|")
                for finding in new_findings:
                    ref = f"`{finding.evidence[0].ref}`" if finding.evidence else "-"
                    trace = " -> ".join(f"`{_esc(loc.ref)}`" for loc in finding.trace) if finding.trace else "-"
                    lines.append(
                        f"| **{_esc(finding.severity)}** | {_esc(finding.enforcement)} | "
                        f"{finding.confidence_score or finding.confidence} | {_esc(finding.exposure or '-')} | "
                        f"{_esc(finding.category)} | {_esc(finding.cwe or '-')} | {ref} | {trace} | "
                        f"{_esc(finding.title)} | {_esc(finding.recommendation)} |"
                    )
            else:
                lines.append("| Severity | Category | CWE | Evidence | Taint path | Finding | Recommendation |")
                lines.append("|---|---|---|---|---|---|---|")
                for finding in new_findings:
                    ref = f"`{finding.evidence[0].ref}`" if finding.evidence else "-"
                    trace = " -> ".join(f"`{_esc(loc.ref)}`" for loc in finding.trace) if finding.trace else "-"
                    lines.append(
                        f"| **{_esc(finding.severity)}** | {_esc(finding.category)} | "
                        f"{_esc(finding.cwe or '-')} | {ref} | {trace} | {_esc(finding.title)} | "
                        f"{_esc(finding.recommendation)} |"
                    )
            lines.append("")
        if policy_active:
            lines.extend(_policy_section(graph, policy))

    lines.extend(_attack_paths_section(graph))

    analysis = meta.get("analysis", {})
    lines.append("## Method & limits")
    lines.append("")
    languages = meta.get("languages") or {}
    language_text = ", ".join(f"{name} ({count})" for name, count in sorted(languages.items())) or "none detected"
    lines.append(
        f"- Scope: **{meta.get('files_discovered', '?')}** files discovered, "
        f"{_indexed_sources_text(meta)} indexed, "
        f"**{meta.get('files_skipped', 0)}** skipped. Languages: {_esc(language_text)}."
    )
    unsupported = meta.get("unsupported_security_languages") or []
    if unsupported:
        lines.append(
            "- Security rules cover Python, Java, C#, JavaScript/TypeScript, PHP, Go and Rust; no checks were run for: "
            + ", ".join(f"`{_esc(name)}`" for name in unsupported)
            + "."
        )
    if meta.get("config_hash"):
        lines.append(
            f"- Configuration fingerprint: `{meta['config_hash']}`; commit: "
            f"`{meta.get('commit') or 'unknown'}`."
        )
    parse_errors = analysis.get("parse_errors") or []
    if parse_errors:
        parse_preview = ", ".join(f"`{_esc(path)}`" for path in parse_errors[:10])
        suffix = f" (+{len(parse_errors) - 10} more)" if len(parse_errors) > 10 else ""
        lines.append(f"- Could not parse: {parse_preview}{suffix}.")
    lines.append(
        "- Symbols come from `ast`; imports and calls are resolved through package roots, "
        "aliases, relative imports, class members, and one-level assignment inference."
    )
    lines.append(
        f"- Unresolved dynamic references: **{analysis.get('unresolved_count', 0)}** "
        f"(shown as samples in `graph.json`)."
    )
    if analysis.get("truncated"):
        lines.append(
            f"- Graph was capped at `--max-nodes`; **{analysis.get('dropped_nodes', 0)}** nodes were dropped."
        )
    lines.append(
        "- Static analysis cannot see plugin loading, runtime registries, or network-delivered code; "
        "treat this report as an auditable orientation map, not a proof of runtime behavior."
    )
    lines.append("")
    lines.append("## Reproduce")
    lines.append("")
    lines.append("```powershell")
    lines.append(f"python secdiagram.py --dir {meta.get('name', '.')} --format json,md,mermaid")
    lines.append("```")
    lines.append("")
    return "\n".join(lines)
