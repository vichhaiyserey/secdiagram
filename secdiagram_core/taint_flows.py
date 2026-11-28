"""Language-neutral taint flows and the attack-path diagram.

Every tainted finding becomes a :class:`TaintFlow`: an ordered list of hops,
each tied to a graph node (endpoint, function, method), a ``path:line`` and a
role (``source``, ``param``, ``call``, ``propagation``, ``return``, ``sink``).

* C#, JS/TS, PHP and Go findings already carry hop-level flows in
  ``finding.metadata["flow"]`` (see :mod:`polyglot_security`).
* Python and Java findings carry ``finding.trace`` locations; each location is
  mapped to the innermost callable node of its file so their flows render the
  same way.

:func:`render_taint_mermaid` draws those flows as an attack-path diagram:
untrusted input -> entry points -> every function the data passes through ->
the vulnerable sink (category, CWE, severity). Shared functions appear once,
so convergent attack paths and choke points are visible at a glance.
"""

from __future__ import annotations

import bisect
import re
from dataclasses import dataclass, field
from typing import Any

from .model import SEVERITY_RANK, Finding, Graph, Loc, Node, _normalize_path_str
from .render_mermaid import MODERN_INIT, _escape

CALLABLE_KINDS = frozenset({"endpoint", "function", "method", "task", "cli"})
ENTRY_KINDS = frozenset({"endpoint", "task", "cli"})
CATEGORY_LABELS = {
    "sql": "SQL injection",
    "nosql": "NoSQL injection",
    "command": "Command injection",
    "code": "Code injection",
    "file-inclusion": "File inclusion",
    "deserialization": "Unsafe deserialization",
    "xss": "Cross-site scripting",
    "path": "Path traversal",
    "ssrf": "SSRF",
    "redirect": "Open redirect",
    "ldap": "LDAP injection",
    "xpath": "XPath injection",
    "template": "Template injection",
    "log": "Log injection",
    "prototype-pollution": "Prototype pollution",
}


@dataclass(frozen=True, slots=True)
class FlowHop:
    loc: Loc
    node_id: str | None
    role: str


@dataclass(slots=True)
class TaintFlow:
    finding: Finding
    hops: list[FlowHop] = field(default_factory=list)

    @property
    def node_path(self) -> list[str]:
        """Distinct consecutive graph nodes the tainted data passes through."""
        path: list[str] = []
        for hop in self.hops:
            if hop.node_id and (not path or path[-1] != hop.node_id):
                path.append(hop.node_id)
        return path

    @property
    def interprocedural(self) -> bool:
        return len(set(self.node_path)) > 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding.id,
            "category": self.finding.category,
            "severity": self.finding.severity,
            "cwe": self.finding.cwe,
            "hops": [
                {"loc": hop.loc.ref, "node": hop.node_id, "role": hop.role} for hop in self.hops
            ],
        }


class _NodeLocator:
    """Map ``path:line`` to the innermost callable graph node of that file."""

    def __init__(self, graph: Graph) -> None:
        self.by_path: dict[str, list[tuple[int, int, str]]] = {}
        for node in graph.sorted_nodes():
            if node.kind not in CALLABLE_KINDS or not node.path or not node.line:
                continue
            span = int(node.attrs.get("body_lines") or 0)
            end = node.line + span - 1 if span > 0 else 0
            key = _normalize_path_str(node.path)
            self.by_path.setdefault(key, []).append((node.line, end, node.id))
        for entries in self.by_path.values():
            entries.sort()
        self.starts = {key: [entry[0] for entry in entries] for key, entries in self.by_path.items()}

    def node_at(self, loc: Loc) -> str | None:
        key = _normalize_path_str(loc.path)
        entries = self.by_path.get(key)
        if not entries:
            return None
        idx = bisect.bisect_right(self.starts[key], loc.line) - 1
        best: str | None = None
        while idx >= 0:
            start, end, node_id = entries[idx]
            if end == 0 or end >= loc.line:
                # Known span covering the line, or unknown span: nearest preceding.
                if end != 0 or best is None:
                    best = node_id
                if end != 0:
                    return node_id
                return best
            idx -= 1
        return best


def _hops_from_metadata(finding: Finding) -> list[FlowHop]:
    hops: list[FlowHop] = []
    for raw in (finding.metadata or {}).get("flow") or []:
        ref = str(raw.get("loc", ""))
        path, _, line = ref.rpartition(":")
        if not path or not line.isdigit():
            continue
        hops.append(FlowHop(Loc(path, int(line)), raw.get("node"), str(raw.get("role", "propagation"))))
    return hops


def _hops_from_trace(finding: Finding, locator: _NodeLocator) -> list[FlowHop]:
    hops: list[FlowHop] = []
    last = len(finding.trace) - 1
    previous_node: str | None = None
    for position, loc in enumerate(finding.trace):
        node_id = locator.node_at(loc)
        if position == 0:
            role = "source"
        elif position == last:
            role = "sink"
        elif node_id != previous_node:
            role = "call"
        else:
            role = "propagation"
        hops.append(FlowHop(loc, node_id, role))
        previous_node = node_id
    if hops and hops[-1].node_id is None and finding.node_id:
        hops[-1] = FlowHop(hops[-1].loc, finding.node_id, "sink")
    return hops


def build_taint_flows(graph: Graph, *, deduplicate: bool = True) -> list[TaintFlow]:
    """One flow per tainted finding (with a source-to-sink path), deterministic."""
    locator = _NodeLocator(graph)
    flows: list[TaintFlow] = []
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    for finding in graph.sorted_findings():
        hops = _hops_from_metadata(finding)
        if not hops and len(finding.trace) >= 2:
            hops = _hops_from_trace(finding, locator)
        # A single hop is still a flow when source and sink share a line
        # (e.g. ``Redirect(returnUrl)`` on a request parameter).
        if not hops:
            continue
        flow = TaintFlow(finding=finding, hops=hops)
        sink_ref = finding.evidence[0].ref if finding.evidence else hops[-1].loc.ref
        key = (finding.category, sink_ref, tuple(flow.node_path))
        if deduplicate and key in seen:  # several rules on one sink: draw the path once
            continue
        seen.add(key)
        flows.append(flow)
    flows.sort(
        key=lambda flow: (
            -float((flow.finding.metadata.get("risk") or {}).get("score", 0.0)),
            -SEVERITY_RANK.get(flow.finding.severity, 0),
            flow.finding.baseline,
            flow.hops[-1].loc.path,
            flow.hops[-1].loc.line,
            flow.finding.category,
        )
    )
    return flows


def annotate_flows(graph: Graph) -> list[TaintFlow]:
    """Attach ``metadata["flow"]`` to every tainted finding and summarize in meta."""
    flows = build_taint_flows(graph)
    for flow in flows:
        if not (flow.finding.metadata or {}).get("flow"):
            flow.finding.metadata["flow"] = [
                {"loc": hop.loc.ref, "node": hop.node_id, "role": hop.role} for hop in flow.hops
            ]
        flow.finding.metadata["interprocedural"] = flow.interprocedural
    entry_nodes = {flow.node_path[0] for flow in flows if flow.node_path}
    graph.meta["taint_flows"] = {
        "count": len(flows),
        "interprocedural": sum(1 for flow in flows if flow.interprocedural),
        "entry_points": len(entry_nodes),
        "by_severity": {
            sev: sum(1 for flow in flows if flow.finding.severity == sev)
            for sev in ("critical", "high", "medium", "low")
            if any(flow.finding.severity == sev for flow in flows)
        },
    }
    return flows


def taint_edge_pairs(flows: list[TaintFlow]) -> set[tuple[str, str]]:
    """Consecutive node pairs on any flow (for overlay highlighting)."""
    pairs: set[tuple[str, str]] = set()
    for flow in flows:
        path = flow.node_path
        pairs.update(zip(path, path[1:], strict=False))
    return pairs


# ------------------------------------------------------------------ rendering

TAINT_CLASSES = """  classDef input fill:#fee2e2,stroke:#b91c1c,stroke-width:2px,color:#7f1d1d;
  classDef entry fill:#eff6ff,stroke:#2563eb,stroke-width:2px,color:#1e3a8a;
  classDef hop fill:#f8fafc,stroke:#64748b,stroke-width:1.5px,color:#0f172a;
  classDef critical fill:#fef2f2,stroke:#dc2626,stroke-width:3px,color:#991b1b;
  classDef high fill:#fff7ed,stroke:#ea580c,stroke-width:2.5px,color:#9a3412;
  classDef medium fill:#fefce8,stroke:#ca8a04,stroke-width:2px,color:#713f12;
  classDef low fill:#f8fafc,stroke:#475569,stroke-width:1.5px,color:#1e293b;"""


PRIORITY_TONE = {"P0": "critical", "P1": "high", "P2": "medium", "P3": "low"}
EXPOSURE_BADGES = {
    "public": "PUBLIC - no auth",
    "unknown": "auth not detected",
    "authenticated": "authenticated",
    "privileged": "authenticated",
    "sensitive_data": "credential material",
    "internal_high_impact": "internal high impact",
    "isolated": "isolated",
    "local": "local entry",
    "internal": "internal",
}


def _node_label(node: Node | None, fallback: Loc, exposure: str | None = None) -> str:
    if node is None:
        return _escape(f"{fallback.path}:{fallback.line}")
    if exposure:
        return _node_label(node, fallback) + "<br/>" + _escape(f"[{EXPOSURE_BADGES.get(exposure, exposure)}]")
    where = f"{node.path}:{node.line}" if node.path and node.line else ""
    if node.kind == "endpoint" and node.attrs.get("routes"):
        route = node.attrs["routes"][0]
        title = f"{route.get('method', '').upper()} {route.get('path', '')}"
        parts = [title] + ([node.name] if node.name and node.name != title else []) + ([where] if where else [])
        return "<br/>".join(_escape(part) for part in parts)
    owner = ""
    if node.kind == "method":
        parts = [part for part in re.split(r"[.:/\\]+", node.qualname) if part]
        owner = parts[-2] + "." if len(parts) >= 2 else ""
    return "<br/>".join(_escape(part) for part in [f"{owner}{node.name}()"] + ([where] if where else []))


def render_taint_mermaid(
    graph: Graph,
    flows: list[TaintFlow] | None = None,
    max_flows: int = 40,
    ascii_only: bool = False,
) -> str:
    """Attack-path diagram: untrusted input -> entry points -> hops -> sinks.

    *ascii_only* drops emoji/typographic glyphs for ASCII-only documents
    (``ARCHITECTURE.md``).
    """
    sym_input, sym_sink, sym_entry, sep = ("⚠️ ", "⛔ ", "🌐 ", " · ") if not ascii_only else ("", "SINK: ", "", " - ")
    flows = build_taint_flows(graph) if flows is None else flows
    lines = [
        "%% Attack-path (taint flow) diagram generated by secdiagram",
        "%% Each path: untrusted input -> entry point -> functions on the path -> vulnerable sink",
        MODERN_INIT,
        "flowchart LR",
    ]
    if not flows:
        lines.append('  none(["No source-to-sink taint flows detected"]):::hop')
        lines.append(TAINT_CLASSES)
        return "\n".join(lines) + "\n"
    shown = flows[:max_flows]
    ids: dict[str, str] = {}

    def mid(key: str) -> str:
        if key not in ids:
            ids[key] = f"t{len(ids)}"
        return ids[key]

    node_lines: list[str] = []
    edge_lines: list[str] = []
    edge_index: dict[tuple[str, str], int] = {}
    edge_severity: dict[int, str] = {}
    declared: set[str] = set()
    entries: set[str] = set()

    def declare(key: str, text: str, cls: str, shape: str = "box") -> None:
        if key in declared:
            return
        declared.add(key)
        if shape == "hex":
            node_lines.append(f'    {mid(key)}{{{{"{text}"}}}}:::{cls}')
        elif shape == "stadium":
            node_lines.append(f'    {mid(key)}(["{text}"]):::{cls}')
        else:
            node_lines.append(f'    {mid(key)}["{text}"]:::{cls}')

    def link(src: str, dst: str, arrow: str, severity: str | None = None) -> None:
        if (src, dst) not in edge_index:
            edge_index[(src, dst)] = len(edge_lines)
            edge_lines.append(f"  {mid(src)} {arrow} {mid(dst)}")
        index = edge_index[(src, dst)]
        if severity and SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(edge_severity.get(index, ""), -1):
            edge_severity[index] = severity

    declare("__input__", f"{sym_input}Untrusted input<br/>HTTP request / CLI args", "input", "stadium")
    for flow in shown:
        finding = flow.finding
        path_nodes = flow.node_path or []
        keys: list[str] = []
        for index, node_id in enumerate(path_nodes):
            node = graph.nodes.get(node_id)
            hop = next(h for h in flow.hops if h.node_id == node_id)
            is_entry = index == 0
            cls = "entry" if is_entry else "hop"
            exposure = (finding.metadata.get("risk") or {}).get("exposure") if is_entry else None
            declare(node_id, _node_label(node, hop.loc, exposure), cls)
            keys.append(node_id)
            if is_entry:
                entries.add(node_id)
        sink_hop = flow.hops[-1]
        sink_key = f"sink:{finding.id}"
        label = CATEGORY_LABELS.get(finding.category, finding.title)
        headline = f"{sym_sink}{label}{sep}{finding.cwe}" if finding.cwe else f"{sym_sink}{label}"
        risk = finding.metadata.get("risk") or {}
        priority = f"{risk['priority']} {risk['score']}{sep}" if "priority" in risk else ""
        status = priority + finding.severity.upper() + (f"{sep}baseline" if finding.baseline else "")
        sink_loc = finding.evidence[0].ref if finding.evidence else sink_hop.loc.ref
        # Colour by risk priority when scored (the diagram must agree with the
        # ranking), otherwise by rule severity.
        tone = PRIORITY_TONE.get(str(risk.get("priority")), finding.severity)
        tone = tone if tone in ("critical", "high", "medium", "low") else "low"
        declare(
            sink_key,
            f"{_escape(headline)}<br/>{_escape(status)}<br/>{_escape(sink_loc)}",
            tone,
            "hex",
        )
        severity = tone
        if keys:
            link("__input__", keys[0], "-.->|untrusted|")
            for src, dst in zip(keys, keys[1:], strict=False):
                link(src, dst, "==>", severity)
            link(keys[-1], sink_key, "==>", severity)
        else:
            link("__input__", sink_key, "==>", severity)

    lines.append(f'  subgraph Entry["{sym_entry}Entry points"]')
    lines.append("    direction TB")
    lines.extend(line for line in node_lines if any(line.strip().startswith(mid(e) + "[") for e in entries))
    lines.append("  end")
    lines.extend(
        line
        for line in node_lines
        if not any(line.strip().startswith(mid(e) + "[") for e in entries)
    )
    lines.extend(edge_lines)
    # Every hop of a path is colored by the worst flow that uses it.
    colors = {"critical": "#dc2626", "high": "#ea580c", "medium": "#ca8a04", "low": "#64748b"}
    for sev in ("critical", "high", "medium", "low"):
        indexes = sorted(i for i, s in edge_severity.items() if s == sev)
        if indexes:
            lines.append(f"  linkStyle {','.join(map(str, indexes))} stroke:{colors[sev]},stroke-width:3px")
    if len(flows) > max_flows:
        lines.append(f"  %% {len(flows) - max_flows} lower-ranked flow(s) omitted for readability")
    lines.append(TAINT_CLASSES)
    text = "\n".join(lines) + "\n"
    return text.encode("ascii", "replace").decode("ascii") if ascii_only else text
