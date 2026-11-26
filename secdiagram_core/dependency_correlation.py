"""Correlate Pub imports and qualified calls with existing Dart graph evidence."""

import hashlib
import re
from collections import deque
from pathlib import PurePosixPath

from .model import Finding, Graph, Loc
from .polyglot_index import PolyglotIndex, symbol_node_id

_IMPORT = re.compile(
    r"(?m)^\s*(import|export|part)\s+(['\"])package:([a-zA-Z0-9_]+)/([^'\"]+)\2"
    r"(?:\s+as\s+([a-zA-Z_]\w*))?([^;\n]*);"
)
_CALL = re.compile(r"(?<![.\w$])([A-Za-z_]\w*)\s*\.\s*([A-Za-z_]\w*)\s*\(")
_DART_IDENTIFIER = re.compile(r"[A-Za-z_$][\w$]*")
_DIRECTIVE = re.compile(r"(?m)^\s*import\b[^;]*;")
_PREFIX = re.compile(r"\bas\s+([A-Za-z_]\w*)\b")


def _unambiguous_prefixes(masked: str, aliases: set[str]) -> set[str]:
    """Treat any bare prefix use or repeated import declaration as ambiguous."""
    counts: dict[str, int] = {}
    declaration_offsets = set()
    for directive in _DIRECTIVE.finditer(masked):
        for match in _PREFIX.finditer(masked, directive.start(), directive.end()):
            alias = match[1]
            if alias in aliases:
                counts[alias] = counts.get(alias, 0) + 1
                declaration_offsets.add(match.start(1))
    safe = {alias for alias, count in counts.items() if count == 1}
    for match in _DART_IDENTIFIER.finditer(masked):
        if match[0] not in safe or match.start() in declaration_offsets:
            continue
        end = match.end()
        while end < len(masked) and masked[end].isspace():
            end += 1
        if end == len(masked) or masked[end] != ".":
            safe.discard(match[0])
    return safe


def correlate(graph: Graph, index: PolyglotIndex, findings: list[Finding]) -> None:
    packages = {}
    projects = set()
    modules = {}
    for node in graph.nodes.values():
        if node.kind == "dependency" and node.attrs.get("ecosystem") == "pub":
            project = PurePosixPath(node.path or "").parent.as_posix()
            packages[project, node.name] = node.id
            projects.add(project)
        elif node.kind == "module" and node.path:
            modules[node.path] = node.id

    used: dict[str, list[tuple[str, Loc]]] = {}
    direct: dict[str, list[dict[str, str | int]]] = {}
    imported: dict[str, list[Loc]] = {}
    entries = set()
    for path, pf in sorted(index.files.items()):
        if pf.language != "dart":
            continue
        source_project = next((parent.as_posix() for parent in PurePosixPath(path).parents
                        if parent.as_posix() in projects), None)
        if source_project is None:
            continue
        aliases: dict[str, tuple[str, str] | None] = {}
        source_hash = hashlib.sha256(pf.text.encode("utf-8")).hexdigest()
        for match in _IMPORT.finditer(pf.code):
            if not pf.masked[match.start(1):match.end(1)].strip():
                continue
            package_id = packages.get((source_project, match[3]))
            if not package_id:
                continue
            loc = Loc(path, pf.line_of(match.start(1)))
            imported.setdefault(package_id, []).append(loc)
            if path in modules:
                graph.add_edge(modules[path], package_id, "imports", evidence=[loc])
            if match[1] == "import" and match[5] and not match[6].strip():
                alias = match[5]
                aliases[alias] = None if alias in aliases else (package_id, f"package:{match[3]}/{match[4]}")
        reviewed_prefixes = _unambiguous_prefixes(pf.masked, set(aliases)) if aliases else set()
        for symbol in pf.symbols:
            if symbol.kind == "class" or not symbol.has_body:
                continue
            node_id = symbol_node_id(pf, symbol)
            if node_id not in graph.nodes:
                continue
            if symbol.kind == "endpoint" or (symbol.name == "main" and not symbol.container):
                if not {"test", "integration_test", "test_driver"}.intersection(PurePosixPath(path).parts) and not path.endswith("_test.dart"):
                    entries.add(node_id)
            if not aliases:
                continue
            for match in _CALL.finditer(pf.masked, symbol.body_start, symbol.body_end):
                imported_alias = aliases.get(match[1])
                if imported_alias:
                    package_id, library = imported_alias
                    loc = Loc(path, pf.line_of(match.start()))
                    used.setdefault(package_id, []).append((node_id, loc))
                    graph.add_edge(node_id, package_id, "uses", evidence=[loc])
                    if match[1] in reviewed_prefixes and node_id in entries and len(direct.setdefault(package_id, [])) < 128:
                        direct[package_id].append({
                            "library": library, "symbol": match[2], "path": path, "line": loc.line,
                            "source_sha256": source_hash, "entry": node_id,
                        })

    calls: dict[str, list[str]] = {}
    for edge in graph.edges:
        if edge.kind == "calls" and edge.confidence >= 0.8:
            calls.setdefault(edge.src, []).append(edge.dst)
    parents: dict[str, str | None] = dict.fromkeys(entries)
    queue = deque(sorted(entries))
    while queue:
        current = queue.popleft()
        for target in sorted(calls.get(current, ())):
            if target not in parents:
                parents[target] = current
                queue.append(target)

    for finding in findings:
        if finding.source != "trivy" or finding.metadata.get("fixed_in_inventory"):
            continue
        package_id = finding.node_id or ""
        if package_id in direct:
            finding.metadata["direct_symbol_candidates"] = direct[package_id]
        locations = imported.get(package_id, [])
        if not locations:
            continue
        finding.reachability = "potentially_reachable"
        finding.exposure = "unknown"
        finding.evidence.extend(locations[:20])
        for caller, loc in used.get(package_id, ()):
            if caller not in parents:
                continue
            chain = [caller]
            parent = parents[caller]
            while parent is not None:
                chain.append(parent)
                parent = parents[parent]
            chain.reverse()
            entry = graph.nodes[chain[0]]
            finding.reachability = "reachable"
            finding.exposure = (
                "public" if entry.attrs.get("auth") in ("anonymous", "public")
                else "authenticated" if entry.attrs.get("auth") == "required"
                else "internal" if entry.name == "main" else "unknown"
            )
            finding.evidence.append(loc)
            finding.metadata["dependency_path"] = [*chain, package_id]
            finding.metadata["affected_components"] = chain
            break
