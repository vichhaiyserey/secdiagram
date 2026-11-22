"""End-to-end analysis pipeline."""

from __future__ import annotations

import copy
import json
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .advisories import apply_advisories, load_advisories
from .ast_index import index_repo
from .cache import IndexCache
from .discover import RepoInfo, discover
from .external_reports import load_external_reports
from .features import assign_features
from .frameworks import annotate, load_frameworks_config
from .graph_builder import BuildStats, GraphBuilder
from .health import diagnostic
from .iac import analyze_iac
from .java_index import analyze_java_security, build_java_graph, index_java
from .misconfig import analyze_misconfig
from .model import DependencyReachabilitySummary, Finding, Graph, TaintTrace, stable_id
from .polyglot_index import build_polyglot_graph, index_polyglot
from .polyglot_security import analyze_polyglot_security
from .protocols import get_registered_indexers, get_registered_security_providers
from .redaction import redact_secrets
from .resolver import Resolver
from .risk import score_findings
from .sca import build_dependency_reachability, check_package_reachable
from .security import analyze as analyze_security
from .taint_flows import annotate_flows
from .threat_model import build_threat_model, summarize_threat_model

LANGUAGE_BY_SUFFIX = {
    ".py": "python",
    ".pyi": "python",
    ".java": "java",
    ".kt": "kotlin",
    ".groovy": "groovy",
    ".scala": "scala",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".cs": "csharp",
    ".fs": "fsharp",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".rs": "rust",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".hpp": "cpp",
    ".swift": "swift",
}

SECURITY_LANGUAGES = ("csharp", "go", "java", "javascript", "php", "python", "rust", "typescript")


@dataclass(slots=True)
class AnalysisConfig:
    root: Path
    include: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    min_confidence: float = 0.5
    max_nodes: int = 2000
    security: bool = True
    sonarqube_report: Path | None = None
    xray_report: Path | None = None
    advisory_dbs: list[Path] = field(default_factory=list)
    jobs: int = 0
    cache_dir: Path | None = None
    skip_paths: list[Path] = field(default_factory=list)
    max_files: int = 10000
    max_file_bytes: int = 2 * 1024 * 1024
    max_total_bytes: int = 64 * 1024 * 1024
    progress: Callable[[str], None] | None = None


@dataclass(slots=True)
class AnalysisResult:
    repo: RepoInfo
    graph: Graph
    stats: BuildStats
    python_files: int
    parse_errors: list[str] = field(default_factory=list)
    java_files: int = 0
    cache_stats: dict[str, dict[str, int | bool | str]] = field(default_factory=dict)
    dependency_usage: dict[str, DependencyReachabilitySummary] = field(default_factory=dict)

    def has_taint_at(self, file_path: str, line: int | None = None) -> bool:
        """Returns True if any taint trace or finding touches file_path[:line]."""
        return self.graph.has_taint_at(file_path, line)

    def get_taint_traces(self, file_path: str, line: int | None = None) -> list[TaintTrace]:
        """Returns all TaintTrace objects touching file_path[:line]."""
        return self.graph.get_taint_traces(file_path, line)

    def is_reachable(self, file_path: str, symbol: str | None = None) -> bool:
        """Returns True if file_path or symbol is reachable from an exposed entrypoint."""
        return self.graph.is_reachable(file_path, symbol)

    def is_package_reachable(self, package_name: str) -> bool:
        """Returns True if any import from package_name is reachable from an exposed entrypoint."""
        return check_package_reachable(self.dependency_usage, package_name)

    def to_dict(self) -> dict[str, Any]:
        return {
            "repo": {
                "root": str(self.repo.root),
                "name": self.repo.name,
                "rel_files": self.repo.rel_files,
                "is_git": self.repo.is_git,
                "commit": self.repo.commit,
                "branch": self.repo.branch,
                "dirty": self.repo.dirty,
                "skipped": self.repo.skipped,
            },
            "graph": self.graph.to_dict(),
            "stats": {
                "unresolved": self.stats.unresolved,
                "duplicate_modules": self.stats.duplicate_modules,
                "truncated": self.stats.truncated,
                "dropped_nodes": self.stats.dropped_nodes,
            },
            "python_files": self.python_files,
            "parse_errors": self.parse_errors,
            "java_files": self.java_files,
            "cache_stats": self.cache_stats,
            "dependency_usage": {k: v.to_dict() for k, v in self.dependency_usage.items()},
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AnalysisResult:
        repo_data = data.get("repo", {})
        repo = RepoInfo(
            root=Path(repo_data.get("root", ".")),
            name=str(repo_data.get("name", "repo")),
            rel_files=list(repo_data.get("rel_files", [])),
            is_git=bool(repo_data.get("is_git", False)),
            commit=repo_data.get("commit"),
            branch=repo_data.get("branch"),
            dirty=bool(repo_data.get("dirty", False)),
            skipped=list(repo_data.get("skipped", [])),
        )
        graph = Graph.from_dict(data.get("graph", {}))
        stats_data = data.get("stats", {})
        stats = BuildStats(
            unresolved=list(stats_data.get("unresolved", [])),
            duplicate_modules=dict(stats_data.get("duplicate_modules", {})),
            truncated=bool(stats_data.get("truncated", False)),
            dropped_nodes=int(stats_data.get("dropped_nodes", 0)),
        )
        dep_usage = {
            k: DependencyReachabilitySummary.from_dict(v)
            for k, v in data.get("dependency_usage", {}).items()
        }
        return cls(
            repo=repo,
            graph=graph,
            stats=stats,
            python_files=int(data.get("python_files", 0)),
            parse_errors=list(data.get("parse_errors", [])),
            java_files=int(data.get("java_files", 0)),
            cache_stats=dict(data.get("cache_stats", {})),
            dependency_usage=dep_usage,
        )

    def to_json(self, path: str | Path | None = None) -> str:
        """Serialize AnalysisResult to JSON string and optionally write to path atomically."""
        serialized = json.dumps(self.to_dict(), indent=2, sort_keys=False) + "\n"
        if path is not None:
            out_path = Path(path)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            temp_path = out_path.with_suffix(f"{out_path.suffix}.tmp.{os.getpid()}")
            temp_path.write_text(serialized, encoding="utf-8")
            temp_path.replace(out_path)
        return serialized

    @classmethod
    def from_json(cls, source: str | Path) -> AnalysisResult:
        """Load AnalysisResult from a JSON file path or a JSON string."""
        source_path = Path(source) if not isinstance(source, Path) else source
        try:
            if source_path.is_file():
                content = source_path.read_text(encoding="utf-8")
                data = json.loads(content)
                return cls.from_dict(data)
        except OSError:
            pass
        if isinstance(source, str):
            data = json.loads(source)
            return cls.from_dict(data)
        raise ValueError(f"Could not load AnalysisResult from source: {source}")


def _plugin_error(kind: str, name: str, exc: BaseException, root: Path) -> dict[str, str]:
    """Return a deterministic, redacted record of a plugin failure."""
    message = redact_secrets(str(exc)).replace(str(root), ".")
    return {"kind": kind, "plugin": str(name), "error": f"{type(exc).__name__}: {message[:300]}"}


def _finding_identity(finding: Finding) -> tuple[str, ...]:
    evidence = tuple(f"{loc.path}:{loc.line}" for loc in finding.evidence)
    return (finding.node_id or "", finding.title, *evidence)


def _disambiguate_plugin_findings(
    provider_name: str, new: list[Finding], existing: list[Finding]
) -> list[Finding]:
    """Give colliding plugin findings unique, deterministic ids.

    Built-in findings are deduplicated by id, so a plugin that reuses one id
    for several distinct findings (e.g. one rule id per match) would silently
    lose all but the first. A finding whose id is already taken by a finding
    with a different identity gets ``stable_id(provider, id, identity...)``;
    the original id is kept in ``metadata["rule_id"]``.
    """
    seen: dict[str, tuple[str, ...]] = {item.id: _finding_identity(item) for item in existing}
    out: list[Finding] = []
    for finding in new:
        identity = _finding_identity(finding)
        prior = seen.get(finding.id)
        if prior is not None and prior != identity:
            finding.metadata.setdefault("rule_id", finding.id)
            finding.id = stable_id(str(provider_name), finding.id, *identity)
        seen.setdefault(finding.id, identity)
        out.append(finding)
    return out


def run_analysis(config: AnalysisConfig) -> AnalysisResult:
    def stage(name: str) -> None:
        if config.progress is not None:
            config.progress(name)

    stage("discovery")
    load_frameworks_config(config.root)
    repo = discover(
        config.root,
        config.include,
        config.exclude,
        skip_paths=config.skip_paths + ([config.cache_dir] if config.cache_dir is not None else []),
        max_files=config.max_files,
        max_file_bytes=config.max_file_bytes,
        max_total_bytes=config.max_total_bytes,
    )
    stage("parsing")
    python_cache = IndexCache(config.cache_dir, "python", repo.commit) if config.cache_dir else None
    java_cache = IndexCache(config.cache_dir, "java", repo.commit) if config.cache_dir else None
    indexes = index_repo(repo.root, repo.python_files, jobs=config.jobs, cache=python_cache)
    annotate(indexes)

    java_index = index_java(repo.root, repo.rel_files, jobs=config.jobs, cache=java_cache)
    polyglot_index = index_polyglot(repo.root, repo.rel_files)

    stage("mapping")
    resolver = Resolver(indexes)
    builder = GraphBuilder(indexes, resolver, max_nodes=config.max_nodes)
    graph = builder.build()

    if java_index.files:
        build_java_graph(graph, java_index)

    if polyglot_index.files:
        build_polyglot_graph(graph, polyglot_index)

    plugin_errors: list[dict[str, str]] = []
    for custom_indexer in sorted(get_registered_indexers(), key=lambda item: str(item.name)):
        snapshot = (copy.deepcopy(graph.nodes), list(graph.edges), list(graph.features))
        try:
            custom_indexer.index_repo(repo.root, repo.rel_files, graph)
        except Exception as exc:  # plugin code is untrusted to be well-behaved
            # Roll back partial changes so a failing indexer cannot leave a
            # half-built graph behind, and record the failure loudly.
            graph.nodes, graph.edges, graph.features = snapshot
            plugin_errors.append(_plugin_error("indexer", custom_indexer.name, exc, repo.root))

    stage("threat analysis")
    findings: list[Finding] = []
    if config.security:
        findings.extend(analyze_iac(graph, repo))
        findings.extend(analyze_security(graph, indexes, resolver, repo.root, repo.rel_files))
        if java_index.files:
            findings.extend(analyze_java_security(graph, java_index, repo.root, repo.name))
        if polyglot_index.files:
            findings.extend(analyze_polyglot_security(graph, polyglot_index))
        findings.extend(analyze_misconfig(graph, repo.root, repo.rel_files))
        for custom_provider in sorted(get_registered_security_providers(), key=lambda item: str(item.name)):
            try:
                provider_findings = list(custom_provider.analyze(graph, repo.root, repo.rel_files))
            except Exception as exc:  # a crashed provider must not look like a clean scan
                plugin_errors.append(_plugin_error("security_provider", custom_provider.name, exc, repo.root))
                continue
            findings.extend(_disambiguate_plugin_findings(custom_provider.name, provider_findings, findings))
        external, external_summaries = load_external_reports(
            repo.root,
            repo.rel_files,
            config.sonarqube_report,
            config.xray_report,
        )
        findings.extend(external)
        if external_summaries:
            graph.meta["external_reports"] = external_summaries
    merged: dict[str, Finding] = {}
    for finding in findings:
        merged.setdefault(finding.id, finding)
    graph.findings = list(merged.values())
    if plugin_errors:
        graph.meta["plugin_errors"] = plugin_errors
    annotate_flows(graph)
    if config.advisory_dbs:
        advisory_index, advisory_summaries = load_advisories(config.advisory_dbs)
        validated = apply_advisories(graph.findings, advisory_index)
        graph.meta["advisory_sources"] = advisory_summaries
        graph.meta["advisory_validated_findings"] = validated
    # Rank by risk last, once flows and exploit intelligence (KEV) are known.
    score_findings(graph)
    summarize_threat_model(graph, build_threat_model(graph))
    graph.edges = [
        edge
        for edge in graph.edges
        if edge.confidence >= config.min_confidence or edge.kind in {"contains", "imports"}
    ]
    assign_features(graph)

    parse_errors = sorted(path for path, index in indexes.items() if index.error)
    diagnostics = [
        diagnostic("parse_error", path, indexes[path].error or "Cannot parse source",
                   "Check syntax and the running Python version; use --exclude to omit this file.")
        for path in parse_errors
    ]
    for module, paths in sorted(builder.stats.duplicate_modules.items()):
        diagnostics.append(diagnostic(
            "ambiguous_layout", ", ".join(sorted(paths)), f"Multiple files resolve to module {module}",
            "Analyze each project with --dir or narrow the scan using --include/--exclude.",
        ))
    for path in sorted(repo.skipped):
        if not path.startswith(("path filter:", "ignored directory:")):
            diagnostics.append(diagnostic("skipped_path", path, "Path was not analyzed", "Review the skip reason and adjust permissions or scan limits."))
    languages: dict[str, int] = {}
    for rel in repo.rel_files:
        name = rel.rsplit("/", 1)[-1]
        if "." not in name:
            continue
        suffix = "." + name.rsplit(".", 1)[-1].lower()
        language = LANGUAGE_BY_SUFFIX.get(suffix)
        if language:
            languages[language] = languages.get(language, 0) + 1
    languages = dict(sorted(languages.items()))
    parsed_paths = {path for path, index in indexes.items() if not index.error}
    parsed_paths.update(java_index.files)
    parsed_paths.update(polyglot_index.files)
    for rel in repo.rel_files:
        language = LANGUAGE_BY_SUFFIX.get(Path(rel).suffix.lower())
        if language and rel not in parsed_paths and rel not in parse_errors:
            diagnostics.append(diagnostic(
                "not_parsed", rel, f"No architecture index produced for {language} source",
                "Built-in indexers cover Python, Java, C#, JavaScript/TypeScript, PHP and Go; check file size and syntax or supply an indexer plugin.",
            ))
    if not parsed_paths:
        diagnostics.append(diagnostic("empty_project", ".", "No supported source files were parsed",
                                      "Check --dir and path filters; use --workspace for a directory containing separate repositories."))
    unsupported_languages = sorted(
        language for language in languages if language not in SECURITY_LANGUAGES
    )
    config_hash = stable_id(
        "config",
        ",".join(sorted(config.include)),
        ",".join(sorted(config.exclude)),
        str(config.min_confidence),
        str(config.max_nodes),
        str(config.security),
        str(config.max_files),
        str(config.max_file_bytes),
        str(config.max_total_bytes),
    )
    graph.meta.update(
        {
            "name": repo.name,
            "commit": repo.commit,
            "branch": repo.branch,
            "dirty": repo.dirty,
            "is_git": repo.is_git,
            "python_files": len(indexes),
            "java_files": len(java_index.files),
            "polyglot_files": polyglot_index.language_counts(),
            "iac_files": len(repo.iac_files),
            "files_discovered": len(repo.rel_files),
            "files_parsed": len(parsed_paths),
            "diagnostics": sorted(diagnostics, key=lambda item: (item["path"], item["code"])),
            "files_skipped": len(repo.skipped),
            "skipped_samples": sorted(repo.skipped)[:20],
            "languages": languages,
            "security_languages": list(SECURITY_LANGUAGES),
            "unsupported_security_languages": unsupported_languages,
            "config_hash": config_hash,
            "security_enabled": config.security,
            "include": sorted(config.include),
            "exclude": sorted(config.exclude),
            "min_confidence": config.min_confidence,
            "analysis": {
                "unresolved_count": graph.meta.get("unresolved_count", 0),
                "truncated": graph.meta.get("truncated", False),
                "dropped_nodes": graph.meta.get("dropped_nodes", 0),
                "parse_errors": parse_errors,
            },
        }
    )
    cache_stats: dict[str, dict[str, int | bool | str]] = {}
    if python_cache is not None:
        cache_stats["python"] = python_cache.summary()
    if java_cache is not None:
        cache_stats["java"] = java_cache.summary()

    dependency_usage = build_dependency_reachability(graph, indexes, java_index)

    return AnalysisResult(
        repo=repo,
        graph=graph,
        stats=builder.stats,
        python_files=len(indexes),
        parse_errors=parse_errors,
        java_files=len(java_index.files),
        cache_stats=cache_stats,
        dependency_usage=dependency_usage,
    )


def analyze(
    root: str | Path | None = None,
    *,
    config: AnalysisConfig | None = None,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
    min_confidence: float = 0.5,
    max_nodes: int = 2000,
    security: bool = True,
    sonarqube_report: Path | None = None,
    xray_report: Path | None = None,
    advisory_dbs: list[Path] | None = None,
    jobs: int = 0,
    cache_dir: Path | None = None,
    **kwargs: Any,
) -> AnalysisResult:
    """High-level analysis facade over run_analysis."""
    if config is not None:
        return run_analysis(config)
    if root is None:
        raise ValueError("Either 'root' or 'config' must be provided to analyze().")
    cfg = AnalysisConfig(
        root=Path(root),
        include=include or [],
        exclude=exclude or [],
        min_confidence=min_confidence,
        max_nodes=max_nodes,
        security=security,
        sonarqube_report=sonarqube_report,
        xray_report=xray_report,
        advisory_dbs=advisory_dbs or [],
        jobs=jobs,
        cache_dir=cache_dir,
    )
    return run_analysis(cfg)


@dataclass(slots=True)
class WorkspaceAnalysisResult:
    """Result of analyzing an entire multi-repo workspace."""

    workspace: Any  # workspace.Workspace (lazy to avoid circular import)
    per_repo: dict[str, AnalysisResult]
    merged_graph: Graph
    repo_roles: dict[str, Any]  # workspace.RepoRole

    def to_dict(self) -> dict[str, Any]:
        return {
            "workspace": self.workspace.to_dict(),
            "per_repo": {name: result.to_dict() for name, result in sorted(self.per_repo.items())},
            "merged_graph": self.merged_graph.to_dict(),
        }


def run_workspace_analysis(
    workspace_root: str | Path,
    *,
    repo_paths: list[str | Path] | None = None,
    manual_roles: dict[str, str] | None = None,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
    min_confidence: float = 0.5,
    max_nodes: int = 2000,
    security: bool = True,
    jobs: int = 0,
    cache_dir: Path | None = None,
) -> WorkspaceAnalysisResult:
    """Analyze multiple repos as a unified workspace.

    1. Discovers repos and assigns roles (auto or manual).
    2. Runs ``run_analysis`` on each repo individually.
    3. Detects cross-repo relationships.
    4. Merges all graphs into a single unified graph.
    """
    from .workspace import discover_workspace, merge_graphs

    ws = discover_workspace(
        workspace_root,
        repo_paths=repo_paths,
        manual_roles=manual_roles,
        include=include,
        exclude=exclude,
    )

    per_repo: dict[str, AnalysisResult] = {}
    repo_graphs: dict[str, Graph] = {}
    repo_roles_map: dict[str, Any] = {}

    for repo_role in sorted(ws.repos, key=lambda r: r.name):
        repo_roles_map[repo_role.name] = repo_role
        try:
            result = run_analysis(AnalysisConfig(
                root=repo_role.path,
                include=include or [],
                exclude=exclude or [],
                min_confidence=min_confidence,
                max_nodes=max_nodes,
                security=security,
                jobs=jobs,
                cache_dir=Path(str(cache_dir) + f"/{repo_role.name}") if cache_dir else None,
            ))
            per_repo[repo_role.name] = result
            repo_graphs[repo_role.name] = result.graph
        except Exception:
            # Skip repos that fail analysis (e.g. empty dirs)
            continue

    merged = merge_graphs(repo_graphs, repo_roles_map, ws.inter_repo_edges)
    merged.meta["workspace"] = ws.to_dict()
    merged.meta["name"] = ws.name
    merged.meta["workspace_mode"] = True

    return WorkspaceAnalysisResult(
        workspace=ws,
        per_repo=per_repo,
        merged_graph=merged,
        repo_roles=repo_roles_map,
    )


def __getattr__(name: str) -> Any:
    """Backward compatibility shims for downstream tools importing across modules."""
    if name in {"build_high_level_architecture", "render_mermaid_highlevel", "HighLevelArchitecture", "Subsystem", "SubsystemConnection"}:
        from . import high_level as hl
        return getattr(hl, name)
    if name == "render_mermaid":
        from .render_mermaid import render_mermaid as rm
        return rm
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
