"""Deterministic analysis coverage and actionable diagnostics (stdlib only)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .analyzer import AnalysisResult


def diagnostic(code: str, path: str, message: str, hint: str) -> dict[str, str]:
    return {"code": code, "path": path, "message": message, "hint": hint}


def health_summary(result: AnalysisResult) -> dict[str, Any]:
    graph = result.graph
    return {
        "files_discovered": len(result.repo.rel_files),
        "files_parsed": graph.meta.get("files_parsed", 0),
        "languages": graph.meta.get("languages", {}),
        "components_identified": len(graph.nodes),
        "unresolved_references": len(result.stats.unresolved),
        "skipped_paths": sorted(result.repo.skipped),
        "parse_errors": sorted(result.parse_errors),
        "graph_truncated": result.stats.truncated,
        "complete": not result.parse_errors and not result.stats.truncated and not graph.meta.get("diagnostics"),
        "diagnostics": graph.meta.get("diagnostics", []),
    }
