"""Deterministic JSON serialisation of the graph."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .dependency_remediation import dependency_details
from .model import Graph


def _payload(graph: Graph) -> dict[str, Any]:
    payload = graph.to_dict()
    details = {
        finding.id: row for finding in graph.findings if (row := dependency_details(finding))
    }
    for finding in payload["findings"]:
        if finding["id"] in details:
            finding["dependency"] = details[finding["id"]]
    return payload


def render_json(graph: Graph) -> str:
    return json.dumps(_payload(graph), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def write_json(graph: Graph, path: Path) -> None:
    """Stream the graph JSON to disk without materialising the full string."""
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(_payload(graph), handle, indent=2, sort_keys=True, ensure_ascii=False)
        handle.write("\n")
