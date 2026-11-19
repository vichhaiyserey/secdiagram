"""Interactive diagram overrides for the secdiagram Studio.

Overrides are intentionally tiny and deterministic: they rename or hide graph
nodes and optionally set the Mermaid direction/theme.  The source graph is
never mutated, so the same analysis can be rendered with or without edits.
"""

from __future__ import annotations

import copy
import json
import os
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .model import Graph

OVERRIDES_SCHEMA_VERSION = 1
OVERRIDES_RELPATH = Path(".secdiagram") / "studio" / "diagram-overrides.json"
MAX_OVERRIDES_BYTES = 1_048_576
MAX_ENTRIES = 5000
MAX_ID_LEN = 200
MAX_LABEL_LEN = 120

_ALLOWED_DIRECTIONS = frozenset({"LR", "RL", "TB", "TD", "BT"})
_ALLOWED_THEMES = frozenset({"modern", "classic"})
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


class DiagramOverrideError(ValueError):
    """Raised when override data is malformed or unsafe."""


@dataclass(slots=True)
class DiagramOverrides:
    schema_version: int = OVERRIDES_SCHEMA_VERSION
    renames: dict[str, str] = field(default_factory=dict)
    hidden: list[str] = field(default_factory=list)
    direction: str | None = None
    theme: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "renames": {key: self.renames[key] for key in sorted(self.renames)},
            "hidden": sorted(set(self.hidden)),
            "direction": self.direction,
            "theme": self.theme,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DiagramOverrides:
        if not isinstance(data, dict):
            raise DiagramOverrideError("overrides must be a JSON object")
        allowed = {"schema_version", "renames", "hidden", "direction", "theme"}
        unknown = sorted(set(data) - allowed)
        if unknown:
            raise DiagramOverrideError(f"unknown override field(s): {', '.join(unknown)}")
        schema = data.get("schema_version", OVERRIDES_SCHEMA_VERSION)
        if schema != OVERRIDES_SCHEMA_VERSION:
            raise DiagramOverrideError(f"unsupported overrides schema_version: {schema!r}")

        raw_renames = data.get("renames", {})
        if not isinstance(raw_renames, dict):
            raise DiagramOverrideError("renames must be an object")
        renames: dict[str, str] = {}
        for node_id, label in raw_renames.items():
            key = _clean_identifier(node_id, "node id")
            renames[key] = _clean_label(label)
        if len(renames) > MAX_ENTRIES:
            raise DiagramOverrideError(f"too many renames (limit {MAX_ENTRIES})")

        raw_hidden = data.get("hidden", [])
        if not isinstance(raw_hidden, list):
            raise DiagramOverrideError("hidden must be a list")
        hidden: list[str] = []
        for item in raw_hidden:
            key = _clean_identifier(item, "hidden node id")
            if key not in hidden:
                hidden.append(key)
        if len(hidden) > MAX_ENTRIES:
            raise DiagramOverrideError(f"too many hidden nodes (limit {MAX_ENTRIES})")

        direction = data.get("direction")
        if direction is not None:
            if not isinstance(direction, str) or direction.upper() not in _ALLOWED_DIRECTIONS:
                raise DiagramOverrideError(
                    "direction must be one of " + ", ".join(sorted(_ALLOWED_DIRECTIONS))
                )
            direction = direction.upper()

        theme = data.get("theme")
        if theme is not None:
            if not isinstance(theme, str) or theme.lower() not in _ALLOWED_THEMES:
                raise DiagramOverrideError("theme must be one of " + ", ".join(sorted(_ALLOWED_THEMES)))
            theme = theme.lower()

        return cls(
            schema_version=OVERRIDES_SCHEMA_VERSION,
            renames=renames,
            hidden=sorted(hidden),
            direction=direction,
            theme=theme,
        )

    @property
    def has_changes(self) -> bool:
        return bool(self.renames or self.hidden or self.direction or self.theme)


def _clean_identifier(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise DiagramOverrideError(f"{label} must be a string")
    cleaned = value.strip()
    if not cleaned:
        raise DiagramOverrideError(f"{label} must be non-empty")
    if len(cleaned) > MAX_ID_LEN:
        raise DiagramOverrideError(f"{label} exceeds {MAX_ID_LEN} characters")
    if _CONTROL_RE.search(cleaned):
        raise DiagramOverrideError(f"{label} contains control characters")
    return cleaned


def _clean_label(value: Any) -> str:
    if not isinstance(value, str):
        raise DiagramOverrideError("rename label must be a string")
    cleaned = " ".join(value.split())
    if not cleaned:
        raise DiagramOverrideError("rename label must be non-empty")
    if len(cleaned) > MAX_LABEL_LEN:
        cleaned = cleaned[:MAX_LABEL_LEN]
    if _CONTROL_RE.search(cleaned):
        raise DiagramOverrideError("rename label contains control characters")
    return cleaned


def overrides_path(root: str | Path) -> Path:
    return Path(root) / OVERRIDES_RELPATH


def load_overrides(root: str | Path) -> DiagramOverrides:
    """Load overrides, returning an empty set when no file exists."""
    path = overrides_path(root)
    if not path.exists():
        return DiagramOverrides()
    if not path.is_file():
        raise DiagramOverrideError("diagram overrides path is not a file")
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise DiagramOverrideError(f"cannot stat diagram overrides: {exc}") from exc
    if size > MAX_OVERRIDES_BYTES:
        raise DiagramOverrideError(f"diagram overrides exceed {MAX_OVERRIDES_BYTES} bytes")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DiagramOverrideError(f"cannot read diagram overrides: {exc}") from exc
    return DiagramOverrides.from_dict(data)


def save_overrides(root: str | Path, overrides: DiagramOverrides) -> Path:
    """Validate and atomically persist overrides with deterministic formatting."""
    payload = overrides.to_dict()
    # Round-trip validation keeps direct constructors honest.
    validated = DiagramOverrides.from_dict(payload)
    content = json.dumps(validated.to_dict(), indent=2, sort_keys=True) + "\n"
    if len(content.encode("utf-8")) > MAX_OVERRIDES_BYTES:
        raise DiagramOverrideError(f"diagram overrides exceed {MAX_OVERRIDES_BYTES} bytes")
    path = overrides_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    return path


def clear_overrides(root: str | Path) -> bool:
    """Delete persisted overrides; return True when a file was removed."""
    path = overrides_path(root)
    try:
        path.unlink()
        return True
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise DiagramOverrideError(f"cannot remove diagram overrides: {exc}") from exc


def apply_overrides(graph: Graph, overrides: DiagramOverrides) -> Graph:
    """Return a deep copy of *graph* with deterministic edits applied."""
    edited = copy.deepcopy(graph)
    if not overrides.has_changes:
        return edited

    hidden = set(overrides.hidden)
    if hidden:
        for node_id in hidden:
            edited.nodes.pop(node_id, None)
        edited.edges = [edge for edge in edited.edges if edge.src not in hidden and edge.dst not in hidden]
        for feature in edited.features:
            feature.nodes = [node_id for node_id in feature.nodes if node_id not in hidden]

    for node_id, label in overrides.renames.items():
        node = edited.nodes.get(node_id)
        if node is not None:
            node.name = label

    return edited


def summarize_overrides(overrides: DiagramOverrides, graph: Graph | None = None) -> dict[str, Any]:
    """Return a small, deterministic summary for UI and API callers."""
    known_renames = 0
    known_hidden = 0
    if graph is not None:
        known_renames = sum(1 for node_id in overrides.renames if node_id in graph.nodes)
        known_hidden = sum(1 for node_id in overrides.hidden if node_id in graph.nodes)
    return {
        "schema_version": overrides.schema_version,
        "renames": len(overrides.renames),
        "hidden": len(overrides.hidden),
        "direction": overrides.direction,
        "theme": overrides.theme,
        "has_changes": overrides.has_changes,
        "matched_renames": known_renames,
        "matched_hidden": known_hidden,
    }
