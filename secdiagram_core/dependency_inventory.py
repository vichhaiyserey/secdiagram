"""Bounded, offline Pub inventory. Package configuration URIs are evidence only."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .model import Loc
from .yaml_lite import parse_yaml

MAX_INPUT = 16 * 1024 * 1024


@dataclass(slots=True)
class Dependency:
    name: str
    project: str
    scope: str
    evidence: list[Loc] = field(default_factory=list)
    version: str = ""
    constraint: str = ""
    source: str = ""
    configuration: dict[str, str] = field(default_factory=dict)


def read_input(path: Path, root: Path | None = None) -> str:
    resolved = path.resolve()
    if root is not None and not resolved.is_relative_to(root):
        raise ValueError("input escapes analysis root")
    if not resolved.is_file():
        raise ValueError("input is not a regular file")
    with resolved.open("rb") as stream:
        payload = stream.read(MAX_INPUT + 1)
    if len(payload) > MAX_INPUT:
        raise ValueError("input exceeds size limit")
    return payload.decode("utf-8")


def read_json(path: Path, root: Path | None = None) -> dict[str, Any]:
    value = json.loads(read_input(path, root))
    if not isinstance(value, dict):
        raise ValueError("expected JSON object")
    return value


def pub_inventory(root: Path, paths: list[str]) -> tuple[list[Dependency], list[str]]:
    root = root.resolve()
    inventory: list[Dependency] = []
    warnings = []
    for manifest in sorted(path for path in paths if Path(path).name == "pubspec.yaml"):
        parent = Path(manifest).parent
        project = parent.as_posix()
        packages: dict[str, Dependency] = {}
        for filename in ("pubspec.yaml", "pubspec.lock"):
            relative = parent / filename
            path = root / relative
            if filename == "pubspec.lock" and not path.exists():
                continue
            try:
                documents = parse_yaml(read_input(path, root))
            except (OSError, ValueError, RuntimeError):
                warnings.append(relative.as_posix())
                continue
            for section in (child for document in documents for child in document.children):
                scope = {
                    "dependencies": "direct", "dev_dependencies": "dev",
                    "dependency_overrides": "override", "packages": "transitive",
                }.get(section.key or "")
                if scope is None or (scope == "transitive") != (filename == "pubspec.lock"):
                    continue
                for entry in section.children:
                    if not entry.key:
                        continue
                    package = packages.setdefault(entry.key, Dependency(entry.key, project, scope))
                    package.evidence.append(Loc(relative.as_posix(), entry.line))
                    if scope == "transitive":
                        version = entry.child("version")
                        source = entry.child("source")
                        classification = entry.child("dependency")
                        if version:
                            package.version = version.value or ""
                        if source:
                            package.source = source.value or ""
                        if classification and package.scope != "override":
                            package.scope = {
                                "direct main": "direct", "direct dev": "dev",
                                "direct overridden": "override",
                            }.get(classification.value or "", package.scope)
                    else:
                        package.scope = scope
                        package.constraint = entry.value or ""
                        package.source = next(
                            (child.key for child in entry.children if child.key in {"sdk", "git", "path", "hosted"}),
                            "",
                        ) or ""
        relative = parent / ".dart_tool/package_config.json"
        if (root / relative).exists():
            try:
                records = read_json(root / relative, root).get("packages")
                if not isinstance(records, list):
                    raise ValueError("invalid package configuration")
                for record in records:
                    if not isinstance(record, dict) or not isinstance(record.get("name"), str):
                        warnings.append(relative.as_posix())
                        continue
                    configured = packages.get(record["name"])
                    if configured:
                        configured.configuration = {
                            key: record[key] for key in ("packageUri", "languageVersion")
                            if isinstance(record.get(key), str)
                        }
            except (OSError, ValueError, RuntimeError):
                warnings.append(relative.as_posix())
        inventory.extend(packages[name] for name in sorted(packages))
    return inventory, sorted(set(warnings))
