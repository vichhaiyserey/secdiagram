"""Bounded lexical Cargo inventory shared by architecture and workspace scans.

This is not a TOML evaluator or Cargo resolver. It recognizes package names,
runtime dependency keys/tables, renamed packages and explicit database features.
It never resolves workspace inheritance, downloads crates or runs build scripts.
"""

from __future__ import annotations

import re

_TOKENS = re.compile(r'''"{3}[\s\S]*?(?:"{3}|$)|'{3}[\s\S]*?(?:'{3}|$)|"(?:\\.|[^"\\])*"|'[^']*'|\#[^\n]*''')
_STRING = re.compile(r'''["']([^"']*)["']''')
_KEY = r'''(?:[A-Za-z0-9_-]+|"[^"\n]+"|'[^'\n]+')'''
_ASSIGN = re.compile(rf"^\s*({_KEY})\s*=\s*(.*)$")
_DATA_FEATURES = frozenset({"postgres", "mysql", "sqlite"})


def cargo_inventory(text: str) -> tuple[str | None, set[str], bool]:
    """Return package name, runtime dependency markers, and package-table presence."""
    def hide_non_inventory(match: re.Match[str]) -> str:
        value = match.group()
        if value.startswith(("#", '"""', "'''")):
            return "".join("\n" if ch == "\n" else " " for ch in value)
        return value

    text = _TOKENS.sub(hide_non_inventory, text)
    name: str | None = None
    dependencies: set[str] = set()
    section = ""
    package = False
    dependency_table = False
    dependency = ""
    features = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("[") and line.endswith("]") and not line.startswith("[["):
            section = line[1:-1].strip()
            package |= section == "package"
            # Development/build dependencies are intentionally excluded.
            match = re.fullmatch(
                r'''(?:workspace\.|target\.(?:"(?:\\.|[^"\\])*"|'[^']*'|[A-Za-z0-9_-]+)\.)?dependencies(?:\.(.+))?''',
                section,
            )
            dependency_table = match is not None and match.group(1) is None
            dependency = match.group(1).strip("\"'") if match and match.group(1) else ""
            if dependency:
                dependencies.add(dependency)
            features = False
            continue
        assignment = _ASSIGN.match(line)
        if assignment is None:
            if features:
                dependencies.update(_DATA_FEATURES.intersection(_STRING.findall(line)))
                features = "]" not in line
            continue
        key, value = assignment.groups()
        key = key.strip("\"'")
        if section == "package" and key == "name":
            match = _STRING.fullmatch(value.strip())
            if match:
                name = match.group(1)
        elif dependency_table:
            dependencies.add(key)
            alias = re.search(r'''\bpackage\s*=\s*["']([^"']+)["']''', value)
            if alias:
                dependencies.add(alias.group(1))
            feature_list = re.search(r"\bfeatures\s*=\s*\[([^\]]*)", value)
            if feature_list:
                dependencies.update(_DATA_FEATURES.intersection(_STRING.findall(feature_list.group(1))))
                features = "]" not in value[feature_list.start():]
        elif dependency:
            if key == "package":
                match = _STRING.fullmatch(value.strip())
                if match:
                    dependencies.add(match.group(1))
            elif key == "features":
                dependencies.update(_DATA_FEATURES.intersection(_STRING.findall(value)))
                features = "]" not in value
    return name, dependencies, package
