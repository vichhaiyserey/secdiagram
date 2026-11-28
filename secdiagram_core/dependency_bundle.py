"""Validate local evidence manifests and pass verified bytes directly to ingestion."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import date
from pathlib import Path, PureWindowsPath
from typing import Any

from .dependency_inventory import read_input, read_json

KINDS = ("trivy", "cyclonedx", "advisory", "review")


def load_bundle(
    manifest: Path, *, as_of: date | None = None, max_age: int = 7,
    analysis_root: Path | None = None,
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    root = manifest.absolute().parent.resolve()
    data = read_json(manifest, root)
    if type(data.get("version")) is not int or data["version"] != 1:
        raise ValueError("unsupported evidence bundle version")
    try:
        snapshot = date.fromisoformat(data["snapshot_date"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("expected an ISO snapshot_date") from exc
    if snapshot.isoformat() != data["snapshot_date"]:
        raise ValueError("expected snapshot_date in YYYY-MM-DD form")
    records = data.get("reports")
    if not isinstance(records, dict) or not (set(records) & {"trivy", "cyclonedx"}) or set(records) - set(KINDS):
        raise ValueError("bundle reports must contain trivy and/or cyclonedx")
    reports: dict[str, dict[str, Any]] = {}
    hashes = {}
    for kind, record in sorted(records.items()):
        if not isinstance(record, dict):
            raise ValueError(f"invalid {kind} report descriptor")
        name, checksum = record.get("path"), record.get("sha256")
        if (
            not isinstance(name, str) or not name or Path(name).is_absolute()
            or PureWindowsPath(name).drive or "\\" in name or ":" in name
            or ".." in name.split("/") or "\x00" in name
        ):
            raise ValueError(f"invalid {kind} report path")
        if not isinstance(checksum, str) or not re.fullmatch(r"[0-9a-f]{64}", checksum):
            raise ValueError(f"invalid {kind} SHA-256")
        content = read_input(root / name, root)
        if hashlib.sha256(content.encode("utf-8")).hexdigest() != checksum:
            raise ValueError(f"{kind} report checksum mismatch")
        value = json.loads(content)
        if not isinstance(value, dict):
            raise ValueError(f"invalid {kind} report object")
        if kind in {"advisory", "review"}:
            pass
        elif value.get("bomFormat") == "CycloneDX":
            for key in ("components", "dependencies", "vulnerabilities"):
                if key in value and not isinstance(value[key], list):
                    raise ValueError(f"invalid CycloneDX {key}")
        elif kind != "trivy" or not isinstance(value.get("Results"), list):
            raise ValueError(f"invalid {kind} document")
        elif any(
            not isinstance(target, dict)
            or ("Vulnerabilities" in target and target["Vulnerabilities"] is not None
                and not isinstance(target["Vulnerabilities"], list))
            for target in value["Results"]
        ):
            raise ValueError("invalid Trivy results")
        reports[kind] = value
        hashes[kind] = checksum
    binding = data.get("repository")
    bound_lockfiles: dict[str, str] = {}
    revision = ""
    if binding is not None:
        if not isinstance(binding, dict) or analysis_root is None:
            raise ValueError("repository binding requires an analysis root")
        revision_value = binding.get("revision")
        lockfiles = binding.get("lockfiles")
        if not isinstance(revision_value, str) or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", revision_value):
            raise ValueError("invalid repository revision")
        if not isinstance(lockfiles, dict) or not lockfiles or len(lockfiles) > 256:
            raise ValueError("invalid repository lockfile descriptors")
        revision = revision_value
        analysis_root = analysis_root.resolve()
        for name, checksum in sorted(lockfiles.items()):
            if (
                not name or Path(name).is_absolute() or PureWindowsPath(name).drive
                or "\\" in name or ":" in name or ".." in name.split("/") or "\x00" in name
                or Path(name).name != "pubspec.lock"
                or not isinstance(checksum, str) or not re.fullmatch(r"[0-9a-f]{64}", checksum)
            ):
                raise ValueError("invalid Pub lockfile binding")
            content = read_input(analysis_root / name, analysis_root)
            if hashlib.sha256(content.encode("utf-8")).hexdigest() != checksum:
                raise ValueError("Pub lockfile checksum mismatch")
            bound_lockfiles[name] = checksum
    age = (as_of - snapshot).days if as_of else None
    freshness = (
        "unchecked" if age is None else "future" if age < 0
        else "stale" if age > max_age else "current"
    )
    status: dict[str, Any] = {"snapshot_date": snapshot.isoformat(), "freshness": freshness, "sha256": hashes}
    if revision:
        status.update({"revision": revision, "lockfiles": bound_lockfiles})
    return reports, status
