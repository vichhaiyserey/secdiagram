"""Conservative Pub affected-range evaluation for local OSV records."""

import re
from typing import Any

from .dependency_reports import dedupe_findings
from .model import Finding, stable_id

_VERSION = re.compile(
    r"(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
Version = tuple[int, int, int, bool, tuple[tuple[int, int | str], ...]]


def parse_version(value: Any) -> Version | None:
    if not isinstance(value, str) or len(value) > 256 or not (match := _VERSION.fullmatch(value)):
        return None
    prerelease: list[tuple[int, int | str]] = []
    if raw := match[4]:
        for item in raw.split("."):
            if item.isdecimal():
                if len(item) > 1 and item.startswith("0"):
                    return None
                prerelease.append((0, int(item)))
            else:
                prerelease.append((1, item))
    return (int(match[1]), int(match[2]), int(match[3]), not prerelease, tuple(prerelease))


def evaluate_range(value: str, events: Any) -> str:
    """Return affected, fixed, outside or unknown for a validated SEMVER range."""
    version = parse_version(value)
    if version is None or not isinstance(events, list) or not events or len(events) > 1000:
        return "unknown"
    active = False
    lower: Version | None = None
    previous: Version | None = None
    affected = False
    fixed = False
    for event in events:
        if not isinstance(event, dict) or len(event) != 1:
            return "unknown"
        kind, boundary = next(iter(event.items()))
        if kind == "introduced":
            if active:
                return "unknown"
            lower = None if boundary == "0" else parse_version(boundary)
            if (lower is None and (boundary != "0" or previous is not None)) or (
                lower is not None and previous is not None and lower < previous
            ):
                return "unknown"
            active = True
        elif kind in {"fixed", "last_affected", "limit"}:
            upper = parse_version(boundary)
            if not active or upper is None or (lower is not None and upper < lower):
                return "unknown"
            if (lower is None or version >= lower) and (
                version <= upper if kind == "last_affected" else version < upper
            ):
                affected = True
            if kind == "fixed" and version >= upper:
                fixed = True
            previous = upper
            active = False
        else:
            return "unknown"
    if affected or (active and (lower is None or version >= lower)):
        return "affected"
    return "fixed" if fixed else "outside"


def apply_pub_ranges(findings: list[Finding], records: list[Any]) -> None:
    """Use local OSV records only when a scoped scanner observation agrees."""
    canonical: dict[tuple[str, str], set[str]] = {}
    ranges_by_key: dict[tuple[str, str], list[Any]] = {}
    for record in records:
        if not isinstance(record, dict) or record.get("withdrawn"):
            continue
        alias_values = record.get("aliases")
        identifiers = [record.get("id"), *(alias_values if isinstance(alias_values, list) else [])]
        affected = record.get("affected")
        if not isinstance(affected, list):
            continue
        for item in affected:
            if not isinstance(item, dict) or not isinstance(package := item.get("package"), dict):
                continue
            name = package.get("name")
            if package.get("ecosystem") != "Pub" or not isinstance(name, str):
                continue
            identifiers_set = {value for value in identifiers if isinstance(value, str)}
            cves = {value for value in identifiers_set if re.fullmatch(r"CVE-[0-9]{4}-[0-9]+", value)}
            if len(cves) == 1:
                for identifier in identifiers_set:
                    canonical.setdefault((identifier, name), set()).update(cves)
            for identifier in identifiers_set:
                ranges_by_key.setdefault((identifier, name), []).append(item)

    for finding in findings:
        metadata = finding.metadata
        resolved = metadata.get("resolved_version")
        observed = metadata.get("version")
        if finding.source != "trivy" or not resolved or not observed:
            continue
        records_for_package = ranges_by_key.get((finding.external_id or "", metadata["package"]), [])
        if not records_for_package:
            continue
        statuses = []
        original = []
        for item in records_for_package:
            versions = item.get("versions", [])
            ranges = item.get("ranges")
            if not isinstance(versions, list) or not isinstance(ranges, list) or not ranges:
                statuses.append("unknown")
                continue
            if resolved in versions:
                statuses.append("affected")
            if observed in versions:
                original.append("affected")
            for affected_range in ranges:
                if not isinstance(affected_range, dict) or affected_range.get("type") != "SEMVER":
                    statuses.append("unknown")
                    continue
                events = affected_range.get("events")
                statuses.append(evaluate_range(resolved, events))
                original.append(evaluate_range(observed, events))
        status = (
            "affected" if "affected" in statuses else
            "fixed" if statuses and all(value == "fixed" for value in statuses) and "affected" in original
            else "unknown"
        )
        aliases = canonical.get((finding.external_id or "", metadata["package"]), set())
        if len(aliases) == 1 and finding.node_id and not metadata.get("fixed_in_inventory"):
            normalized = next(iter(aliases))
            finding.external_id = normalized
            finding.title = f"{normalized} in {metadata['package']}"
            metadata["cves"] = [normalized]
            finding.id = stable_id("pub-advisory", normalized, finding.node_id, observed)
        metadata["advisory_version_status"] = status
        metadata["fixed_in_inventory"] = status == "fixed"
        if status == "fixed":
            finding.recommendation = "Rescan the lockfile to confirm the resolved Pub release."
        elif status == "unknown":
            finding.recommendation = "Review the advisory ranges and verify the resolved Pub release."

    findings[:] = dedupe_findings(findings)
