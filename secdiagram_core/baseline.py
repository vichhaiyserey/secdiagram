"""Security baseline and governed suppressions.

Two mechanisms share this module:

* **Baseline** (schema 1, read-only legacy): a set of finding fingerprints so
  CI fails only on regressions. Entries suppress without expiry.
* **Governed suppressions** (schema 2): scoped, expiring, owned exceptions.
  Each entry records the finding fingerprint, rule id, scope, reason, owner,
  approver, ticket, and expiry date. Expired suppressions automatically
  reactivate the finding. Suppressed findings remain visible in every report.

Fingerprints are the finding id, itself derived from rule category, source
path, line number, and title. A finding wiped or shifted in the source
therefore regenerates and is reported as new, which is the expected baseline
drift behaviour.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

from .model import Finding, Graph

BASELINE_SCHEMA_VERSION = "1"
GOVERNED_SCHEMA_VERSION = "2"
ISO_DATE_LENGTH = 10


def finding_fingerprint(finding: Finding) -> str:
    """Return the stable, deterministic fingerprint of a finding."""
    return finding.id


def _validate_iso_date(value: str, field: str) -> str:
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"suppression {field} must be an ISO date (YYYY-MM-DD): {value!r}") from exc
    return parsed.isoformat()


@dataclass(frozen=True, slots=True)
class SuppressionEntry:
    """A governed, scoped, expiring exception for one finding fingerprint."""

    id: str
    rule_id: str = ""
    scope: str = ""
    reason: str = ""
    owner: str = ""
    approver: str = ""
    ticket: str = ""
    expires: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "scope": self.scope,
            "reason": self.reason,
            "owner": self.owner,
            "approver": self.approver,
            "ticket": self.ticket,
            "expires": self.expires,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SuppressionEntry:
        if not isinstance(data, dict) or not isinstance(data.get("id"), str) or not data["id"]:
            raise ValueError("suppression entries must have a non-empty 'id'")
        entry_id = data["id"]
        expires_raw = str(data.get("expires") or "").strip()
        expires = _validate_iso_date(expires_raw, "expires") if expires_raw else ""
        return cls(
            id=entry_id,
            rule_id=str(data.get("rule_id") or ""),
            scope=str(data.get("scope") or ""),
            reason=str(data.get("reason") or ""),
            owner=str(data.get("owner") or ""),
            approver=str(data.get("approver") or ""),
            ticket=str(data.get("ticket") or ""),
            expires=expires,
        )

    def is_expired(self, today: str) -> bool:
        """True when the suppression expiry has passed relative to ``today`` (ISO date)."""
        if not self.expires or not today:
            return False
        return self.expires < today


def _read_payload(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("baseline must be a JSON object")
    return payload


def load_baseline(path: Path) -> set[str]:
    """Load baseline fingerprints from ``path``; raise on malformed content.

    Accepts schema 1 (findings list) and schema 2 (governed suppressions).
    """
    payload = _read_payload(path)
    version = payload.get("schema_version")
    if version == BASELINE_SCHEMA_VERSION:
        findings = payload.get("findings", [])
        if not isinstance(findings, list):
            raise ValueError("baseline 'findings' must be a list")
        entries = set()
        for item in findings:
            if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not item["id"]:
                raise ValueError("baseline findings entries must have a non-empty 'id'")
            entries.add(item["id"])
        return entries
    if version == GOVERNED_SCHEMA_VERSION:
        suppressions = payload.get("suppressions", [])
        if not isinstance(suppressions, list):
            raise ValueError("baseline 'suppressions' must be a list")
        return {SuppressionEntry.from_dict(item).id for item in suppressions}
    raise ValueError(f"unsupported baseline schema_version: {version!r}")


def load_suppressions(path: Path, today: str) -> tuple[dict[str, dict[str, str]], dict[str, dict[str, str]], set[str], str]:
    """Load governed suppressions from ``path``.

    Returns ``(active, expired, legacy_ids, schema_version)``:

    * ``active`` - fingerprint -> entry dict for unexpired governed entries.
    * ``expired`` - fingerprint -> entry dict for entries past their expiry;
      these findings reactivate automatically.
    * ``legacy_ids`` - fingerprints from a schema-1 baseline (suppress without
      expiry); empty for a governed file.
    """
    payload = _read_payload(path)
    version = payload.get("schema_version")
    if version == BASELINE_SCHEMA_VERSION:
        legacy = load_baseline(path)
        return {}, {}, set(legacy), BASELINE_SCHEMA_VERSION
    if version != GOVERNED_SCHEMA_VERSION:
        raise ValueError(f"unsupported baseline schema_version: {version!r}")
    suppressions = payload.get("suppressions", [])
    if not isinstance(suppressions, list):
        raise ValueError("baseline 'suppressions' must be a list")
    active: dict[str, dict[str, str]] = {}
    expired: dict[str, dict[str, str]] = {}
    seen: set[str] = set()
    for item in suppressions:
        entry = SuppressionEntry.from_dict(item)
        if entry.id in seen:
            raise ValueError(f"duplicate suppression id: {entry.id}")
        seen.add(entry.id)
        if entry.is_expired(today):
            expired[entry.id] = entry.to_dict()
        else:
            active[entry.id] = entry.to_dict()
    return active, expired, set(), GOVERNED_SCHEMA_VERSION


def write_baseline(graph: Graph, path: Path) -> int:
    """Write a deterministic governed baseline file with the current findings.

    Entries created this way are pending governed triage: they suppress
    without expiry until an owner, approver, ticket, and expiry date are
    recorded. Returns the number of entries.
    """
    records: list[dict[str, str]] = []
    for finding in graph.sorted_findings():
        first = finding.evidence[0] if finding.evidence else None
        records.append(
            {
                "id": finding.id,
                "rule_id": f"{finding.category}:{finding.cwe or ''}",
                "scope": first.path if first else "",
                "line": str(first.line if first else 0),
                "reason": "created by --create-baseline; pending governed triage",
                "owner": "",
                "approver": "",
                "ticket": "",
                "expires": "",
            }
        )
    records.sort(key=lambda record: record["id"])
    payload = {
        "schema_version": GOVERNED_SCHEMA_VERSION,
        "tool": "secdiagram",
        "usage": (
            "pass --baseline with this file so CI fails only on findings not listed here; "
            "entries suppress until their expiry date (empty expires = pending governed triage); "
            "fill in owner, approver, ticket, and expires for approved exceptions; "
            "regenerate with --create-baseline after triaging new findings"
        ),
        "suppressions": records,
    }
    text = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    path.write_text(text, encoding="utf-8", newline="\n")
    return len(records)


def apply_baseline(graph: Graph, entries: set[str], file_label: str) -> tuple[int, int]:
    """Mark findings listed in the baseline and annotate graph meta.

    Returns ``(known, new)`` where ``known`` is how many findings were
    suppressed and ``new`` how many are not covered by the baseline.
    """
    known = 0
    for finding in graph.findings:
        if finding.id in entries:
            finding.baseline = True
            known += 1
    total = len(graph.findings)
    graph.meta["security_baseline"] = {
        "file": file_label,
        "known": known,
        "new": total - known,
        "total": total,
    }
    return known, total - known


def ignore_baseline(graph: Graph, file_label: str) -> None:
    """Record a baseline-mode run where no findings could be suppressed."""
    graph.meta["security_baseline"] = {
        "file": file_label,
        "known": 0,
        "new": len(graph.findings),
        "total": len(graph.findings),
    }
