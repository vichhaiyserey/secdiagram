# Evidence-backed threat modeling

Run the usual offline analysis with security enabled:

```sh
secdiagram --dir ./service --out ./review --offline --format json,md
```

This writes `THREAT_MODEL.md` and `threat-model.json` alongside the existing
architecture and graph reports. Either the `json` or `md` output enables the JSON
snapshot; Markdown additionally enables the human-readable report. Workspace
scans produce the same threat artifacts with repository-prefixed evidence.
`--no-security` and `--dry-run` do not write threat artifacts.

## What constitutes a threat observation

Each observation links a static rule to source locations, affected component IDs,
assets and any resolved source-to-sink trace. It includes STRIDE classification,
rule severity, rule confidence, existing risk score/priority, exploitability
assessment, recommendations and source-specific verification steps. One finding
can support more than one STRIDE consequence; it retains the same finding ID in
each record. Findings without usable source evidence or a supported STRIDE
mapping are listed under `unrepresented_findings`, rather than invented into
source-backed observations. Suppressed baseline findings remain available in
the existing graph/security reports and are excluded from active threat records.

The six classes are Spoofing, Tampering, Repudiation, Information disclosure,
Denial of service and Elevation of privilege. The catalog overview describes
coverage. Unmatched categories, audit logging requirements and rate-limit advice
are not presented as observed findings.

Facts report what the analyzer detected. A static trace is evidence that the
analyzer connected locations; it does not prove a feasible runtime exploit.
`exploitability: static-flow` means a trace is attached, while `unverified` means
there is no resolved trace. Neither value means exploitation was demonstrated.
Confidence is the rule's estimate, not a measured probability of exploitation.
Severity and risk retain the existing finding/risk model; no new CI blocking
policy or ATT&CK audit behavior is introduced.

Authentication signals are deliberately conservative. For example:

> Route POST /api/upload has no detected authentication marker; see routes.py:42.

This creates an informational **review** record. It does not assert that the
route accepts file data, is deployed publicly, or lacks all authorization.
Explicit anonymous-access markers are distinguished from unknown authentication.
Global middleware, gateways and custom controls may not be recognized. Review
steps identify the exact route and evidence, then ask reviewers to inspect
inherited controls and test anonymous/insufficient-privilege access against the
intended policy. Authenticated routes do not receive a missing-auth review record.

Components come from finding ownership and trace hops. Unresolved ownership is
stated explicitly and source files become affected assets. Missing flows are
reported as unresolved; ordinary dependency edges are never promoted to proven
data flows. Workspace flow node IDs and locations are remapped during merging.
Reports use locations and rule metadata without copying detected source snippets.

## Compare two code versions

Generate a snapshot for each version using matching analysis settings, then:

```sh
secdiagram threat-diff ./before/threat-model.json ./after/threat-model.json --out ./threat-diff.md
secdiagram threat-diff ./before/threat-model.json ./after/threat-model.json --format json --out ./threat-diff.json
secdiagram threat-diff ./before/threat-model.json ./after/threat-model.json --output json
```

Without `--out`, the diff goes to stdout. `--output json` uses the existing CI
console envelope and includes the comparison under `diff`. A successful
comparison exits 0 even when threats changed; malformed/unreadable snapshots
exit 1 and invalid command arguments exit 2. This command reads snapshots only:
it does not access the network, invoke Git, execute project code or rescan source.

The diff separates added, removed, changed and unchanged records, shows exact
changed fields, retains both versions' evidence, and identifies the repository
revisions when available. It also exposes analysis context changes: filters,
configuration identity, parse errors, skipped paths, truncation, suppressions,
unsupported languages and unavailable workspace repositories. Cache hits and
timing are excluded from context to avoid spurious differences.

**A removed record is absent from the new snapshot, not proven fixed.** Check
coverage and suppression changes before concluding remediation. Compare snapshots
from the same project and analyzer version; detector changes can create changes
without source changes. The snapshot schema is versioned independently.

Identity uses the STRIDE catalog entry, rule, source path, owning symbol and
occurrence order. Line-only shifts normally appear as changes with updated
citations. Moves, renames and insertion/removal of repeated identical rules can
produce removals/additions or different occurrence pairings. No heuristic match
is represented as certain. Revisions are descriptive metadata, not a signature
or proof that a snapshot came from that checkout.

Snapshot input is capped at 32 MiB and rejects unsupported schemas, duplicate
JSON keys/record IDs, non-finite scores and missing actionable fields. The diff
refuses to overwrite either input file. Keep larger analyses scoped with existing
path filters and retain the graph/security reports for full underlying evidence.

## Verification

`tests/test_threat_review.py` checks exact evidence/flow/component relationships,
real polyglot authentication signals, unresolved ownership, duplicate flow rules,
workspace remapping, baseline exclusion, deterministic serialization and
before/after diffs, including actual vulnerable and safe source revisions. It also exercises malformed snapshots, read limits, CI JSON,
offline operation and input-file preservation. The targeted test-depth audit
injects regressions into evidence, flows, authentication classification and diff
reporting; only genuine assertion failures count as detections.
