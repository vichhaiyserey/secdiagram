# Dependency risk correlation

Use existing local scanner evidence with a Flutter project:

```sh
secdiagram --dir . --offline --trivy-report trivy.json --sbom inventory.cdx.json --format json,sarif,vex
```

Pub manifests and lockfiles supply package scopes, resolved versions and source
locations. The analyzer reads package configuration metadata without following
package URIs. Pub lockfiles list transitive packages without their parent edges.
CycloneDX component references provide explicit dependency edges when available.

Trivy advisories match Pub inventory by repository-relative lockfile target, name
and exact resolved version. Static Dart imports identify potential use. A
qualified package call connected to an entry point by call edges establishes
package reachability. The graph records the path and source evidence. Unqualified
symbols, dynamic dispatch and Flutter callbacks can escape correlation.

Risk scoring weights inventory, imports and package call paths differently.
Package reachability is evidence for prioritization. Trivy findings remain in
CycloneDX in-triage state and cannot block policy because this implementation
does not establish whether the particular vulnerable function can execute.
Absence of a path in the lexical graph never proves absence of reachability.

## Restricted environments

Dependency correlation reads local files. It requires Python and the installed
secdiagram package. Trivy, Pub, Dart and Flutter are unnecessary on the analysis
host. Stage reports and advisory snapshots through an approved transfer process.
Record the source revision, input hashes, scanner version and advisory database
date alongside the outputs. A successful audit does not certify that supplied
reports are complete or current.

Generating a fresh scanner report is a separate operation. Trivy needs a
compatible vulnerability database, supplied from an approved mirror or local
cache in an air-gapped deployment. See the
[Trivy connectivity guide](https://trivy.dev/docs/v0.76/guide/advanced/air-gap/).
Fetching GitHub issues or pushing code is a maintainer workflow; those operations
are separate from product analysis.

Use the following command to capture dependency evidence alongside the existing
audit result:

```sh
secdiagram audit . --offline --trivy-report trivy.json --sbom inventory.cdx.json --json audit.json
```

Audit JSON includes report summaries and invalid record counts. A package
correlation is advisory evidence. A stale Trivy record can be marked resolved
when an exact scoped lockfile resolves the single stable version named as the
fix. Prereleases and ambiguous fixed-version lists remain in triage.

## Verified local evidence bundles

Place the manifest next to the reports on read-only storage where practical.
Paths are relative to the manifest. Supply SHA-256 hashes of the original
report bytes.

```json
{
  "version": 1,
  "snapshot_date": "2026-11-20",
  "reports": {
    "trivy": {"path": "trivy.json", "sha256": "<64 lowercase hexadecimal characters>"},
    "cyclonedx": {"path": "inventory.cdx.json", "sha256": "<64 lowercase hexadecimal characters>"}
  }
}
```

```sh
secdiagram audit . --offline --evidence-bundle evidence.json --json audit.json
secdiagram audit . --offline --evidence-bundle evidence.json --require-evidence --evidence-max-age 7 --json audit.json
```

A bundle may contain one or both report types. Checksums verify consistency
with the manifest. They do not authenticate the producer or establish database
freshness independently of the supplied snapshot date. Distribute the manifest
through the same trusted process as the evidence.

By default the audit continues when the bundle is invalid or unavailable.
With an explicit reference date, stale verified reports remain useful for
triage and carry a warning. Strict mode exits 2 for missing, invalid, stale
or future-dated evidence, or malformed scanner records. Exit 1 continues to
indicate an audit policy violation or an analysis error. Use
`--evidence-as-of YYYY-MM-DD` for reproducible audits against a fixed date.
Strict mode otherwise evaluates freshness against the current UTC date.

## Reviewed symbol gate

Run an offline audit with an explicitly trusted review file and local CISA KEV snapshot:

```sh
secdiagram audit . --offline --evidence-bundle evidence.json --advisory-db kev.json --dependency-review reviewed.json --json audit.json
```

Use a policy-owned review file outside the untrusted checkout. A version-1
document contains a `reviews` array. Each review specifies `target` (the
repository-relative Pub lockfile), `package`, `version`, `advisory` (CVE),
`library` (exact package URI), `symbol`, `path` (repository-relative Dart
file), `line`, and `source_sha256`. Audit JSON exposes exact site fields
under `direct_symbol_candidates` for human review. Verify that the import
prefix resolves to the intended package, that the advisory covers the exact
symbol and version, and that the detected endpoint is a real application entry
point before approving it. The scanner checks the source hash against the
decoded UTF-8 source for normal UTF-8 inputs, preserving line endings.

A matching reviewed site, local KEV corroboration, high/critical severity
and a risk score of at least 6 trigger audit exit 1. The result records the
entry point and call locations in `dependency_violations`. Ordinary package
findings still appear in audit output. Initial enforcement is limited to direct
qualified calls inside detected endpoints. Indirect or ambiguous calls require
stronger evidence before they can be considered for enforcement.

## Performance and reproducibility check

Run `python scripts/benchmark_dependencies.py` from the checkout. The benchmark
generates its own Pub inventory and Trivy records, exercises 100, 1,000 and
10,000 packages, checks exact advisory matches, and compares JSON, SARIF and
VEX digests across two runs. It applies a 30-second ceiling per run, including
serialization. Image rendering is excluded. Run in a network-disabled
environment to verify the same workload in a restricted deployment.

## Remediation exports

The Markdown Security review includes a dependency remediation table. HTML
shows the same data in finding details. JSON and SARIF expose a structured
`dependency` object. CycloneDX carries the fields as namespaced properties
and links advisories to component references. The reported vulnerable version,
resolved inventory version, and scanner-proposed fix remain separate.

Duplicate records with the same normalized advisory identifier and scoped
package identity retain the highest reported severity and a duplicate count.
Conflicting proposed fixes stay visible and prevent a resolved disposition.
Trivy targets are scoped by path, class, ecosystem and installed version.
CycloneDX findings are scoped by the referenced component in each document.
Different advisory IDs and unverified identities across scanner sources remain
separate.

### Pub advisory ranges and repository binding

Pass a trusted local OSV JSON record or directory through `--advisory-db`.
A scoped Trivy observation can use matching Pub SEMVER ranges, including
prerelease bounds and multiple affected intervals. The resolved package must
fall outside all supplied affected ranges and meet their explicit fix bounds
before the audit reports a fix. Conflicting or unsupported range evidence
remains in triage.

A version-1 manifest can include a `repository` object with a full Git
`revision` and a `lockfiles` mapping from repository-relative
`pubspec.lock` paths to lowercase SHA-256 digests. The audit checks the lockfile
bytes and compares the revision with a clean checkout. Strict mode rejects a
mismatched binding. Keep manifest, evidence and audit output outside the
checkout when using clean-revision verification.

The manifest can also carry `advisory` and `review` entries under `reports`,
using the same path and SHA-256 fields as scanner reports. These inputs are
parsed from the verified bytes. Use a policy-owned manifest and trusted local
inputs. A digest alone does not establish who supplied the data.
