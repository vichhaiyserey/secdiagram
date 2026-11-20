# 📖 CLI Reference Manual

`secdiagram` provides a deterministic command-line interface for architecture discovery, security analysis, and diagram rendering.

---

## 1. Synopsis

```text
secdiagram [-h] [--dir DIR] [--out OUT] [--format FORMAT]
           [--include GLOB] [--exclude GLOB]
           [--min-confidence MIN_CONFIDENCE] [--max-nodes MAX_NODES]
           [--jobs N] [--cache-dir PATH] [--no-cache]
           [--dry-run] [--verbose] [--output {text,json}] [--config FILE]
           [--max-files N] [--max-file-bytes N] [--max-total-bytes N]
           [--min-finding-confidence SCORE]
           [--security] [--no-security]
           [--security-report {html,md,both}]
           [--sonarqube-report PATH] [--xray-report PATH]
           [--advisory-db PATH]
           [--link-base LINK_BASE]
           [--image [FORMAT]] [--image-format {png,svg,pdf}]
           [--image-provider {auto,local,kroki,mermaid.ink}]
           [--image-endpoint IMAGE_ENDPOINT] [--offline]
           [--diagram-detail {architecture,full,high-level,overview}]
           [--high-level]
           [--max-diagram-nodes MAX_DIAGRAM_NODES]
           [--diagram-direction {LR,TB}]
           [--diagram-theme {modern,classic}]
           [--ollama [MODEL]] [--llm] [--llm-model LLM_MODEL]
           [--llm-base-url LLM_BASE_URL] [--llm-api-key LLM_API_KEY]
           [--llm-template {comprehensive,threat-model,remediation,compliance}]
           [--llm-timeout LLM_TIMEOUT] [--llm-max-tokens LLM_MAX_TOKENS]
           [--llm-context-chars LLM_CONTEXT_CHARS]
            [--fail-on {critical,high,medium,low,info,block,none}]
            [--policy {shadow,report-only,strict}]
            [--baseline FILE] [--create-baseline]
           [--quiet] [--version]
```

---

## 2. Options Reference

| Flag | Default | Description |
| :--- | :--- | :--- |
| `--dir DIR` | `.` | Target repository directory to inspect |
| `--out OUT` | `<dir>/.secdiagram` | Output directory for all generated artifacts |
| `--format FORMAT` | `json,md,mermaid` | Comma-separated outputs: `json` (`graph.json`), `md` (`ARCHITECTURE.md`, plus `THREAT_MODEL.md` when security analysis is on), `mermaid` (`diagram.mmd`, `diagram-highlevel.mmd`, `diagram-taint.mmd`), `sarif`, `vex`, `html`, `png`, `svg`, `pdf`. Security-enabled `json` or `md` also writes `threat-model.json`. |
| `--high-level` | `false` | Generate high-level system overview diagram (`secdiagram.com` style) as primary diagram |
| `--diagram-detail` | `architecture` | Visual detail level: `architecture`, `full`, `high-level`, `overview` |
| `--image [FORMAT]` | `png` | Render visual diagrams to image (`png`, `svg`, `pdf`) |
| `--image-format` | `png` | Format when `--image` is specified without arguments: `png`, `svg`, `pdf` |
| `--image-provider` | `local` | Local `mmdc` by default. Explicit `auto` permits HTTP fallback; `kroki` and `mermaid.ink` explicitly select HTTP services |
| `--image-endpoint URL` | `None` | Custom HTTP endpoint for private Kroki instances |
| `--offline` | `false` | Enforce strictly offline execution; forbids external HTTP calls |
| `--max-diagram-nodes N`| `150` | Maximum components displayed in diagram; `0` for unlimited |
| `--diagram-direction` | `LR` | Diagram orientation: `LR` (horizontal) or `TB` (top-to-bottom) |
| `--diagram-theme` | `modern` | Visual theme palette: `modern` (Tailwind) or `classic` |
| `--validate` | `false` | Validate the canonical diagram model before rendering (`DQ001`-`DQ010`): duplicate ids/labels, orphans, cycles, self-loops, dangling or duplicated relationships, tier inversions, rank skips, and unlabeled edges. Prints a deterministic report and exits `1` without writing artifacts when error-severity issues are found |
| `--include GLOB` | `None` | Filter source files to include (repeatable) |
| `--exclude GLOB` | `None` | Patterns to exclude during analysis (repeatable) |
| `--link-base URL` | `None` | Prefix for clickable source links (e.g. `https://github.com/org/repo/blob/main`) |
| `--jobs N` | `0` (auto) | Parallel indexer processes; `0` auto-tunes, `1` forces serial execution |
| `--cache-dir PATH` | `<out>/cache` | Incremental per-file index cache keyed by content hash |
| `--no-cache` | `false` | Disable the index cache for this run |
| `--dry-run` | `false` | Validate local inputs and discover selected paths; no parsing, cache/output writes, image rendering or narrative requests |
| `--verbose` | `false` | Detailed diagnostics and skipped paths on stderr |
| `--output text\|json` | `text` | Console summary format, separate from artifact `--format`; JSON stdout contains one versioned document |
| `--config FILE` | none | Scan settings JSON; explicit CLI options override file values. In server mode this selects the separate server configuration schema |
| `--max-files N` | `10000` | Maximum selected files; `0` disables |
| `--max-file-bytes N` | `2097152` | Maximum bytes per selected file; `0` disables. Individual indexers also retain their own safety limits |
| `--max-total-bytes N` | `67108864` | Total selected input byte budget; `0` disables. Input budget, not a process RSS cap |
| `--security / --no-security` | enabled | Toggle SAST security rules and IaC configuration checks |
| `--security-report {html,md,both}` | `none` | Write a standalone `security-report.html` and/or `SECURITY_REVIEW.md` |
| `--sonarqube-report PATH` | `none` | Import a SonarQube issues JSON export as security findings |
| `--xray-report PATH` | `none` | Import JFrog Xray violations JSON as dependency findings |
| `--advisory-db PATH` | `none` | Validate imported CVEs against a local CISA KEV/NVD/OSV JSON file or directory (repeatable) |
| `--min-confidence SCORE` | `0.5` | Drop call/inheritance edges below this confidence (`0.0`-`1.0`) |
| `--min-finding-confidence SCORE` | `0.0` | Drop security findings below this confidence (`0.0`-`1.0`) |
| `--fail-on SEVERITY` | `none` | Return exit code `2` if findings meet or exceed severity threshold: `critical`, `high`, `medium`, `low`, `info`, `block` (policy block decisions; implies `--policy strict`), `none` |
| `--policy MODE` | `None` (informational) | Enforcement policy layer separating detection from CI impact: `shadow` (record decisions, never fail CI), `report-only` (record and surface in reports), `strict` (block decisions fail CI with exit code `2`). Decisions combine severity, decision confidence (>= 0.90), evidence quality, reachability, exposure, and mitigation status; LLM-produced findings never block |
| `--baseline FILE` | `none` | Suppress findings listed in baseline so CI fails only on NEW findings |
| `--create-baseline` | `false` | Generate `security.baseline.json` from the current scan and exit `0` |
| `--ollama [MODEL]` | `qwen2.5-coder` | Generate AI review using local Ollama (`qwen2.5-coder`, `qwen2.5:7b`, etc.) |
| `--llm` | `false` | Enable LLM narrative review generation |
| `--llm-model MODEL` | `qwen2.5-coder` | Target LLM model name |
| `--llm-base-url URL` | Ollama default | Base URL for LLM provider (Ollama or OpenAI-compatible) |
| `--llm-api-key KEY` | `None` | API key for OpenAI-compatible endpoints |
| `--llm-template` | `comprehensive` | Prompt profile: `comprehensive`, `threat-model`, `remediation`, `compliance` |
| `--llm-timeout N` | `300s` | Network timeout in seconds for LLM generation |
| `--llm-max-tokens N` | `1500` | Maximum completion tokens generated by the model |
| `--llm-context-chars N` | auto | Maximum graph evidence characters sent to the LLM |
| `--quiet` | `false` | Suppress console summary output |
| `--version` | — | Display program version and exit |

---

## 3. Exit Codes

| Exit Code | Meaning |
| :---: | :--- |
| `0` | **Success**: Analysis completed without errors, and no `--fail-on` security threshold or strict-policy block decision was violated. Also returned on `--help`, `--version`, or `--create-baseline`. |
| `1` | **Execution Error**: Fatal runtime error, invalid argument combination, missing required file, or unhandled exception. Also returned when `--validate` reports an error-severity diagram issue; rendering is skipped and no artifacts are written. |
| `2` | **Security Violation**: Active security or IaC findings met or exceeded the threshold defined in `--fail-on` (e.g. `--fail-on high`), or a strict-policy run (`--policy strict` / `--fail-on block`) produced at least one `block` enforcement decision. |

---

## 4. Common CLI Recipes

### Offline preview, diagnostics and CI coverage

```bash
secdiagram --dir . --offline --dry-run --verbose
secdiagram --dir . --offline --output json --format json,sarif --fail-on high > scan-summary.json
secdiagram --dir . --include 'src/*' --exclude 'archive/**' --jobs 1 --max-total-bytes 33554432
```

Normal runs emit discovery, parsing, mapping, threat analysis, rendering and report
generation stages on stderr. `--quiet` suppresses progress and the human summary;
`--output json` still emits its JSON document. Fatal diagnostics stay on stderr.
`--offline` blocks image HTTP providers and narrative HTTP requests, including Ollama;
omit narrative flags for fully offline analysis. Core analysis requires no configuration.

JSON summaries have `schema_version: 1`, `status`, `exit_code`, `dry_run`, and
`stages`. Completed analyses also include `health`, `cache`, and `written`.
Dry runs include a `plan` of selected files, skipped paths and intended stages.
Fatal failures include `error`; argument errors return `2`, execution errors `1`,
and security gates retain exit `2`. Check `health.complete` separately: recoverable
parse failures, unsupported languages, ambiguous modules or resource skips can
produce partial results with exit `0`. Coverage is static and heuristic, not a
guarantee that all runtime relationships were resolved.

`health` includes `files_discovered` (selected files after filters and limits),
`files_parsed` (successful architecture indexes), detected `languages` with file
counts, `components_identified` (graph nodes), `unresolved_references`,
`skipped_paths`, `parse_errors`, `graph_truncated`, `complete` and actionable
`diagnostics` (`code`, `path`, `message`, `hint`). Ignored directories are reported
as directory entries; Git-ignored files are not enumerated.

Scan configuration example:

```json
{"include": ["src/*"], "exclude": ["archive/**"], "jobs": 1,
 "max_files": 10000, "max_file_bytes": 2097152,
 "max_total_bytes": 67108864, "max_nodes": 2000, "security": true}
```

These are the accepted scan configuration keys; missing, malformed or unknown
settings produce an actionable error. The new console controls apply to `--dir`
scans. For workspace projects, scan each project separately to use these controls.

Discovery selects paths in deterministic order and records skipped files with
reasons. Directory exclusion patterns such as `archive/**` prune non-Git walks.
Limits bound input retained by indexers; ASTs, graphs, caches and worker processes
consume additional memory. Use `--jobs 1`, a lower input budget and tighter path
filters on constrained machines. The existing content-hash cache reuses Python
and Java indexes, safely ignores stale/corrupt entries, and never executes cached
code. Cache hit/miss counters appear only in console telemetry, preserving
deterministic artifact bytes.

### Standard Architecture Scan with PNG Images
```bash
secdiagram --dir . --image
```

### High-Level System Overview for Executive Architecture Reviews
```bash
secdiagram --dir . --high-level --image svg
```

### Diagram Model Validation Gate
```bash
secdiagram --dir . --validate --format mermaid,json
```

Fails the build when the canonical diagram model contains structural errors
such as dependency cycles or dangling relationships, so broken diagrams never
reach documentation or pull requests.

The gate covers the selected primary diagram and its high-level companion,
including workspace scans. Detailed modes check the same node collapsing,
filters and caps used by rendering. On failure, existing baselines and reports
remain unchanged, and no new baseline or workspace manifest is written.
Incremental index caches can still be updated during analysis.

### Strict CI Pipeline with SARIF Export and Failure on High Vulnerabilities
```bash
secdiagram --dir . --format sarif,json,html --fail-on high --baseline .secdiagram/security.baseline.json
```

### High-Confidence Policy Rollout (shadow, then strict)
```bash
# Step 1: record enforcement decisions without affecting CI
secdiagram --dir . --policy shadow --format sarif,json

# Step 2: fail CI only on evidence-backed block decisions
secdiagram --dir . --policy strict --format sarif,json
```

### External Scanner Ingestion with CycloneDX VEX Export
```bash
secdiagram --dir . --sonarqube-report sonar.json --xray-report xray.json --format vex
```

### Scale-Optimized Monorepo Analysis with Shared Cache
```bash
secdiagram --dir /path/to/monorepo --jobs 8 --cache-dir ~/.cache/secdiagram
```

### Continuous Threat Modeling Audit (ATT&CK Policy Gate)
```bash
secdiagram audit /path/to/repo --policy policy.yaml --json audit-result.json
```

Evaluates the parsed architecture against MITRE ATT&CK techniques (e.g. `T1190`
Exploit Public-Facing Application, `T1040` Network Sniffing, `T1552` Unsecured
Credentials) with evidence from the scan, prints a technique/mitigation summary,
and exits `1` when the policy thresholds in `policy.yaml` are violated so
CI/CD can block the build. When `--policy` is omitted, `<dir>/policy.yaml` is
used when present, otherwise built-in defaults. `--json` writes a
deterministic machine-readable result (`policy`, `techniques`, `violations`,
`pass`).

---

## 5. `secdiagram audit` Subcommand

```text
secdiagram audit [DIR] [--policy FILE] [--json PATH] [--quiet]
```

| Flag | Default | Description |
| :--- | :--- | :--- |
| `DIR` | `.` | Repository directory to audit |
| `--policy FILE` | `<dir>/policy.yaml` if present, else built-in | Audit policy file (restricted YAML dialect; see `policy.yaml`) |
| `--json PATH` | `None` | Write deterministic machine-readable audit result |
| `--quiet` | `false` | Print only the violation line or PASS |

Exit codes: `0` policy satisfied, `1` policy violated or execution error.

## 6. `secdiagram threat-diff` Subcommand

```text
secdiagram threat-diff BEFORE.json AFTER.json [--format md|json] [--out FILE] [--output text|json]
```

Compares saved `threat-model.json` artifacts offline. The default Markdown diff
shows added/removed/changed records with source evidence, verification steps and
analysis coverage changes. `--format json` emits the raw comparison; `--output
json` emits the standard CI console envelope containing `diff`. Without `--out`,
output goes to stdout. Input snapshots cannot be overwritten.

Exit codes: `0` comparison completed (including differences), `1` unreadable or
invalid snapshots, `2` invalid arguments. Removed records are not proof of fixes.
See [Threat modeling](THREAT_MODELING.md) for identity and coverage limitations.

## 7. `secdiagram studio` Subcommand

```text
secdiagram studio install [--home DIR] [--project-root DIR] [--no-venv] [--force] [--profile NAME] [--json]
secdiagram studio status  [--home DIR] [--json]
secdiagram studio uninstall [--home DIR] [--keep-venv] [--json]
secdiagram studio serve   [--dir DIR] [server flags...]
```

Installs a user-level Studio home with a private virtual environment, portable launchers, and the `secdiagram-diagramming` agent skill. `serve` forwards to `secdiagram serve` and exposes the Studio at `/studio`. The default home is `~/.secdiagram/studio`; set `SECDIAGRAM_STUDIO_HOME` to override it. Installer writes are CLI-only. See [Agentic Studio](STUDIO.md).
