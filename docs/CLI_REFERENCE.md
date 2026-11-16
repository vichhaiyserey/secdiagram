# 📖 CLI Reference Manual

`secdiagram` provides a deterministic command-line interface for architecture discovery, security analysis, and diagram rendering.

---

## 1. Synopsis

```text
secdiagram [-h] [--dir DIR] [--out OUT] [--format FORMAT]
           [--include GLOB] [--exclude GLOB]
           [--min-confidence MIN_CONFIDENCE] [--max-nodes MAX_NODES]
           [--jobs N] [--cache-dir PATH] [--no-cache]
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
           [--fail-on {critical,high,medium,low,info,none}]
           [--baseline FILE] [--create-baseline]
           [--quiet] [--version]
```

---

## 2. Options Reference

| Flag | Default | Description |
| :--- | :--- | :--- |
| `--dir DIR` | `.` | Target repository directory to inspect |
| `--out OUT` | `<dir>/.secdiagram` | Output directory for all generated artifacts |
| `--format FORMAT` | `json,md,mermaid` | Comma-separated outputs: `json` (`graph.json`), `md` (`ARCHITECTURE.md`, plus `THREAT_MODEL.md` when security analysis is on), `mermaid` (`diagram.mmd`, `diagram-highlevel.mmd`, `diagram-taint.mmd`), `sarif`, `vex`, `html`, `png`, `svg`, `pdf` |
| `--high-level` | `false` | Generate high-level system overview diagram (`secdiagram.com` style) as primary diagram |
| `--diagram-detail` | `architecture` | Visual detail level: `architecture`, `full`, `high-level`, `overview` |
| `--image [FORMAT]` | `png` | Render visual diagrams to image (`png`, `svg`, `pdf`) |
| `--image-format` | `png` | Format when `--image` is specified without arguments: `png`, `svg`, `pdf` |
| `--image-provider` | `auto` | Image renderer: `auto`, `local` (`mmdc`), `kroki`, `mermaid.ink` |
| `--image-endpoint URL` | `None` | Custom HTTP endpoint for private Kroki instances |
| `--offline` | `false` | Enforce strictly offline execution; forbids external HTTP calls |
| `--max-diagram-nodes N`| `150` | Maximum components displayed in diagram; `0` for unlimited |
| `--diagram-direction` | `LR` | Diagram orientation: `LR` (horizontal) or `TB` (top-to-bottom) |
| `--diagram-theme` | `modern` | Visual theme palette: `modern` (Tailwind) or `classic` |
| `--include GLOB` | `None` | Filter source files to include (repeatable) |
| `--exclude GLOB` | `None` | Patterns to exclude during analysis (repeatable) |
| `--link-base URL` | `None` | Prefix for clickable source links (e.g. `https://github.com/org/repo/blob/main`) |
| `--jobs N` | `0` (auto) | Parallel indexer processes; `0` auto-tunes, `1` forces serial execution |
| `--cache-dir PATH` | `<out>/cache` | Incremental per-file index cache keyed by content hash |
| `--no-cache` | `false` | Disable the index cache for this run |
| `--security / --no-security` | enabled | Toggle SAST security rules and IaC configuration checks |
| `--security-report {html,md,both}` | `none` | Write a standalone `security-report.html` and/or `SECURITY_REVIEW.md` |
| `--sonarqube-report PATH` | `none` | Import a SonarQube issues JSON export as security findings |
| `--xray-report PATH` | `none` | Import JFrog Xray violations JSON as dependency findings |
| `--advisory-db PATH` | `none` | Validate imported CVEs against a local CISA KEV/NVD/OSV JSON file or directory (repeatable) |
| `--min-confidence SCORE` | `0.5` | Drop call/inheritance edges below this confidence (`0.0`-`1.0`) |
| `--min-finding-confidence SCORE` | `0.0` | Drop security findings below this confidence (`0.0`-`1.0`) |
| `--fail-on SEVERITY` | `none` | Return exit code `2` if findings meet or exceed severity threshold: `critical`, `high`, `medium`, `low`, `info`, `none` |
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
| `0` | **Success**: Analysis completed without errors, and no `--fail-on` security threshold was violated. Also returned on `--help`, `--version`, or `--create-baseline`. |
| `1` | **Execution Error**: Fatal runtime error, invalid argument combination, missing required file, or unhandled exception. |
| `2` | **Security Violation**: Active security or IaC findings met or exceeded the threshold defined in `--fail-on` (e.g. `--fail-on high`). |

---

## 4. Common CLI Recipes

### Standard Architecture Scan with PNG Images
```bash
secdiagram --dir . --image
```

### High-Level System Overview for Executive Architecture Reviews
```bash
secdiagram --dir . --high-level --image svg
```

### Strict CI Pipeline with SARIF Export and Failure on High Vulnerabilities
```bash
secdiagram --dir . --format sarif,json,html --fail-on high --baseline .secdiagram/security.baseline.json
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
