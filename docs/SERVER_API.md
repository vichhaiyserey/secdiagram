# 🖥️ Hardened Platform Server & REST API Guide

`secdiagram` includes a hardened, zero-dependency platform server and REST API daemon that serves interactive reports, architectural graphs, and triggers scans on demand.

---

## 1. Starting the Server

The server runs via the `serve` subcommand:

```bash
# Recommended: authenticated, loopback-only server
secdiagram serve --dir . --user analyst --password 'change-me'

# Local-only development without authentication (explicitly insecure):
secdiagram serve --dir . --insecure-no-auth

# Remote binding (0.0.0.0): authentication is strictly enforced
secdiagram serve --dir . --host 0.0.0.0 --user analyst --password 'change-me'
```

---

## 2. Security Defaults & Hardening Rules

- **Loopback Binding by Default**: Binds to `127.0.0.1` unless `--host` is specified.
- **Mandatory Authentication**: Basic Authentication is enforced by default. `--insecure-no-auth` is rejected if `--host` is bound to any non-loopback interface.
- **Per-Client Rate Limiting**: Controlled via `--rate-limit` (default: 240 requests/minute). Set to `0` to disable.
- **Bounded Request Bodies**: Controlled via `--max-request-bytes` (default: 1 MiB / 1,048,576 bytes) to prevent resource exhaustion attacks.
- **Bounded Concurrency**: `--max-concurrent-scans` limits parallel scans (default: `1`). Requests exceeding the limit return HTTP `429 Too Many Requests`.
- **Path Traversal & Scan Root Containment**: Scans are strictly restricted to the served repository directory and any paths specified in `--scan-root`. Requests targeting paths outside allowlisted roots are rejected with HTTP `403 Forbidden`.
- **Credential & Host Path Scrubbing**: Absolute host paths, secret tokens, and sensitive environment variables are automatically scrubbed from responses, graph exports, and audit logs.
- **Structured JSON Audit Logging**: Security events (auth failures, scan requests, rejected paths, rate limits, SARIF downloads, server lifecycle) are emitted to stderr or `--audit-log FILE` as structured JSON Lines (`audit.jsonl`).
- **Same-Origin State Changes**: Studio POSTs reject cross-origin `Origin` values with `403 Forbidden`.
- **Bounded Studio State**: Diagram overrides are schema-validated, capped at 1 MiB and 5,000 entries, and persisted atomically under `.secdiagram/studio/`.
- **Strict Studio CSP**: `/studio` and its assets use `script-src 'self'` with no CDN or inline-script allowance, and `img-src 'self' data: blob:` for local SVG previews. The classic report retains its broader inline/CDN policy.
- **Installer Isolation**: The HTTP API exposes installer status only; all installer writes remain CLI-only.
- **LLM Endpoint Allowlist**: Studio AI requests accept loopback/private addresses and OpenAI hosts; link-local metadata endpoints such as `169.254.169.254` are rejected.

---

## 3. Configuration File (`secdiagram.config.json`)

Server options can be configured in a `secdiagram.config.json` file in your repository root or server working directory:

```json
{
  "server": {
    "host": "127.0.0.1",
    "port": 8080,
    "auth_mode": "basic",
    "auth_username": "analyst",
    "auth_password": "change-me",
    "read_only": false,
    "max_request_bytes": 1048576,
    "rate_limit_per_minute": 240,
    "max_concurrent_scans": 1,
    "scan_roots": ["."],
    "audit_log": "audit.jsonl"
  }
}
```

---

## 4. REST API Endpoints

All endpoints require Basic Authentication unless the server was explicitly started with `--insecure-no-auth`.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/` | Interactive self-contained HTML report (`report.html`) |
| `GET` | `/api/v1/health` | Server health and version |
| `GET` | `/api/v1/config` | Active configuration (secrets omitted) |
| `GET` | `/api/v1/summary` | Node/edge/finding counts, severity counts, canonical assessment counts, and coverage metadata |
| `GET` | `/api/v1/graph` | Deterministic graph JSON (`graph.json`), including `findings[].metadata.flow` taint paths |
| `GET` | `/api/v1/sarif` | OASIS SARIF v2.1.0 security report (`security.sarif`) |
| `GET` | `/api/v1/findings` | Findings ordered by canonical priority then score. Each carries `assessment`, `rule`, `provenance`, and `remediation` objects. Filters: `severity`, `category`, `min_confidence`, `priority`, `assessment_level`, `reachability`, `rule`, `suppressed`. |
| `GET` | `/api/v1/rules` | Observed rules with finding counts, severities, CWE/OWASP metadata, and help URIs |
| `GET` | `/api/v1/threat-model` | STRIDE threat model per trust boundary (Markdown) |
| `GET` | `/api/v1/diagram` | Mermaid diagram. `?detail=architecture` (default, taint paths highlighted), `?detail=high-level` (C4 tiers) or `?detail=taint` (attack-path diagram) |
| `POST` | `/api/v1/scan` | Trigger a new scan. Body accepts JSON options (`{"dir": "...", "security": true}`). Disabled when `read_only: true`. |
| `GET` | `/studio` | Agentic Studio single-page app (offline assets only). |
| `GET` | `/api/v1/studio/status` | Read-only installer (`installer`, including `source_checkout`), SDLC, overrides, and capability status. |
| `GET` | `/api/v1/studio/sdlc` | Deterministic SDLC phase state and progress. |
| `GET` | `/api/v1/studio/nodes` | Sorted node page for the editor. Supports `limit` (default 400, max 1000), `offset`, and `q`; returns `total`, `returned`, `limit`, and `offset`. |
| `GET` | `/api/v1/studio/diagram` | Mermaid from the edited graph (`detail`, `direction`, `theme`). |
| `GET` | `/api/v1/studio/render` | Local `mmdc` SVG/PNG render; returns `503` when unavailable. |
| `GET` | `/api/v1/studio/handoff` | Preview the stable Markdown handoff. |
| `GET` | `/api/v1/studio/skill` | Installed or built-in agent skill manifest and Markdown. |
| `POST` | `/api/v1/studio/sdlc` | Apply `start`, `complete`, `block`, `unblock`, `reset`, `note`, or `evidence`. |
| `POST` | `/api/v1/studio/overrides` | Persist diagram renames/hidden nodes/direction/theme, or `{"action":"reset"}`. |
| `POST` | `/api/v1/studio/handoff` | Write `HANDOFF.md`/`handoff.json` with `{"write":true}` after all phases are done. |
| `POST` | `/api/v1/studio/generate` | Optional evidence-grounded narrative from Ollama or OpenAI. |
| `POST` | `/api/v1/studio/installer` | Always `403`; installer writes are CLI-only. |

### Finding assessment contract

`/api/v1/graph`, `/api/v1/findings`, and `security.sarif` share the same canonical assessment fields. Existing keys are unchanged and `schema_version` stays `1`; consumers can detect the additive contract through `schema_features`.

```json
{
  "id": "…",
  "severity": "high",
  "assessment": {
    "model": "canonical-assessment/v1",
    "priority": "P3",
    "score": 0.7,
    "level": "unlikely",
    "impact_class": "supply-chain",
    "reachability": "unknown",
    "exposure": "isolated",
    "evidence": "inventory-only",
    "provenance": "dependency-in-use",
    "context": "production",
    "confidence": 0.8,
    "recommended_action": "monitor",
    "conditions": ["…"],
    "blocking": false,
    "suppressed": false,
    "trust": "external-unverified"
  },
  "rule": {
    "id": "dependency:CWE-829",
    "name": "secdiagram/trivy/dependency",
    "category": "dependency",
    "cwe": "CWE-829",
    "owasp": ["A03:2025", "A06:2021"],
    "help_uri": "https://cwe.mitre.org/data/definitions/829.html",
    "source": "trivy"
  },
  "provenance": {
    "source": "trivy",
    "external_id": "CVE-2023-39137",
    "report": "trivy.json",
    "imported": true,
    "validated": false,
    "evidence_quality": "",
    "trust": "external-unverified"
  },
  "remediation": {
    "summary": "Upgrade archive to 3.3.8.",
    "actions": ["Upgrade the affected package to a fixed version"],
    "commands": ["flutter pub upgrade archive:^3.3.8"]
  }
}
```

Public client identifiers (for example Firebase `google-services.json` API keys) are reported as `severity: info` with `metadata.secret_kind: public_client_identifier`. They are not credential material, do not trigger ATT&CK `T1552`, and never block policy or audit gates. Format-verified provider tokens remain `provider_token` and keep their blocking behavior.

---

## 5. Production & Reverse Proxy Deployment

> [!WARNING]
> The internal server engine speaks unencrypted HTTP. When deploying to remote hosts or shared environments:
> 1. Always terminate TLS using a trusted reverse proxy (e.g. NGINX, Caddy, Envoy, or Traefik).
> 2. Keep Basic Authentication enabled with a strong password.
> 3. Use `read_only: true` if the server is only intended to publish existing analysis reports.
