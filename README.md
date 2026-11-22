<div align="center">

# ⚡ secdiagram

### *Small but Gold* — Deterministic Architecture Diagrams, Polyglot System Mapping, and Security Intelligence.

[![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14%20%7C%203.15-blue.svg?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Standard%20Library%20Only-success.svg?style=flat-square)](pyproject.toml)
[![Tests](https://github.com/vichhaiyserey/secdiagram/actions/workflows/ci.yml/badge.svg?branch=develop)](https://github.com/vichhaiyserey/secdiagram/actions/workflows/ci.yml?query=branch%3Adevelop)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg?style=flat-square&logo=docker&logoColor=white)](Dockerfile)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![Cross Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Ubuntu%20%7C%20RHEL%20%7C%20Windows-blueviolet.svg?style=flat-square)](docs/CONTAINER_AND_COMPOSE.md)

<p align="center">
  <b>Transform codebases into clear, human-friendly system architecture diagrams, publication-quality images, security threat models, and AI reviews.</b><br>
  <i>100% offline-first. Zero external Python runtime dependencies. Polyglot architecture and security analysis across <b>.NET (C#)</b>, <b>Java / Spring Boot</b>, <b>Node.js / TypeScript</b>, <b>PHP</b>, <b>Go</b>, <b>Rust</b>, <b>Python</b>, and <b>Docker / Kubernetes / Terraform</b>.</i>
</p>

---

</div>

## 🌟 Key Highlights

- **Pure Python Standard Library (`zero dependencies`)**: Core analysis requires no third-party Python packages. Optional renderers and developer tools have separate pinned dependencies.
- **High-Level C4 System Diagrams**: Automatically compiles clean C4 tier diagrams (`diagram-highlevel.mmd` & `diagram-highlevel.png`) showing Ingress, Gateways, Core Services, Databases, Caches, Brokers, and External APIs.
- **Multi-Format Image Rendering**: Export diagrams directly to **PNG**, **SVG**, or **PDF** offline via bundled Mermaid CLI (`mmdc`) or zero-dependency HTTP fallbacks (Kroki, mermaid.ink).
- **Security & IaC SAST Overlay**: Discovers entrypoints, traces taint dataflows **across functions and files** (controller → service → repository) to dangerous sinks (CWE-78, CWE-89, CWE-502), draws them as an attack-path diagram, catches hardcoded secrets, and audits Dockerfile, Kubernetes, Terraform, and GitHub Actions configurations.
- **Web/API Misconfiguration Checks**: Flags broken JWT validation (`alg=none`, signature/expiry checks off), CORS that trusts any origin **with credentials**, disabled CSRF protection, cookies without `HttpOnly`/`Secure`, XXE-prone XML parsers, non-cryptographic RNGs used for tokens, and JS prototype pollution across C#, JS/TS, PHP, Go, and Java.
- **Risk-Ranked "Fix First" List**: Scores every finding 0–10 by impact × exposure (anonymous, authenticated, or internal entry point, detected from framework auth markers) × evidence × confidence × CISA KEV, and groups them P0–P3 in reports, SARIF, and diagrams.
- **STRIDE Threat Model**: Generates `THREAT_MODEL.md` and `threat-model.json` with affected components, assets, source evidence, static flows, severity/confidence, and verification steps. Facts and assessments are separated; `secdiagram threat-diff` compares saved versions offline. See [Threat modeling](docs/THREAT_MODELING.md).
- **MITRE ATT&CK Audit Gate**: `secdiagram audit <dir>` maps the parsed architecture to ATT&CK techniques (T1190 Exploit Public-Facing Application, T1040 Network Sniffing, T1552 Unsecured Credentials, …) with evidence and missing mitigations, and **fails CI/CD with exit code 1** when findings violate `policy.yaml` thresholds.
- **CycloneDX 1.6 VEX & SARIF Export**: Generates industry-standard `security.sarif` and CycloneDX 1.6 VEX documents (`vex.json`) with automated reachability justifications (`code_not_reachable`) for dead/internal code.
- **AI Architectural & Threat Modeling Reviews**: Integrates with local/containerized **Ollama (Qwen, LLaMA, DeepSeek)** or OpenAI endpoints to generate evidence-grounded architectural reviews citing exact `path:line` with zero hallucinations.
- **Agentic Studio & Portable AI Skill**: User-level installer with a private venv, portable launchers, and an agent skill manifest. The hardened Studio SPA adds interactive diagram overrides, a five-phase discover/model/secure/review/handoff state machine with evidence gates, executable handoff artifacts, and local-Ollama or OpenAI reviews -- all without adding a runtime dependency. See [Agentic Studio](docs/STUDIO.md).
- **100% Deterministic & Air-Gapped**: Byte-for-byte reproducible outputs across runs. Fully functional in offline, isolated, or air-gapped environments.

---

## 🚀 Quick Start

### 1. Instant Run (Python 3.10+)

Because `secdiagram` requires **only the Python standard library**, run it directly without installing third-party dependencies:

```bash
# Analyze current repository and generate detailed architecture diagrams:
python secdiagram.py --dir="."

# Generate both detailed and high-level C4 system diagrams with PNG images:
python secdiagram.py --dir="." --image

# Generate high-level system overview as primary diagram:
python secdiagram.py --dir="." --high-level --image

# ATT&CK audit gate for CI/CD - exits 1 on policy violations:
python secdiagram.py audit . --policy policy.yaml --json audit-result.json
```

### 2. Standalone Container Execution (Docker / Podman)

Run using the pre-built, hardened non-root container with bundled Chromium and Mermaid CLI:

```bash
# Linux / macOS:
docker run --rm -v "$(pwd):/repo" secdiagram:local --image

# Windows PowerShell:
docker run --rm -v "${PWD}:/repo" secdiagram:local --image

# RHEL / Fedora (SELinux mode):
docker run --rm -v "$(pwd):/repo:z" secdiagram:local --image
```

### 3. Agentic Studio & Portable AI Skill

```bash
# Install the user-level Studio home, launchers, and agent skill:
python secdiagram.py studio install

# Serve the Studio on loopback with authentication:
python secdiagram.py studio serve --dir . --user analyst --password 'change-me'
```

Open `http://127.0.0.1:8080/studio` to edit diagrams, drive the SDLC phases, request local AI
reviews, and generate handoff artifacts. The installer is CLI-only; the Studio reuses the
hardened platform server. See the [Agentic Studio guide](docs/STUDIO.md).

### 4. Python Public Facade

Integrate directly into custom automation scripts or DevSecOps pipelines:

```python
from secdiagram_core import analyze, render_mermaid, AnalysisConfig

result = analyze(AnalysisConfig(root=".", security=True))
print(f"Discovered {len(result.graph.nodes)} nodes and {len(result.graph.findings)} findings.")

# Native taint and package reachability query:
if result.has_taint_at("app/api.py", line=42):
    print("Tainted dataflow detected at line 42!")
```

---

## 🔀 Supported Ecosystems

| Ecosystem | Manifests Inspected | Architectural & Security Elements Detected |
| :--- | :--- | :--- |
| **.NET (C# / F#)** | `*.sln`, `*.csproj`, `*.fsproj`, `*.cs` | Project dependencies, ASP.NET Core controllers & Minimal APIs (routes, `[Authorize]`), EF Core DbContexts, MediatR CQRS, constructor DI; interprocedural taint to SQL, command, SSRF, path, redirect sinks; JWT/CORS/CSRF/cookie/XXE checks |
| **Node.js / TypeScript** | `package.json`, workspaces, `schema.prisma`, `*.js`/`*.ts` | Express, Fastify, Koa, Hono, NestJS, Next.js routes & auth middleware; Prisma, TypeORM, Mongoose; interprocedural taint to SQL/NoSQL, `child_process`, `eval`, XSS, path, SSRF sinks; prototype pollution; JWT/CORS/cookie checks |
| **PHP** | `composer.json`, `*.php` | Laravel routes & middleware, Symfony `#[Route]`/`#[IsGranted]`, Slim, legacy page scripts; constructor DI; taint to SQL, `system`/`exec`, `include`, `unserialize`, XSS, path, SSRF; CSRF/CORS/cookie/XXE checks |
| **Go** | `go.mod`, `*.go` | `net/http` (incl. Go 1.22 `"GET /path"`), Gin, Echo, Chi routes & auth middleware; structs, receiver methods, `NewX` injection; taint to SQL, `exec.Command`, path, SSRF, XSS; JWT/CORS/cookie/TLS checks |
| **Rust** | `Cargo.toml`, `*.rs` | Structs/enums/traits, `impl` methods, Axum router and Actix attribute routes; request-to-SQLx, shell-command, filesystem and HTTP sink evidence; TLS/CORS and selected non-cryptographic RNG checks. Lexical coverage and limits: [Rust support](docs/RUST_SUPPORT.md). |
| **Java / Spring Boot** | `pom.xml`, `build.gradle(.kts)` | Stereotypes (`@RestController`, `@Service`, `@Repository`), DI (`@Autowired`), injection/call edges, `@PreAuthorize`/`@PermitAll`; SQLi, command injection, deserialization, SSRF, XSS, XXE; JWT/CORS/CSRF/cookie checks |
| **Python** | `pyproject.toml`, `requirements.txt`, `*.py` AST | FastAPI, Flask, Django, Celery; SQLAlchemy, Tortoise-ORM, asyncpg, pymongo; AST taint tracking from sources to dangerous execution sinks |
| **Infrastructure & IaC** | `docker-compose.yml`, `Dockerfile`, K8s, Terraform | Compose service ports & links; Dockerfile unpinned tags & root user; Kubernetes capabilities & security contexts; Terraform public ACLs |

---

## 📦 Generated Artifacts

Preview a scan without writing files, or capture a structured CI summary:

```bash
secdiagram --dir . --offline --dry-run --verbose
secdiagram --dir . --offline --output json --format json,sarif > scan-summary.json
```

Progress stages appear on stderr. The summary reports parsed files, detected languages,
components, unresolved references and skipped paths. Use `--verbose` for diagnostic
details, and check `health.complete` in CI to detect partial coverage.
Image rendering defaults to local `mmdc`; HTTP rendering requires an explicit provider.
For large repositories, combine repeatable `--include`/`--exclude` filters with the
incremental cache and configurable input limits. See the [CLI reference](docs/CLI_REFERENCE.md).

By default, all outputs are written deterministically to `<repo>/.secdiagram/`:

- `diagram-highlevel.mmd` / `.png` — High-level C4 system tier diagram (`secdiagram.com` style).
- `diagram.mmd` / `.png` — Detailed architecture flowchart and component relationships (taint paths highlighted in red).
- `diagram-taint.mmd` / `.png` — Attack-path diagram: untrusted input → entry points → every function on the path → vulnerable sink.
- `ARCHITECTURE.md` — Complete markdown architecture report with embedded diagrams and a risk-ranked "Fix first" table.
- `THREAT_MODEL.md` — STRIDE threat model per trust boundary, backed by findings and their risk priority.
- `threat-model.json` — Versioned source-backed observations and coverage context; compare versions with `secdiagram threat-diff before/threat-model.json after/threat-model.json`.
- `audit-result.json` — Machine-readable ATT&CK audit result (`secdiagram audit --json`): policy, per-technique status/evidence, and violations.
- `graph.json` — Machine-readable graph schema (nodes, edges, confidence, features, findings with hop-by-hop `metadata.flow` and `metadata.risk`).
- `security.sarif` — OASIS SARIF v2.1.0 code-scanning report with taint `codeFlows`; `rank` and `riskScore`/`riskPriority` follow the risk model.
- `vex.json` — CycloneDX 1.6 VEX document with automated reachability justifications.
- `report.html` — Zero-dependency interactive HTML report with dark mode, filtering, and an "Attack paths" view.
- `SECURITY_REVIEW.md` / `security-report.html` — Standalone security review (`--security-report md|html|both`).
- `NARRATIVE.md` — Optional evidence-grounded AI review (`--llm` / `--ollama`).
- `security.baseline.json` — Accepted-findings baseline (`--create-baseline`, then `--baseline`).

---

## 📚 Documentation Index

For comprehensive guides, references, and deployment patterns, see:

| Guide | Description |
| :--- | :--- |
| [**Architecture Diagrams & Image Rendering**](docs/ARCHITECTURE_DIAGRAMS.md) | C4 high-level diagrams, visual tiering, detail modes, PNG/SVG/PDF rendering, and providers. |
| [**Container & Docker Compose Guide**](docs/CONTAINER_AND_COMPOSE.md) | Standalone Docker & Podman, Windows Git Bash tips, SELinux mode, and local Ollama Compose. |
| [**Security & IaC Static Analysis**](docs/SECURITY_AND_IAC.md) | SAST and interprocedural taint rules per language, web/API misconfiguration checks, risk model, STRIDE threat model, MITRE ATT&CK audit gate, attack-path diagram, IaC checks, SonarQube/Xray import, CycloneDX VEX. |
| [**Rust / Axum / Actix Support**](docs/RUST_SUPPORT.md) | Supported syntax, Cargo inventory, evidence-backed rules, offline examples and coverage limits. |
| [**Threat Modeling & Diffs**](docs/THREAT_MODELING.md) | Facts versus assessments, source-linked STRIDE observations and version comparison. |
| [**Hardened Platform Server & REST API**](docs/SERVER_API.md) | Daemon mode (`secdiagram serve`), authentication, rate limits, request caps, and config schema. |
| [**Agentic Studio & AI-Skill Installer**](docs/STUDIO.md) | User-level install, portable agent skill, Studio UI, diagram overrides, SDLC evidence gates, handoffs, and local AI reviews. |
| [**CLI Reference Manual**](docs/CLI_REFERENCE.md) | Complete command-line syntax, options breakdown table, and exit codes. |
| [**Python Public Facade & Developer API**](docs/PYTHON_API.md) | Stable facade (`secdiagram_core`), taint/reachability queries, SCA bridge, and cache serialization. |
| [**Task Tracking Guide**](docs/TASK_TRACKING.md) | GitHub Issues & Projects v2 task lifecycle tracking with `taskctl.py`. |
| [**Test Contracts & Validation**](docs/TEST_VALIDATION.md) | Meaningful test conditions, isolated fault checks, cross-platform verification and known gaps. |

---

## 🧪 Verification & Testing

`secdiagram` maintains behavior-focused tests covering the supported application languages, including Rust, plus infrastructure-as-code, interprocedural taint, misconfiguration rules, risk scoring, the STRIDE threat model and MITRE ATT&CK audit gate, graph builders, image rendering, and deterministic CLI behaviors. Related conditions use named subtests; full-content checks and positive/negative controls take precedence over assertion counts. CI runs the suite on Ubuntu **and** Windows for every supported Python version. See [test contracts and validation](docs/TEST_VALIDATION.md) for the inventory, fault checks and coverage limits.

```bash
# Run unit test suite:
python -m unittest discover -s tests -v
```

---

## 🤝 Contributing & License

- **Contributing**: Please review [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`AGENTS.md`](AGENTS.md) for architectural guardrails and commit conventions.
- **License**: Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for details.
