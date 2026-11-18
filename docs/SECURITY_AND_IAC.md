# 🛡️ Security & IaC Static Analysis Guide

`secdiagram` provides deterministic static security analysis across application code, third-party dependencies, and infrastructure configurations without running or executing any untrusted code.

---

## 1. Application Security Rules (SAST)

The static analysis engine inspects Python and Java/Spring sources (and, see 1.1, C#/.NET, JavaScript/TypeScript, PHP and Go) to detect security vulnerabilities, untrusted source-to-sink dataflows, and dangerous configurations:

| Category | CWE | Patterns Detected | Default Severity |
| :--- | :--- | :--- | :--- |
| **Command Injection** | CWE-78 | `subprocess` with `shell=True`, `os.system`, `os.popen`, `eval`, `exec` with tainted variables | Critical / High |
| **SQL Injection** | CWE-89 | Raw SQL string interpolation, f-strings, `%` formatting in DB executions | High |
| **Unsafe Deserialization** | CWE-502 | `pickle.loads`, `yaml.load` without `SafeLoader` | Critical / High |
| **Path Traversal** | CWE-22 | Unsanitized file path joins (`os.path.join`, `open`, `Path`) with user inputs | High |
| **Weak Cryptography** | CWE-327 | Use of `MD5`, `SHA1` for security contexts, hardcoded AES ECB mode | Medium |
| **Hardcoded Secrets** | CWE-798 | Embedded API keys, AWS tokens, private keys, populated `.env` files | High / Medium |
| **SSRF** | CWE-918 | Outgoing HTTP requests using unvalidated user input | High |
| **Cross-Site Scripting** | CWE-79 | Rendering raw user input into HTML/templates without escaping | High / Medium |

Findings carry full source-to-sink taint paths (`codeFlows`), exact `path:line` citations, and stable partial fingerprints.

### 1.1 C#/.NET, JavaScript/TypeScript, PHP and Go

`polyglot_index.py` and `polyglot_security.py` add the same graph and SAST
outputs for four more ecosystems. Like the Java indexer they are stdlib-only and
lexical: source is read as text and never compiled or executed.

**Architecture captured**

| Language | Endpoints & routes | Structure & edges |
| :--- | :--- | :--- |
| C#/.NET | ASP.NET Core attribute routing (`[Route]`, `[HttpGet]`, `[controller]`/`[action]` tokens, conventional routes), minimal APIs (`MapGet`/`MapPost`... with `MapGroup` prefixes), SignalR hubs | namespaces, classes/records/interfaces, constructor and primary-constructor DI, MediatR `Send`/`Publish` → handler, EF Core `DbSet<T>` entities, inheritance, calls |
| JavaScript / TypeScript | Express/Koa/Fastify/Hono router calls and `.route()` chains, NestJS `@Controller` + `@Get`..., Next.js app router `route.ts` handlers and `pages/api` | modules, relative `import`/`require` edges, classes, functions, arrow handlers, NestJS constructor DI |
| PHP | Laravel `Route::get/post/match/resource` (closures, `[Controller::class, 'method']`, `'Controller@method'`), Symfony `#[Route]` (class prefix + methods), Slim/Lumen receivers, legacy page scripts reading superglobals | namespaces, classes/traits/interfaces, `__construct` DI, inheritance, calls |
| Go | `net/http` `HandleFunc` (incl. Go 1.22 `"GET /path"` patterns), gin/echo/chi/gorilla `.Methods()` | packages, structs/interfaces, methods by receiver, `NewX(...)` constructor injection, calls |

Route registrations that name their handler (`app.get('/x', listUsers)`,
`Route::get('/x', [UserController::class, 'show'])`, `r.GET("/x", h.Get)`)
are linked to that handler, even across files, so the handler itself becomes the
endpoint node.

**Security rules (interprocedural taint)**

Request input (ASP.NET action parameters and `Request.*`, `req.query/body/params`,
NestJS `@Body/@Query/@Param`, `$_GET/$_POST/$request->input()`, Laravel/Symfony
route parameters, `c.Query/c.Param/r.FormValue/r.URL.Query()` and gin/echo
binders) is followed **across functions and files**:

1. Every value carries labels: `src` (request input) or `p<i>` (came from
   parameter *i*), each with the hop-by-hop trace that produced it.
2. Calls are resolved to their targets: same class/file, unique plain
   functions, `this.x` / `$this->x` / `_x` fields and typed parameters (through
   the declared type, or its single implementer for interfaces), local
   `x = new X(...)` / `NewX(...)` instances, static `Class.method` calls and Go
   receiver fields. Member calls on receivers of unknown type (`pool.query`,
   `client.find`) are never guessed.
3. Each function gets a summary (which parameters reach which sinks; whether it
   returns request input). Summaries are composed along calls with a worklist
   until a fixed point, so controller -> service -> repository chains of any
   depth are found, and helpers that *return* input taint their callers.
4. A sink is reported as tainted only when a real request source reaches it.
   A service method that builds SQL from a parameter is critical when some
   endpoint passes request input to it, and a medium "dynamic SQL" review item
   otherwise.

Numeric casts (`parseInt`, `int.Parse`, `intval`, `strconv.Atoi`), including
inside call arguments, and contextual sanitizers (`htmlspecialchars`,
`encodeURIComponent`, `basename`, `escapeshellarg`, `Url.IsLocalUrl`...) end the
chain. Every tainted finding records its flow in `metadata.flow` (location,
graph node, role: `source`, `param`, `call`, `propagation`, `return`, `sink`)
and as SARIF `codeFlows`.

| Category | CWE | Examples |
| :--- | :--- | :--- |
| SQL injection | CWE-89 | `new SqlCommand(sql)`, `FromSqlRaw($"...")`, Dapper; `pool.query(`...${x}`)`, knex `raw`, Prisma `$queryRawUnsafe`; `DB::select("..." . $id)`, `mysqli_query`; `db.Query(fmt.Sprintf(...))`. Only the query text is checked; bound parameters are safe. |
| Command injection | CWE-78 | `Process.Start`, `child_process.exec/spawn`, `system`/`shell_exec`/backticks, `exec.Command` |
| Code evaluation / file inclusion | CWE-95 / CWE-98 | `CSharpScript.EvaluateAsync`, `eval`/`new Function`/`vm.run*`, PHP `eval`/`assert`/`include $x` |
| Unsafe deserialization | CWE-502 | `BinaryFormatter`, `TypeNameHandling.All/Auto`, `unserialize($input)`, `node-serialize` |
| Cross-site scripting | CWE-79 | `Html.Raw`, `innerHTML`/`dangerouslySetInnerHTML`/`res.send(input)`, PHP `echo`/`<?=`, Go `template.HTML`/`w.Write` |
| Path traversal | CWE-22 | `File.*`/`PhysicalFile`, `fs.readFile`/`res.sendFile`, `file_get_contents`/`fopen`, `os.Open`/`http.ServeFile` |
| SSRF | CWE-918 | `HttpClient.Get*Async`, `fetch`/`axios`, `curl_init`/`CURLOPT_URL`, `http.Get`/`http.NewRequest` |
| Open redirect | CWE-601 | `Redirect(...)`, `res.redirect`/`Response.redirect`, `header('Location: ...')`, `http.Redirect` |
| NoSQL injection | CWE-943 | Mongo filters taken directly from `req.body`/`req.query` |
| TLS validation disabled | CWE-295 | certificate callbacks returning `true`, `rejectUnauthorized: false`, `CURLOPT_SSL_VERIFYPEER false`, `InsecureSkipVerify: true` |
| Weak cryptography | CWE-327/328 | `MD5`/`SHA1`/`DES` creation, `createHash('md5')`, `md5($password)`, `md5.Sum` |

SQL, command and code builders that are assembled dynamically (concatenation,
interpolation, `string.Format`/`sprintf`/`fmt.Sprintf`) without proven request
input are still reported, at lower severity, unless every spliced value is a
known numeric cast. Hardcoded secrets in these languages are covered by the
shared secret scanner.

**Known limits.** Taint stored in object fields or collections and read later
by another method, dynamic dispatch through reflection/DI containers resolved at
runtime, and interfaces with several implementations (at most three candidate
targets are followed) are approximated. Flows are capped at 14 hops (the source
and the sink end are always kept). JavaScript regex literals and PHP heredocs
are not tokenized specially. Router mount prefixes (`app.use('/api', router)`,
Laravel `Route::prefix`) are not prepended.

### 1.2 Web/API misconfiguration (C#, JS/TS, PHP, Go, Java)

`misconfig.py` brings the configuration checks that Python already had to every
other language. Each rule is a comment-free line match; some require a companion
pattern nearby (CORS wildcard **and** credentials) or are suppressed by a
mitigation elsewhere in the file (`jwt.decode` next to `jwt.verify`, a
developer page behind `IsDevelopment()`).

| Category | CWE | Examples detected |
| :--- | :--- | :--- |
| JWT validation | CWE-347 / 287 / 613 | `ValidateIssuerSigningKey = false`, `ValidateLifetime = false`; `algorithms: ['none']`, `jwt.decode` without `jwt.verify`, `ignoreExpiration: true`; PHP `'alg' => 'none'`; Go `ParseUnverified`, `SigningMethodNone`; Java `parseClaimsJwt`, `Algorithm.none()`, `JWT.decode` without `JWT.require` |
| CORS with credentials | CWE-942 | `SetIsOriginAllowed(_ => true)` + `AllowCredentials()`; `cors({ origin: true, credentials: true })`, reflected `req.headers.origin`; PHP `Access-Control-Allow-Origin: *` / reflected `HTTP_ORIGIN` + credentials, Laravel `allowed_origins => ['*']` + `supports_credentials`; Go `AllowAllOrigins` / `AllowOriginFunc ... return true` + `AllowCredentials`; Spring `allowedOriginPatterns("*")` + `allowCredentials(true)` |
| CSRF disabled | CWE-352 | `[IgnoreAntiforgeryToken]`; Laravel `$except = ['*']` / `validateCsrfTokens(except: ['*'])`; Spring `csrf(AbstractHttpConfigurer::disable)` |
| Cookie flags | CWE-1004 / 614 | `HttpOnly = false`, `CookieSecurePolicy.None`; `httpOnly: false` in cookie/session options; `session.cookie_httponly = 0`; `http.Cookie{HttpOnly: false}`; `setHttpOnly(false)` |
| XXE | CWE-611 | `DtdProcessing.Parse`, `XmlUrlResolver`; libxmljs `noent: true`; `LIBXML_NOENT` (Java XXE is covered by the Java rules) |
| Insecure randomness | CWE-338 | `new Random()`, `Math.random()`, `mt_rand`/`uniqid`, `math/rand`, `java.util.Random` on lines that build tokens, secrets, OTPs, session ids or reset codes |
| Prototype pollution | CWE-1321 | `_.merge(target, req.body)`, `$.extend(true, ...)`, `deepmerge(...)` when a *source* argument carries request data (taint rule) |
| Debug exposure | CWE-209 | `UseDeveloperExceptionPage()` without an environment guard |

### 1.3 Risk-ranked findings ("fix first")

Severity says how bad a class of bug is; it does not say what to fix first.
Every finding gets a 0-10 risk score (`metadata.risk`):

`score = impact x exposure x evidence x confidence x exploit_intel`

| Factor | Values |
| :--- | :--- |
| Impact | RCE (command/code 10, deserialization/file inclusion 9.5) > SQL 9 > JWT/auth bypass 8.5 > SSRF/secrets/NoSQL 8 > path/XXE 7.5 > prototype pollution 7 > CORS 6.5 > XSS/TLS/CI 6 > CSRF 5.5 > randomness 5 > redirect/crypto 4.5 > cookies/misconfig 4. Configuration rules scale by their own severity. |
| Exposure | entry point of the flow: **public** (explicitly anonymous) 1.0, **unknown** (no auth marker detected - assumed reachable) 0.9, **authenticated** 0.65, **local** (CLI/job) 0.45, **internal** 0.4 |
| Evidence | proven source-to-sink flow 1.0, credential in source 0.95, unsafe configuration 0.9, pattern 0.7, dynamically built query/command without proven input 0.5 |
| Confidence | `0.7 + 0.3 x rule confidence` |
| Exploit intel | x1.2 and a P0 floor when a matched advisory is in CISA KEV (`--advisory-db`) |

Priorities: **P0** >= 8.0 (fix now), **P1** >= 6.0, **P2** >= 4.0, **P3** below.
Auth markers are detected per framework: ASP.NET `[Authorize]` /
`[AllowAnonymous]` / `RequireAuthorization()` (also on `MapGroup`), NestJS
`@UseGuards` / `@Public`, Express auth middleware in the route or a preceding
`app.use(...)`, Next.js `getServerSession()` / `auth()`, Laravel
`->middleware('auth')` and auth route groups, Symfony `#[IsGranted]`, Go auth
middleware on routes, groups or `.Use(...)`, Spring `@PreAuthorize` /
`@Secured` / `@RolesAllowed` / `@PermitAll`, Python auth decorators. A missing
marker means *unknown*, never *safe*.

The ranking drives the "Fix first" table in `ARCHITECTURE.md`, the security
report priorities, SARIF `rank` (score x 10) with `riskScore` / `riskPriority`
/ `exposure` properties, and the attack-path diagram (ordered and coloured by
priority, entry points badged with their exposure). High-level subsystems are
badged with their P0/P1 counts.

### 1.4 STRIDE threat model (`THREAT_MODEL.md`)

Written with `--format md` (security enabled) and served at
`/api/v1/threat-model`. Threats are organized per trust boundary - Internet ->
Application, Application -> Data stores, Application -> External services,
Application -> Host/runtime, Source & supply chain - with a STRIDE category, an
evidence-backed status (**observed** with the findings and their top priority,
**review** for structural signals such as entry points without detected auth,
**no evidence** when there is no matching active finding in the graph, **not assessed** for
threats static analysis cannot verify such as repudiation and rate limiting)
and a coverage overview. A boundary diagram colours each crossing by its worst
priority.

Individual source-backed records separate facts from assessments, link affected
components/assets and static data flows, and include severity, confidence,
exploitability limits and verification steps. Missing authentication markers are
informational review signals, not confirmed bypasses. The CLI also writes
`threat-model.json` with security-enabled `json` or `md` outputs. Compare versions
offline with `secdiagram threat-diff before/threat-model.json after/threat-model.json`.
See [Threat modeling](THREAT_MODELING.md) for the schema and interpretation limits.

### 1.5 MITRE ATT&CK audit gate (`secdiagram audit`)

Continuous threat modeling: the parsed architecture is evaluated against MITRE
ATT&CK techniques with the same evidence model as the STRIDE table.

```bash
# CI/CD gate - exits 1 when policy thresholds are violated:
secdiagram audit . --policy policy.yaml --json audit-result.json
```

Rules map findings and architectural signals to techniques:

| Technique | Name | Fired by |
| :--- | :--- | :--- |
| `T1190` | Exploit Public-Facing Application | Public/unknown-exposure entry points (structural **review** signal) and injection/XSS/path findings on them (**observed**) |
| `T1040` | Network Sniffing | TLS verification findings (interceptable traffic) |
| `T1078` | Valid Accounts | JWT, auth and cookie weaknesses |
| `T1552` | Unsecured Credentials | Credentials committed to source or images |
| `T1195` | Supply Chain Compromise | Supply-chain, dependency and CI pipeline findings |
| `T1068` | Exploit for Privilege Escalation | Container/cloud over-privilege findings |

Each technique gets a status (**observed** = findings, **review** = structural
signal only, **no evidence** = rules ran and matched nothing), a priority and
score from the risk model, the mitigation, and the missing mitigation. "No
evidence" is not a proof of absence.

`policy.yaml` (loaded from the audited repository root when present, otherwise
built-in defaults) defines the gate: `fail_priorities` (default `[P0, P1]`),
`min_score` (default `6.0`), `include_review` (default `false`), a `techniques`
allowlist and `ignore_techniques` exemptions. The parser is a restricted
stdlib-only YAML dialect (nested maps, lists, scalars, comments) - no third
party dependency. The plain-text summary lists every technique with status,
priority, missing mitigation and evidence; `--json` writes a deterministic
machine-readable result. Exit code `0` passes the gate, `1` violates it.

### 1.6 Attack-path diagram (`diagram-taint.mmd`)

Every tainted finding, in every language (Python and Java flows are derived from
their traces), becomes an attack path: **untrusted input -> entry point ->
each function the data passes through -> vulnerable sink** (category, CWE,
severity, `path:line`). Shared functions are drawn once, so convergent paths
and choke points stand out, and every edge on a path is coloured by the worst
severity that uses it. The same flows are highlighted in red on the detailed
`diagram.mmd`, listed under **Attack paths** in `ARCHITECTURE.md`, shown as the
**Attack paths** view in the HTML report, and summarized in
`graph.json` -> `meta.taint_flows`.

---

## 2. Infrastructure-as-Code (IaC) Rules

The engine audits infrastructure files for security misconfigurations. Every
rule carries a stable identifier (`IAC-<PLATFORM>-<NNN>`) exposed through
`Finding.metadata["rule_id"]` and used as the SARIF `ruleId`, enabling
per-rule baselines, ignore lists and CI triage:

- **Dockerfile** (`IAC-DOCKER-001..008`): unpinned base images, remote `ADD`,
  `curl|wget … | sh`, secrets baked into `ENV`/`ARG`, `chmod 777`, `sudo`
  build steps, root execution.
- **Docker Compose** (`IAC-COMPOSE-001..012`): unpinned images, privileged
  mode, host network/PID/IPC/user namespaces, Docker socket mounts,
  dangerous capabilities, unconfined seccomp/AppArmor, sensitive host path
  mounts, root user, hardcoded environment secrets.
- **GitHub Actions workflows** (`IAC-CI-001..007`): `write-all` permissions
  (inline and block forms, top-level and job-level), actions not pinned to a
  commit SHA, `pull_request_target` / `workflow_run` triggers,
  `${{ github.event.* }}` script injection (including multi-line `run:` blocks
  and Helm-style templating), secrets interpolated into shell commands.
- **GitLab CI pipelines** (`.gitlab-ci.yml`, `IAC-GITLAB-001..004`): unpinned
  remote includes, project includes with mutable refs, `curl|sh` in scripts,
  hardcoded secret variables.
- **Jenkins pipelines** (`Jenkinsfile`, `IAC-JENKINS-001..003`): `curl|sh`
  shell steps, hardcoded credential literals, `--privileged` containers.
- **Kubernetes manifests** (`IAC-K8S-001..013`): pod security standard checks
  (privileged, host namespaces, UID 0, `runAsNonRoot: false`, privilege
  escalation, writable root filesystem, automounted service account tokens,
  unconfined seccomp), hostPath volumes (including Docker sockets),
  dangerous capabilities, mutable image tags. Checks apply per-document with
  exact key/value matching to avoid false positives; non-workload kinds
  (e.g. ConfigMap) are skipped.
- **Terraform / `.tfvars`** (`IAC-TF-001..007`): open security groups
  (`0.0.0.0/0`), public storage ACLs, disabled encryption, publicly
  accessible databases, disabled public access blocks, wildcard IAM
  actions, hardcoded secrets (literals and heredocs).

YAML-backed analyzers use a deterministic, stdlib-only, indentation-aware
skeleton parser (`secdiagram_core.yaml_lite`); Helm/Jinja expressions are
treated as opaque values and never executed.

---

## 3. External Scanner Import (SonarQube & JFrog Xray)

Merge existing scanner findings into `secdiagram`'s deterministic graph, SARIF output, and architecture overlays:

```bash
# Import SonarQube issues and JFrog Xray violations with local CISA KEV validation:
secdiagram --sonarqube-report sonar-issues.json \
  --xray-report xray-violations.json \
  --advisory-db cisa-kev.json \
  --format json,md,sarif
```

- **SonarQube**: Tolerates both `{"issues": [...]}` wrappers and bare issue arrays. Security vulnerabilities and hotspots are mapped; closed, false-positive, and won't-fix issues are skipped.
- **JFrog Xray**: Accepts `violations` wrappers or component/artifact maps. Preserves package, version, CVSS score, fixed versions, and CVE identifiers.
- **Advisory Database Validation**: Corroborates CVEs against local CISA KEV, NVD, or OSV JSON files. KEV matches force `critical` severity (confidence `0.98`); multi-source matches elevate confidence to `0.97`. No outbound network calls are made.

---

## 4. Standalone Security Review (`--security-report`)

Generate a print-first security review artifact that is separate from the architectural diagram:

```bash
secdiagram --dir . --security-report both --format sarif --fail-on high
```

This writes:
- `security-report.html` — Static, A4-printable HTML report with no CDN or JavaScript dependency.
- `SECURITY_REVIEW.md` — The same review formatted in GitHub-flavored Markdown.
- `security.sarif` — OASIS SARIF v2.1.0 machine-readable export.

### Transparent Risk Index
Calculated as:
$$\text{Risk Index} = \min(100, 20 \times \text{critical} + 8 \times \text{high} + 3 \times \text{medium} + 1 \times \text{low})$$
The risk label floors at **High** for any critical finding and **Moderate** for any high finding. Baseline-suppressed findings are excluded from the risk index but retained in the evidence appendix.

---

## 5. CycloneDX 1.6 VEX Export (`--format vex`)

Generate machine-readable Vulnerability Exploitability eXchange (VEX) documents under the **CycloneDX 1.6** specification:

```bash
secdiagram --dir . --format vex --out .secdiagram
```

When a vulnerability or finding is located in code or dependencies that are unreachable from any exposed entrypoint (e.g. dead code or internal non-invoked modules), `secdiagram` automatically exports:

```json
{
  "analysis": {
    "state": "not_affected",
    "justification": "code_not_reachable",
    "detail": "AST entrypoint graph confirms no execution path from public controller to sink."
  }
}
```

This allows downstream triage tools and SBOM scanners to automatically justify non-exploitable findings without manual analyst overhead.

---

## 6. Pluggable Framework, Sanitizer & Sink Registry

Extend `secdiagram`'s detection heuristics to recognize internal microservice frameworks, custom authentication decorators, or proprietary sanitization functions.

### Configuration via `.secdiagram.yml`

Create a `.secdiagram.yml` file in the repository root:

```yaml
frameworks:
  - name: "internal-rpc"
    entrypoint_decorators:
      - "@rpc_handler"
      - "@microservice_endpoint"
    sanitizers:
      - "sanitize_db_input"
      - "clean_sql"
    sinks:
      - "internal_db_execute"
      - "vault_secret_query"

sanitizers:
  - "custom_html_escape"
  - "safe_str"

sinks:
  - "raw_system_call"
  - "dispatch_untrusted_command"
```

### Programmatic Python Registry

You can also register custom rules programmatically:

```python
from secdiagram_core.frameworks import register_framework, register_sanitizer, register_sink

register_framework(
    name="custom-gateway",
    entrypoint_decorators=["@route", "@api_action"],
    sanitizers=["escape_sql", "strip_tags"],
    sinks=["query_db", "exec_cmd"],
)

register_sanitizer("my_custom_sanitizer")
register_sink("my_custom_sink")
```

---

## 7. Security Baseline (`security.baseline.json`)

Establish a baseline of known, accepted findings to prevent breaking CI on legacy issues:

```bash
# 1. Create baseline from current scan:
secdiagram --dir . --create-baseline

# 2. In CI: fail only if NEW findings are introduced:
secdiagram --dir . --baseline .secdiagram/security.baseline.json --fail-on high
```

The baseline uses deterministic location and finding fingerprints. Suppressed counts are reported in all output artifacts.

### 7.1 Governed suppressions (schema 2)

Baselines written by `--create-baseline` use schema 2: every entry records the finding fingerprint, rule id, scope, reason, owner, approver, ticket, and expiry date. Entries created automatically are marked *pending governed triage* and suppress without expiry until an owner, approver, ticket, and `expires` date (`YYYY-MM-DD`) are filled in. Expired suppressions automatically reactivate the finding; suppressed findings remain visible in every report and in `graph.json`. Schema-1 baselines are still accepted read-only and suppress without expiry.

### 7.2 High-confidence enforcement policy

Detection and enforcement are separated: only high-risk, evidence-backed, reachable findings block CI, everything else stays informational. A finding can block only when severity is critical/high, decision confidence is >= 0.90, evidence is deterministic or externally verified, the issue is reachable from an exposed or privileged entry point, no compensating control exists, and the category is in the approved high-risk scope (verified secrets, known-exploited reachable dependencies, verified reachable injection findings). LLM-produced findings never block.

```bash
# 1. Shadow mode: record decisions, CI never fails because of them
secdiagram --dir . --policy shadow --format sarif,json

# 2. Strict mode: block decisions fail CI (exit code 2)
secdiagram --dir . --policy strict --format sarif,json
```

In SARIF output under a policy mode, `error` is reserved for `block` decisions; review and informational findings are `note`; suppressed findings are `none`. The `ARCHITECTURE.md` report gains an "Enforcement policy" section listing block decisions, required actions, and reactivated suppressions.
