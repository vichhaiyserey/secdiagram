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

### 1.2 Attack-path diagram (`diagram-taint.mmd`)

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

The engine audits infrastructure files for security misconfigurations:

- **Dockerfile**:
  - Root user execution (`USER root` or missing non-root `USER` directive).
  - Unpinned base image tags (e.g. `:latest`).
  - Sensitive files copied into image contexts.
  - Exposed privileged ports.
- **Kubernetes Manifests**:
  - Containers running without `runAsNonRoot: true`.
  - Privileged containers (`privileged: true`).
  - Dangerous capabilities (e.g. `SYS_ADMIN`).
  - Missing CPU and memory resource limits.
- **Terraform**:
  - S3 buckets configured with public read/write ACLs.
  - Unrestricted security group ingress (`0.0.0.0/0`).
  - Unencrypted storage volumes or databases.
- **GitHub Actions Workflows**:
  - `pull_request_target` triggers combined with explicit repository checkouts of untrusted code.
  - Inline script executions referencing untrusted pull request title/body expressions.

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
