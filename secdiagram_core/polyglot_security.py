"""Interprocedural taint SAST for C#/.NET, JavaScript/TypeScript, PHP and Go.

Works on the :mod:`secdiagram_core.polyglot_index` views of each file (source
text only; nothing is executed).

1. **Facts.** Every function (and each file's top level) gets its parameters,
   assignments, call sites, ``return`` expressions and sink hits.
2. **Calls.** Call sites are resolved to functions: same class / file, unique
   plain functions, ``this.x`` / ``$this->x`` / ``_x`` fields and typed
   parameters (through their declared type or its single implementer), static
   ``Class.method`` calls and Go receiver fields. Member calls on receivers
   whose type is unknown (``pool.query``) are deliberately left unresolved.
3. **Labels.** Values carry labels: ``src`` (request input) or ``p<i>``
   (flows from parameter *i*), each with the hop-by-hop trace that produced
   it. Numeric casts end a chain; sanitizers suppress the sink.
4. **Summaries.** Per function: which parameters reach which sinks and
   whether request input is returned. Summaries are composed along calls until
   a fixed point, so controller -> service -> repository chains are followed
   across files.
5. **Findings.** A sink is tainted when request input reaches it locally or
   through a call chain; the shortest flow is kept and recorded both as the
   SARIF trace and as ``metadata["flow"]`` (hop location, graph node, role)
   for the attack-path diagram.

``dynamic`` rules (SQL/command/code builders) also fire, at lower severity,
when the argument is assembled by concatenation, interpolation or formatting.
Severity and CWE choices mirror ``security.py``.
"""

from __future__ import annotations

import bisect
import re
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from .model import Finding, Graph, Loc, stable_id
from .polyglot_index import (
    JS_LANGS,
    LANGUAGE_LABELS,
    PgFile,
    PgSymbol,
    PolyglotIndex,
    _match_paren,
    symbol_node_id,
)
from .redaction import redact_secrets

ALL = frozenset({"csharp", "javascript", "typescript", "php", "go"})
CS = frozenset({"csharp"})
JS = JS_LANGS
PHP = frozenset({"php"})
GO = frozenset({"go"})

RECOMMEND = {
    "sql": "Use parameterized queries / bound parameters (SqlParameter, FromSqlInterpolated, prepared statements, "
    "query placeholders) instead of building SQL strings.",
    "command": "Avoid shells; pass a fixed executable with an argument list and allowlist/escape user input.",
    "code": "Never evaluate user-influenced code; use explicit dispatch or a safe parser.",
    "xss": "Encode output for its context (HTML-encode, templating auto-escaping) and avoid raw-HTML sinks.",
    "path": "Resolve the path against a fixed base directory, reject '..' and absolute paths, or use an allowlist.",
    "ssrf": "Validate outbound URLs against an allowlist of hosts/schemes and block internal address ranges.",
    "redirect": "Only redirect to relative paths or allowlisted hosts (e.g. Url.IsLocalUrl / LocalRedirect).",
    "deserialization": "Do not deserialize untrusted data with type-resolving serializers; use a data-only "
    "format (JSON without type names) and explicit DTOs.",
    "tls": "Keep TLS certificate verification enabled; trust a specific CA bundle instead of disabling checks.",
    "crypto": "Use modern primitives (SHA-256+, AES-GCM, bcrypt/Argon2 for passwords) instead of MD5/SHA-1/DES/RC4/ECB.",
    "nosql": "Cast filter values to expected primitive types and reject operator objects ($ne, $gt...) from input.",
    "file-inclusion": "Never include files based on user input; map identifiers to a fixed allowlist of files.",
}


@dataclass(frozen=True, slots=True)
class Rule:
    rule_id: str
    languages: frozenset[str]
    category: str
    cwe: str
    title: str
    sink: re.Pattern[str]
    mode: str  # taint | dynamic | always
    severity: str
    untainted: str | None = None
    requires: re.Pattern[str] | None = None
    sanitizer: re.Pattern[str] | None = None
    assignment: bool = False


def _r(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


XSS_SANITIZER = _r(
    r"encodeURI(?:Component)?|escape(?:Html|HTML)?\s*\(|sanitize|DOMPurify|htmlspecialchars|htmlentities|"
    r"\be\s*\(|HtmlEncoder|HtmlEncode|HTMLEscapeString|html\.EscapeString|strip_tags"
)
PATH_SANITIZER = _r(r"\bbasename\s*\(|path\.basename|Path\.GetFileName\b|filepath\.Base\b")
REDIRECT_SANITIZER = _r(r"IsLocalUrl|isLocalUrl|isSafeRedirect|allowlist|whitelist")
COMMAND_SANITIZER = _r(r"escapeshellarg|escapeshellcmd|shell-?quote|shellescape")

RULES: tuple[Rule, ...] = (
    # ----------------------------------------------------------------- C#
    Rule("PG-CS-SQL", CS, "sql", "CWE-89", "SQL injection",
         _r(r"\bnew\s+(?:Sql|Npgsql|MySql|Sqlite|Oracle|OleDb|Odbc)Command\s*\(|"
            r"\.\s*(?:FromSqlRaw|ExecuteSqlRaw(?:Async)?|SqlQueryRaw)\s*\(|"
            r"\.\s*(?:Query|QueryAsync|QueryFirst\w*|QuerySingle\w*|Execute|ExecuteAsync|ExecuteScalar\w*)"
            r"\s*(?:<[^>()]*>)?\s*\(|\.\s*CommandText\s*="),
         "dynamic", "critical", "medium"),
    Rule("PG-CS-CMD", CS, "command", "CWE-78", "Command injection",
         _r(r"\bProcess\.Start\s*\(|\bnew\s+ProcessStartInfo\s*\(|\b(?:FileName|Arguments)\s*="),
         "taint", "critical", sanitizer=COMMAND_SANITIZER),
    Rule("PG-CS-CODE", CS, "code", "CWE-95", "Dynamic code evaluation",
         _r(r"\bCSharpScript\.(?:EvaluateAsync|RunAsync|Create)\s*\("), "dynamic", "critical", "high"),
    Rule("PG-CS-DESER", CS, "deserialization", "CWE-502", "Unsafe deserializer",
         _r(r"\bnew\s+(?:BinaryFormatter|NetDataContractSerializer|LosFormatter|ObjectStateFormatter|SoapFormatter)\b|"
            r"TypeNameHandling\s*=\s*TypeNameHandling\.(?:All|Auto|Objects|Arrays)|new\s+JavaScriptSerializer\s*\(\s*new\s+SimpleTypeResolver"),
         "always", "high"),
    Rule("PG-CS-PATH", CS, "path", "CWE-22", "Path traversal",
         _r(r"\b(?:System\.IO\.)?(?:File\.(?:ReadAllText|ReadAllBytes|ReadAllLines|OpenRead|OpenWrite|Open|WriteAllText|"
            r"WriteAllBytes|AppendAllText|Delete|Copy|Move|Exists)|Directory\.(?:GetFiles|EnumerateFiles|Delete|"
            r"CreateDirectory)|PhysicalFile)\s*\(|\bnew\s+(?:FileStream|StreamReader|StreamWriter|FileInfo)\s*\("),
         "taint", "high", sanitizer=PATH_SANITIZER),
    Rule("PG-CS-SSRF", CS, "ssrf", "CWE-918", "Server-side request forgery",
         _r(r"\.\s*(?:GetAsync|GetStringAsync|GetStreamAsync|GetByteArrayAsync|GetFromJsonAsync|PostAsync|PutAsync|"
            r"DeleteAsync|PostAsJsonAsync)\s*\(|\bWebRequest\.Create\s*\(|\.\s*DownloadString(?:Async)?\s*\("),
         "taint", "high"),
    Rule("PG-CS-XSS", CS, "xss", "CWE-79", "Cross-site scripting (raw HTML)",
         _r(r"\b(?:Html\.Raw|new\s+HtmlString|new\s+MarkupString|\(MarkupString\))\s*\(?"),
         "taint", "high", sanitizer=XSS_SANITIZER),
    Rule("PG-CS-REDIRECT", CS, "redirect", "CWE-601", "Open redirect",
         _r(r"\b(?:Redirect|RedirectPermanent)\s*\(|\bResponse\.Redirect\s*\("),
         "taint", "medium", sanitizer=REDIRECT_SANITIZER),
    Rule("PG-CS-TLS", CS, "tls", "CWE-295", "TLS certificate validation disabled",
         _r(r"(?:ServerCertificateCustomValidationCallback|ServerCertificateValidationCallback|"
            r"RemoteCertificateValidationCallback)\s*\+?=\s*(?:\([^)]*\)|\w+)\s*=>\s*true\b|"
            r"DangerousAcceptAnyServerCertificateValidator"),
         "always", "high"),
    Rule("PG-CS-CRYPTO", CS, "crypto", "CWE-327", "Weak cryptographic algorithm",
         _r(r"\b(?:MD5|SHA1|DES|TripleDES|RC2)\.Create\s*\(|\bnew\s+(?:MD5|SHA1|DES|TripleDES|RC2)CryptoServiceProvider\b|"
            r"\bCipherMode\.ECB\b|\bnew\s+SHA1Managed\b"),
         "always", "medium"),
    # ------------------------------------------------------------- JS / TS
    Rule("PG-JS-SQL", JS, "sql", "CWE-89", "SQL injection",
         _r(r"\.\s*(?:query|execute|raw|whereRaw|orderByRaw|\$queryRawUnsafe|\$executeRawUnsafe|unsafe)\s*\("),
         "dynamic", "critical", "medium"),
    Rule("PG-JS-NOSQL", JS, "nosql", "CWE-943", "NoSQL operator injection",
         _r(r"\.\s*(?:find|findOne|findOneAndUpdate|updateOne|updateMany|deleteOne|deleteMany|countDocuments)\s*\(\s*"
            r"(?:req|request|ctx\.request)\.(?:body|query)\b"),
         "always", "high"),
    Rule("PG-JS-CMD", JS, "command", "CWE-78", "Command injection",
         _r(r"(?:(?<![\w$.])|\b(?:child_process|childProcess|cp)\.)(?:exec|execSync)\s*\("),
         "dynamic", "critical", "medium", requires=_r(r"child_process"), sanitizer=COMMAND_SANITIZER),
    Rule("PG-JS-SPAWN", JS, "command", "CWE-78", "Command injection",
         _r(r"(?:(?<![\w$.])|\b(?:child_process|childProcess|cp)\.)(?:spawn|spawnSync|execFile|execFileSync)\s*\("),
         "taint", "high", requires=_r(r"child_process"), sanitizer=COMMAND_SANITIZER),
    Rule("PG-JS-CODE", JS, "code", "CWE-95", "Dynamic code evaluation",
         _r(r"(?<![\w$.])eval\s*\(|\bnew\s+Function\s*\(|\bvm\.(?:runInNewContext|runInThisContext|runInContext|"
            r"compileFunction)\s*\("),
         "dynamic", "critical", "high"),
    Rule("PG-JS-XSS", JS, "xss", "CWE-79", "Cross-site scripting",
         _r(r"\.(?:innerHTML|outerHTML)\s*=|\bdocument\.write(?:ln)?\s*\(|dangerouslySetInnerHTML|"
            r"\.insertAdjacentHTML\s*\(|\b(?:res|reply)\.(?:send|write|end)\s*\("),
         "taint", "high", sanitizer=XSS_SANITIZER),
    Rule("PG-JS-PATH", JS, "path", "CWE-22", "Path traversal",
         _r(r"\bfs(?:\.promises)?\.(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|appendFile|"
            r"unlink|unlinkSync|rm|rmSync|readdir|readdirSync|createWriteStream)\s*\(|\b(?:res|reply)\.(?:sendFile|download)\s*\("),
         "taint", "high", sanitizer=PATH_SANITIZER),
    Rule("PG-JS-SSRF", JS, "ssrf", "CWE-918", "Server-side request forgery",
         _r(r"(?<![\w$.])fetch\s*\(|\baxios(?:\.(?:get|post|put|delete|patch|request|head))?\s*\(|"
            r"\bgot(?:\.(?:get|post))?\s*\(|\bhttps?\.(?:get|request)\s*\(|\bneedle\s*\("),
         "taint", "high"),
    Rule("PG-JS-REDIRECT", JS, "redirect", "CWE-601", "Open redirect",
         _r(r"\b(?:res|reply|ctx|Response|NextResponse)\.redirect\s*\(|\b(?:window\.)?location(?:\.href)?\s*=(?!=)|\blocation\.(?:assign|replace)\s*\("),
         "taint", "medium", sanitizer=REDIRECT_SANITIZER),
    Rule("PG-JS-DESER", JS, "deserialization", "CWE-502", "Unsafe deserialization",
         _r(r"\b(?:serialize\.)?unserialize\s*\("), "always", "high", requires=_r(r"node-serialize|serialize-javascript")),
    Rule("PG-JS-TLS", JS, "tls", "CWE-295", "TLS certificate validation disabled",
         _r(r"\brejectUnauthorized\s*:\s*false\b|NODE_TLS_REJECT_UNAUTHORIZED['\"]?\s*\]?\s*=\s*['\"]?0|\bstrictSSL\s*:\s*false\b"),
         "always", "high"),
    Rule("PG-JS-CRYPTO", JS, "crypto", "CWE-327", "Weak cryptographic algorithm",
         _r(r"\bcreateHash\s*\(\s*['\"](?:md5|sha1|md4)['\"]|\bcreateCipher(?:iv)?\s*\(\s*['\"](?:des|des-ede3?|rc4|bf|"
            r"aes-\d+-ecb)[\w-]*['\"]"),
         "always", "medium"),
    # ----------------------------------------------------------------- PHP
    Rule("PG-PHP-SQL", PHP, "sql", "CWE-89", "SQL injection",
         _r(r"\b(?:mysqli_query|mysql_query|mysqli_multi_query|pg_query|sqlsrv_query|sqlite_query)\s*\(|"
            r"->\s*(?:query|exec|prepare|multi_query|whereRaw|selectRaw|orderByRaw|havingRaw|statement|unprepared)\s*\(|"
            r"\bDB::(?:select|statement|unprepared|raw|insert|update|delete)\s*\("),
         "dynamic", "critical", "medium"),
    Rule("PG-PHP-CMD", PHP, "command", "CWE-78", "Command injection",
         _r(r"(?<![\w>:$])(?:exec|system|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(|`[^`]*\$"),
         "dynamic", "critical", "medium", sanitizer=COMMAND_SANITIZER),
    Rule("PG-PHP-CODE", PHP, "code", "CWE-95", "Dynamic code evaluation",
         _r(r"(?<![\w>:$])(?:eval|assert|create_function)\s*\(|\bpreg_replace\s*\(\s*['\"][^'\"]*/[a-zA-Z]*e[a-zA-Z]*['\"]"),
         "dynamic", "critical", "high"),
    Rule("PG-PHP-INCLUDE", PHP, "file-inclusion", "CWE-98", "File inclusion",
         _r(r"\b(?:include|include_once|require|require_once)\b\s*\(?\s*(?=[^'\";\s])"), "taint", "critical"),
    Rule("PG-PHP-DESER", PHP, "deserialization", "CWE-502", "Unsafe deserialization",
         _r(r"(?<![\w>:$])unserialize\s*\("), "dynamic", "high", "medium"),
    Rule("PG-PHP-XSS", PHP, "xss", "CWE-79", "Cross-site scripting",
         _r(r"<\?=|(?<![\w>$])(?:echo|print)\b|(?<![\w>$])printf\s*\("), "taint", "high", sanitizer=XSS_SANITIZER),
    Rule("PG-PHP-PATH", PHP, "path", "CWE-22", "Path traversal",
         _r(r"(?<![\w>:$])(?:file_get_contents|fopen|readfile|file|unlink|file_put_contents|copy|rename|opendir|scandir|"
            r"move_uploaded_file)\s*\("),
         "taint", "high", sanitizer=PATH_SANITIZER),
    Rule("PG-PHP-SSRF", PHP, "ssrf", "CWE-918", "Server-side request forgery",
         _r(r"\bcurl_init\s*\(|CURLOPT_URL|\bHttp::(?:get|post|put|delete)\s*\(|->\s*request\s*\(\s*['\"]\w+['\"]\s*,"),
         "taint", "high"),
    Rule("PG-PHP-REDIRECT", PHP, "redirect", "CWE-601", "Open redirect",
         _r(r"\bheader\s*\(\s*['\"]Location:|\bredirect\s*\(|->\s*away\s*\("), "taint", "medium", sanitizer=REDIRECT_SANITIZER),
    Rule("PG-PHP-TLS", PHP, "tls", "CWE-295", "TLS certificate validation disabled",
         _r(r"CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)\b|CURLOPT_SSL_VERIFYHOST\s*,\s*(?:false|0)\b|['\"]verify['\"]\s*=>\s*false\b|"
            r"['\"]verify_peer['\"]\s*=>\s*false\b"),
         "always", "high"),
    Rule("PG-PHP-CRYPTO", PHP, "crypto", "CWE-328", "Weak password hashing",
         _r(r"\b(?:md5|sha1)\s*\(\s*\$\w*(?:pass|pwd|secret)\w*"), "always", "medium"),
    # ------------------------------------------------------------------ Go
    Rule("PG-GO-SQL", GO, "sql", "CWE-89", "SQL injection",
         _r(r"\.\s*(?:Query|QueryRow|QueryContext|QueryRowContext|Exec|ExecContext|Raw|Prepare|PrepareContext)\s*\("),
         "dynamic", "critical", "medium"),
    Rule("PG-GO-CMD", GO, "command", "CWE-78", "Command injection",
         _r(r"\bexec\.Command(?:Context)?\s*\("), "taint", "critical", sanitizer=COMMAND_SANITIZER),
    Rule("PG-GO-PATH", GO, "path", "CWE-22", "Path traversal",
         _r(r"\b(?:os\.(?:Open|OpenFile|ReadFile|Create|Remove|RemoveAll|WriteFile|ReadDir)|ioutil\.(?:ReadFile|WriteFile|"
            r"ReadDir)|http\.ServeFile|c\.(?:File|FileAttachment))\s*\("),
         "taint", "high", sanitizer=PATH_SANITIZER),
    Rule("PG-GO-SSRF", GO, "ssrf", "CWE-918", "Server-side request forgery",
         _r(r"\bhttp\.(?:Get|Post|Head|PostForm|NewRequest(?:WithContext)?)\s*\(|\bclient\.(?:Get|Post|Head)\s*\("),
         "taint", "high"),
    Rule("PG-GO-XSS", GO, "xss", "CWE-79", "Cross-site scripting",
         _r(r"\btemplate\.HTML\s*\(|\bfmt\.Fprint(?:f|ln)?\s*\(\s*w\s*,|\bw\.Write\s*\(|\bio\.WriteString\s*\(\s*w\s*,"),
         "taint", "high", sanitizer=XSS_SANITIZER),
    Rule("PG-GO-REDIRECT", GO, "redirect", "CWE-601", "Open redirect",
         _r(r"\bhttp\.Redirect\s*\(|\bc\.Redirect\s*\("), "taint", "medium", sanitizer=REDIRECT_SANITIZER),
    Rule("PG-GO-TLS", GO, "tls", "CWE-295", "TLS certificate validation disabled",
         _r(r"\bInsecureSkipVerify\s*:\s*true\b"), "always", "high"),
    Rule("PG-GO-CRYPTO", GO, "crypto", "CWE-327", "Weak cryptographic algorithm",
         _r(r"\b(?:md5|sha1)\.(?:New|Sum)\b|\b(?:des\.NewCipher|des\.NewTripleDESCipher|rc4\.NewCipher)\b"),
         "always", "medium"),
)

SOURCES: dict[str, re.Pattern[str]] = {
    "csharp": _r(
        r"\b(?:Request|HttpContext\.Request|context\.Request|ctx\.Request)\.(?:Query|Form|Headers|Cookies|Body|"
        r"RouteValues|Path|QueryString)\b|\bConsole\.ReadLine\s*\(|\bEnvironment\.GetCommandLineArgs\b"
    ),
    "js": _r(
        r"\b(?:req|request|ctx\.request)\.(?:query|params|body|headers|cookies|url|originalUrl|path|files?|hostname)\b|"
        r"\bctx\.(?:query|params|querystring)\b|\bevent\.(?:body|queryStringParameters|pathParameters|headers)\b|"
        r"\bsearchParams\.get\s*\(|\b(?:request|req)\.(?:json|text|formData)\s*\(|\bprocess\.argv\b|"
        r"\b(?:window\.)?location\.(?:search|hash|href)\b|\bdocument\.(?:URL|referrer|cookie)\b|"
        r"\bc\.req\.(?:query|param|json|header|parseBody)\s*\("
    ),
    "php": _r(
        r"\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b|\$request\s*->\s*(?:input|get|query|post|all|route|header|"
        r"cookie|file|json)\s*\(|\$request\s*->\s*(?:query|request|attributes|cookies|headers|files)\s*->\s*get\s*\(|"
        r"\bRequest::(?:input|get|query|all)\s*\(|\brequest\s*\(\s*(?:\)|['\"])|php://input"
    ),
    "go": _r(
        r"\.URL\.Query\s*\(\s*\)|\.URL\.(?:Path|RawQuery)\b|\.(?:FormValue|PostFormValue|FormFile)\s*\(|\bmux\.Vars\s*\(|"
        r"\bchi\.URLParam\s*\(|\bc\.(?:Query|DefaultQuery|Param|PostForm|DefaultPostForm|GetHeader|QueryParam|"
        r"FormValue|Cookie|QueryArray|GetQuery|Params\.ByName)\s*\(|\br\.(?:Body|Header)\b|\bos\.Args\b"
    ),
}
NUMERIC_CAST_RE = _r(
    r"^\s*(?:\(\s*int\s*\)|parseInt\s*\(|parseFloat\s*\(|Number\s*\(|Math\.\w+\s*\(|int\.Parse\s*\(|int\.TryParse|"
    r"long\.Parse\s*\(|Guid\.Parse\s*\(|Convert\.ToInt\d*\s*\(|intval\s*\(|floatval\s*\(|(?:\(int\)|\(float\))|"
    r"strconv\.(?:Atoi|ParseInt|ParseFloat|ParseBool)\s*\(|uuid\.Parse\s*\(|filter_var\s*\([^,]+,\s*FILTER_VALIDATE_INT)"
)
ASSIGN_RES: dict[str, re.Pattern[str]] = {
    "csharp": _r(r"(?:\b(?:var|[\w<>\[\],.?]+)\s+)?\b([A-Za-z_]\w*)\s*(?:\+=|=)(?![=>])\s*(.+)"),
    "js": _r(r"(?:\b(?:const|let|var)\s+)?(\{[^}]*\}|\[[^\]]*\]|[A-Za-z_$][\w$]*)\s*(?::\s*[\w<>\[\]|. ]+)?\s*(?:\+=|=)(?![=>])\s*(.+)"),
    "php": _r(r"(\$\w+)\s*(?:\.=|=)(?![=>])\s*(.+)"),
    "go": _r(r"^\s*(?:var\s+)?([\w\s,]+?)\s*(?::=|=)(?!=)\s*(.+)"),
}
GO_BIND_RE = _r(r"\.(?:ShouldBind\w*|Bind\w*|Decode|Unmarshal)\s*\((?:[^,()]*,\s*)?&(\w+)")
DYNAMIC_RES: dict[str, re.Pattern[str]] = {
    "csharp": _r(r"\$@?\"[^\"]*\{|@\$\"[^\"]*\{|\"\s*\+|\+\s*\"|\b(?:string|String)\.(?:Format|Concat)\s*\("),
    "js": _r(r"`[^`]*\$\{|['\"`]\s*\+|\+\s*['\"`]|\.concat\s*\(|\butil\.format\s*\("),
    "php": _r(r"\"[^\"]*\$\w|\"[^\"]*\{\$|['\"]\s*\.\s*\$|\$\w+(?:\[[^\]]*\])?\s*\.\s*['\"]|\bsprintf\s*\(|\bimplode\s*\("),
    "go": _r(r"\bfmt\.Sprintf\s*\(|\"\s*\+|\+\s*\"|\bstrings\.Join\s*\("),
}


def _family(language: str) -> str:
    return "js" if language in JS_LANGS else language


# ----------------------------------------------------------------- taint model

MAX_HOPS = 14
MAX_TARGETS = 3
MAX_SUMMARY_UPDATES = 200_000  # safety valve; summaries are monotone so this is never hit in practice


@dataclass(frozen=True, slots=True)
class _Hop:
    """One step of a taint flow: where it is, which graph node, and what happens."""

    path: str
    line: int
    node_id: str | None
    role: str  # source | param | call | propagation | return | sink


Trace = tuple[_Hop, ...]
Labels = dict[str, Trace]  # "src" or "p<i>" -> trace from origin


def _extend(trace: Trace, hop: _Hop) -> Trace:
    if trace and trace[-1].path == hop.path and trace[-1].line == hop.line and trace[-1].node_id == hop.node_id:
        return trace
    extended = trace + (hop,)
    if len(extended) > MAX_HOPS:
        # Keep the origin (where input enters) and the most recent hops (the sink side).
        extended = extended[:3] + extended[-(MAX_HOPS - 3) :]
    return extended


def _better(a: Trace | None, b: Trace) -> bool:
    """True when *b* should replace *a* (shorter, then lexicographically smaller)."""
    if a is None:
        return True
    key_a = (len(a), [(h.path, h.line, h.role) for h in a])
    key_b = (len(b), [(h.path, h.line, h.role) for h in b])
    return key_b < key_a


@dataclass(slots=True)
class _Call:
    pos: int
    line: int
    name: str
    receiver: str
    args: list[tuple[int, int]]
    targets: list[_Fn] = field(default_factory=list)


@dataclass(slots=True)
class _Sink:
    pos: int
    line: int
    rule: Rule
    order: int
    arg_start: int
    arg_end: int
    assignment: bool
    line_text: str


@dataclass(slots=True)
class _Fn:
    pf: PgFile
    sym: PgSymbol | None
    start: int
    end: int
    node_id: str | None
    owner: str = ""
    receiver_var: str = ""
    params: list[list[str]] = field(default_factory=list)
    param_types: dict[str, str] = field(default_factory=dict)
    assigns: list[tuple[int, int, list[str], int, int]] = field(default_factory=list)  # pos, line, lhs, rhs s/e
    binds: list[tuple[int, int, str, bool]] = field(default_factory=list)  # pos, line, var, from binder
    calls: list[_Call] = field(default_factory=list)
    call_positions: list[int] = field(default_factory=list)
    returns: list[tuple[int, int, int]] = field(default_factory=list)  # line, start, end
    sinks: list[_Sink] = field(default_factory=list)
    # results
    env: dict[str, Labels] = field(default_factory=dict)
    dynamic: set[str] = field(default_factory=set)
    sanitized: set[str] = field(default_factory=set)
    returns_src: Trace | None = None
    param_sinks: dict[int, dict[tuple[str, int, int], Trace]] = field(default_factory=dict)

    @property
    def family(self) -> str:
        return _family(self.pf.language)


# ------------------------------------------------------------------ fact extraction

CALL_SITE_RE = re.compile(
    r"((?:\$?[A-Za-z_][\w]*\s*(?:\?\.|->|::|\.)\s*)*)(?<![\w$])([A-Za-z_$][\w$]*)\s*\("
)
NOT_CALLS = frozenset(
    {"if", "for", "foreach", "while", "switch", "catch", "function", "return", "typeof", "sizeof", "nameof",
     "using", "lock", "fixed", "func", "await", "new", "throw", "echo", "print", "isset", "empty", "unset",
     "array", "list", "elseif", "match", "when", "with", "super", "base"}
)
RETURN_RE = re.compile(r"\breturn\b")
INTERP_RE = re.compile(r"\$\{([^}]*)\}|(?<![\w$])\{([A-Za-z_][\w.]*)\}|(\$\w+)")
IDENT_RE = re.compile(r"(?<![\w$.>:])[$]?[A-Za-z_$][\w$]*")
NON_VALUE_WORDS = frozenset({"new", "null", "nil", "true", "false", "this", "self", "await", "string", "String", "fmt",
                             "Sprintf", "Format", "Concat", "sprintf", "implode", "util", "format", "strings", "Join"})
NEW_VAR_RE = re.compile(
    r"(?:\b(?:const|let|var|final|readonly)\s+|\b[A-Z][\w<>,.?]*\s+)?(\$?[A-Za-z_]\w*)\s*(?::=|=)\s*"
    r"(?:new\s+([A-Za-z_][\w.\\]*)|&?([A-Z]\w*)\s*\{|New([A-Z]\w*)\s*\()"
)
GO_RECEIVER_RE = re.compile(r"^\s*func\s*\(\s*(\w+)\s+\*?\s*\w+")
FIELD_RES: dict[str, tuple[re.Pattern[str], ...]] = {
    "csharp": (
        re.compile(
            r"^\s*(?:\[[^\]]*\]\s*)*(?:(?:public|private|protected|internal|static|readonly|required|volatile)\s+)*"
            r"([A-Za-z_][\w.]*(?:<[^;=()]*>)?\??)\s+(_?[A-Za-z_]\w*)\s*(?:;|=[^>]|\{\s*get)"
        ),
    ),
    "js": (
        re.compile(r"(?:private|public|protected|readonly)\s+(?:readonly\s+)?([A-Za-z_$][\w$]*)\s*[!?]?\s*:\s*([A-Za-z_$][\w$.]*)"),
    ),
    "php": (
        re.compile(r"(?:private|public|protected)\s+(?:readonly\s+)?\??([A-Za-z_\\][\w\\]*)\s+\$(\w+)"),
    ),
    "go": (re.compile(r"^\s*(\w+)\s+\*?\[?\]?\*?([A-Za-z_][\w.]*)\s*(?:`[^`]*`)?\s*$"),),
}


def _value_text(pf: PgFile, start: int, end: int) -> str:
    """Argument code with string contents removed but interpolations kept.

    ``"WHERE id = @id"`` must not match a variable ``id``, while ``$"...{id}"``,
    `` `${id}` `` and PHP ``"$id"`` must.
    """
    parts = [pf.masked[start:end]]
    for groups in INTERP_RE.findall(pf.code[start:end]):
        parts.extend(group for group in groups if group)
    return " ".join(parts)


def _split_top_level(pf: PgFile, start: int, end: int) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    depth = 0
    seg = start
    for k in range(start, end):
        ch = pf.masked[k]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            ranges.append((seg, k))
            seg = k + 1
    if pf.masked[seg:end].strip():
        ranges.append((seg, end))
    return ranges


def _argument_range(pf: PgFile, match_end: int, assignment: bool) -> tuple[int, int]:
    code = pf.code
    if assignment or code[match_end - 1 : match_end] != "(":
        stop = code.find(";", match_end)
        newline = code.find("\n", match_end)
        candidates = [c for c in (stop, newline) if c != -1]
        return match_end, (min(candidates) if candidates else len(code))
    close = _match_paren(pf, match_end - 1)
    if close == -1:
        newline = code.find("\n", match_end)
        return match_end, (newline if newline != -1 else len(code))
    return match_end, close


def _param_names(param: str, family: str) -> tuple[list[str], str]:
    """Names bound by one declared parameter, plus its declared type (if any)."""
    text = re.sub(r"@\w+\s*\([^)]*\)\s*", "", param)
    text = re.sub(r"\[[^\]]*\]\s*", "", text) if family == "csharp" else text
    text = text.split("=", 1)[0].strip()
    if family == "php":
        match = re.search(r"(\??[A-Za-z_\\][\w\\]*)?\s*&?(?:\.\.\.)?(\$\w+)\s*$", re.sub(
            r"^(?:(?:public|private|protected|readonly)\s+)+", "", text))
        return ([match.group(2)], (match.group(1) or "").lstrip("?")) if match else ([], "")
    if family == "js":
        text = re.sub(r"^(?:(?:public|private|protected|readonly)\s+)+", "", text)
        if text.startswith(("{", "[")):
            inner = text[1 : text.find("}" if text.startswith("{") else "]")] if ("}" in text or "]" in text) else ""
            names = [p.split(":")[-1].strip() for p in inner.split(",")]
            return [n for n in names if re.match(r"^[A-Za-z_$][\w$]*$", n)], ""
        name, _, typ = text.partition(":")
        name = name.strip().rstrip("?").lstrip(".")
        return ([name] if re.match(r"^[A-Za-z_$][\w$]*$", name) else []), typ.strip()
    if family == "go":
        parts = text.split()
        if not parts:
            return [], ""
        typ = parts[1] if len(parts) > 1 else ""
        return ([parts[0]] if re.match(r"^[A-Za-z_]\w*$", parts[0]) else []), typ.lstrip("*")
    text = re.sub(r"^(?:this|params|ref|out|in|scoped)\s+", "", text)
    pieces = text.rsplit(None, 1)
    if len(pieces) == 2 and re.match(r"^[A-Za-z_]\w*$", pieces[1]):
        return [pieces[1]], pieces[0]
    return [], ""


def _owner_of(sym: PgSymbol | None, pf: PgFile) -> str:
    if sym is None:
        return ""
    if sym.container:
        return _simple_type(sym.container)
    if pf.language == "go" and sym.decl_kind == "method":
        parts = sym.qualname.split(".")
        return parts[-2] if len(parts) >= 2 else ""
    return ""


def _simple_type(name: str) -> str:
    name = re.sub(r"<.*", "", name.strip())
    name = name.replace("\\", ".").replace("::", ".").rstrip("?*&[] ").lstrip("?*&[] ")
    # JS/TS qualnames are "path/to/file.ts:ClassName".
    return re.split(r"[.:/]", name)[-1]


def _fn_node_id(graph: Graph, pf: PgFile, sym: PgSymbol | None) -> str | None:
    if sym is None:
        module_id = stable_id("pg", pf.language, "module", pf.path, pf.path)
        return module_id if module_id in graph.nodes else None
    node_id = symbol_node_id(pf, sym)
    return node_id if node_id in graph.nodes else None


def _collect_facts(graph: Graph, index: PolyglotIndex) -> list[_Fn]:
    fns: list[_Fn] = []
    for path in sorted(index.files):
        pf = index.files[path]
        family = _family(pf.language)
        file_fn = _Fn(pf=pf, sym=None, start=0, end=len(pf.code), node_id=_fn_node_id(graph, pf, None))
        scoped = [
            _Fn(pf=pf, sym=sym, start=sym.body_start, end=sym.body_end, node_id=_fn_node_id(graph, pf, sym),
                owner=_owner_of(sym, pf))
            for sym in pf.symbols
            if sym.kind != "class" and sym.has_body
        ]
        code_lines = pf.code.split("\n")
        for fn in scoped:
            assert fn.sym is not None
            for raw in fn.sym.params:
                names, typ = _param_names(raw, family)
                fn.params.append(names)
                for name in names:
                    if typ:
                        fn.param_types[name] = typ
            if pf.language == "go":
                receiver = GO_RECEIVER_RE.match(code_lines[fn.sym.line - 1])
                fn.receiver_var = receiver.group(1) if receiver else ""
            if pf.masked[fn.start] != "{":
                fn.returns.append((pf.line_of(fn.start), fn.start + 2, fn.end))
        items: list[tuple[int, int, str, Any]] = []
        assign_re = ASSIGN_RES[family]
        line_start = 0
        for line_no, masked_line in enumerate(pf.masked.split("\n"), start=1):
            seg_start = 0
            for seg in masked_line.split(";"):
                abs_start = line_start + seg_start
                code_seg = pf.code[abs_start : abs_start + len(seg)]
                match = assign_re.search(code_seg)
                if match and match.group(1) and match.group(2) is not None:
                    names = _names_from_lhs(match.group(1).strip(), family)
                    if names:
                        op_pos = abs_start + match.end(1)
                        items.append((op_pos, 0, "assign", (line_no, names, abs_start + match.start(2), abs_start + len(seg))))
                if family == "go":
                    for bind in GO_BIND_RE.finditer(code_seg):
                        binder = bool(re.search(r"\.(?:ShouldBind\w*|Bind\w*)\s*\(", code_seg))
                        items.append((abs_start + bind.start(), 1, "bind", (line_no, bind.group(1), binder, abs_start, abs_start + len(seg))))
                for ret in RETURN_RE.finditer(seg):
                    items.append((abs_start + ret.start(), 2, "return", (line_no, abs_start + ret.end(), abs_start + len(seg))))
                seg_start += len(seg) + 1
            line_start += len(masked_line) + 1
        for match in CALL_SITE_RE.finditer(pf.masked):
            name = match.group(2)
            if name in NOT_CALLS or pf.masked[max(0, match.start(2) - 4) : match.start(2)] == "new ":
                continue
            open_pos = match.end() - 1
            close = _match_paren(pf, open_pos)
            if close == -1:
                continue
            recv_text = re.sub(r"\s+", "", match.group(1) or "")
            recv_text = recv_text.replace("?.", ".").replace("->", ".").replace("::", ".").rstrip(".")
            items.append(
                (match.start(2), 3, "call",
                 _Call(pos=match.start(2), line=pf.line_of(match.start(2)), name=name, receiver=recv_text,
                       args=_split_top_level(pf, open_pos + 1, close)))
            )
        rules = [r for r in RULES if pf.language in r.languages and (r.requires is None or r.requires.search(pf.code))]
        line_starts = [0] + [m.end() for m in re.finditer("\n", pf.code)]
        for order, rule in enumerate(rules):
            for match in rule.sink.finditer(pf.code):
                pos = match.start()
                if pf.masked[pos] == " " and not pf.code[pos].isspace():
                    continue  # sink text inside a string literal
                line_no = pf.line_of(pos)
                newline = pf.code.find("\n", pos)
                line_text = pf.code[line_starts[line_no - 1] : newline if newline != -1 else len(pf.code)]
                assignment = match.group(0).rstrip().endswith("=")
                arg_start, arg_end = _argument_range(pf, match.end(), assignment)
                if rule.category == "sql" and not assignment:
                    parts = _split_top_level(pf, arg_start, arg_end)
                    if parts:
                        arg_end = parts[0][1]
                items.append(
                    (pos, 4 + order, "sink",
                     _Sink(pos=pos, line=line_no, rule=rule, order=order, arg_start=arg_start, arg_end=arg_end,
                           assignment=assignment, line_text=line_text))
                )
        _assign_to_scopes(items, scoped, file_fn)
        for fn in scoped + [file_fn]:
            fn.call_positions = [call.pos for call in fn.calls]
        fns.extend(scoped)
        fns.append(file_fn)
    return fns


def _assign_to_scopes(items: list[tuple[int, int, str, Any]], scoped: list[_Fn], file_fn: _Fn) -> None:
    """Attach every statement/call/sink to its innermost function (single sweep)."""
    ordered = sorted(scoped, key=lambda fn: (fn.start, -fn.end))
    stack: list[_Fn] = []
    nxt = 0
    for pos, _prio, kind, payload in sorted(items, key=lambda item: (item[0], item[1])):
        while nxt < len(ordered) and ordered[nxt].start <= pos:
            while stack and stack[-1].end < ordered[nxt].start:
                stack.pop()
            stack.append(ordered[nxt])
            nxt += 1
        while stack and stack[-1].end < pos:
            stack.pop()
        fn = stack[-1] if stack else file_fn
        if kind == "assign":
            line, names, rhs_start, rhs_end = payload
            fn.assigns.append((pos, line, names, rhs_start, rhs_end))
        elif kind == "bind":
            line, var, binder, seg_start, seg_end = payload
            fn.binds.append((pos, line, var, binder))
            fn.assigns.append((pos, line, [], seg_start, seg_end))  # keeps statement order for binds
        elif kind == "return":
            line, start, end = payload
            fn.returns.append((line, start, end))
        elif kind == "call":
            fn.calls.append(payload)
        else:
            fn.sinks.append(payload)


# -------------------------------------------------------------- call resolution


def _class_tables(index: PolyglotIndex) -> tuple[dict[tuple[str, str], list[tuple[PgFile, PgSymbol]]], dict[tuple[str, str], list[str]]]:
    classes: dict[tuple[str, str], list[tuple[PgFile, PgSymbol]]] = {}
    implementers: dict[tuple[str, str], list[str]] = {}
    for path in sorted(index.files):
        pf = index.files[path]
        family = _family(pf.language)
        for sym in pf.symbols:
            if sym.kind != "class":
                continue
            classes.setdefault((family, sym.name), []).append((pf, sym))
            for base in sym.bases:
                implementers.setdefault((family, _simple_type(base)), []).append(sym.name)
    return classes, implementers


def _field_types(pf: PgFile, cls: PgSymbol) -> dict[str, str]:
    """Declared field/property/promoted-parameter types of a class (name -> type)."""
    family = _family(pf.language)
    types: dict[str, str] = {}
    if not cls.has_body:
        return types
    body_code = pf.code[cls.body_start : cls.body_end]
    body_masked = pf.masked[cls.body_start : cls.body_end]
    pattern = FIELD_RES[family][0]
    if family == "csharp":
        for line in body_masked.split("\n"):
            match = pattern.match(line)
            if match:
                types.setdefault(match.group(2), match.group(1))
    elif family == "go":
        for line in body_masked.split("\n"):
            match = pattern.match(line)
            if match:
                types.setdefault(match.group(1), match.group(2))
    elif family == "js":
        for match in pattern.finditer(body_code):
            types.setdefault(match.group(1), match.group(2))
    else:
        for match in pattern.finditer(body_code):
            types.setdefault("$" + match.group(2), match.group(1))
    for raw in cls.params:  # C# 12 primary constructors
        names, typ = _param_names(raw, family)
        for name in names:
            if typ:
                types.setdefault(name, typ)
    return types


class _Resolver:
    def __init__(self, index: PolyglotIndex, fns: list[_Fn]) -> None:
        self.classes, self.implementers = _class_tables(index)
        self.by_owner: dict[tuple[str, str, str], list[_Fn]] = {}
        self.by_name: dict[tuple[str, str], list[_Fn]] = {}
        for fn in fns:
            if fn.sym is None:
                continue
            key_name = fn.sym.name
            if fn.sym.decl_kind == "route":
                continue
            if fn.owner:
                self.by_owner.setdefault((fn.family, fn.owner, key_name), []).append(fn)
            else:
                self.by_name.setdefault((fn.family, key_name), []).append(fn)
        self.local_types: dict[str, dict[str, str]] = {}
        for path in sorted(index.files):
            pf = index.files[path]
            types: dict[str, str] = {}
            for match in NEW_VAR_RE.finditer(pf.masked):
                typ = match.group(2) or match.group(3) or match.group(4)
                if typ:
                    types.setdefault(match.group(1), typ)
            self.local_types[path] = types
        self.fields: dict[tuple[str, str], dict[str, str]] = {}
        for (family, name), entries in sorted(self.classes.items()):
            merged: dict[str, str] = {}
            for pf, cls in entries:
                for k, v in _field_types(pf, cls).items():
                    merged.setdefault(k, v)
            self.fields[(family, name)] = merged

    def _methods_of_type(self, family: str, type_name: str, method: str) -> list[_Fn]:
        simple = _simple_type(type_name)
        if not simple:
            return []
        owners = [simple] + sorted(set(self.implementers.get((family, simple), [])))
        out: list[_Fn] = []
        for owner in owners:
            out.extend(self.by_owner.get((family, owner, method), []))
        return out[:MAX_TARGETS]

    def resolve(self, fn: _Fn, call: _Call) -> list[_Fn]:
        family = fn.family
        receiver = call.receiver
        if not receiver:
            if fn.owner:
                same = self.by_owner.get((family, fn.owner, call.name), [])
                if same:
                    return same[:1]
            local = [f for f in self.by_name.get((family, call.name), []) if f.pf.path == fn.pf.path]
            if local:
                return local[:1]
            unique = self.by_name.get((family, call.name), [])
            return unique if len(unique) == 1 else []
        parts = receiver.split(".")
        head = parts[0]
        self_names = {"this", "$this", "self", "static"}
        if fn.receiver_var:
            self_names.add(fn.receiver_var)
        if head in self_names and len(parts) == 1:
            return self.by_owner.get((family, fn.owner, call.name), [])[:MAX_TARGETS] if fn.owner else []
        fields = self.fields.get((family, fn.owner), {}) if fn.owner else {}
        if head in self_names and len(parts) == 2:
            field_name = parts[1] if family != "php" else "$" + parts[1]
            typ = fields.get(field_name) or fields.get(parts[1])
            return self._methods_of_type(family, typ, call.name) if typ else []
        if len(parts) == 1:
            typ = fn.param_types.get(head) or fields.get(head) or self.local_types.get(fn.pf.path, {}).get(head)
            if typ:
                return self._methods_of_type(family, typ, call.name)
            if (family, head) in self.classes:  # static call: Class.method / Class::method
                return self._methods_of_type(family, head, call.name)
        return []


# --------------------------------------------------------------- propagation


def _names_from_lhs(lhs: str, family: str) -> list[str]:
    if family == "php":
        return re.findall(r"\$\w+", lhs)
    if lhs.startswith(("{", "[")):
        inner = re.sub(r"\.\.\.", "", lhs[1:-1])
        names = []
        for part in inner.split(","):
            part = part.split("=")[0]
            names.append(part.split(":")[-1].strip())
        return [n for n in names if re.match(r"^[A-Za-z_$][\w$]*$", n)]
    if family == "go":
        return [n for n in (p.strip() for p in lhs.split(",")) if re.match(r"^[A-Za-z_]\w*$", n) and n != "_"]
    return [lhs.strip()] if re.match(r"^[A-Za-z_$][\w$]*$", lhs.strip()) else []


def _merge(target: Labels, label: str, trace: Trace) -> bool:
    if _better(target.get(label), trace):
        target[label] = trace
        return True
    return False


def _labels_of(fn: _Fn, start: int, end: int) -> Labels:
    """Taint labels carried by the code in ``[start, end)`` of *fn*."""
    pf = fn.pf
    code = pf.code[start:end].strip()
    if NUMERIC_CAST_RE.match(code) and code.endswith(")"):
        return {}
    values = _value_text(pf, start, end)
    out: Labels = {}
    line = pf.line_of(start)
    if SOURCES[fn.family].search(values):
        out["src"] = (_Hop(pf.path, line, fn.node_id, "source"),)
    for ident in set(IDENT_RE.findall(values)):
        for label, trace in fn.env.get(ident, {}).items():
            _merge(out, label, trace)
    lo = bisect.bisect_left(fn.call_positions, start)
    hi = bisect.bisect_left(fn.call_positions, end)
    for call in fn.calls[lo:hi]:
        for target in call.targets:
            if target.returns_src is not None:
                hop = _Hop(pf.path, call.line, fn.node_id, "call")
                _merge(out, "src", _extend(target.returns_src, hop))
    return out


def _propagate_fn(fn: _Fn) -> None:
    """Intra-procedural label propagation using current callee summaries."""
    pf = fn.pf
    fn.env = {}
    for i, names in enumerate(fn.params):
        for name in names:
            fn.env.setdefault(name, {})[f"p{i}"] = (_Hop(pf.path, fn.sym.line if fn.sym else 1, fn.node_id, "param"),)
    if fn.sym is not None:
        for name in fn.sym.tainted_params:
            fn.env.setdefault(name, {})["src"] = (_Hop(pf.path, fn.sym.line, fn.node_id, "source"),)
    fn.dynamic = set()
    fn.sanitized = set()
    dynamic_re = DYNAMIC_RES[fn.family]
    binds = {pos: (line, var, binder) for pos, line, var, binder in fn.binds}
    for _ in range(3):
        changed = False
        for pos, line, names, rhs_start, rhs_end in fn.assigns:
            if pos in binds:
                bline, var, binder = binds[pos]
                labels = _labels_of(fn, rhs_start, rhs_end)
                if binder:
                    labels.setdefault("src", (_Hop(pf.path, bline, fn.node_id, "source"),))
                for label, trace in labels.items():
                    changed |= _merge(fn.env.setdefault(var, {}), label, _extend(trace, _Hop(pf.path, bline, fn.node_id, "propagation")))
                continue
            rhs_code = pf.code[rhs_start:rhs_end]
            if dynamic_re.search(rhs_code):
                fn.dynamic.update(names)
            if NUMERIC_CAST_RE.match(rhs_code):
                fn.sanitized.update(names)
                continue
            labels = _labels_of(fn, rhs_start, rhs_end)
            for label, trace in labels.items():
                hop = _Hop(pf.path, line, fn.node_id, "propagation")
                for name in names:
                    changed |= _merge(fn.env.setdefault(name, {}), label, _extend(trace, hop))
        if not changed:
            break


def _sink_key(fn: _Fn, sink: _Sink) -> tuple[str, int, int]:
    return (fn.pf.path, sink.pos, sink.order)


def _update_summaries(fn: _Fn) -> bool:
    changed = False
    pf = fn.pf
    for line, start, end in fn.returns:
        labels = _labels_of(fn, start, end)
        if "src" in labels:
            trace = _extend(labels["src"], _Hop(pf.path, line, fn.node_id, "return"))
            if _better(fn.returns_src, trace):
                fn.returns_src = trace
                changed = True
    for sink in fn.sinks:
        labels = _labels_of(fn, sink.arg_start, sink.arg_end)
        for label, trace in labels.items():
            if label.startswith("p"):
                entry = fn.param_sinks.setdefault(int(label[1:]), {})
                full = _extend(trace, _Hop(pf.path, sink.line, fn.node_id, "sink"))
                if _better(entry.get(_sink_key(fn, sink)), full):
                    entry[_sink_key(fn, sink)] = full
                    changed = True
    for call in fn.calls:
        for target in call.targets:
            if not target.param_sinks:
                continue
            for j, (start, end) in enumerate(call.args):
                downstream = target.param_sinks.get(j)
                if not downstream:
                    continue
                labels = _labels_of(fn, start, end)
                for label, trace in labels.items():
                    if not label.startswith("p"):
                        continue
                    entry = fn.param_sinks.setdefault(int(label[1:]), {})
                    call_hop = _Hop(pf.path, call.line, fn.node_id, "call")
                    for key, tail in sorted(downstream.items()):
                        full = _extend(trace, call_hop)
                        for hop in tail:
                            full = _extend(full, hop)
                        if _better(entry.get(key), full):
                            entry[key] = full
                            changed = True
    return changed


# ------------------------------------------------------------------ findings


def _uses_only_sanitized(fn: _Fn, start: int, end: int) -> bool:
    """True when every value spliced into a dynamic argument is a known-safe cast."""
    names = set(IDENT_RE.findall(fn.pf.masked[start:end]))
    for groups in INTERP_RE.findall(fn.pf.code[start:end]):
        for group in groups:
            names.update(IDENT_RE.findall(group))
    values = {n for n in names if n not in NON_VALUE_WORDS and not n[:1].isupper()}
    return bool(values) and values <= fn.sanitized


def _is_literal_only(arg: str) -> bool:
    stripped = arg.strip()
    return bool(re.fullmatch(r"(?:@|\$)?(['\"`])(?:(?!\1).)*\1\s*(?:,.*)?", stripped, re.S)) and "${" not in stripped


def _flow_metadata(trace: Trace) -> list[dict[str, Any]]:
    return [{"loc": f"{hop.path}:{hop.line}", "node": hop.node_id, "role": hop.role} for hop in trace]


def analyze_polyglot_security(graph: Graph, index: PolyglotIndex) -> list[Finding]:
    """Interprocedural taint SAST over every indexed C#, JS/TS, PHP and Go file."""
    fns = _collect_facts(graph, index)
    resolver = _Resolver(index, fns)
    for fn in fns:
        for call in fn.calls:
            call.targets = [t for t in resolver.resolve(fn, call) if t is not fn]
    # Worklist fixed point: when a function's summary changes, only its callers
    # need re-evaluation. Summaries only move toward shorter traces, so this
    # terminates, and chains of any depth are composed (callee-first order is
    # not required).
    callers: dict[int, list[int]] = {}
    position = {id(fn): i for i, fn in enumerate(fns)}
    for i, fn in enumerate(fns):
        for call in fn.calls:
            for target in call.targets:
                callers.setdefault(position[id(target)], []).append(i)
    queue = deque(range(len(fns)))
    queued = set(queue)
    updates = 0
    while queue and updates < MAX_SUMMARY_UPDATES:
        i = queue.popleft()
        queued.discard(i)
        fn = fns[i]
        _propagate_fn(fn)
        updates += 1
        if _update_summaries(fn):
            for caller in sorted(set(callers.get(i, []))):
                if caller not in queued:
                    queued.add(caller)
                    queue.append(caller)

    # Final pass: request input reaching each sink, locally or via callees.
    tainted_at: dict[tuple[str, int, int], Trace] = {}
    for fn in fns:
        _propagate_fn(fn)
        pf = fn.pf
        for sink in fn.sinks:
            labels = _labels_of(fn, sink.arg_start, sink.arg_end)
            if "src" in labels:
                full = _extend(labels["src"], _Hop(pf.path, sink.line, fn.node_id, "sink"))
                if _better(tainted_at.get(_sink_key(fn, sink)), full):
                    tainted_at[_sink_key(fn, sink)] = full
        for call in fn.calls:
            for target in call.targets:
                for j, (start, end) in enumerate(call.args):
                    downstream = target.param_sinks.get(j)
                    if not downstream:
                        continue
                    labels = _labels_of(fn, start, end)
                    if "src" not in labels:
                        continue
                    for key, tail in sorted(downstream.items()):
                        full = _extend(labels["src"], _Hop(pf.path, call.line, fn.node_id, "call"))
                        for hop in tail:
                            full = _extend(full, hop)
                        if _better(tainted_at.get(key), full):
                            tainted_at[key] = full

    findings: list[Finding] = []
    seen: set[str] = set()
    for fn in fns:
        pf = fn.pf
        family = fn.family
        dynamic_re = DYNAMIC_RES[family]
        for sink in sorted(fn.sinks, key=lambda s: (s.pos, s.order)):
            rule = sink.rule
            arg = pf.code[sink.arg_start : sink.arg_end]
            if rule.sanitizer is not None and rule.sanitizer.search(arg):
                continue
            trace = tainted_at.get(_sink_key(fn, sink))
            tainted = trace is not None
            if rule.mode == "taint":
                if not tainted:
                    continue
                severity = rule.severity
            elif rule.mode == "dynamic":
                values = _value_text(pf, sink.arg_start, sink.arg_end)
                dyn_names = set(IDENT_RE.findall(values)) & fn.dynamic
                is_dynamic = bool(dynamic_re.search(arg) or dyn_names)
                if not tainted and not is_dynamic:
                    if rule.category not in ("code", "deserialization") or _is_literal_only(arg) or not arg.strip():
                        continue
                if not tainted and is_dynamic and _uses_only_sanitized(fn, sink.arg_start, sink.arg_end):
                    continue
                severity = rule.severity if tainted else (rule.untainted or rule.severity)
            else:
                severity = rule.severity
            dedupe_key = f"{rule.category}:{pf.path}:{sink.line}:{rule.title}"
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            node = graph.nodes.get(fn.node_id or "")
            if node is not None:
                tags = set(node.attrs.get("tags", []))
                tags.update({"sink", rule.category})
                node.attrs["tags"] = sorted(tags)
            functions = sorted({h.node_id for h in trace or () if h.node_id})
            interprocedural = len(functions) > 1
            where = fn.sym.name if fn.sym else pf.path
            if rule.mode == "always":
                detail = "uses an unsafe API or configuration"
            elif tainted and interprocedural:
                origin = trace[0] if trace else None
                detail = (
                    f"receives request-controlled data from {origin.path}:{origin.line} "
                    f"through {len(functions) - 1} call(s)"
                    if origin
                    else "receives request-controlled data through calls"
                )
            elif tainted:
                detail = "passes request-controlled data to this sink"
            else:
                detail = "builds the argument dynamically (concatenation/interpolation/format)"
            locs = [Loc(h.path, h.line) for h in trace] if trace else []
            deduped: list[Loc] = []
            for loc in locs:
                if not deduped or deduped[-1] != loc:
                    deduped.append(loc)
            metadata: dict[str, Any] = {"rule_id": rule.rule_id, "language": pf.language, "tainted": tainted}
            if trace:
                metadata["flow"] = _flow_metadata(trace)
                metadata["interprocedural"] = interprocedural
            findings.append(
                Finding(
                    id=stable_id("finding", rule.category, pf.path, str(sink.line), rule.title),
                    category=rule.category,
                    severity=severity,
                    title=rule.title,
                    message=f"{LANGUAGE_LABELS[pf.language]} `{where}` {detail}: "
                    f"`{redact_secrets(sink.line_text.strip())[:160]}` ({pf.path}:{sink.line}).",
                    node_id=fn.node_id if node is not None else None,
                    cwe=rule.cwe,
                    confidence=(0.8 if interprocedural else 0.85) if tainted or rule.mode == "always" else 0.6,
                    evidence=[Loc(pf.path, sink.line)],
                    recommendation=RECOMMEND[rule.category],
                    trace=deduped if len(deduped) > 1 else [],
                    metadata=metadata,
                )
            )
    findings.sort(key=lambda f: (f.evidence[0].path, f.evidence[0].line, f.category, f.title))
    return findings
