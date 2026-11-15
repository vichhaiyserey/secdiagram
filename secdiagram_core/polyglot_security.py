"""Taint-aware SAST heuristics for C#/.NET, JavaScript/TypeScript, PHP and Go.

Works on the :mod:`secdiagram_core.polyglot_index` views of each file (source
text only; nothing is executed). For every sink match the enclosing function
is used as the taint scope:

1. Seed tainted variables from handler parameters bound to request input
   (ASP.NET action parameters, NestJS ``@Body``/``@Query``, Laravel/Symfony
   route parameters) and from assignments whose right-hand side reads a
   request source (``req.query``, ``Request.Query``, ``$_GET``, ``c.Query``...).
2. Propagate through plain assignments (bounded passes). Numeric casts such as
   ``parseInt``/``int.Parse``/``intval``/``strconv.Atoi`` stop propagation.
3. Report the sink when its argument references a source or tainted variable.
   ``dynamic`` rules (SQL/command builders) also fire, at lower severity, when
   the argument is assembled by concatenation, interpolation or formatting.

Severity and CWE choices mirror ``security.py`` so findings from every
language rank consistently in SARIF and the security report.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

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


@dataclass(slots=True)
class _Scope:
    start: int
    end: int
    symbol: PgSymbol | None
    tainted: dict[str, int]
    dynamic: set[str]
    sanitized: set[str]


def _var_pattern(names: list[str], family: str) -> re.Pattern[str] | None:
    if not names:
        return None
    escaped = "|".join(re.escape(n) for n in sorted(names, key=len, reverse=True))
    if family == "php":
        return re.compile(rf"(?:{escaped})\b")
    return re.compile(rf"(?<![\w$.])(?:{escaped})\b")


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


def _build_scope(pf: PgFile, start: int, end: int, symbol: PgSymbol | None, code_lines: list[str]) -> _Scope:
    family = _family(pf.language)
    source_re = SOURCES[family]
    assign_re = ASSIGN_RES[family]
    dynamic_re = DYNAMIC_RES[family]
    first_line = pf.line_of(start)
    last_line = pf.line_of(end)
    lines = code_lines[first_line - 1 : last_line]
    tainted: dict[str, int] = {}
    for name in symbol.tainted_params if symbol else []:
        tainted.setdefault(name, symbol.line if symbol else first_line)
    dynamic: set[str] = set()
    sanitized: set[str] = set()
    for _ in range(3):
        changed = False
        pattern = _var_pattern(list(tainted), family)
        for offset, line in enumerate(lines):
            line_no = first_line + offset
            for statement in line.split(";"):
                match = assign_re.search(statement)
                if family == "go":
                    for bind in GO_BIND_RE.finditer(statement):
                        # gin/echo binders read the request themselves; json Decode /
                        # Unmarshal need a request source or tainted value in the call.
                        binder = re.search(r"\.(?:ShouldBind\w*|Bind\w*)\s*\(", statement)
                        from_request = binder or source_re.search(statement) or (pattern and pattern.search(statement))
                        if from_request and bind.group(1) not in tainted:
                            tainted[bind.group(1)] = line_no
                            changed = True
                if not match:
                    continue
                rhs = match.group(2)
                names = _names_from_lhs(match.group(1).strip(), family)
                if not names:
                    continue
                if dynamic_re.search(rhs):
                    dynamic.update(names)
                if NUMERIC_CAST_RE.match(rhs):
                    sanitized.update(names)
                    continue
                if source_re.search(rhs) or (pattern is not None and pattern.search(rhs)):
                    for name in names:
                        if name not in tainted:
                            tainted[name] = line_no
                            changed = True
        if not changed:
            break
    return _Scope(start, end, symbol, tainted, dynamic, sanitized)


class _ScopeLocator:
    """Innermost function scope for ascending positions in one linear sweep."""

    def __init__(self, pf: PgFile, code_lines: list[str]) -> None:
        self.pf = pf
        self.code_lines = code_lines
        self.symbols = sorted(
            (sym for sym in pf.symbols if sym.kind != "class" and sym.has_body),
            key=lambda sym: (sym.body_start, -sym.body_end),
        )
        self.next = 0
        self.stack: list[PgSymbol] = []
        self.cache: dict[int, _Scope] = {}

    def scope_at(self, pos: int) -> _Scope:
        while self.next < len(self.symbols) and self.symbols[self.next].body_start <= pos:
            sym = self.symbols[self.next]
            while self.stack and self.stack[-1].body_end < sym.body_start:
                self.stack.pop()
            self.stack.append(sym)
            self.next += 1
        while self.stack and self.stack[-1].body_end < pos:
            self.stack.pop()
        best = self.stack[-1] if self.stack else None
        key = id(best) if best is not None else 0
        if key not in self.cache:
            if best is None:
                self.cache[key] = _build_scope(self.pf, 0, len(self.pf.code), None, self.code_lines)
            else:
                self.cache[key] = _build_scope(self.pf, best.body_start, best.body_end, best, self.code_lines)
        return self.cache[key]


def _argument_text(pf: PgFile, match_end: int, assignment: bool) -> str:
    code = pf.code
    if assignment or code[match_end - 1 : match_end] != "(":
        stop = code.find(";", match_end)
        newline = code.find("\n", match_end)
        candidates = [c for c in (stop, newline) if c != -1]
        return code[match_end : min(candidates) if candidates else len(code)]
    close = _match_paren(pf, match_end - 1)
    if close == -1:
        # Unbalanced call: fall back to the rest of the line.
        newline = code.find("\n", match_end)
        return code[match_end : newline if newline != -1 else len(code)]
    return code[match_end:close]


INTERP_RE = re.compile(r"\$\{([^}]*)\}|(?<![\w$])\{([A-Za-z_][\w.]*)\}|(\$\w+)")
IDENT_RE = re.compile(r"(?<![\w$.])[$]?[A-Za-z_$][\w$]*")
NON_VALUE_WORDS = frozenset({"new", "null", "nil", "true", "false", "this", "self", "await", "string", "String", "fmt",
                             "Sprintf", "Format", "Concat", "sprintf", "implode", "util", "format", "strings", "Join"})


def _uses_only_sanitized(pf: PgFile, start: int, end: int, scope: _Scope) -> bool:
    """True when every value spliced into a dynamic argument is a known-safe cast."""
    masked_arg = pf.masked[start:end]
    code_arg = pf.code[start:end]
    names = set(IDENT_RE.findall(masked_arg))
    for groups in INTERP_RE.findall(code_arg):
        for group in groups:
            names.update(IDENT_RE.findall(group))
    values = {n for n in names if n not in NON_VALUE_WORDS and not n[:1].isupper()}
    return bool(values) and values <= scope.sanitized


def _value_text(pf: PgFile, start: int, end: int) -> str:
    """Code of an argument with string contents removed but interpolations kept.

    ``"WHERE id = @id"`` must not match a tainted variable ``id``, while
    ``$"...{id}"`` / `` `${id}` `` / ``"$id"`` (PHP) must.
    """
    parts = [pf.masked[start:end]]
    for groups in INTERP_RE.findall(pf.code[start:end]):
        parts.extend(group for group in groups if group)
    return " ".join(parts)


def _first_arg_end(pf: PgFile, start: int, end: int) -> int:
    depth = 0
    for k in range(start, end):
        ch = pf.masked[k]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            return k
    return end


def _is_literal_only(arg: str) -> bool:
    stripped = arg.strip()
    return bool(re.fullmatch(r"(?:@|\$)?(['\"`])(?:(?!\1).)*\1\s*(?:,.*)?", stripped, re.S)) and "${" not in stripped


def analyze_polyglot_security(graph: Graph, index: PolyglotIndex) -> list[Finding]:
    """Run the polyglot SAST rules over every indexed file (deterministic)."""
    findings: list[Finding] = []
    seen: set[str] = set()
    for path in sorted(index.files):
        pf = index.files[path]
        family = _family(pf.language)
        source_re = SOURCES[family]
        dynamic_re = DYNAMIC_RES[family]
        code_lines = pf.code.split("\n")
        locator = _ScopeLocator(pf, code_lines)
        rules = [r for r in RULES if pf.language in r.languages and (r.requires is None or r.requires.search(pf.code))]
        line_starts = [0] + [m.end() for m in re.finditer("\n", pf.code)]
        hits = sorted(
            ((match.start(), order, rule, match) for order, rule in enumerate(rules) for match in rule.sink.finditer(pf.code)),
            key=lambda hit: (hit[0], hit[1]),
        )
        for pos, _order, rule, match in hits:
            line_no = pf.line_of(pos)
            line_text = pf.code[line_starts[line_no - 1] : pf.code.find("\n", pos) if pf.code.find("\n", pos) != -1 else len(pf.code)]
            if pf.masked[pos] == " " and not pf.code[pos].isspace():
                continue  # sink text sits inside a string literal or comment
            assignment = match.group(0).rstrip().endswith("=")
            arg = _argument_text(pf, match.end(), assignment)
            if rule.sanitizer is not None and rule.sanitizer.search(arg):
                continue
            scope = locator.scope_at(pos)
            var_re = _var_pattern(list(scope.tainted), family)
            arg_start = match.end()
            arg_end = arg_start + len(arg)
            if rule.category == "sql" and not assignment:
                # Only the query text matters; later arguments are bound parameters.
                arg_end = _first_arg_end(pf, arg_start, arg_end)
                arg = pf.code[arg_start:arg_end]
            values = _value_text(pf, arg_start, arg_end)
            source_hit = source_re.search(values)
            var_hit = var_re.search(values) if var_re else None
            tainted = bool(source_hit or var_hit)
            trace: list[Loc] = []
            if var_hit and not source_hit:
                origin = scope.tainted.get(var_hit.group(0))
                if origin and origin != line_no:
                    trace.append(Loc(pf.path, origin))
            trace.append(Loc(pf.path, line_no))
            if rule.mode == "taint":
                if not tainted:
                    continue
                severity = rule.severity
            elif rule.mode == "dynamic":
                dyn_vars = _var_pattern(sorted(scope.dynamic), family)
                is_dynamic = bool(dynamic_re.search(arg) or (dyn_vars and dyn_vars.search(values)))
                if not tainted and not is_dynamic:
                    if rule.category not in ("code", "deserialization") or _is_literal_only(arg) or not arg.strip():
                        continue
                if not tainted and is_dynamic and _uses_only_sanitized(pf, arg_start, arg_end, scope):
                    continue
                severity = rule.severity if tainted else (rule.untainted or rule.severity)
            else:
                severity = rule.severity
            title = rule.title
            key = f"{rule.category}:{pf.path}:{line_no}:{title}"
            if key in seen:
                continue
            seen.add(key)
            owner = scope.symbol
            node_id = symbol_node_id(pf, owner) if owner is not None else None
            node = graph.nodes.get(node_id or "")
            if node is not None:
                tags = set(node.attrs.get("tags", []))
                tags.update({"sink", rule.category})
                node.attrs["tags"] = sorted(tags)
            where = f"{owner.name}" if owner else pf.path
            if rule.mode == "always":
                detail = "uses an unsafe API or configuration"
            elif tainted:
                detail = "passes request-controlled data to this sink"
            else:
                detail = "builds the argument dynamically (concatenation/interpolation/format)"
            findings.append(
                Finding(
                    id=stable_id("finding", rule.category, pf.path, str(line_no), title),
                    category=rule.category,
                    severity=severity,
                    title=title,
                    message=f"{LANGUAGE_LABELS[pf.language]} `{where}` {detail}: "
                    f"`{redact_secrets(line_text.strip())[:160]}` ({pf.path}:{line_no}).",
                    node_id=node_id if node is not None else None,
                    cwe=rule.cwe,
                    confidence=0.85 if tainted or rule.mode == "always" else 0.6,
                    evidence=[Loc(pf.path, line_no)],
                    recommendation=RECOMMEND[rule.category],
                    trace=trace if tainted and len(trace) > 1 else [],
                    metadata={"rule_id": rule.rule_id, "language": pf.language, "tainted": tainted},
                )
            )
    findings.sort(key=lambda f: (f.evidence[0].path, f.evidence[0].line, f.category, f.title))
    return findings
