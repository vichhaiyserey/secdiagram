"""Web/API security misconfiguration rules for C#, JS/TS, PHP, Go and Java.

Python has equivalent checks in :mod:`security`. These rules cover the
configuration-level weaknesses that keep appearing in breach reports and the
OWASP Top 10 / API Security Top 10, independent of data flow:

* broken token validation (JWT signature/lifetime checks off, ``alg=none``,
  decoding without verification),
* CORS that trusts any (or a reflected) origin **while sending credentials**,
* CSRF protection switched off, cookies without ``HttpOnly`` / ``Secure``,
* XML parsers that resolve external entities (XXE),
* non-cryptographic RNGs used for tokens, secrets, OTPs or session ids,
* developer exception pages without an environment guard.

Each rule matches a line of comment-free code (string literals stay visible
where the rule needs them) and may require a companion pattern *near* the
match (e.g. CORS wildcard **and** credentials) or be suppressed when a
mitigating pattern is present anywhere in the file (e.g. ``jwt.verify``).
Source is read as text only; nothing is executed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .model import Finding, Graph, Loc, stable_id
from .polyglot_index import _views
from .redaction import redact_secrets

MAX_BYTES = 2 * 1024 * 1024
NEAR_LINES = 8

LANGUAGE_BY_SUFFIX = {
    ".cs": "csharp",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".php": "php",
    ".go": "go",
    ".java": "java",
}
TOKEN_WORDS = r"(?i:token|secret|password|passw|otp|nonce|salt|session|api_?key|apikey|reset|verification|csrf|auth_?code)"

CS = frozenset({"csharp"})
JS = frozenset({"javascript", "typescript"})
PHP = frozenset({"php"})
GO = frozenset({"go"})
JAVA = frozenset({"java"})

RECOMMEND = {
    "jwt": "Validate token signatures with a pinned algorithm and key, and enforce expiry, issuer and audience.",
    "cors": "Allow an explicit list of trusted origins when credentials are enabled; never reflect or wildcard origins.",
    "csrf": "Keep CSRF protection enabled for cookie-authenticated, state-changing endpoints "
    "(only token-authenticated stateless APIs may opt out).",
    "cookie": "Set HttpOnly and Secure (and SameSite) on session and authentication cookies.",
    "xxe": "Disable DTD processing and external entity resolution on XML parsers.",
    "randomness": "Generate tokens, secrets and OTPs with a CSPRNG (RandomNumberGenerator, crypto.randomBytes / "
    "randomUUID, random_bytes, crypto/rand, SecureRandom).",
    "misconfig": "Enable detailed error pages only in development (guard with an environment check).",
}


@dataclass(frozen=True, slots=True)
class ConfigRule:
    rule_id: str
    languages: frozenset[str]
    category: str
    cwe: str
    severity: str
    title: str
    pattern: re.Pattern[str]
    near: re.Pattern[str] | None = None  # must also appear within NEAR_LINES lines
    near_lines: int = NEAR_LINES
    absent: re.Pattern[str] | None = None  # mitigation anywhere in the file suppresses
    requires: re.Pattern[str] | None = None  # file must contain
    in_strings: bool = False  # pattern may start inside a string literal


def _r(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern)


RULES: tuple[ConfigRule, ...] = (
    # ------------------------------------------------------------------ JWT
    ConfigRule("CFG-CS-JWT-SIG", CS, "jwt", "CWE-347", "high", "JWT signature validation disabled",
               _r(r"\b(?:ValidateIssuerSigningKey|RequireSignedTokens)\s*=\s*false\b|\bSignatureValidator\s*=")),
    ConfigRule("CFG-CS-JWT-CLAIMS", CS, "jwt", "CWE-287", "medium", "JWT lifetime/issuer/audience validation disabled",
               _r(r"\b(?:ValidateLifetime|RequireExpirationTime|ValidateIssuer|ValidateAudience)\s*=\s*false\b")),
    ConfigRule("CFG-JS-JWT-NONE", JS, "jwt", "CWE-347", "high", "JWT 'none' algorithm accepted",
               _r(r"\balgorithms\s*:\s*\[[^\]]*['\"]none['\"]"), in_strings=False),
    ConfigRule("CFG-JS-JWT-DECODE", JS, "jwt", "CWE-347", "medium", "JWT decoded without signature verification",
               _r(r"\bjwt\.decode\s*\("), absent=_r(r"\bjwt\.verify\s*\(|\bjwtVerify\s*\(")),
    ConfigRule("CFG-JS-JWT-EXP", JS, "jwt", "CWE-613", "medium", "JWT expiry ignored",
               _r(r"\bignoreExpiration\s*:\s*true\b")),
    ConfigRule("CFG-PHP-JWT-NONE", PHP, "jwt", "CWE-347", "high", "JWT 'none' algorithm accepted",
               _r(r"['\"](?:alg|algorithms?)['\"]\s*=>\s*\[?[^\]\n]*['\"]none['\"]")),
    ConfigRule("CFG-GO-JWT-UNVERIFIED", GO, "jwt", "CWE-347", "high", "JWT parsed without signature verification",
               _r(r"\.ParseUnverified\s*\(|\bSigningMethodNone\b|\bUnsafeAllowNoneSignatureType\b")),
    ConfigRule("CFG-GO-JWT-CLAIMS", GO, "jwt", "CWE-613", "medium", "JWT claims validation disabled",
               _r(r"\bjwt\.WithoutClaimsValidation\s*\(")),
    ConfigRule("CFG-JAVA-JWT-UNSIGNED", JAVA, "jwt", "CWE-347", "high", "Unsigned JWT accepted",
               _r(r"\.(?:parseClaimsJwt|parseUnsecuredClaims)\s*\(|\bAlgorithm\.none\s*\(")),
    ConfigRule("CFG-JAVA-JWT-DECODE", JAVA, "jwt", "CWE-347", "medium", "JWT decoded without signature verification",
               _r(r"\bJWT\.decode\s*\("), absent=_r(r"\bJWT\.require\s*\(|\.verify\s*\(")),
    # ----------------------------------------------------------------- CORS
    ConfigRule("CFG-CS-CORS", CS, "cors", "CWE-942", "high", "CORS trusts any origin with credentials",
               _r(r"\bSetIsOriginAllowed\s*\(\s*(?:_|\w+)\s*=>\s*true\s*\)"), near=_r(r"\bAllowCredentials\s*\(")),
    ConfigRule("CFG-JS-CORS", JS, "cors", "CWE-942", "high", "CORS trusts any origin with credentials",
               _r(r"\borigin\s*:\s*(?:true\b|['\"]\*['\"]|\(\s*\w*\s*,\s*\w+\s*\)\s*=>\s*\w+\s*\(\s*null\s*,\s*true\s*\))"),
               near=_r(r"\bcredentials\s*:\s*true\b"), in_strings=False),
    ConfigRule("CFG-JS-CORS-REFLECT", JS, "cors", "CWE-942", "high", "CORS reflects the request origin with credentials",
               _r(r"Access-Control-Allow-Origin['\"]\s*,\s*req\.headers\.origin"), near=_r(r"Access-Control-Allow-Credentials"),
               in_strings=True),
    ConfigRule("CFG-PHP-CORS", PHP, "cors", "CWE-942", "high", "CORS trusts any origin with credentials",
               _r(r"Access-Control-Allow-Origin:\s*(?:\*|['\"]\s*\.\s*\$_SERVER\[['\"]HTTP_ORIGIN)|"
                  r"['\"]allowed_origins['\"]\s*=>\s*\[\s*['\"]\*['\"]"),
               near=_r(r"Access-Control-Allow-Credentials:\s*true|['\"]supports_credentials['\"]\s*=>\s*true"),
               near_lines=30, in_strings=True),
    ConfigRule("CFG-GO-CORS", GO, "cors", "CWE-942", "high", "CORS trusts any origin with credentials",
               _r(r"\bAllowAllOrigins\s*:\s*true\b|\bAllowOriginFunc\s*:\s*func\s*\([^)]*\)\s*bool\s*\{\s*return\s+true\b|"
                  r"\bAllowedOrigins\s*:\s*\[\]string\s*\{\s*\"\*\""),
               near=_r(r"\bAllowCredentials\s*:\s*true\b")),
    ConfigRule("CFG-JAVA-CORS", JAVA, "cors", "CWE-942", "high", "CORS trusts any origin with credentials",
               _r(r"@CrossOrigin\s*\([^)]*origins\s*=\s*\"\*\"[^)]*allowCredentials\s*=\s*\"true\"|"
                  r"\b(?:set)?[Aa]llowedOriginPatterns\s*\([^)]*\"\*\""),
               near=_r(r"allowCredentials\s*=\s*\"true\"|\b(?:set)?[Aa]llowCredentials\s*\(\s*true\s*\)")),
    # ----------------------------------------------------------------- CSRF
    ConfigRule("CFG-CS-CSRF", CS, "csrf", "CWE-352", "medium", "Anti-forgery validation disabled",
               _r(r"\[\s*IgnoreAntiforgeryToken\b|\bnew\s+IgnoreAntiforgeryTokenAttribute\s*\(")),
    ConfigRule("CFG-PHP-CSRF", PHP, "csrf", "CWE-352", "high", "CSRF verification disabled for every route",
               _r(r"\$except\s*=\s*\[\s*['\"]\*['\"]|\bvalidateCsrfTokens\s*\(\s*except\s*:\s*\[\s*['\"]\*['\"]"),
               in_strings=False),
    ConfigRule("CFG-JAVA-CSRF", JAVA, "csrf", "CWE-352", "medium", "Spring Security CSRF protection disabled",
               _r(r"\.csrf\s*\(\s*\)\s*\.disable\s*\(|\.csrf\s*\(\s*(?:AbstractHttpConfigurer::disable|"
                  r"CsrfConfigurer::disable|\w+\s*->\s*\w+\.disable\s*\(\s*\))")),
    # -------------------------------------------------------------- cookies
    ConfigRule("CFG-CS-COOKIE", CS, "cookie", "CWE-1004", "medium", "Cookie without HttpOnly/Secure",
               _r(r"\b(?:HttpOnly|Secure)\s*=\s*false\b|\bCookieSecurePolicy\.None\b")),
    ConfigRule("CFG-JS-COOKIE", JS, "cookie", "CWE-1004", "medium", "Cookie without HttpOnly/Secure",
               _r(r"\b(?:httpOnly|secure)\s*:\s*false\b"), near=_r(r"(?i)cookie|session"), near_lines=4),
    ConfigRule("CFG-PHP-COOKIE", PHP, "cookie", "CWE-1004", "medium", "Cookie without HttpOnly/Secure",
               _r(r"\bini_set\s*\(\s*['\"]session\.cookie_(?:httponly|secure)['\"]\s*,\s*['\"]?(?:0|false|off)\b|"
                  r"['\"](?:http_only|httponly|secure)['\"]\s*=>\s*false\b")),
    ConfigRule("CFG-GO-COOKIE", GO, "cookie", "CWE-1004", "medium", "Cookie without HttpOnly/Secure",
               _r(r"\b(?:HttpOnly|Secure)\s*:\s*false\b"), near=_r(r"\bhttp\.Cookie\b|SetCookie|Cookie\s*\{"), near_lines=6),
    ConfigRule("CFG-JAVA-COOKIE", JAVA, "cookie", "CWE-1004", "medium", "Cookie without HttpOnly/Secure",
               _r(r"\.set(?:HttpOnly|Secure)\s*\(\s*false\s*\)")),
    # ------------------------------------------------------------------ XXE
    ConfigRule("CFG-CS-XXE", CS, "xxe", "CWE-611", "high", "XML parser resolves external entities",
               _r(r"\bDtdProcessing\s*=\s*DtdProcessing\.Parse\b|\bXmlResolver\s*=\s*new\s+XmlUrlResolver\b|"
                  r"\bProhibitDtd\s*=\s*false\b")),
    ConfigRule("CFG-JS-XXE", JS, "xxe", "CWE-611", "high", "XML parser resolves external entities",
               _r(r"\bnoent\s*:\s*true\b")),
    ConfigRule("CFG-PHP-XXE", PHP, "xxe", "CWE-611", "high", "XML parser resolves external entities",
               _r(r"\bLIBXML_NOENT\b|\blibxml_disable_entity_loader\s*\(\s*false\s*\)")),
    # ------------------------------------------------------------ randomness
    ConfigRule("CFG-CS-RANDOM", CS, "randomness", "CWE-338", "medium", "Non-cryptographic RNG for a security value",
               _r(r"\bnew\s+Random\s*\(|\bRandom\.Shared\b"), near=_r(TOKEN_WORDS), near_lines=1),
    ConfigRule("CFG-JS-RANDOM", JS, "randomness", "CWE-338", "medium", "Non-cryptographic RNG for a security value",
               _r(r"\bMath\.random\s*\(\s*\)"), near=_r(TOKEN_WORDS), near_lines=1),
    ConfigRule("CFG-PHP-RANDOM", PHP, "randomness", "CWE-338", "medium", "Non-cryptographic RNG for a security value",
               _r(r"(?<![\w>:$])(?:rand|mt_rand|uniqid|lcg_value|str_shuffle)\s*\("), near=_r(TOKEN_WORDS), near_lines=1),
    ConfigRule("CFG-GO-RANDOM", GO, "randomness", "CWE-338", "medium", "Non-cryptographic RNG for a security value",
               _r(r"\brand\.(?:Int\w*|Read|Uint\w*|Float\w*|Perm|Shuffle)\s*\("), near=_r(TOKEN_WORDS), near_lines=1,
               requires=_r(r"\"math/rand(?:/v2)?\"")),
    ConfigRule("CFG-JAVA-RANDOM", JAVA, "randomness", "CWE-338", "medium", "Non-cryptographic RNG for a security value",
               _r(r"\bnew\s+Random\s*\(|\bMath\.random\s*\(|\bThreadLocalRandom\.current\s*\("), near=_r(TOKEN_WORDS),
               near_lines=1),
    # ----------------------------------------------------------- debug pages
    ConfigRule("CFG-CS-DEVPAGE", CS, "misconfig", "CWE-209", "medium", "Developer exception page without environment guard",
               _r(r"\bUseDeveloperExceptionPage\s*\("), absent=_r(r"\bIsDevelopment\s*\(|\bIsEnvironment\s*\(")),
)


def _language(path: str) -> str | None:
    lower = path.lower()
    if lower.endswith((".d.ts", ".min.js")):
        return None
    name = lower.rsplit("/", 1)[-1]
    return LANGUAGE_BY_SUFFIX.get("." + name.rsplit(".", 1)[-1]) if "." in name else None


def _read(root: Path, rel_path: str) -> str | None:
    try:
        resolved = (root / rel_path).resolve()
        if not resolved.is_relative_to(root.resolve()) or not resolved.is_file():
            return None
        if resolved.stat().st_size > MAX_BYTES:
            return None
        return resolved.read_text(encoding="utf-8", errors="replace")
    except (OSError, ValueError):
        return None


def _innermost_nodes(graph: Graph) -> dict[str, list[tuple[int, str]]]:
    by_path: dict[str, list[tuple[int, str]]] = {}
    for node in graph.sorted_nodes():
        if node.path and node.line and node.kind in {"endpoint", "function", "method", "class", "task", "cli"}:
            by_path.setdefault(node.path, []).append((node.line, node.id))
    for entries in by_path.values():
        entries.sort()
    return by_path


def analyze_misconfig(graph: Graph, root: Path, rel_files: list[str]) -> list[Finding]:
    """Scan C#, JS/TS, PHP, Go and Java sources for web/API misconfigurations."""
    findings: list[Finding] = []
    seen: set[str] = set()
    nodes = _innermost_nodes(graph)
    for rel_path in sorted(rel_files):
        language = _language(rel_path)
        if language is None:
            continue
        rules = [rule for rule in RULES if language in rule.languages]
        if not rules:
            continue
        text = _read(root, rel_path)
        if text is None:
            continue
        # Java shares C-style comment/string syntax with C#.
        code, masked = _views(text, "csharp" if language == "java" else language)
        code_lines = code.split("\n")
        line_starts = [0]
        for match in re.finditer("\n", code):
            line_starts.append(match.end())
        for rule in rules:
            if rule.requires is not None and not rule.requires.search(code):
                continue
            if rule.absent is not None and rule.absent.search(code):
                continue
            for match in rule.pattern.finditer(code):
                pos = match.start()
                if not rule.in_strings and masked[pos] == " " and not code[pos].isspace():
                    continue  # match starts inside a string literal
                line_no = _line_of(line_starts, pos)
                if rule.near is not None:
                    lo = max(0, line_no - 1 - rule.near_lines)
                    window = "\n".join(code_lines[lo : line_no + rule.near_lines])
                    if not rule.near.search(window):
                        continue
                key = f"{rule.rule_id}:{rel_path}:{line_no}"
                if key in seen:
                    continue
                seen.add(key)
                node_id = _node_at(nodes.get(rel_path, []), line_no)
                node = graph.nodes.get(node_id or "")
                if node is not None:
                    tags = set(node.attrs.get("tags", []))
                    tags.update({"misconfig", rule.category})
                    node.attrs["tags"] = sorted(tags)
                snippet = redact_secrets(code_lines[line_no - 1].strip())[:160]
                findings.append(
                    Finding(
                        id=stable_id("finding", rule.category, rel_path, str(line_no), rule.title),
                        category=rule.category,
                        severity=rule.severity,
                        title=rule.title,
                        message=f"{rule.title}: `{snippet}` ({rel_path}:{line_no}).",
                        node_id=node_id if node is not None else None,
                        cwe=rule.cwe,
                        confidence=0.8,
                        evidence=[Loc(rel_path, line_no)],
                        recommendation=RECOMMEND[rule.category],
                        metadata={"rule_id": rule.rule_id, "language": language},
                    )
                )
    findings.sort(key=lambda f: (f.evidence[0].path, f.evidence[0].line, f.category, f.title))
    return findings


def _line_of(line_starts: list[int], pos: int) -> int:
    lo, hi = 0, len(line_starts)
    while lo < hi:
        mid = (lo + hi) // 2
        if line_starts[mid] <= pos:
            lo = mid + 1
        else:
            hi = mid
    return lo


def _node_at(entries: list[tuple[int, str]], line: int) -> str | None:
    best: str | None = None
    for start, node_id in entries:
        if start > line:
            break
        best = node_id
    return best
