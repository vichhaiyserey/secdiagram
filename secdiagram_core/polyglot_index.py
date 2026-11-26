"""Stdlib-only lexical analyzer for C#/.NET, JavaScript/TypeScript, PHP, Go and Rust.

Analyzed code is untrusted data: it is read as text and never imported,
compiled or executed (AGENTS.md Rule 3). Each file is tokenized once into two
views of identical length:

* ``code``   - comments blanked, string literals intact (routes, SQL, sinks)
* ``masked`` - comments *and* string contents blanked (structure, braces)

Because both views keep every character offset and newline, a position found in
one view is valid in the other. Declarations are recognized with per-language
line regexes on the masked view, bodies are delimited by bracket matching, and
framework conventions (ASP.NET Core, Express/NestJS/Next.js, Laravel/Symfony,
net/http/gin/echo/chi) turn handlers into endpoint nodes with routes.

Every output is deterministic: files, symbols and edges are emitted in sorted
order and identifiers come from :func:`secdiagram_core.model.stable_id`.
"""

from __future__ import annotations

import bisect
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .model import Graph, Loc, Node, stable_id

MAX_SOURCE_BYTES = 2 * 1024 * 1024

LANGUAGE_BY_SUFFIX: dict[str, str] = {
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
    ".rs": "rust",
    ".dart": "dart",
}
LANGUAGE_LABELS = {
    "csharp": "C# / .NET",
    "javascript": "JavaScript",
    "typescript": "TypeScript",
    "php": "PHP",
    "go": "Go",
    "rust": "Rust",
    "dart": "Dart / Flutter",
}
JS_LANGS: frozenset[str] = frozenset({"javascript", "typescript"})
HTTP_METHODS = ("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD")

# Call names that are too generic to resolve by name across files.
CALL_STOPLIST = frozenset(
    {
        "if", "for", "foreach", "while", "switch", "catch", "return", "function", "new", "typeof",
        "sizeof", "nameof", "using", "lock", "await", "async", "yield", "super", "this", "base",
        "get", "set", "then", "map", "filter", "reduce", "push", "pop", "log", "json", "send",
        "toString", "ToString", "Equals", "GetHashCode", "length", "Count", "Add", "Remove",
        "append", "len", "make", "panic", "print", "println", "printf", "echo", "isset", "empty",
        "array", "list", "count", "require", "import", "include", "Ok", "NotFound", "BadRequest",
    }
)


# --------------------------------------------------------------------------- data


@dataclass(slots=True)
class PgSymbol:
    """A declaration (namespace/class/function/method) or a route handler."""

    kind: str  # class | function | method | endpoint
    name: str
    qualname: str
    line: int
    end_line: int
    body_start: int = -1
    body_end: int = -1
    container: str = ""
    decl_kind: str = ""
    params: list[str] = field(default_factory=list)
    bases: list[str] = field(default_factory=list)
    routes: list[dict[str, str]] = field(default_factory=list)
    decorators: list[str] = field(default_factory=list)
    stereotype: str = ""
    framework: str = ""
    handler_ref: str = ""
    tainted_params: list[str] = field(default_factory=list)
    injected: list[str] = field(default_factory=list)
    auth: str = ""  # required | anonymous | "" (unknown)
    entities: list[str] = field(default_factory=list)

    @property
    def has_body(self) -> bool:
        return self.body_start >= 0 and self.body_end > self.body_start


@dataclass(slots=True)
class PgFile:
    path: str
    language: str
    text: str
    code: str
    masked: str
    namespace: str = ""
    imports: list[tuple[str, int]] = field(default_factory=list)
    symbols: list[PgSymbol] = field(default_factory=list)
    _line_starts: list[int] = field(default_factory=list)
    _brace_parent: dict[int, int] = field(default_factory=dict)
    _brace_close: dict[int, int] = field(default_factory=dict)
    _class_by_brace: dict[int, PgSymbol] = field(default_factory=dict)
    _sorted_opens: list[int] = field(default_factory=list)
    _tree_built: bool = False
    _paren_close: dict[int, int] = field(default_factory=dict)
    _parens_built: bool = False

    def line_of(self, pos: int) -> int:
        return bisect.bisect_right(self._line_starts, pos)

    def line_start(self, line: int) -> int:
        return self._line_starts[line - 1]

    @property
    def code_lines(self) -> list[str]:
        return self.code.split("\n")


@dataclass(slots=True)
class PolyglotIndex:
    files: dict[str, PgFile] = field(default_factory=dict)

    def language_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for pf in self.files.values():
            counts[pf.language] = counts.get(pf.language, 0) + 1
        return dict(sorted(counts.items()))


# --------------------------------------------------------------------- tokenizer

_STARTERS = {
    "csharp": re.compile(r'//|/\*|\$@"|@\$"|@"|\$+"|"|\''),
    "javascript": re.compile(r"//|/\*|\"|'|`"),
    "typescript": re.compile(r"//|/\*|\"|'|`"),
    "php": re.compile(r"//|/\*|#(?!\[)|\"|'|`|\?>"),
    "go": re.compile(r"//|/\*|\"|'|`"),
    # A lifetime/label (e.g. 'static or 'outer:) is not a character literal.
    "rust": re.compile(r"""//|/\*|b?r#*"|b?"|b?'(?:\\(?:u\{[0-9a-fA-F_]+\}|x[0-9a-fA-F]{2}|[^\r\n])|[^\\'\r\n])'"""),
    "dart": re.compile(r'''//|/\*|r?"""|r?\'\'\'|r?"|r?\''''),
}
_RUST_COMMENT_DELIMITER = re.compile(r"/\*|\*/")
_PHP_OPEN_RE = re.compile(r"<\?(?:php|=)?")


def _blank(buf: list[str], start: int, end: int) -> None:
    for k in range(start, end):
        if buf[k] != "\n":
            buf[k] = " "


def _blank_php_open_tag(code: list[str], masked: list[str], tag: re.Match[str]) -> None:
    # ``<?php`` / ``<?`` are markup; ``<?=`` is an echo statement and stays visible.
    if tag.group(0) != "<?=":
        _blank(code, tag.start(), tag.end())
        _blank(masked, tag.start(), tag.end())


def _views(text: str, language: str) -> tuple[str, str]:
    """Return ``(code, masked)`` views of *text* (same length, same newlines)."""
    code = list(text)
    masked = list(text)
    starter = _STARTERS[language]
    n = len(text)
    pos = 0
    if language == "php":
        first = _PHP_OPEN_RE.search(text)
        head_end = first.start() if first else n
        _blank(code, 0, head_end)
        _blank(masked, 0, head_end)
        if first is not None:
            _blank_php_open_tag(code, masked, first)
        pos = first.end() if first else n
    while pos < n:
        match = starter.search(text, pos)
        if match is None:
            break
        start = match.start()
        token = match.group(0)
        if token in ("//", "#"):
            end = text.find("\n", start)
            end = n if end == -1 else end
            if language == "php":
                close = text.find("?>", start, end)
                if close != -1:
                    end = close
            _blank(code, start, end)
            _blank(masked, start, end)
            pos = end
            continue
        if token == "/*":
            if language in ("rust", "dart"):
                depth = 1
                curr = start + 2
                while curr < n and depth > 0:
                    delimiter = _RUST_COMMENT_DELIMITER.search(text, curr)
                    if delimiter is None:
                        curr = n
                        break
                    if delimiter.group() == "/*":
                        depth += 1
                    else:
                        depth -= 1
                    curr = delimiter.end()
                end = curr
            else:
                end = text.find("*/", start + 2)
                end = n if end == -1 else end + 2
            _blank(code, start, end)
            _blank(masked, start, end)
            pos = end
            continue
        if token == "?>":
            reopen = _PHP_OPEN_RE.search(text, start + 2)
            end = reopen.start() if reopen else n
            _blank(code, start, end)
            _blank(masked, start, end)
            if reopen is not None:
                _blank_php_open_tag(code, masked, reopen)
            pos = reopen.end() if reopen else n
            continue
        if language == "rust" and "r" in token and '"' in token:
            hashes = token.count("#")
            closer = '"' + ("#" * hashes)
            end_idx = text.find(closer, match.end())
            end = n if end_idx == -1 else end_idx + len(closer)
            inner_end = end_idx if end_idx != -1 else n
            _blank(masked, match.end(), inner_end)
            pos = max(end, start + 1)
            continue
        if language == "rust" and token.endswith("'"):
            _blank(masked, start + (2 if token.startswith("b") else 1), match.end() - 1)
            pos = match.end()
            continue
        if language == "dart" and token.endswith(('"""', "'''")):
            delim = token[-3:]
            raw_dart = token.startswith("r")
            j = match.end()
            end = n
            while j < n:
                if not raw_dart and text[j] == "\\":
                    j += 2
                    continue
                if text.startswith(delim, j):
                    end = j + 3
                    break
                j += 1
            inner_end = end - 3 if end <= n and text.startswith(delim, end - 3) else end
            _blank(masked, match.end(), inner_end)
            pos = max(end, start + 1)
            continue
        quote = token[-1]
        verbatim = language == "csharp" and "@" in token
        raw = (language == "go" and quote == "`") or (language == "dart" and token.startswith("r"))
        multiline = quote == "`" or verbatim or language in ("php", "rust")
        escapes = not verbatim and not raw
        j = match.end()
        end = n
        while j < n:
            ch = text[j]
            if escapes and ch == "\\":
                j += 2
                continue
            if ch == quote:
                if verbatim and j + 1 < n and text[j + 1] == quote:
                    j += 2
                    continue
                end = j + 1
                break
            if ch == "\n" and not multiline:
                end = j
                break
            j += 1
        else:
            end = n
        inner_end = end - 1 if end <= n and end > match.end() and text[end - 1] == quote else end
        _blank(masked, match.end(), inner_end)
        pos = max(end, start + 1)
    return "".join(code), "".join(masked)


# ------------------------------------------------------------------ structure


def _brace_pairs(masked: str) -> dict[int, int]:
    pairs: dict[int, int] = {}
    stack: list[int] = []
    for match in re.finditer(r"[{}]", masked):
        if match.group(0) == "{":
            stack.append(match.start())
        elif stack:
            pairs[stack.pop()] = match.start()
    return pairs


def _match_paren(pf: PgFile, open_pos: int) -> int:
    """Offset of the ``)`` matching the ``(`` at *open_pos* (``-1`` if unmatched).

    All pairs are computed once per file with a stack, so lookups are O(1)
    even for adversarial input full of unclosed calls.
    """
    if not pf._parens_built:
        stack: list[int] = []
        for match in re.finditer(r"[()]", pf.masked):
            if match.group(0) == "(":
                stack.append(match.start())
            elif stack:
                pf._paren_close[stack.pop()] = match.start()
        pf._parens_built = True
    return pf._paren_close.get(open_pos, -1)


_BODY_RE = re.compile(r"\{|;|=>")


def _body_after(masked: str, pairs: dict[int, int], pos: int) -> tuple[int, int]:
    """Return the ``(start, end)`` offsets of the body that follows *pos*."""
    match = _BODY_RE.search(masked, pos, min(len(masked), pos + 2000))
    if match is None:
        return -1, -1
    if match.group(0) == "{":
        close = pairs.get(match.start(), -1)
        return (match.start(), close) if close != -1 else (-1, -1)
    if match.group(0) == ";":
        return -1, -1
    # Expression-bodied member / arrow: block or expression up to ';' or ')'.
    k = match.end()
    while k < len(masked) and masked[k] in " \t\r\n":
        k += 1
    if k < len(masked) and masked[k] == "{":
        close = pairs.get(k, -1)
        return (k, close) if close != -1 else (-1, -1)
    end = k
    depth = 0
    limit = min(len(masked), k + 4000)
    while end < limit:
        ch = masked[end]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                break
            depth -= 1
        elif ch in ";," and depth == 0:
            break
        end += 1
    return match.start(), end


def _split_params(text: str) -> list[str]:
    out: list[str] = []
    depth = 0
    current: list[str] = []
    for ch in text:
        if ch in "<([{":
            depth += 1
        elif ch in ">)]}":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            out.append("".join(current).strip())
            current = []
            continue
        current.append(ch)
    tail = "".join(current).strip()
    if tail:
        out.append(tail)
    return [part for part in out if part]


def _simple(name: str) -> str:
    name = re.sub(r"<.*", "", name.strip())
    name = name.replace("\\", ".").replace("::", ".")
    return name.rsplit(".", 1)[-1].strip(" ?*&[]")


def _line_scopes(masked: str, line_starts: list[int]) -> list[int]:
    """For each line, the offset of the innermost open ``{`` at its start."""
    scopes: list[int] = []
    stack: list[int] = []
    brace_iter = re.finditer(r"[{}]", masked)
    pending = next(brace_iter, None)
    for start in line_starts:
        while pending is not None and pending.start() < start:
            if pending.group(0) == "{":
                stack.append(pending.start())
            elif stack:
                stack.pop()
            pending = next(brace_iter, None)
        scopes.append(stack[-1] if stack else -1)
    return scopes


def _decorators_before(code_lines: list[str], line_idx: int, prefix: str) -> list[str]:
    """Collect attribute/decorator-only lines directly above *line_idx*."""
    found: list[str] = []
    k = line_idx - 1
    while k >= 0:
        stripped = code_lines[k].strip()
        if not stripped:
            k -= 1
            continue
        if stripped.startswith(prefix):
            found.append(stripped)
            k -= 1
            continue
        if prefix == "@" and stripped.endswith(")") and found:
            # Multi-line decorator arguments: keep scanning upwards.
            found.append(stripped)
            k -= 1
            continue
        break
    found.reverse()
    return found


def _join_route(*parts: str) -> str:
    pieces = [p.strip().strip("/") for p in parts if p and p.strip().strip("/")]
    path = "/" + "/".join(pieces)
    return re.sub(r"/{2,}", "/", path)


def _new_file(path: str, language: str, text: str) -> PgFile:
    code, masked = _views(text, language)
    starts = [0]
    for match in re.finditer("\n", text):
        starts.append(match.end())
    return PgFile(path=path, language=language, text=text, code=code, masked=masked, _line_starts=starts)


def _add_symbol(pf: PgFile, sym: PgSymbol) -> PgSymbol:
    pf.symbols.append(sym)
    if sym.kind == "class" and sym.has_body and pf.masked[sym.body_start] == "{":
        pf._class_by_brace[sym.body_start] = sym
    return sym


def _build_brace_tree(pf: PgFile) -> None:
    stack: list[int] = []
    for match in re.finditer(r"[{}]", pf.masked):
        if match.group(0) == "{":
            pf._brace_parent[match.start()] = stack[-1] if stack else -1
            stack.append(match.start())
        elif stack:
            pf._brace_close[stack.pop()] = match.start()
    pf._sorted_opens = sorted(pf._brace_parent)
    pf._tree_built = True


def _enclosing_brace(pf: PgFile, pos: int) -> int:
    """Offset of the innermost ``{`` still open at *pos* (``-1`` if none).

    The last ``{`` before *pos* either encloses it or closed earlier; in the
    latter case only its ancestors can enclose *pos*, so walk up the tree.
    """
    if not pf._tree_built:
        _build_brace_tree(pf)
    idx = bisect.bisect_left(pf._sorted_opens, pos) - 1
    brace = pf._sorted_opens[idx] if idx >= 0 else -1
    end = len(pf.masked)
    while brace >= 0 and pf._brace_close.get(brace, end) < pos:
        brace = pf._brace_parent.get(brace, -1)
    return brace


def _container_for(pf: PgFile, pos: int) -> PgSymbol | None:
    """Innermost class whose body encloses *pos*."""
    brace = _enclosing_brace(pf, pos)
    while brace >= 0:
        sym = pf._class_by_brace.get(brace)
        if sym is not None:
            return sym
        brace = pf._brace_parent.get(brace, -1)
    return None


# ------------------------------------------------------------------------- C#

CS_NAMESPACE_RE = re.compile(r"^\s*namespace\s+([A-Za-z_][\w.]*)")
CS_USING_RE = re.compile(r"^\s*(?:global\s+)?using\s+(?:static\s+)?([A-Za-z_][\w.]*)\s*;")
CS_TYPE_RE = re.compile(
    r"^\s*(?:\[[^\]]*\]\s*)*(?:(?:public|private|protected|internal|static|sealed|abstract|partial|readonly|"
    r"unsafe|file|new|ref)\s+)*(class|interface|struct|enum|record(?:\s+(?:class|struct))?)\s+([A-Za-z_]\w*)"
)
CS_METHOD_RE = re.compile(
    r"^\s*(?:\[[^\]]*\]\s*)*((?:(?:public|private|protected|internal|static|async|virtual|override|sealed|"
    r"abstract|partial|extern|new|unsafe|readonly)\s+)+)(?:([\w.]+(?:<[^()]*?>)?(?:\[\])*\??)\s+)?"
    r"([A-Za-z_]\w*)\s*(?:<[\w\s,]*>)?\s*\("
)
CS_ATTR_RE = re.compile(r"(\w+?)(?:Attribute)?\s*(?:\(((?:[^()]|\([^()]*\))*)\))?\s*(?:,|\]|$)")
CS_STRING_RE = re.compile(r'@?"((?:[^"\\]|\\.)*)"')
CS_MAP_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\.\s*Map(Get|Post|Put|Delete|Patch|Methods)?\s*\(\s*@?\"([^\"]*)\"")
CS_MAPGROUP_RE = re.compile(r"\b(?:var\s+)?([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*\.\s*MapGroup\s*\(\s*@?\"([^\"]*)\"")
CS_HTTP_ATTRS = {f"Http{m.capitalize()}": m for m in HTTP_METHODS}
CS_INPUT_TYPES = frozenset({"IFormFile", "IFormFileCollection", "IFormCollection"})
CS_SERVICE_TYPE_RE = re.compile(
    r"^(?:I[A-Z]\w*|\w*(?:Context|Service|Repository|Logger|Options|Mediator|Sender|Factory|Provider|Client)"
    r"(?:<.*>)?|CancellationToken|HttpContext|HttpRequest|ClaimsPrincipal|ILogger<.*>)$"
)


def _cs_is_service(ptype: str, pattrs: list[str]) -> bool:
    """True for injected services/infrastructure parameters (not user input)."""
    if not ptype or "FromBody" in pattrs or ptype.rstrip("?") in CS_INPUT_TYPES:
        return False
    return bool(CS_SERVICE_TYPE_RE.match(ptype))


def _cs_attributes(lines: list[str]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for line in lines:
        for block in re.findall(r"\[([^\[\]]*(?:\[[^\[\]]*\][^\[\]]*)*)\]", line):
            for match in CS_ATTR_RE.finditer(block.strip() + "]"):
                if match.group(1):
                    out.append((match.group(1), match.group(2) or ""))
    return out


def _first_string(args: str) -> str | None:
    match = CS_STRING_RE.search(args) or re.search(r"'([^']*)'", args) or re.search(r"`([^`]*)`", args)
    return match.group(1) if match else None


def _cs_param_name(param: str) -> tuple[str, str, list[str]]:
    attrs = re.findall(r"\[(\w+)", param)
    cleaned = re.sub(r"\[[^\]]*\]", "", param)
    cleaned = cleaned.split("=")[0].strip()
    cleaned = re.sub(r"^(?:this|params|ref|out|in|scoped)\s+", "", cleaned)
    parts = cleaned.rsplit(None, 1)
    if len(parts) == 2:
        return parts[1], parts[0].strip(), attrs
    return cleaned, "", attrs


def _parse_csharp(pf: PgFile) -> None:
    masked_lines = pf.masked.split("\n")
    code_lines = pf.code.split("\n")
    pairs = _brace_pairs(pf.masked)
    namespaces: list[tuple[int, int, str]] = []
    for idx, line in enumerate(masked_lines):
        using = CS_USING_RE.match(line)
        if using:
            pf.imports.append((using.group(1), idx + 1))
        ns = CS_NAMESPACE_RE.match(line)
        if ns:
            start = pf.line_start(idx + 1) + ns.end()
            body = _body_after(pf.masked, pairs, start)
            end = body[1] if body[0] >= 0 and pf.masked[body[0]] == "{" else len(pf.masked)
            namespaces.append((start, end, ns.group(1)))
    pf.namespace = namespaces[0][2] if namespaces else ""

    def namespace_at(pos: int) -> str:
        best = ""
        for start, end, name in namespaces:
            if start <= pos <= end:
                best = name
        return best

    # Types first so methods can find their containers.
    for idx, line in enumerate(masked_lines):
        match = CS_TYPE_RE.match(line)
        if not match:
            continue
        pos = pf.line_start(idx + 1) + match.end()
        decl_kind = match.group(1).split()[0]
        name = match.group(2)
        after = pf.masked[pos : pos + 4000]
        params: list[str] = []
        primary = re.match(r"\s*(?:<[^>{;]*>)?\s*\(", after)
        if primary:
            open_pos = pos + primary.end() - 1
            close = _match_paren(pf, open_pos)
            if close != -1:
                params = _split_params(pf.code[open_pos + 1 : close])
                pos = close + 1
                after = pf.masked[pos : pos + 4000]
        bases: list[str] = []
        base_match = re.match(r"\s*(?:<[^>{;]*>)?\s*:\s*([^{;]*?)(?:\bwhere\b|\{|;|$)", after, re.S)
        if base_match:
            raw = pf.code[pos + base_match.start(1) : pos + base_match.end(1)]
            bases = [re.sub(r"\s*\(.*$", "", b, flags=re.S).strip() for b in _split_params(raw)]
        body = _body_after(pf.masked, pairs, pos)
        container = _container_for(pf, pf.line_start(idx + 1))
        namespace = namespace_at(pf.line_start(idx + 1))
        qual_prefix = container.qualname if container else namespace
        attrs = _cs_attributes(_decorators_before(code_lines, idx, "[") + [code_lines[idx]])
        sym = PgSymbol(
            kind="class",
            name=name,
            qualname=f"{qual_prefix}.{name}" if qual_prefix else name,
            line=idx + 1,
            end_line=pf.line_of(body[1]) if body[1] >= 0 else idx + 1,
            body_start=body[0],
            body_end=body[1],
            container=container.qualname if container else "",
            decl_kind=decl_kind,
            params=params,
            bases=bases,
            decorators=[f"{a}({v})" if v else a for a, v in attrs],
        )
        _cs_classify_type(sym, attrs)
        if params and decl_kind != "record":
            # C# 12 primary constructors on classes inject services; record
            # primary constructors declare data, not dependencies.
            sym.injected = [
                ptype for _, ptype, _ in (_cs_param_name(p) for p in params) if ptype and ptype[:1].isupper()
            ]
        _add_symbol(pf, sym)

    classes = [s for s in pf.symbols if s.kind == "class"]
    for idx, line in enumerate(masked_lines):
        match = CS_METHOD_RE.match(line)
        if not match:
            continue
        name = match.group(3)
        if name in CALL_STOPLIST and name not in {"Add", "Remove", "Count"}:
            continue
        open_pos = pf.line_start(idx + 1) + match.end() - 1
        close = _match_paren(pf, open_pos)
        if close == -1:
            continue
        container = _container_for(pf, open_pos)
        if container is None:
            continue
        params = _split_params(pf.code[open_pos + 1 : close])
        body = _body_after(pf.masked, pairs, close + 1)
        modifiers = match.group(1).split()
        attrs = _cs_attributes(_decorators_before(code_lines, idx, "[") + [code_lines[idx][: match.end()]])
        is_ctor = name == container.name and not match.group(2)
        sym = PgSymbol(
            kind="method",
            name=name,
            qualname=f"{container.qualname}.{name}",
            line=idx + 1,
            end_line=pf.line_of(body[1]) if body[1] >= 0 else idx + 1,
            body_start=body[0],
            body_end=body[1],
            container=container.qualname,
            decl_kind="constructor" if is_ctor else "method",
            params=params,
            decorators=[f"{a}({v})" if v else a for a, v in attrs],
        )
        if is_ctor:
            container.injected.extend(t for _, t, _ in (_cs_param_name(p) for p in params) if t)
        elif container.stereotype == "controller" and "public" in modifiers and "static" not in modifiers:
            if not any(a == "NonAction" for a, _ in attrs):
                _cs_controller_route(sym, container, attrs)
        else:
            _cs_attribute_route(sym, attrs)
        if sym.routes:
            sym.kind = "endpoint"
            sym.framework = "aspnetcore"
            for p in params:
                pname, ptype, pattrs = _cs_param_name(p)
                if "FromServices" in pattrs:
                    continue
                if _cs_is_service(ptype, pattrs):
                    continue
                sym.tainted_params.append(pname)
        _add_symbol(pf, sym)

    _cs_minimal_apis(pf, pairs, code_lines)
    for cls in classes:
        cls.injected = sorted(set(cls.injected))


def _cs_classify_type(sym: PgSymbol, attrs: list[tuple[str, str]]) -> None:
    simple_bases = [_simple(b) for b in sym.bases]
    names = {a for a, _ in attrs}
    if "ApiController" in names or sym.name.endswith("Controller") or {"Controller", "ControllerBase"} & set(simple_bases):
        sym.stereotype = "controller"
        sym.framework = "aspnetcore"
        for attr, args in attrs:
            if attr == "Route":
                template = _first_string(args)
                if template is not None:
                    sym.routes.append({"method": "ANY", "path": template})
    elif "DbContext" in simple_bases or sym.name.endswith("DbContext"):
        sym.stereotype = "repository"
    elif any(b.startswith(("IRequestHandler", "INotificationHandler")) for b in sym.bases):
        sym.stereotype = "handler"
        sym.framework = "mediatr"
    elif sym.name.endswith("Repository"):
        sym.stereotype = "repository"
    elif sym.name.endswith("Service"):
        sym.stereotype = "service"
    elif "Hub" in simple_bases:
        sym.stereotype = "controller"
        sym.framework = "signalr"


def _cs_route_tokens(path: str, controller: str, action: str) -> str:
    ctrl = controller[: -len("Controller")] if controller.endswith("Controller") else controller
    return path.replace("[controller]", ctrl).replace("[action]", action).replace("[area]", "")


def _cs_controller_route(sym: PgSymbol, container: PgSymbol, attrs: list[tuple[str, str]]) -> None:
    class_routes = [r["path"] for r in container.routes] or [""]
    verbs: list[tuple[str, str | None]] = []
    method_routes: list[str] = []
    for attr, args in attrs:
        if attr in CS_HTTP_ATTRS:
            verbs.append((CS_HTTP_ATTRS[attr], _first_string(args)))
        elif attr == "Route":
            template = _first_string(args)
            if template is not None:
                method_routes.append(template)
        elif attr == "AcceptVerbs":
            for verb in re.findall(r"\"(\w+)\"", args):
                verbs.append((verb.upper(), None))
    if not verbs:
        verbs = [("ANY", None)]
    templates: list[tuple[str, str]] = []
    for verb, template in verbs:
        for route in method_routes or [template or ""]:
            templates.append((verb, route if template is None else template))
    if not container.routes and not method_routes and all(t is None for _, t in verbs):
        templates = [(verb, "[controller]/[action]") for verb, _ in verbs]
    for verb, template in templates:
        for prefix in class_routes:
            if template.startswith(("/", "~/")):
                path = _join_route(template.lstrip("~"))
            else:
                path = _join_route(prefix, template)
            sym.routes.append({"method": verb, "path": _cs_route_tokens(path, container.name, sym.name)})
    sym.routes = _dedupe_routes(sym.routes)


def _cs_attribute_route(sym: PgSymbol, attrs: list[tuple[str, str]]) -> None:
    for attr, args in attrs:
        if attr in CS_HTTP_ATTRS:
            template = _first_string(args)
            if template is not None:
                sym.routes.append({"method": CS_HTTP_ATTRS[attr], "path": _join_route(template)})


def _cs_minimal_apis(pf: PgFile, pairs: dict[int, int], code_lines: list[str]) -> None:
    groups: dict[str, str] = {}
    for line in code_lines:
        for match in CS_MAPGROUP_RE.finditer(line):
            base = groups.get(match.group(2), "")
            groups[match.group(1)] = _join_route(base, match.group(3))
    for idx, line in enumerate(code_lines):
        for match in CS_MAP_RE.finditer(line):
            verb = (match.group(2) or "").upper()
            if verb in ("", "METHODS"):
                verb = "ANY"
            receiver = match.group(1)
            path = _join_route(groups.get(receiver, ""), match.group(3))
            call_open = pf.line_start(idx + 1) + line.index("(", match.start(2) if match.group(2) else match.start())
            _route_handler_symbol(pf, pairs, idx, call_open, verb, path, "aspnetcore-minimal", csharp=True)


def _dedupe_routes(routes: list[dict[str, str]]) -> list[dict[str, str]]:
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, str]] = []
    for route in routes:
        key = (route["method"], route["path"])
        if key not in seen:
            seen.add(key)
            out.append(route)
    return sorted(out, key=lambda r: (r["path"], r["method"]))


def _route_handler_symbol(
    pf: PgFile,
    pairs: dict[int, int],
    idx: int,
    call_open: int,
    verb: str,
    path: str,
    framework: str,
    *,
    csharp: bool = False,
) -> PgSymbol:
    """Create an endpoint for a route registration call ``x.get('/p', handler)``."""
    close = _match_paren(pf, call_open)
    if close == -1:
        close = min(len(pf.masked), call_open + 200)
    args_masked = pf.masked[call_open + 1 : close]
    args_code = pf.code[call_open + 1 : close]
    body = (-1, -1)
    params: list[str] = []
    handler_ref = ""
    inline = re.search(r"=>|\bfunction\b|\bfunc\s*\(", args_masked)
    if inline:
        head = args_masked[: inline.start()]
        paren = head.rfind("(")
        if paren != -1:
            p_close = _match_paren(pf, call_open + 1 + paren)
            if p_close != -1 and p_close < call_open + 1 + inline.start() + 1:
                params = _split_params(pf.code[call_open + 2 + paren : p_close])
        if inline.group(0) == "=>":
            body = _body_after(pf.masked, pairs, call_open + 1 + inline.start())
        else:
            fn_paren = inline.end() - 1 if inline.group(0).endswith("(") else args_masked.find("(", inline.end())
            if fn_paren != -1:
                p_close = _match_paren(pf, call_open + 1 + fn_paren)
                if p_close != -1:
                    params = _split_params(pf.code[call_open + 2 + fn_paren : p_close])
                    body = _body_after(pf.masked, pairs, p_close + 1)
        if body[0] == -1:
            body = (call_open, close)
    else:
        idents = re.findall(
            r"([A-Za-z_$\\][\w$.\\]*)(?:::class\s*,\s*['\"](\w+)['\"])?", args_code.split(",", 1)[-1]
        )
        refs = [f"{a}::{b}" if b else a for a, b in idents if a and not a.startswith(("'", '"'))]
        string_ref = re.search(r"['\"]([\w\\]+)@(\w+)['\"]", args_code)
        if string_ref:
            handler_ref = f"{string_ref.group(1)}::{string_ref.group(2)}"
        elif refs:
            handler_ref = refs[-1]
        body = (call_open, close)
    tainted: list[str] = []
    if csharp:
        for p in params:
            pname, ptype, pattrs = _cs_param_name(p)
            if "FromServices" in pattrs or _cs_is_service(ptype, pattrs):
                continue
            tainted.append(pname)
    sym = PgSymbol(
        kind="endpoint",
        name=f"{verb} {path}",
        qualname=f"{pf.path}:{verb} {path}",
        line=idx + 1,
        end_line=pf.line_of(body[1]) if body[1] >= 0 else idx + 1,
        body_start=body[0],
        body_end=body[1],
        params=params,
        routes=[{"method": verb, "path": path}],
        framework=framework,
        handler_ref=handler_ref,
        tainted_params=tainted,
        decl_kind="route",
    )
    return _add_symbol(pf, sym)


# ------------------------------------------------------------------ JS / TS

JS_IMPORT_RES = (
    re.compile(r"^\s*(?:import|export)\s+(?:type\s+)?(?:[\w*{}\s,$]+?\s+from\s+)?['\"]([^'\"]+)['\"]"),
    re.compile(r"\brequire\s*\(\s*['\"]([^'\"]+)['\"]\s*\)"),
    re.compile(r"\bimport\s*\(\s*['\"]([^'\"]+)['\"]\s*\)"),
)
JS_CLASS_RE = re.compile(
    r"^\s*(?:export\s+)?(?:default\s+)?(?:abstract\s+)?class\s+([A-Za-z_$][\w$]*)(?:\s*<[^>{]*>)?"
    r"(?:\s+extends\s+([\w$.]+)(?:<[^>{]*>)?)?(?:\s+implements\s+([\w$.,\s<>]+?))?\s*\{"
)
JS_FUNCTION_RE = re.compile(
    r"^\s*(export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)\s*(?:<[^>(]*>)?\s*\("
)
JS_ARROW_RE = re.compile(
    r"^\s*(export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*[^=]+?)?=\s*(?:async\s+)?"
    r"(?:function\b[^(]*\(|(\()|([A-Za-z_$][\w$]*)\s*=>)"
)
JS_METHOD_RE = re.compile(
    r"^\s*(?:@\w+(?:\([^)]*\))?\s*)*(?:(?:public|private|protected|static|async|readonly|override|abstract|"
    r"get|set)\s+)*\*?([A-Za-z_$][\w$]*)\s*(?:<[^>(]*>)?\s*\("
)
JS_PROP_ARROW_RE = re.compile(
    r"^\s*(?:(?:public|private|protected|static|readonly)\s+)*([A-Za-z_$][\w$]*)\s*(?::\s*[^=]+?)?=\s*"
    r"(?:async\s+)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*(?::\s*[^=]+?)?=>"
)
JS_ROUTE_RE = re.compile(
    r"\b([A-Za-z_$][\w$]*)\s*\.\s*(get|post|put|delete|patch|options|head|all)\s*\(\s*(['\"`])(/[^'\"`]*)\3"
)
JS_ROUTE_CHAIN_RE = re.compile(r"\b([A-Za-z_$][\w$]*)\s*\.\s*route\s*\(\s*(['\"`])(/[^'\"`]*)\2\s*\)")
JS_ROUTER_RECEIVER_RE = re.compile(
    r"^(?:app|router|server|api|fastify|routes?|hono|koa|instance|\w*(?:Router|router|App|app|Routes|routes|"
    r"Server|server|Api|api))$"
)
JS_KEYWORDS = frozenset(
    {"if", "for", "while", "switch", "catch", "function", "return", "super", "with", "else", "do"}
)
NEST_ROUTE_DECOS = {m.capitalize(): m for m in HTTP_METHODS} | {"All": "ANY"}
NEXT_APP_ROUTE_RE = re.compile(r"(?:^|/)app/(?:(.*)/)?route\.(?:[mc]?[jt]sx?)$")
NEXT_PAGES_API_RE = re.compile(r"(?:^|/)pages/api/(.+)\.(?:[mc]?[jt]sx?)$")


def _next_path(segment: str) -> str:
    parts = []
    for part in segment.split("/"):
        if not part or (part.startswith("(") and part.endswith(")")) or part.startswith("@"):
            continue
        part = re.sub(r"^\[\[?\.\.\.(\w+)\]?\]$", r"{\1*}", part)
        part = re.sub(r"^\[(\w+)\]$", r"{\1}", part)
        parts.append(part)
    return "/" + "/".join(parts)


def _parse_js(pf: PgFile) -> None:
    masked_lines = pf.masked.split("\n")
    code_lines = pf.code.split("\n")
    pairs = _brace_pairs(pf.masked)
    scopes = _line_scopes(pf.masked, pf._line_starts)
    for idx, line in enumerate(code_lines):
        for regex in JS_IMPORT_RES:
            for imp in regex.finditer(line):
                pf.imports.append((imp.group(1), idx + 1))

    for idx, line in enumerate(masked_lines):
        match = JS_CLASS_RE.match(line)
        if not match:
            continue
        brace = pf.line_start(idx + 1) + match.end() - 1
        close = pairs.get(brace, -1)
        bases = [b for b in [match.group(2) or ""] + _split_params(match.group(3) or "") if b]
        decos = _decorators_before(code_lines, idx, "@")
        sym = PgSymbol(
            kind="class",
            name=match.group(1),
            qualname=f"{pf.path}:{match.group(1)}",
            line=idx + 1,
            end_line=pf.line_of(close) if close != -1 else idx + 1,
            body_start=brace,
            body_end=close,
            decl_kind="class",
            bases=bases,
            decorators=decos,
        )
        for deco in decos:
            ctrl = re.match(r"@Controller\s*\(\s*(?:['\"`]([^'\"`]*)['\"`])?", deco)
            if ctrl:
                sym.stereotype = "controller"
                sym.framework = "nestjs"
                sym.routes.append({"method": "ANY", "path": ctrl.group(1) or ""})
            elif re.match(r"@Injectable\b", deco):
                sym.stereotype = "service"
                sym.framework = "nestjs"
            elif re.match(r"@(?:Entity|Schema)\b", deco):
                sym.stereotype = "model"
        _add_symbol(pf, sym)

    classes_by_brace = {s.body_start: s for s in pf.symbols if s.kind == "class"}
    for idx, line in enumerate(masked_lines):
        line_pos = pf.line_start(idx + 1)
        exported = False
        name = ""
        open_pos = -1
        container: PgSymbol | None = None
        fn = JS_FUNCTION_RE.match(line)
        arrow = None if fn else JS_ARROW_RE.match(line)
        if fn:
            exported, name = bool(fn.group(1)), fn.group(2)
            open_pos = line_pos + fn.end() - 1
        elif arrow:
            exported, name = bool(arrow.group(1)), arrow.group(2)
            if arrow.group(3):
                open_pos = line_pos + arrow.start(3)
            elif arrow.group(4):
                open_pos = -2  # single identifier param arrow
            else:
                open_pos = line_pos + arrow.end() - 1
        else:
            owner = classes_by_brace.get(scopes[idx]) if idx < len(scopes) else None
            if owner is None:
                continue
            method: re.Match[str] | None = JS_METHOD_RE.match(line)
            prop = None if method else JS_PROP_ARROW_RE.match(line)
            if method and method.group(1) not in JS_KEYWORDS:
                name = method.group(1)
                open_pos = line_pos + method.end() - 1
            elif prop:
                name = prop.group(1)
                open_pos = -2
            else:
                continue
            container = owner
        params: list[str] = []
        if open_pos >= 0:
            close = _match_paren(pf, open_pos)
            if close == -1:
                continue
            if arrow and arrow.group(3):
                after = pf.masked[close + 1 : close + 200]
                if not re.match(r"\s*(?::[^=;{]+)?=>", after):
                    continue
            params = _split_params(pf.code[open_pos + 1 : close])
            body = _body_after(pf.masked, pairs, close + 1)
        else:
            body = _body_after(pf.masked, pairs, line_pos + len(line.split("=>", 1)[0]))
        if body[0] == -1:
            continue
        if container is None:
            container = _container_for(pf, line_pos)
        sym = PgSymbol(
            kind="method" if container else "function",
            name=name,
            qualname=f"{container.qualname}.{name}" if container else f"{pf.path}:{name}",
            line=idx + 1,
            end_line=pf.line_of(body[1]),
            body_start=body[0],
            body_end=body[1],
            container=container.qualname if container else "",
            decl_kind="constructor" if name == "constructor" else ("export" if exported else "function"),
            params=params,
            decorators=_decorators_before(code_lines, idx, "@") if container else [],
        )
        if container is not None and name == "constructor":
            for p in params:
                typed = re.search(r":\s*([A-Za-z_$][\w$.]*)", p)
                if typed:
                    container.injected.append(typed.group(1))
        if container is not None and container.framework == "nestjs":
            _nest_route(sym, container)
        _add_symbol(pf, sym)

    _next_routes(pf)
    # Variables created from a router/app factory are routers whatever their name.
    router_vars = {
        m.group(1)
        for m in re.finditer(
            r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?(?:new\s+)?"
            r"(?:express(?:\.Router)?|Router|Hono|Koa|KoaRouter|fastify|Fastify|polka|restify\.createServer)\s*\(",
            pf.code,
        )
    }
    for idx, line in enumerate(code_lines):
        for match in JS_ROUTE_RE.finditer(line):
            if not (JS_ROUTER_RECEIVER_RE.match(match.group(1)) or match.group(1) in router_vars):
                continue
            verb = match.group(2).upper()
            verb = "ANY" if verb == "ALL" else verb
            call_open = pf.line_start(idx + 1) + line.index("(", match.start(2))
            _route_handler_symbol(pf, pairs, idx, call_open, verb, match.group(4), "express")
        for match in JS_ROUTE_CHAIN_RE.finditer(line):
            statement_end = pf.masked.find(";", pf.line_start(idx + 1) + match.end())
            statement_end = len(pf.masked) if statement_end == -1 else statement_end
            stmt_start = pf.line_start(idx + 1) + match.end()
            for verb_match in re.finditer(r"\.\s*(get|post|put|delete|patch|all)\s*\(", pf.masked[stmt_start:statement_end]):
                verb = verb_match.group(1).upper()
                call_open = stmt_start + verb_match.end() - 1
                _route_handler_symbol(
                    pf, pairs, pf.line_of(call_open) - 1, call_open, "ANY" if verb == "ALL" else verb,
                    match.group(3), "express",
                )
    for cls in pf.symbols:
        if cls.kind == "class":
            cls.injected = sorted(set(cls.injected))


def _nest_route(sym: PgSymbol, container: PgSymbol) -> None:
    prefix = container.routes[0]["path"] if container.routes else ""
    for deco in sym.decorators:
        match = re.match(r"@(\w+)\s*\(\s*(?:['\"`]([^'\"`]*)['\"`])?", deco)
        if match and match.group(1) in NEST_ROUTE_DECOS:
            verb = NEST_ROUTE_DECOS[match.group(1)]
            sym.routes.append({"method": verb, "path": _join_route(prefix, match.group(2) or "")})
    if sym.routes:
        sym.kind = "endpoint"
        sym.framework = "nestjs"
        sym.routes = _dedupe_routes(sym.routes)
        for p in sym.params:
            param_deco = re.match(r"\s*@(Body|Query|Param|Headers|Req|Request)\b[^)]*\)\s*(\w+)", p)
            if param_deco:
                sym.tainted_params.append(param_deco.group(2))


def _next_routes(pf: PgFile) -> None:
    app_match = NEXT_APP_ROUTE_RE.search(pf.path)
    pages_match = NEXT_PAGES_API_RE.search(pf.path)
    if not app_match and not pages_match:
        return
    if app_match:
        path = _next_path(app_match.group(1) or "")
        for sym in pf.symbols:
            if sym.kind == "function" and sym.name in HTTP_METHODS and sym.container == "":
                sym.kind = "endpoint"
                sym.framework = "nextjs"
                sym.routes = [{"method": sym.name, "path": path}]
        return
    assert pages_match is not None
    segment = re.sub(r"/index$", "", pages_match.group(1))
    path = _next_path("api/" + segment)
    default = re.search(r"^\s*export\s+default\s+(?:async\s+)?function\s*([A-Za-z_$][\w$]*)?", pf.masked, re.M)
    target = None
    if default and default.group(1):
        target = next((s for s in pf.symbols if s.name == default.group(1)), None)
    if target is None:
        target = next((s for s in pf.symbols if s.kind == "function" and s.decl_kind == "export"), None)
    if target is not None:
        target.kind = "endpoint"
        target.framework = "nextjs"
        target.routes = [{"method": "ANY", "path": path}]


# ------------------------------------------------------------------------ PHP

PHP_NAMESPACE_RE = re.compile(r"^\s*namespace\s+([A-Za-z_][\w\\]*)")
PHP_USE_RE = re.compile(r"^\s*use\s+([A-Za-z_][\w\\]*)(?:\s+as\s+(\w+))?\s*;")
PHP_CLASS_RE = re.compile(
    r"^\s*(?:#\[[^\]]*\]\s*)*(?:(?:abstract|final|readonly)\s+)*(class|interface|trait|enum)\s+([A-Za-z_]\w*)"
    r"(?:\s+extends\s+([\w\\]+(?:\s*,\s*[\w\\]+)*))?(?:\s+implements\s+([\w\\,\s]+?))?\s*(?:\{|$)"
)
PHP_FUNCTION_RE = re.compile(
    r"^\s*(?:#\[[^\]]*\]\s*)*((?:(?:public|private|protected|static|final|abstract)\s+)*)function\s+&?([A-Za-z_]\w*)\s*\("
)
PHP_LARAVEL_ROUTE_RE = re.compile(
    r"\bRoute::(get|post|put|patch|delete|options|any|match|resource|apiResource)\s*\(\s*"
    r"(?:\[([^\]]*)\]\s*,\s*)?['\"]([^'\"]*)['\"]"
)
PHP_RECEIVER_ROUTE_RE = re.compile(
    r"\$(\w+)\s*->\s*(get|post|put|patch|delete|options|any|map)\s*\(\s*['\"](/[^'\"]*)['\"]"
)
PHP_SYMFONY_ROUTE_RE = re.compile(
    r"#\[Route\(\s*(?:path\s*:\s*)?['\"]([^'\"]*)['\"](?:[^\]]*?methods\s*:\s*\[([^\]]*)\])?"
)
PHP_SUPERGLOBAL_RE = re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b")
PHP_SCALAR_TYPES = frozenset({"", "int", "string", "float", "bool", "array", "mixed", "?int", "?string", "?float"})


def _parse_php(pf: PgFile) -> None:
    masked_lines = pf.masked.split("\n")
    code_lines = pf.code.split("\n")
    pairs = _brace_pairs(pf.masked)
    aliases: dict[str, str] = {}
    for idx, line in enumerate(masked_lines):
        ns = PHP_NAMESPACE_RE.match(line)
        if ns and not pf.namespace:
            pf.namespace = ns.group(1)
        use = PHP_USE_RE.match(line)
        if use:
            pf.imports.append((use.group(1), idx + 1))
            aliases[use.group(2) or use.group(1).rsplit("\\", 1)[-1]] = use.group(1)

    for idx, line in enumerate(masked_lines):
        match = PHP_CLASS_RE.match(line)
        if not match:
            continue
        pos = pf.line_start(idx + 1) + match.end(2)
        body = _body_after(pf.masked, pairs, pos)
        bases = _split_params(match.group(3) or "") + _split_params(match.group(4) or "")
        decos = _decorators_before(code_lines, idx, "#[")
        sym = PgSymbol(
            kind="class",
            name=match.group(2),
            qualname=f"{pf.namespace}\\{match.group(2)}" if pf.namespace else match.group(2),
            line=idx + 1,
            end_line=pf.line_of(body[1]) if body[1] >= 0 else idx + 1,
            body_start=body[0],
            body_end=body[1],
            decl_kind=match.group(1),
            bases=bases,
            decorators=decos,
        )
        simple_bases = {_simple(b) for b in bases}
        if sym.name.endswith("Controller") or {"Controller", "AbstractController", "BaseController"} & simple_bases:
            sym.stereotype = "controller"
        elif {"Model", "Authenticatable"} & simple_bases:
            sym.stereotype = "model"
            sym.framework = "laravel"
        elif sym.name.endswith("Repository"):
            sym.stereotype = "repository"
        elif sym.name.endswith("Service"):
            sym.stereotype = "service"
        for deco in decos:
            route = PHP_SYMFONY_ROUTE_RE.search(deco)
            if route:
                sym.routes.append({"method": "ANY", "path": route.group(1)})
                sym.framework = "symfony"
        _add_symbol(pf, sym)

    for idx, line in enumerate(masked_lines):
        match = PHP_FUNCTION_RE.match(line)
        if not match:
            continue
        name = match.group(2)
        open_pos = pf.line_start(idx + 1) + match.end() - 1
        close = _match_paren(pf, open_pos)
        if close == -1:
            continue
        params = _split_params(pf.code[open_pos + 1 : close])
        body = _body_after(pf.masked, pairs, close + 1)
        container = _container_for(pf, open_pos)
        decos = _decorators_before(code_lines, idx, "#[")
        sym = PgSymbol(
            kind="method" if container else "function",
            name=name,
            qualname=f"{container.qualname}::{name}" if container else (f"{pf.namespace}\\{name}" if pf.namespace else name),
            line=idx + 1,
            end_line=pf.line_of(body[1]) if body[1] >= 0 else idx + 1,
            body_start=body[0],
            body_end=body[1],
            container=container.qualname if container else "",
            decl_kind="constructor" if name == "__construct" else "method",
            params=params,
            decorators=decos,
        )
        if container is not None and name == "__construct":
            for p in params:
                typed = re.match(r"\s*(?:(?:public|private|protected|readonly)\s+)*\??([A-Za-z_\\][\w\\]*)\s+\$", p)
                if typed and typed.group(1).lower() not in PHP_SCALAR_TYPES:
                    container.injected.append(aliases.get(typed.group(1), typed.group(1)))
        prefix = container.routes[0]["path"] if container and container.routes else ""
        for deco in decos:
            route = PHP_SYMFONY_ROUTE_RE.search(deco)
            if route:
                methods = re.findall(r"['\"](\w+)['\"]", route.group(2) or "") or ["ANY"]
                for verb in methods:
                    sym.routes.append({"method": verb.upper(), "path": _join_route(prefix, route.group(1))})
        if sym.routes:
            sym.kind = "endpoint"
            sym.framework = "symfony"
            sym.routes = _dedupe_routes(sym.routes)
            sym.tainted_params = _php_tainted_params(params)
        _add_symbol(pf, sym)

    for idx, line in enumerate(code_lines):
        for match in PHP_LARAVEL_ROUTE_RE.finditer(line):
            verb = match.group(1).upper()
            if verb == "MATCH":
                verbs = [v.upper() for v in re.findall(r"['\"](\w+)['\"]", match.group(2) or "")] or ["ANY"]
                verb = ",".join(verbs)
            elif verb in ("RESOURCE", "APIRESOURCE"):
                verb = "RESOURCE"
            call_open = pf.line_start(idx + 1) + line.index("(", match.start(1))
            sym = _route_handler_symbol(pf, pairs, idx, call_open, verb, _join_route(match.group(3)), "laravel")
            sym.tainted_params = _php_tainted_params(sym.params)
        for match in PHP_RECEIVER_ROUTE_RE.finditer(line):
            verb = match.group(2).upper()
            call_open = pf.line_start(idx + 1) + line.index("(", match.start(2))
            sym = _route_handler_symbol(
                pf, pairs, idx, call_open, "ANY" if verb in ("ANY", "MAP") else verb, match.group(3), "slim"
            )
            sym.tainted_params = _php_tainted_params(sym.params)

    # Legacy page scripts: no classes, superglobals used outside functions.
    if not any(s.kind == "class" for s in pf.symbols) and not any(s.kind == "endpoint" for s in pf.symbols):
        function_spans = [(s.body_start, s.body_end) for s in pf.symbols if s.has_body]
        for match in PHP_SUPERGLOBAL_RE.finditer(pf.code):
            if not any(a <= match.start() <= b for a, b in function_spans):
                _add_symbol(
                    pf,
                    PgSymbol(
                        kind="endpoint",
                        name=f"ANY /{pf.path}",
                        qualname=f"{pf.path}:page",
                        line=1,
                        end_line=pf.line_of(len(pf.masked)),
                        body_start=0,
                        body_end=len(pf.masked),
                        routes=[{"method": "ANY", "path": "/" + pf.path}],
                        framework="php-page",
                        decl_kind="page",
                    ),
                )
                break
    for cls in pf.symbols:
        if cls.kind == "class":
            cls.injected = sorted(set(cls.injected))


def _php_tainted_params(params: list[str]) -> list[str]:
    tainted: list[str] = []
    for p in params:
        match = re.match(r"\s*(?:(?:public|private|protected|readonly)\s+)*(\??[\w\\]+\s+)?&?(?:\.\.\.)?(\$\w+)", p)
        if match and (match.group(1) or "").strip().lower() in PHP_SCALAR_TYPES:
            tainted.append(match.group(2))
    return tainted


# ------------------------------------------------------------------------- Go

GO_PACKAGE_RE = re.compile(r"^\s*package\s+(\w+)")
GO_IMPORT_SINGLE_RE = re.compile(r"^\s*import\s+(?:\w+\s+)?\"([^\"]+)\"")
GO_IMPORT_LINE_RE = re.compile(r"^\s*(?:[\w.]+\s+)?\"([^\"]+)\"\s*$")
GO_TYPE_RE = re.compile(r"^\s*type\s+([A-Za-z_]\w*)(?:\[[^\]]*\])?\s+(struct|interface)\b")
GO_FUNC_RE = re.compile(
    r"^func\s+(?:\(\s*(\w+\s+)?\*?\s*([A-Za-z_]\w*)(?:\[[^\]]*\])?\s*\)\s*)?([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*\("
)
GO_ROUTE_RE = re.compile(
    r"\b([A-Za-z_]\w*)\s*\.\s*(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD|Any|Get|Post|Put|Delete|Patch|Options|Head|"
    r"Handle|HandleFunc|Method)\s*\(\s*(?:\"(\w+)\"\s*,\s*)?\"([^\"]*)\""
)


def _parse_go(pf: PgFile) -> None:
    masked_lines = pf.masked.split("\n")
    code_lines = pf.code.split("\n")
    pairs = _brace_pairs(pf.masked)
    in_import_block = False
    for idx, line in enumerate(code_lines):
        pkg = GO_PACKAGE_RE.match(masked_lines[idx])
        if pkg and not pf.namespace:
            pf.namespace = pkg.group(1)
        if re.match(r"^\s*import\s*\(", line):
            in_import_block = True
            continue
        if in_import_block:
            if line.strip().startswith(")"):
                in_import_block = False
                continue
            imp = GO_IMPORT_LINE_RE.match(line)
            if imp:
                pf.imports.append((imp.group(1), idx + 1))
            continue
        single = GO_IMPORT_SINGLE_RE.match(line)
        if single:
            pf.imports.append((single.group(1), idx + 1))

    package_dir = pf.path.rsplit("/", 1)[0] if "/" in pf.path else "."
    for idx, line in enumerate(masked_lines):
        match = GO_TYPE_RE.match(line)
        if not match:
            continue
        pos = pf.line_start(idx + 1) + match.end()
        body = _body_after(pf.masked, pairs, pos)
        _add_symbol(
            pf,
            PgSymbol(
                kind="class",
                name=match.group(1),
                qualname=f"{package_dir}.{match.group(1)}",
                line=idx + 1,
                end_line=pf.line_of(body[1]) if body[1] >= 0 else idx + 1,
                body_start=body[0],
                body_end=body[1],
                decl_kind=match.group(2),
                stereotype=_go_stereotype(match.group(1)),
            ),
        )
    types = {s.name: s for s in pf.symbols if s.kind == "class"}
    for idx, line in enumerate(masked_lines):
        match = GO_FUNC_RE.match(line)
        if not match:
            continue
        open_pos = pf.line_start(idx + 1) + match.end() - 1
        close = _match_paren(pf, open_pos)
        if close == -1:
            continue
        body = _body_after(pf.masked, pairs, close + 1)
        receiver = match.group(2) or ""
        name = match.group(3)
        owner = f"{package_dir}.{receiver}" if receiver else ""
        sym = PgSymbol(
            kind="method" if receiver else "function",
            name=name,
            qualname=f"{owner}.{name}" if receiver else f"{package_dir}.{name}",
            line=idx + 1,
            end_line=pf.line_of(body[1]) if body[1] >= 0 else idx + 1,
            body_start=body[0],
            body_end=body[1],
            container=owner if receiver and receiver in types else "",
            decl_kind="method" if receiver else "function",
            params=_split_params(pf.code[open_pos + 1 : close]),
        )
        if not receiver and name.startswith("New") and name[3:] in types:
            # Constructor function: its parameters are the injected dependencies.
            types[name[3:]].injected.extend(
                p.split()[-1].lstrip("*") for p in sym.params if len(p.split()) >= 2
            )
        _add_symbol(pf, sym)

    for idx, line in enumerate(code_lines):
        for match in GO_ROUTE_RE.finditer(line):
            path = match.group(4)
            verb = match.group(2).upper()
            if match.group(3):
                verb = match.group(3).upper()
            pattern = re.match(r"^(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+(/\S*)$", path)
            if pattern:
                verb, path = pattern.group(1), pattern.group(2)
            if not path.startswith("/"):
                continue
            if verb in ("HANDLE", "HANDLEFUNC", "ANY", "METHOD"):
                methods = re.search(r"\.Methods\(\s*\"(\w+)\"", line)
                verb = methods.group(1).upper() if methods else "ANY"
            call_open = pf.line_start(idx + 1) + line.index("(", match.start(2))
            _route_handler_symbol(pf, pairs, idx, call_open, verb, path, "go-http")
    for cls in pf.symbols:
        if cls.kind == "class":
            cls.injected = sorted(set(cls.injected))


def _go_stereotype(name: str) -> str:
    lower = name.lower()
    for suffix, stereotype in (("handler", "controller"), ("controller", "controller"), ("repository", "repository"),
                               ("repo", "repository"), ("store", "repository"), ("service", "service")):
        if lower.endswith(suffix):
            return stereotype
    return ""


# ----------------------------------------------------------------------- Rust

RUST_USE_RE = re.compile(r"^\s*use\s+([^;]+);")
RUST_MOD_RE = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_]\w*)\s*;")
RUST_TYPE_RE = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(struct|enum|trait|union)\s+([A-Za-z_]\w*)(?:<[^>{;(]*>)?"
)
RUST_IMPL_RE = re.compile(
    r"^\s*impl(?:<[^>]*>)?\s+(?:([\w:]+)(?:<[^>]*>)?\s+for\s+)?([\w:]+)(?:<[^>{]*>)?\s*\{"
)
RUST_FN_RE = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?(?:extern(?:\s+\"[^\"]*\")?\s+)?fn\s+([A-Za-z_]\w*)\s*(?:<[^(){};]*>)?\s*\("
)
RUST_ACTIX_ROUTE_RE = re.compile(r"^\s*#\[(?:actix_web::)?(get|post|put|delete|patch|head|options)\s*\(\s*\"([^\"]+)\"")
RUST_AXUM_ROUTE_RE = re.compile(r'\.route\s*\(')
RUST_AXUM_METHOD_RE = re.compile(r"\b(get|post|put|delete|patch|head|options|any)\s*\(\s*([A-Za-z_][\w:]*)")


def _rust_stereotype(name: str) -> str:
    lower = name.lower()
    for suffix, stereotype in (
        ("handler", "controller"),
        ("controller", "controller"),
        ("repository", "repository"),
        ("repo", "repository"),
        ("store", "repository"),
        ("service", "service"),
    ):
        if lower.endswith(suffix):
            return stereotype
    return ""


def _rust_tainted_params(params: list[str]) -> list[str]:
    tainted: list[str] = []
    for p in params:
        p = p.strip()
        if p in ("self", "&self", "&mut self", "mut self"):
            continue
        ext_match = re.match(r"^(\w+)\s*\(\s*(?:mut\s+)?(\w+)\s*\)", p)
        if ext_match:
            wrapper = ext_match.group(1)
            if wrapper in ("Query", "Json", "Path", "Form", "HeaderMap"):
                tainted.append(ext_match.group(2))
                continue
        name, _, typ = p.partition(":")
        name = re.sub(r"^(?:mut|ref)\s+", "", name).strip()
        typ = typ.strip()
        if re.match(r"(?:[A-Za-z_]\w*::)*(?:State|Extension|Data)\s*<", typ):
            continue  # application state is not request-controlled input
        if re.search(r"\b(?:Query|Json|Path|Form|HeaderMap|Bytes|String|HttpRequest)\b", typ):
            tainted.append(name)
    return tainted


def _parse_rust(pf: PgFile) -> None:
    masked_lines = pf.masked.split("\n")
    code_lines = pf.code.split("\n")
    pairs = _brace_pairs(pf.masked)
    scopes = _line_scopes(pf.masked, pf._line_starts)

    # 1. Imports / Modules
    for idx, line in enumerate(code_lines):
        use_match = RUST_USE_RE.match(line) if RUST_USE_RE.match(masked_lines[idx]) else None
        if use_match:
            pf.imports.append((use_match.group(1).strip(), idx + 1))
        mod_match = RUST_MOD_RE.match(masked_lines[idx])
        if mod_match:
            pf.imports.append((mod_match.group(1).strip(), idx + 1))

    # 2. Structs, Enums, Traits, Unions
    for idx, line in enumerate(masked_lines):
        match = RUST_TYPE_RE.match(line)
        if not match:
            continue
        name = match.group(2)
        decl_kind = match.group(1)
        pos = pf.line_start(idx + 1) + match.end()
        body = _body_after(pf.masked, pairs, pos)
        decos = _decorators_before(code_lines, idx, "#[")
        sym = PgSymbol(
            kind="class",
            name=name,
            qualname=f"{pf.path}:{name}",
            line=idx + 1,
            end_line=pf.line_of(body[1]) if body[1] >= 0 else idx + 1,
            body_start=body[0],
            body_end=body[1],
            decl_kind=decl_kind,
            decorators=decos,
            stereotype=_rust_stereotype(name),
        )
        _add_symbol(pf, sym)

    # 3. Impl blocks to link methods to structs and record trait bases
    types_by_name = {s.name: s for s in pf.symbols if s.kind == "class"}
    impl_by_brace: dict[int, str] = {}
    for idx, line in enumerate(masked_lines):
        impl_match = RUST_IMPL_RE.match(line)
        if not impl_match:
            continue
        trait_name = impl_match.group(1)
        struct_name = impl_match.group(2).rsplit("::", 1)[-1]
        brace = pf.line_start(idx + 1) + impl_match.end() - 1
        impl_by_brace[brace] = struct_name
        if trait_name and struct_name in types_by_name:
            types_by_name[struct_name].bases.append(trait_name.rsplit("::", 1)[-1])

    # 4. Functions & Methods
    for idx, line in enumerate(masked_lines):
        match = RUST_FN_RE.match(line)
        if not match:
            continue
        open_pos = pf.line_start(idx + 1) + match.end() - 1
        close = _match_paren(pf, open_pos)
        if close == -1:
            continue
        body = _body_after(pf.masked, pairs, close + 1)
        name = match.group(1)
        decos = _decorators_before(code_lines, idx, "#[")
        raw_params = _split_params(pf.code[open_pos + 1 : close])
        is_method = False
        owner_name = ""
        current_scope = scopes[idx] if idx < len(scopes) else -1
        if current_scope in impl_by_brace:
            owner_name = impl_by_brace[current_scope]
            is_method = True
        elif raw_params and any(p.strip().startswith(("self", "&self", "&mut self", "mut self")) for p in raw_params[:1]):
            is_method = True

        owner_qual = f"{pf.path}:{owner_name}" if owner_name else ""
        sym = PgSymbol(
            kind="method" if is_method else "function",
            name=name,
            qualname=f"{owner_qual}.{name}" if owner_qual else f"{pf.path}:{name}",
            line=idx + 1,
            end_line=pf.line_of(body[1]) if body[1] >= 0 else idx + 1,
            body_start=body[0],
            body_end=body[1],
            container=owner_qual,
            decl_kind="method" if is_method else "function",
            params=raw_params,
            decorators=decos,
        )

        # Check for Actix-web / Rocket attribute routing: #[get("/path")]
        for deco in decos:
            actix_match = RUST_ACTIX_ROUTE_RE.match(deco)
            if actix_match:
                verb = actix_match.group(1).upper()
                route_path = actix_match.group(2)
                sym.kind = "endpoint"
                sym.framework = "actix-web"
                sym.routes.append({"method": verb, "path": route_path})
                sym.tainted_params = _rust_tainted_params(sym.params)

        _add_symbol(pf, sym)

    # 5. Axum Router declarations: Router::new().route("/path", get(handler).post(handler))
    for route_match in RUST_AXUM_ROUTE_RE.finditer(pf.masked):
        open_pos = route_match.end() - 1
        close = _match_paren(pf, open_pos)
        if close == -1:
            continue
        path_match = re.match(r'\s*"([^"\\]*)"\s*,', pf.code[open_pos + 1 : close])
        if path_match is None:
            continue
        route_path = path_match.group(1)
        handlers_start = open_pos + 1 + path_match.end()
        for m_match in RUST_AXUM_METHOD_RE.finditer(pf.masked, handlers_start, close):
            verb = m_match.group(1).upper()
            handler_ref = m_match.group(2)
            call_line = pf.line_of(route_match.start())
            route_sym = PgSymbol(
                kind="endpoint",
                name=f"{verb} {route_path}",
                qualname=f"{pf.path}:{call_line}:{verb} {route_path}",
                line=call_line,
                end_line=pf.line_of(close),
                routes=[{"method": verb, "path": route_path}],
                framework="axum",
                handler_ref=handler_ref,
                decl_kind="route",
            )
            _add_symbol(pf, route_sym)

    for cls in pf.symbols:
        if cls.kind == "class":
            cls.bases = sorted(set(cls.bases))


# ------------------------------------------------------------------ Dart / Flutter

DART_IMPORT_RE = re.compile(r"^\s*(?:import|export|part)\s+['\"]([^'\"]+)['\"]")
DART_TYPE_RE = re.compile(
    r"^\s*(?:abstract\s+(?:interface\s+|base\s+|final\s+|sealed\s+)?)?"
    r"(class|mixin|enum|extension)\s+([A-Za-z_]\w*)"
)
DART_BASES_RE = re.compile(r"\b(?:extends|with|implements|on)\s+([^{]+)")
DART_FN_RE = re.compile(
    r"^\s*(?:(?:static|external|factory|const|abstract|override)\s+)*"
    r"(?:[\w.<>, ?]+\s+)?([A-Za-z_]\w*)\s*\("
)
DART_NOT_FN = frozenset(
    {
        "if", "for", "while", "switch", "catch", "return", "throw", "assert",
        "else", "try", "finally", "new", "const", "super", "this", "await",
    }
)
DART_GOROUTE_RE = re.compile(r"\bGoRoute\s*\(")
DART_SHELF_ROUTE_RE = re.compile(
    r"\b(?:router|app)\s*\.\s*(get|post|put|delete|patch|all)\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*([A-Za-z_]\w*)"
)
DART_INGRESS_TYPES = (
    "GoRouterState", "RouteSettings", "MethodCall", "JavaScriptMessage",
    "RequestContext", "Request", "Uri",
)


def _dart_stereotype(name: str, bases: list[str]) -> str:
    lower = name.lower()
    base_lower = " ".join(b.lower() for b in bases)
    if any(w in base_lower for w in ("statelesswidget", "statefulwidget", "state<", "consumerwidget", "hookwidget")):
        return "view"
    for suffix, stereotype in (
        ("controller", "controller"),
        ("bloc", "controller"),
        ("cubit", "controller"),
        ("notifier", "controller"),
        ("repository", "repository"),
        ("repo", "repository"),
        ("datasource", "repository"),
        ("dao", "repository"),
        ("service", "service"),
        ("client", "service"),
        ("api", "service"),
    ):
        if lower.endswith(suffix):
            return stereotype
    return ""


def _dart_tainted_params(params: list[str]) -> list[str]:
    tainted: list[str] = []
    for raw in params:
        text = re.sub(r"^(?:required|covariant|final)\s+", "", raw.strip()).strip("{}[] ")
        if not text:
            continue
        # Remove default value
        text = text.split("=", 1)[0].strip()
        parts = text.rsplit(None, 1)
        if len(parts) == 2:
            typ, name = parts[0].strip(), parts[1].strip()
            if any(t in typ for t in DART_INGRESS_TYPES):
                tainted.append(name)
        elif len(parts) == 1 and re.match(r"^[A-Za-z_]\w*$", parts[0]):
            if parts[0] in ("request", "context", "call", "message", "state", "settings", "uri", "args"):
                tainted.append(parts[0])
    return tainted


def _parse_dart(pf: PgFile) -> None:
    masked_lines = pf.masked.split("\n")
    code_lines = pf.code.split("\n")
    pairs = _brace_pairs(pf.masked)
    scopes = _line_scopes(pf.masked, pf._line_starts)

    for idx, line in enumerate(code_lines):
        imp = DART_IMPORT_RE.match(line) if DART_IMPORT_RE.match(masked_lines[idx]) else None
        if imp:
            pf.imports.append((imp.group(1).strip(), idx + 1))

    for idx, line in enumerate(masked_lines):
        match = DART_TYPE_RE.match(line)
        if not match:
            continue
        decl_kind, name = match.group(1), match.group(2)
        pos = pf.line_start(idx + 1) + match.end()
        body = _body_after(pf.masked, pairs, pos)
        header = pf.code[pf.line_start(idx + 1) : body[0] if body[0] >= 0 else pf.line_start(idx + 1) + len(line)]
        bases: list[str] = []
        bases_m = DART_BASES_RE.search(header)
        if bases_m:
            raw_bases = re.split(r"\b(?:extends|with|implements|on)\b", bases_m.group(1))
            for chunk in raw_bases:
                for b in chunk.split(","):
                    b = b.strip()
                    if b:
                        bases.append(b)
        decos = _decorators_before(code_lines, idx, "@")
        sym = PgSymbol(
            kind="class",
            name=name,
            qualname=f"{pf.path}:{name}",
            line=idx + 1,
            end_line=pf.line_of(body[1]) if body[1] >= 0 else idx + 1,
            body_start=body[0],
            body_end=body[1],
            decl_kind=decl_kind,
            bases=sorted(set(bases)),
            decorators=decos,
            stereotype=_dart_stereotype(name, bases),
        )
        _add_symbol(pf, sym)

    classes_by_brace = {s.body_start: s for s in pf.symbols if s.kind == "class" and s.body_start >= 0}
    for idx, line in enumerate(masked_lines):
        if DART_TYPE_RE.match(line):
            continue
        match = DART_FN_RE.match(line)
        if not match:
            continue
        name = match.group(1)
        if name in DART_NOT_FN:
            continue
        open_pos = pf.line_start(idx + 1) + match.end() - 1
        close = _match_paren(pf, open_pos)
        if close == -1:
            continue
        body = _body_after(pf.masked, pairs, close + 1)
        if body[0] < 0 or body[1] <= body[0]:
            continue
        owner = classes_by_brace.get(scopes[idx]) if idx < len(scopes) else None
        if owner is not None and name == owner.name:
            continue  # constructor
        raw_params = _split_params(pf.code[open_pos + 1 : close])
        decos = _decorators_before(code_lines, idx, "@")
        owner_qual = owner.qualname if owner is not None else ""
        is_method = owner is not None
        tainted_params = _dart_tainted_params(raw_params)
        is_entrypoint = bool(tainted_params) or name in ("main", "onRequest", "onGenerateRoute")
        sym = PgSymbol(
            kind="endpoint" if (is_entrypoint and tainted_params) else ("method" if is_method else "function"),
            name=name,
            qualname=f"{owner_qual}.{name}" if owner_qual else f"{pf.path}:{name}",
            line=idx + 1,
            end_line=pf.line_of(body[1]) if body[1] >= 0 else idx + 1,
            body_start=body[0],
            body_end=body[1],
            container=owner_qual,
            decl_kind="method" if is_method else "function",
            params=raw_params,
            decorators=decos,
            tainted_params=tainted_params,
            routes=[{"method": "INGRESS", "path": f"/{name}"}] if (is_entrypoint and tainted_params) else [],
            auth="anonymous" if (is_entrypoint and tainted_params) else "",
            framework="flutter" if (is_entrypoint and tainted_params) else "",
        )
        _add_symbol(pf, sym)

    # GoRouter routes: GoRoute(path: '/...', ...)
    for route_match in DART_GOROUTE_RE.finditer(pf.masked):
        open_pos = route_match.end() - 1
        close = _match_paren(pf, open_pos)
        if close == -1:
            continue
        args_code = pf.code[open_pos + 1 : close]
        path_m = re.search(r"\bpath\s*:\s*['\"]([^'\"]+)['\"]", args_code)
        if not path_m:
            continue
        route_path = path_m.group(1)
        call_line = pf.line_of(route_match.start())
        route_sym = PgSymbol(
            kind="endpoint",
            name=f"ROUTE {route_path}",
            qualname=f"{pf.path}:{call_line}:ROUTE {route_path}",
            line=call_line,
            end_line=pf.line_of(close),
            routes=[{"method": "NAV", "path": route_path}],
            framework="go_router",
            decl_kind="route",
        )
        _add_symbol(pf, route_sym)

    # Shelf / Dart backend routes: router.get('/path', handler)
    for shelf_m in DART_SHELF_ROUTE_RE.finditer(pf.code):
        verb, route_path, handler_ref = shelf_m.group(1).upper(), shelf_m.group(2), shelf_m.group(3)
        call_line = pf.line_of(shelf_m.start())
        _add_symbol(
            pf,
            PgSymbol(
                kind="endpoint",
                name=f"{verb} {route_path}",
                qualname=f"{pf.path}:{call_line}:{verb} {route_path}",
                line=call_line,
                end_line=call_line,
                routes=[{"method": verb, "path": route_path}],
                framework="shelf",
                handler_ref=handler_ref,
                decl_kind="route",
            ),
        )


# ------------------------------------------------------------- auth markers

AUTH_MW_RE = re.compile(
    r"(?i)(?<!\w)(?:auth|authn|authz|authenticated?|authorized?|requireAuth\w*|isAuthenticated|ensureAuthenticated|"
    r"ensureLoggedIn|isLoggedIn|loginRequired|login_required|requiresAuth|withAuth|verifyToken|verifyJwt|checkJwt|"
    r"jwtAuth|jwtMiddleware|authMiddleware|authGuard|requireUser|requireLogin|protect|basicAuth|JWTAuth|"
    r"passport\.authenticate|auth:sanctum|auth:api|sanctum|RequireAuthorization)(?:\b|\()"
)
ANON_DECORATOR_RE = re.compile(r"(?i)^(?:AllowAnonymous|@?Public|@?AllowAnonymous|@?SkipAuth|PermitAll)\b|PUBLIC_ACCESS|IS_AUTHENTICATED_ANONYMOUSLY")
AUTH_DECORATOR_RE = re.compile(
    r"(?i)^(?:Authorize|@?UseGuards|#\[IsGranted|IsGranted|@?Roles|PreAuthorize|Secured|RolesAllowed)\b"
)
NEXT_AUTH_CALL_RE = re.compile(r"\b(?:getServerSession|auth|currentUser|getToken|requireAuth|getAuth|clerkClient)\s*\(")


def _decorator_auth(decorators: list[str]) -> str:
    names = [re.sub(r"^\s*(?:#\[)?@?", "", d) for d in decorators]
    if any(ANON_DECORATOR_RE.search(d) or ANON_DECORATOR_RE.search(n) for d, n in zip(decorators, names, strict=False)):
        return "anonymous"
    if any(AUTH_DECORATOR_RE.search(n) or AUTH_DECORATOR_RE.search(d) for d, n in zip(decorators, names, strict=False)):
        return "required"
    return ""


def _statement_after(pf: PgFile, pos: int, limit: int = 400) -> str:
    end = pf.masked.find(";", pos, pos + limit)
    return pf.code[pos : end if end != -1 else min(len(pf.code), pos + limit)]


def _detect_auth(pf: PgFile) -> None:
    """Record ``required`` / ``anonymous`` auth markers on endpoints and methods.

    Most specific wins: method-level anonymous > method-level required >
    class-level > route-group / file-level middleware. Empty means no marker was
    found (unknown exposure), never "safe".
    """
    classes = {s.qualname: s for s in pf.symbols if s.kind == "class"}
    class_auth: dict[str, str] = {}
    for cls in classes.values():
        marker = _decorator_auth(cls.decorators)
        if not marker and pf.language == "php" and cls.has_body:
            body = pf.code[cls.body_start : cls.body_end]
            if re.search(r"\$this->middleware\(\s*\[?\s*['\"]auth", body):
                marker = "required"
        if marker:
            class_auth[cls.qualname] = marker
    # Route groups / middleware applied to a router variable or a closure.
    guarded_vars: set[str] = set()
    for match in re.finditer(r"\b(\w+)\s*:?=\s*\w+\s*\.\s*(?:Group|MapGroup|group)\s*\(([^;]*)", pf.code):
        if AUTH_MW_RE.search(match.group(2)):
            guarded_vars.add(match.group(1))
    for match in re.finditer(r"\b(\w+)\s*\.\s*(?:Use|use)\s*\(([^;]*)", pf.code):
        if AUTH_MW_RE.search(match.group(2)):
            guarded_vars.add(match.group(1))
    js_auth_uses: list[int] = []
    if pf.language in JS_LANGS:
        js_auth_uses = [
            m.start() for m in re.finditer(r"\.\s*use\s*\(([^;]*)", pf.code) if AUTH_MW_RE.search(m.group(1))
        ]
    first_js_auth_use = min(js_auth_uses) if js_auth_uses else -1
    pairs: dict[int, int] | None = None
    guarded_spans: list[tuple[int, int]] = []
    for match in re.finditer(
        r"Route::(?:middleware\s*\(([^)]*)\)|group\s*\(\s*\[([^\]]*)\])[^;{]*?function\s*\([^)]*\)\s*(?:use\s*\([^)]*\)\s*)?\{",
        pf.code,
    ):
        args = (match.group(1) or "") + (match.group(2) or "")
        if AUTH_MW_RE.search(args):
            open_pos = match.end() - 1
            if pairs is None:
                pairs = _brace_pairs(pf.masked)
            close = pairs.get(open_pos, -1)
            if close != -1:
                guarded_spans.append((open_pos, close))
    for sym in pf.symbols:
        if sym.kind == "class":
            continue
        marker = _decorator_auth(sym.decorators)
        if not marker and sym.decl_kind == "route":
            line_start = pf.line_start(sym.line)
            # Middleware arguments sit just before the handler; bound the window
            # so minified / single-line sources stay linear.
            window_start = max(line_start, sym.body_start - 400) if sym.body_start > line_start else line_start
            before = pf.code[window_start : sym.body_start if sym.body_start > line_start else line_start + 300]
            after = _statement_after(pf, max(sym.body_end, line_start))
            if re.search(r"\.AllowAnonymous\s*\(|withoutMiddleware\s*\([^)]*auth", before + after):
                marker = "anonymous"
            elif AUTH_MW_RE.search(before.split(",", 1)[-1]) or re.search(
                r"\.RequireAuthorization\s*\(|->\s*middleware\s*\([^)]*auth", after + before
            ):
                marker = "required"
            else:
                receiver = re.match(r"\s*\$?(\w+)\s*(?:\.|->)", pf.code[window_start : window_start + 200])
                if receiver and receiver.group(1) in guarded_vars:
                    marker = "required"
                elif any(a < sym.body_start < b or a < line_start < b for a, b in guarded_spans):
                    marker = "required"
        if not marker and sym.container in class_auth:
            marker = class_auth[sym.container]
        if not marker and sym.framework == "nextjs" and sym.has_body:
            if NEXT_AUTH_CALL_RE.search(pf.code[sym.body_start : sym.body_end]):
                marker = "required"
        if not marker and pf.language in JS_LANGS and sym.kind == "endpoint" and sym.decl_kind == "route":
            # app.use(authMiddleware) earlier in the file guards later routes.
            if first_js_auth_use != -1 and first_js_auth_use < pf.line_start(sym.line):
                marker = "required"
        sym.auth = marker


# -------------------------------------------------------------------- indexing

PARSERS = {
    "csharp": _parse_csharp,
    "javascript": _parse_js,
    "typescript": _parse_js,
    "php": _parse_php,
    "go": _parse_go,
    "rust": _parse_rust,
    "dart": _parse_dart,
}


def language_for(path: str) -> str | None:
    lower = path.lower()
    if lower.endswith((".d.ts", ".d.mts", ".d.cts")):
        return None
    suffix = "." + lower.rsplit(".", 1)[-1] if "." in lower.rsplit("/", 1)[-1] else ""
    return LANGUAGE_BY_SUFFIX.get(suffix)


def parse_polyglot_file(path: str, text: str) -> PgFile | None:
    language = language_for(path)
    if language is None:
        return None
    pf = _new_file(path, language, text)
    PARSERS[language](pf)
    _detect_auth(pf)
    pf.symbols.sort(key=lambda s: (s.line, s.kind, s.name))
    return pf


def index_polyglot(root: Path, rel_files: list[str]) -> PolyglotIndex:
    """Index every C#, JS/TS, PHP and Go source file under *root* (deterministic)."""
    index = PolyglotIndex()
    base = root.resolve()
    for rel_path in sorted(rel_files):
        if language_for(rel_path) is None:
            continue
        try:
            resolved = (root / rel_path).resolve()
            if not resolved.is_relative_to(base) or not resolved.is_file():
                continue
            if resolved.stat().st_size > MAX_SOURCE_BYTES:
                continue
            text = resolved.read_text(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            continue
        pf = parse_polyglot_file(rel_path, text)
        if pf is not None:
            index.files[rel_path] = pf
    _link_route_handlers(index)
    return index


def _link_route_handlers(index: PolyglotIndex) -> None:
    """Move routes registered by name (``app.get('/x', listUsers)``) onto the handler."""
    by_lang_name: dict[tuple[str, str], list[tuple[PgFile, PgSymbol]]] = {}
    for path in sorted(index.files):
        pf = index.files[path]
        family = "js" if pf.language in JS_LANGS else pf.language
        for sym in pf.symbols:
            if sym.kind in ("function", "method", "endpoint") and sym.has_body and not sym.handler_ref:
                by_lang_name.setdefault((family, sym.name), []).append((pf, sym))
                if sym.container:
                    owner = sym.container.rsplit(":", 1)[-1] if family == "rust" else _simple(sym.container)
                    by_lang_name.setdefault((family, f"{owner}::{sym.name}"), []).append((pf, sym))
    for path in sorted(index.files):
        pf = index.files[path]
        family = "js" if pf.language in JS_LANGS else pf.language
        remaining: list[PgSymbol] = []
        for sym in pf.symbols:
            if sym.kind != "endpoint" or not sym.handler_ref:
                remaining.append(sym)
                continue
            ref = sym.handler_ref
            if family == "rust":
                key = ref.rsplit("::", 1)[-1]
            elif "::" in ref:
                cls, _, method = ref.rpartition("::")
                key = f"{_simple(cls)}::{method}"
            else:
                key = ref.rsplit(".", 1)[-1]
            candidates = by_lang_name.get((family, key), [])
            if family == "rust" and "::" in ref:
                modules = ref.split("::")[:-1]
                associated = by_lang_name.get((family, f"{modules[-1]}::{key}"), [])
                if associated:
                    candidates = associated
                    modules = modules[:-1]
                parent = pf.path.rsplit("/", 1)[0] if "/" in pf.path else ""
                if modules and modules[0] == "crate":
                    parent = pf.path.rsplit("/src/", 1)[0] + "/src" if "/src/" in pf.path else "src"
                    modules = modules[1:]
                elif modules and modules[0] == "self":
                    modules = modules[1:]
                while modules and modules[0] == "super":
                    parent = parent.rsplit("/", 1)[0] if "/" in parent else ""
                    modules = modules[1:]
                module_path = "/".join(p for p in [parent, *modules] if p)
                paths = {module_path + ".rs", module_path + "/mod.rs"} if modules else {pf.path}
                candidates = [c for c in candidates if c[0].path in paths]
            same_file = [c for c in candidates if c[0].path == pf.path]
            chosen = same_file if len(same_file) == 1 else (candidates if len(candidates) == 1 else [])
            if not chosen:
                remaining.append(sym)
                continue
            _, target = chosen[0]
            target.routes = _dedupe_routes(target.routes + sym.routes)
            if sym.auth and not target.auth:
                target.auth = sym.auth
            target.kind = "endpoint"
            target.framework = target.framework or sym.framework
            if not target.tainted_params:
                if pf.language == "php":
                    target.tainted_params = _php_tainted_params(target.params)
                elif pf.language == "rust":
                    target.tainted_params = _rust_tainted_params(target.params)
                elif pf.language == "dart":
                    target.tainted_params = _dart_tainted_params(target.params)
            target.decorators.append(f"route@{pf.path}:{sym.line}")
        pf.symbols = remaining


# ---------------------------------------------------------------------- graph


def _node_id(pf: PgFile, kind: str, qualname: str) -> str:
    return stable_id("pg", pf.language, kind, pf.path, qualname)


def symbol_node_id(pf: PgFile, sym: PgSymbol) -> str:
    """Graph node id for *sym* (shared by the graph builder and SAST)."""
    kind = "class" if sym.kind == "class" else ("fn" if sym.kind == "endpoint" else sym.kind)
    return _node_id(pf, kind, sym.qualname)


def _tags(node: Node, *tags: str) -> None:
    current = set(node.attrs.get("tags", []))
    current.update(t for t in tags if t)
    node.attrs["tags"] = sorted(current)


def _resolve_js_import(index: PolyglotIndex, from_path: str, spec: str) -> str | None:
    if not spec.startswith("."):
        return None
    base_dir = from_path.rsplit("/", 1)[0] if "/" in from_path else ""
    parts: list[str] = [p for p in base_dir.split("/") if p]
    for piece in spec.split("/"):
        if piece in ("", "."):
            continue
        if piece == "..":
            if parts:
                parts.pop()
            continue
        parts.append(piece)
    stem = "/".join(parts)
    stem_no_ext = re.sub(r"\.(?:[mc]?js|jsx)$", "", stem)
    candidates = [stem] + [
        f"{s}{ext}"
        for s in (stem_no_ext, stem_no_ext + "/index")
        for ext in (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts")
    ]
    for candidate in candidates:
        if candidate in index.files:
            return candidate
    return None


CALL_RE = re.compile(r"(?:(\$this|this|self|static|parent|base)\s*(?:->|\.|::)\s*)?\b([A-Za-z_$][\w$]*)\s*\(")
NEW_RE = re.compile(r"\bnew\s+([A-Za-z_\\][\w\\.]*)")
MEDIATR_RE = re.compile(r"\.\s*(?:Send|Publish)\s*\(\s*new\s+([A-Za-z_]\w*)")


def build_polyglot_graph(graph: Graph, index: PolyglotIndex) -> None:
    """Append polyglot nodes and edges to *graph* deterministically."""
    containers: dict[tuple[str, str], str] = {}
    class_nodes: dict[str, list[tuple[PgFile, PgSymbol, str]]] = {}
    fn_nodes: dict[str, list[tuple[PgFile, PgSymbol, str]]] = {}
    sym_node: dict[int, str] = {}
    module_nodes: dict[str, str] = {}

    def container_node(pf: PgFile) -> str:
        if pf.language in JS_LANGS or pf.language == "dart" or (pf.language == "php" and not pf.namespace):
            key = ("module", pf.path)
            if key not in containers:
                stem = re.sub(r"\.[^./]+$", "", pf.path)
                node = Node(
                    id=_node_id(pf, "module", pf.path),
                    kind="module",
                    name=stem.rsplit("/", 1)[-1],
                    qualname=stem.replace("/", "."),
                    path=pf.path,
                    line=1,
                    attrs={"language": pf.language},
                )
                graph.add_node(node)
                containers[key] = node.id
                module_nodes[pf.path] = node.id
            return containers[key]
        if pf.language == "go":
            name = (pf.path.rsplit("/", 1)[0] if "/" in pf.path else ".") + f" ({pf.namespace or 'main'})"
        else:
            name = pf.namespace or "(global)"
        key = (pf.language, name)
        if key not in containers:
            node = Node(
                id=stable_id("pg", pf.language, "package", name),
                kind="package",
                name=name,
                qualname=name,
                attrs={"language": pf.language},
            )
            graph.add_node(node)
            containers[key] = node.id
        return containers[key]

    # Pass 1: nodes and containment.
    for path in sorted(index.files):
        pf = index.files[path]
        family = "js" if pf.language in JS_LANGS else pf.language
        parent = container_node(pf)
        class_ids: dict[str, str] = {}
        for sym in pf.symbols:
            if sym.kind != "class":
                continue
            attrs: dict[str, Any] = {"language": pf.language, "decl": sym.decl_kind}
            if sym.stereotype:
                attrs["stereotype"] = sym.stereotype
            if sym.framework:
                attrs["framework"] = sym.framework
            node = Node(
                id=symbol_node_id(pf, sym),
                kind="class",
                name=sym.name,
                qualname=sym.qualname,
                path=pf.path,
                line=sym.line,
                attrs=attrs,
            )
            graph.add_node(node)
            class_ids[sym.qualname] = node.id
            sym_node[id(sym)] = node.id
            class_nodes.setdefault(f"{family}:{sym.name}", []).append((pf, sym, node.id))
            owner = class_ids.get(sym.container) if sym.container else None
            graph.add_edge(owner or parent, node.id, "contains", evidence=[Loc(pf.path, sym.line)])
        for sym in pf.symbols:
            if sym.kind == "class":
                continue
            attrs = {"language": pf.language}
            if sym.params:
                attrs["args"] = [re.sub(r"\s+", " ", p)[:80] for p in sym.params[:12]]
            if sym.routes:
                attrs["routes"] = sym.routes
            if sym.framework:
                attrs["framework"] = sym.framework
            if sym.auth:
                attrs["auth"] = sym.auth
            if sym.has_body:
                attrs["body_lines"] = max(1, sym.end_line - sym.line + 1)
            node = Node(
                id=symbol_node_id(pf, sym),
                kind=sym.kind,
                name=sym.name,
                qualname=sym.qualname,
                path=pf.path,
                line=sym.line,
                attrs=attrs,
            )
            if sym.kind == "endpoint":
                _tags(node, "endpoint", "route")
                if pf.language == "dart" and sym.tainted_params:
                    node.attrs["trust_boundary"] = "ingress"
                    node.attrs["security"] = ["source"]
            graph.add_node(node)
            sym_node[id(sym)] = node.id
            fn_nodes.setdefault(f"{family}:{sym.name}", []).append((pf, sym, node.id))
            owner = class_ids.get(sym.container) if sym.container else None
            if owner is None and sym.container:
                owner = next(
                    (nid for f, s, nid in class_nodes.get(f"{family}:{_simple(sym.container)}", []) if s.qualname == sym.container),
                    None,
                )
            graph.add_edge(owner or parent, node.id, "contains", evidence=[Loc(pf.path, sym.line)])

    def resolve_class(family: str, name: str, pf: PgFile) -> tuple[PgFile, PgSymbol, str] | None:
        candidates = class_nodes.get(f"{family}:{_simple(name)}", [])
        if len(candidates) == 1:
            return candidates[0]
        same_file = [c for c in candidates if c[0].path == pf.path]
        if len(same_file) == 1:
            return same_file[0]
        same_ns = [c for c in candidates if c[0].namespace and c[0].namespace == pf.namespace]
        return same_ns[0] if len(same_ns) == 1 else None

    implementers: dict[str, list[str]] = {}
    for key in sorted(class_nodes):
        family = key.split(":", 1)[0]
        for pf, sym, nid in class_nodes[key]:
            for base in sym.bases:
                target = resolve_class(family, base, pf)
                if target is None or target[2] == nid:
                    continue
                graph.add_edge(nid, target[2], "inherits", resolution="name", evidence=[Loc(pf.path, sym.line)])
                implementers.setdefault(target[2], []).append(nid)

    # Pass 2: dependency injection, instantiation, mediator dispatch, calls.
    for key in sorted(class_nodes):
        family = key.split(":", 1)[0]
        for pf, sym, nid in class_nodes[key]:
            for dep in sym.injected:
                target = resolve_class(family, dep, pf)
                if target is None or target[2] == nid:
                    continue
                impls = sorted(set(implementers.get(target[2], [])))
                dst = impls[0] if len(impls) == 1 else target[2]
                graph.add_edge(
                    nid, dst, "calls", confidence=0.85, resolution="injected",
                    evidence=[Loc(pf.path, sym.line)], attrs={"injection": "constructor"},
                )
    handlers_for: dict[str, list[str]] = {}
    for key in sorted(class_nodes):
        for _pf, sym, nid in class_nodes[key]:
            for base in sym.bases:
                generic = re.match(r"I(?:Request|Notification)Handler\s*<\s*([A-Za-z_]\w*)", base.strip())
                if generic:
                    handlers_for.setdefault(generic.group(1), []).append(nid)

    for path in sorted(index.files):
        pf = index.files[path]
        family = "js" if pf.language in JS_LANGS else pf.language
        for sym in pf.symbols:
            src = sym_node.get(id(sym))
            if src is None or sym.kind == "class":
                continue
            if sym.handler_ref:
                # Unresolved by the route linker: link only an unambiguous target.
                handler_name = sym.handler_ref.rsplit("::", 1)[-1].rsplit(".", 1)[-1]
                targets = fn_nodes.get(f"{family}:{handler_name}", [])
                if len(targets) == 1:
                    graph.add_edge(
                        src, targets[0][2], "calls", confidence=0.6, resolution="route", evidence=[Loc(pf.path, sym.line)]
                    )
            if not sym.has_body:
                continue
            body = pf.masked[sym.body_start : sym.body_end + 1]
            body_code = pf.code[sym.body_start : sym.body_end + 1]
            seen: set[str] = set()
            for match in NEW_RE.finditer(body):
                target = resolve_class(family, match.group(1), pf)
                if target is None or target[2] in seen:
                    continue
                seen.add(target[2])
                line = pf.line_of(sym.body_start + match.start())
                graph.add_edge(src, target[2], "instantiates", confidence=0.8, resolution="name", evidence=[Loc(pf.path, line)])
            for match in MEDIATR_RE.finditer(body_code):
                line = pf.line_of(sym.body_start + match.start())
                for handler in sorted(set(handlers_for.get(match.group(1), []))):
                    graph.add_edge(src, handler, "calls", confidence=0.9, resolution="mediator", evidence=[Loc(pf.path, line)])
            for match in CALL_RE.finditer(body):
                if body[max(0, match.start() - 4) : match.start()] == "new ":
                    continue
                name = match.group(2)
                if name in CALL_STOPLIST or name == sym.name and not match.group(1):
                    continue
                candidates = [c for c in fn_nodes.get(f"{family}:{name}", []) if c[2] != src]
                if not candidates:
                    continue
                if match.group(1):
                    chosen = [c for c in candidates if c[1].container and c[1].container == sym.container]
                    confidence = 0.9
                else:
                    chosen = [c for c in candidates if c[0].path == pf.path]
                    confidence = 0.8
                    if not chosen and len(candidates) == 1 and len(name) >= 4:
                        chosen, confidence = candidates, 0.5
                if len(chosen) != 1 or chosen[0][2] in seen:
                    continue
                seen.add(chosen[0][2])
                line = pf.line_of(sym.body_start + match.start())
                graph.add_edge(src, chosen[0][2], "calls", confidence=confidence, resolution="name", evidence=[Loc(pf.path, line)])

    for path in sorted(index.files):
        pf = index.files[path]
        if path not in module_nodes:
            continue
        if pf.language in JS_LANGS:
            for spec, line in sorted(set(pf.imports), key=lambda item: (item[1], item[0])):
                imported = _resolve_js_import(index, path, spec)
                if imported and imported in module_nodes and imported != path:
                    graph.add_edge(module_nodes[path], module_nodes[imported], "imports", evidence=[Loc(path, line)])
        elif pf.language == "dart":
            base_dir = path.rsplit("/", 1)[0] if "/" in path else ""
            for spec, line in sorted(set(pf.imports), key=lambda item: (item[1], item[0])):
                if spec.startswith(("dart:", "package:flutter/")):
                    continue
                target_path: str | None = None
                if spec.startswith("package:"):
                    rel = spec.split("/", 1)[1] if "/" in spec else ""
                    if rel:
                        cand = f"lib/{rel}"
                        if cand in index.files:
                            target_path = cand
                        else:
                            for p in index.files:
                                if p.endswith("/" + cand):
                                    target_path = p
                                    break
                else:
                    parts = [p for p in base_dir.split("/") if p]
                    for piece in spec.split("/"):
                        if piece in ("", "."):
                            continue
                        if piece == "..":
                            if parts:
                                parts.pop()
                        else:
                            parts.append(piece)
                    cand = "/".join(parts)
                    if cand in index.files:
                        target_path = cand
                if target_path and target_path in module_nodes and target_path != path:
                    graph.add_edge(module_nodes[path], module_nodes[target_path], "imports", evidence=[Loc(path, line)])

    for path in sorted(index.files):
        pf = index.files[path]
        for sym in pf.symbols:
            if sym.stereotype == "repository" and pf.language == "csharp":
                entities = sorted(set(re.findall(r"\bDbSet\s*<\s*([A-Za-z_]\w*)\s*>", pf.code[sym.body_start : sym.body_end + 1])))
                context_node = graph.nodes.get(sym_node.get(id(sym), ""))
                if context_node is not None and entities:
                    context_node.attrs["entities"] = entities
                    for entity in entities:
                        entity_target = resolve_class("csharp", entity, pf)
                        if entity_target is not None:
                            graph.add_edge(
                                context_node.id, entity_target[2], "calls", confidence=0.9, resolution="dbset",
                                evidence=[Loc(pf.path, sym.line)],
                            )

    graph.meta["polyglot_files"] = index.language_counts()
