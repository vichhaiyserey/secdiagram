"""Bounded, text-only Dart declaration headers (not a compiler or evaluator).

Every header consumes at most 4096 characters / 512 tokens. Type recursion is
limited to 32 levels. The caller advances monotonically and skips function
bodies, so widget trees and callbacks are never mistaken for declarations.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

MAX_HEADER_CHARS = 4096
MAX_HEADER_TOKENS = 512
MAX_TYPE_DEPTH = 32
_TOKEN = re.compile(r"(?:[^\W\d]|[$])[\w$]*|=>|[^\s]", re.UNICODE)
_IDENT = re.compile(r"(?:[^\W\d]|[$])[\w$]*\Z", re.UNICODE)
_MODIFIERS = frozenset({"static", "external", "factory", "const", "abstract", "augment"})
_TYPE_MODIFIERS = frozenset({"abstract", "base", "interface", "final", "sealed", "augment"})
_STATEMENTS = frozenset({
    "if", "else", "for", "while", "do", "switch", "case", "default", "catch",
    "try", "finally", "return", "throw", "rethrow", "assert", "await", "yield",
    "break", "continue", "import", "export", "part", "library", "var", "final", "late",
})


class _TypeDepthLimit(Exception):
    """Internal deterministic type-grammar budget exhaustion."""


@dataclass(frozen=True, slots=True)
class Token:
    value: str
    start: int
    end: int


@dataclass(slots=True)
class Header:
    tokens: list[Token]
    end: int
    terminator: Token | None = None
    limited: bool = False


@dataclass(frozen=True, slots=True)
class Declaration:
    name: str
    kind: str
    params_start: int = -1
    params_end: int = -1


def scan_header(masked: str, start: int) -> Header:
    """Read one balanced header, leaving the body to the caller's brace map."""
    limit = min(len(masked), start + MAX_HEADER_CHARS)
    tokens: list[Token] = []
    stack: list[str] = []
    closers = {"(": ")", "[": "]", "{": "}"}
    initializer_colon = False
    initializer_equal = -1
    for match in _TOKEN.finditer(masked, start, limit):
        value = match.group()
        token = Token(value, match.start(), match.end())
        # A collection/closure in a constructor initializer is not its body.
        initializer = False
        if not stack:
            if value == ":":
                initializer_colon = True
            elif value == "=" and initializer_colon:
                initializer_equal = len(tokens)
            if value == "{" and initializer_equal >= 0:
                tail = [t.value for t in tokens[initializer_equal + 1 :]]
                initializer = not tail or tail[-1] in ("const", ">")
                if tail and tail[0] == "(" and _group(tail, 0) == len(tail):
                    initializer = True
        if not stack and value in ("{", ";", "=>", "}") and not initializer:
            return Header(tokens, token.end, token)
        if len(tokens) >= MAX_HEADER_TOKENS:
            return Header(tokens, token.end, limited=True)
        tokens.append(token)
        if value in closers:
            stack.append(closers[value])
        elif value in (")", "]", "}"):
            if not stack or stack.pop() != value:
                return Header(tokens, token.end)
    return Header(tokens, limit, limited=limit < len(masked) or bool(stack))


def _ident(value: str) -> bool:
    return _IDENT.fullmatch(value) is not None


def strip_annotations(header: Header) -> Header:
    values = [t.value for t in header.tokens]
    pos = 0
    while pos + 1 < len(values) and values[pos] == "@" and _ident(values[pos + 1]):
        pos += 2
        while pos + 1 < len(values) and values[pos] == "." and _ident(values[pos + 1]):
            pos += 2
        if pos < len(values) and values[pos] == "(":
            end = _group(values, pos)
            if end is None:
                return Header([], header.end)
            pos = end
    return Header(header.tokens[pos:], header.end, header.terminator, header.limited)


def _group(values: list[str], pos: int) -> int | None:
    """End of a balanced parameter/record group; iterative even on hostile data."""
    closers = {"(": ")", "[": "]", "{": "}"}
    stack: list[str] = []
    for idx in range(pos, len(values)):
        value = values[idx]
        if value in closers:
            stack.append(closers[value])
        elif value in (")", "]", "}"):
            if not stack or stack.pop() != value:
                return None
            if not stack:
                return idx + 1
    return None


def _type_parameters(values: list[str], pos: int, depth: int) -> int | None:
    pos += 1  # '<'
    while pos < len(values) and _ident(values[pos]):
        pos += 1
        if pos < len(values) and values[pos] == "extends":
            bound = _type(values, pos + 1, depth + 1)
            if bound is None:
                return None
            pos = bound
        if pos < len(values) and values[pos] == ">":
            return pos + 1
        if pos >= len(values) or values[pos] != ",":
            return None
        pos += 1
    return None


def _record(values: list[str], pos: int, depth: int) -> int | None:
    pos += 1
    named = False
    fields = 0
    comma = False
    while pos < len(values):
        if values[pos] == "{":
            if named:
                return None
            named = True
            pos += 1
        end = _type(values, pos, depth + 1)
        if end is None:
            return None
        pos = end
        has_name = pos < len(values) and _ident(values[pos])
        if has_name:
            pos += 1
        if named and not has_name:
            return None
        fields += 1
        if pos < len(values) and values[pos] == ",":
            comma = True
            pos += 1
            if pos < len(values) and values[pos] not in ("}", ")"):
                continue
        if named:
            if pos >= len(values) or values[pos] != "}":
                return None
            pos += 1
            if pos < len(values) and values[pos] == ",":
                pos += 1
        if pos < len(values) and values[pos] == ")" and (named or fields > 1 or comma):
            return pos + 1
        return None
    return None


def _type(values: list[str], pos: int, depth: int = 0) -> int | None:
    if depth >= MAX_TYPE_DEPTH:
        raise _TypeDepthLimit
    if pos >= len(values):
        return None
    if values[pos] == "(":
        end = _record(values, pos, depth)
        if end is None:
            return None
        pos = end
    elif _ident(values[pos]) and values[pos] not in _STATEMENTS:
        is_function = values[pos] == "Function"
        pos += 1
        while pos + 1 < len(values) and values[pos] == "." and _ident(values[pos + 1]):
            pos += 2
        if pos < len(values) and values[pos] == "<":
            pos += 1
            while True:
                end = _type(values, pos, depth + 1)
                if end is None:
                    return None
                pos = end
                if pos < len(values) and values[pos] == ">":
                    pos += 1
                    break
                if pos >= len(values) or values[pos] != ",":
                    return None
                pos += 1
        if is_function and pos < len(values) and values[pos] == "(":
            end = _group(values, pos)
            if end is None:
                return None
            pos = end
    else:
        return None
    if pos < len(values) and values[pos] == "?":
        pos += 1
    if pos < len(values) and values[pos] == "Function":
        pos += 1
        if pos < len(values) and values[pos] == "<":
            end = _type_parameters(values, pos, depth)
            if end is None:
                return None
            pos = end
        if pos >= len(values) or values[pos] != "(":
            return None
        end = _group(values, pos)
        if end is None:
            return None
        pos = end
        if pos < len(values) and values[pos] == "?":
            pos += 1
    return pos


def type_declaration(header: Header) -> Declaration | None:
    values = [t.value for t in header.tokens]
    pos = 0
    while pos < len(values) and values[pos] in _TYPE_MODIFIERS:
        pos += 1
    if pos >= len(values):
        return None
    kind = values[pos]
    if kind not in ("class", "mixin", "enum", "extension", "typedef"):
        return None
    pos += 1
    if kind == "mixin" and pos < len(values) and values[pos] == "class":
        pos += 1
    if kind == "extension" and pos < len(values) and values[pos] == "type":
        kind = "extension type"
        pos += 1
    if kind == "extension" and pos < len(values) and values[pos] == "on":
        return Declaration("", kind)  # unnamed extension; caller supplies a stable name
    if pos >= len(values) or not _ident(values[pos]):
        return None
    name = values[pos]
    if kind == "typedef" and "=" not in values:
        try:
            end = _type(values, pos)
        except _TypeDepthLimit:
            header.limited = True
            return None
        if end is not None and end < len(values) and _ident(values[end]):
            name = values[end]  # legacy: typedef void Callback(String value);
    return Declaration(name, kind)


def function_declaration(header: Header, owner: str = "") -> Declaration | None:
    try:
        return _function_declaration(header, owner)
    except _TypeDepthLimit:
        header.limited = True
        return None


def _function_declaration(header: Header, owner: str) -> Declaration | None:
    if header.terminator is None or header.limited or not header.tokens:
        return None
    values = [t.value for t in header.tokens]
    pos = 0
    while pos < len(values) and values[pos] in _MODIFIERS:
        pos += 1
    if pos >= len(values) or values[pos] in _STATEMENTS:
        return None

    # Constructors have no return type; named constructors retain their owner.
    if owner and values[pos] in (owner, "new"):
        name = owner
        pos += 1
        if pos + 1 < len(values) and values[pos] == "." and _ident(values[pos + 1]):
            name += "." + values[pos + 1]
            pos += 2
        result = _callable(header, values, pos, name, "constructor", constructor=True)
        if result is not None:
            return result

    # Try an inferred return type, then a controlled explicit type grammar.
    result = _named_function(header, values, pos)
    if result is None:
        end = _type(values, pos)
        if end is not None:
            result = _named_function(header, values, end)
    if result is None:
        return None
    if header.terminator.value == ";" and not owner and "external" not in values[:pos]:
        return None  # a top-level call is not an external declaration
    return result


def _named_function(header: Header, values: list[str], pos: int) -> Declaration | None:
    if pos >= len(values):
        return None
    value = values[pos]
    if value == "get" and pos + 2 == len(values) and _ident(values[pos + 1]):
        return Declaration(values[pos + 1], "getter")
    if value == "set" and pos + 1 < len(values) and _ident(values[pos + 1]):
        return _callable(header, values, pos + 2, values[pos + 1], "setter")
    if value == "operator":
        end = pos + 1
        while end < len(values) and values[end] != "(":
            end += 1
        operator = "".join(values[pos + 1 : end])
        if operator not in {"+", "-", "*", "/", "~/", "%", "==", "<", ">", "<=", ">=",
                            "&", "|", "^", "~", "<<", ">>", ">>>", "[]", "[]="}:
            return None
        return _callable(header, values, end, "operator " + operator, "operator")
    if not _ident(value) or value in _STATEMENTS or value in (
        "get", "set", "void", "true", "false", "null", "new", "this", "super",
    ):
        return None
    end = pos + 1
    if end < len(values) and values[end] == "<":
        params_end = _type_parameters(values, end, 0)
        if params_end is None:
            return None
        end = params_end
    return _callable(header, values, end, value, "function")


def _callable(
    header: Header, values: list[str], pos: int, name: str, kind: str,
    *, constructor: bool = False,
) -> Declaration | None:
    if pos >= len(values) or values[pos] != "(":
        return None
    end = _group(values, pos)
    if end is None:
        return None
    suffix = values[end:]
    if constructor:
        if suffix and suffix[0] not in (":", "="):
            return None
    elif suffix not in ([], ["async"], ["async", "*"], ["sync", "*"]):
        return None
    return Declaration(name, kind, header.tokens[pos].end, header.tokens[end - 1].start)
