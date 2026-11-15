"""Best-effort redaction helpers for secrets and host paths.

These helpers are applied to text that leaves the process through audit logs,
API error responses, and embedded HTML source snippets. They are intentionally
conservative: they target well-known credential shapes and sensitive
key/value assignments rather than every token-like string.
"""

from __future__ import annotations

import re
from pathlib import Path

REDACTED = "[REDACTED]"

# Up to three label words (``RSA``, ``ENCRYPTED``, ``SSH2 ENCRYPTED``...) and
# both PEM (``-----BEGIN X-----``) and SSH2 (``---- BEGIN X ----``) framing.
_PRIVATE_KEY_LABEL = r"(?:[A-Z0-9_-]+ ){0,3}PRIVATE KEY(?: BLOCK)? ?-{4,5}"
_PRIVATE_KEY_BEGIN_RE = re.compile(r"-{4,5} ?BEGIN " + _PRIVATE_KEY_LABEL)
_PRIVATE_KEY_END_RE = re.compile(r"-{4,5} ?END " + _PRIVATE_KEY_LABEL)
_TOKEN_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bA[SK]IA[0-9A-Z]{16}\b"),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bgl(?:ptt|rt|oas|agent)-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bxapp-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bsk-ant-(?:admin01-|api03-)[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"),
    re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bkey-[0-9a-zA-Z]{32}\b"),
    re.compile(r"\bdop_v1_[a-f0-9]{64}\b"),
    re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
    re.compile(r"\bshp(?:at|ca|ss)_[a-fA-F0-9]{32}\b"),
    re.compile(r"\b[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}\b"),
    re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"\bAccountKey=[A-Za-z0-9+/=]{40,}"),
    re.compile(r"\bhv[bs]\.[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bdapi[a-f0-9]{32}\b"),
    re.compile(r"\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b"),
)
# Scheme anchored at the start of a run and length-bounded so that long
# ``a.a.a...`` inputs cannot trigger quadratic backtracking.
# The username may be empty (``redis://:pass@host``) and the password may
# contain an unencoded ``/``; the password stops at the first ``@``. Both parts
# are length-bounded so repeated ``a://b:`` input stays linear.
_URL_CREDENTIAL_RE = re.compile(
    r"(?i)((?<![a-z0-9+.\-])[a-z][a-z0-9+.\-]{0,31}://[^:\s/@]{0,256}:)([^@\s]{1,256}?)(@)"
)
_AUTH_HEADER_RE = re.compile(
    r"(?i)(\bauthorization\b\s*[:=]\s*['\"]?(?:bearer|basic|token)\s+)([A-Za-z0-9._~+/=-]{8,})"
)
# The key may only start at the beginning of an identifier run (negative
# lookbehind instead of ``\b``, which also matches at every ``.``/``-``), and
# its prefix/suffix are length-bounded. Both constraints keep matching linear
# in the input length; unbounded ``[\w.\-]*`` on either side of the keyword
# made attacker-controlled text (e.g. ``'a.' * 4000``) quadratic.
_KEY_PATTERN = (
    r"(?<![\w.\-])[\w.\-]{0,64}?(?:secret|password|passwd|pwd|token|api[_-]?key|access[_-]?key|"
    r"credential|private[_-]?key|client[_-]?secret|auth[_-]?token)[\w.\-]{0,64}"
)

_ASSIGNMENT_QUOTED_RE = re.compile(
    rf"((?P<key>{_KEY_PATTERN})\s*[:=]\s*(?P<q>['\"]))([^'\"]+)(?P=q)",
    re.IGNORECASE,
)
# Unquoted assignments are scanned in two steps (key prefix, then value only
# for sensitive keys) so benign keys never trigger a scan of their value.
_ASSIGNMENT_PREFIX_RE = re.compile(rf"(?P<key>{_KEY_PATTERN})\s*[:=]\s*", re.IGNORECASE)
_UNQUOTED_VALUE_RE = re.compile(r"[^\s'\";,]{6,}")

# Precise key check applied after the broad regex match. A key is sensitive
# only if one of its segments (split on ``_ . -`` and camelCase) or two
# adjacent segments joined is a credential word, or a segment ends with one.
# This keeps ``DB_PASSWORD``, ``app.db.password``, ``githubToken``, ``apiKey``
# and ``dbpassword`` redacted while leaving ``max_tokens`` and ``tokenizer``.
_SENSITIVE_SEGMENTS = frozenset(
    {
        "secret", "secrets", "password", "passwd", "pwd", "token", "apikey",
        "accesskey", "credential", "credentials", "privatekey", "clientsecret",
        "authtoken", "secretkey", "passphrase",
    }
)
_SENSITIVE_SUFFIXES = ("password", "passwd", "secret", "token", "apikey", "credential", "credentials", "privatekey")
_SEGMENT_SPLIT_RE = re.compile(r"[_.\-]+|(?<=[a-z0-9])(?=[A-Z])")


def _is_sensitive_key(key: str) -> bool:
    segments = [part.lower() for part in _SEGMENT_SPLIT_RE.split(key) if part]
    for index, segment in enumerate(segments):
        if segment in _SENSITIVE_SEGMENTS or segment.endswith(_SENSITIVE_SUFFIXES):
            return True
        if index + 1 < len(segments) and segment + segments[index + 1] in _SENSITIVE_SEGMENTS:
            return True
    return False


def _redact_private_keys(text: str) -> str:
    """Replace each BEGIN...END private key block with the marker.

    A single forward scan replaces a lazy ``BEGIN.*?END`` regex, which is
    quadratic when many BEGIN headers have no matching END: if one BEGIN has
    no END after it, no later BEGIN can either, so the scan stops there.
    """
    out: list[str] = []
    pos = 0
    while True:
        begin = _PRIVATE_KEY_BEGIN_RE.search(text, pos)
        if begin is None:
            break
        end = _PRIVATE_KEY_END_RE.search(text, begin.end())
        if end is None:
            break
        out.append(text[pos : begin.start()])
        out.append(REDACTED)
        pos = end.end()
    out.append(text[pos:])
    return "".join(out)


def _redact_unquoted_assignments(text: str) -> str:
    """Redact unquoted ``key=value`` pairs whose key is sensitive.

    Scanning resumes right after each key prefix, so a sensitive pair nested
    in a benign value (``max_tokens=password=...``) is still found, and a
    value is only scanned when it is about to be redacted. The position only
    moves forward, which keeps the scan linear.
    """
    out: list[str] = []
    pos = 0
    while True:
        prefix = _ASSIGNMENT_PREFIX_RE.search(text, pos)
        if prefix is None:
            break
        out.append(text[pos : prefix.end()])
        pos = prefix.end()
        if not _is_sensitive_key(prefix.group("key")):
            continue
        value = _UNQUOTED_VALUE_RE.match(text, pos)
        if value is not None:
            out.append(REDACTED)
            pos = value.end()
    out.append(text[pos:])
    return "".join(out)


def redact_secrets(text: str) -> str:
    """Return *text* with recognized credentials replaced by a marker."""
    if not text:
        return text
    cleaned = _redact_private_keys(text)
    cleaned = _URL_CREDENTIAL_RE.sub(lambda m: m.group(1) + REDACTED + m.group(3), cleaned)
    cleaned = _AUTH_HEADER_RE.sub(lambda m: m.group(1) + REDACTED, cleaned)
    cleaned = _ASSIGNMENT_QUOTED_RE.sub(
        lambda m: m.group(1) + REDACTED + m.group("q") if _is_sensitive_key(m.group("key")) else m.group(0),
        cleaned,
    )
    cleaned = _redact_unquoted_assignments(cleaned)
    for pattern in _TOKEN_PATTERNS:
        cleaned = pattern.sub(REDACTED, cleaned)
    return cleaned


def sanitize_path_text(text: str, root: Path | None = None) -> str:
    """Remove a repository root prefix from *text* and hide other absolute paths."""
    if not text:
        return text
    cleaned = text
    if root is not None:
        try:
            cleaned = cleaned.replace(str(root.resolve()), ".")
        except OSError:
            pass
    if len(cleaned) >= 3 and cleaned[1:3] in {":\\", ":/"} and cleaned[0].isalpha():
        return "[external-path]"
    if cleaned.startswith("\\\\"):
        return "[external-path]"
    if cleaned.startswith("/"):
        return "[external-path]"
    return cleaned


def sanitize_url_path(text: str, max_len: int = 512) -> str:
    """Return a loggable HTTP request path: truncated and secret-redacted.

    Request paths are URL routes (``/api/scan``), not filesystem paths, so they
    must not go through :func:`sanitize_path_text`, which would hide every one
    of them as ``[external-path]``. The input is cut to a small multiple of
    *max_len* before redaction to bound the work done on attacker-controlled
    input, while leaving enough context that a secret near the cut is still
    recognized.
    """
    if not text:
        return text
    return redact_secrets(text[: max_len * 4])[:max_len]


def redact_snippet_line(line: str) -> str:
    """Redact secrets from a single source line before embedding it in a report."""
    return redact_secrets(line)
