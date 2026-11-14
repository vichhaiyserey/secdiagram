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

_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY(?: BLOCK)?-----.*?-----END (?:[A-Z0-9_-]+ )?PRIVATE KEY(?: BLOCK)?-----",
    re.DOTALL,
)
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
_URL_CREDENTIAL_RE = re.compile(
    r"(?i)(\b[a-z][a-z0-9+.-]*://[^:\s/@]+:)([^@\s/]+)(@)"
)
_AUTH_HEADER_RE = re.compile(
    r"(?i)(\bauthorization\b\s*[:=]\s*['\"]?(?:bearer|basic|token)\s+)([A-Za-z0-9._~+/=-]{8,})"
)
_KEY_PATTERN = (
    r"\b[\w.\-]*(?:secret|password|passwd|pwd|token|api[_-]?key|access[_-]?key|"
    r"credential|private[_-]?key|client[_-]?secret|auth[_-]?token)[\w.\-]*"
)

_ASSIGNMENT_QUOTED_RE = re.compile(
    rf"({_KEY_PATTERN}\s*[:=]\s*(?P<q>['\"]))([^'\"]+)(?P=q)",
    re.IGNORECASE,
)
_ASSIGNMENT_UNQUOTED_RE = re.compile(
    rf"({_KEY_PATTERN}\s*[:=]\s*)([^\s'\";,]{{6,}})",
    re.IGNORECASE,
)


def redact_secrets(text: str) -> str:
    """Return *text* with recognized credentials replaced by a marker."""
    if not text:
        return text
    cleaned = _PRIVATE_KEY_RE.sub(REDACTED, text)
    cleaned = _URL_CREDENTIAL_RE.sub(lambda m: m.group(1) + REDACTED + m.group(3), cleaned)
    cleaned = _AUTH_HEADER_RE.sub(lambda m: m.group(1) + REDACTED, cleaned)
    cleaned = _ASSIGNMENT_QUOTED_RE.sub(lambda m: m.group(1) + REDACTED + m.group("q"), cleaned)
    cleaned = _ASSIGNMENT_UNQUOTED_RE.sub(lambda m: m.group(1) + REDACTED, cleaned)
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
    if cleaned.startswith("/") and not cleaned.startswith("/."):
        return "[external-path]"
    return cleaned


def redact_snippet_line(line: str) -> str:
    """Redact secrets from a single source line before embedding it in a report."""
    return redact_secrets(line)
