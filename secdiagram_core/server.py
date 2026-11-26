"""Deterministic, secure, stdlib-only platform HTTP server and REST API for secdiagram."""

from __future__ import annotations

import abc
import base64
import errno
import ipaddress
import json
import secrets
import shutil
import sys
import tempfile
import threading
import time
from collections.abc import Mapping
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, cast
from urllib.parse import parse_qs, urlsplit

from . import __version__, agentic, studio_ui
from . import studio as studio_install
from .analyzer import AnalysisConfig, AnalysisResult, run_analysis
from .config import SecdiagramConfig, load_config
from .diagram_edit import (
    DiagramOverrideError,
    DiagramOverrides,
    apply_overrides,
    clear_overrides,
    summarize_overrides,
)
from .diagram_edit import (
    load_overrides as load_diagram_overrides,
)
from .diagram_edit import (
    save_overrides as save_diagram_overrides,
)
from .high_level import build_high_level_architecture, render_mermaid_highlevel
from .llm import NarrativeError, generate_narrative
from .model import SEVERITY_RANK, Finding, Graph
from .redaction import redact_secrets, sanitize_path_text, sanitize_url_path
from .render_html import render_html
from .render_image import ImageRenderError, render_image
from .render_json import render_json
from .render_mermaid import render_mermaid
from .render_sarif import render_sarif
from .taint_flows import render_taint_mermaid
from .threat_model import render_threat_model


def _sev_counts(graph: Graph) -> dict[str, int]:
    counts = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
    for finding in graph.findings:
        severity = finding.severity.lower()
        if severity not in counts:
            counts[severity] = 0
        counts[severity] += 1
    return counts


def _is_loopback_host(host: str) -> bool:
    """Return True only for literal loopback bind addresses or ``localhost``."""
    value = (host or "").strip().strip("[]").lower()
    if value == "localhost":
        return True
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def _is_within(path: Path, parent: Path) -> bool:
    """Return True when *path* is *parent* or lives underneath it."""
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


# Standard security headers applied to all HTTP responses.  The inline script
# and Mermaid CDN allowances are required by the classic standalone HTML report.
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self';"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
    "Cache-Control": "no-store, no-cache, must-revalidate",
}

# The Studio has no inline scripts or CDN assets.  Its SVG preview uses a
# same-origin blob URL, which must be explicitly allowed by CSP.
STUDIO_SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; "
        "connect-src 'self'; "
        "base-uri 'none'; "
        "object-src 'none'; "
        "frame-ancestors 'none';"
    ),
}


STUDIO_DIR_REL = Path(".secdiagram") / "studio"
_ALLOWED_DIRECTIONS = frozenset({"LR", "RL", "TB", "TD", "BT"})
_ALLOWED_THEMES = frozenset({"modern", "classic"})
_ALLOWED_LLM_TEMPLATES = frozenset(
    {"comprehensive", "threat-model", "remediation", "compliance"}
)
_ALLOWED_LLM_PROVIDERS = frozenset({"ollama", "openai"})


def _sdlc_payload(state: agentic.SdlcState) -> dict[str, Any]:
    """Return the UI/API projection of SDLC state."""
    return {
        "state": state.to_dict(),
        "progress": state.progress,
        "blockers": agentic.blockers(state),
        "can_handoff": not agentic.blockers(state),
        "phases": [
            {
                "phase": phase,
                "title": agentic.PHASE_TITLES[phase],
                "description": agentic.PHASE_DESCRIPTIONS[phase],
                "status": state.phases[phase].status,
                "evidence": list(state.phases[phase].evidence),
                "note": state.phases[phase].note,
                "expected_artifacts": list(agentic.PHASE_ARTIFACTS[phase]),
                "can_start": agentic.can_start(state, phase),
            }
            for phase in agentic.PHASES
        ],
    }


def _llm_base_url_allowed(url: str) -> bool:
    """Restrict Studio LLM calls to loopback, private, or OpenAI hosts.

    This prevents the authenticated UI from being used as an SSRF pivot into
    arbitrary internet or metadata endpoints.
    """
    try:
        parsed = urlsplit(url)
    except ValueError:
        return False
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False
    host = parsed.hostname.lower()
    if host == "api.openai.com" or host.endswith(".openai.com"):
        return True
    if host == "localhost":
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    # Link-local addresses (including cloud metadata endpoints such as
    # 169.254.169.254) are deliberately rejected, even though some Python
    # releases also classify them as private.
    if address.is_link_local:
        return False
    mapped = getattr(address, "ipv4_mapped", None)
    if mapped is not None and mapped.is_link_local:
        return False
    return address.is_loopback or address.is_private


def _query_choice(query: dict[str, list[str]], key: str, allowed: frozenset[str]) -> str | None:
    values = query.get(key)
    if not values:
        return None
    value = values[0].strip()
    if value.upper() in allowed:
        return value.upper()
    if value.lower() in allowed:
        return value.lower()
    return None


def _read_text_bounded(path: Path, limit: int = 512 * 1024) -> str | None:
    try:
        if not path.is_file() or path.stat().st_size > limit:
            return None
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def _studio_skill_payload() -> dict[str, Any]:
    """Read the installed skill, or render the canonical preview."""
    home = studio_install.default_home()
    status = studio_install.status(home)
    skill_dir = home / studio_install.SKILL_DIRNAME
    manifest_path = skill_dir / "skill.json"
    markdown_path = skill_dir / "SKILL.md"
    installed_manifest = _read_text_bounded(manifest_path)
    installed_markdown = _read_text_bounded(markdown_path)
    manifest_data: Any = None
    if installed_manifest:
        try:
            manifest_data = json.loads(installed_manifest)
        except json.JSONDecodeError:
            manifest_data = None
    if manifest_data is None:
        manifest_data = studio_install.skill_manifest()
    markdown = installed_markdown or studio_install.render_skill_markdown()
    return {
        "installed": status.get("installed", False),
        "manifest": manifest_data,
        "markdown": markdown,
    }


# ------------------------------------------------------------------- Authentication
class Authenticator(abc.ABC):
    """Abstract authentication backend interface.

    Allows adding future authentication methods (Bearer token, OAuth2, API key)
    without modifying core server request dispatching.
    """

    @abc.abstractmethod
    def authenticate(self, headers: Mapping[str, str]) -> tuple[bool, str | None]:
        """Verify request headers; return (is_authenticated, identity_identifier)."""

    @abc.abstractmethod
    def challenge_header(self) -> str | None:
        """Return WWW-Authenticate header challenge string, if applicable."""


class NoOpAuthenticator(Authenticator):
    """Permissive authenticator for explicit, loopback-only development mode."""

    def authenticate(self, headers: Mapping[str, str]) -> tuple[bool, str | None]:
        return True, "anonymous"

    def challenge_header(self) -> str | None:
        return None


class BasicAuthenticator(Authenticator):
    """Timing-attack-safe HTTP Basic Authenticator using secrets.compare_digest."""

    def __init__(self, username: str, password: str, realm: str = "secdiagram") -> None:
        self.username = username
        self.password = password
        self.realm = realm

    def authenticate(self, headers: Mapping[str, str]) -> tuple[bool, str | None]:
        auth_header = headers.get("authorization") or headers.get("Authorization") or ""
        if not auth_header.startswith("Basic "):
            return False, None
        try:
            raw_b64 = auth_header[6:].strip()
            decoded = base64.b64decode(raw_b64).decode("utf-8")
            if ":" not in decoded:
                return False, None
            user, pwd = decoded.split(":", 1)
            user_ok = secrets.compare_digest(user, self.username)
            pwd_ok = secrets.compare_digest(pwd, self.password)
            if user_ok and pwd_ok:
                return True, user
            return False, None
        except Exception:
            return False, None

    def challenge_header(self) -> str | None:
        return f'Basic realm="{self.realm}", charset="UTF-8"'


# ------------------------------------------------------------------- Audit Logging
class AuditLogger:
    """Append-only structured audit log for security-relevant events.

    Secrets are redacted and repository paths are normalised before writing.
    Logging failures are swallowed so auditing can never take down the server.
    """

    # Fields holding HTTP request paths (URL routes, not filesystem paths).
    URL_PATH_FIELDS = frozenset({"path"})
    MAX_FIELD_LEN = 512

    def __init__(self, destination: str | None, root: Path) -> None:
        self.root = root.resolve()
        self._lock = threading.Lock()
        self._path: Path | None = None
        self._stderr = destination is None or destination == "-"
        if destination and destination != "-":
            candidate = Path(destination).expanduser()
            if not candidate.is_absolute():
                candidate = self.root / candidate
            self._path = candidate
            try:
                self._path.parent.mkdir(parents=True, exist_ok=True)
            except OSError:
                self._path = None

    def log(self, event: str, **fields: Any) -> None:
        record: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "event": event,
        }
        for key, value in fields.items():
            raw = str(value)
            if key in self.URL_PATH_FIELDS:
                record[key] = sanitize_url_path(raw, self.MAX_FIELD_LEN)
                continue
            text = sanitize_path_text(redact_secrets(raw[: self.MAX_FIELD_LEN * 8]), self.root)
            record[key] = text[: self.MAX_FIELD_LEN]
        line = json.dumps(record, sort_keys=True, ensure_ascii=True)
        with self._lock:
            try:
                if self._path is not None:
                    with self._path.open("a", encoding="utf-8") as handle:
                        handle.write(line + "\n")
                elif self._stderr:
                    print(line, file=sys.stderr, flush=True)
            except OSError:
                pass


# ------------------------------------------------------------------- Rate Limiting
class RateLimiter:
    """Thread-safe sliding-window request rate limiter keyed by client identity."""

    def __init__(self, limit_per_minute: int, window_seconds: float = 60.0) -> None:
        self.limit = max(0, int(limit_per_minute))
        self.window = max(1.0, float(window_seconds))
        self._events: dict[str, list[float]] = {}
        self._lock = threading.Lock()
        self._last_prune = time.monotonic()

    def check(self, key: str) -> tuple[bool, float]:
        """Return (allowed, retry_after_seconds). A non-positive limit disables limiting."""
        if self.limit <= 0:
            return True, 0.0
        now = time.monotonic()
        cutoff = now - self.window
        with self._lock:
            events = [stamp for stamp in self._events.get(key, ()) if stamp > cutoff]
            if len(events) >= self.limit:
                retry_after = max(0.0, self.window - (now - events[0]))
                self._events[key] = events
                return False, retry_after
            events.append(now)
            self._events[key] = events
            if now - self._last_prune > self.window:
                for stale_key in list(self._events):
                    kept = [stamp for stamp in self._events[stale_key] if stamp > cutoff]
                    if kept:
                        self._events[stale_key] = kept
                    else:
                        del self._events[stale_key]
                self._last_prune = now
            return True, 0.0


class ScanManager:
    """Bounded concurrent-scan gate for API-triggered rescans."""

    def __init__(self, max_concurrent: int) -> None:
        self.max_concurrent = max(1, int(max_concurrent))
        self._semaphore = threading.BoundedSemaphore(self.max_concurrent)

    def try_acquire(self) -> bool:
        return self._semaphore.acquire(blocking=False)

    def release(self) -> None:
        try:
            self._semaphore.release()
        except ValueError:
            pass


# ------------------------------------------------------------------- Platform State
class PlatformState:
    """Thread-safe state holding the latest analysis result, cache, and settings."""

    def __init__(self, root: Path, config: SecdiagramConfig, allowed_scan_roots: list[Path]) -> None:
        self.root = root.resolve()
        self.config = config
        self.allowed_scan_roots = allowed_scan_roots
        self.lock = threading.Lock()
        self.last_analysis: AnalysisResult | None = None
        self.last_scan_timestamp: float = 0.0
        self.html_cache: str | None = None

    @property
    def studio_dir(self) -> Path:
        return self.root / STUDIO_DIR_REL

    def get_sdlc(self) -> agentic.SdlcState:
        try:
            return agentic.load_state(self.root)
        except agentic.SdlcError:
            return agentic.default_state()

    def get_overrides(self) -> DiagramOverrides:
        try:
            return load_diagram_overrides(self.root)
        except DiagramOverrideError:
            return DiagramOverrides()

    def get_edited_graph(self) -> Graph:
        return apply_overrides(self.get_analysis().graph, self.get_overrides())

    def render_studio_diagram(
        self,
        detail: str = "architecture",
        direction: str | None = None,
        theme: str | None = None,
    ) -> str:
        overrides = self.get_overrides()
        chosen_direction = direction or overrides.direction or self.config.analysis.diagram_direction
        chosen_theme = theme or overrides.theme or self.config.analysis.diagram_theme
        graph = apply_overrides(self.get_analysis().graph, overrides)
        if detail == "taint":
            return render_taint_mermaid(graph)
        if detail in {"high-level", "overview"}:
            hla = build_high_level_architecture(self.root, graph)
            return render_mermaid_highlevel(hla, direction=chosen_direction, theme=chosen_theme)
        return render_mermaid(
            graph,
            detail=detail,
            direction=chosen_direction,
            theme=chosen_theme,
        )

    def rescan(self, *, force: bool = True) -> AnalysisResult:
        with self.lock:
            if not force and self.last_analysis is not None:
                return self.last_analysis
            ana_cfg = self.config.analysis
            result = run_analysis(
                AnalysisConfig(
                    root=self.root,
                    include=ana_cfg.include,
                    exclude=ana_cfg.exclude,
                    min_confidence=ana_cfg.min_confidence,
                    max_nodes=ana_cfg.max_nodes,
                    security=ana_cfg.security,
                )
            )
            if ana_cfg.min_finding_confidence > 0:
                result.graph.findings = [
                    f for f in result.graph.findings
                    if f.confidence >= ana_cfg.min_finding_confidence
                ]
            self.last_analysis = result
            self.last_scan_timestamp = time.time()
            self.html_cache = None  # invalidate cache
            return result

    def get_analysis(self) -> AnalysisResult:
        with self.lock:
            if self.last_analysis is not None:
                return self.last_analysis
        # Re-check under the lock inside rescan so concurrent first requests run
        # the analysis exactly once.
        return self.rescan(force=False)

    def get_html_report(self) -> str:
        with self.lock:
            if self.html_cache is not None:
                return self.html_cache
        result = self.get_analysis()
        with self.lock:
            hla = build_high_level_architecture(self.root, result.graph)
            highlevel_mermaid = render_mermaid_highlevel(
                hla,
                direction=self.config.analysis.diagram_direction,
                theme=self.config.analysis.diagram_theme,
            )
            detail_mermaid = render_mermaid(
                result.graph,
                detail=self.config.analysis.diagram_detail,
                direction=self.config.analysis.diagram_direction,
                theme=self.config.analysis.diagram_theme,
            )
            html = render_html(
                result.graph,
                meta=dict(result.graph.meta),
                hla=hla,
                highlevel_mermaid=highlevel_mermaid,
                detail_mermaid=detail_mermaid,
                root=self.root,
                offline=False,
            )
            self.html_cache = html
            return html


# ------------------------------------------------------------------- Request Handler
class PlatformHTTPServer(ThreadingHTTPServer):
    """Threading HTTPServer with strongly typed platform state and authenticator."""

    platform_state: PlatformState
    authenticator: Authenticator
    audit: AuditLogger
    rate_limiter: RateLimiter
    scan_manager: ScanManager


class SecdiagramRequestHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler implementing REST API endpoints and modular UI hosting."""

    server_version = f"secdiagram-platform/{__version__}"

    @property
    def platform_server(self) -> PlatformHTTPServer:
        return cast(PlatformHTTPServer, self.server)

    def send_security_headers(self, overrides: Mapping[str, str] | None = None) -> None:
        headers = SECURITY_HEADERS if overrides is None else {**SECURITY_HEADERS, **overrides}
        for header, value in headers.items():
            self.send_header(header, value)

    def _send_json(
        self,
        status_code: int,
        data: Any,
        extra_headers: Mapping[str, str] | None = None,
    ) -> None:
        raw_json = (
            json.dumps(data, indent=2, sort_keys=True)
            .replace("<", "\\u003c")
            .replace(">", "\\u003e")
            .replace("&", "\\u0026")
        )
        payload = raw_json.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        if extra_headers:
            for header, value in extra_headers.items():
                self.send_header(header, value)
        self.send_security_headers()
        self.end_headers()
        self.wfile.write(payload)

    def _send_text(
        self,
        status_code: int,
        content: str,
        content_type: str = "text/plain; charset=utf-8",
        *,
        security_headers: Mapping[str, str] | None = None,
    ) -> None:
        payload = content.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_security_headers(security_headers)
        self.end_headers()
        self.wfile.write(payload)

    def _send_bytes(self, status_code: int, payload: bytes, content_type: str) -> None:
        overrides = (
            {"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox"}
            if content_type == "image/svg+xml"
            else None
        )
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_security_headers(overrides)
        self.end_headers()
        self.wfile.write(payload)

    def _check_origin(self) -> bool:
        """Reject cross-origin state-changing requests (defence in depth)."""
        origin = self.headers.get("Origin")
        if not origin:
            return True
        host = self.headers.get("Host") or ""
        try:
            parsed = urlsplit(origin)
        except ValueError:
            parsed = None
        if parsed is None or parsed.netloc.lower() != host.lower():
            self.platform_server.audit.log(
                "request_rejected",
                remote=self._client_key(),
                path=self._request_path(),
                reason="cross_origin",
            )
            self._send_json(403, {"error": "Forbidden", "message": "Cross-origin request rejected."})
            return False
        return True

    def _client_key(self) -> str:
        address = self.client_address
        if isinstance(address, tuple) and address:
            return str(address[0])
        return "unknown"

    def _request_path(self) -> str:
        return urlsplit(self.path).path or "/"

    def _check_rate_limit(self) -> bool:
        allowed, retry_after = self.platform_server.rate_limiter.check(self._client_key())
        if allowed:
            return True
        self.platform_server.audit.log(
            "rate_limited",
            remote=self._client_key(),
            path=self._request_path(),
        )
        self._send_json(
            429,
            {"error": "TooManyRequests", "message": "Rate limit exceeded. Retry later."},
            extra_headers={"Retry-After": str(max(1, int(retry_after + 0.5)))},
        )
        return False

    def _auth_username(self) -> str:
        raw = self.headers.get("authorization") or self.headers.get("Authorization") or ""
        if not raw.startswith("Basic "):
            return ""
        try:
            decoded = base64.b64decode(raw[6:].strip()).decode("utf-8")
            return decoded.split(":", 1)[0] if ":" in decoded else ""
        except Exception:
            return ""

    def _check_auth(self) -> bool:
        authenticator: Authenticator = self.platform_server.authenticator
        ok, identity = authenticator.authenticate(dict(self.headers))
        if ok:
            return True
        self.platform_server.audit.log(
            "auth_failure",
            remote=self._client_key(),
            path=self._request_path(),
            user=self._auth_username(),
            credential_present=bool(self.headers.get("Authorization") or self.headers.get("authorization")),
        )
        challenge = authenticator.challenge_header()
        body = json.dumps({"error": "Unauthorized", "message": "Authentication required."})
        err_body = body.encode("utf-8")
        self.send_response(401)
        if challenge:
            self.send_header("WWW-Authenticate", challenge)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(err_body)))
        self.send_security_headers()
        self.end_headers()
        self.wfile.write(err_body)
        return False

    def _read_json_body(self) -> tuple[bool, dict[str, Any]]:
        """Read a bounded JSON object request body.

        Returns ``(ok, payload)``; on failure a response has already been sent.
        """
        max_bytes = self.platform_server.platform_state.config.server.max_request_bytes
        if self.headers.get("Transfer-Encoding"):
            self.platform_server.audit.log(
                "request_rejected", remote=self._client_key(), path=self._request_path(), reason="chunked_body"
            )
            self._send_json(411, {"error": "LengthRequired", "message": "Chunked request bodies are not supported."})
            return False, {}
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            return True, {}
        try:
            length = int(raw_length)
        except ValueError:
            self._send_json(400, {"error": "BadRequest", "message": "Invalid Content-Length header."})
            return False, {}
        if length < 0 or length > max_bytes:
            self.platform_server.audit.log(
                "request_rejected", remote=self._client_key(), path=self._request_path(), reason="body_too_large"
            )
            self._send_json(
                413,
                {"error": "PayloadTooLarge", "message": "Request body exceeds the configured limit."},
            )
            return False, {}
        if length == 0:
            return True, {}
        raw = self.rfile.read(length)
        if not raw.strip():
            return True, {}
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send_json(400, {"error": "BadRequest", "message": "Request body must be valid JSON."})
            return False, {}
        if not isinstance(data, dict):
            self._send_json(400, {"error": "BadRequest", "message": "Request body must be a JSON object."})
            return False, {}
        return True, data

    def do_GET(self) -> None:
        if not self._check_rate_limit():
            return
        if not self._check_auth():
            return

        parsed = urlsplit(self.path)
        path = parsed.path.rstrip("/") or "/"
        query = parse_qs(parsed.query)
        state: PlatformState = self.platform_server.platform_state

        # 1. UI Root
        if path in {"/", "/app"}:
            try:
                html = state.get_html_report()
                self._send_text(200, html, "text/html; charset=utf-8")
            except Exception as exc:
                self.platform_server.audit.log("report_failed", remote=self._client_key(), error=type(exc).__name__)
                self._send_json(500, {"error": "InternalServerError", "message": "The report could not be generated."})
            return

        # 2. Studio single-page app and static assets
        if path in {"/studio", "/studio/index.html"}:
            try:
                self._send_text(
                    200,
                    studio_ui.render_studio_html(),
                    "text/html; charset=utf-8",
                    security_headers=STUDIO_SECURITY_HEADERS,
                )
            except studio_ui.StudioAssetError:
                self._send_json(500, {"error": "InternalServerError", "message": "Studio UI assets are missing."})
            return
        if path.startswith("/studio/"):
            name = path[len("/studio/"):]
            try:
                content_type, content = studio_ui.read_asset(name)
            except studio_ui.StudioAssetError:
                self._send_json(404, {"error": "NotFound", "message": f"Studio asset '{name}' does not exist."})
                return
            self._send_text(
                200,
                content,
                content_type,
                security_headers=STUDIO_SECURITY_HEADERS,
            )
            return

        # 3. REST API v1
        if path == "/api/v1/health":
            last_dt = (
                datetime.fromtimestamp(state.last_scan_timestamp, tz=timezone.utc).isoformat()
                if state.last_scan_timestamp else None
            )
            self._send_json(200, {
                "status": "ok",
                "version": __version__,
                "repo": state.root.name,
                "read_only": state.config.server.read_only,
                "auth_mode": state.config.server.auth_mode,
                "last_scan": last_dt,
            })
            return

        if path == "/api/v1/config":
            self._send_json(200, state.config.safe_dict())
            return

        if path == "/api/v1/summary":
            analysis = state.get_analysis()
            graph = analysis.graph
            self._send_json(200, {
                "name": analysis.repo.name,
                "commit": analysis.repo.commit,
                "branch": analysis.repo.branch,
                "nodes_count": len(graph.nodes),
                "edges_count": len(graph.edges),
                "findings_count": len(graph.findings),
                "features_count": len(graph.features),
                "severities": _sev_counts(graph),
                "languages": graph.meta.get("languages", {}),
            })
            return

        if path == "/api/v1/graph":
            analysis = state.get_analysis()
            self._send_text(200, render_json(analysis.graph), "application/json; charset=utf-8")
            return

        if path == "/api/v1/sarif":
            analysis = state.get_analysis()
            self.platform_server.audit.log("sarif_download", remote=self._client_key(), user=self._auth_username() or "anonymous")
            self._send_text(200, render_sarif(analysis.graph), "application/json; charset=utf-8")
            return

        if path == "/api/v1/findings":
            analysis = state.get_analysis()
            findings: list[Finding] = list(analysis.graph.findings)

            # Filtering query parameters
            sev_filter = query.get("severity")
            if sev_filter:
                allowed_sevs = {s.lower() for s in sev_filter}
                findings = [f for f in findings if f.severity.lower() in allowed_sevs]

            cat_filter = query.get("category")
            if cat_filter:
                allowed_cats = {c.lower() for c in cat_filter}
                findings = [f for f in findings if f.category.lower() in allowed_cats]

            min_conf = query.get("min_confidence")
            if min_conf:
                try:
                    conf_floor = float(min_conf[0])
                    findings = [f for f in findings if f.confidence >= conf_floor]
                except ValueError:
                    pass

            findings.sort(key=lambda f: (-SEVERITY_RANK.get(f.severity, 0), f.id))
            self._send_json(200, {
                "total": len(findings),
                "findings": [f.to_dict() for f in findings],
            })
            return

        if path == "/api/v1/threat-model":
            analysis = state.get_analysis()
            self._send_text(200, render_threat_model(analysis.graph), "text/markdown; charset=utf-8")
            return

        if path == "/api/v1/diagram":
            analysis = state.get_analysis()
            detail = query.get("detail", ["architecture"])[0]
            if detail == "taint":
                diagram_text = render_taint_mermaid(analysis.graph)
            elif detail in {"high-level", "overview"}:
                hla = build_high_level_architecture(state.root, analysis.graph)
                diagram_text = render_mermaid_highlevel(
                    hla,
                    direction=state.config.analysis.diagram_direction,
                    theme=state.config.analysis.diagram_theme,
                )
            else:
                diagram_text = render_mermaid(
                    analysis.graph,
                    detail=detail,
                    direction=state.config.analysis.diagram_direction,
                    theme=state.config.analysis.diagram_theme,
                )
            self._send_text(200, diagram_text, "text/plain; charset=utf-8")
            return

        # 4. Studio API
        if path == "/api/v1/studio/status":
            analysis = state.get_analysis()
            overrides = state.get_overrides()
            sdlc = state.get_sdlc()
            self._send_json(200, {
                "installer": studio_install.status(),
                "studio_dir": STUDIO_DIR_REL.as_posix(),
                "sdlc": _sdlc_payload(sdlc),
                "overrides": summarize_overrides(overrides, analysis.graph),
                "capabilities": {
                    "local_svg": bool(shutil.which("mmdc")),
                    "llm_providers": sorted(_ALLOWED_LLM_PROVIDERS),
                    "offline_first": True,
                    "static_analysis_only": True,
                },
            })
            return

        if path == "/api/v1/studio/sdlc":
            self._send_json(200, _sdlc_payload(state.get_sdlc()))
            return

        if path == "/api/v1/studio/overrides":
            overrides = state.get_overrides()
            self._send_json(200, {
                "overrides": overrides.to_dict(),
                "summary": summarize_overrides(overrides, state.get_analysis().graph),
            })
            return

        if path == "/api/v1/studio/nodes":
            # Return the unedited graph so hidden nodes remain editable in the
            # Studio; overrides are applied when rendering the diagram.
            try:
                limit = int(query.get("limit", ["400"])[0])
            except ValueError:
                limit = 400
            try:
                offset = int(query.get("offset", ["0"])[0])
            except ValueError:
                offset = 0
            limit = max(1, min(limit, 1000))
            offset = max(0, offset)
            needle = (query.get("q", [""])[0] or "").strip().lower()[:200]
            graph = state.get_analysis().graph
            nodes: list[dict[str, Any]] = []
            for node in sorted(
                graph.nodes.values(),
                key=lambda item: (
                    item.feature or "",
                    item.kind,
                    item.qualname,
                    item.path or "",
                    item.id,
                ),
            ):
                haystack = " ".join(
                    part for part in (node.id, node.name, node.kind, node.qualname, node.path, node.feature) if part
                ).lower()
                if needle and needle not in haystack:
                    continue
                nodes.append({
                    "id": node.id,
                    "name": node.name,
                    "kind": node.kind,
                    "qualname": node.qualname,
                    "path": node.path,
                    "line": node.line,
                    "feature": node.feature,
                })
            total = len(nodes)
            page = nodes[offset: offset + limit]
            self._send_json(200, {
                "total": total,
                "returned": len(page),
                "limit": limit,
                "offset": offset,
                "nodes": page,
            })
            return

        if path == "/api/v1/studio/diagram":
            detail = (query.get("detail", ["architecture"])[0] or "architecture").strip()
            if detail not in {"architecture", "high-level", "overview", "taint"}:
                self._send_json(400, {
                    "error": "BadRequest",
                    "message": "detail must be architecture, high-level, overview, or taint.",
                })
                return
            direction = _query_choice(query, "direction", _ALLOWED_DIRECTIONS)
            theme = _query_choice(query, "theme", _ALLOWED_THEMES)
            self._send_text(
                200,
                state.render_studio_diagram(detail, direction=direction, theme=theme),
                "text/plain; charset=utf-8",
            )
            return

        if path == "/api/v1/studio/render":
            detail = (query.get("detail", ["high-level"])[0] or "high-level").strip()
            if detail not in {"architecture", "high-level", "overview", "taint"}:
                self._send_json(400, {"error": "BadRequest", "message": "Unsupported diagram detail."})
                return
            image_format = (query.get("format", ["svg"])[0] or "svg").strip().lower()
            if image_format not in {"svg", "png"}:
                self._send_json(400, {"error": "BadRequest", "message": "format must be svg or png."})
                return
            direction = _query_choice(query, "direction", _ALLOWED_DIRECTIONS)
            theme = _query_choice(query, "theme", _ALLOWED_THEMES)
            source = state.render_studio_diagram(detail, direction=direction, theme=theme)
            try:
                with tempfile.TemporaryDirectory(prefix="secdiagram-studio-") as tmp:
                    output = Path(tmp) / f"diagram.{image_format}"
                    render_image(
                        source,
                        output,
                        image_format=image_format,
                        provider="local",
                        timeout=30.0,
                        offline=True,
                    )
                    image_payload = output.read_bytes()
            except (ImageRenderError, OSError, ValueError) as exc:
                self.platform_server.audit.log(
                    "studio_render_failed", remote=self._client_key(), error=type(exc).__name__
                )
                self._send_json(503, {
                    "error": "RenderUnavailable",
                    "message": redact_secrets(str(exc)),
                })
                return
            content_type = "image/svg+xml" if image_format == "svg" else "image/png"
            self._send_bytes(200, image_payload, content_type)
            return

        if path == "/api/v1/studio/handoff":
            sdlc = state.get_sdlc()
            graph = state.get_analysis().graph
            handoff_payload = agentic.build_handoff(
                sdlc,
                repo_name=state.root.name,
                graph=graph,
                out_dir=state.root / ".secdiagram",
            )
            self._send_text(
                200,
                agentic.render_handoff_markdown(handoff_payload),
                "text/markdown; charset=utf-8",
            )
            return

        if path == "/api/v1/studio/skill":
            self._send_json(200, _studio_skill_payload())
            return

        if path == "/api/v1/studio/brief":
            phase = (query.get("phase", [""])[0] or "").strip()
            try:
                markdown = agentic.render_phase_brief(
                    state.get_sdlc(), phase, repo_name=state.root.name
                )
            except agentic.SdlcError as exc:
                self._send_json(400, {"error": "BadRequest", "message": str(exc)})
                return
            self._send_text(200, markdown, "text/markdown; charset=utf-8")
            return

        # 404 Not Found
        self._send_json(404, {"error": "NotFound", "message": f"Endpoint '{path}' does not exist."})

    def do_POST(self) -> None:
        if not self._check_rate_limit():
            return
        if not self._check_auth():
            return
        if not self._check_origin():
            return

        parsed = urlsplit(self.path)
        path = parsed.path.rstrip("/") or "/"
        state: PlatformState = self.platform_server.platform_state

        if path == "/api/v1/studio/sdlc":
            body_ok, body = self._read_json_body()
            if not body_ok:
                return
            if state.config.server.read_only:
                self._send_json(403, {
                    "error": "Forbidden",
                    "message": "Platform is running in read-only mode; SDLC state cannot be changed.",
                })
                return
            action = body.get("action")
            phase = body.get("phase")
            evidence = body.get("evidence")
            note = body.get("note")
            if evidence is not None and not isinstance(evidence, str):
                self._send_json(400, {"error": "BadRequest", "message": "evidence must be a string."})
                return
            if note is not None and not isinstance(note, str):
                self._send_json(400, {"error": "BadRequest", "message": "note must be a string."})
                return
            sdlc = state.get_sdlc()
            try:
                agentic.apply_action(
                    sdlc,
                    str(action),
                    str(phase),
                    evidence=evidence,
                    note=note,
                )
            except agentic.SdlcError as exc:
                self._send_json(400, {"error": "BadRequest", "message": str(exc)})
                return
            try:
                agentic.save_state(state.root, sdlc)
            except (OSError, agentic.SdlcError) as exc:
                self._send_json(500, {"error": "StateWriteFailed", "message": redact_secrets(str(exc))})
                return
            self.platform_server.audit.log(
                "studio_sdlc",
                remote=self._client_key(),
                user=self._auth_username() or "anonymous",
                action=str(action),
                phase=str(phase),
            )
            self._send_json(200, {"status": "ok", "state": _sdlc_payload(sdlc)})
            return

        if path == "/api/v1/studio/overrides":
            body_ok, body = self._read_json_body()
            if not body_ok:
                return
            if state.config.server.read_only:
                self._send_json(403, {
                    "error": "Forbidden",
                    "message": "Platform is running in read-only mode; diagram edits cannot be changed.",
                })
                return
            if body.get("action") == "reset":
                try:
                    clear_overrides(state.root)
                except (DiagramOverrideError, OSError) as exc:
                    self._send_json(500, {
                        "error": "StateWriteFailed",
                        "message": redact_secrets(str(exc)),
                    })
                    return
                overrides = DiagramOverrides()
            else:
                try:
                    overrides = DiagramOverrides.from_dict(body)
                    save_diagram_overrides(state.root, overrides)
                except DiagramOverrideError as exc:
                    self._send_json(400, {"error": "BadRequest", "message": str(exc)})
                    return
                except OSError as exc:
                    self._send_json(500, {"error": "StateWriteFailed", "message": redact_secrets(str(exc))})
                    return
            self.platform_server.audit.log(
                "studio_overrides",
                remote=self._client_key(),
                user=self._auth_username() or "anonymous",
                renames=len(overrides.renames),
                hidden=len(overrides.hidden),
            )
            self._send_json(200, {
                "status": "ok",
                "overrides": overrides.to_dict(),
                "summary": summarize_overrides(overrides, state.get_analysis().graph),
            })
            return

        if path == "/api/v1/studio/generate":
            body_ok, body = self._read_json_body()
            if not body_ok:
                return
            provider = str(body.get("provider", "ollama") or "ollama").strip().lower()
            if provider not in _ALLOWED_LLM_PROVIDERS:
                self._send_json(400, {
                    "error": "BadRequest",
                    "message": "provider must be ollama or openai.",
                })
                return
            template = str(body.get("template", "comprehensive") or "comprehensive").strip()
            if template not in _ALLOWED_LLM_TEMPLATES:
                self._send_json(400, {
                    "error": "BadRequest",
                    "message": "template must be one of " + ", ".join(sorted(_ALLOWED_LLM_TEMPLATES)) + ".",
                })
                return
            model_value = body.get("model")
            if model_value is not None and (not isinstance(model_value, str) or len(model_value) > 200):
                self._send_json(400, {"error": "BadRequest", "message": "model must be a string up to 200 characters."})
                return
            base_value = body.get("base_url")
            if base_value is not None:
                if not isinstance(base_value, str) or len(base_value) > 500:
                    self._send_json(400, {"error": "BadRequest", "message": "base_url must be a string up to 500 characters."})
                    return
                if base_value.strip() and not _llm_base_url_allowed(base_value.strip()):
                    self._send_json(400, {
                        "error": "BadRequest",
                        "message": (
                            "base_url must target loopback, a private address, or an OpenAI host; "
                            "use the CLI for other endpoints."
                        ),
                    })
                    return
            try:
                narrative = generate_narrative(
                    state.get_analysis().graph,
                    model=model_value.strip() if isinstance(model_value, str) and model_value.strip() else None,
                    base_url=base_value.strip() if isinstance(base_value, str) and base_value.strip() else None,
                    provider=provider,
                    template=template,
                    timeout=120.0,
                )
            except (NarrativeError, OSError, TimeoutError, ValueError) as exc:
                self.platform_server.audit.log(
                    "studio_llm_failed", remote=self._client_key(), error=type(exc).__name__
                )
                self._send_json(502, {
                    "error": "NarrativeUnavailable",
                    "message": redact_secrets(str(exc)),
                })
                return
            self.platform_server.audit.log(
                "studio_llm",
                remote=self._client_key(),
                user=self._auth_username() or "anonymous",
                provider=provider,
                template=template,
            )
            self._send_json(200, {"status": "ok", "narrative": narrative})
            return

        if path == "/api/v1/studio/handoff":
            body_ok, body = self._read_json_body()
            if not body_ok:
                return
            write_requested = bool(body.get("write", False))
            sdlc = state.get_sdlc()
            graph = state.get_analysis().graph
            if not write_requested:
                payload = agentic.build_handoff(
                    sdlc,
                    repo_name=state.root.name,
                    graph=graph,
                    out_dir=state.root / ".secdiagram",
                )
                self._send_text(
                    200,
                    agentic.render_handoff_markdown(payload),
                    "text/markdown; charset=utf-8",
                )
                return
            if state.config.server.read_only:
                self._send_json(403, {
                    "error": "Forbidden",
                    "message": "Platform is running in read-only mode; handoff files cannot be written.",
                })
                return
            try:
                md_path, json_path = agentic.write_handoff(
                    state.studio_dir,
                    sdlc,
                    repo_name=state.root.name,
                    graph=graph,
                    artifact_dir=state.root / ".secdiagram",
                )
            except agentic.HandoffBlocked as exc:
                self._send_json(409, {"error": "HandoffBlocked", "message": str(exc)})
                return
            except (OSError, agentic.SdlcError) as exc:
                self._send_json(500, {"error": "HandoffWriteFailed", "message": redact_secrets(str(exc))})
                return
            self.platform_server.audit.log(
                "studio_handoff",
                remote=self._client_key(),
                user=self._auth_username() or "anonymous",
            )
            self._send_json(200, {
                "status": "ok",
                "markdown": md_path.read_text(encoding="utf-8"),
                "files": [
                    str(md_path.relative_to(state.root).as_posix()),
                    str(json_path.relative_to(state.root).as_posix()),
                ],
            })
            return

        if path == "/api/v1/studio/installer":
            body_ok, _body = self._read_json_body()
            if not body_ok:
                return
            self._send_json(403, {
                "error": "Forbidden",
                "message": "The installer performs writes and is available only through `secdiagram studio install`.",
            })
            return

        if path == "/api/v1/scan":
            body_ok, body = self._read_json_body()
            if not body_ok:
                return

            requested = body.get("path") or body.get("root") or body.get("dir")
            if requested is not None:
                if not isinstance(requested, str) or not requested.strip():
                    self._send_json(400, {"error": "BadRequest", "message": "Scan path must be a non-empty string."})
                    return

                root_text = str(state.root.resolve())
                requested_expanded = str(Path(requested).expanduser())
                requested_normalized = str(Path(requested_expanded))

                if requested_normalized != root_text:
                    self.platform_server.audit.log(
                        "scan_rejected",
                        remote=self._client_key(),
                        scan_path=requested,
                        reason="path_not_allowlisted",
                    )
                    self._send_json(
                        403,
                        {
                            "error": "Forbidden",
                            "message": "The requested scan path is not allowlisted.",
                        },
                    )
                    return

                try:
                    candidate = Path(requested_normalized).resolve()
                except (OSError, ValueError):
                    candidate = None
                allowlisted = (
                    candidate is not None
                    and candidate == state.root
                    and any(_is_within(candidate, allowed) for allowed in state.allowed_scan_roots)
                )
                if not allowlisted:
                    self.platform_server.audit.log(
                        "scan_rejected",
                        remote=self._client_key(),
                        scan_path=requested,
                        reason="path_not_allowlisted",
                    )
                    self._send_json(
                        403,
                        {
                            "error": "Forbidden",
                            "message": "The requested scan path is not allowlisted.",
                        },
                    )
                    return

            if state.config.server.read_only:
                self.platform_server.audit.log(
                    "scan_rejected", remote=self._client_key(), user=self._auth_username() or "anonymous",
                    reason="read_only",
                )
                self._send_json(403, {
                    "error": "Forbidden",
                    "message": "Platform is running in read-only mode; scans cannot be triggered via API.",
                })
                return

            self.platform_server.audit.log(
                "scan_requested", remote=self._client_key(), user=self._auth_username() or "anonymous"
            )
            if not self.platform_server.scan_manager.try_acquire():
                self.platform_server.audit.log(
                    "scan_rejected", remote=self._client_key(), reason="concurrency_limit"
                )
                self._send_json(
                    429,
                    {"error": "TooManyRequests", "message": "Another scan is already running. Retry later."},
                    extra_headers={"Retry-After": "5"},
                )
                return
            try:
                result = state.rescan()
                self.platform_server.audit.log(
                    "scan_succeeded",
                    remote=self._client_key(),
                    nodes=len(result.graph.nodes),
                    edges=len(result.graph.edges),
                    findings=len(result.graph.findings),
                )
                self._send_json(200, {
                    "status": "success",
                    "message": "Repository re-scanned successfully.",
                    "nodes_count": len(result.graph.nodes),
                    "edges_count": len(result.graph.edges),
                    "findings_count": len(result.graph.findings),
                })
            except Exception as exc:
                self.platform_server.audit.log(
                    "scan_failed", remote=self._client_key(), error=type(exc).__name__
                )
                self._send_json(500, {"error": "ScanFailed", "message": "The scan could not be completed."})
            finally:
                self.platform_server.scan_manager.release()
            return

        self._send_json(404, {"error": "NotFound", "message": f"Endpoint '{path}' does not exist."})

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress noisy standard HTTP access logs to keep CLI/daemon stdout clean
        pass


# ------------------------------------------------------------------- Server Construction
def _resolve_scan_roots(root: Path, configured: list[str]) -> list[Path]:
    """Resolve the configured scan allowlist and require the served root to be inside it."""
    entries = configured or [str(root)]
    resolved: list[Path] = []
    for entry in entries:
        candidate = Path(entry).expanduser()
        if not candidate.is_absolute():
            candidate = root / candidate
        try:
            resolved.append(candidate.resolve())
        except OSError:
            continue
    if not resolved:
        resolved = [root.resolve()]
    if not any(_is_within(root.resolve(), allowed) for allowed in resolved):
        raise ValueError("Served repository is not inside the configured scan allowlist.")
    return resolved


def _is_port_in_use_error(exc: OSError) -> bool:
    addr_in_use_errnos = {
        errno.EADDRINUSE,
        getattr(errno, "WSAEADDRINUSE", 10048),
    }
    winerror = getattr(exc, "winerror", None)
    return exc.errno in addr_in_use_errnos or winerror in {10048, 10013}


def _bind_server(
    host: str,
    port: int,
    strict_port: bool = False,
    max_port_attempts: int = 100,
) -> tuple[PlatformHTTPServer, int]:
    """Bind PlatformHTTPServer, automatically trying subsequent ports if port is in use."""
    if port == 0 or strict_port:
        server = PlatformHTTPServer((host, port), SecdiagramRequestHandler)
        bound_port = int(server.server_address[1])
        return server, bound_port

    last_error: OSError | None = None
    for offset in range(max_port_attempts):
        candidate_port = port + offset
        if candidate_port > 65535:
            break
        try:
            server = PlatformHTTPServer((host, candidate_port), SecdiagramRequestHandler)
            bound_port = int(server.server_address[1])
            if offset > 0:
                print(
                    f"Port {port} is in use; starting platform on port {bound_port}.",
                    file=sys.stderr,
                )
            return server, bound_port
        except OSError as exc:
            if _is_port_in_use_error(exc):
                last_error = exc
                continue
            raise

    if last_error is not None:
        raise last_error
    raise OSError(f"Could not bind to any port in range {port}..{min(65535, port + max_port_attempts - 1)}")


def create_server(
    root: Path,
    config: SecdiagramConfig | None = None,
    strict_port: bool | None = None,
) -> PlatformHTTPServer:
    """Create and configure a PlatformHTTPServer instance."""
    resolved_root = root.resolve()
    cfg = config or load_config(resolved_root)
    if strict_port is not None:
        cfg.server.strict_port = strict_port

    if not cfg.server.is_auth_enabled():
        if not cfg.server.insecure_no_auth:
            raise ValueError(
                "Authentication is required. Configure HTTP Basic Auth credentials "
                "(--server-user/--server-pass or SECDIAGRAM_AUTH_USER/SECDIAGRAM_AUTH_PASS), "
                "or pass --insecure-no-auth for loopback-only development."
            )
        if not _is_loopback_host(cfg.server.host):
            raise ValueError(
                "Refusing to bind a non-loopback host without authentication. "
                "Configure credentials or bind to 127.0.0.1."
            )

    allowed_scan_roots = _resolve_scan_roots(resolved_root, cfg.server.scan_roots)
    server, bound_port = _bind_server(
        cfg.server.host,
        cfg.server.port,
        strict_port=cfg.server.strict_port,
    )
    cfg.server.port = bound_port

    state = PlatformState(resolved_root, cfg, allowed_scan_roots)
    audit = AuditLogger(cfg.server.audit_log, resolved_root)

    # Initialize authenticator
    if cfg.server.is_auth_enabled():
        assert cfg.server.auth_username is not None
        assert cfg.server.auth_password is not None
        authenticator: Authenticator = BasicAuthenticator(
            username=cfg.server.auth_username,
            password=cfg.server.auth_password,
        )
    else:
        authenticator = NoOpAuthenticator()

    server.platform_state = state
    server.authenticator = authenticator
    server.audit = audit
    server.rate_limiter = RateLimiter(cfg.server.rate_limit_per_minute)
    server.scan_manager = ScanManager(cfg.server.max_concurrent_scans)
    return server


def serve(
    root: Path,
    host: str | None = None,
    port: int | None = None,
    auth_username: str | None = None,
    auth_password: str | None = None,
    read_only: bool = False,
    config_path: Path | None = None,
    insecure_no_auth: bool = False,
    max_request_bytes: int | None = None,
    rate_limit_per_minute: int | None = None,
    max_concurrent_scans: int | None = None,
    scan_roots: list[str] | None = None,
    audit_log: str | None = None,
    strict_port: bool = False,
) -> int:
    """Run the platform server daemon."""
    cfg = load_config(root, config_path)
    if host:
        cfg.server.host = host
    if port:
        cfg.server.port = port
    if strict_port:
        cfg.server.strict_port = True
    if auth_username:
        cfg.server.auth_username = auth_username
    if auth_password:
        cfg.server.auth_password = auth_password
    if read_only:
        cfg.server.read_only = True
    if insecure_no_auth:
        cfg.server.insecure_no_auth = True
    if max_request_bytes is not None:
        cfg.server.max_request_bytes = max_request_bytes
    if rate_limit_per_minute is not None:
        cfg.server.rate_limit_per_minute = rate_limit_per_minute
    if max_concurrent_scans is not None:
        cfg.server.max_concurrent_scans = max_concurrent_scans
    if scan_roots is not None:
        cfg.server.scan_roots = list(scan_roots)
    if audit_log is not None:
        cfg.server.audit_log = audit_log

    if cfg.server.auth_username and cfg.server.auth_password:
        cfg.server.auth_mode = "basic"

    server = create_server(root, cfg)
    addr = server.server_address
    bind_host = addr[0].decode("ascii") if isinstance(addr[0], bytes) else str(addr[0])
    bind_port = int(addr[1])
    auth_status = "Basic Auth (active)" if cfg.server.is_auth_enabled() else "None (insecure loopback development mode)"

    server.audit.log(
        "server_started",
        host=bind_host,
        port=bind_port,
        auth_mode=cfg.server.auth_mode,
        read_only=cfg.server.read_only,
        root=str(root.resolve()),
    )
    if not _is_loopback_host(bind_host):
        print(
            "WARNING: secdiagram platform is bound to a non-loopback interface; "
            "ensure a trusted reverse proxy, TLS, and authentication are in place.",
            file=sys.stderr,
        )

    print(f"secdiagram platform listening on http://{bind_host}:{bind_port}", file=sys.stderr)
    print(f"  Repository: {root.name}", file=sys.stderr)
    print(f"  Authentication: {auth_status}", file=sys.stderr)
    print(f"  REST API: http://{bind_host}:{bind_port}/api/v1/health", file=sys.stderr)
    print(f"  Web UI: http://{bind_host}:{bind_port}/", file=sys.stderr)
    print("Press Ctrl+C to terminate.", file=sys.stderr)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down secdiagram platform...", file=sys.stderr)
    finally:
        server.audit.log("server_stopped", host=bind_host, port=bind_port)
        server.server_close()
    return 0
