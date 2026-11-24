"""Deterministic ingestion of DAST runtime evidence.

OWASP ZAP and Nuclei are *dynamic* scanners: they observe a running
application over HTTP. ``secdiagram`` never launches them (that would require
network targets, external binaries, and non-deterministic execution), so this
module imports their JSON output instead and correlates every observed request
with the statically parsed endpoint graph.

The result is realistic runtime context without weakening the project's
guarantees:

* only local report files are read (no network, no code execution);
* report data is treated as untrusted input and bounded in size;
* every observation is normalized and matched deterministically to endpoint
  nodes so the same report always produces the same graph, metadata, and
  findings;
* runtime-only endpoints (observed by the scanner but absent from the static
  graph) are reported instead of invented as nodes.

Supported inputs:

* ZAP Traditional JSON (``{"site": [{"alerts": [{"instances": [...]}]}]}``),
  with or without request/response bodies.
* Nuclei ``-jsonl``/``-json`` output (JSON Lines, a JSON array, or a single
  result object).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from .model import Finding, Graph, Loc, stable_id
from .redaction import redact_secrets

MAX_REPORT_BYTES = 32 * 1024 * 1024
MAX_ISSUES = 5000
MAX_OBSERVATION_TEXT = 240
MAX_RUNTIME_ENDPOINTS = 100
MAX_RUNTIME_PARAMS = 20

DAST_SOURCES = frozenset({"zap", "nuclei"})

CWE_RE = re.compile(r"\bCWE[-_ ]?(\d{1,4})\b", re.IGNORECASE)
BARE_CWE_RE = re.compile(r"^\s*(\d{1,4})\s*$")
TAG_RE = re.compile(r"<[^>]+>")
PLACEHOLDER_RE = re.compile(
    r"^(?:\{[^/]+\}|<[^>]+>|:[A-Za-z_]\w*|\[[^\]]+\]|\*|\*\*)$"
)
STATUS_RE = re.compile(r"^HTTP/\d(?:\.\d)?\s+(\d{3})", re.IGNORECASE)

_SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
    "unknown": "low",
}
_ZAP_RISK = {"3": "high", "2": "medium", "1": "low", "0": "info"}
_NUCLEI_CATEGORY = {
    "sqli": "sql",
    "sql": "sql",
    "nosql": "nosql",
    "xss": "xss",
    "rce": "command",
    "command": "command",
    "lfi": "path",
    "path": "path",
    "traversal": "path",
    "ssrf": "network",
    "xxe": "xxe",
    "ssti": "template",
    "template": "template",
    "redirect": "redirect",
    "open-redirect": "redirect",
    "deserialization": "deserialization",
}
_CWE_CATEGORY = {
    22: "path",
    77: "command",
    78: "command",
    79: "xss",
    80: "xss",
    89: "sql",
    90: "sql",
    94: "code",
    95: "code",
    98: "path",
    434: "path",
    502: "deserialization",
    564: "sql",
    601: "redirect",
    611: "xxe",
    643: "sql",
    917: "code",
    918: "network",
    943: "sql",
}


class DASTReportError(ValueError):
    """Raised when a supplied DAST report cannot be normalized."""


@dataclass(slots=True)
class RuntimeObservation:
    """A single HTTP request/observation reported by a DAST scanner."""

    source: str
    method: str
    url: str
    path: str
    param: str = ""
    status_code: int | None = None
    evidence: str = ""
    matched_node: str | None = None
    matched_route: str = ""

    @property
    def id(self) -> str:
        return stable_id("runtime", self.source, self.method, self.path, self.param)

    @property
    def label(self) -> str:
        method = self.method or "ANY"
        return f"{method} {self.path}".strip()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source,
            "method": self.method,
            "path": self.path,
            "url": self.url,
            "param": self.param,
            "status_code": self.status_code,
            "evidence": self.evidence,
            "matched_node": self.matched_node,
            "matched_route": self.matched_route,
        }


@dataclass(slots=True)
class _EndpointRoute:
    node_id: str
    method: str
    path: str
    literals: int
    segments: list[str] = field(default_factory=list)


def _read_text(path: Path) -> str:
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise FileNotFoundError(f"DAST report not found: {path}")
    try:
        size = resolved.stat().st_size
        if size > MAX_REPORT_BYTES:
            raise DASTReportError(
                f"DAST report is larger than {MAX_REPORT_BYTES // (1024 * 1024)} MiB: {path}"
            )
        return resolved.read_text(encoding="utf-8", errors="replace")
    except DASTReportError:
        raise
    except OSError as exc:
        raise DASTReportError(f"could not read DAST report {path}: {exc}") from exc


def _read_json(path: Path) -> Any:
    text = _read_text(path)
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise DASTReportError(f"could not parse JSON DAST report {path}: {exc}") from exc


def _clean(value: Any, limit: int = MAX_OBSERVATION_TEXT) -> str:
    text = " ".join(str(value or "").split())
    text = redact_secrets(text)
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)].rstrip() + "..."


def _plain(value: Any, limit: int = MAX_OBSERVATION_TEXT) -> str:
    return _clean(TAG_RE.sub(" ", str(value or "")), limit)


def _severity(value: Any) -> str:
    return _SEVERITY_MAP.get(str(value or "").strip().lower(), "medium")


def _nuclei_severity(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text == "unknown":
        return "low"
    return _SEVERITY_MAP.get(text, "low")


def _cwe_number(*values: Any) -> int | None:
    for value in values:
        if not value:
            continue
        items = value if isinstance(value, list) else [value]
        for item in items:
            text = str(item)
            match = CWE_RE.search(text) or BARE_CWE_RE.match(text)
            if match:
                number = int(match.group(1))
                if 1 <= number <= 2000:
                    return number
    return None


def _cwe_label(number: int | None) -> str | None:
    return f"CWE-{number}" if number is not None else None


def _category(cwe: int | None, tags: list[str], text: str) -> str:
    if cwe is not None and cwe in _CWE_CATEGORY:
        return _CWE_CATEGORY[cwe]
    haystack = " ".join(tags + [text]).lower()
    for token in sorted(_NUCLEI_CATEGORY):
        if re.search(rf"(?<![a-z0-9]){re.escape(token)}(?![a-z0-9])", haystack):
            return _NUCLEI_CATEGORY[token]
    return "runtime"


def _status_code(value: Any) -> int | None:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if 100 <= number <= 599 else None


def _status_from_header(value: Any) -> int | None:
    match = STATUS_RE.search(str(value or ""))
    return _status_code(match.group(1)) if match else None


def _url_path(raw: Any) -> str:
    text = str(raw or "").strip()
    if not text:
        return "/"
    if "://" in text:
        try:
            parsed = urlsplit(text)
        except ValueError:
            return "/"
        path = parsed.path or "/"
    else:
        path = text.split("?", 1)[0].split("#", 1)[0]
    if not path.startswith("/"):
        path = "/" + path
    return path or "/"


def _normalize_url_path(raw: Any) -> str:
    path = _url_path(raw).split("?", 1)[0].split("#", 1)[0]
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    return path or "/"


def _segments(path: str) -> list[str]:
    trimmed = path.strip("/")
    if not trimmed:
        return []
    return [unquote(segment) for segment in trimmed.split("/")]


def _is_placeholder(segment: str) -> bool:
    return bool(PLACEHOLDER_RE.match(segment)) or segment == "*"


def _match_segments(route: list[str], runtime: list[str]) -> bool:
    if not route:
        return not runtime
    index = 0
    while index < len(route):
        segment = route[index]
        if segment == "**":
            return True
        if index >= len(runtime):
            return False
        if segment == "*" or _is_placeholder(segment):
            index += 1
            continue
        if segment != runtime[index]:
            return False
        index += 1
    return index == len(runtime)


def _path_matches(route_path: str, runtime_path: str) -> bool:
    route = _segments(_normalize_url_path(route_path))
    runtime = _segments(_normalize_url_path(runtime_path))
    if not route:
        return not runtime
    if _match_segments(route, runtime):
        return True
    if len(runtime) > len(route):
        # Applications are often mounted under a base path (for example
        # /api/v1) that the route table does not include.
        return _match_segments(route, runtime[-len(route) :])
    return False


def _method_matches(route_method: str, runtime_method: str) -> bool:
    route = (route_method or "ANY").upper().strip()
    runtime = (runtime_method or "").upper().strip()
    if not runtime:
        return True
    if route in {"ANY", "ALL", "*"}:
        return True
    return runtime in {part.strip() for part in re.split(r"[,|]", route) if part.strip()}


def _literal_count(path: str) -> int:
    return sum(
        1
        for segment in _segments(path)
        if segment and segment != "**" and not _is_placeholder(segment)
    )


def _ordered_observations(observations: list[RuntimeObservation]) -> list[RuntimeObservation]:
    return sorted(
        observations,
        key=lambda item: (item.source, item.method, item.path, item.param, item.url),
    )


def _zap_risk(alert: dict[str, Any]) -> str:
    code = str(alert.get("riskcode") or "").strip()
    if code in _ZAP_RISK:
        return _ZAP_RISK[code]
    riskdesc = str(alert.get("riskdesc") or "").split("(", 1)[0]
    return _severity(riskdesc)


def _zap_confidence(alert: dict[str, Any], severity: str) -> float:
    code = str(alert.get("confidence") or "").strip()
    if code == "3":
        return 0.99
    if code == "2":
        return 0.97
    if code == "1":
        return 0.92
    return 0.95 if severity in {"critical", "high"} else 0.9


def _zap_tags(alert: dict[str, Any]) -> list[str]:
    tags: list[str] = []
    for item in alert.get("tags") or []:
        if isinstance(item, dict):
            value = item.get("tag")
        else:
            value = item
        text = _clean(value, 80)
        if text:
            tags.append(text)
    return sorted(set(tags))


def _zap_findings(
    data: Any, report_name: str
) -> tuple[list[Finding], list[RuntimeObservation]]:
    sites = data.get("site") if isinstance(data, dict) else None
    if not isinstance(sites, list):
        raise DASTReportError("ZAP report must contain a 'site' list")
    findings: dict[str, Finding] = {}
    observations: list[RuntimeObservation] = []
    for site in sites:
        if not isinstance(site, dict):
            continue
        alerts = site.get("alerts")
        if not isinstance(alerts, list):
            continue
        for alert in alerts:
            if not isinstance(alert, dict):
                continue
            instances = alert.get("instances")
            if not isinstance(instances, list) or not instances:
                # An alert with no captured request was never observed at
                # runtime; it is only a scanner rule, not runtime evidence.
                continue
            name = _plain(alert.get("alert") or alert.get("name") or "ZAP alert", 200)
            severity = _zap_risk(alert)
            confidence = _zap_confidence(alert, severity)
            cwe = _cwe_number(alert.get("cweid"), alert.get("cwe"))
            tags = _zap_tags(alert)
            category = _category(cwe, tags, f"{name} {alert.get('desc') or ''}")
            plugin = _clean(alert.get("pluginid") or alert.get("alertRef"), 40)
            solution = _plain(alert.get("solution"), 300)
            reference = _clean(alert.get("reference"), 200)
            for instance in instances:
                if len(observations) >= MAX_ISSUES:
                    break
                if not isinstance(instance, dict):
                    continue
                url = str(instance.get("uri") or instance.get("url") or site.get("@name") or "")
                if not url:
                    continue
                method = str(instance.get("method") or "").upper()
                path = _normalize_url_path(url)
                param = _clean(instance.get("param"), 80)
                evidence = _clean(instance.get("evidence") or instance.get("attack"), 200)
                status = _status_from_header(instance.get("response-header"))
                observation = RuntimeObservation(
                    source="zap",
                    method=method,
                    url=_clean(url, 300),
                    path=path,
                    param=param,
                    status_code=status,
                    evidence=evidence,
                )
                observations.append(observation)
                finding_id = stable_id("dast", "zap", plugin, path, param, name)
                if finding_id in findings:
                    continue
                detail = f"OWASP ZAP observed {name} at {method or 'ANY'} {path}".strip()
                if param:
                    detail += f" (parameter {param})"
                if status is not None:
                    detail += f" [HTTP {status}]"
                metadata: dict[str, Any] = {
                    "tool": "zap",
                    "plugin_id": plugin,
                    "alert": name,
                    "risk": severity,
                    "tags": tags,
                    "url": observation.url,
                    "method": method,
                    "param": param,
                    "status_code": status,
                    "evidence": evidence,
                    "reference": reference,
                    "runtime": observation.to_dict(),
                }
                metadata = {
                    key: value
                    for key, value in metadata.items()
                    if value not in ("", None, [])
                }
                findings[finding_id] = Finding(
                    id=finding_id,
                    category=category,
                    severity=severity,
                    title=f"ZAP: {name}",
                    message=detail,
                    cwe=_cwe_label(cwe),
                    confidence=confidence,
                    evidence=[Loc(report_name, 1)],
                    recommendation=(
                        solution
                        or "Reproduce the runtime finding, fix the affected endpoint, and add a regression test."
                    ),
                    source="zap",
                    external_id=plugin or None,
                    metadata=metadata,
                )
    return list(findings.values()), observations


def _nuclei_records(text: str) -> list[dict[str, Any]]:
    stripped = text.strip()
    if not stripped:
        return []
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        records: list[dict[str, Any]] = []
        for number, line in enumerate(stripped.splitlines(), 1):
            entry = line.strip()
            if not entry:
                continue
            try:
                parsed = json.loads(entry)
            except json.JSONDecodeError as exc:
                raise DASTReportError(
                    f"invalid Nuclei JSONL on line {number}: {exc}"
                ) from exc
            if isinstance(parsed, dict):
                records.append(parsed)
        return records
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        if "site" in data and "info" not in data:
            raise DASTReportError(
                "the supplied report looks like OWASP ZAP output; use --zap-report"
            )
        return [data] if data else []
    raise DASTReportError("Nuclei report must contain JSON objects")


def _nuclei_tags(info: dict[str, Any]) -> list[str]:
    raw = info.get("tags")
    if isinstance(raw, list):
        tags = [_clean(item, 60) for item in raw]
    else:
        tags = [_clean(item, 60) for item in str(raw or "").split(",")]
    return sorted({tag for tag in tags if tag})


def _nuclei_method(record: dict[str, Any]) -> str:
    metadata = record.get("metadata")
    candidates = [
        record.get("method"),
        record.get("request-method"),
        metadata.get("method") if isinstance(metadata, dict) else None,
    ]
    for candidate in candidates:
        text = str(candidate or "").strip().upper()
        if text and re.fullmatch(r"[A-Z]{2,10}", text):
            return text
    return ""


def _nuclei_findings(
    records: list[dict[str, Any]], report_name: str
) -> tuple[list[Finding], list[RuntimeObservation]]:
    findings: dict[str, Finding] = {}
    observations: list[RuntimeObservation] = []
    for record in records[:MAX_ISSUES]:
        info = record.get("info")
        if not isinstance(info, dict):
            info = {}
        if not (
            record.get("template-id")
            or record.get("templateID")
            or record.get("template")
            or info
            or record.get("matched-at")
            or record.get("host")
        ):
            continue
        template = _clean(
            record.get("template-id")
            or record.get("templateID")
            or record.get("template")
            or "",
            120,
        )
        name = _plain(
            info.get("name") or record.get("matcher-name") or template or "Nuclei finding",
            200,
        )
        severity = _nuclei_severity(info.get("severity"))
        classification = info.get("classification")
        if not isinstance(classification, dict):
            classification = {}
        cwe = _cwe_number(
            classification.get("cwe-id"),
            classification.get("cwe_id"),
            record.get("cwe"),
        )
        tags = _nuclei_tags(info)
        text = " ".join(
            str(part)
            for part in (
                name,
                template,
                info.get("description"),
                record.get("matcher-name"),
            )
            if part
        )
        category = _category(cwe, tags, text)
        url = str(
            record.get("matched-at")
            or record.get("matched")
            or record.get("url")
            or record.get("host")
            or ""
        )
        method = _nuclei_method(record)
        protocol = str(record.get("type") or "").lower()
        is_http = protocol in {"http", "https"} or url.startswith(("http://", "https://"))
        path = _normalize_url_path(url)
        param = _clean(
            (record.get("metadata") or {}).get("parameter")
            if isinstance(record.get("metadata"), dict)
            else "",
            80,
        )
        status = _status_code(record.get("status-code") or record.get("status_code"))
        extracted = record.get("extracted-results")
        if isinstance(extracted, list):
            extracted = [_clean(item, 120) for item in extracted[:5]]
        else:
            extracted = []
        observation: RuntimeObservation | None = None
        if is_http and url:
            observation = RuntimeObservation(
                source="nuclei",
                method=method,
                url=_clean(url, 300),
                path=path,
                param=param,
                status_code=status,
                evidence=", ".join(str(item) for item in extracted),
            )
            observations.append(observation)
        finding_id = stable_id("dast", "nuclei", template, path, param, name)
        if finding_id in findings:
            continue
        detail = f"Nuclei observed {name} at {method or 'ANY'} {path}".strip()
        if template:
            detail += f" (template {template})"
        if status is not None:
            detail += f" [HTTP {status}]"
        metadata: dict[str, Any] = {
            "tool": "nuclei",
            "template_id": template,
            "matcher": _clean(record.get("matcher-name"), 120),
            "tags": tags,
            "type": protocol,
            "url": observation.url if observation is not None else _clean(url, 300),
            "method": method,
            "param": param,
            "status_code": status,
            "extracted_results": extracted,
            "description": _plain(info.get("description"), 300),
        }
        if observation is not None:
            metadata["runtime"] = observation.to_dict()
        metadata = {
            key: value
            for key, value in metadata.items()
            if value not in ("", None, [])
        }
        remediation = _plain(info.get("remediation"), 300)
        findings[finding_id] = Finding(
            id=finding_id,
            category=category,
            severity=severity,
            title=f"Nuclei: {name}",
            message=detail,
            cwe=_cwe_label(cwe),
            confidence=0.98 if severity in {"critical", "high"} else 0.95,
            evidence=[Loc(report_name, 1)],
            recommendation=(
                remediation
                or "Reproduce the runtime finding, fix the affected endpoint, and add a regression test."
            ),
            source="nuclei",
            external_id=template or None,
            metadata=metadata,
        )
    return list(findings.values()), observations


def load_dast_reports(
    root: Path,
    rel_files: list[str],
    zap_report: Path | None = None,
    nuclei_report: Path | None = None,
) -> tuple[list[Finding], list[RuntimeObservation], list[dict[str, Any]]]:
    """Load configured DAST reports and return findings, observations, provenance."""
    del root, rel_files  # Signature mirrors external_reports for a uniform pipeline.
    findings: list[Finding] = []
    observations: list[RuntimeObservation] = []
    summaries: list[dict[str, Any]] = []
    if zap_report is not None:
        zap_findings, zap_observations = _zap_findings(
            _read_json(zap_report), zap_report.name
        )
        findings.extend(zap_findings)
        observations.extend(zap_observations)
        summaries.append(
            {
                "source": "zap",
                "file": zap_report.name,
                "findings": len(zap_findings),
                "requests": len(zap_observations),
            }
        )
    if nuclei_report is not None:
        nuclei_findings, nuclei_observations = _nuclei_findings(
            _nuclei_records(_read_text(nuclei_report)), nuclei_report.name
        )
        findings.extend(nuclei_findings)
        observations.extend(nuclei_observations)
        summaries.append(
            {
                "source": "nuclei",
                "file": nuclei_report.name,
                "findings": len(nuclei_findings),
                "requests": len(nuclei_observations),
            }
        )
    findings.sort(
        key=lambda item: (
            item.source,
            item.category,
            item.evidence[0].path if item.evidence else "",
            item.id,
        )
    )
    summaries.sort(key=lambda item: (item["source"], item["file"]))
    return findings, _ordered_observations(observations), summaries


def _endpoint_routes(graph: Graph) -> list[_EndpointRoute]:
    routes: list[_EndpointRoute] = []
    for node in graph.sorted_nodes():
        if node.kind != "endpoint" and node.attrs.get("role") != "endpoint":
            continue
        raw_routes = node.attrs.get("routes")
        if not isinstance(raw_routes, list):
            continue
        for route in raw_routes:
            if not isinstance(route, dict):
                continue
            method = str(route.get("method") or "ANY").upper().strip() or "ANY"
            path = _normalize_url_path(route.get("path") or "/")
            routes.append(
                _EndpointRoute(
                    node_id=node.id,
                    method=method,
                    path=path,
                    literals=_literal_count(path),
                    segments=_segments(path),
                )
            )
    routes.sort(key=lambda item: (-item.literals, item.node_id, item.method, item.path))
    return routes


def _best_match(
    routes: list[_EndpointRoute], observation: RuntimeObservation
) -> _EndpointRoute | None:
    for route in routes:
        if not _method_matches(route.method, observation.method):
            continue
        if _path_matches(route.path, observation.path):
            return route
    return None


def _merge_observation(
    aggregate: dict[str, Any], observation: RuntimeObservation
) -> None:
    aggregate["requests"] = int(aggregate.get("requests", 0)) + 1
    for key, value in (
        ("sources", observation.source),
        ("methods", observation.method),
        ("params", observation.param),
        ("paths", observation.path),
    ):
        if not value:
            continue
        bucket = aggregate.setdefault(key, [])
        if value not in bucket:
            bucket.append(value)
            bucket.sort()


def _entry_observation(graph: Graph, finding: Finding) -> tuple[int, list[str]]:
    """Return (runtime requests, sources) for a finding's entry point."""
    node_ids: list[str] = []
    if finding.node_id:
        node_ids.append(finding.node_id)
    flow = finding.metadata.get("flow")
    if isinstance(flow, list) and flow:
        first = flow[0]
        if isinstance(first, dict):
            node_id = first.get("node") or first.get("node_id")
            if isinstance(node_id, str) and node_id and node_id not in node_ids:
                node_ids.append(node_id)
    requests = 0
    sources: list[str] = []
    for node_id in node_ids:
        observed = graph.nodes.get(node_id)
        if observed is None:
            continue
        runtime = observed.attrs.get("runtime_observed")
        if not isinstance(runtime, dict):
            continue
        requests += int(runtime.get("requests") or 0)
        for source in runtime.get("sources") or []:
            source_text = str(source)
            if source_text and source_text not in sources:
                sources.append(source_text)
    return requests, sorted(sources)


def correlate_runtime(
    graph: Graph, observations: list[RuntimeObservation]
) -> dict[str, Any]:
    """Match observations to endpoint nodes and annotate the graph deterministically."""
    routes = _endpoint_routes(graph)
    per_node: dict[str, dict[str, Any]] = {}
    runtime_only: set[str] = set()
    matched_requests = 0
    endpoint_node_ids = {route.node_id for route in routes}
    observation_index = {observation.id: observation for observation in observations}
    for observation in observations:
        route = _best_match(routes, observation)
        if route is None:
            runtime_only.add(observation.label)
            continue
        observation.matched_node = route.node_id
        observation.matched_route = f"{route.method} {route.path}".strip()
        matched_requests += 1
        aggregate = per_node.setdefault(route.node_id, {})
        _merge_observation(aggregate, observation)
    for node_id in sorted(per_node):
        node = graph.nodes.get(node_id)
        if node is None:
            continue
        aggregate = per_node[node_id]
        node.attrs["runtime_observed"] = {
            "requests": int(aggregate.get("requests", 0)),
            "sources": sorted(aggregate.get("sources", [])),
            "methods": sorted(aggregate.get("methods", [])),
            "params": sorted(aggregate.get("params", []))[:MAX_RUNTIME_PARAMS],
            "paths": sorted(aggregate.get("paths", []))[:MAX_RUNTIME_PARAMS],
        }
    confirmed = 0
    static_observed = 0
    for finding in graph.findings:
        runtime = finding.metadata.get("runtime")
        if isinstance(runtime, dict):
            runtime_id = runtime.get("id")
            matched_observation = observation_index.get(str(runtime_id or ""))
            if matched_observation is not None:
                enriched = matched_observation.to_dict()
                finding.metadata["runtime"] = enriched
                if matched_observation.matched_node:
                    finding.node_id = matched_observation.matched_node
                    node = graph.nodes.get(matched_observation.matched_node)
                    if node is not None and node.path and node.line:
                        finding.evidence = [Loc(node.path, node.line)]
        if finding.source in DAST_SOURCES:
            finding.metadata["runtime_confirmed"] = True
            confirmed += 1
            requests, sources = _entry_observation(graph, finding)
            if requests:
                finding.metadata["runtime_requests"] = requests
                finding.metadata["runtime_sources"] = sources
            if finding.node_id in per_node:
                finding.metadata["runtime_matched"] = True
            continue
        requests, sources = _entry_observation(graph, finding)
        if finding.node_id in per_node or requests:
            finding.metadata["runtime_entrypoint_observed"] = True
            finding.metadata["runtime_requests"] = requests
            finding.metadata["runtime_sources"] = sources
            static_observed += 1
    observed_endpoint_ids = sorted(per_node)
    unobserved: list[str] = []
    for route in routes:
        if route.node_id in per_node:
            continue
        node = graph.nodes.get(route.node_id)
        qualname = node.qualname if node is not None else route.node_id
        label = f"{route.method} {route.path} ({qualname})"
        if label not in unobserved:
            unobserved.append(label)
    unobserved.sort()
    return {
        "sources": sorted({observation.source for observation in observations}),
        "requests": len(observations),
        "matched_requests": matched_requests,
        "unmatched_requests": len(observations) - matched_requests,
        "runtime_findings": confirmed,
        "confirmed_findings": confirmed,
        "runtime_entrypoints_observed": static_observed,
        "endpoints_total": len(endpoint_node_ids),
        "endpoints_observed": len(observed_endpoint_ids),
        "observed_endpoints": observed_endpoint_ids,
        "runtime_only_count": len(runtime_only),
        "runtime_only_endpoints": sorted(runtime_only)[:MAX_RUNTIME_ENDPOINTS],
        "unobserved_count": len(unobserved),
        "unobserved_endpoints": unobserved[:MAX_RUNTIME_ENDPOINTS],
    }
