"""Command-line interface for secdiagram."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import sys
from datetime import date
from pathlib import Path
from typing import Any

from . import __version__
from . import studio as studio_install
from .analyzer import AnalysisConfig, run_analysis
from .baseline import apply_baseline, ignore_baseline, load_suppressions, write_baseline
from .diagram_model import build_diagram_model
from .diagram_quality import (
    SEVERITY_ORDER,
    analyze_diagram_quality,
    format_quality_report,
    has_errors,
)
from .discover import discover
from .health import health_summary
from .high_level import (
    HighLevelArchitecture,
    build_high_level_architecture,
    render_mermaid_highlevel,
)
from .llm import NarrativeError, generate_narrative
from .model import SEVERITY_RANK, Graph
from .policy import POLICY_MODES, apply_policy
from .protocols import get_registered_exporters
from .redaction import redact_secrets
from .render_html import render_html
from .render_image import ImageRenderError, render_image
from .render_json import write_json
from .render_markdown import render_markdown
from .render_mermaid import build_mermaid_model, render_mermaid
from .render_sarif import render_sarif
from .render_security import render_security_html, render_security_markdown
from .render_vex import render_vex
from .risk import score_findings
from .security_report import build_security_report
from .taint_flows import render_taint_mermaid
from .threat_model import (
    DEFAULT_POLICY_YAML,
    Threat,
    attack_status_label,
    build_threat_model,
    evaluate_attack,
    load_policy,
    parse_policy,
    policy_violations,
    render_attack_summary,
    render_threat_model,
    summarize_attack,
    summarize_threat_model,
)
from .threat_review import (
    build_threat_snapshot,
    diff_threat_snapshots,
    load_threat_snapshot,
    render_snapshot,
    render_threat_diff,
    threat_analysis_context,
)

FORMATS = {"json", "md", "mermaid", "sarif", "png", "svg", "pdf", "image", "html", "vex"}


def _parse_formats(value: str) -> list[str]:
    formats = []
    custom_exporters = get_registered_exporters()
    for item in value.split(","):
        item = item.strip().lower()
        if item == "markdown":
            item = "md"
        elif item in {"img", "picture"}:
            item = "image"
        elif item in {"web", "report"}:
            item = "html"
        if item and item not in FORMATS and item not in custom_exporters:
            raise argparse.ArgumentTypeError(f"unknown format: {item}")
        if item and item not in formats:
            formats.append(item)
    if not formats:
        raise argparse.ArgumentTypeError("at least one format is required")
    return formats


def _security_reproduce_command(args: argparse.Namespace) -> str:
    def quote(value: str) -> str:
        return f'"{value}"' if " " in value else value

    parts = [
        "secdiagram",
        "--dir",
        quote(args.dir),
        "--security-report",
        args.security_report,
    ]
    if args.sonarqube_report:
        parts.extend(["--sonarqube-report", quote(args.sonarqube_report)])
    if args.xray_report:
        parts.extend(["--xray-report", quote(args.xray_report)])
    for advisory in args.advisory_db:
        parts.extend(["--advisory-db", quote(advisory)])
    if args.baseline:
        parts.extend(["--baseline", quote(args.baseline)])
    if args.fail_on != "none":
        parts.extend(["--fail-on", args.fail_on])
    return " ".join(parts)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secdiagram",
        description="Build deterministic architecture, relationship, and security diagrams for a Python repository.",
        epilog=(
            "Compare saved threat models offline: secdiagram threat-diff BEFORE.json AFTER.json "
            "--format md|json [--out FILE]\n"
            "Install the user-level Studio and agent skill: secdiagram studio install\n"
            "Serve the agentic Studio: secdiagram studio serve --dir . --user analyst --password 'change-me'"
        ),
    )
    parser.add_argument("--dir", default=".", help="repository directory to analyze (default: .)")
    parser.add_argument("--dry-run", action="store_true", help="validate inputs and discover files without parsing, cache writes, rendering or network requests")
    parser.add_argument("--verbose", action="store_true", help="show detailed diagnostics and skipped paths on stderr")
    parser.add_argument("--output", choices=("text", "json"), default="text", help="console summary format; JSON stdout is suitable for CI (default: text)")
    parser.add_argument("--max-files", type=int, default=10000, help="maximum selected files; 0 disables (default: 10000)")
    parser.add_argument("--max-file-bytes", type=int, default=2097152, help="per-file input byte limit; 0 disables (default: 2097152)")
    parser.add_argument("--max-total-bytes", type=int, default=67108864, help="total selected input bytes; 0 disables (default: 67108864); bounds input, not process RSS")
    parser.add_argument(
        "--workspace",
        default=None,
        metavar="DIR",
        help=(
            "analyze multiple repos under DIR as a unified product workspace; "
            "each immediate subdirectory is treated as a separate microservice/repo"
        ),
    )
    parser.add_argument(
        "--role",
        action="append",
        default=[],
        metavar="REPO=ROLE",
        help=(
            "manually assign a role to a repo in the workspace (repeatable); "
            "roles: backend, frontend, gateway, worker, data-layer, infrastructure, library "
            "(e.g. --role user-service=backend --role web-app=frontend)"
        ),
    )
    parser.add_argument(
        "--out",
        default=None,
        help="output directory (default: <dir>/.secdiagram)",
    )
    parser.add_argument(
        "--format",
        default="json,md,mermaid",
        type=_parse_formats,
        help="comma-separated outputs: json, md, mermaid, sarif, html, png, svg, pdf (default: json,md,mermaid)",
    )
    parser.add_argument("--include", action="append", default=[], metavar="GLOB", help="include path glob")
    parser.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="exclude path glob")
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=0.5,
        help="drop call/inheritance edges below this confidence (default: 0.5)",
    )
    parser.add_argument(
        "--min-finding-confidence",
        type=float,
        default=0.0,
        metavar="SCORE",
        help="drop security findings below this confidence (0.0-1.0; default: 0.0)",
    )
    parser.add_argument(
        "--max-nodes",
        type=int,
        default=2000,
        help="cap the graph node count; 0 disables the cap (default: 2000)",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=0,
        metavar="N",
        help="parallel indexer processes; 0 = auto, 1 = serial (default: 0)",
    )
    parser.add_argument(
        "--cache-dir",
        default=None,
        metavar="PATH",
        help="incremental index cache directory (default: <out>/cache)",
    )
    parser.add_argument(
        "--no-cache",
        dest="cache",
        action="store_false",
        default=True,
        help="disable the incremental index cache",
    )
    parser.add_argument(
        "--security",
        dest="security",
        action="store_true",
        default=True,
        help="enable the security and IaC overlay (default)",
    )
    parser.add_argument(
        "--no-security",
        dest="security",
        action="store_false",
        help="disable security findings and IaC analysis",
    )
    parser.add_argument(
        "--security-report",
        choices=("html", "md", "both"),
        default=None,
        help="write a standalone security review (security-report.html and/or SECURITY_REVIEW.md)",
    )
    parser.add_argument(
        "--sonarqube-report",
        default=None,
        metavar="PATH",
        help="import a SonarQube issues JSON export as security findings",
    )
    parser.add_argument(
        "--xray-report",
        default=None,
        metavar="PATH",
        help="import a JFrog Xray violations JSON export as dependency findings",
    )
    parser.add_argument(
        "--advisory-db",
        action="append",
        default=[],
        metavar="PATH",
        help="validate imported CVEs against a local CISA KEV/NVD/OSV JSON file or directory (repeatable)",
    )
    parser.add_argument(
        "--link-base",
        default=None,
        help="base URL for Mermaid node clicks, e.g. https://github.com/org/repo/blob/main",
    )
    parser.add_argument(
        "--llm",
        action="store_true",
        help="write NARRATIVE.md using an optional OpenAI-compatible endpoint",
    )
    parser.add_argument(
        "--ollama",
        nargs="?",
        const="qwen2.5-coder",
        default=None,
        metavar="MODEL",
        help="generate NARRATIVE.md using local/docker Ollama (default model: qwen2.5-coder)",
    )
    parser.add_argument(
        "--llm-model",
        default=None,
        help="LLM model name (e.g. qwen2.5-coder, qwen2.5:7b, gpt-4o-mini)",
    )
    parser.add_argument(
        "--llm-base-url",
        default=None,
        help="LLM API base URL (default: http://localhost:11434 for Ollama native API, https://api.openai.com/v1 for OpenAI)",
    )
    parser.add_argument(
        "--llm-api-key",
        default=None,
        help="LLM API key (optional for Ollama)",
    )
    parser.add_argument(
        "--llm-template",
        choices=["comprehensive", "threat-model", "remediation", "compliance"],
        default="comprehensive",
        help="security review prompt template: comprehensive (default), threat-model, remediation, compliance",
    )
    parser.add_argument(
        "--llm-timeout",
        type=float,
        default=None,
        help="LLM API request timeout in seconds (default: 300s for Ollama, 120s for cloud endpoints)",
    )
    parser.add_argument(
        "--llm-max-tokens",
        type=int,
        default=None,
        help="maximum completion tokens generated by the LLM (default: 1500 for Ollama)",
    )
    parser.add_argument(
        "--llm-context-chars",
        type=int,
        default=None,
        help="maximum graph evidence characters sent to the LLM (default: auto-sized to the model context)",
    )
    parser.add_argument(
        "--image",
        nargs="?",
        const="png",
        default=None,
        metavar="FORMAT",
        choices=["png", "svg", "pdf"],
        help="generate diagram image from diagram.mmd (formats: png, svg, pdf; default: png)",
    )
    parser.add_argument(
        "--to-image",
        dest="image",
        nargs="?",
        const="png",
        metavar="FORMAT",
        choices=["png", "svg", "pdf"],
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--image-format",
        choices=["png", "svg", "pdf"],
        default="png",
        help="default diagram image format when generating images (default: png)",
    )
    parser.add_argument(
        "--image-provider",
        choices=["auto", "local", "kroki", "mermaid.ink"],
        default="local",
        help="renderer: local (mmdc, default), auto (permits HTTP fallback), kroki, mermaid.ink",
    )
    parser.add_argument(
        "--image-endpoint",
        default=None,
        help="custom HTTP rendering endpoint URL for kroki or mermaid.ink",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="strictly offline mode: forbids external HTTP diagram rendering and requires local tools",
    )
    parser.add_argument(
        "--mermaid-js",
        default=None,
        metavar="PATH",
        help="inline a local mermaid.min.js bundle into the HTML report for fully offline diagram rendering",
    )
    parser.add_argument(
        "--diagram-detail",
        choices=["architecture", "full", "high-level", "overview"],
        default="architecture",
        help="diagram detail level: architecture (clean, human-friendly), full (every symbol), high-level (subsystem C4 overview) (default: architecture)",
    )
    parser.add_argument(
        "--high-level",
        action="store_true",
        help="generate high-level system overview diagram (subsystems, tiers & connections) as primary diagram",
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help=(
            "check the canonical diagram model for quality issues (duplicates, orphans, cycles, "
            "dangling or duplicated relationships, tier inversions, rank skips) before rendering; "
            "exits 1 and skips rendering when error-severity issues are found"
        ),
    )
    parser.add_argument(
        "--max-diagram-nodes",
        type=int,
        default=150,
        help="maximum components displayed in Mermaid architecture diagrams; 0 for unlimited (default: 150)",
    )
    parser.add_argument(
        "--diagram-direction",
        choices=["LR", "TB"],
        default="LR",
        help="diagram layout direction: LR (horizontal), TB (vertical) (default: LR)",
    )
    parser.add_argument(
        "--diagram-theme",
        choices=["modern", "classic"],
        default="modern",
        help="diagram visual theme: modern, classic (default: modern)",
    )
    parser.add_argument(
        "--fail-on",
        type=str.lower,
        choices=["critical", "high", "medium", "low", "info", "block", "none"],
        default="none",
        help="exit with code 2 when a finding at or above this severity exists; 'block' fails on policy block decisions (implies --policy strict)",
    )
    parser.add_argument(
        "--policy",
        type=str.lower,
        choices=list(POLICY_MODES),
        default=None,
        help=(
            "enforcement policy mode: shadow (record decisions, never fail CI), "
            "report-only (record and surface in reports), strict (block decisions fail CI; exit 2)"
        ),
    )
    parser.add_argument(
        "--baseline",
        default=None,
        metavar="FILE",
        help="suppress findings listed in this baseline file so CI fails only on new findings",
    )
    parser.add_argument(
        "--create-baseline",
        action="store_true",
        help="write security.baseline.json from the current scan (path from --baseline, default <out>/security.baseline.json)",
    )
    parser.add_argument(
        "--serve",
        action="store_true",
        help="launch the interactive platform HTTP server and REST API daemon",
    )
    parser.add_argument(
        "--server-port",
        type=int,
        default=None,
        metavar="PORT",
        help="port for the platform HTTP server (default: 8080)",
    )
    parser.add_argument(
        "--server-host",
        default=None,
        metavar="HOST",
        help="host binding for the platform server (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--server-user",
        default=None,
        metavar="USER",
        help="username for platform HTTP Basic Authentication",
    )
    parser.add_argument(
        "--server-pass",
        default=None,
        metavar="PASS",
        help="password for platform HTTP Basic Authentication",
    )
    parser.add_argument(
        "--server-read-only",
        action="store_true",
        default=False,
        help="disallow re-scans via the platform REST API",
    )
    parser.add_argument(
        "--server-insecure-no-auth",
        action="store_true",
        default=False,
        help="allow unauthenticated access in loopback-only development mode (never for remote binds)",
    )
    parser.add_argument(
        "--server-max-request-bytes",
        type=int,
        default=None,
        metavar="BYTES",
        help="maximum accepted HTTP request body size (default: 1048576)",
    )
    parser.add_argument(
        "--server-rate-limit",
        type=int,
        default=None,
        metavar="N",
        help="maximum requests per client per minute (default: 240, 0 disables)",
    )
    parser.add_argument(
        "--server-max-concurrent-scans",
        type=int,
        default=None,
        metavar="N",
        help="maximum concurrent API-triggered scans (default: 1)",
    )
    parser.add_argument(
        "--server-scan-root",
        action="append",
        default=None,
        metavar="DIR",
        help="allowlisted scan directory (repeatable; default: served repository root)",
    )
    parser.add_argument(
        "--server-audit-log",
        default=None,
        metavar="FILE",
        help="append structured audit events to FILE (default: stderr)",
    )
    parser.add_argument(
        "--config",
        default=None,
        metavar="FILE",
        help="path to secdiagram configuration JSON file",
    )
    parser.add_argument("--quiet", action="store_true", help="suppress the summary")
    parser.add_argument("--version", action="version", version=f"secdiagram {__version__}")
    return parser


def _normalize_cli_path(path_str: str) -> Path:
    p = Path(path_str).expanduser()
    if p.exists() or os.name == "nt":
        return p
    # Detect MSYS2 / Git Bash automatic POSIX-to-Windows path conversion inside Linux environments:
    # Git Bash automatically converts "/repo" -> "C:/Program Files/Git/repo" or "C:\Program Files\Git\repo"
    import re

    m = re.match(
        r"^[a-zA-Z]:[/\\](?:Program Files[/\\]Git[/\\]|msys\d*[/\\]|cygwin\d*[/\\])?(.*)$",
        path_str,
        re.IGNORECASE,
    )
    if m:
        subpath = m.group(1).replace("\\", "/").strip("/")
        if subpath:
            candidate_abs = Path("/" + subpath)
            if candidate_abs.exists() or candidate_abs.parent.exists():
                return candidate_abs
            candidate_rel = Path(subpath)
            if candidate_rel.exists() or candidate_rel.parent.exists():
                return candidate_rel

        # Last resort for converted paths only (e.g. another Git install root):
        # strip leading components, preferring a target that already exists.
        parts = Path(path_str.replace("\\", "/")).parts
        candidates = [Path("/" + "/".join(parts[i:])) for i in range(1, len(parts))]
        for cand in candidates:
            if cand.exists():
                return cand
        for cand in candidates:
            if cand.parent.exists() and cand.parent != Path("/"):
                return cand
    # Any other path is taken literally; the caller creates missing parents.
    # (Rewriting it here once turned `--out build/reports/x` into `/x`.)
    return p


def server_main(argv: list[str] | None = None) -> int:
    """Dedicated entrypoint for secdiagram-server."""
    parser = argparse.ArgumentParser(
        prog="secdiagram-server",
        description="Run the secdiagram platform HTTP server and REST API daemon.",
    )
    parser.add_argument("--dir", default=".", help="repository directory to serve (default: .)")
    parser.add_argument("--host", default=None, help="host binding (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=None, help="port (default: 8080)")
    parser.add_argument("--user", default=None, help="HTTP Basic Auth username")
    parser.add_argument("--password", default=None, help="HTTP Basic Auth password")
    parser.add_argument("--read-only", action="store_true", default=False, help="disallow API-triggered scans")
    parser.add_argument(
        "--insecure-no-auth",
        action="store_true",
        default=False,
        help="allow unauthenticated access in loopback-only development mode",
    )
    parser.add_argument(
        "--max-request-bytes",
        type=int,
        default=None,
        metavar="BYTES",
        help="maximum accepted HTTP request body size (default: 1048576)",
    )
    parser.add_argument(
        "--rate-limit",
        type=int,
        default=None,
        metavar="N",
        help="maximum requests per client per minute (default: 240, 0 disables)",
    )
    parser.add_argument(
        "--max-concurrent-scans",
        type=int,
        default=None,
        metavar="N",
        help="maximum concurrent API-triggered scans (default: 1)",
    )
    parser.add_argument(
        "--scan-root",
        action="append",
        default=None,
        metavar="DIR",
        help="allowlisted scan directory (repeatable; default: served repository root)",
    )
    parser.add_argument(
        "--audit-log",
        default=None,
        metavar="FILE",
        help="append structured audit events to FILE (default: stderr)",
    )
    parser.add_argument("--config", default=None, help="configuration file path")
    args = parser.parse_args(argv)
    from .server import serve
    root = _normalize_cli_path(args.dir)
    cfg_path = _normalize_cli_path(args.config) if args.config else None
    return serve(
        root=root,
        host=args.host,
        port=args.port,
        auth_username=args.user,
        auth_password=args.password,
        read_only=args.read_only,
        config_path=cfg_path,
        insecure_no_auth=args.insecure_no_auth,
        max_request_bytes=args.max_request_bytes,
        rate_limit_per_minute=args.rate_limit,
        max_concurrent_scans=args.max_concurrent_scans,
        scan_roots=args.scan_root,
        audit_log=args.audit_log,
    )


def studio_main(argv: list[str] | None = None) -> int:
    """``secdiagram studio``: user-level installer, status, and Studio server."""
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "serve":
        return server_main(argv[1:])

    parser = argparse.ArgumentParser(
        prog="secdiagram studio",
        description=(
            "Install the user-level AI skill and serve the agentic Studio UI. "
            "The Studio is served by the hardened stdlib platform server."
        ),
    )
    sub = parser.add_subparsers(dest="command")

    install_parser = sub.add_parser("install", help="create the Studio home, venv, launchers, and agent skill")
    install_parser.add_argument("--home", type=Path, default=None, help="Studio home (default: ~/.secdiagram/studio)")
    install_parser.add_argument("--project-root", type=Path, default=None, help="secdiagram source checkout")
    install_parser.add_argument("--no-venv", action="store_true", help="skip virtual environment creation")
    install_parser.add_argument("--force", action="store_true", help="update or repair an existing install")
    install_parser.add_argument("--profile", default="default", help="skill profile name (default: default)")
    install_parser.add_argument("--json", action="store_true", help="print machine-readable JSON")

    status_parser = sub.add_parser("status", help="show installer status")
    status_parser.add_argument("--home", type=Path, default=None, help="Studio home (default: ~/.secdiagram/studio)")
    status_parser.add_argument("--json", action="store_true", help="print machine-readable JSON")

    uninstall_parser = sub.add_parser("uninstall", help="remove managed Studio files")
    uninstall_parser.add_argument("--home", type=Path, default=None, help="Studio home (default: ~/.secdiagram/studio)")
    uninstall_parser.add_argument("--keep-venv", action="store_true", help="keep the private virtual environment")
    uninstall_parser.add_argument("--json", action="store_true", help="print machine-readable JSON")

    serve_parser = sub.add_parser(
        "serve",
        help="serve the Studio and REST API (forwards to secdiagram serve)",
        add_help=False,
    )
    serve_parser.add_argument("--dir", default=".", help="repository directory to serve (default: .)")

    args, unknown = parser.parse_known_args(argv)
    if args.command is None:
        parser.print_help()
        print("\nExamples:\n  secdiagram studio install\n  secdiagram studio serve --dir .", file=sys.stderr)
        return 0
    if args.command == "serve":
        return server_main(["--dir", args.dir, *unknown])
    if args.command == "install":
        try:
            result = studio_install.install(
                studio_install.InstallOptions(
                    home=args.home,
                    project_root=args.project_root,
                    create_venv=not args.no_venv,
                    force=args.force,
                    profile=args.profile,
                )
            )
        except studio_install.StudioError as exc:
            print(f"secdiagram studio: {exc}", file=sys.stderr)
            return 1
        if args.json:
            print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
        else:
            print(f"secdiagram Studio installed at {result.home}")
            print(f"  project root: {result.project_root}")
            print(f"  virtualenv: {'created' if result.venv_created else 'present'}")
            print(f"  skill: {(result.home / studio_install.SKILL_DIRNAME / 'SKILL.md').as_posix()}")
            print(f"  launcher: {(result.home / 'bin' / 'secdiagram-studio').as_posix()}")
            print("  next: secdiagram studio serve --dir .")
        return 0
    if args.command == "status":
        payload = studio_install.status(args.home)
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        elif not payload.get("installed"):
            print(f"secdiagram Studio is not installed (home: {payload.get('home')})")
            print("  install: secdiagram studio install")
        else:
            print(f"secdiagram Studio home: {payload.get('home')}")
            print(f"  version: {payload.get('version')} (current {payload.get('current_version')})")
            print(f"  healthy: {'yes' if payload.get('healthy') else 'no'}")
            print(f"  skill: {'present' if payload.get('skill_installed') else 'missing'}")
            print(f"  virtualenv: {'present' if payload.get('venv_present') else 'missing'}")
        return 0
    if args.command == "uninstall":
        try:
            uninstall_result = studio_install.uninstall(args.home, keep_venv=args.keep_venv)
        except studio_install.StudioError as exc:
            print(f"secdiagram studio: {exc}", file=sys.stderr)
            return 1
        if args.json:
            print(json.dumps(uninstall_result, indent=2, sort_keys=True))
        else:
            print(
                f"Removed {len(uninstall_result['removed'])} managed path(s) "
                f"from {uninstall_result['home']}"
            )
            if uninstall_result["skipped"]:
                print(
                    f"  skipped {len(uninstall_result['skipped'])} unmanaged path(s)",
                    file=sys.stderr,
                )
        return 0
    parser.print_help()
    return 0


def audit_main(argv: list[str] | None = None) -> int:
    """``secdiagram audit <dir>``: ATT&CK evaluation gated by policy.yaml.

    Fails the pipeline with exit code 1 when unmitigated architectural flaws
    violate the policy thresholds, so CI/CD can block the build.
    """
    parser = argparse.ArgumentParser(
        prog="secdiagram audit",
        description="Evaluate the parsed architecture against MITRE ATT&CK techniques and fail on policy violations.",
    )
    parser.add_argument("dir", nargs="?", default=".", help="repository directory to audit (default: .)")
    parser.add_argument(
        "--policy",
        default=None,
        metavar="FILE",
        help="audit policy file (default: <dir>/policy.yaml when present, else built-in defaults)",
    )
    parser.add_argument(
        "--json",
        dest="json_out",
        default=None,
        metavar="PATH",
        help="write the machine-readable audit result to PATH",
    )
    parser.add_argument("--quiet", action="store_true", help="print only violations or PASS")
    args = parser.parse_args(argv)
    root = _normalize_cli_path(args.dir)

    try:
        if args.policy:
            policy = load_policy(_normalize_cli_path(args.policy))
            policy_source = args.policy
        else:
            default_path = root / "policy.yaml"
            if default_path.exists():
                policy = load_policy(default_path)
                policy_source = str(default_path)
            else:
                policy = parse_policy(DEFAULT_POLICY_YAML)
                policy_source = "built-in defaults"
    except (ValueError, OSError) as exc:
        print(f"secdiagram: invalid audit policy ({exc})", file=sys.stderr)
        return 1

    try:
        result = run_analysis(AnalysisConfig(root=root, security=True))
    except (FileNotFoundError, NotADirectoryError) as exc:
        print(f"secdiagram: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # pragma: no cover - defensive top-level guard
        print(f"secdiagram: analysis failed: {exc}", file=sys.stderr)
        return 1

    graph = result.graph
    score_findings(graph)
    evals = evaluate_attack(graph)
    violating = policy_violations(evals, policy)
    summarize_attack(graph, evals)

    if args.json_out:
        payload = {
            "repository": result.repo.name,
            "policy": policy.to_dict(),
            "policy_source": policy_source,
            "pass": not violating,
            "techniques": [evaluation.to_dict() for evaluation in evals],
            "violations": [evaluation.to_dict() for evaluation in violating],
        }
        path = _normalize_cli_path(args.json_out)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
        except OSError as exc:
            print(f"secdiagram: could not write audit json: {exc}", file=sys.stderr)
            return 1

    if not args.quiet:
        print(render_attack_summary(evals, policy, violating), end="")

    if violating:
        print(
            f"secdiagram: audit FAILED against {policy_source}: "
            + ", ".join(
                f"{e.technique} {e.name} ({attack_status_label(e.status)})" for e in violating
            ),
            file=sys.stderr,
        )
        return 1
    if not args.quiet:
        print(f"secdiagram: audit PASS against {policy_source}", file=sys.stderr)
    return 0


def _parse_role_args(role_args: list[str]) -> dict[str, str]:
    """Parse ``--role REPO=ROLE`` arguments into a dict."""
    manual_roles: dict[str, str] = {}
    for item in role_args:
        if "=" not in item:
            continue
        name, _, role = item.partition("=")
        name = name.strip()
        role = role.strip().lower()
        if name and role:
            manual_roles[name] = role
    return manual_roles


def _write_threat_outputs(graph: Graph, threats: list[Threat], args: argparse.Namespace, out: Path) -> list[Path]:
    if not args.security or not {"json", "md"}.intersection(args.format):
        return []
    paths = [out / "threat-model.json"]
    paths[0].write_text(render_snapshot(build_threat_snapshot(graph, threats)), encoding="utf-8", newline="\n")
    if "md" in args.format:
        paths.append(out / "THREAT_MODEL.md")
        paths[-1].write_text(render_threat_model(graph, threats), encoding="utf-8", newline="\n")
    return paths


def threat_diff_main(argv: list[str], summary: dict[str, Any] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="secdiagram threat-diff", description="Compare two saved threat-model.json snapshots without executing or checking out source.")
    parser.add_argument("before", help="older threat-model.json snapshot")
    parser.add_argument("after", help="newer threat-model.json snapshot")
    parser.add_argument("--format", choices=("md", "json"), default="md")
    parser.add_argument("--out", help="write diff to this file; otherwise print to stdout")
    parser.add_argument("--output", choices=("text", "json"), default="text", help="use the standard CI JSON console envelope")
    args = parser.parse_args(argv)
    before, after = _normalize_cli_path(args.before), _normalize_cli_path(args.after)
    output = _normalize_cli_path(args.out) if args.out else None
    if output and output.resolve() in {before.resolve(), after.resolve()}:
        parser.error("--out must differ from both input snapshots")
    try:
        diff = diff_threat_snapshots(load_threat_snapshot(before), load_threat_snapshot(after))
        if output and output.exists() and (output.samefile(before) or output.samefile(after)):
            raise ValueError("--out aliases an input snapshot; choose a separate output file")
        if summary is not None:
            summary["diff"] = diff
        text = render_snapshot(diff) if args.format == "json" else render_threat_diff(diff)
        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(text, encoding="utf-8", newline="\n")
        elif args.output != "json":
            print(text, end="")
    except (OSError, ValueError, UnicodeError, RecursionError) as exc:
        message = redact_secrets(f"cannot compare threat snapshots: {exc}; provide readable threat-model.json files from the same schema")
        if summary is not None:
            summary["error"] = message
        print(f"secdiagram: {message}", file=sys.stderr)
        return 1
    return 0


def _validate_diagrams(graph: Graph, hla: HighLevelArchitecture, args: argparse.Namespace) -> bool:
    """Validate the primary projection and accompanying high-level diagram before writes."""
    models = [build_diagram_model(graph, hla)]
    if args.diagram_detail not in {"high-level", "overview"}:
        models.append(build_mermaid_model(graph, args.diagram_detail, args.max_diagram_nodes))
    issues = sorted(
        {issue for model in models for issue in analyze_diagram_quality(model)},
        key=lambda issue: (SEVERITY_ORDER.get(issue.severity, 9), issue.code, issue.subjects, issue.message),
    )
    for line in format_quality_report(issues):
        print(line)
    if has_errors(issues):
        print("secdiagram: diagram validation failed; rendering skipped", file=sys.stderr)
        return False
    return True


def _run_workspace_mode(args: argparse.Namespace, out: Path, cache_dir: Path | None) -> int:
    """Handle the --workspace flag: analyze multiple repos as a unified product."""
    from .analyzer import run_workspace_analysis
    from .high_level import build_high_level_architecture, render_mermaid_highlevel
    from .workspace import VALID_ROLES

    workspace_root = _normalize_cli_path(args.workspace)
    manual_roles = _parse_role_args(args.role)

    # Validate role names
    for repo_name, role in manual_roles.items():
        if role not in VALID_ROLES:
            print(
                f"secdiagram: invalid role '{role}' for repo '{repo_name}'; "
                f"valid roles: {', '.join(sorted(VALID_ROLES))}",
                file=sys.stderr,
            )
            return 1

    try:
        ws_result = run_workspace_analysis(
            workspace_root,
            manual_roles=manual_roles,
            include=args.include,
            exclude=args.exclude,
            min_confidence=args.min_confidence,
            max_nodes=args.max_nodes,
            security=args.security,
            jobs=args.jobs,
            cache_dir=cache_dir,
        )
    except (FileNotFoundError, NotADirectoryError) as exc:
        print(f"secdiagram: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # pragma: no cover - defensive top-level guard
        print(f"secdiagram: workspace analysis failed: {exc}", file=sys.stderr)
        return 1

    graph = ws_result.merged_graph
    # Score and build threat model on merged graph
    score_findings(graph)
    graph.meta["workspace_analysis"] = {
        "repositories": {
            name: {"analysis": threat_analysis_context(result.graph), "commit": result.repo.commit}
            for name, result in sorted(ws_result.per_repo.items())
        },
        "unavailable_repositories": sorted(role.name for role in ws_result.workspace.repos if role.name not in ws_result.per_repo),
    }
    threats = build_threat_model(graph)
    summarize_threat_model(graph, threats)
    hla = build_high_level_architecture(workspace_root, graph)

    # Enrich HLA with workspace role metadata
    for repo_role in ws_result.workspace.repos:
        for sub in hla.subsystems:
            if sub.path and repo_role.name in sub.path:
                sub.metadata["workspace_role"] = repo_role.role
                sub.metadata["workspace_repo"] = repo_role.name

    if args.validate and not _validate_diagrams(graph, hla, args):
        return 1

    out.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    ws_json_path = out / "workspace.json"
    ws_json_path.write_text(
        json.dumps(ws_result.workspace.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    written.append(ws_json_path)

    highlevel_mermaid = render_mermaid_highlevel(
        hla,
        direction=args.diagram_direction if args.diagram_direction == "LR" else "TB",
        theme=args.diagram_theme,
    )

    mermaid_text: str | None = None

    try:
        written.extend(_write_threat_outputs(graph, threats, args, out))
        if "json" in args.format:
            path = out / "graph.json"
            write_json(graph, path)
            written.append(path)
        if "md" in args.format:
            path = out / "ARCHITECTURE.md"
            meta = dict(graph.meta)
            meta["name"] = ws_result.workspace.name
            path.write_text(
                render_markdown(graph, meta, high_level_mermaid=highlevel_mermaid),
                encoding="utf-8",
                newline="\n",
            )
            written.append(path)
        if "mermaid" in args.format:
            if args.diagram_detail in {"high-level", "overview"}:
                mermaid_text = highlevel_mermaid
            else:
                mermaid_text = render_mermaid(
                    graph,
                    link_base=args.link_base,
                    detail=args.diagram_detail,
                    direction=args.diagram_direction,
                    theme=args.diagram_theme,
                    max_diagram_nodes=args.max_diagram_nodes,
                )
            path = out / "diagram.mmd"
            path.write_text(mermaid_text, encoding="utf-8", newline="\n")
            written.append(path)

            hl_path = out / "diagram-highlevel.mmd"
            hl_path.write_text(highlevel_mermaid, encoding="utf-8", newline="\n")
            written.append(hl_path)
        if "sarif" in args.format:
            path = out / "security.sarif"
            path.write_text(render_sarif(graph), encoding="utf-8", newline="\n")
            written.append(path)
    except (OSError, ImageRenderError) as exc:
        print(f"secdiagram: could not write output: {exc}", file=sys.stderr)
        return 1

    if not args.quiet:
        # Print workspace summary
        total_nodes = len(graph.nodes)
        total_edges = len(graph.edges)
        total_findings = len(graph.findings)
        repo_count = len(ws_result.workspace.repos)

        print(f"secdiagram workspace: {ws_result.workspace.name}")
        print(f"  {repo_count} repo(s), {total_nodes} nodes, {total_edges} edges, {total_findings} findings")
        for repo_role in sorted(ws_result.workspace.repos, key=lambda r: r.name):
            confidence_pct = f"{repo_role.confidence * 100:.0f}%"
            manual_tag = " (manual)" if repo_role.manual else ""
            per_repo = ws_result.per_repo.get(repo_role.name)
            file_count = len(per_repo.repo.rel_files) if per_repo else 0
            print(f"  • {repo_role.name}: {repo_role.role} ({confidence_pct}{manual_tag}) [{file_count} files]")

        cross_edges = ws_result.workspace.inter_repo_edges
        if cross_edges:
            print(f"  {len(cross_edges)} cross-repo relationship(s):")
            for edge in cross_edges:
                print(f"    {edge.src_repo} --[{edge.kind}]--> {edge.dst_repo}: {edge.label}")

        for path in written:
            print(f"  wrote {path}")

    return 0


def _scan_main(argv: list[str] | None = None, summary: dict[str, Any] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if argv and argv[0] == "serve":
        return server_main(argv[1:])
    if argv and argv[0] == "audit":
        return audit_main(argv[1:])
    if argv and argv[0] == "threat-diff":
        return threat_diff_main(argv[1:], summary)
    if argv and argv[0] == "studio":
        return studio_main(argv[1:])

    parser = build_parser()
    args = parser.parse_args(argv)
    args.offline = args.offline or os.environ.get("SECDIAGRAM_OFFLINE", "").strip().lower() in {"1", "true", "yes"}
    summary = summary if summary is not None else {}
    summary.update({"schema_version": 1, "dry_run": args.dry_run, "stages": []})

    def progress(stage: str) -> None:
        summary["stages"].append(stage)
        if not args.quiet:
            print(f"secdiagram: {stage}", file=sys.stderr)

    def fail(message: str) -> int:
        summary["error"] = redact_secrets(message)
        print(f"secdiagram: {summary['error']}", file=sys.stderr)
        return 1

    if args.config and not args.serve:
        try:
            configured = json.loads(_normalize_cli_path(args.config).read_text(encoding="utf-8"))
            allowed = {"include": list, "exclude": list, "jobs": int, "max_nodes": int,
                       "max_files": int, "max_file_bytes": int, "max_total_bytes": int, "security": bool}
            if not isinstance(configured, dict):
                raise ValueError("expected a JSON object")
            for key, value in configured.items():
                if key not in allowed or type(value) is not allowed[key]:
                    raise ValueError(f"unknown key or invalid type: {key}")
                if isinstance(value, list) and not all(isinstance(item, str) for item in value):
                    raise ValueError(f"{key} must contain path glob strings")
                flag = "--no-security" if key == "security" else "--" + key.replace("_", "-")
                explicit = any(item.split("=", 1)[0] in {flag, "--security" if key == "security" else flag} for item in argv)
                if not explicit:
                    setattr(args, key, value)
        except (OSError, ValueError) as exc:
            return fail(f"cannot load --config {args.config}: {exc}; provide a readable scan configuration JSON file")
    if args.jobs < 0:
        parser.error("--jobs must be zero (auto) or a positive integer")
    for option in ("max_files", "max_file_bytes", "max_total_bytes", "max_nodes"):
        if getattr(args, option) < 0:
            return fail(f"--{option.replace('_', '-')} must be zero or positive")
    root = _normalize_cli_path(args.dir)

    if args.serve:
        if args.dry_run:
            return fail("--dry-run applies to --dir analysis; omit --serve to preview a scan")
        from .server import serve
        cfg_path = _normalize_cli_path(args.config) if args.config else None
        return serve(
            root=root,
            host=args.server_host,
            port=args.server_port,
            auth_username=args.server_user,
            auth_password=args.server_pass,
            read_only=args.server_read_only,
            config_path=cfg_path,
            insecure_no_auth=args.server_insecure_no_auth,
            max_request_bytes=args.server_max_request_bytes,
            rate_limit_per_minute=args.server_rate_limit,
            max_concurrent_scans=args.server_max_concurrent_scans,
            scan_roots=args.server_scan_root,
            audit_log=args.server_audit_log,
        )

    out = _normalize_cli_path(args.out) if args.out else root / ".secdiagram"
    cache_dir = None
    if args.cache:
        cache_dir = _normalize_cli_path(args.cache_dir) if args.cache_dir else out / "cache"

    # ── Workspace mode: multi-repo analysis ───────────────────────────
    if args.high_level:
        args.diagram_detail = "high-level"
    if args.workspace:
        if args.dry_run or args.output == "json" or args.verbose or any(
            item.split("=", 1)[0] in {"--max-files", "--max-file-bytes", "--max-total-bytes", "--config"} for item in argv
        ):
            return fail("these scan controls currently require --dir; scan each workspace project separately")
        return _run_workspace_mode(args, out, cache_dir)

    if args.offline and (args.llm or args.ollama):
        return fail("--offline disables narrative HTTP requests; omit --llm/--ollama for a fully offline scan")
    for label, value in (("--sonarqube-report", args.sonarqube_report), ("--xray-report", args.xray_report), ("--mermaid-js", args.mermaid_js)):
        if value and not _normalize_cli_path(value).is_file():
            return fail(f"{label} file does not exist or is unreadable: {value}; provide a readable local file or omit {label}")
    for value in args.advisory_db:
        if not _normalize_cli_path(value).exists():
            return fail(f"--advisory-db path does not exist: {value}; supply a local advisory export")
    if args.dry_run:
        progress("discovery")
        try:
            repo = discover(root, args.include, args.exclude, skip_paths=[out, cache_dir] if cache_dir else [out],
                            max_files=args.max_files, max_file_bytes=args.max_file_bytes, max_total_bytes=args.max_total_bytes)
        except OSError as exc:
            return fail(f"{exc}; check --dir and read permissions")
        summary["plan"] = {"files": repo.rel_files, "skipped_paths": sorted(repo.skipped), "formats": args.format,
                           "stages": ["discovery", "parsing", "mapping", "threat analysis", "rendering", "report generation"],
                           "out": out.as_posix(), "cache": cache_dir.as_posix() if cache_dir else None}
        if not args.quiet:
            print(f"secdiagram: dry run: {len(repo.rel_files)} selected files, {len(repo.skipped)} skipped paths; no files written")
            if args.verbose:
                for selected_path in repo.rel_files + sorted(repo.skipped):
                    print(f"  {selected_path}", file=sys.stderr)
        return 0

    try:
        result = run_analysis(
            AnalysisConfig(
                root=root,
                include=args.include,
                exclude=args.exclude,
                min_confidence=args.min_confidence,
                max_nodes=args.max_nodes,
                security=args.security,
                jobs=args.jobs,
                cache_dir=cache_dir,
                skip_paths=[out],
                progress=progress,
                max_files=args.max_files,
                max_file_bytes=args.max_file_bytes,
                max_total_bytes=args.max_total_bytes,
                sonarqube_report=(
                    _normalize_cli_path(args.sonarqube_report)
                    if args.sonarqube_report
                    else None
                ),
                xray_report=(
                    _normalize_cli_path(args.xray_report) if args.xray_report else None
                ),
                advisory_dbs=[
                    _normalize_cli_path(path) for path in args.advisory_db
                ],
            )
        )
    except (FileNotFoundError, NotADirectoryError) as exc:
        return fail(f"{exc}; check --dir and local input paths")
    except Exception as exc:  # pragma: no cover - defensive top-level guard
        return fail(f"analysis failed: {exc}; check input permissions, syntax and scan configuration")

    graph = result.graph
    summary["health"] = health_summary(result)
    graph.meta["health"] = summary["health"]
    summary["cache"] = result.cache_stats
    diagnostics = graph.meta.get("diagnostics", [])
    for item in diagnostics if args.verbose else diagnostics[:20]:
        print(f"secdiagram: {item['path']}: {item['message']}. {item['hint']}", file=sys.stderr)
    if not args.verbose and len(diagnostics) > 20:
        print(f"secdiagram: {len(diagnostics) - 20} more diagnostics; use --verbose or --output json for details", file=sys.stderr)
    if args.verbose:
        for skipped_path in sorted(result.repo.skipped):
            print(f"secdiagram: skipped {skipped_path}", file=sys.stderr)
    if args.min_finding_confidence > 0:
        graph.findings = [
            finding
            for finding in graph.findings
            if finding.confidence >= args.min_finding_confidence
        ]
    graph.meta["finding_confidence_floor"] = args.min_finding_confidence
    if args.validate:
        validation_hla = build_high_level_architecture(root, graph)
        if not _validate_diagrams(graph, validation_hla, args):
            return 1
    try:
        out.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return fail(f"cannot create output directory: {exc}; use --out with a writable directory")
    written: list[Path] = []

    baseline_mode = args.create_baseline or args.baseline is not None
    baseline_path = (
        _normalize_cli_path(args.baseline)
        if args.baseline
        else out / "security.baseline.json"
    )
    baseline_label = args.baseline if args.baseline else baseline_path.name
    active_suppressions: dict[str, dict[str, str]] = {}
    expired_suppressions: dict[str, dict[str, str]] = {}
    if baseline_mode:
        if args.create_baseline:
            count = write_baseline(graph, baseline_path)
            apply_baseline(graph, {finding.id for finding in graph.findings}, baseline_label)
            print(f"secdiagram: created baseline with {count} finding(s): {baseline_path}", file=sys.stderr)
            written.append(baseline_path)
        else:
            try:
                active_s, expired_s, legacy_ids, schema_v = load_suppressions(baseline_path, date.today().isoformat())
            except FileNotFoundError:
                print(
                    f"secdiagram: baseline file not found: {baseline_path} "
                    f"(no findings suppressed; create one with --create-baseline)",
                    file=sys.stderr,
                )
                ignore_baseline(graph, baseline_label)
            except (ValueError, OSError, json.JSONDecodeError) as exc:
                print(
                    f"secdiagram: ignoring malformed baseline ({exc}); "
                    "regenerate it with --create-baseline",
                    file=sys.stderr,
                )
                ignore_baseline(graph, baseline_label)
            else:
                if legacy_ids:
                    known, new = apply_baseline(graph, legacy_ids, baseline_label)
                    print(
                        f"secdiagram: baseline {baseline_label} suppresses {known} known finding(s); "
                        f"{new} new finding(s) remain",
                        file=sys.stderr,
                    )
                else:
                    active_suppressions, expired_suppressions = active_s, expired_s
                    apply_baseline(graph, set(active_s) | set(expired_s), baseline_label)
                    print(
                        f"secdiagram: governed baseline {baseline_label} (schema {schema_v}): "
                        f"{len(active_s)} active suppression(s), {len(expired_s)} expired (reactivated)",
                        file=sys.stderr,
                    )

    # Re-rank after confidence filtering and baseline suppression.
    score_findings(graph)
    # Policy layer: enforcement decisions. Runs when --policy is given, when
    # --fail-on block is used (implies strict), or when governed suppressions
    # are in play. Without any of these, findings stay informational and all
    # outputs are byte-identical to pre-policy runs.
    policy_mode = args.policy or ("strict" if args.fail_on == "block" else None)
    policy_summary = None
    if policy_mode or active_suppressions or expired_suppressions:
        policy_summary = apply_policy(
            graph,
            mode=policy_mode or "shadow",
            active_suppressions=active_suppressions,
            expired_suppressions=expired_suppressions,
            dependency_usage=result.dependency_usage,
        )
    threats = build_threat_model(graph)
    summarize_threat_model(graph, threats)
    meta = dict(graph.meta)
    meta.update(
        {
            "name": result.repo.name,
            "commit": result.repo.commit,
            "branch": result.repo.branch,
            "dirty": result.repo.dirty,
            "analysis": graph.meta.get("analysis", {}),
            "finding_confidence_floor": args.min_finding_confidence,
        }
    )
    if "security_baseline" in graph.meta:
        meta["security_baseline"] = graph.meta["security_baseline"]

    progress("rendering")
    hla = build_high_level_architecture(root, graph)

    highlevel_mermaid = render_mermaid_highlevel(
        hla,
        direction=args.diagram_direction if args.diagram_direction == "LR" else "TB",
        theme=args.diagram_theme,
    )

    mermaid_text: str | None = None
    narrative_text: str | None = None

    progress("report generation")
    try:
        written.extend(_write_threat_outputs(graph, threats, args, out))
        if "json" in args.format:
            path = out / "graph.json"
            write_json(graph, path)
            written.append(path)
        if "md" in args.format:
            path = out / "ARCHITECTURE.md"
            path.write_text(
                render_markdown(graph, meta, high_level_mermaid=highlevel_mermaid),
                encoding="utf-8",
                newline="\n",
            )
            written.append(path)
        if "mermaid" in args.format:
            if args.diagram_detail in {"high-level", "overview"}:
                mermaid_text = highlevel_mermaid
            else:
                mermaid_text = render_mermaid(
                    graph,
                    link_base=args.link_base,
                    detail=args.diagram_detail,
                    direction=args.diagram_direction,
                    theme=args.diagram_theme,
                    max_diagram_nodes=args.max_diagram_nodes,
                )
            path = out / "diagram.mmd"
            path.write_text(mermaid_text, encoding="utf-8", newline="\n")
            written.append(path)

            hl_path = out / "diagram-highlevel.mmd"
            hl_path.write_text(highlevel_mermaid, encoding="utf-8", newline="\n")
            written.append(hl_path)

            taint_path = out / "diagram-taint.mmd"
            taint_path.write_text(render_taint_mermaid(graph), encoding="utf-8", newline="\n")
            written.append(taint_path)
        if "sarif" in args.format:
            path = out / "security.sarif"
            path.write_text(render_sarif(graph), encoding="utf-8", newline="\n")
            written.append(path)
        if "vex" in args.format:
            path = out / "vex.json"
            path.write_text(render_vex(result), encoding="utf-8", newline="\n")
            written.append(path)

        image_formats: list[str] = []
        if args.image:
            image_formats.append(args.image.lower())
        if "image" in args.format:
            fmt = (args.image or args.image_format or "png").lower()
            if fmt not in image_formats:
                image_formats.append(fmt)
        for fmt in ("png", "svg", "pdf"):
            if fmt in args.format and fmt not in image_formats:
                image_formats.append(fmt)

        if image_formats:
            if mermaid_text is None:
                if args.diagram_detail in {"high-level", "overview"}:
                    mermaid_text = highlevel_mermaid
                else:
                    mermaid_text = render_mermaid(
                        graph,
                        link_base=args.link_base,
                        detail=args.diagram_detail,
                        direction=args.diagram_direction,
                        theme=args.diagram_theme,
                        max_diagram_nodes=args.max_diagram_nodes,
                    )
            for fmt in image_formats:
                img_path = out / f"diagram.{fmt}"
                render_image(
                    mermaid_source=mermaid_text,
                    output_path=img_path,
                    image_format=fmt,
                    provider=args.image_provider,
                    endpoint=args.image_endpoint,
                    offline=args.offline,
                )
                written.append(img_path)

                hl_img_path = out / f"diagram-highlevel.{fmt}"
                render_image(
                    mermaid_source=highlevel_mermaid,
                    output_path=hl_img_path,
                    image_format=fmt,
                    provider=args.image_provider,
                    endpoint=args.image_endpoint,
                    offline=args.offline,
                )
                written.append(hl_img_path)

                if (graph.meta.get("taint_flows") or {}).get("count"):
                    taint_img_path = out / f"diagram-taint.{fmt}"
                    render_image(
                        mermaid_source=render_taint_mermaid(graph),
                        output_path=taint_img_path,
                        image_format=fmt,
                        provider=args.image_provider,
                        endpoint=args.image_endpoint,
                        offline=args.offline,
                    )
                    written.append(taint_img_path)

        if args.ollama:
            args.llm = True
            llm_provider = "ollama"
            llm_model = args.llm_model or args.ollama
        else:
            llm_provider = None
            llm_model = args.llm_model

        if args.llm:
            try:
                narrative_text = generate_narrative(
                    graph,
                    model=llm_model,
                    base_url=args.llm_base_url,
                    api_key=args.llm_api_key,
                    provider=llm_provider,
                    template=args.llm_template,
                    timeout=args.llm_timeout,
                    max_tokens=args.llm_max_tokens,
                    context_chars=args.llm_context_chars,
                )
            except NarrativeError as exc:
                return fail(str(exc))
            path = out / "NARRATIVE.md"
            path.write_text(narrative_text, encoding="utf-8", newline="\n")
            written.append(path)

        if args.security_report:
            report = build_security_report(
                graph,
                meta,
                fail_on=args.fail_on,
                reproduce=_security_reproduce_command(args),
                narrative=narrative_text,
                policy=graph.meta.get("policy"),
            )
            if args.security_report in {"md", "both"}:
                path = out / "SECURITY_REVIEW.md"
                path.write_text(
                    render_security_markdown(report),
                    encoding="utf-8",
                    newline="\n",
                )
                written.append(path)
            if args.security_report in {"html", "both"}:
                path = out / "security-report.html"
                path.write_text(
                    render_security_html(report),
                    encoding="utf-8",
                    newline="\n",
                )
                written.append(path)

        if "html" in args.format:
            mermaid_js_text: str | None = None
            if args.mermaid_js:
                bundle = _normalize_cli_path(args.mermaid_js)
                try:
                    mermaid_js_text = bundle.read_text(encoding="utf-8")
                except OSError as exc:
                    print(f"secdiagram: could not read mermaid bundle: {exc}", file=sys.stderr)
                    return 1
            if args.diagram_detail in {"high-level", "overview"}:
                report_detail = highlevel_mermaid
            else:
                if mermaid_text is None:
                    mermaid_text = render_mermaid(
                        graph,
                        link_base=args.link_base,
                        detail=args.diagram_detail,
                        direction=args.diagram_direction,
                        theme=args.diagram_theme,
                        max_diagram_nodes=args.max_diagram_nodes,
                    )
                report_detail = mermaid_text
            path = out / "report.html"
            path.write_text(
                render_html(
                    graph,
                    meta=meta,
                    hla=hla,
                    highlevel_mermaid=highlevel_mermaid,
                    detail_mermaid=report_detail,
                    narrative=narrative_text,
                    root=root,
                    mermaid_js=mermaid_js_text,
                    offline=args.offline,
                ),
                encoding="utf-8",
                newline="\n",
            )
            written.append(path)

        for exp_name, exporter in get_registered_exporters().items():
            if exp_name in args.format:
                try:
                    exp_result = exporter.export(graph, out)
                    if isinstance(exp_result, list):
                        written.extend(exp_result)
                    elif isinstance(exp_result, Path):
                        written.append(exp_result)
                except Exception as exc:  # plugin failure: report, keep other outputs, exit non-zero
                    plugin_errors = graph.meta.setdefault("plugin_errors", [])
                    plugin_errors.append(
                        {
                            "kind": "exporter",
                            "plugin": exp_name,
                            "error": f"{type(exc).__name__}: {redact_secrets(str(exc))[:300]}",
                        }
                    )
    except (OSError, ImageRenderError) as exc:
        return fail(f"could not write output: {exc}; check --out permissions; for offline images install local mmdc/Chromium or use --format mermaid")

    summary["written"] = sorted(path.as_posix() for path in written)
    if not args.quiet:
        health = summary["health"]
        print(f"secdiagram health: {health['files_parsed']} files parsed, {health['components_identified']} components, "
              f"{health['unresolved_references']} unresolved references, {len(health['skipped_paths'])} skipped paths")
        counts: dict[str, int] = {}
        for finding in graph.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        severity_text = ", ".join(f"{key}={counts[key]}" for key in ("critical", "high", "medium", "low", "info") if key in counts)
        baseline_info = ""
        if baseline_mode:
            info = graph.meta.get("security_baseline") or {}
            baseline_info = f", {info.get('known', 0)} known in baseline, {info.get('new', 0)} new"
        polyglot_bits = []
        if hla.languages:
            polyglot_bits.append(f"languages: {', '.join(sorted(hla.languages))}")
        if hla.frameworks:
            polyglot_bits.append(f"frameworks: {', '.join(sorted(hla.frameworks))}")
        polyglot_info = f" [{'; '.join(polyglot_bits)}]" if polyglot_bits else ""
        print(
            f"secdiagram: {result.python_files} Python files, {len(graph.nodes)} nodes, "
            f"{len(graph.edges)} edges, {len(graph.features)} features, {len(hla.subsystems)} subsystems, "
            f"{len(graph.findings)} findings"
            + (f" ({severity_text})" if severity_text else "")
            + (baseline_info if baseline_info else "")
            + polyglot_info
        )
        if result.cache_stats:
            parts = [
                f"{name} {stats['hits']} hit(s)/{stats['misses']} miss(es)"
                for name, stats in sorted(result.cache_stats.items())
            ]
            print("secdiagram: index cache " + ", ".join(parts), file=sys.stderr)
        if result.parse_errors:
            print(f"secdiagram: skipped {len(result.parse_errors)} file(s) with parse errors", file=sys.stderr)
        for path in written:
            print(f"  wrote {path}")

    plugin_failures = graph.meta.get("plugin_errors") or []
    for failure in plugin_failures:
        print(
            f"secdiagram: warning: {failure['kind']} plugin '{failure['plugin']}' failed: {failure['error']}",
            file=sys.stderr,
        )

    if policy_summary is not None:
        decision_bits = [f"{key}={value}" for key, value in sorted(policy_summary.decisions.items()) if value]
        print(
            f"secdiagram: policy {policy_summary.mode}: " + ", ".join(decision_bits or ["no findings"])
            + (f", {len(policy_summary.reactivated)} reactivated" if policy_summary.reactivated else ""),
            file=sys.stderr,
        )

    if args.fail_on == "block" or args.policy == "strict":
        if any(finding.enforcement == "block" and not finding.baseline for finding in graph.findings):
            return 2
    elif args.fail_on != "none":
        threshold = SEVERITY_RANK[args.fail_on]
        if any(
            SEVERITY_RANK.get(finding.severity, 0) >= threshold and not finding.baseline
            for finding in graph.findings
        ):
            return 2
    if plugin_failures:
        # Results are incomplete (a security provider may not have run), so a
        # clean exit would be a silent false negative in CI security gates.
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    """Keep JSON stdout a single versioned document, including failed scans."""
    argv = list(sys.argv[1:] if argv is None else argv)
    machine = "--output=json" in argv or any(
        value == "--output" and index + 1 < len(argv) and argv[index + 1] == "json"
        for index, value in enumerate(argv)
    )
    summary: dict[str, Any] = {"schema_version": 1}

    def run() -> int:
        try:
            return _scan_main(argv, summary)
        except SystemExit as exc:
            if not machine:
                raise
            code = int(exc.code or 0)
            if code:
                summary["error"] = "Invalid command arguments; see stderr and --help."
            return code
        except (OSError, ValueError, MemoryError, RecursionError) as exc:
            summary["error"] = redact_secrets(f"scan failed: {exc}; check local inputs and output permissions; reduce --max-total-bytes or use --jobs 1 for resource failures")
            print(f"secdiagram: {summary['error']}", file=sys.stderr)
            return 1

    if not machine:
        return run()
    with contextlib.redirect_stdout(sys.stderr):
        code = run()
    if code == 1 and "error" not in summary:
        summary["error"] = "Scan could not complete; see stderr diagnostics."
    summary.update({"exit_code": code, "status": "ok" if code == 0 else "failed"})
    print(json.dumps(summary, sort_keys=True))
    return code
