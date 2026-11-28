"""User-level AI-skill installer for secdiagram Studio.

The installer follows the spirit of Unsloth Studio's user-level architecture:
everything lives under a per-user home, a private virtual environment is
created for the runtime, and portable launchers plus an agent skill manifest
are generated.  It deliberately stays standard-library only so the core
``secdiagram`` package keeps its zero-dependency guarantee.

Only the CLI performs writes.  The HTTP server exposes read-only status.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import __version__

MANIFEST_SCHEMA_VERSION = 1
SKILL_SCHEMA_VERSION = 1
SKILL_NAME = "secdiagram-diagramming"
MANIFEST_FILENAME = "manifest.json"
PROJECT_ROOT_FILENAME = "project-root.txt"
README_FILENAME = "README.md"
VENV_DIRNAME = "venv"
SKILL_DIRNAME = Path("skills") / SKILL_NAME
LAUNCHER_DIRNAME = "bin"
_TIMEOUT = 300


class StudioError(RuntimeError):
    """Base class for installer failures."""


class StudioInstallError(StudioError):
    """Raised when the user-level install cannot proceed safely."""


@dataclass(slots=True)
class InstallOptions:
    home: Path | None = None
    project_root: Path | None = None
    create_venv: bool = True
    force: bool = False
    profile: str = "default"


@dataclass(slots=True)
class InstallResult:
    home: Path
    project_root: Path
    manifest: dict[str, Any]
    created: bool
    venv_created: bool
    files: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "home": str(self.home),
            "project_root": str(self.project_root),
            "created": self.created,
            "venv_created": self.venv_created,
            "files": sorted(self.files),
            "manifest": self.manifest,
        }


def default_home() -> Path:
    """Return the user-level Studio home.

    ``SECDIAGRAM_STUDIO_HOME`` takes precedence so tests, containers, and
    air-gapped operators can pin the location explicitly.
    """
    env = os.environ.get("SECDIAGRAM_STUDIO_HOME", "").strip()
    if env:
        return Path(env).expanduser()
    return Path.home() / ".secdiagram" / "studio"


def resolve_project_root() -> Path:
    """Best-effort absolute path to the secdiagram source checkout."""
    package_parent = Path(__file__).resolve().parent.parent
    if (package_parent / "pyproject.toml").is_file():
        return package_parent
    return Path.cwd().resolve()


def skill_manifest(profile: str = "default") -> dict[str, Any]:
    """Return the portable agent-skill manifest (deterministic, no timestamps)."""
    return {
        "schema_version": SKILL_SCHEMA_VERSION,
        "name": SKILL_NAME,
        "display_name": "secdiagram Architecture & Security Diagramming",
        "version": __version__,
        "profile": profile,
        "description": (
            "Generate deterministic architecture, relationship, and security diagrams "
            "with evidence-grounded AI reviews for local or hosted models."
        ),
        "homepage": "https://github.com/vichhaiyserey/secdiagram",
        "license": "MIT",
        "entrypoint": {
            "command": "secdiagram",
            "module": "secdiagram_core.cli",
            "studio": "secdiagram studio serve",
        },
        "triggers": [
            "architecture diagram",
            "system diagram",
            "c4 diagram",
            "dependency graph",
            "threat model",
            "attack path",
            "security architecture review",
            "sdlc handoff",
        ],
        "phases": ["discover", "model", "secure", "review", "handoff"],
        "tools": [
            {
                "name": "analyze_repository",
                "description": "Statically analyze a repository and emit deterministic artifacts.",
                "command": [
                    "secdiagram",
                    "--dir",
                    "{repo}",
                    "--offline",
                    "--format",
                    "json,md,mermaid,html,sarif",
                ],
            },
            {
                "name": "audit_repository",
                "description": "Evaluate MITRE ATT&CK technique coverage against policy.yaml.",
                "command": ["secdiagram", "audit", "{repo}", "--policy", "policy.yaml"],
            },
            {
                "name": "compare_threat_models",
                "description": "Compare two saved threat models offline.",
                "command": [
                    "secdiagram",
                    "threat-diff",
                    "{before}",
                    "{after}",
                    "--format",
                    "json",
                ],
            },
            {
                "name": "open_studio",
                "description": "Serve the agentic Studio UI on loopback.",
                "command": ["secdiagram", "studio", "serve", "--dir", "{repo}"],
            },
        ],
        "guardrails": [
            "Core runtime is Python standard library only.",
            "Analyzed repositories are parsed statically; no code is executed.",
            "Generated artifacts are byte-for-byte deterministic.",
            "Offline mode is the default; network rendering and LLMs are opt-in.",
        ],
        "artifacts": [
            "graph.json",
            "diagram.mmd",
            "diagram-highlevel.mmd",
            "ARCHITECTURE.md",
            "THREAT_MODEL.md",
            "security.sarif",
            "vex.json",
            "report.html",
            "HANDOFF.md",
            "handoff.json",
        ],
    }


def render_skill_markdown(profile: str = "default") -> str:
    """Render an agent-readable SKILL.md with YAML front matter."""
    manifest = skill_manifest(profile)
    return (
        "---\n"
        f"name: {manifest['name']}\n"
        "description: >-\n"
        "  Generate deterministic, evidence-backed architecture and security diagrams\n"
        "  for polyglot repositories, then hand off SDLC phases to the next agent.\n"
        f"version: {manifest['version']}\n"
        f"license: {manifest['license']}\n"
        "---\n"
        "\n"
        f"# {manifest['display_name']}\n"
        "\n"
        f"{manifest['description']}\n"
        "\n"
        "## Use this skill when\n"
        "\n"
        "- The user asks for an architecture, system, C4, dependency, or attack-path diagram.\n"
        "- The user asks for a security architecture review, threat model, or SDLC handoff.\n"
        "- Another agent needs a deterministic map of a repository before editing it.\n"
        "\n"
        "## Safe workflow\n"
        "\n"
        "1. **Discover** the repository without executing it.\n"
        "2. **Model** the graph and high-level C4 diagram.\n"
        "3. **Secure** with SAST, IaC, risk scoring, threat model, and policy gates.\n"
        "4. **Review** with an evidence-grounded local or hosted LLM (optional).\n"
        "5. **Handoff** by attaching `HANDOFF.md` and `handoff.json` to the change.\n"
        "\n"
        "```bash\n"
        "# Full deterministic analysis (offline):\n"
        "secdiagram --dir . --offline --format json,md,mermaid,html,sarif\n"
        "\n"
        "# Interactive Studio on loopback:\n"
        "secdiagram studio serve --dir . --user analyst --password 'change-me'\n"
        "\n"
        "# Policy-gated audit (exits non-zero on violations):\n"
        "secdiagram audit . --policy policy.yaml\n"
        "```\n"
        "\n"
        "## Guardrails\n"
        "\n"
        "- Never execute code from the analyzed repository; use AST and lexical parsing only.\n"
        "- Keep artifacts deterministic: sort keys and pin IDs before writing.\n"
        "- Prefer `--offline`; enable LLM or remote rendering only on explicit request.\n"
        "- Cite `path:line` evidence for every architectural or security claim.\n"
        "- Do not place API keys in commands, diagrams, or generated artifacts.\n"
        "\n"
        "## Phase evidence\n"
        "\n"
        "Record concrete evidence on each Studio phase (for example `graph.json`, "
        "`security.sarif`, or `THREAT_MODEL.md`). The handoff gate refuses to close "
        "until every phase is complete.\n"
    )


def render_readme(home: Path, project_root: Path) -> str:
    return (
        "# secdiagram Studio\n"
        "\n"
        "User-level installation of the secdiagram agentic diagram workspace.\n"
        "\n"
        f"- Home: `{home.as_posix()}`\n"
        f"- Source: `{project_root.as_posix()}`\n"
        f"- Version: `{__version__}`\n"
        "\n"
        "## Launch\n"
        "\n"
        "```bash\n"
        "secdiagram studio serve --dir /path/to/repository --user analyst --password 'change-me'\n"
        "```\n"
        "\n"
        "The generated launchers in `bin/` default to the repository recorded at "
        "install time (`project-root.txt`). Override it with `--dir` if needed. "
        "The server requires Basic Auth by default; you can also set "
        "`SECDIAGRAM_AUTH_USER` and `SECDIAGRAM_AUTH_PASS`, and use "
        "`--insecure-no-auth` only for loopback development. The Studio is served "
        "on `http://127.0.0.1:8080/studio` and inherits the hardened rate-limit "
        "and request-size defaults.\n"
        "\n"
        "## Agent skill\n"
        "\n"
        f"The portable skill lives in `{SKILL_DIRNAME.as_posix()}/`. Point an agent "
        "at `SKILL.md` and `skill.json` to let it invoke deterministic secdiagram "
        "commands with the documented guardrails.\n"
        "\n"
        "## Uninstall\n"
        "\n"
        "```bash\n"
        "secdiagram studio uninstall\n"
        "```\n"
        "\n"
        "This directory is managed by secdiagram. Existing files outside the "
        "managed manifest are never deleted.\n"
    )


def launcher_scripts(*, source_checkout: bool = True, package_root: Path | None = None) -> dict[str, str]:
    """Return portable launcher scripts keyed by relative path.

    Source installs add the checkout to ``PYTHONPATH``.  Package installs point
    ``PYTHONPATH`` at the installed package parent instead, so pip-installed
    copies do not depend on a source tree.  Both default ``--dir`` to the
    repository recorded at install time.
    """
    runtime = (package_root or Path(__file__).resolve().parent.parent).as_posix()
    posix_pythonpath = (
        'PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"'
        if source_checkout
        else f'PYTHONPATH="{runtime}${{PYTHONPATH:+:$PYTHONPATH}}"'
    )
    cmd_pythonpath = "%ROOT%;%PYTHONPATH%" if source_checkout else f"{runtime};%PYTHONPATH%"
    ps_pythonpath = '"$root;$env:PYTHONPATH"' if source_checkout else f'"{runtime};$env:PYTHONPATH"'
    posix = (
        "#!/bin/sh\n"
        "set -eu\n"
        'HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)\n'
        'ROOT=$(cat "$HERE/../project-root.txt")\n'
        'PY="$HERE/../venv/bin/python"\n'
        '[ -x "$PY" ] || PY="${PYTHON:-python3}"\n'
        f'{posix_pythonpath} exec "$PY" -m secdiagram_core.cli studio serve --dir "$ROOT" "$@"\n'
    )
    windows_cmd = (
        "@echo off\r\n"
        "setlocal\r\n"
        'set "HERE=%~dp0"\r\n'
        'set /p ROOT=<"%HERE%..\\project-root.txt"\r\n'
        'set "PY=%HERE%..\\venv\\Scripts\\python.exe"\r\n'
        'if not exist "%PY%" set "PY=python"\r\n'
        f'set "PYTHONPATH={cmd_pythonpath}"\r\n'
        '"%PY%" -m secdiagram_core.cli studio serve --dir "%ROOT%" %*\r\n'
    )
    windows_ps1 = (
        "$ErrorActionPreference = 'Stop'\n"
        "$here = Split-Path -Parent $MyInvocation.MyCommand.Path\n"
        "$root = Get-Content -LiteralPath (Join-Path $here '..\\project-root.txt')\n"
        "$py = Join-Path $here '..\\venv\\Scripts\\python.exe'\n"
        "if (-not (Test-Path -LiteralPath $py)) { $py = 'python' }\n"
        f"$env:PYTHONPATH = {ps_pythonpath}\n"
        "& $py -m secdiagram_core.cli studio serve --dir \"$root\" @args\n"
        "exit $LASTEXITCODE\n"
    )
    return {
        f"{LAUNCHER_DIRNAME}/secdiagram-studio": posix,
        f"{LAUNCHER_DIRNAME}/secdiagram-studio.cmd": windows_cmd,
        f"{LAUNCHER_DIRNAME}/secdiagram-studio.ps1": windows_ps1,
    }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_write_text(path: Path, content: str, *, executable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(content)
    if executable and os.name != "nt":
        tmp.chmod(0o755)
    os.replace(tmp, path)


def _safe_within(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except (OSError, ValueError):
        return False


def _read_manifest(home: Path) -> dict[str, Any] | None:
    path = home / MANIFEST_FILENAME
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _create_venv(venv_dir: Path, python: str | None = None) -> None:
    if venv_dir.exists():
        return
    executable = python or sys.executable
    try:
        completed = subprocess.run(
            [executable, "-m", "venv", "--without-pip", str(venv_dir)],
            check=False,
            capture_output=True,
            text=True,
            timeout=_TIMEOUT,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise StudioInstallError(f"could not create Studio virtual environment: {exc}") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "").strip().splitlines()
        reason = detail[-1] if detail else f"exit code {completed.returncode}"
        raise StudioInstallError(f"could not create Studio virtual environment: {reason}")


def install(options: InstallOptions | None = None) -> InstallResult:
    """Install the Studio and agent skill under a user-level home."""
    opts = options or InstallOptions()
    home = (opts.home or default_home()).expanduser().resolve()
    project_root = (opts.project_root or resolve_project_root()).expanduser().resolve()
    profile = (opts.profile or "default").strip() or "default"

    if home.exists() and not home.is_dir():
        raise StudioInstallError(f"Studio home exists and is not a directory: {home}")

    existing = _read_manifest(home)
    created = existing is None
    if existing and existing.get("version") != __version__ and not opts.force:
        raise StudioInstallError(
            f"Studio home is at version {existing.get('version')!r}, current is {__version__!r}; "
            "re-run with --force to update"
        )
    if not project_root.is_dir():
        raise StudioInstallError(f"project root does not exist or is not a directory: {project_root}")
    source_checkout = (project_root / "secdiagram_core").is_dir() and (project_root / "pyproject.toml").is_file()
    package_root = Path(__file__).resolve().parent.parent

    home.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        try:
            home.chmod(0o700)
        except OSError:
            pass

    venv_created = False
    venv_dir = home / VENV_DIRNAME
    if opts.create_venv and not venv_dir.exists():
        _create_venv(venv_dir)
        venv_created = True

    files: list[str] = []
    _atomic_write_text(home / PROJECT_ROOT_FILENAME, project_root.as_posix() + "\n")
    files.append(PROJECT_ROOT_FILENAME)
    _atomic_write_text(home / README_FILENAME, render_readme(home, project_root))
    files.append(README_FILENAME)

    skill_dir = home / SKILL_DIRNAME
    _atomic_write_text(skill_dir / "SKILL.md", render_skill_markdown(profile))
    files.append((SKILL_DIRNAME / "SKILL.md").as_posix())
    _atomic_write_text(
        skill_dir / "skill.json",
        json.dumps(skill_manifest(profile), indent=2, sort_keys=True) + "\n",
    )
    files.append((SKILL_DIRNAME / "skill.json").as_posix())

    launchers = launcher_scripts(
        source_checkout=source_checkout,
        package_root=None if source_checkout else package_root,
    )
    for rel_path, content in sorted(launchers.items()):
        _atomic_write_text(home / rel_path, content, executable=rel_path.endswith("secdiagram-studio"))
        files.append(rel_path)

    file_records: list[dict[str, Any]] = []
    for rel_path in sorted(files):
        target = home / rel_path
        if target.is_file():
            file_records.append(
                {
                    "path": rel_path,
                    "bytes": target.stat().st_size,
                    "sha256": _sha256_file(target),
                }
            )

    manifest: dict[str, Any] = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "product": "secdiagram-studio",
        "version": __version__,
        "profile": profile,
        "home": home.as_posix(),
        "project_root": project_root.as_posix(),
        "source_checkout": source_checkout,
        "venv": VENV_DIRNAME if venv_dir.exists() else None,
        "skill": {
            "name": SKILL_NAME,
            "version": __version__,
            "path": (SKILL_DIRNAME / "SKILL.md").as_posix(),
        },
        "launcher": {
            "posix": f"{LAUNCHER_DIRNAME}/secdiagram-studio",
            "windows": f"{LAUNCHER_DIRNAME}/secdiagram-studio.cmd",
            "powershell": f"{LAUNCHER_DIRNAME}/secdiagram-studio.ps1",
        },
        "files": file_records,
    }
    _atomic_write_text(home / MANIFEST_FILENAME, json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    return InstallResult(
        home=home,
        project_root=project_root,
        manifest=manifest,
        created=created,
        venv_created=venv_created,
        files=sorted(files),
    )


def status(home: Path | None = None) -> dict[str, Any]:
    """Return read-only installer status for the CLI and HTTP API."""
    target = (home or default_home()).expanduser().resolve()
    manifest = _read_manifest(target)
    if manifest is None:
        return {
            "installed": False,
            "home": target.as_posix(),
            "version": __version__,
            "current_version": __version__,
            "healthy": False,
            "stale": False,
            "skill_installed": False,
            "venv_present": False,
            "source_checkout": False,
        }

    skill_rel = f"{SKILL_DIRNAME.as_posix()}/SKILL.md"
    launcher_rel = f"{LAUNCHER_DIRNAME}/secdiagram-studio"
    project_root = str(manifest.get("project_root", ""))
    venv_rel = manifest.get("venv")
    return {
        "installed": True,
        "home": target.as_posix(),
        "version": str(manifest.get("version", "")),
        "current_version": __version__,
        "profile": str(manifest.get("profile", "default")),
        "project_root": project_root,
        "project_root_present": bool(project_root) and Path(project_root).is_dir(),
        "source_checkout": bool(manifest.get("source_checkout", True)),
        "skill_installed": (target / skill_rel).is_file(),
        "skill_path": (target / skill_rel).as_posix(),
        "skill_manifest": (target / SKILL_DIRNAME / "skill.json").as_posix(),
        "launcher_present": (target / launcher_rel).is_file(),
        "venv_present": bool(venv_rel) and (target / str(venv_rel)).is_dir(),
        "healthy": (target / skill_rel).is_file()
        and (target / launcher_rel).is_file()
        and bool(project_root)
        and Path(project_root).is_dir(),
        "stale": str(manifest.get("version", "")) != __version__,
    }


def manifest(home: Path | None = None) -> dict[str, Any] | None:
    """Return the persisted install manifest, if any."""
    return _read_manifest((home or default_home()).expanduser().resolve())


def uninstall(home: Path | None = None, *, keep_venv: bool = False) -> dict[str, Any]:
    """Remove managed files, refusing to touch anything outside the Studio home."""
    target = (home or default_home()).expanduser().resolve()
    manifest_data = _read_manifest(target)
    removed: list[str] = []
    skipped: list[str] = []

    candidates: list[str] = []
    if manifest_data:
        for record in manifest_data.get("files", []):
            if isinstance(record, dict) and isinstance(record.get("path"), str):
                candidates.append(record["path"])
    if not candidates:
        candidates = [
            PROJECT_ROOT_FILENAME,
            README_FILENAME,
            (SKILL_DIRNAME / "SKILL.md").as_posix(),
            (SKILL_DIRNAME / "skill.json").as_posix(),
            *sorted(launcher_scripts()),
        ]

    for rel_path in sorted(set(candidates)):
        candidate = target / rel_path
        if not _safe_within(candidate, target) or candidate.resolve() == target.resolve():
            skipped.append(rel_path)
            continue
        try:
            candidate.unlink()
            removed.append(rel_path)
        except FileNotFoundError:
            continue
        except OSError:
            skipped.append(rel_path)

    venv_dir = target / VENV_DIRNAME
    if not keep_venv and venv_dir.is_dir() and _safe_within(venv_dir, target):
        try:
            shutil.rmtree(venv_dir)
            removed.append(VENV_DIRNAME)
        except OSError:
            skipped.append(VENV_DIRNAME)

    manifest_path = target / MANIFEST_FILENAME
    if manifest_path.is_file() and _safe_within(manifest_path, target):
        try:
            manifest_path.unlink()
            removed.append(MANIFEST_FILENAME)
        except OSError:
            skipped.append(MANIFEST_FILENAME)

    for rel_dir in (LAUNCHER_DIRNAME, SKILL_DIRNAME.as_posix(), SKILL_DIRNAME.parent.as_posix()):
        directory = target / rel_dir
        try:
            directory.rmdir()
            removed.append(rel_dir + "/")
        except (FileNotFoundError, OSError):
            pass

    return {
        "home": target.as_posix(),
        "removed": sorted(removed),
        "skipped": sorted(skipped),
        "kept_venv": keep_venv,
    }


__all__ = [
    "InstallOptions",
    "InstallResult",
    "StudioError",
    "StudioInstallError",
    "default_home",
    "install",
    "launcher_scripts",
    "manifest",
    "render_skill_markdown",
    "resolve_project_root",
    "skill_manifest",
    "status",
    "uninstall",
]
