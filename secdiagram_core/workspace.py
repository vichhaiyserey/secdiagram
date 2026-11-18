"""Multi-repo workspace: discover, role-detect, and merge graphs from sibling repositories.

A *workspace* is a directory whose immediate children are separate repositories
(or a list of explicit paths).  Each repo is assigned a **role** that describes
its function inside the product:

    backend · frontend · gateway · worker · data-layer · infrastructure · library · unknown

Roles are detected heuristically from manifest files, directory conventions,
framework dependencies, and file composition.  An optional ``workspace.json``
config allows the user to override or pin roles manually.

The public entry-point is :func:`discover_workspace`, which returns a
:class:`Workspace` containing individually-analysed repos plus a merged
:class:`~secdiagram_core.model.Graph`.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .discover import RepoInfo, discover
from .model import Graph, Loc, Node, stable_id

# ── Role vocabulary ────────────────────────────────────────────────────
VALID_ROLES = frozenset({
    "backend",
    "frontend",
    "gateway",
    "worker",
    "data-layer",
    "infrastructure",
    "library",
    "unknown",
})


@dataclass(slots=True)
class RepoRole:
    """A single repo inside the workspace, its detected/assigned role, and evidence."""

    path: Path
    name: str
    role: str  # one of VALID_ROLES
    confidence: float = 1.0
    evidence: list[str] = field(default_factory=list)
    manual: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "name": self.name,
            "role": self.role,
            "confidence": round(float(self.confidence), 2),
            "evidence": sorted(self.evidence),
            "manual": self.manual,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RepoRole:
        return cls(
            path=Path(str(data["path"])),
            name=str(data.get("name", "")),
            role=str(data.get("role", "unknown")),
            confidence=float(data.get("confidence", 1.0)),
            evidence=list(data.get("evidence", [])),
            manual=bool(data.get("manual", False)),
        )


@dataclass(slots=True)
class InterRepoEdge:
    """A cross-repository relationship (HTTP call, shared schema, import, queue, etc.)."""

    src_repo: str
    dst_repo: str
    kind: str  # "http", "queue", "shared-db", "import", "config"
    label: str = ""
    confidence: float = 0.8
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "src_repo": self.src_repo,
            "dst_repo": self.dst_repo,
            "kind": self.kind,
            "label": self.label,
            "confidence": round(float(self.confidence), 2),
            "evidence": sorted(self.evidence),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> InterRepoEdge:
        return cls(
            src_repo=str(data["src_repo"]),
            dst_repo=str(data["dst_repo"]),
            kind=str(data.get("kind", "unknown")),
            label=str(data.get("label", "")),
            confidence=float(data.get("confidence", 0.8)),
            evidence=list(data.get("evidence", [])),
        )


@dataclass(slots=True)
class Workspace:
    """A unified view of multiple repositories that form one product."""

    name: str
    root: Path
    repos: list[RepoRole] = field(default_factory=list)
    inter_repo_edges: list[InterRepoEdge] = field(default_factory=list)
    config_path: Path | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "root": str(self.root),
            "repos": [r.to_dict() for r in sorted(self.repos, key=lambda r: r.name)],
            "inter_repo_edges": [e.to_dict() for e in self.inter_repo_edges],
            "config_path": str(self.config_path) if self.config_path else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Workspace:
        return cls(
            name=str(data.get("name", "")),
            root=Path(str(data["root"])),
            repos=[RepoRole.from_dict(r) for r in data.get("repos", [])],
            inter_repo_edges=[InterRepoEdge.from_dict(e) for e in data.get("inter_repo_edges", [])],
            config_path=Path(str(data["config_path"])) if data.get("config_path") else None,
        )


# ── Workspace configuration loading ───────────────────────────────────

_WORKSPACE_CONFIG_NAMES = ("workspace.json", "secdiagram-workspace.json")


def _load_workspace_config(root: Path) -> dict[str, Any] | None:
    """Load a workspace.json from *root*, returning None if absent."""
    for name in _WORKSPACE_CONFIG_NAMES:
        path = root / name
        if path.is_file():
            try:
                text = path.read_text(encoding="utf-8")
                data = json.loads(text)
                if isinstance(data, dict):
                    data["_config_path"] = str(path)
                    return data
            except (OSError, json.JSONDecodeError, ValueError):
                continue
    return None


def _safe_read_text(root: Path, target: Path, max_size: int = 2 * 1024 * 1024) -> str | None:
    """Safely read a file, respecting root containment."""
    try:
        resolved = target.resolve()
        if not resolved.is_relative_to(root.resolve()) or not resolved.is_file():
            return None
        if resolved.stat().st_size > max_size:
            return None
        return resolved.read_text(encoding="utf-8", errors="replace")
    except (ValueError, OSError):
        return None


# ── Role detection heuristics ──────────────────────────────────────────

_FRONTEND_FRAMEWORKS = frozenset({
    "react", "react-dom", "vue", "svelte", "@angular/core",
    "next", "nuxt", "gatsby", "@sveltejs/kit", "vite",
    "webpack", "parcel",
})

_BACKEND_FRAMEWORKS_JS = frozenset({
    "express", "fastify", "@nestjs/core", "koa", "hapi",
    "@hapi/hapi", "hono", "restify",
})

_GATEWAY_INDICATORS = frozenset({
    "kong", "envoy", "traefik", "nginx", "haproxy",
    "ocelot", "yarp", "zuul", "spring-cloud-gateway",
})

_WORKER_INDICATORS = frozenset({
    "celery", "bullmq", "bull", "bee-queue", "agenda",
    "sidekiq", "resque", "hangfire",
})


def _detect_role_from_package_json(repo_path: Path) -> tuple[str, float, list[str]]:
    """Detect role from a root-level package.json."""
    pkg_path = repo_path / "package.json"
    if not pkg_path.is_file():
        return "unknown", 0.0, []

    try:
        text = pkg_path.read_text(encoding="utf-8")
        content = json.loads(text)
    except (OSError, json.JSONDecodeError, ValueError):
        return "unknown", 0.0, []

    deps = set(content.get("dependencies", {}).keys())
    dev_deps = set(content.get("devDependencies", {}).keys())
    all_deps = deps | dev_deps
    evidence: list[str] = []

    # Check for frontend frameworks
    frontend_hits = _FRONTEND_FRAMEWORKS & all_deps
    if frontend_hits:
        evidence.extend(f"package.json dep: {d}" for d in sorted(frontend_hits))

    # Check for backend frameworks
    backend_hits = _BACKEND_FRAMEWORKS_JS & all_deps
    if backend_hits:
        evidence.extend(f"package.json dep: {d}" for d in sorted(backend_hits))

    # Check for worker frameworks
    worker_hits = _WORKER_INDICATORS & all_deps
    if worker_hits:
        evidence.extend(f"package.json dep: {d}" for d in sorted(worker_hits))

    # Next.js is special: it's a fullstack framework, but if there's also a
    # separate backend, it's probably the frontend.
    if "next" in all_deps:
        if backend_hits - {"next"}:
            return "backend", 0.8, evidence
        return "frontend", 0.9, evidence

    if frontend_hits and not backend_hits:
        return "frontend", 0.9, evidence
    if backend_hits and not frontend_hits:
        return "backend", 0.85, evidence
    if worker_hits:
        return "worker", 0.8, evidence
    if frontend_hits and backend_hits:
        return "backend", 0.6, evidence  # ambiguous, lean backend

    return "unknown", 0.0, evidence


def _detect_role_from_python(repo_path: Path) -> tuple[str, float, list[str]]:
    """Detect role from Python project indicators."""
    evidence: list[str] = []

    # Check for common Python files
    setup_files = ["setup.py", "setup.cfg", "pyproject.toml"]
    has_setup = any((repo_path / f).is_file() for f in setup_files)
    if not has_setup:
        return "unknown", 0.0, []

    # Read pyproject.toml or setup.cfg for deps
    deps_text = ""
    for config_file in ("pyproject.toml", "setup.cfg", "requirements.txt"):
        path = repo_path / config_file
        if path.is_file():
            try:
                deps_text += path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass

    deps_lower = deps_text.lower()

    # Web frameworks
    web_frameworks = {
        "django": "Django",
        "flask": "Flask",
        "fastapi": "FastAPI",
        "starlette": "Starlette",
        "tornado": "Tornado",
        "sanic": "Sanic",
        "aiohttp": "aiohttp",
        "bottle": "Bottle",
        "falcon": "Falcon",
    }
    for key, name in web_frameworks.items():
        if key in deps_lower:
            evidence.append(f"Python dep: {name}")
            return "backend", 0.85, evidence

    # Worker frameworks
    worker_frameworks = {"celery", "dramatiq", "huey", "rq", "arq"}
    for wf in worker_frameworks:
        if wf in deps_lower:
            evidence.append(f"Python dep: {wf}")
            return "worker", 0.8, evidence

    # Data / ML frameworks
    data_frameworks = {
        "pandas", "numpy", "scikit-learn", "tensorflow", "pytorch",
        "sqlalchemy", "alembic", "dbt-core",
    }
    for df in data_frameworks:
        if df in deps_lower:
            evidence.append(f"Python dep: {df}")
            return "data-layer", 0.7, evidence

    # Library pattern: has setup but no web/worker deps
    if has_setup:
        evidence.append("Python package (library pattern)")
        return "library", 0.5, evidence

    return "unknown", 0.0, evidence


def _detect_role_from_dotnet(repo_path: Path) -> tuple[str, float, list[str]]:
    """Detect role from .NET project files."""
    evidence: list[str] = []
    for dirpath, dirnames, filenames in os.walk(repo_path):
        dirnames[:] = [d for d in dirnames if d not in {".git", "bin", "obj", "node_modules"}]
        for f in filenames:
            if f.endswith((".csproj", ".fsproj")):
                try:
                    import xml.etree.ElementTree as ET

                    tree = ET.parse(os.path.join(dirpath, f))
                    xml_root = tree.getroot()
                    sdk = xml_root.get("Sdk", "")
                    if "Microsoft.NET.Sdk.Web" in sdk:
                        evidence.append(f".NET Web SDK: {f}")
                        return "backend", 0.9, evidence
                    if "Microsoft.NET.Sdk.Worker" in sdk:
                        evidence.append(f".NET Worker SDK: {f}")
                        return "worker", 0.9, evidence
                    packages = [
                        (pkg.get("Include") or "").lower()
                        for pkg in xml_root.findall(".//PackageReference")
                    ]
                    if any("ocelot" in p or "yarp" in p for p in packages):
                        evidence.append(f".NET Gateway pkg in {f}")
                        return "gateway", 0.85, evidence
                    if any("entityframeworkcore" in p for p in packages):
                        evidence.append(f"EF Core in {f}")
                except (ET.ParseError, OSError):
                    continue
    if evidence:
        return "backend", 0.7, evidence
    return "unknown", 0.0, []


def _detect_role_from_java(repo_path: Path) -> tuple[str, float, list[str]]:
    """Detect role from Java/Gradle/Maven project files."""
    evidence: list[str] = []

    for manifest_name in ("pom.xml", "build.gradle", "build.gradle.kts"):
        manifest = repo_path / manifest_name
        if not manifest.is_file():
            continue
        try:
            text = manifest.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        text_lower = text.lower()
        if "spring-cloud-gateway" in text_lower or "zuul" in text_lower:
            evidence.append(f"Java gateway dep in {manifest_name}")
            return "gateway", 0.9, evidence
        if "spring-boot" in text_lower or "spring-web" in text_lower:
            evidence.append(f"Spring Boot in {manifest_name}")
            return "backend", 0.85, evidence
        if "spring-kafka" in text_lower or "spring-amqp" in text_lower:
            evidence.append(f"Java messaging dep in {manifest_name}")
            return "worker", 0.8, evidence

    return "unknown", 0.0, []


def _detect_role_from_go(repo_path: Path) -> tuple[str, float, list[str]]:
    """Detect role from go.mod."""
    gomod = repo_path / "go.mod"
    if not gomod.is_file():
        return "unknown", 0.0, []

    try:
        text = gomod.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return "unknown", 0.0, []

    evidence: list[str] = []
    text_lower = text.lower()

    web_markers = ("gin-gonic/gin", "labstack/echo", "go-chi/chi", "gofiber/fiber", "gorilla/mux")
    for marker in web_markers:
        if marker in text_lower:
            evidence.append(f"Go web framework: {marker}")
            return "backend", 0.85, evidence

    if "net/http" in text_lower:
        evidence.append("Go net/http")
        return "backend", 0.6, evidence

    return "unknown", 0.0, []


def _detect_role_from_infra(repo_path: Path) -> tuple[str, float, list[str]]:
    """Detect infrastructure repos from Terraform, Helm, K8s manifests, Dockerfiles."""
    evidence: list[str] = []

    # Terraform files at root or in terraform/ directory
    tf_files = list(repo_path.glob("*.tf")) + list(repo_path.glob("terraform/*.tf"))
    if tf_files:
        evidence.append(f"{len(tf_files)} Terraform files")
        return "infrastructure", 0.9, evidence

    # Helm charts
    if (repo_path / "Chart.yaml").is_file() or (repo_path / "helm").is_dir():
        evidence.append("Helm chart")
        return "infrastructure", 0.9, evidence

    # K8s manifests directory
    k8s_dirs = ["k8s", "kubernetes", "manifests", "deploy"]
    for d in k8s_dirs:
        k8s_path = repo_path / d
        if k8s_path.is_dir():
            yaml_files = list(k8s_path.glob("*.yaml")) + list(k8s_path.glob("*.yml"))
            if yaml_files:
                evidence.append(f"K8s manifests in {d}/")
                return "infrastructure", 0.85, evidence

    # CI/CD-only repos (only has .github, Jenkinsfile, etc.)
    ci_files = [".github", "Jenkinsfile", ".gitlab-ci.yml", ".circleci"]
    non_ci_entries = [
        e for e in os.listdir(repo_path)
        if not e.startswith(".") and e not in {"README.md", "LICENSE", "CHANGELOG.md"}
    ]
    if not non_ci_entries and any((repo_path / f).exists() for f in ci_files):
        evidence.append("CI/CD-only repository")
        return "infrastructure", 0.7, evidence

    return "unknown", 0.0, []


def _detect_role_from_directory_name(name: str) -> tuple[str, float, list[str]]:
    """Use directory naming conventions as a last-resort heuristic."""
    name_lower = name.lower().replace("-", "").replace("_", "")

    # Order matters: more specific patterns first to avoid false matches
    # (e.g. "api-gateway" should match gateway, not backend via "api").
    patterns: list[tuple[str, re.Pattern[str]]] = [
        ("gateway", re.compile(r"(gateway|proxy|apigw|bff|edge)")),
        ("frontend", re.compile(r"(frontend|web|ui|client|app|dashboard|portal)")),
        ("backend", re.compile(r"(backend|api|server|service)")),
        ("worker", re.compile(r"(worker|job|consumer|processor|cron|scheduler)")),
        ("data-layer", re.compile(r"(data|database|db|migration|schema|etl|pipeline)")),
        ("infrastructure", re.compile(r"(infra|infrastructure|deploy|ops|devops|platform|terraform|helm)")),
        ("library", re.compile(r"(lib|common|shared|util|sdk|core|pkg)")),
    ]

    for role, pattern in patterns:
        if pattern.search(name_lower):
            return role, 0.4, [f"directory name matches '{role}' pattern"]

    return "unknown", 0.0, []


def detect_repo_role(
    repo_path: Path,
    manual_role: str | None = None,
) -> RepoRole:
    """Detect the role of a single repo, with optional manual override.

    Detection order (first match with confidence > 0 wins):
    1. Manual override from workspace config
    2. package.json (Node.js)
    3. Python project indicators
    4. .NET project files
    5. Java/Gradle/Maven
    6. Go modules
    7. Infrastructure markers
    8. Directory name conventions
    """
    repo_path = repo_path.resolve()
    name = repo_path.name

    if manual_role is not None:
        role = manual_role.lower().strip()
        if role not in VALID_ROLES:
            role = "unknown"
        return RepoRole(
            path=repo_path,
            name=name,
            role=role,
            confidence=1.0,
            evidence=[f"manual override: {manual_role}"],
            manual=True,
        )

    detectors = [
        _detect_role_from_package_json,
        _detect_role_from_python,
        _detect_role_from_dotnet,
        _detect_role_from_java,
        _detect_role_from_go,
        _detect_role_from_infra,
    ]

    best_role = "unknown"
    best_confidence = 0.0
    best_evidence: list[str] = []

    for detector in detectors:
        role, confidence, evidence = detector(repo_path)
        if confidence > best_confidence:
            best_role = role
            best_confidence = confidence
            best_evidence = evidence

    # Fall back to directory name heuristic
    if best_confidence < 0.5:
        dir_role, dir_conf, dir_ev = _detect_role_from_directory_name(name)
        if dir_conf > best_confidence:
            best_role = dir_role
            best_confidence = dir_conf
            best_evidence = dir_ev

    return RepoRole(
        path=repo_path,
        name=name,
        role=best_role,
        confidence=best_confidence,
        evidence=best_evidence,
    )


# ── Cross-repo edge detection ─────────────────────────────────────────

# HTTP client patterns indicating calls to other services
_HTTP_URL_PATTERNS = re.compile(
    r"""(?:https?://|fetch\s*\(|requests?\.(get|post|put|delete|patch)|"""
    r"""HttpClient|WebClient|RestTemplate|axios\.|http\.|urllib|"""
    r"""httpx\.|aiohttp\.ClientSession|Flurl|\.GetAsync|\.PostAsync)""",
    re.IGNORECASE,
)

# Service name reference patterns in URLs / env vars
_SERVICE_REF_RE = re.compile(
    r"""(?:https?://|SERVICE_URL|_HOST|_ENDPOINT|_BASE_URL|_API_URL)"""
    r"""[=:]*\s*["']?(?:https?://)?([a-zA-Z][\w-]+)""",
    re.IGNORECASE,
)

# Shared database references (connection strings, env vars)
_DB_REF_PATTERNS = re.compile(
    r"""(?:DATABASE_URL|DB_HOST|POSTGRES_|MYSQL_|MONGO_|REDIS_|"""
    r"""ConnectionStrings?|jdbc:|mongodb\+srv://|amqp://)""",
    re.IGNORECASE,
)

# Queue / event patterns
_QUEUE_PATTERNS = re.compile(
    r"""(?:RABBITMQ_|KAFKA_|AMQP_URL|QUEUE_|EVENT_|topic\s*=|"""
    r"""exchange\s*=|routing_key|@RabbitListener|@KafkaListener|"""
    r"""channel\.queue_declare|\.subscribe\(|\.publish\()""",
    re.IGNORECASE,
)


def _detect_inter_repo_edges(
    repos: list[RepoRole],
    repo_infos: dict[str, RepoInfo],
) -> list[InterRepoEdge]:
    """Detect cross-repo relationships from code, configs, and env files."""
    edges: list[InterRepoEdge] = []
    seen: set[tuple[str, str, str]] = set()
    repo_names_lower = {r.name.lower(): r.name for r in repos}

    for repo_role in repos:
        info = repo_infos.get(repo_role.name)
        if info is None:
            continue

        has_queue = False
        has_db = False
        referenced_services: set[str] = set()

        # Scan code and config files for cross-repo references
        for rel_file in info.rel_files[:200]:  # Cap scanning to avoid huge repos
            suffix = rel_file.rsplit(".", 1)[-1].lower() if "." in rel_file else ""
            if suffix not in {
                "py", "js", "ts", "jsx", "tsx", "java", "cs", "go",
                "yaml", "yml", "json", "toml", "env", "cfg", "conf",
                "properties",
            }:
                continue

            file_path = info.root / rel_file
            try:
                text = file_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            if _QUEUE_PATTERNS.search(text):
                has_queue = True

            if _DB_REF_PATTERNS.search(text):
                has_db = True

            # Find service name references
            for match in _SERVICE_REF_RE.finditer(text):
                svc_name = match.group(1).lower()
                if svc_name in repo_names_lower and svc_name != repo_role.name.lower():
                    referenced_services.add(repo_names_lower[svc_name])

        # Create edges for explicit service references
        for target in sorted(referenced_services):
            key = (repo_role.name, target, "http")
            if key not in seen:
                seen.add(key)
                edges.append(InterRepoEdge(
                    src_repo=repo_role.name,
                    dst_repo=target,
                    kind="http",
                    label="HTTP / API call",
                    confidence=0.7,
                    evidence=[f"{repo_role.name} references {target} service"],
                ))

        # Infer gateway→backend edges from roles
        if repo_role.role == "gateway":
            for target_repo in repos:
                if target_repo.role == "backend" and target_repo.name != repo_role.name:
                    key = (repo_role.name, target_repo.name, "http")
                    if key not in seen:
                        seen.add(key)
                        edges.append(InterRepoEdge(
                            src_repo=repo_role.name,
                            dst_repo=target_repo.name,
                            kind="http",
                            label="Routes to backend",
                            confidence=0.6,
                            evidence=["gateway→backend role inference"],
                        ))

        # Infer frontend→gateway/backend edges from roles
        if repo_role.role == "frontend":
            targets = [r for r in repos if r.role in ("gateway", "backend") and r.name != repo_role.name]
            if targets:
                # Prefer gateway if available
                preferred = next((t for t in targets if t.role == "gateway"), targets[0])
                key = (repo_role.name, preferred.name, "http")
                if key not in seen:
                    seen.add(key)
                    edges.append(InterRepoEdge(
                        src_repo=repo_role.name,
                        dst_repo=preferred.name,
                        kind="http",
                        label="API requests",
                        confidence=0.6,
                        evidence=["frontend→gateway/backend role inference"],
                    ))

        # Shared database edges (repos that share the same DB connection patterns)
        if has_db and repo_role.role in ("backend", "data-layer", "worker"):
            for other in repos:
                if other.name == repo_role.name:
                    continue
                other_info = repo_infos.get(other.name)
                if other_info is None:
                    continue
                if other.role in ("backend", "data-layer", "worker"):
                    key = (repo_role.name, other.name, "shared-db")
                    rev_key = (other.name, repo_role.name, "shared-db")
                    if key not in seen and rev_key not in seen:
                        seen.add(key)
                        edges.append(InterRepoEdge(
                            src_repo=repo_role.name,
                            dst_repo=other.name,
                            kind="shared-db",
                            label="Shared data store",
                            confidence=0.5,
                            evidence=["both repos reference database connections"],
                        ))

        # Queue/event edges between workers and backends
        if has_queue:
            for other in repos:
                if other.name == repo_role.name:
                    continue
                if other.role in ("backend", "worker"):
                    key = (repo_role.name, other.name, "queue")
                    rev_key = (other.name, repo_role.name, "queue")
                    if key not in seen and rev_key not in seen:
                        seen.add(key)
                        edges.append(InterRepoEdge(
                            src_repo=repo_role.name,
                            dst_repo=other.name,
                            kind="queue",
                            label="Pub/Sub events",
                            confidence=0.5,
                            evidence=["queue/event patterns detected"],
                        ))

    return edges


# ── Graph merging ──────────────────────────────────────────────────────

def _prefix_path(path: str | None, repo_name: str) -> str | None:
    """Prefix a relative path with the repo name for disambiguation."""
    if path is None:
        return None
    # Already prefixed
    if path.startswith(f"{repo_name}/"):
        return path
    return f"{repo_name}/{path}"


def merge_graphs(
    repo_graphs: dict[str, Graph],
    repo_roles: dict[str, RepoRole],
    inter_repo_edges: list[InterRepoEdge],
) -> Graph:
    """Merge per-repo graphs into a single workspace graph.

    - Node IDs are made globally unique by incorporating the repo name.
    - File paths are prefixed with the repo name.
    - Cross-repo edges are added from inter_repo_edges.
    """
    merged = Graph()
    # Map: (repo_name, old_node_id) -> new_node_id
    id_map: dict[tuple[str, str], str] = {}
    # Map: repo_name -> list of endpoint node IDs in merged graph
    repo_endpoints: dict[str, list[str]] = {}

    for repo_name in sorted(repo_graphs.keys()):
        graph = repo_graphs[repo_name]
        role = repo_roles.get(repo_name)
        repo_endpoints[repo_name] = []

        for old_id, node in sorted(graph.nodes.items(), key=lambda kv: kv[0]):
            new_id = stable_id("workspace", repo_name, old_id)
            id_map[(repo_name, old_id)] = new_id

            new_node = Node(
                id=new_id,
                kind=node.kind,
                name=node.name,
                qualname=f"{repo_name}::{node.qualname}",
                path=_prefix_path(node.path, repo_name),
                line=node.line,
                feature=f"{repo_name}/{node.feature}" if node.feature else repo_name,
                doc=node.doc,
                attrs={
                    **node.attrs,
                    "workspace_repo": repo_name,
                    "workspace_role": role.role if role else "unknown",
                },
            )
            merged.add_node(new_node)

            if node.kind == "endpoint":
                repo_endpoints[repo_name].append(new_id)

        for edge in graph.edges:
            new_src = id_map.get((repo_name, edge.src))
            new_dst = id_map.get((repo_name, edge.dst))
            if new_src and new_dst:
                merged.add_edge(
                    new_src,
                    new_dst,
                    edge.kind,
                    confidence=edge.confidence,
                    resolution=edge.resolution,
                    evidence=[
                        Loc(_prefix_path(loc.path, repo_name) or loc.path, loc.line, loc.col)
                        for loc in edge.evidence
                    ],
                    attrs={**edge.attrs, "workspace_repo": repo_name},
                )

        for feature in graph.features:
            from .model import Feature

            merged.features.append(Feature(
                id=stable_id("workspace-feature", repo_name, feature.id),
                name=f"{repo_name}/{feature.name}",
                description=feature.description,
                nodes=[id_map.get((repo_name, nid), nid) for nid in feature.nodes],
                files=[_prefix_path(f, repo_name) or f for f in feature.files],
            ))

        for finding in graph.findings:
            from .model import Finding

            new_finding = Finding(
                id=stable_id("workspace-finding", repo_name, finding.id),
                category=finding.category,
                severity=finding.severity,
                title=f"[{repo_name}] {finding.title}",
                message=finding.message,
                node_id=id_map.get((repo_name, finding.node_id), finding.node_id) if finding.node_id else None,
                cwe=finding.cwe,
                confidence=finding.confidence,
                evidence=[
                    Loc(_prefix_path(loc.path, repo_name) or loc.path, loc.line, loc.col)
                    for loc in finding.evidence
                ],
                recommendation=finding.recommendation,
                trace=[
                    Loc(_prefix_path(loc.path, repo_name) or loc.path, loc.line, loc.col)
                    for loc in finding.trace
                ],
                source=finding.source,
                external_id=finding.external_id,
                metadata={**finding.metadata, "workspace_repo": repo_name},
            )
            merged.findings.append(new_finding)

    # Add cross-repo edges
    for ire in inter_repo_edges:
        src_endpoints = repo_endpoints.get(ire.src_repo, [])
        dst_endpoints = repo_endpoints.get(ire.dst_repo, [])

        # Create a synthetic node representing the cross-repo link if no endpoints
        if not src_endpoints:
            src_id = stable_id("workspace-bridge", ire.src_repo, "out")
            merged.add_node(Node(
                id=src_id,
                kind="external",
                name=f"{ire.src_repo} (outbound)",
                qualname=f"{ire.src_repo}::outbound",
                attrs={
                    "workspace_repo": ire.src_repo,
                    "workspace_role": repo_roles.get(ire.src_repo, RepoRole(Path("."), "", "unknown")).role,
                    "bridge": True,
                },
            ))
            src_endpoints = [src_id]

        if not dst_endpoints:
            dst_id = stable_id("workspace-bridge", ire.dst_repo, "in")
            merged.add_node(Node(
                id=dst_id,
                kind="external",
                name=f"{ire.dst_repo} (inbound)",
                qualname=f"{ire.dst_repo}::inbound",
                attrs={
                    "workspace_repo": ire.dst_repo,
                    "workspace_role": repo_roles.get(ire.dst_repo, RepoRole(Path("."), "", "unknown")).role,
                    "bridge": True,
                },
            ))
            dst_endpoints = [dst_id]

        # Connect first endpoint of source to first endpoint of destination
        merged.add_edge(
            src_endpoints[0],
            dst_endpoints[0],
            kind=f"cross-repo-{ire.kind}",
            confidence=ire.confidence,
            resolution="heuristic",
            attrs={
                "workspace_src_repo": ire.src_repo,
                "workspace_dst_repo": ire.dst_repo,
                "cross_repo": True,
                "label": ire.label,
            },
        )

    return merged


# ── Public API ─────────────────────────────────────────────────────────

def discover_workspace(
    root: str | Path,
    repo_paths: list[str | Path] | None = None,
    manual_roles: dict[str, str] | None = None,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
) -> Workspace:
    """Discover repos in a workspace directory and assign roles.

    Parameters
    ----------
    root : Path
        Workspace root directory (parent of the repos).
    repo_paths : list[Path], optional
        Explicit list of repo directories.  When omitted, all immediate
        subdirectories that contain at least one source file are scanned.
    manual_roles : dict[str, str], optional
        Map of repo-name → role to override auto-detection.
    include / exclude :
        Glob filters passed through to :func:`discover`.

    Returns
    -------
    Workspace
        Contains per-repo roles, discovered repo infos, and inter-repo edges.
    """
    root_path = Path(root).expanduser().resolve()
    if not root_path.exists():
        raise FileNotFoundError(f"workspace directory does not exist: {root_path}")
    if not root_path.is_dir():
        raise NotADirectoryError(f"not a directory: {root_path}")

    manual_roles = dict(manual_roles or {})

    # Load workspace.json if present (overrides but doesn't replace manual_roles)
    config = _load_workspace_config(root_path)
    config_path: Path | None = None
    workspace_name = root_path.name

    if config:
        config_path = Path(config.get("_config_path", ""))
        workspace_name = str(config.get("name", workspace_name))
        for entry in config.get("repos", []):
            if isinstance(entry, dict) and "name" in entry and "role" in entry:
                repo_name = str(entry["name"])
                if repo_name not in manual_roles:
                    manual_roles[repo_name] = str(entry["role"])

    # Discover repo directories
    if repo_paths is not None:
        dirs = [Path(p).expanduser().resolve() for p in repo_paths]
    else:
        dirs = sorted(
            d
            for d in root_path.iterdir()
            if d.is_dir() and not d.name.startswith(".")
            and d.name not in {
                "node_modules", "__pycache__", ".git", ".secdiagram",
                "dist", "build", "target",
            }
        )

    # Filter to directories that look like repos (have source files or manifests)
    repo_dirs: list[Path] = []
    _source_indicators = {
        "package.json", "pyproject.toml", "setup.py", "setup.cfg",
        "go.mod", "pom.xml", "build.gradle", "build.gradle.kts",
        "composer.json", "Cargo.toml", "Gemfile",
        "Chart.yaml",  # Helm
    }
    _source_suffixes = {
        ".py", ".js", ".ts", ".java", ".cs", ".go", ".php", ".rb",
        ".tf",  # Terraform
    }

    for d in dirs:
        if any((d / indicator).is_file() for indicator in _source_indicators):
            repo_dirs.append(d)
            continue
        # Check for source files in top-level
        try:
            top_files = list(d.iterdir())[:100]
            if any(f.suffix in _source_suffixes for f in top_files if f.is_file()):
                repo_dirs.append(d)
        except OSError:
            continue

    # Detect roles and discover repos
    repos: list[RepoRole] = []
    repo_infos: dict[str, RepoInfo] = {}

    for d in repo_dirs:
        name = d.name
        manual_role = manual_roles.get(name)
        repo_role = detect_repo_role(d, manual_role=manual_role)
        repos.append(repo_role)

        try:
            info = discover(d, include, exclude)
            repo_infos[name] = info
        except (FileNotFoundError, NotADirectoryError):
            continue

    # Detect cross-repo edges
    inter_edges = _detect_inter_repo_edges(repos, repo_infos)

    return Workspace(
        name=workspace_name,
        root=root_path,
        repos=repos,
        inter_repo_edges=inter_edges,
        config_path=config_path,
    )
