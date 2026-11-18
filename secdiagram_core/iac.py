"""Best-effort infrastructure-as-code inspection (Docker, Compose, CI, K8s, Terraform).

Every rule carries a stable ``IAC-<PLATFORM>-<NNN>`` identifier exposed through
``Finding.metadata["rule_id"]`` so downstream consumers (SARIF, baselines,
ignore lists) can reference individual rules deterministically. YAML-backed
platforms (Compose, GitHub Actions, GitLab CI, Kubernetes) are parsed with the
indentation-aware skeleton parser in :mod:`secdiagram_core.yaml_lite` instead
of raw line heuristics; Helm/Jinja templating is treated as opaque.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .discover import RepoInfo
from .model import Finding, Graph, Loc, Node, stable_id
from .yaml_lite import YamlNode, iter_nodes, parse_yaml, walk

_SECRETS = "SECRET|TOKEN|PASSWORD|PASSWD|API[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIAL|ACCESS[_-]?KEY"
_SECRET_NAME_RE = re.compile(rf"(?i)(?:{_SECRETS})")
_CURL_SH_RE = re.compile(r"(?:curl|wget)[^|]*\|\s*(?:ba)?sh")
_PLACEHOLDER_VALUES = {
    "changeme",
    "change_me",
    "example",
    "placeholder",
    "dummy",
    "none",
    "null",
    "todo",
    "xxxx",
    "mock_token_12345",
    "dummy-api-key",
}
_DANGEROUS_CAPS_RE = re.compile(r"(?i)SYS_ADMIN|NET_ADMIN|SYS_PTRACE|SYS_MODULE|\bALL\b")
_UNCONFINED_RE = re.compile(r"(?i)(?:seccomp|apparmor)\s*[=:]\s*unconfined")
_SENSITIVE_MOUNT_RE = re.compile(r"(?i)^(?:/etc|/proc|/sys|/root|/home|/var/lib/docker)\b")


@dataclass
class IacFinding:
    category: str
    rule_id: str
    severity: str
    title: str
    message: str
    path: str
    line: int
    cwe: str | None
    recommendation: str
    confidence: float = 0.85


@dataclass
class IacResult:
    nodes: list[Node] = field(default_factory=list)
    findings: list[IacFinding] = field(default_factory=list)


def _node(path: str, name: str, kind: str, line: int, attrs: dict) -> Node:
    return Node(
        id=stable_id("infra", path, name),
        kind=kind,
        name=name,
        qualname=f"infra:{path}#{name}",
        path=path,
        line=line,
        feature="infrastructure",
        doc=None,
        attrs=attrs,
    )


def _finding(
    result: IacResult,
    rule_id: str,
    category: str,
    severity: str,
    title: str,
    message: str,
    path: str,
    line: int,
    cwe: str,
    recommendation: str,
    confidence: float = 0.85,
) -> None:
    result.findings.append(
        IacFinding(
            category=category,
            rule_id=rule_id,
            severity=severity,
            title=title,
            message=message,
            path=path,
            line=line,
            cwe=cwe,
            recommendation=recommendation,
            confidence=confidence,
        )
    )


def _safe_read_text(root: Path, path: str, max_size: int = 5 * 1024 * 1024) -> str | None:
    target = root / path
    try:
        resolved = target.resolve()
        if not resolved.is_relative_to(root.resolve()) or not resolved.is_file():
            return None
        if resolved.stat().st_size > max_size:
            return None
        return resolved.read_text(encoding="utf-8", errors="replace")
    except (ValueError, OSError):
        return None


def _is_secret_name(name: str) -> bool:
    return bool(_SECRET_NAME_RE.search(name))


def _is_placeholder(value: str) -> bool:
    return not value or value.lower() in _PLACEHOLDER_VALUES


def _scalar(value: str | None) -> str:
    return (value or "").strip().strip("'\"")


def _node_text(node: YamlNode) -> str:
    """Inline value, block content and descendant scalar values of *node*."""
    parts = [node.text()]
    parts.extend(child.value or "" for child in walk(node))
    return "\n".join(parts)


def _is_secret_literal(value: str) -> bool:
    if not value or "{{" in value or value.startswith(("$", "${")):
        return False
    return not _is_placeholder(value)


# ---------------------------------------------------------------------------
# Dockerfile
# ---------------------------------------------------------------------------


def _dockerfile(root: Path, path: str) -> IacResult:
    result = IacResult()
    text = _safe_read_text(root, path)
    if text is None:
        return result
    lines = text.splitlines()
    base_images: list[str] = []
    user: str | None = None
    exposed: list[str] = []
    node = _node(path, path.rsplit("/", 1)[-1], "infra", 1, {"type": "container_image"})
    for number, raw in enumerate(lines, start=1):
        line = raw.strip()
        upper = line.upper()
        if upper.startswith("FROM "):
            image = re.split(r"(?i)\s+as\s+", line.split(None, 1)[1])[0].strip()
            base_images.append(image)
            if image.endswith(":latest") or ":" not in image.split("@")[0]:
                _finding(
                    result,
                    "IAC-DOCKER-001",
                    "supply-chain",
                    "low",
                    "Unpinned container base image",
                    f"`{image}` is not pinned to a digest or version at {path}:{number}.",
                    path,
                    number,
                    "CWE-1357",
                    "Pin base images to a version and digest; rebuild on a schedule.",
                )
        elif upper.startswith("USER "):
            user = line.split(None, 1)[1].strip()
        elif upper.startswith("EXPOSE "):
            exposed.extend(line.split(None, 1)[1].split())
        elif upper.startswith("ADD ") and ("http://" in line or "https://" in line):
            _finding(
                result,
                "IAC-DOCKER-002",
                "supply-chain",
                "medium",
                "Remote ADD instruction",
                f"Remote fetch via ADD at {path}:{number}.",
                path,
                number,
                "CWE-829",
                "Use COPY with verified artifacts and checksums.",
            )
        if _CURL_SH_RE.search(line):
            _finding(
                result,
                "IAC-DOCKER-003",
                "supply-chain",
                "high",
                "Remote script piped to shell",
                f"Unverified remote script execution at {path}:{number}.",
                path,
                number,
                "CWE-829",
                "Download, verify a checksum/signature, then execute.",
            )
        env_match = re.match(r"(?i)ENV\s+([A-Za-z_][A-Za-z0-9_]*)\s*[= ]\s*(.+)", line)
        if env_match and _is_secret_name(env_match.group(1)):
            value = env_match.group(2).strip().strip('"')
            if not _is_placeholder(value) and "{{" not in value:
                _finding(
                    result,
                    "IAC-DOCKER-004",
                    "secret",
                    "high",
                    "Secret in container image environment",
                    f"`{env_match.group(1)}` is baked into the image at {path}:{number}.",
                    path,
                    number,
                    "CWE-798",
                    "Inject secrets at runtime from a secret manager.",
                    confidence=0.7,
                )
        arg_match = re.match(r"(?i)ARG\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)", line)
        if arg_match and _is_secret_name(arg_match.group(1)):
            value = arg_match.group(2).strip().strip('"')
            if not _is_placeholder(value) and "{{" not in value:
                _finding(
                    result,
                    "IAC-DOCKER-005",
                    "secret",
                    "medium",
                    "Secret in Docker build argument",
                    f"`{arg_match.group(1)}` is stored in image history at {path}:{number}.",
                    path,
                    number,
                    "CWE-798",
                    "Pass secrets with BuildKit secret mounts instead of ARG/ENV.",
                    confidence=0.7,
                )
        if re.search(r"(?i)\bchmod\s+(?:-R\s+)?777\b", line):
            _finding(
                result,
                "IAC-DOCKER-006",
                "container",
                "high",
                "World-writable permissions",
                f"chmod 777 in image at {path}:{number}.",
                path,
                number,
                "CWE-732",
                "Use least-privilege file permissions such as 750 or 640.",
            )
        if re.search(r"(?i)^RUN\b.*\bsudo\b", line):
            _finding(
                result,
                "IAC-DOCKER-007",
                "container",
                "low",
                "Build step uses sudo",
                f"Elevated build step at {path}:{number}.",
                path,
                number,
                "CWE-250",
                "Run build steps as the unprivileged build user.",
            )
    if user is None or user.lower() in {"root", "0"}:
        _finding(
            result,
            "IAC-DOCKER-008",
            "container",
            "medium",
            "Container runs as root",
            f"No non-root USER is set in {path}.",
            path,
            1,
            "CWE-250",
            "Create an unprivileged user and set `USER <name>`.",
        )
    node.attrs.update({"base_images": base_images, "user": user or "root", "exposed_ports": exposed})
    result.nodes.append(node)
    return result


# ---------------------------------------------------------------------------
# Docker Compose
# ---------------------------------------------------------------------------

_COMPOSE_HOST_NS = {
    "network_mode": ("IAC-COMPOSE-003", "Host network mode", "CWE-284"),
    "pid": ("IAC-COMPOSE-004", "Host PID namespace", "CWE-250"),
    "ipc": ("IAC-COMPOSE-005", "Host IPC namespace", "CWE-250"),
    "userns_mode": ("IAC-COMPOSE-006", "Host user namespace", "CWE-250"),
}
_ENV_ENTRY_RE = re.compile(r"(?i)^([A-Za-z_][A-Za-z0-9_]*)\s*[=:]\s*(\S.*)$")


def _compose_env_secret(
    result: IacResult,
    service: str,
    path: str,
    line: int,
    name: str,
    value: str,
) -> None:
    if not _is_secret_name(name) or not _is_secret_literal(_scalar(value)):
        return
    _finding(
        result,
        "IAC-COMPOSE-012",
        "secret",
        "high",
        "Secret in Compose environment",
        f"`{name}` is hardcoded in service `{service}` at {path}:{line}.",
        path,
        line,
        "CWE-798",
        "Use Compose secrets or a secret manager instead of inline values.",
        confidence=0.7,
    )


def _compose(root: Path, path: str) -> IacResult:
    result = IacResult()
    text = _safe_read_text(root, path)
    if text is None:
        return result
    for doc in parse_yaml(text):
        for key_path, services in iter_nodes(doc, ()):
            if key_path != ("services",):
                continue
            for service in services.children:
                if service.key is None or service.key.startswith("x-"):
                    continue
                name = service.key
                attrs: dict[str, object] = {"type": "compose_service"}
                result.nodes.append(_node(path, name, "service", service.line, attrs))
                for item in walk(service):
                    value = _scalar(item.value)
                    low = value.lower()
                    text_of_item = _node_text(item)
                    if item.key == "image" and value:
                        attrs["image"] = value
                        if ":" not in value or value.endswith(":latest"):
                            _finding(
                                result,
                                "IAC-COMPOSE-001",
                                "supply-chain",
                                "low",
                                "Unpinned container image",
                                f"Service `{name}` uses an unpinned image at {path}:{item.line}.",
                                path,
                                item.line,
                                "CWE-1357",
                                "Pin the image tag/digest.",
                            )
                        continue
                    if item.key == "privileged" and low == "true":
                        attrs["privileged"] = "true"
                        _finding(
                            result,
                            "IAC-COMPOSE-002",
                            "container",
                            "critical",
                            "Privileged container",
                            f"Service `{name}` enables privileged mode at {path}:{item.line}.",
                            path,
                            item.line,
                            "CWE-250",
                            "Remove the elevated setting or isolate the workload.",
                        )
                    elif item.key in _COMPOSE_HOST_NS and low == "host":
                        rule_id, title, cwe = _COMPOSE_HOST_NS[item.key]
                        attrs[item.key] = "host"
                        _finding(
                            result,
                            rule_id,
                            "container",
                            "high",
                            title,
                            f"Service `{name}` enables {item.key} at {path}:{item.line}.",
                            path,
                            item.line,
                            cwe,
                            "Remove the elevated setting or isolate the workload.",
                        )
                    elif item.key == "user" and low in {"root", "0"}:
                        attrs["user"] = "root"
                        _finding(
                            result,
                            "IAC-COMPOSE-011",
                            "container",
                            "high",
                            "Container runs as root",
                            f"Service `{name}` runs as root at {path}:{item.line}.",
                            path,
                            item.line,
                            "CWE-250",
                            "Set a non-root user in the service definition.",
                        )
                    elif item.key == "cap_add" and _DANGEROUS_CAPS_RE.search(text_of_item):
                        attrs["dangerous_capability"] = True
                        _finding(
                            result,
                            "IAC-COMPOSE-008",
                            "container",
                            "high",
                            "Dangerous Linux capability added",
                            f"Service `{name}` adds an elevated capability at {path}:{item.line}.",
                            path,
                            item.line,
                            "CWE-250",
                            "Drop all capabilities and add only the minimum required set.",
                        )
                    elif item.key == "security_opt" and _UNCONFINED_RE.search(text_of_item):
                        attrs["unconfined_profile"] = True
                        _finding(
                            result,
                            "IAC-COMPOSE-009",
                            "container",
                            "high",
                            "Unconfined security profile",
                            f"Service `{name}` disables a security profile at {path}:{item.line}.",
                            path,
                            item.line,
                            "CWE-250",
                            "Keep seccomp and AppArmor profiles enabled.",
                        )
                    elif item.key in {"volumes", "devices"}:
                        entries = list(walk(item)) if item.children else [item]
                        if item.value:
                            entries.append(item)
                        for entry in entries:
                            mount = _scalar(entry.value)
                            if not mount:
                                continue
                            if "/var/run/docker.sock" in mount:
                                attrs["docker_socket"] = True
                                _finding(
                                    result,
                                    "IAC-COMPOSE-007",
                                    "container",
                                    "high",
                                    "Docker socket mounted",
                                    f"Service `{name}` mounts the Docker socket at {path}:{entry.line}.",
                                    path,
                                    entry.line,
                                    "CWE-250",
                                    "Avoid mounting the Docker socket; use a scoped API proxy.",
                                )
                            elif _SENSITIVE_MOUNT_RE.match(mount.split(":")[0]):
                                _finding(
                                    result,
                                    "IAC-COMPOSE-010",
                                    "container",
                                    "high",
                                    "Sensitive host path mounted",
                                    f"Service `{name}` mounts a sensitive host path at {path}:{entry.line}.",
                                    path,
                                    entry.line,
                                    "CWE-250",
                                    "Mount only scoped data directories with read-only access.",
                                )
                    elif item.key == "environment":
                        for entry in walk(item):
                            if entry.key is not None:
                                _compose_env_secret(
                                    result, name, path, entry.line, entry.key, entry.value or ""
                                )
                            else:
                                inline = _ENV_ENTRY_RE.match(_scalar(entry.value))
                                if inline:
                                    _compose_env_secret(
                                        result, name, path, entry.line, inline.group(1), inline.group(2)
                                    )
                        inline_env = _ENV_ENTRY_RE.match(_scalar(item.value))
                        if inline_env:
                            _compose_env_secret(
                                result, name, path, item.line, inline_env.group(1), inline_env.group(2)
                            )
    return result


# ---------------------------------------------------------------------------
# GitHub Actions workflows
# ---------------------------------------------------------------------------

_TRIGGER_RULES = {
    "pull_request_target": ("IAC-CI-004", "pull_request_target trigger"),
    "workflow_run": ("IAC-CI-005", "workflow_run trigger"),
}


def _workflow_script_check(result: IacResult, path: str, node: YamlNode, text: str) -> None:
    if not text:
        return
    if _CURL_SH_RE.search(text):
        _finding(
            result,
            "IAC-CI-003",
            "supply-chain",
            "high",
            "Remote script piped to shell in CI",
            f"Unverified remote script execution at {path}:{node.line}.",
            path,
            node.line,
            "CWE-829",
            "Pin and verify downloaded tooling.",
        )
    if re.search(r"\$\{\{\s*github\.(?:event|head_ref|head\.ref)", text):
        _finding(
            result,
            "IAC-CI-006",
            "ci",
            "high",
            "Untrusted GitHub context interpolated into a shell",
            f"Potential workflow script injection at {path}:{node.line}.",
            path,
            node.line,
            "CWE-94",
            "Pass untrusted values through an environment variable and quote them.",
        )
    if re.search(r"\$\{\{\s*secrets\.", text):
        _finding(
            result,
            "IAC-CI-007",
            "ci",
            "medium",
            "Secret interpolated into a shell command",
            f"Secret may be exposed in logs at {path}:{node.line}.",
            path,
            node.line,
            "CWE-532",
            "Pass secrets through env and avoid printing or tracing commands.",
            confidence=0.7,
        )


def _workflow(root: Path, path: str) -> IacResult:
    result = IacResult()
    text = _safe_read_text(root, path)
    if text is None:
        return result
    name = path.rsplit("/", 1)[-1]
    node = _node(path, name, "workflow", 1, {"type": "ci_workflow"})
    actions: set[str] = set()
    secrets: set[str] = set()
    triggers: set[str] = set()
    for doc in parse_yaml(text):
        for _key_path, item in iter_nodes(doc, ()):
            key = item.key
            if key is None:
                continue
            value = _scalar(item.value)
            if key == "on":
                if value:
                    inline = value.strip("[]")
                    for part in inline.split(","):
                        trigger = part.strip().strip("'\"")
                        if trigger:
                            triggers.add(trigger)
                            if trigger in _TRIGGER_RULES:
                                rule_id, title = _TRIGGER_RULES[trigger]
                                _finding(
                                    result,
                                    rule_id,
                                    "ci",
                                    "medium",
                                    title,
                                    f"Privileged trigger `{trigger}` at {path}:{item.line}.",
                                    path,
                                    item.line,
                                    "CWE-829",
                                    "Review checkout and secret exposure for this trigger.",
                                )
                for child in item.children:
                    if not child.key:
                        continue
                    triggers.add(child.key)
                    if child.key in _TRIGGER_RULES:
                        rule_id, title = _TRIGGER_RULES[child.key]
                        _finding(
                            result,
                            rule_id,
                            "ci",
                            "medium",
                            title,
                            f"Privileged trigger `{child.key}` at {path}:{child.line}.",
                            path,
                            child.line,
                            "CWE-829",
                            "Review checkout and secret exposure for this trigger.",
                        )
                continue
            if key == "permissions" and "write-all" in _node_text(item).lower():
                _finding(
                    result,
                    "IAC-CI-001",
                    "ci",
                    "high",
                    "Workflow grants write-all permissions",
                    f"Overly broad permissions at {path}:{item.line}.",
                    path,
                    item.line,
                    "CWE-732",
                    "Grant least-privilege permissions per job.",
                )
            elif key == "uses" and value and "{{" not in value:
                action = value
                if not action.startswith("./"):
                    actions.add(action)
                    if "@" in action:
                        ref = action.rsplit("@", 1)[1]
                        if not re.fullmatch(r"[0-9a-fA-F]{40}", ref):
                            _finding(
                                result,
                                "IAC-CI-002",
                                "supply-chain",
                                "low",
                                "Unpinned GitHub Action",
                                f"`{action}` is not pinned to a commit SHA at {path}:{item.line}.",
                                path,
                                item.line,
                                "CWE-1357",
                                "Pin third-party actions to a full commit SHA.",
                            )
            elif key == "run":
                _workflow_script_check(result, path, item, _node_text(item))
            for found in re.findall(r"secrets\.([A-Za-z0-9_]+)", _node_text(item)):
                secrets.add(found)
    node.attrs.update(
        {
            "actions": sorted(actions),
            "secrets": sorted(secrets),
            "triggers": sorted(triggers),
        }
    )
    result.nodes.append(node)
    return result


# ---------------------------------------------------------------------------
# Kubernetes manifests
# ---------------------------------------------------------------------------

K8S_KINDS = {"deployment", "statefulset", "daemonset", "pod", "job", "cronjob", "replicaset"}

_K8S_CHECKS: tuple[tuple[str, str, str, str, str, str], ...] = (
    ("privileged", "true", "critical", "CWE-250", "Privileged container", "IAC-K8S-001"),
    ("hostNetwork", "true", "high", "CWE-284", "Host network namespace", "IAC-K8S-002"),
    ("hostPID", "true", "high", "CWE-250", "Host PID namespace", "IAC-K8S-003"),
    ("hostIPC", "true", "high", "CWE-284", "Host IPC namespace", "IAC-K8S-004"),
    ("runAsUser", "0", "high", "CWE-250", "Container runs as UID 0", "IAC-K8S-005"),
    ("runAsNonRoot", "false", "high", "CWE-250", "Container permitted to run as root", "IAC-K8S-006"),
    ("allowPrivilegeEscalation", "true", "medium", "CWE-250", "Privilege escalation allowed", "IAC-K8S-007"),
    ("readOnlyRootFilesystem", "false", "medium", "CWE-250", "Writable container root filesystem", "IAC-K8S-008"),
    ("automountServiceAccountToken", "true", "medium", "CWE-522", "Service account token automounted", "IAC-K8S-009"),
)


def _image_is_mutable(image: str) -> bool:
    if "{{" in image:
        return False
    base = image.split("@")[0]
    if ":" in base.rsplit("/", 1)[-1]:
        return base.rsplit(":", 1)[1].lower() == "latest"
    return True


def _kubernetes(root: Path, path: str) -> IacResult:
    result = IacResult()
    text = _safe_read_text(root, path)
    if text is None:
        return result
    filename = path.rsplit("/", 1)[-1]
    for doc in parse_yaml(text):
        kind_node = doc.child("kind")
        kind = (kind_node.value or "").lower() if kind_node else ""
        if kind not in K8S_KINDS or not kind_node:
            continue
        metadata = doc.child("metadata")
        meta_name = None
        if metadata is not None:
            name_node = metadata.child("name")
            if name_node and name_node.value and "{{" not in name_node.value:
                meta_name = name_node.value.strip("'\"")
        attrs: dict[str, object] = {"type": f"k8s_{kind}"}
        if meta_name:
            attrs["name"] = meta_name
        node = _node(path, f"{kind}/{meta_name or filename}", "infra", kind_node.line, attrs)
        result.nodes.append(node)
        for _, item in iter_nodes(doc, ()):
            key = item.key
            if key is None:
                continue
            value = _scalar(item.value)
            low = value.lower()
            if key == "name" and value and "name" not in node.attrs:
                node.attrs["name"] = value
            for check_key, check_value, severity, cwe, title, rule_id in _K8S_CHECKS:
                if key == check_key and not item.template and low == check_value:
                    if check_key == "runAsUser":
                        node.attrs["user"] = "root"
                    elif check_key == "privileged":
                        node.attrs["privileged"] = "true"
                    elif check_key == "hostNetwork":
                        node.attrs["host_network"] = True
                    _finding(
                        result,
                        rule_id,
                        "container",
                        severity,
                        title,
                        f"Kubernetes manifest sets {check_key}: {check_value} at {path}:{item.line}.",
                        path,
                        item.line,
                        cwe,
                        "Apply least privilege and a restricted pod security profile.",
                    )
            if key == "seccompProfile" and not item.template and "unconfined" in _node_text(item).lower():
                _finding(
                    result,
                    "IAC-K8S-010",
                    "container",
                    "medium",
                    "Seccomp profile disabled",
                    f"Kubernetes manifest sets seccompProfile: unconfined at {path}:{item.line}.",
                    path,
                    item.line,
                    "CWE-250",
                    "Apply least privilege and a restricted pod security profile.",
                )
            elif key == "hostPath":
                node.attrs["host_path"] = True
                if "/var/run/docker.sock" in _node_text(item):
                    node.attrs["docker_socket"] = True
                _finding(
                    result,
                    "IAC-K8S-011",
                    "container",
                    "high",
                    "Host path volume mounted",
                    f"Kubernetes manifest mounts a host path at {path}:{item.line}.",
                    path,
                    item.line,
                    "CWE-250",
                    "Avoid hostPath volumes; use managed persistent volumes.",
                )
            elif key == "capabilities" and item.value and not item.template and _DANGEROUS_CAPS_RE.search(value):
                node.attrs["dangerous_capability"] = True
                _finding(
                    result,
                    "IAC-K8S-012",
                    "container",
                    "high",
                    "Dangerous Linux capability added",
                    f"Kubernetes manifest adds an elevated capability at {path}:{item.line}.",
                    path,
                    item.line,
                    "CWE-250",
                    "Drop ALL capabilities and add only the required ones.",
                )
            elif key == "add" and not item.template and _DANGEROUS_CAPS_RE.search(_node_text(item)):
                node.attrs["dangerous_capability"] = True
                _finding(
                    result,
                    "IAC-K8S-012",
                    "container",
                    "high",
                    "Dangerous Linux capability added",
                    f"Kubernetes manifest adds an elevated capability at {path}:{item.line}.",
                    path,
                    item.line,
                    "CWE-250",
                    "Drop ALL capabilities and add only the required ones.",
                )
            elif key == "image" and value and _image_is_mutable(value):
                _finding(
                    result,
                    "IAC-K8S-013",
                    "supply-chain",
                    "low",
                    "Mutable container image tag",
                    f"Image `{value}` is not pinned to a digest or version at {path}:{item.line}.",
                    path,
                    item.line,
                    "CWE-1357",
                    "Pin images by digest or an immutable version tag.",
                )
    return result


# ---------------------------------------------------------------------------
# Terraform
# ---------------------------------------------------------------------------

_TF_SECRET_KEY = r"(?i)\b\w*?(?:password|passwd|secret|token|api_key|access_key|private_key)\b"
_TF_SECRET_ATTR_RE = re.compile(
    _TF_SECRET_KEY + r"\s*=\s*(?:\"([^\"$]{8,})\"|'([^'$]{8,})')"
)
_TF_HEREDOC_SECRET_RE = re.compile(_TF_SECRET_KEY + r"\s*=\s*<<-?\s*([A-Za-z0-9_-]+)")
_TF_HEREDOC_MAX_LINES = 500


def _terraform(root: Path, path: str) -> IacResult:
    result = IacResult()
    text = _safe_read_text(root, path)
    if text is None:
        return result
    lines = text.splitlines()
    node = _node(path, path.rsplit("/", 1)[-1], "infra", 1, {"type": "terraform"})
    heredoc_end: str | None = None
    heredoc_start = 0
    for number, raw in enumerate(lines, start=1):
        stripped = raw.strip()
        if heredoc_end is not None:
            if stripped == heredoc_end or number - heredoc_start > _TF_HEREDOC_MAX_LINES:
                if stripped:
                    _finding(
                        result,
                        "IAC-TF-007",
                        "secret",
                        "high",
                        "Hardcoded secret in Terraform",
                        f"Secret literal found in heredoc starting at {path}:{heredoc_start}.",
                        path,
                        heredoc_start,
                        "CWE-798",
                        "Reference a secret manager or encrypted variable instead of a literal.",
                        confidence=0.7,
                    )
                heredoc_end = None
            continue
        heredoc_match = _TF_HEREDOC_SECRET_RE.search(stripped)
        if heredoc_match:
            heredoc_end = heredoc_match.group(1)
            heredoc_start = number
            continue
        if re.search(r"\"(?:0\.0\.0\.0/0|::/0)\"", stripped):
            _finding(
                result,
                "IAC-TF-001",
                "cloud",
                "high",
                "Security group open to the internet",
                f"0.0.0.0/0 ingress at {path}:{number}.",
                path,
                number,
                "CWE-284",
                "Restrict CIDR ranges to known networks.",
            )
        if re.search(r"acl\s*=\s*\"public", stripped):
            _finding(
                result,
                "IAC-TF-002",
                "cloud",
                "high",
                "Public storage ACL",
                f"Public ACL at {path}:{number}.",
                path,
                number,
                "CWE-284",
                "Use private ACLs and explicit access policies.",
            )
        if re.search(r"encrypted\s*=\s*false", stripped):
            _finding(
                result,
                "IAC-TF-003",
                "cloud",
                "medium",
                "Encryption disabled",
                f"Encryption disabled at {path}:{number}.",
                path,
                number,
                "CWE-311",
                "Enable encryption at rest and in transit.",
            )
        if re.search(r"(?i)publicly_accessible\s*=\s*true", stripped):
            _finding(
                result,
                "IAC-TF-004",
                "cloud",
                "high",
                "Database publicly accessible",
                f"Public database endpoint at {path}:{number}.",
                path,
                number,
                "CWE-284",
                "Disable public accessibility and place databases in private subnets.",
            )
        if re.search(
            r"(?i)(?:block_public_\w+|ignore_public_acls|restrict_public_buckets)\s*=\s*false",
            stripped,
        ):
            _finding(
                result,
                "IAC-TF-005",
                "cloud",
                "high",
                "Public access block disabled",
                f"Public access protections disabled at {path}:{number}.",
                path,
                number,
                "CWE-284",
                "Enable all public access block settings for storage resources.",
            )
        if re.search(r"(?i)\b(?:Action|actions)\s*=\s*(?:\"\*\"|\[\s*\"\*\"\s*\])", stripped):
            _finding(
                result,
                "IAC-TF-006",
                "cloud",
                "high",
                "IAM policy allows all actions",
                f"Wildcard IAM action at {path}:{number}.",
                path,
                number,
                "CWE-732",
                "Scope IAM actions and resources to the minimum required set.",
            )
        secret_attr = _TF_SECRET_ATTR_RE.search(stripped)
        if secret_attr:
            value = (secret_attr.group(1) or secret_attr.group(2) or "").strip()
            if not _is_placeholder(value):
                _finding(
                    result,
                    "IAC-TF-007",
                    "secret",
                    "high",
                    "Hardcoded secret in Terraform",
                    f"Secret literal found at {path}:{number}.",
                    path,
                    number,
                    "CWE-798",
                    "Reference a secret manager or encrypted variable instead of a literal.",
                    confidence=0.7,
                )
    result.nodes.append(node)
    return result


# ---------------------------------------------------------------------------
# GitLab CI pipelines
# ---------------------------------------------------------------------------


def _gitlab(root: Path, path: str) -> IacResult:
    result = IacResult()
    text = _safe_read_text(root, path)
    if text is None:
        return result
    name = path.rsplit("/", 1)[-1]
    node = _node(path, name, "workflow", 1, {"type": "gitlab_pipeline"})
    scripts: set[str] = set()
    for doc in parse_yaml(text):
        for key_path, item in iter_nodes(doc, ()):
            key = item.key
            if key is None:
                continue
            value = _scalar(item.value)
            if key_path == ("include",):
                last_project: tuple[str, int] | None = None
                for child in item.children:
                    if child.key == "remote" and re.match(r"(?i)https?://", _scalar(child.value)):
                        _finding(
                            result,
                            "IAC-GITLAB-001",
                            "supply-chain",
                            "medium",
                            "Unpinned remote include",
                            f"Pipeline includes a remote configuration at {path}:{child.line}.",
                            path,
                            child.line,
                            "CWE-829",
                            "Vendor the included pipeline and pin it to a reviewed revision.",
                        )
                    elif child.key == "project" and _scalar(child.value):
                        last_project = (_scalar(child.value), child.line)
                    elif child.key == "ref" and _scalar(child.value) and last_project:
                        ref = _scalar(child.value)
                        if not re.fullmatch(r"[0-9a-fA-F]{40}", ref):
                            _finding(
                                result,
                                "IAC-GITLAB-004",
                                "supply-chain",
                                "medium",
                                "Project include not pinned to a commit SHA",
                                f"`{last_project[0]}` is included with mutable ref `{ref}` at {path}:{child.line}.",
                                path,
                                child.line,
                                "CWE-1357",
                                "Pin included pipeline projects to a full commit SHA.",
                            )
            elif key in {"script", "before_script", "after_script"}:
                scripts.add(item.text())
                for child in walk(item):
                    if child.value:
                        scripts.add(child.value)
                if _CURL_SH_RE.search(_node_text(item)):
                    _finding(
                        result,
                        "IAC-GITLAB-002",
                        "supply-chain",
                        "high",
                        "Remote script piped to shell in CI",
                        f"Unverified remote script execution in `{key}` at {path}:{item.line}.",
                        path,
                        item.line,
                        "CWE-829",
                        "Pin and verify downloaded tooling.",
                    )
            elif len(key_path) >= 2 and key_path[-2] == "variables" and not item.template:
                if _is_secret_name(key):
                    literal = value
                    if not literal:
                        value_child = item.child("value")
                        literal = _scalar(value_child.value) if value_child else ""
                    if _is_secret_literal(literal):
                        _finding(
                            result,
                            "IAC-GITLAB-003",
                            "secret",
                            "high",
                            "Hardcoded secret in pipeline variables",
                            f"`{key}` is hardcoded at {path}:{item.line}.",
                            path,
                            item.line,
                            "CWE-798",
                            "Store pipeline secrets in protected CI/CD variables, not in the file.",
                            confidence=0.7,
                        )
    node.attrs.update({"scripts": sorted(scripts)})
    result.nodes.append(node)
    return result


# ---------------------------------------------------------------------------
# Jenkins pipelines
# ---------------------------------------------------------------------------

_JENKINS_SECRET_ASSIGN_RE = re.compile(
    r"(?i)^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*['\"]([^'\"$\{]{4,})['\"]"
)


def _jenkins(root: Path, path: str) -> IacResult:
    result = IacResult()
    text = _safe_read_text(root, path)
    if text is None:
        return result
    name = path.rsplit("/", 1)[-1]
    node = _node(path, name, "workflow", 1, {"type": "jenkins_pipeline"})
    for number, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if _CURL_SH_RE.search(stripped):
            _finding(
                result,
                "IAC-JENKINS-001",
                "supply-chain",
                "high",
                "Remote script piped to shell in CI",
                f"Unverified remote script execution at {path}:{number}.",
                path,
                number,
                "CWE-829",
                "Download, verify a checksum/signature, then execute.",
            )
        secret_match = _JENKINS_SECRET_ASSIGN_RE.match(stripped)
        if secret_match and _is_secret_name(secret_match.group(1)):
            value = secret_match.group(2)
            if not _is_placeholder(value):
                _finding(
                    result,
                    "IAC-JENKINS-002",
                    "secret",
                    "high",
                    "Hardcoded secret in pipeline environment",
                    f"`{secret_match.group(1)}` is hardcoded at {path}:{number}.",
                    path,
                    number,
                    "CWE-798",
                    "Use Jenkins credentials bindings instead of literal values.",
                    confidence=0.7,
                )
        if re.search(r"(?i)--privileged\b", stripped):
            _finding(
                result,
                "IAC-JENKINS-003",
                "container",
                "high",
                "Privileged container execution",
                f"`--privileged` used at {path}:{number}.",
                path,
                number,
                "CWE-250",
                "Drop privileged mode and run containers with the minimum capabilities.",
            )
    result.nodes.append(node)
    return result


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def analyze_iac(graph: Graph, repo: RepoInfo) -> list[Finding]:
    results: list[IacResult] = []
    for path in repo.iac_files:
        lower = path.lower()
        name = lower.rsplit("/", 1)[-1]
        if name.startswith("dockerfile"):
            results.append(_dockerfile(repo.root, path))
        elif name in {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}:
            results.append(_compose(repo.root, path))
        elif "/.github/workflows/" in f"/{lower}" and lower.endswith((".yml", ".yaml")):
            results.append(_workflow(repo.root, path))
        elif name == ".gitlab-ci.yml":
            results.append(_gitlab(repo.root, path))
        elif name.startswith("jenkinsfile"):
            results.append(_jenkins(repo.root, path))
        elif lower.endswith((".tf", ".tfvars")):
            results.append(_terraform(repo.root, path))
        elif lower.endswith((".yml", ".yaml")):
            results.append(_kubernetes(repo.root, path))

    findings: list[Finding] = []
    seen: set[str] = set()
    for result in results:
        for node in result.nodes:
            graph.add_node(node)
        for item in result.findings:
            key = f"{item.rule_id}:{item.path}:{item.line}"
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    id=stable_id("iac", item.category, item.path, str(item.line), item.title),
                    category=item.category,
                    severity=item.severity,
                    title=item.title,
                    message=item.message,
                    cwe=item.cwe,
                    confidence=item.confidence,
                    evidence=[Loc(item.path, item.line)],
                    recommendation=item.recommendation,
                    metadata={"rule_id": item.rule_id},
                )
            )
    return findings
