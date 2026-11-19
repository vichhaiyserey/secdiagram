"""Deterministic SDLC phase-handoff automation for the secdiagram Studio.

The Studio treats an architecture engagement as a small, auditable state
machine.  Each phase has explicit entry gates and produces evidence that the
next agent (human or AI) can consume.  State is persisted as JSON next to the
generated analysis artifacts so a handoff survives process restarts.

The module is intentionally standard-library only and never executes code from
the analyzed repository.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .model import Graph

STATE_SCHEMA_VERSION = 1

PHASES: tuple[str, ...] = ("discover", "model", "secure", "review", "handoff")

PHASE_TITLES: dict[str, str] = {
    "discover": "Discover",
    "model": "Model",
    "secure": "Secure",
    "review": "Review",
    "handoff": "Handoff",
}

PHASE_DESCRIPTIONS: dict[str, str] = {
    "discover": "Inventory the repository, languages, manifests, and entry points.",
    "model": "Compile the canonical graph and human-facing architecture diagrams.",
    "secure": "Run SAST, IaC, risk scoring, threat modeling, and policy gates.",
    "review": "Collect evidence-grounded narrative and reviewer sign-off.",
    "handoff": "Package reproducible artifacts and a phase handoff for the next agent.",
}

PHASE_ARTIFACTS: dict[str, tuple[str, ...]] = {
    "discover": ("graph.json",),
    "model": ("diagram-highlevel.mmd", "diagram.mmd", "ARCHITECTURE.md"),
    "secure": ("security.sarif", "THREAT_MODEL.md", "vex.json"),
    "review": ("NARRATIVE.md", "SECURITY_REVIEW.md"),
    "handoff": ("HANDOFF.md", "handoff.json"),
}

# Stable, bounded list used when hashing artifacts for a handoff.
ARTIFACT_NAMES: tuple[str, ...] = tuple(
    dict.fromkeys(
        (
            "graph.json",
            "diagram.mmd",
            "diagram-highlevel.mmd",
            "diagram-taint.mmd",
            "ARCHITECTURE.md",
            "THREAT_MODEL.md",
            "threat-model.json",
            "security.sarif",
            "vex.json",
            "report.html",
            "NARRATIVE.md",
            "SECURITY_REVIEW.md",
            "security.baseline.json",
        )
    )
)

_STATUSES = frozenset({"pending", "in_progress", "blocked", "done"})
_ACTIONS = frozenset({"start", "complete", "block", "unblock", "reset", "note", "evidence"})
_MAX_EVIDENCE = 64
_MAX_TEXT = 2000

DEFAULT_STATE_RELPATH = Path(".secdiagram") / "studio" / "sdlc.json"


class SdlcError(ValueError):
    """Raised when an SDLC transition or persisted state is invalid."""


class HandoffBlocked(SdlcError):
    """Raised when a handoff is requested before every phase is complete."""


@dataclass(slots=True)
class PhaseRecord:
    status: str = "pending"
    evidence: list[str] = field(default_factory=list)
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "evidence": list(self.evidence),
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PhaseRecord:
        status = str(data.get("status", "pending"))
        if status not in _STATUSES:
            raise SdlcError(f"invalid phase status: {status!r}")
        evidence_raw = data.get("evidence", [])
        if not isinstance(evidence_raw, list):
            raise SdlcError("phase evidence must be a list")
        evidence: list[str] = []
        for item in evidence_raw:
            text = _clean_text(item, "evidence")
            if text and text not in evidence:
                evidence.append(text)
        return cls(
            status=status,
            evidence=evidence[:_MAX_EVIDENCE],
            note=_clean_text(data.get("note", ""), "note"),
        )


@dataclass(slots=True)
class SdlcState:
    schema_version: int = STATE_SCHEMA_VERSION
    current: str = PHASES[0]
    phases: dict[str, PhaseRecord] = field(
        default_factory=lambda: {phase: PhaseRecord() for phase in PHASES}
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "current": self.current,
            "phases": {phase: self.phases[phase].to_dict() for phase in PHASES},
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SdlcState:
        if not isinstance(data, dict):
            raise SdlcError("SDLC state must be a JSON object")
        raw_phases = data.get("phases", {})
        if not isinstance(raw_phases, dict):
            raise SdlcError("SDLC phases must be an object")
        phases: dict[str, PhaseRecord] = {}
        for phase in PHASES:
            value = raw_phases.get(phase, {})
            if not isinstance(value, dict):
                raise SdlcError(f"phase {phase!r} must be an object")
            phases[phase] = PhaseRecord.from_dict(value)
        current = str(data.get("current", PHASES[0]))
        if current not in (*PHASES, "complete"):
            current = _first_open_phase(phases)
        return cls(schema_version=STATE_SCHEMA_VERSION, current=current, phases=phases)

    @property
    def progress(self) -> dict[str, int]:
        done = sum(1 for record in self.phases.values() if record.status == "done")
        return {"done": done, "total": len(PHASES)}

    @property
    def complete(self) -> bool:
        return all(self.phases[phase].status == "done" for phase in PHASES)


def default_state() -> SdlcState:
    """Return a fresh, deterministic SDLC state."""
    return SdlcState()


def state_path(root: str | Path) -> Path:
    """Return the project-scoped SDLC state path."""
    return Path(root) / DEFAULT_STATE_RELPATH


def load_state(root: str | Path) -> SdlcState:
    """Load SDLC state, returning a fresh state when no file exists."""
    path = state_path(root)
    if not path.is_file():
        return default_state()
    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise SdlcError(f"cannot read SDLC state at {path.name}: {exc}") from exc
    return SdlcState.from_dict(data)


def save_state(root: str | Path, state: SdlcState) -> Path:
    """Atomically persist SDLC state with deterministic JSON formatting."""
    path = state_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(state.to_dict(), indent=2, sort_keys=True) + "\n"
    _atomic_write(path, content)
    return path


def _clean_text(value: Any, label: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise SdlcError(f"{label} must be a string")
    cleaned = "".join(ch for ch in value if ch == "\n" or ch == "\t" or ch.isprintable())
    cleaned = cleaned.strip()
    return cleaned[:_MAX_TEXT]


def _first_open_phase(phases: dict[str, PhaseRecord]) -> str:
    for phase in PHASES:
        if phases[phase].status != "done":
            return phase
    return "complete"


def _previous_phases(phase: str) -> tuple[str, ...]:
    index = PHASES.index(phase)
    return PHASES[:index]


def blockers(state: SdlcState) -> list[str]:
    """Return phases that still block a complete handoff."""
    return [phase for phase in PHASES if state.phases[phase].status != "done"]


def can_start(state: SdlcState, phase: str) -> bool:
    """Return True when *phase* satisfies its entry gate."""
    _require_phase(phase)
    if state.phases[phase].status != "pending":
        return False
    return all(state.phases[prev].status == "done" for prev in _previous_phases(phase))


def _require_phase(phase: Any) -> str:
    if not isinstance(phase, str) or phase not in PHASES:
        raise SdlcError(f"unknown phase: {phase!r}; expected one of {', '.join(PHASES)}")
    return phase


def apply_action(
    state: SdlcState,
    action: str,
    phase: str,
    *,
    evidence: str | None = None,
    note: str | None = None,
) -> SdlcState:
    """Apply one lifecycle action and return the mutated state.

    Actions are deliberately small so HTTP and CLI callers share exactly the
    same transition rules.
    """
    if action not in _ACTIONS:
        raise SdlcError(f"unknown action: {action!r}; expected one of {', '.join(sorted(_ACTIONS))}")
    _require_phase(phase)
    record = state.phases[phase]

    if action == "start":
        if record.status == "done":
            raise SdlcError(f"phase {phase!r} is already done")
        if record.status == "blocked":
            raise SdlcError(f"phase {phase!r} is blocked; unblock it before starting")
        if not can_start(state, phase):
            missing = [p for p in _previous_phases(phase) if state.phases[p].status != "done"]
            raise SdlcError(f"phase {phase!r} is gated by incomplete phase(s): {', '.join(missing)}")
        record.status = "in_progress"
        state.current = phase
        return state

    if action == "complete":
        if record.status != "in_progress":
            raise SdlcError(f"phase {phase!r} must be in progress before completion")
        if evidence:
            _append_evidence(record, evidence)
        if note:
            record.note = _clean_text(note, "note")
        record.status = "done"
        state.current = _first_open_phase(state.phases)
        return state

    if action == "block":
        if record.status == "done":
            raise SdlcError(f"phase {phase!r} is already done")
        reason = _clean_text(note or evidence or "", "reason")
        if not reason:
            raise SdlcError("blocking a phase requires a reason")
        record.status = "blocked"
        record.note = reason
        state.current = phase
        return state

    if action == "unblock":
        if record.status != "blocked":
            raise SdlcError(f"phase {phase!r} is not blocked")
        record.status = "in_progress"
        state.current = phase
        return state

    if action == "reset":
        start = PHASES.index(phase)
        for downstream in PHASES[start:]:
            state.phases[downstream] = PhaseRecord()
        state.current = phase
        return state

    if action == "note":
        text = _clean_text(note, "note")
        if not text:
            raise SdlcError("note action requires a note")
        record.note = text
        return state

    if action == "evidence":
        _append_evidence(record, evidence or "")
        return state

    raise SdlcError(f"unsupported action: {action!r}")


def _append_evidence(record: PhaseRecord, evidence: str) -> None:
    text = _clean_text(evidence, "evidence")
    if not text:
        raise SdlcError("evidence must be a non-empty string")
    if text not in record.evidence:
        record.evidence.append(text)
    if len(record.evidence) > _MAX_EVIDENCE:
        del record.evidence[: len(record.evidence) - _MAX_EVIDENCE]


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collect_artifacts(out_dir: str | Path) -> list[dict[str, Any]]:
    """Return deterministic metadata for known artifacts that exist on disk."""
    base = Path(out_dir)
    artifacts: list[dict[str, Any]] = []
    for name in ARTIFACT_NAMES:
        path = base / name
        if not path.is_file():
            continue
        try:
            size = path.stat().st_size
            digest = _hash_file(path)
        except OSError:
            continue
        artifacts.append({"path": name, "bytes": size, "sha256": digest})
    return artifacts


def _severity_counts(graph: Graph) -> dict[str, int]:
    counts = {key: 0 for key in ("critical", "high", "medium", "low", "info")}
    for finding in graph.findings:
        severity = finding.severity.lower()
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def _top_findings(graph: Graph, limit: int = 10) -> list[dict[str, Any]]:
    ranked = sorted(
        graph.findings,
        key=lambda f: (
            -{"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(f.severity, 0),
            f.category,
            f.id,
        ),
    )
    out: list[dict[str, Any]] = []
    for finding in ranked[:limit]:
        ref = ""
        if finding.evidence:
            ref = finding.evidence[0].ref
        out.append(
            {
                "id": finding.id,
                "severity": finding.severity,
                "category": finding.category,
                "title": finding.title,
                "ref": ref,
            }
        )
    return out


def build_handoff(
    state: SdlcState,
    *,
    repo_name: str = "Repository",
    graph: Graph | None = None,
    out_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Build a deterministic, serialisable handoff payload."""
    blocked = blockers(state)
    findings: dict[str, Any] = {"counts": {}, "top": [], "total": 0}
    if graph is not None:
        findings = {
            "counts": _severity_counts(graph),
            "top": _top_findings(graph),
            "total": len(graph.findings),
        }

    artifacts = collect_artifacts(out_dir) if out_dir is not None else []

    next_actions: list[str] = []
    for phase in blocked:
        next_actions.append(f"Complete the {PHASE_TITLES.get(phase, phase)} phase and attach evidence.")
    if findings["counts"].get("critical", 0) or findings["counts"].get("high", 0):
        next_actions.append(
            "Remediate or explicitly accept critical/high findings before release handoff."
        )
    if not next_actions:
        next_actions.append("Attach the generated artifacts and this handoff to the change request.")

    return {
        "schema_version": STATE_SCHEMA_VERSION,
        "product": "secdiagram-studio",
        "repo": repo_name,
        "complete": not blocked,
        "current": state.current,
        "progress": state.progress,
        "phases": [
            {
                "phase": phase,
                "title": PHASE_TITLES[phase],
                "description": PHASE_DESCRIPTIONS[phase],
                "status": state.phases[phase].status,
                "evidence": copy.copy(state.phases[phase].evidence),
                "note": state.phases[phase].note,
                "expected_artifacts": list(PHASE_ARTIFACTS[phase]),
            }
            for phase in PHASES
        ],
        "findings": findings,
        "artifacts": artifacts,
        "next_actions": next_actions,
    }


def render_handoff_markdown(payload: dict[str, Any]) -> str:
    """Render a handoff payload as stable Markdown."""
    repo = _md_cell(str(payload.get("repo", "Repository")))
    complete = "yes" if payload.get("complete") else "no"
    progress = payload.get("progress", {})
    lines = [
        f"# Handoff - {repo}",
        "",
        "> Generated by secdiagram Studio. Static analysis only; no repository code was executed.",
        "",
        f"- Handoff complete: **{complete}**",
        f"- Current phase: **{_md_cell(str(payload.get('current', 'discover')))}**",
        f"- Progress: **{progress.get('done', 0)}/{progress.get('total', len(PHASES))}** phases",
        "",
        "## Phases",
        "",
        "| Phase | Status | Evidence | Notes |",
        "| :--- | :--- | :--- | :--- |",
    ]
    for entry in payload.get("phases", []):
        evidence = "<br>".join(_md_cell(item) for item in entry.get("evidence", [])) or "-"
        note = _md_cell(str(entry.get("note", ""))) or "-"
        lines.append(
            f"| {_md_cell(str(entry.get('title', entry.get('phase', ''))))} "
            f"| {_md_cell(str(entry.get('status', 'pending')))} | {evidence} | {note} |"
        )

    findings = payload.get("findings", {})
    lines.extend(
        [
            "",
            "## Security summary",
            "",
            f"- Total findings: **{findings.get('total', 0)}**",
            "- Severity: "
            + ", ".join(
                f"{name}={count}" for name, count in sorted(findings.get("counts", {}).items())
            ),
            "",
        ]
    )
    top = findings.get("top", [])
    if top:
        lines.extend(["| Severity | Category | Title | Evidence |", "| :--- | :--- | :--- | :--- |"])
        for finding in top:
            lines.append(
                f"| {_md_cell(str(finding.get('severity', '')))} "
                f"| {_md_cell(str(finding.get('category', '')))} "
                f"| {_md_cell(str(finding.get('title', '')))} "
                f"| {_md_cell(str(finding.get('ref', ''))) or '-'} |"
            )
        lines.append("")

    artifacts = payload.get("artifacts", [])
    lines.extend(["## Artifacts", ""])
    if artifacts:
        lines.extend(["| Artifact | Bytes | SHA-256 |", "| :--- | ---: | :--- |"])
        for artifact in artifacts:
            lines.append(
                f"| {_md_cell(str(artifact.get('path', '')))} "
                f"| {int(artifact.get('bytes', 0))} "
                f"| `{str(artifact.get('sha256', ''))}` |"
            )
    else:
        lines.append("No artifacts were found in the output directory.")
    lines.append("")

    lines.extend(["## Next actions", ""])
    for action in payload.get("next_actions", []):
        lines.append(f"- {_md_cell(str(action))}")
    lines.append("")
    return "\n".join(lines)


def _md_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ").strip()


def render_phase_brief(state: SdlcState, phase: str, *, repo_name: str = "Repository") -> str:
    """Render a focused brief for the agent taking over *phase*."""
    _require_phase(phase)
    record = state.phases[phase]
    previous = _previous_phases(phase)
    lines = [
        f"# {PHASE_TITLES[phase]} phase brief - {_md_cell(repo_name)}",
        "",
        PHASE_DESCRIPTIONS[phase],
        "",
        f"- Status: **{record.status}**",
        f"- Entry gate: **{'open' if can_start(state, phase) else 'closed'}**",
        "",
        "## Inputs from prior phases",
        "",
    ]
    if previous:
        for prev in previous:
            status = state.phases[prev].status
            evidence = ", ".join(state.phases[prev].evidence) or "no evidence recorded"
            lines.append(f"- **{PHASE_TITLES[prev]}** ({status}): {_md_cell(evidence)}")
    else:
        lines.append("- None; this is the first phase.")
    lines.extend(["", "## Expected outputs", ""])
    for artifact in PHASE_ARTIFACTS[phase]:
        lines.append(f"- `{artifact}`")
    lines.extend(["", "## Evidence recorded", ""])
    if record.evidence:
        for item in record.evidence:
            lines.append(f"- {_md_cell(item)}")
    else:
        lines.append("- No evidence recorded yet.")
    if record.note:
        lines.extend(["", "## Notes", "", _md_cell(record.note)])
    lines.append("")
    return "\n".join(lines)


def write_handoff(
    out_dir: str | Path,
    state: SdlcState,
    *,
    repo_name: str = "Repository",
    graph: Graph | None = None,
    artifact_dir: str | Path | None = None,
) -> tuple[Path, Path]:
    """Write deterministic Markdown and JSON handoff artifacts.

    ``out_dir`` receives ``HANDOFF.md``/``handoff.json`` while
    ``artifact_dir`` (the standard ``.secdiagram`` output directory) is hashed
    for the artifact inventory.
    """
    if blockers(state):
        raise HandoffBlocked(
            "handoff requires all phases to be done; incomplete: " + ", ".join(blockers(state))
        )
    base = Path(out_dir)
    artifact_base = Path(artifact_dir) if artifact_dir is not None else base
    payload = build_handoff(state, repo_name=repo_name, graph=graph, out_dir=artifact_base)
    markdown = render_handoff_markdown(payload)
    json_path = base / "handoff.json"
    md_path = base / "HANDOFF.md"
    _atomic_write(json_path, json.dumps(payload, indent=2, sort_keys=True) + "\n")
    _atomic_write(md_path, markdown)
    return md_path, json_path
