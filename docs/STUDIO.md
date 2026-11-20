# Agentic Studio & AI-Skill Installer

`secdiagram studio` combines a user-level installer, a portable agent skill, and a hardened
browser workspace for architecture and security reviews. It follows the deployment shape of
Unsloth Studio -- a per-user home, a private virtual environment, and local launch scripts --
while preserving secdiagram's core guarantee: **the runtime is Python standard library only**.

The Studio UI is a dependency-free HTML/CSS/JavaScript single-page app. It is served by the
existing hardened platform server, so there is no FastAPI, React, npm runtime, or CDN request
in the analysis path.

---

## 1. Install the Studio and Agent Skill

```bash
# Create ~/.secdiagram/studio with a private venv, launchers, and the skill:
secdiagram studio install

# Explicit locations (useful for containers and air-gapped operators):
secdiagram studio install --home /opt/secdiagram-studio --project-root /opt/secdiagram

# Skip venv creation when the host already provides Python:
secdiagram studio install --no-venv

# Inspect or remove managed files:
secdiagram studio status --json
secdiagram studio uninstall --keep-venv
```

`SECDIAGRAM_STUDIO_HOME` overrides the default home. The installer writes only inside that
home and records every managed file with its size and SHA-256 in `manifest.json`. It never
edits the analyzed repository. Uninstall skips paths that escape the home directory or that
were not recorded in the manifest.

Installed layout:

```text
~/.secdiagram/studio/
  manifest.json
  project-root.txt
  README.md
  bin/secdiagram-studio        # POSIX
  bin/secdiagram-studio.cmd    # Windows CMD
  bin/secdiagram-studio.ps1    # PowerShell
  skills/secdiagram-diagramming/
    SKILL.md
    skill.json
  venv/                        # unless --no-venv
```

The skill is deliberately portable: point any compatible agent at `SKILL.md` and `skill.json`,
or copy the directory into your agent's skills folder. The manifest lists deterministic
commands, expected artifacts, and the project's safety guardrails.

---

## 2. Launch the Studio

```bash
# Authenticated loopback server (recommended):
secdiagram studio serve --dir . --user analyst --password 'change-me'

# Local-only development without authentication (explicitly insecure):
secdiagram studio serve --dir . --insecure-no-auth
```

Open `http://127.0.0.1:8080/studio`. `studio serve` forwards all flags to `secdiagram serve`,
so authentication, rate limiting, request caps, read-only mode, audit logging, and scan-root
containment behave exactly as documented in [SERVER_API.md](SERVER_API.md).

The installer itself is **CLI-only**. The HTTP API exposes read-only installer status and
rejects installer writes with `403 Forbidden`.

---

## 3. Studio Workspace

| Panel | Purpose |
| :--- | :--- |
| **Overview** | Repository name, languages, node/edge/component counts, risk-ranked findings, and artifact status. |
| **Diagram** | Render architecture, high-level C4, overview, or attack-path diagrams. Rename or hide nodes, choose direction/theme, and export Mermaid or a local image. |
| **SDLC** | Drive the five phases, attach evidence, block/unblock, and preview the next agent handoff. |
| **AI Review** | Request an evidence-grounded narrative from local Ollama or an OpenAI-compatible endpoint with an explicit provider, model, template, and base URL. |
| **Installer** | Read-only view of the user-level Studio home, skill, launcher, and virtualenv status. |

Edits are stored separately from the analysis:

- `.secdiagram/studio/diagram-overrides.json` -- renames, hidden nodes, direction, theme.
- `.secdiagram/studio/sdlc.json` -- phase status, evidence, and notes.
- `.secdiagram/studio/HANDOFF.md` and `handoff.json` -- only written after every phase is done.

The source graph is never mutated. Re-running the analysis and re-applying the overrides
produces the same edited graph.

---

## 4. SDLC Phase Handoff

The Studio treats an engagement as a deterministic state machine:

1. **Discover** -- inventory languages, manifests, and entry points (`graph.json`).
2. **Model** -- compile the architecture and C4 diagrams.
3. **Secure** -- run SAST, IaC, risk scoring, threat modeling, and policy gates.
4. **Review** -- attach narrative and reviewer sign-off.
5. **Handoff** -- package artifacts and a machine-readable handoff.

A phase can start only when every previous phase is `done`. A handoff write is refused with
`409 Conflict` until all five phases are complete. Evidence is bounded, deduplicated, and
recorded per phase.

The handoff payload includes:

- phase status, evidence, notes, and expected artifacts;
- severity counts and the highest-ranked findings with `path:line` references;
- SHA-256 records for known artifacts in `.secdiagram/`;
- explicit next actions for the receiving agent.

`HANDOFF.md` is stable Markdown; `handoff.json` is sorted JSON. Both can be attached directly
to a change request or consumed by CI.

---

## 5. Local AI Reviews

The AI panel supports:

- `provider=ollama` with a local base URL such as `http://127.0.0.1:11434`;
- `provider=openai` with `https://api.openai.com` (or a private OpenAI-compatible endpoint);
- templates `comprehensive`, `threat-model`, `remediation`, and `compliance`.

The server rejects link-local targets such as `169.254.169.254`, accepts only loopback/private
addresses and OpenAI hosts, and never logs the API key. Use the CLI for any other endpoint.
Narratives are optional: the Studio remains fully useful offline with static analysis only.

---

## 6. Security Model

- Authentication is required unless `--insecure-no-auth` is used on loopback.
- State-changing POSTs reject cross-origin `Origin` values.
- Request bodies are bounded; installer writes are unavailable over HTTP.
- Overrides are capped at 1 MiB and 5,000 entries, with strict schema validation.
- Diagram text is sent with the server's standard security headers and no remote assets.
- Image rendering uses local `mmdc`; if it is missing the endpoint returns `503` instead of
  silently calling a remote service.
- The analyzed repository is parsed statically. No repository code is imported or executed.

---

## 7. Keyboard and Accessibility

The Studio is designed to be usable without a mouse:

- Press `Tab` once to reveal **Skip to content**; `Enter` moves focus to the main workspace.
- Section tabs support `Tab`, `Shift+Tab`, arrow keys, `Home`, and `End`. Selecting a tab
  updates `aria-selected`, the visible panel, and the document title.
- Every input, select, textarea, and generated node control has an accessible name.
- Async actions set `aria-busy`; results and failures are announced through polite and
  assertive live regions, not only through the visual toast.
- The diagram preview, Mermaid source, component list, handoff preview, AI narrative, and
  skill preview are keyboard-focusable scroll regions.
- Toggle buttons expose `aria-expanded`; the SDLC progress bar exposes progressbar values.
- Status is never communicated by color alone; every state also has text.
- `prefers-reduced-motion` disables panel fades, progress transitions, and button movement.
- Narrow layouts wrap toolbars and long paths, and code/diagram panels scroll instead of
  truncating content.

Accessibility changes are checked with static asset tests, but no screen-reader
certification is implied. Validate changes with the assistive technology you support.

---

## 8. Verification

```bash
python -m unittest tests.test_agentic tests.test_diagram_edit \
  tests.test_studio_installer tests.test_studio_server \
  tests.test_studio_ui_accessibility -v
node --check secdiagram_core/studio_ui/app.js
```

The tests cover phase gates, deterministic state/handoff files, override validation and
non-mutation, installer containment and idempotency, Studio asset serving, read-only mode,
origin rejection, SSRF rejection, the complete phase flow through the REST API, and the
Studio's landmark, tab, labelling, live-region, focus, and reduced-motion hooks.
