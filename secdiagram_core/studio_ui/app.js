"use strict";

const PHASE_TITLES = {
  discover: "Discover",
  model: "Model",
  secure: "Secure",
  review: "Review",
  handoff: "Handoff",
};

const VIEW_META = {
  dashboard: ["Overview", "Deterministic architecture intelligence for this repository."],
  diagram: ["Diagram studio", "Render, edit, and persist diagram overrides without touching the analysis."],
  pipeline: ["Agentic SDLC", "Move evidence between phases and gate the final handoff."],
  ai: ["AI review", "Ask a local Ollama model or an OpenAI-compatible endpoint for an evidence-grounded review."],
  installer: ["AI skill installer", "Inspect the user-level Studio install and the portable agent skill."],
};

const state = {
  view: "dashboard",
  detail: "architecture",
  summary: null,
  sdlc: null,
  overrides: { renames: {}, hidden: [], direction: null, theme: null },
  edits: { renames: {}, hidden: new Set() },
  nodes: [],
  filter: "",
  installer: null,
};

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key === "html") node.innerHTML = value;
    else if (key === "dataset") Object.assign(node.dataset, value);
    else if (key.startsWith("on") && typeof value === "function") node.addEventListener(key.slice(2).toLowerCase(), value);
    else if (value !== undefined && value !== null) node.setAttribute(key, value);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function toast(message, bad = false) {
  const box = $("#toast");
  box.textContent = message;
  box.classList.toggle("bad", bad);
  box.classList.add("show");
  window.clearTimeout(toast._timer);
  toast._timer = window.setTimeout(() => box.classList.remove("show"), 4200);
}

async function api(path, options = {}) {
  const opts = { method: options.method || "GET", headers: { Accept: "application/json" } };
  if (options.body !== undefined) {
    opts.body = JSON.stringify(options.body);
    opts.headers["Content-Type"] = "application/json";
  }
  if (options.signal) opts.signal = options.signal;
  const response = await fetch(path, opts);
  const type = response.headers.get("content-type") || "";
  if (!response.ok) {
    let message = `${response.status} ${response.statusText}`;
    try {
      if (type.includes("application/json")) {
        const payload = await response.json();
        message = payload.message || payload.error || message;
      } else {
        const text = await response.text();
        if (text) message = text.slice(0, 300);
      }
    } catch (_) { /* keep status text */ }
    throw new Error(message);
  }
  if (type.includes("application/json")) return response.json();
  return response.text();
}

function setView(name) {
  if (!VIEW_META[name]) name = "dashboard";
  state.view = name;
  $$(".navbtn").forEach((btn) => btn.classList.toggle("active", btn.dataset.view === name));
  $$(".view").forEach((view) => view.classList.toggle("active", view.id === `view-${name}`));
  const [title, subtitle] = VIEW_META[name];
  $("#view-title").textContent = title;
  $("#view-sub").textContent = subtitle;
  if (name === "diagram") loadDiagram();
  if (name === "installer") loadInstaller();
  if (name === "pipeline") loadPipeline();
}

async function loadCore() {
  const results = await Promise.allSettled([
    api("/api/v1/health"),
    api("/api/v1/summary"),
    api("/api/v1/studio/sdlc"),
    api("/api/v1/studio/overrides"),
    api("/api/v1/studio/nodes"),
  ]);
  const [health, summary, sdlc, overrides, nodes] = results;
  if (health.status === "fulfilled") {
    const pill = $("#health");
    pill.textContent = `online · v${health.value.version}`;
    pill.classList.add("ok");
    $("#side-version").textContent = `v${health.value.version}`;
    $("#side-repo").textContent = health.value.repo || "repository";
  } else {
    const pill = $("#health");
    pill.textContent = "offline";
    pill.classList.add("bad");
  }
  if (summary.status === "fulfilled") state.summary = summary.value;
  if (sdlc.status === "fulfilled") state.sdlc = sdlc.value;
  if (overrides.status === "fulfilled") {
    state.overrides = overrides.value.overrides || state.overrides;
    syncEditsFromOverrides();
  }
  if (nodes.status === "fulfilled") state.nodes = nodes.value.nodes || [];
  renderDashboard();
  renderPipeline();
  if (state.view === "diagram") loadDiagram();
}

function syncEditsFromOverrides() {
  state.edits.renames = { ...(state.overrides.renames || {}) };
  state.edits.hidden = new Set(state.overrides.hidden || []);
  $("#direction").value = state.overrides.direction || "";
  $("#theme").value = state.overrides.theme || "";
}

function renderDashboard() {
  const s = state.summary;
  $("#stat-nodes").textContent = s ? s.nodes_count : "-";
  $("#stat-edges").textContent = s ? s.edges_count : "-";
  $("#stat-findings").textContent = s ? s.findings_count : "-";
  if (state.sdlc) {
    const done = state.sdlc.progress ? state.sdlc.progress.done : 0;
    const total = state.sdlc.progress ? state.sdlc.progress.total : 5;
    $("#stat-phases").textContent = `${done}/${total}`;
  }

  const bars = $("#sev-bars");
  bars.replaceChildren();
  const severities = s && s.severities ? s.severities : {};
  const total = Object.values(severities).reduce((sum, value) => sum + value, 0);
  $("#sev-total").textContent = `${total} findings`;
  const max = Math.max(1, ...Object.values(severities));
  for (const name of ["critical", "high", "medium", "low", "info"]) {
    const count = severities[name] || 0;
    const width = Math.max(2, Math.round((count / max) * 100));
    bars.append(
      el("div", { class: `bar ${name}` },
        el("span", { text: name }),
        el("div", { class: "track" }, el("div", { class: "fill", style: `width:${width}%` })),
        el("span", { class: "mono", text: String(count) })
      )
    );
  }
  if (!total) bars.append(el("p", { class: "muted", text: "No findings reported for this scan." }));

  const timeline = $("#phase-mini");
  timeline.replaceChildren();
  if (state.sdlc) {
    for (const phase of state.sdlc.phases) {
      timeline.append(
        el("li", {},
          el("span", { class: `dot ${phase.status}` }),
          el("span", { text: `${phase.title}` }),
          el("span", { class: "muted", text: phase.status.replace("_", " ") })
        )
      );
    }
  }

  const artifacts = $("#artifact-list");
  artifacts.replaceChildren();
  const names = ["diagram-highlevel.mmd", "diagram.mmd", "diagram-taint.mmd", "graph.json", "ARCHITECTURE.md", "THREAT_MODEL.md", "security.sarif", "vex.json", "report.html"];
  for (const name of names) artifacts.append(el("span", { class: "chip", text: name }));
}

function renderPipeline() {
  if (!state.sdlc) return;
  const grid = $("#phase-cards");
  grid.replaceChildren();
  const done = state.sdlc.progress ? state.sdlc.progress.done : 0;
  const total = state.sdlc.progress ? state.sdlc.progress.total : 5;
  $("#phase-progress").style.width = `${Math.round((done / total) * 100)}%`;

  for (const phase of state.sdlc.phases) {
    const evidence = el("textarea", {
      class: "phase-evidence",
      "aria-label": `Evidence for ${phase.title}`,
      placeholder: "Evidence, e.g. graph.json or security.sarif",
      id: `evidence-${phase.phase}`,
    });
    if (phase.note) evidence.value = phase.note;
    const actions = el("div", { class: "phase-actions" });
    const defs = [
      ["start", "Start", phase.status === "pending"],
      ["complete", "Complete", phase.status === "in_progress"],
      ["unblock", "Unblock", phase.status === "blocked"],
      ["block", "Block", phase.status !== "done" && phase.status !== "blocked"],
      ["reset", "Reset", phase.status !== "pending"],
    ];
    for (const [action, label, shown] of defs) {
      if (!shown) continue;
      actions.append(el("button", {
        class: `btn small ${action === "complete" ? "primary" : action === "reset" ? "danger" : ""}`,
        dataset: { action, phase: phase.phase },
        text: label,
        onclick: () => phaseAction(action, phase.phase),
      }));
    }
    const expected = (phase.expected_artifacts || []).join(" · ");
    grid.append(
      el("article", { class: "phase" },
        el("header", {},
          el("div", {}, el("div", { class: "num", text: String(state.sdlc.phases.indexOf(phase) + 1).padStart(2, "0") }), el("strong", { text: phase.title })),
          el("span", { class: `pill ${phase.status === "done" ? "ok" : phase.status === "blocked" ? "bad" : ""}`, text: phase.status.replace("_", " ") })
        ),
        el("p", { text: phase.description }),
        el("div", { class: "evidence", text: expected || "No expected artifacts." }),
        el("div", { class: "evidence", text: (phase.evidence || []).join("\n") || "No evidence recorded." }),
        evidence,
        actions
      )
    );
  }
}

async function phaseAction(action, phase) {
  const input = document.getElementById(`evidence-${phase}`);
  const note = input ? input.value.trim() : "";
  try {
    const payload = { action, phase };
    if (action === "block") payload.note = note || "Blocked from Studio";
    else if (note) payload.evidence = note;
    const result = await api("/api/v1/studio/sdlc", { method: "POST", body: payload });
    state.sdlc = result.state;
    renderPipeline();
    renderDashboard();
    toast(`${PHASE_TITLES[phase] || phase}: ${action} ok`);
  } catch (error) {
    toast(error.message, true);
  }
}

async function previewHandoff(write) {
  try {
    const path = "/api/v1/studio/handoff";
    const markdown = write
      ? (await api(path, { method: "POST", body: { write: true } })).markdown
      : await api(path);
    const output = $("#handoff-output");
    output.textContent = markdown;
    output.classList.remove("hidden");
    toast(write ? "Handoff written to .secdiagram/studio/HANDOFF.md" : "Handoff preview generated");
  } catch (error) {
    toast(error.message, true);
  }
}

function diagramParams() {
  const params = new URLSearchParams({ detail: state.detail });
  const direction = $("#direction").value;
  const theme = $("#theme").value;
  if (direction) params.set("direction", direction);
  if (theme) params.set("theme", theme);
  return params.toString();
}

async function loadDiagram() {
  if (!state.nodes.length || !state.summary) {
    try {
      const result = await api("/api/v1/studio/nodes");
      state.nodes = result.nodes || [];
    } catch (_) { /* keep current */ }
  }
  renderNodeList();
  try {
    const source = await api(`/api/v1/studio/diagram?${diagramParams()}`);
    $("#mermaid-source").textContent = source;
  } catch (error) {
    $("#mermaid-source").textContent = `Could not load diagram: ${error.message}`;
  }
  renderOverridesMeta();
}

async function renderSvg() {
  const button = $("#render-svg");
  button.disabled = true;
  button.textContent = "Rendering…";
  try {
    const response = await fetch(`/api/v1/studio/render?${diagramParams()}`);
    if (!response.ok) {
      let message = `Render failed (${response.status})`;
      try {
        const payload = await response.json();
        message = payload.message || payload.error || message;
      } catch (_) { /* ignore */ }
      throw new Error(message);
    }
    const svg = await response.text();
    const url = URL.createObjectURL(new Blob([svg], { type: "image/svg+xml" }));
    const preview = $("#diagram-preview");
    preview.replaceChildren(el("img", { src: url, alt: "Rendered architecture diagram" }));
    toast("Rendered locally with Mermaid CLI");
  } catch (error) {
    const preview = $("#diagram-preview");
    preview.replaceChildren(
      el("div", { class: "placeholder" },
        el("div", { text: "Local SVG rendering is unavailable." }),
        el("div", { class: "muted", text: error.message }),
        el("div", { class: "muted", text: "The Mermaid source is still available; install mmdc or use the container image for offline rendering." })
      )
    );
    toast(error.message, true);
  } finally {
    button.disabled = false;
    button.textContent = "Render SVG";
  }
}

function renderNodeList() {
  const list = $("#node-list");
  if (!list) return;
  list.replaceChildren();
  const filter = state.filter.toLowerCase();
  const nodes = state.nodes
    .filter((node) => !filter || `${node.name} ${node.kind} ${node.path || ""}`.toLowerCase().includes(filter))
    .slice(0, 400);
  if (!nodes.length) {
    list.append(el("p", { class: "muted", text: "No matching nodes." }));
    return;
  }
  for (const node of nodes) {
    const checkbox = el("input", {
      type: "checkbox",
      title: "Hide from diagram",
      checked: state.edits.hidden.has(node.id) ? "checked" : null,
      onchange: (event) => {
        if (event.target.checked) state.edits.hidden.add(node.id);
        else state.edits.hidden.delete(node.id);
      },
    });
    const input = el("input", {
      type: "text",
      value: state.edits.renames[node.id] || "",
      placeholder: node.name,
      "aria-label": `Rename ${node.name}`,
      oninput: (event) => {
        const value = event.target.value.trim();
        if (value) state.edits.renames[node.id] = value;
        else delete state.edits.renames[node.id];
      },
    });
    list.append(
      el("div", { class: "node" },
        checkbox,
        el("div", { class: "row" },
          input,
          el("div", { class: "meta", text: `${node.kind} · ${node.name}${node.path ? ` · ${node.path}` : ""}` })
        )
      )
    );
  }
}

function renderOverridesMeta() {
  const countR = Object.keys(state.edits.renames).length;
  const countH = state.edits.hidden.size;
  const bits = [];
  if (countR) bits.push(`${countR} rename${countR === 1 ? "" : "s"}`);
  if (countH) bits.push(`${countH} hidden`);
  $("#override-meta").textContent = bits.length ? `Unsaved: ${bits.join(", ")}` : "No unsaved edits";
}

async function saveOverrides() {
  const payload = {
    renames: state.edits.renames,
    hidden: Array.from(state.edits.hidden),
    direction: $("#direction").value || null,
    theme: $("#theme").value || null,
  };
  try {
    const result = await api("/api/v1/studio/overrides", { method: "POST", body: payload });
    state.overrides = result.overrides;
    syncEditsFromOverrides();
    renderOverridesMeta();
    await loadDiagram();
    toast("Diagram overrides saved");
  } catch (error) {
    toast(error.message, true);
  }
}

async function resetOverrides() {
  try {
    const result = await api("/api/v1/studio/overrides", { method: "POST", body: { action: "reset" } });
    state.overrides = result.overrides;
    syncEditsFromOverrides();
    renderNodeList();
    renderOverridesMeta();
    await loadDiagram();
    toast("Diagram overrides reset");
  } catch (error) {
    toast(error.message, true);
  }
}

async function generateAi() {
  const button = $("#generate-ai");
  const output = $("#ai-output");
  const status = $("#ai-status");
  button.disabled = true;
  status.textContent = "working…";
  output.textContent = "Waiting for the model…";
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), 180000);
  try {
    const result = await api("/api/v1/studio/generate", {
      method: "POST",
      signal: controller.signal,
      body: {
        provider: $("#llm-provider").value,
        model: $("#llm-model").value.trim() || null,
        base_url: $("#llm-base").value.trim() || null,
        template: $("#llm-template").value,
      },
    });
    output.textContent = result.narrative || "The model returned no narrative.";
    status.textContent = "ready";
    toast("AI review generated");
  } catch (error) {
    output.textContent = `Generation failed: ${error.message}`;
    status.textContent = "failed";
    toast(error.message, true);
  } finally {
    window.clearTimeout(timer);
    button.disabled = false;
  }
}

async function loadInstaller() {
  try {
    const [status, skill] = await Promise.all([
      api("/api/v1/studio/status"),
      api("/api/v1/studio/skill").catch(() => null),
    ]);
    state.installer = status;
    const pill = $("#installer-pill");
    pill.textContent = status.installed ? (status.healthy ? "healthy" : "needs attention") : "not installed";
    pill.className = `pill ${status.installed && status.healthy ? "ok" : status.installed ? "bad" : ""}`;
    const kv = $("#installer-kv");
    kv.replaceChildren();
    const rows = [
      ["Installed", status.installed ? "yes" : "no"],
      ["Home", status.home],
      ["Version", `${status.version} (current ${status.current_version})`],
      ["Profile", status.profile || "-"],
      ["Project root", status.project_root || "-"],
      ["Virtualenv", status.venv_present ? "present" : "not created"],
      ["Skill", status.skill_installed ? status.skill_path : "not installed"],
      ["Launcher", status.launcher_present ? "present" : "not installed"],
    ];
    for (const [key, value] of rows) {
      kv.append(el("dt", { text: key }), el("dd", { text: String(value) }));
    }
    if (skill) {
      const preview = skill.markdown || JSON.stringify(skill.manifest || {}, null, 2);
      $("#skill-preview").textContent = preview;
    } else {
      $("#skill-preview").textContent = "No skill manifest is installed. Run `secdiagram studio install`.";
    }
  } catch (error) {
    $("#installer-pill").textContent = "unavailable";
    $("#installer-pill").className = "pill bad";
    toast(error.message, true);
  }
}

async function rescan() {
  const button = $("#rescan");
  button.disabled = true;
  button.textContent = "Scanning…";
  try {
    await api("/api/v1/scan", { method: "POST", body: {} });
    await loadCore();
    toast("Repository rescanned");
  } catch (error) {
    toast(error.message, true);
  } finally {
    button.disabled = false;
    button.textContent = "Rescan";
  }
}

function bindEvents() {
  $$(".navbtn").forEach((button) => button.addEventListener("click", () => setView(button.dataset.view)));
  $$("[data-goto]").forEach((button) => button.addEventListener("click", () => setView(button.dataset.goto)));
  $("#rescan").addEventListener("click", rescan);

  $$("#detail-seg button").forEach((button) => {
    button.addEventListener("click", () => {
      state.detail = button.dataset.detail;
      $$("#detail-seg button").forEach((item) => item.classList.toggle("active", item === button));
      loadDiagram();
    });
  });
  $("#render-svg").addEventListener("click", renderSvg);
  $("#show-source").addEventListener("click", () => $("#mermaid-source").classList.toggle("hidden"));
  $("#save-overrides").addEventListener("click", saveOverrides);
  $("#reset-overrides").addEventListener("click", resetOverrides);
  $("#node-filter").addEventListener("input", (event) => {
    state.filter = event.target.value;
    renderNodeList();
  });
  $("#direction").addEventListener("change", () => { renderOverridesMeta(); if (state.view === "diagram") loadDiagram(); });
  $("#theme").addEventListener("change", () => { renderOverridesMeta(); if (state.view === "diagram") loadDiagram(); });

  $("#handoff-preview").addEventListener("click", () => previewHandoff(false));
  $("#handoff-write").addEventListener("click", () => previewHandoff(true));
  $("#generate-ai").addEventListener("click", generateAi);
  $("#llm-provider").addEventListener("change", (event) => {
    $("#llm-base").placeholder = event.target.value === "ollama" ? "http://localhost:11434" : "https://api.openai.com/v1";
  });

  $$("[data-copy]").forEach((button) => button.addEventListener("click", async () => {
    const text = button.dataset.copy;
    try {
      await navigator.clipboard.writeText(text);
      toast("Command copied");
    } catch (_) {
      toast(text);
    }
  }));
}

document.addEventListener("DOMContentLoaded", async () => {
  bindEvents();
  await loadCore();
  setView("dashboard");
});
