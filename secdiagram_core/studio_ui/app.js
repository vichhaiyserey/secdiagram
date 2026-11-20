"use strict";

const PHASE_TITLES = {
  discover: "Discover",
  model: "Model",
  secure: "Secure",
  review: "Review",
  handoff: "Handoff",
};

const DETAIL_LABELS = {
  architecture: "architecture",
  "high-level": "high-level C4",
  taint: "attack paths",
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
  renderUrl: null,
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

function announce(message, bad = false) {
  const status = $("#status-live");
  const error = $("#error-live");
  if (!status || !error) return;
  status.textContent = "";
  error.textContent = "";
  window.requestAnimationFrame(() => {
    (bad ? error : status).textContent = message;
  });
}

function toast(message, bad = false) {
  const box = $("#toast");
  box.textContent = message;
  box.classList.toggle("bad", bad);
  box.classList.add("show");
  announce(message, bad);
  window.clearTimeout(toast._timer);
  toast._timer = window.setTimeout(() => box.classList.remove("show"), 4200);
}

function setBusy(target, busy) {
  const node = typeof target === "string" ? $(target) : target;
  if (node) node.setAttribute("aria-busy", busy ? "true" : "false");
}

function setPanelStatus(id, text, bad = false) {
  const node = document.getElementById(id);
  if (!node) return;
  node.textContent = text;
  node.classList.toggle("bad", bad);
}

function failureMessage(result) {
  const reason = result ? result.reason : null;
  return reason && reason.message ? reason.message : "request failed";
}

function formatStatus(status) {
  return String(status || "").replace(/_/g, " ");
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

function setView(name, options = {}) {
  if (!VIEW_META[name]) name = "dashboard";
  state.view = name;
  $$("#nav [role=tab]").forEach((button) => {
    const selected = button.dataset.view === name;
    button.classList.toggle("active", selected);
    button.setAttribute("aria-selected", selected ? "true" : "false");
    button.tabIndex = selected ? 0 : -1;
  });
  $$(".view").forEach((view) => {
    const selected = view.id === `view-${name}`;
    view.classList.toggle("active", selected);
    view.setAttribute("aria-hidden", selected ? "false" : "true");
  });
  const [title, subtitle] = VIEW_META[name];
  $("#view-title").textContent = title;
  $("#view-sub").textContent = subtitle;
  document.title = `${title} · secdiagram Studio`;
  if (options.focusTab) {
    const tab = document.getElementById(`tab-${name}`);
    if (tab) tab.focus();
  }
  if (name === "diagram") loadDiagram();
  if (name === "installer") loadInstaller();
  if (name === "pipeline") loadPipeline();
}

async function loadCore() {
  setBusy("#view-dashboard", true);
  setPanelStatus("dashboard-status", "Loading repository summary…");
  const results = await Promise.allSettled([
    api("/api/v1/health"),
    api("/api/v1/summary"),
    api("/api/v1/studio/sdlc"),
    api("/api/v1/studio/overrides"),
    api("/api/v1/studio/nodes"),
  ]);
  const [health, summary, sdlc, overrides, nodes] = results;
  const pill = $("#health");
  if (health.status === "fulfilled") {
    pill.textContent = `online · v${health.value.version}`;
    pill.classList.add("ok");
    pill.classList.remove("bad");
    $("#side-version").textContent = `v${health.value.version}`;
    $("#side-repo").textContent = health.value.repo || "repository";
  } else {
    pill.textContent = "offline";
    pill.classList.add("bad");
    pill.classList.remove("ok");
  }
  if (summary.status === "fulfilled") {
    state.summary = summary.value;
    setPanelStatus(
      "dashboard-status",
      `${summary.value.nodes_count} nodes, ${summary.value.edges_count} edges, ${summary.value.findings_count} findings.`,
    );
  } else {
    setPanelStatus("dashboard-status", `Summary unavailable: ${failureMessage(summary)}`, true);
  }
  if (sdlc.status === "fulfilled") {
    state.sdlc = sdlc.value;
    const done = sdlc.value.progress ? sdlc.value.progress.done : 0;
    const total = sdlc.value.progress ? sdlc.value.progress.total : 5;
    setPanelStatus("pipeline-status", `${done} of ${total} phases complete.`);
  } else {
    setPanelStatus("pipeline-status", `Pipeline unavailable: ${failureMessage(sdlc)}`, true);
  }
  if (overrides.status === "fulfilled") {
    state.overrides = overrides.value.overrides || state.overrides;
    syncEditsFromOverrides();
  } else {
    setPanelStatus("diagram-status", `Overrides unavailable: ${failureMessage(overrides)}`, true);
  }
  if (nodes.status === "fulfilled") {
    state.nodes = nodes.value.nodes || [];
  } else {
    setPanelStatus("diagram-status", `Components unavailable: ${failureMessage(nodes)}`, true);
  }
  renderDashboard();
  renderPipeline();
  if (state.view === "diagram") loadDiagram();
  setBusy("#view-dashboard", false);
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
    const label = `${name.charAt(0).toUpperCase()}${name.slice(1)}: ${count} finding${count === 1 ? "" : "s"}`;
    bars.append(
      el("div", { class: `bar ${name}`, role: "listitem", "aria-label": label },
        el("span", { text: name, "aria-hidden": "true" }),
        el("div", { class: "track", "aria-hidden": "true" }, el("div", { class: "fill", style: `width:${width}%` })),
        el("span", { class: "mono", text: String(count), "aria-hidden": "true" })
      )
    );
  }
  if (!total) bars.append(el("p", { class: "muted", role: "listitem", text: "No findings reported for this scan." }));

  const timeline = $("#phase-mini");
  timeline.replaceChildren();
  if (state.sdlc) {
    for (const phase of state.sdlc.phases) {
      timeline.append(
        el("li", {},
          el("span", { class: `dot ${phase.status}`, "aria-hidden": "true" }),
          el("span", { text: `${phase.title}` }),
          el("span", { class: "muted", text: formatStatus(phase.status) })
        )
      );
    }
  } else {
    timeline.append(el("li", { class: "muted", text: "Pipeline state is unavailable." }));
  }

  const artifacts = $("#artifact-list");
  artifacts.replaceChildren();
  const names = ["diagram-highlevel.mmd", "diagram.mmd", "diagram-taint.mmd", "graph.json", "ARCHITECTURE.md", "THREAT_MODEL.md", "security.sarif", "vex.json", "report.html"];
  for (const name of names) artifacts.append(el("span", { class: "chip", text: name }));
}

async function loadPipeline() {
  setBusy("#view-pipeline", true);
  setPanelStatus("pipeline-status", "Loading pipeline state…");
  try {
    state.sdlc = await api("/api/v1/studio/sdlc");
    renderPipeline();
    renderDashboard();
    const done = state.sdlc.progress ? state.sdlc.progress.done : 0;
    const total = state.sdlc.progress ? state.sdlc.progress.total : 5;
    setPanelStatus("pipeline-status", `${done} of ${total} phases complete.`);
  } catch (error) {
    setPanelStatus("pipeline-status", error.message, true);
    toast(error.message, true);
  } finally {
    setBusy("#view-pipeline", false);
  }
}

function renderPipeline(focusPhase = null) {
  const grid = $("#phase-cards");
  const progress = $(".progress");
  if (!state.sdlc) {
    grid.replaceChildren(el("p", { class: "muted", text: "Pipeline state is unavailable." }));
    $("#phase-progress").style.width = "0%";
    if (progress) {
      progress.setAttribute("aria-valuenow", "0");
      progress.setAttribute("aria-valuetext", "Pipeline state unavailable");
    }
    return;
  }
  grid.replaceChildren();
  const done = state.sdlc.progress ? state.sdlc.progress.done : 0;
  const total = state.sdlc.progress ? state.sdlc.progress.total : 5;
  $("#phase-progress").style.width = `${Math.round((done / total) * 100)}%`;
  if (progress) {
    progress.setAttribute("aria-valuenow", String(done));
    progress.setAttribute("aria-valuemax", String(total));
    progress.setAttribute("aria-valuetext", `${done} of ${total} phases complete`);
  }

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
        type: "button",
        class: `btn small ${action === "complete" ? "primary" : action === "reset" ? "danger" : ""}`,
        dataset: { action, phase: phase.phase },
        text: label,
        onclick: () => phaseAction(action, phase.phase),
      }));
    }
    const expected = (phase.expected_artifacts || []).join(" · ");
    grid.append(
      el("article", {
        class: "phase",
        id: `phase-${phase.phase}`,
        tabindex: "-1",
        "aria-labelledby": `phase-title-${phase.phase}`,
      },
        el("header", {},
          el("div", {},
            el("div", { class: "num", text: String(state.sdlc.phases.indexOf(phase) + 1).padStart(2, "0"), "aria-hidden": "true" }),
            el("h3", { id: `phase-title-${phase.phase}`, text: phase.title })
          ),
          el("span", { class: `pill ${phase.status === "done" ? "ok" : phase.status === "blocked" ? "bad" : ""}`, text: formatStatus(phase.status) })
        ),
        el("p", { text: phase.description }),
        el("div", { class: "evidence", text: expected || "No expected artifacts." }),
        el("div", { class: "evidence", text: (phase.evidence || []).join("\n") || "No evidence recorded." }),
        evidence,
        actions
      )
    );
  }
  if (focusPhase) {
    const target = document.getElementById(`phase-${focusPhase}`);
    if (target) target.focus();
  }
}

async function phaseAction(action, phase) {
  const card = document.getElementById(`phase-${phase}`);
  if (card) {
    setBusy(card, true);
    $$("button", card).forEach((button) => { button.disabled = true; });
  }
  const input = document.getElementById(`evidence-${phase}`);
  const note = input ? input.value.trim() : "";
  setPanelStatus("pipeline-status", `${PHASE_TITLES[phase] || phase}: ${action} in progress…`);
  try {
    const payload = { action, phase };
    if (action === "block") payload.note = note || "Blocked from Studio";
    else if (note) payload.evidence = note;
    const result = await api("/api/v1/studio/sdlc", { method: "POST", body: payload });
    state.sdlc = result.state;
    renderPipeline(phase);
    renderDashboard();
    setPanelStatus("pipeline-status", `${PHASE_TITLES[phase] || phase}: ${action} completed.`);
    toast(`${PHASE_TITLES[phase] || phase}: ${action} ok`);
  } catch (error) {
    if (card) {
      setBusy(card, false);
      $$("button", card).forEach((button) => { button.disabled = false; });
    }
    setPanelStatus("pipeline-status", error.message, true);
    toast(error.message, true);
  }
}

async function previewHandoff(write) {
  const previewButton = $("#handoff-preview");
  const writeButton = $("#handoff-write");
  const output = $("#handoff-output");
  previewButton.disabled = true;
  writeButton.disabled = true;
  setBusy(output, true);
  setPanelStatus("pipeline-status", write ? "Writing handoff…" : "Generating handoff preview…");
  try {
    const path = "/api/v1/studio/handoff";
    const markdown = write
      ? (await api(path, { method: "POST", body: { write: true } })).markdown
      : await api(path);
    output.textContent = markdown;
    output.classList.remove("hidden");
    setPanelStatus("pipeline-status", write ? "Handoff written to .secdiagram/studio/HANDOFF.md." : "Handoff preview ready.");
    toast(write ? "Handoff written to .secdiagram/studio/HANDOFF.md" : "Handoff preview generated");
    if (!write) output.focus();
  } catch (error) {
    setPanelStatus("pipeline-status", error.message, true);
    toast(error.message, true);
  } finally {
    setBusy(output, false);
    previewButton.disabled = false;
    writeButton.disabled = false;
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
  setBusy("#view-diagram", true);
  setPanelStatus("diagram-status", "Loading diagram…");
  let nodeError = null;
  if (!state.nodes.length || !state.summary) {
    try {
      const result = await api("/api/v1/studio/nodes");
      state.nodes = result.nodes || [];
    } catch (error) {
      nodeError = error;
    }
  }
  renderNodeList();
  try {
    const source = await api(`/api/v1/studio/diagram?${diagramParams()}`);
    $("#mermaid-source").textContent = source;
    if (nodeError) setPanelStatus("diagram-status", `Components unavailable: ${nodeError.message}`, true);
    else setPanelStatus("diagram-status", "Diagram source ready.");
  } catch (error) {
    $("#mermaid-source").textContent = `Could not load diagram: ${error.message}`;
    setPanelStatus("diagram-status", `Could not load diagram: ${error.message}`, true);
  }
  renderOverridesMeta();
  setBusy("#view-diagram", false);
}

async function renderSvg() {
  const button = $("#render-svg");
  const preview = $("#diagram-preview");
  const label = DETAIL_LABELS[state.detail] || state.detail;
  button.disabled = true;
  button.textContent = "Rendering…";
  setBusy(preview, true);
  setPanelStatus("diagram-status", `Rendering ${label} diagram…`);
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
    if (state.renderUrl) URL.revokeObjectURL(state.renderUrl);
    state.renderUrl = url;
    preview.replaceChildren(el("img", { src: url, alt: `Rendered ${label} diagram` }));
    setPanelStatus("diagram-status", `Rendered ${label} diagram locally.`);
    toast("Rendered locally with Mermaid CLI");
  } catch (error) {
    preview.replaceChildren(
      el("div", { class: "placeholder" },
        el("div", { text: "Local SVG rendering is unavailable." }),
        el("div", { class: "muted", text: error.message }),
        el("div", { class: "muted", text: "The Mermaid source is still available; install mmdc or use the container image for offline rendering." })
      )
    );
    setPanelStatus("diagram-status", error.message, true);
    toast(error.message, true);
  } finally {
    setBusy(preview, false);
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
    list.append(el("p", { class: "muted", text: state.nodes.length ? "No matching nodes." : "No components available." }));
    return;
  }
  nodes.forEach((node, index) => {
    const metaId = `node-meta-${index}`;
    const metaText = `${node.kind} · ${node.name}${node.path ? ` · ${node.path}` : ""}`;
    const checkbox = el("input", {
      type: "checkbox",
      title: "Hide from diagram",
      "aria-label": `Hide ${node.name} from diagram`,
      "aria-describedby": metaId,
      checked: state.edits.hidden.has(node.id) ? "checked" : null,
      onchange: (event) => {
        if (event.target.checked) state.edits.hidden.add(node.id);
        else state.edits.hidden.delete(node.id);
        renderOverridesMeta();
      },
    });
    const input = el("input", {
      type: "text",
      value: state.edits.renames[node.id] || "",
      placeholder: node.name,
      "aria-label": `Rename ${node.name}`,
      "aria-describedby": metaId,
      oninput: (event) => {
        const value = event.target.value.trim();
        if (value) state.edits.renames[node.id] = value;
        else delete state.edits.renames[node.id];
        renderOverridesMeta();
      },
    });
    list.append(
      el("div", { class: "node", role: "group", "aria-label": node.name },
        checkbox,
        el("div", { class: "row" },
          input,
          el("div", { class: "meta", id: metaId, title: metaText, text: metaText })
        )
      )
    );
  });
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
  const card = $("#view-diagram .card");
  const saveButton = $("#save-overrides");
  const resetButton = $("#reset-overrides");
  const payload = {
    renames: state.edits.renames,
    hidden: Array.from(state.edits.hidden),
    direction: $("#direction").value || null,
    theme: $("#theme").value || null,
  };
  setBusy(card, true);
  saveButton.disabled = true;
  resetButton.disabled = true;
  setPanelStatus("diagram-status", "Saving diagram overrides…");
  try {
    const result = await api("/api/v1/studio/overrides", { method: "POST", body: payload });
    state.overrides = result.overrides;
    syncEditsFromOverrides();
    renderOverridesMeta();
    await loadDiagram();
    toast("Diagram overrides saved");
  } catch (error) {
    setPanelStatus("diagram-status", error.message, true);
    toast(error.message, true);
  } finally {
    setBusy(card, false);
    saveButton.disabled = false;
    resetButton.disabled = false;
  }
}

async function resetOverrides() {
  const card = $("#view-diagram .card");
  const saveButton = $("#save-overrides");
  const resetButton = $("#reset-overrides");
  setBusy(card, true);
  saveButton.disabled = true;
  resetButton.disabled = true;
  setPanelStatus("diagram-status", "Resetting diagram overrides…");
  try {
    const result = await api("/api/v1/studio/overrides", { method: "POST", body: { action: "reset" } });
    state.overrides = result.overrides;
    syncEditsFromOverrides();
    renderNodeList();
    renderOverridesMeta();
    await loadDiagram();
    toast("Diagram overrides reset");
  } catch (error) {
    setPanelStatus("diagram-status", error.message, true);
    toast(error.message, true);
  } finally {
    setBusy(card, false);
    saveButton.disabled = false;
    resetButton.disabled = false;
  }
}

async function generateAi() {
  const button = $("#generate-ai");
  const output = $("#ai-output");
  const status = $("#ai-status");
  button.disabled = true;
  status.textContent = "working…";
  output.textContent = "Waiting for the model…";
  setBusy(output, true);
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
    setBusy(output, false);
    button.disabled = false;
  }
}

async function loadInstaller() {
  setBusy("#view-installer", true);
  setPanelStatus("installer-status", "Loading installer status…");
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
    setPanelStatus(
      "installer-status",
      status.installed
        ? (status.healthy ? "Studio install is healthy." : "Studio install needs attention.")
        : "Studio is not installed. Run the CLI install command below.",
      status.installed && !status.healthy,
    );
  } catch (error) {
    $("#installer-pill").textContent = "unavailable";
    $("#installer-pill").className = "pill bad";
    setPanelStatus("installer-status", error.message, true);
    toast(error.message, true);
  } finally {
    setBusy("#view-installer", false);
  }
}

async function rescan() {
  const button = $("#rescan");
  button.disabled = true;
  button.textContent = "Scanning…";
  setBusy("#view-dashboard", true);
  setPanelStatus("dashboard-status", "Scanning repository…");
  try {
    await api("/api/v1/scan", { method: "POST", body: {} });
    await loadCore();
    toast("Repository rescanned");
  } catch (error) {
    setPanelStatus("dashboard-status", error.message, true);
    toast(error.message, true);
  } finally {
    button.disabled = false;
    button.textContent = "Rescan";
  }
}

function bindTabs() {
  const tabs = $$("#nav [role=tab]");
  tabs.forEach((tab, index) => {
    tab.addEventListener("click", () => setView(tab.dataset.view));
    tab.addEventListener("keydown", (event) => {
      let next = null;
      if (event.key === "ArrowDown" || event.key === "ArrowRight") next = tabs[(index + 1) % tabs.length];
      else if (event.key === "ArrowUp" || event.key === "ArrowLeft") next = tabs[(index - 1 + tabs.length) % tabs.length];
      else if (event.key === "Home") next = tabs[0];
      else if (event.key === "End") next = tabs[tabs.length - 1];
      if (!next) return;
      event.preventDefault();
      next.focus();
      setView(next.dataset.view);
    });
  });
}

function bindEvents() {
  bindTabs();
  $$("[data-goto]").forEach((button) => button.addEventListener("click", () => setView(button.dataset.goto, { focusTab: true })));
  $("#rescan").addEventListener("click", rescan);

  $$("#detail-seg button").forEach((button) => {
    button.addEventListener("click", () => {
      state.detail = button.dataset.detail;
      $$("#detail-seg button").forEach((item) => {
        const selected = item === button;
        item.classList.toggle("active", selected);
        item.setAttribute("aria-pressed", selected ? "true" : "false");
      });
      loadDiagram();
    });
  });
  $("#render-svg").addEventListener("click", renderSvg);
  $("#show-source").addEventListener("click", () => {
    const source = $("#mermaid-source");
    const toggle = $("#show-source");
    const hidden = source.classList.toggle("hidden");
    toggle.setAttribute("aria-expanded", hidden ? "false" : "true");
    toggle.textContent = hidden ? "Show Mermaid source" : "Hide Mermaid source";
    if (!hidden) source.focus();
  });
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

window.addEventListener("beforeunload", () => {
  if (state.renderUrl) URL.revokeObjectURL(state.renderUrl);
});

document.addEventListener("DOMContentLoaded", async () => {
  bindEvents();
  await loadCore();
  setView("dashboard");
});
