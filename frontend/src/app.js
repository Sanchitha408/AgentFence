/** Dashboard shell: data loading, hash routing and the Run again action. */

import { API_BASE, api } from "./services/api.js";
import { esc } from "./utils/format.js";
import * as overview from "./pages/overview.js";
import * as results from "./pages/results.js";
import * as policies from "./pages/policies.js";
import * as audit from "./pages/audit.js";
import * as compare from "./pages/compare.js";

const PAGES = { overview, results, policies, audit, compare };

const META = {
  overview: {
    title: "Overview",
    subtitle: "Attack success rate before vs after enforcement.",
  },
  results: {
    title: "Results",
    subtitle: "Every attack, its OWASP mapping, and what fired.",
  },
  policies: {
    title: "Policies",
    subtitle: "Generated rules and the baseline failures behind them.",
  },
  audit: {
    title: "Audit log",
    subtitle: "Recent tool-call decisions from the policy guard.",
  },
  compare: {
    title: "Compare",
    subtitle: "Baseline vs enforced, attack by attack.",
  },
};

const state = {
  loading: true,
  running: false,
  fatal: null,
  compare: null,
  baseline: null,
  enforced: null,
  policies: [],
  audit: [],
  errors: {},
};

const view = document.getElementById("view");
const title = document.getElementById("page-title");
const subtitle = document.getElementById("page-subtitle");
const runButton = document.getElementById("run-again");
const toastElement = document.getElementById("toast");

let toastTimer = null;

function showToast(message, isError = false) {
  toastElement.textContent = message;
  toastElement.className = `toast show${isError ? " error" : ""}`;
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => {
    toastElement.className = "toast";
  }, 5200);
}

function currentRoute() {
  const route = window.location.hash.replace(/^#\/?/, "").split("?")[0];
  return PAGES[route] ? route : "overview";
}

function value(result) {
  return result.status === "fulfilled" ? result.value : null;
}

function failure(result) {
  return result.status === "rejected" ? result.reason : null;
}

async function loadAll() {
  state.loading = true;
  state.fatal = null;
  render();

  try {
    await api("/api/health");
  } catch (error) {
    state.fatal = error;
    state.loading = false;
    render();
    return;
  }

  const [compareResult, baselineResult, enforcedResult, policiesResult, auditResult] =
    await Promise.allSettled([
      api("/api/compare"),
      api("/api/runs/baseline"),
      api("/api/runs/enforced"),
      api("/api/policies"),
      api("/api/audit?limit=200"),
    ]);

  state.compare = value(compareResult);
  state.baseline = value(baselineResult);
  state.enforced = value(enforcedResult);
  state.policies = value(policiesResult)?.policies || [];
  state.audit = value(auditResult)?.entries || [];

  state.errors = {
    compare: failure(compareResult),
    baseline: failure(baselineResult),
    enforced: failure(enforcedResult),
    policies: failure(policiesResult),
    audit: failure(auditResult),
  };
  state.loading = false;
  render();
}

function fatalPanel(error) {
  const command = `venv/bin/uvicorn backend.app:app --host 127.0.0.1 --port 8000`;
  return `<section class="error-panel">
    <div class="error-icon" aria-hidden="true">!</div>
    <h2>The dashboard API is not reachable</h2>
    <p>Start the local backend, then retry. No network access is needed.</p>
    <pre class="command-block">${esc(command)}</pre>
    <p class="faint" style="margin-top: 12px">
      Dashboard: <span class="mono">http://127.0.0.1:8000/ui/</span> ·
      API base: <span class="mono">${esc(API_BASE || "same origin")}</span>
    </p>
    <p class="error-detail">${esc(error?.message || "Unknown connection error")}</p>
    <button class="button button-primary" type="button" data-action="retry">Retry connection</button>
  </section>`;
}

function loadingPanel() {
  return `<div class="loading-panel">
    <div class="spinner spinner-large" aria-hidden="true"></div>
    <p>Loading reports, policies and audit log…</p>
  </div>`;
}

function render() {
  const route = currentRoute();
  const meta = META[route];

  title.textContent = meta.title;
  subtitle.textContent = meta.subtitle;
  document.title = `${meta.title} · AgentFence`;

  document.querySelectorAll(".nav-link").forEach((link) => {
    const active = link.dataset.route === route;
    link.classList.toggle("active", active);
    if (active) {
      link.setAttribute("aria-current", "page");
    } else {
      link.removeAttribute("aria-current");
    }
  });

  if (state.fatal) {
    view.innerHTML = fatalPanel(state.fatal);
  } else if (state.loading) {
    view.innerHTML = loadingPanel();
  } else {
    view.innerHTML = PAGES[route].render(state);
    PAGES[route].mount?.(view, state, render);
  }
}

async function runAgain() {
  if (state.running) return;

  state.running = true;
  runButton.disabled = true;
  runButton.classList.add("is-busy");
  runButton.querySelector(".label").textContent = "Running…";

  try {
    const result = await api("/api/run", {
      method: "POST",
      body: JSON.stringify({ kind: "compare" }),
    });
    const after = result.summary?.after;
    showToast(
      `Run complete: ${after?.succeeded ?? "?"}/${after?.attacks ?? "?"} attacks succeed after enforcement.`,
    );
    await loadAll();
  } catch (error) {
    showToast(error.message || "The comparison run failed.", true);
  } finally {
    state.running = false;
    runButton.disabled = false;
    runButton.classList.remove("is-busy");
    runButton.querySelector(".label").textContent = "Run again";
  }
}

window.addEventListener("hashchange", render);

document.addEventListener("click", (event) => {
  const trigger = event.target.closest("[data-action]");
  if (!trigger) return;
  if (trigger.dataset.action === "run-again") runAgain();
  if (trigger.dataset.action === "retry") loadAll();
});

runButton.addEventListener("click", runAgain);

if (!window.location.hash) {
  window.history.replaceState(null, "", "#/overview");
}

loadAll();
