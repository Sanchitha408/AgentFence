/** Policies: rules from the YAML files, with the attacks that motivated them. */

import {
  chips,
  decisionPill,
  emptyPanel,
  esc,
} from "../utils/format.js";

let selectedFile = "generated.yaml";

export function render(state) {
  const entries = state.policies || [];

  if (!entries.length) {
    const error = state.errors?.policies;
    return emptyPanel(
      "No policies available",
      error
        ? error.message
        : "Add a YAML policy to policies/ and reload this page.",
      error ? { action: "retry", actionLabel: "Retry" } : {},
    );
  }

  if (!entries.some((entry) => entry.file === selectedFile)) {
    selectedFile =
      entries.find((entry) => entry.file === "generated.yaml")?.file ||
      entries.find((entry) => !entry.error)?.file ||
      entries[0].file;
  }

  const policy = entries.find((entry) => entry.file === selectedFile) || entries[0];
  const selector = entries
    .map(
      (entry) =>
        `<option value="${esc(entry.file)}" ${
          entry.file === policy.file ? "selected" : ""
        }>${esc(entry.file)}</option>`,
    )
    .join("");

  if (policy.error) {
    return `<div class="stack">
      <div class="filters">
        <div class="field">
          <label for="policy-file">Policy file</label>
          <select id="policy-file" data-policy-select>${selector}</select>
        </div>
      </div>
      <div class="error-panel">
        <div class="error-icon" aria-hidden="true">!</div>
        <h2>This policy could not be parsed</h2>
        <p class="error-detail">${esc(policy.error)}</p>
      </div>
    </div>`;
  }

  const rules = policy.rules || [];
  const rows = rules
    .map(
      (rule, index) => `<tr>
        <td class="faint">${index + 1}</td>
        <td><span class="mono">${esc(rule.id)}</span></td>
        <td><span class="chip">${esc(rule.type)}</span></td>
        <td>${decisionPill(rule.decision)}</td>
        <td>${esc(rule.reason)}</td>
        <td>${chips(rule.derived_from, "no motivating attacks")}</td>
      </tr>`,
    )
    .join("");

  return `<div class="stack">
    <div class="filters">
      <div class="field">
        <label for="policy-file">Policy file</label>
        <select id="policy-file" data-policy-select>${selector}</select>
      </div>
      <span class="filter-note">
        ${esc(policy.name || policy.file)} · default decision
        <strong>${esc(policy.default_decision || "block")}</strong> ·
        ${rules.length} rule${rules.length === 1 ? "" : "s"}
      </span>
    </div>

    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>Rule id</th>
            <th>Type</th>
            <th>Decision</th>
            <th>Reason</th>
            <th>Derived from</th>
          </tr>
        </thead>
        <tbody>
          ${
            rows ||
            `<tr><td colspan="6" class="center muted">This policy has no rules.</td></tr>`
          }
        </tbody>
      </table>
    </div>

    <p class="faint">
      Rules are evaluated top to bottom; first match wins.
      <span class="mono">derived_from</span> lists the baseline failures that
      motivated a generated rule. Held-out attacks are never used here.
    </p>
  </div>`;
}

export function mount(root, state, rerender) {
  const select = root.querySelector("[data-policy-select]");
  if (!select) return;
  select.addEventListener("change", () => {
    selectedFile = select.value;
    rerender();
  });
}
