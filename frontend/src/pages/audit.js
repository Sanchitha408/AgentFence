/** Audit log: recent tool-call decisions, newest first. */

import {
  decisionPill,
  emptyPanel,
  esc,
  formatTime,
} from "../utils/format.js";

let visibleLimit = 50;

export function render(state) {
  const entries = state.audit || [];
  if (!entries.length) {
    return emptyPanel(
      "No audit entries yet",
      "The audit log is written when attacks run under enforcement. Run again to produce decisions.",
      { action: "run-again", actionLabel: "Run again" },
    );
  }

  // The API returns oldest-to-newest; show the newest first.
  const shown = entries.slice(-visibleLimit).reverse();
  const rows = shown
    .map((entry) => {
      const decision = String(entry.decision || "").toLowerCase();
      const rowClass =
        decision === "block" ? "row-danger" : "";
      const argumentsText = JSON.stringify(entry.arguments || {});
      return `<tr class="${rowClass}">
        <td class="mono-cell" title="${esc(entry.timestamp)}">${esc(formatTime(entry.timestamp))}</td>
        <td><span class="chip">${esc(entry.tool)}</span></td>
        <td>${decisionPill(decision)}</td>
        <td><span class="mono">${esc(entry.rule_id || "—")}</span></td>
        <td>${esc(entry.reason || "—")}</td>
        <td class="mono-cell" title="${esc(argumentsText)}">${esc(argumentsText)}</td>
        <td>${entry.executed ? '<span class="pill pill-ok">yes</span>' : '<span class="pill pill-neutral">no</span>'}</td>
      </tr>`;
    })
    .join("");

  const options = [25, 50, 100, 200]
    .map(
      (value) =>
        `<option value="${value}" ${value === visibleLimit ? "selected" : ""}>Last ${value}</option>`,
    )
    .join("");

  return `<div class="stack">
    <div class="filters">
      <div class="field">
        <label for="audit-limit">Entries</label>
        <select id="audit-limit" data-audit-limit>${options}</select>
      </div>
      <span class="filter-note">
        Showing ${shown.length} of ${entries.length} loaded decisions ·
        newest first
      </span>
    </div>

    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Tool</th>
            <th>Decision</th>
            <th>Rule</th>
            <th>Reason</th>
            <th>Arguments</th>
            <th>Executed</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>

    <p class="faint">
      Every attempted tool call is logged, including calls the policy blocked.
      <span class="mono">allow</span> calls executed;
      <span class="mono">block</span> and <span class="mono">ask</span> calls did not.
    </p>
  </div>`;
}

export function mount(root, state, rerender) {
  const select = root.querySelector("[data-audit-limit]");
  if (!select) return;
  select.addEventListener("change", () => {
    visibleLimit = Number(select.value);
    rerender();
  });
}
