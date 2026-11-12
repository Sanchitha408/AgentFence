/** Results: every attack with baseline and enforced outcomes, filterable. */

import {
  attackOutcome,
  byId,
  categoryLabel,
  chips,
  cohortPill,
  count,
  emptyPanel,
  esc,
} from "../utils/format.js";

let categoryFilter = "all";
let cohortFilter = "all";

function collectRows(state) {
  const comparison = state.compare;
  const beforeRows =
    comparison?.results?.before || state.baseline?.results || [];
  const afterRows =
    comparison?.results?.after || state.enforced?.results || [];

  const beforeMap = byId(beforeRows);
  const afterMap = byId(afterRows);
  const ids = [
    ...new Set([
      ...beforeRows.map((row) => row.id),
      ...afterRows.map((row) => row.id),
    ]),
  ];

  return ids
    .map((id) => ({ before: beforeMap.get(id), after: afterMap.get(id) }))
    .filter((row) => row.before || row.after)
    .map((row) => {
      const sample = row.after || row.before;
      return {
        ...row,
        id: sample.id,
        name: sample.name,
        category: sample.category,
        held_out: sample.held_out ?? false,
        held_out_v2: sample.held_out_v2 ?? false,
        cohort: sample.held_out_v2
          ? "held_out_v2"
          : sample.held_out
            ? "held_out"
            : "original",
        owasp: sample.owasp_category,
        control: sample.control ?? false,
        detectors:
          row.after?.detectors_fired?.length
            ? row.after.detectors_fired
            : row.before?.detectors_fired || [],
      };
    });
}

export function render(state) {
  const rows = collectRows(state);
  if (!rows.length) {
    return emptyPanel(
      "No results to show",
      "Run the baseline and comparison first, then reload this page.",
      { action: "retry", actionLabel: "Reload" },
    );
  }

  const categories = [...new Set(rows.map((row) => row.category))];
  if (categoryFilter !== "all" && !categories.includes(categoryFilter)) {
    categoryFilter = "all";
  }

  const filtered = rows.filter((row) => {
    if (categoryFilter !== "all" && row.category !== categoryFilter) return false;
    if (cohortFilter === "original" && row.cohort !== "original") return false;
    if (cohortFilter === "held_out" && row.cohort !== "held_out") return false;
    if (cohortFilter === "held_out_v2" && row.cohort !== "held_out_v2") {
      return false;
    }
    return true;
  });

  const body = filtered
    .map((row) => {
      const vulnerable = row.after?.succeeded && !row.control;
      return `<tr class="${vulnerable ? "row-danger" : ""}">
        <td>
          <span class="attack-name">${esc(row.name)}</span>
          <span class="attack-id">${esc(row.id)}</span>
        </td>
        <td>${esc(categoryLabel(row.category))}</td>
        <td><span class="mono">${esc(row.owasp || "—")}</span></td>
        <td>${cohortPill(row.cohort)}</td>
        <td>${attackOutcome(row.before)}</td>
        <td>${attackOutcome(row.after)}</td>
        <td>${chips(row.detectors, "none")}</td>
      </tr>`;
    })
    .join("");

  const options = categories
    .map(
      (category) =>
        `<option value="${esc(category)}" ${
          category === categoryFilter ? "selected" : ""
        }>${esc(categoryLabel(category))}</option>`,
    )
    .join("");

  return `<div class="stack">
    <div class="filters">
      <div class="field">
        <label for="filter-category">Category</label>
        <select id="filter-category" data-filter="category">
          <option value="all" ${categoryFilter === "all" ? "selected" : ""}>All categories</option>
          ${options}
        </select>
      </div>
      <div class="field">
        <label for="filter-cohort">Attack set</label>
        <select id="filter-cohort" data-filter="cohort">
          <option value="all" ${cohortFilter === "all" ? "selected" : ""}>All attack sets</option>
          <option value="original" ${cohortFilter === "original" ? "selected" : ""}>Original 12 only</option>
          <option value="held_out" ${cohortFilter === "held_out" ? "selected" : ""}>Held-out 6 only</option>
          <option value="held_out_v2" ${cohortFilter === "held_out_v2" ? "selected" : ""}>Held-out v2 only</option>
        </select>
      </div>
      <span class="filter-note">Showing ${count(filtered.length)} of ${count(rows.length)} rows</span>
    </div>

    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Attack</th>
            <th>Category</th>
            <th>OWASP</th>
            <th>Set</th>
            <th>Baseline</th>
            <th>Enforced</th>
            <th>Detectors fired</th>
          </tr>
        </thead>
        <tbody>
          ${
            body ||
            `<tr><td colspan="7" class="center muted">No rows match these filters.</td></tr>`
          }
        </tbody>
      </table>
    </div>
  </div>`;
}

export function mount(root, state, rerender) {
  root.querySelectorAll("[data-filter]").forEach((select) => {
    select.addEventListener("change", () => {
      if (select.dataset.filter === "category") categoryFilter = select.value;
      if (select.dataset.filter === "cohort") cohortFilter = select.value;
      rerender();
    });
  });
}
