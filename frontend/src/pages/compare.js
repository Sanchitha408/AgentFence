/** Compare: baseline vs enforced side by side, with still-succeeding callouts. */

import {
  attackOutcome,
  byId,
  categoryLabel,
  chips,
  cohortPill,
  emptyPanel,
  esc,
  pct,
} from "../utils/format.js";

function missing(state) {
  const error = state.errors?.compare;
  if (error && error.status !== 404) {
    return emptyPanel("Could not load the comparison", error.message, {
      action: "retry",
      actionLabel: "Retry",
    });
  }
  return emptyPanel(
    "Nothing to compare yet",
    "Generate reports/compare.json with the compare command or the Run again button.",
    { action: "run-again", actionLabel: "Run again" },
  );
}

function metric(label, value, detail, tone) {
  return `<article class="metric">
    <span class="metric-label">${esc(label)}</span>
    <span class="metric-value ${tone || ""}">${esc(value)}</span>
    <span class="metric-detail">${detail}</span>
  </article>`;
}

export function render(state) {
  const comparison = state.compare;
  if (!comparison) return missing(state);

  const beforeRows = comparison.results?.before || [];
  const afterRows = comparison.results?.after || [];
  const beforeMap = byId(beforeRows);
  const afterMap = byId(afterRows);
  const fixedMap = byId(comparison.fixed || []);
  const stillMap = byId(comparison.still_succeeding || []);

  const ids = [
    ...new Set([
      ...beforeRows.map((row) => row.id),
      ...afterRows.map((row) => row.id),
    ]),
  ];

  const rows = ids
    .map((id) => {
      const before = beforeMap.get(id);
      const after = afterMap.get(id);
      const sample = before || after;
      return { id, before, after, sample };
    })
    .filter((row) => row.sample);

  const body = rows
    .map(({ id, before, after, sample }) => {
      const still = stillMap.get(id);
      const fixed = fixedMap.get(id);
      const blockedBy =
        fixed?.blocked_by ||
        [
          ...new Set(
            (after?.blocked_calls || [])
              .map((call) => call.rule_id)
              .filter(Boolean),
          ),
        ];

      const rowClass = still ? "row-danger" : "";
      const mainRow = `<tr class="${rowClass}">
        <td>
          <span class="attack-name">${esc(sample.name)}</span>
          <span class="attack-id">${esc(id)}</span>
        </td>
        <td>${esc(categoryLabel(sample.category))}</td>
        <td>${cohortPill(sample.held_out ?? false)}</td>
        <td>${attackOutcome(before)}</td>
        <td>${attackOutcome(after)}</td>
        <td>${
          still
            ? '<span class="pill pill-danger">Still succeeds</span>'
            : chips(blockedBy, "no blocking rule recorded")
        }</td>
      </tr>`;

      const why = still
        ? `<tr class="why-row"><td colspan="6">
            <div class="why-text"><strong>Why it still succeeds:</strong> ${esc(
              still.reason,
            )}${
              still.evidence?.length
                ? ` <span class="faint">Evidence: ${esc(
                    still.evidence.join("; "),
                  )}</span>`
                : ""
            }</div>
          </td></tr>`
        : "";

      return mainRow + why;
    })
    .join("");

  const summary = comparison.summary || {};
  const stillCount = (comparison.still_succeeding || []).length;
  const fixedCount = summary.attacks_fixed ?? (comparison.fixed || []).length;
  const regressions = (comparison.regressions || []).length;

  return `<div class="stack">
    <section class="grid grid-metrics">
      ${metric(
        "Baseline success rate",
        pct(summary.before?.asr),
        `${summary.before?.succeeded ?? 0}/${summary.before?.attacks ?? 0} attacks`,
        "tone-red",
      )}
      ${metric(
        "Enforced success rate",
        pct(summary.after?.asr),
        `${summary.after?.succeeded ?? 0}/${summary.after?.attacks ?? 0} attacks`,
        "tone-green",
      )}
      ${metric("Fixed", fixedCount, "attacks no longer succeed", "tone-green")}
      ${metric("Still succeeding", stillCount, "highlighted below", stillCount ? "tone-red" : "")}
      ${metric("Regressions", regressions, "newly successful attacks", regressions ? "tone-amber" : "")}
    </section>

    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Attack</th>
            <th>Category</th>
            <th>Set</th>
            <th>Baseline</th>
            <th>Enforced</th>
            <th>Blocked by / result</th>
          </tr>
        </thead>
        <tbody>${body}</tbody>
      </table>
    </div>

    <p class="faint">
      Baseline and enforced outcomes come from the same attack in the same
      simulated sandbox. Rows in red still succeed and include the recorded
      reason.
    </p>
  </div>`;
}

export function mount() {}
