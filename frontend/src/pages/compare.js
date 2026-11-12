/** Compare: baseline vs enforced side by side, with still-succeeding callouts. */

import {
  byId,
  categoryLabel,
  chips,
  cohortPill,
  emptyPanel,
  esc,
  pct,
  stageOutcome,
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
  const v2 = comparison.v2 || null;
  const v2Map = byId(v2?.attacks || []);

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
      const v2Row = v2Map.get(id);
      const v2Fails = Boolean(
        v2Row &&
          !v2Row.control &&
          (v2Row.v2_succeeded || !(v2Row.v2_blocked_by || []).length),
      );
      const highlight = v2 ? v2Fails : Boolean(still);
      const blockedBy =
        fixed?.blocked_by ||
        [
          ...new Set(
            (after?.blocked_calls || [])
              .map((call) => call.rule_id)
              .filter(Boolean),
          ),
        ];
      const cohort = v2Row
        ? v2Row.cohort === "held_out_v2"
          ? "held_out_v2"
          : v2Row.cohort
        : sample.held_out
          ? "held_out"
          : "original";

      const stage = (row) =>
        stageOutcome({
          succeeded: row?.succeeded ?? false,
          control: row?.control ?? false,
          blockedBy: (row?.blocked_calls || [])
            .map((call) => call.rule_id)
            .filter(Boolean),
          replyBlocked: row?.reply_check?.blocked,
        });
      const v2Outcome = v2Row
        ? stageOutcome({
            succeeded: v2Row.v2_succeeded,
            control: v2Row.control,
            blockedBy: v2Row.v2_blocked_by,
          })
        : '<span class="faint">—</span>';

      const rowClass = highlight ? "row-danger" : "";
      const mainRow = `<tr class="${rowClass}">
        <td>
          <span class="attack-name">${esc(sample.name)}</span>
          <span class="attack-id">${esc(id)}</span>
        </td>
        <td>${esc(categoryLabel(sample.category))}</td>
        <td>${cohortPill(cohort)}</td>
        <td>${stage(before)}</td>
        <td>${stage(after)}</td>
        ${v2 ? `<td>${v2Outcome}</td>` : ""}
        <td>${
          v2
            ? v2Row?.v2_succeeded
              ? '<span class="pill pill-danger">Still succeeds</span>'
              : chips(
                  v2Row?.v2_blocked_by,
                  v2Row?.control ? "not blocked" : "not blocked — leak",
                )
            : still
              ? '<span class="pill pill-danger">Still succeeds</span>'
              : chips(blockedBy, "no blocking rule recorded")
        }</td>
      </tr>`;

      const whyText = v2
        ? v2Fails
          ? v2Row.note
          : null
        : still
          ? still.reason
          : null;
      const why = whyText
        ? `<tr class="why-row"><td colspan="${v2 ? 7 : 6}">
            <div class="why-text"><strong>Why it still succeeds:</strong> ${esc(
              whyText,
            )}${
              !v2 && still?.evidence?.length
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
  const stillCount = v2
    ? (v2.still_succeeding || []).length
    : (comparison.still_succeeding || []).length;
  const fixedCount = v2
    ? v2.summary?.attacks_fixed ?? (v2.fixed || []).length
    : summary.attacks_fixed ?? (comparison.fixed || []).length;
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
        "v1 enforced success rate",
        pct(summary.after?.asr),
        `${summary.after?.succeeded ?? 0}/${summary.after?.attacks ?? 0} attacks`,
        "tone-green",
      )}
      ${v2 ? metric(
        "v2 enforced success rate",
        pct(v2.summary?.after?.asr),
        `${v2.summary?.after?.succeeded ?? 0}/${v2.summary?.after?.attacks ?? 0} attacks · data-loss stage on`,
        "tone-green",
      ) : ""}
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
            <th>v1 enforced</th>
            ${v2 ? "<th>v2 enforced</th>" : ""}
            <th>${v2 ? "v2 blocked by / result" : "Blocked by / result"}</th>
          </tr>
        </thead>
        <tbody>${body}</tbody>
      </table>
    </div>

    <p class="faint">
      Baseline, v1 and v2 outcomes come from the same attack in the same
      simulated sandbox. Rows in red still succeed under the last enforced
      stage and include the recorded reason.
    </p>
  </div>`;
}

export function mount() {}
