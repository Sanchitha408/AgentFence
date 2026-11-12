/** Overview: before vs after attack success rate, cohorts, controls and counts. */

import { groupedBarChart } from "../components/chart.js";
import {
  categoryLabel,
  emptyPanel,
  esc,
  pct,
  rate,
} from "../utils/format.js";

function comparisonMissing(state) {
  const error = state.errors?.compare;
  if (error && error.status !== 404) {
    return emptyPanel(
      "Could not load the comparison",
      error.message,
      { action: "retry", actionLabel: "Retry" },
    );
  }
  return emptyPanel(
    "No comparison report yet",
    "Run the attacks under the generated policy to produce reports/compare.json, then reload this page.",
    {
      command:
        "venv/bin/python -m agentfence compare --baseline reports/baseline.json \\\n  --policy policies/generated.yaml --out reports/compare.json",
      action: "run-again",
      actionLabel: "Run again",
    },
  );
}

function metric(label, value, detail, tone) {
  return `<article class="metric">
    <span class="metric-label">${esc(label)}</span>
    <span class="metric-value ${tone || ""}">${esc(value)}</span>
    <span class="metric-detail">${detail}</span>
  </article>`;
}

function v2Progression(comparison, v2) {
  const base = comparison.summary || {};
  const controls = v2.controls || {};
  const rows = [
    {
      label: "Overall",
      v1: base.after,
      v2: v2.summary?.after,
    },
    ...Object.entries(v2.cohorts || {}).map(([key, cell]) => ({
      label: cell.label || key,
      v1: comparison.cohorts?.[key]?.after,
      v2: cell.after,
    })),
  ];

  const body = rows
    .map(
      (row) => `<tr>
        <td>${esc(row.label)}</td>
        <td class="tone-red">${esc(rate(row.v1))}</td>
        <td class="tone-green">${esc(rate(row.v2))}</td>
      </tr>`,
    )
    .join("");

  const still = v2.still_succeeding || [];
  const unresolved = v2.unresolved || [];
  return `<section class="card">
    <div class="card-title">
      <div>
        <h2>v1 → v2</h2>
        <p>Argument-level data-loss scanning on top of the v1 tool policy</p>
      </div>
      <span class="pill pill-neutral">${esc(v2.policy || "v2")}</span>
    </div>
    <table>
      <thead><tr><th>Attack set</th><th>v1</th><th>v2</th></tr></thead>
      <tbody>${body}</tbody>
    </table>
    <div class="grid grid-two" style="margin-top: 18px">
      <div>
        <h3 style="font-size: 0.95rem; margin: 0 0 6px">Control false positives</h3>
        <p class="faint" style="margin: 0">
          v1 ${esc(`${controls.before?.false_positives ?? 0}/${controls.before?.controls ?? 0}`)}
          → v2 ${esc(`${controls.after?.false_positives ?? 0}/${controls.after?.controls ?? 0}`)}
          · benign calls blocked by v2 ${esc(controls.after?.blocked_calls ?? 0)}
        </p>
      </div>
      <div>
        <h3 style="font-size: 0.95rem; margin: 0 0 6px">Still succeeding under v2</h3>
        <p class="faint" style="margin: 0">
          ${still.length ? still.map((row) => `<span class="mono">${esc(row.id)}</span>`).join(", ") : "None detected by the current detectors."}
          ${unresolved.length ? `<br />Not blocked and not detected: ${unresolved.map((row) => `<span class="mono">${esc(row.id)}</span>`).join(", ")}` : ""}
        </p>
      </div>
    </div>
  </section>`;
}

export function render(state) {
  const comparison = state.compare;
  if (!comparison) return comparisonMissing(state);

  const summary = comparison.summary || {};
  const cohorts = comparison.cohorts || {};
  const controls = comparison.controls || {};
  const original = cohorts.original || {};
  const held = cohorts.held_out || {};
  const heldV2 = cohorts.held_out_v2 || {};
  const v2 = comparison.v2 || null;
  const after = summary.after || {};
  const before = summary.before || {};

  const overallGroups = [
    {
      label: "Overall",
      attacks: before.attacks ?? 0,
      before,
      after,
    },
    {
      label: "Original 12",
      attacks: original.before?.attacks ?? 0,
      before: original.before,
      after: original.after,
    },
    {
      label: `Held-out ${held.before?.attacks ?? 0}`,
      attacks: held.before?.attacks ?? 0,
      before: held.before,
      after: held.after,
    },
    ...(heldV2.before
      ? [
          {
            label: `Held-out v2 ${heldV2.before.attacks}`,
            attacks: heldV2.before.attacks,
            before: heldV2.before,
            after: heldV2.after,
          },
        ]
      : []),
  ];

  const categoryGroups = Object.entries(comparison.by_category || {}).map(
    ([key, cell]) => ({
      label: cell.label || categoryLabel(key),
      attacks: cell.before?.attacks ?? 0,
      before: cell.before,
      after: cell.after,
    }),
  );

  const still = comparison.still_succeeding || [];
  const fixed = summary.attacks_fixed ?? (comparison.fixed || []).length;
  const regressions = (comparison.regressions || []).length;
  const controlAfter = controls.after || {};
  const controlBefore = controls.before || {};

  const stillCallout = still.length
    ? `<div class="callout callout-danger">
        <div>
          <strong>${still.length} attack${still.length === 1 ? "" : "s"} still succeed after v1 enforcement</strong>
          <p>${still
            .slice(0, 2)
            .map(
              (row) =>
                `<span class="mono">${esc(row.id)}</span> (${esc(
                  row.cohort === "held_out_v2"
                    ? "held-out v2"
                    : row.cohort === "held_out"
                      ? "held-out"
                      : "original",
                )})`,
            )
            .join(", ")} — open Compare for the evidence and the reason.</p>
        </div>
        <a class="button button-secondary" href="#/compare">See why</a>
      </div>`
    : `<div class="callout">
        <div>
          <strong>No attack still succeeds</strong>
          <p>Every attack in this run was stopped by a policy rule or the reply stage.</p>
        </div>
      </div>`;

  return `<div class="stack">
    <section class="grid grid-metrics">
      ${metric(
        "Before enforcement",
        pct(before.asr),
        `${before.succeeded ?? 0}/${before.attacks ?? 0} attacks succeeded`,
        "tone-red",
      )}
      ${metric(
        "After v1 enforcement",
        pct(after.asr),
        `${after.succeeded ?? 0}/${after.attacks ?? 0} attacks succeeded`,
        "tone-green",
      )}
      ${v2 ? metric(
        "After v2 enforcement",
        pct(v2.summary?.after?.asr),
        `${v2.summary?.after?.succeeded ?? 0}/${v2.summary?.after?.attacks ?? 0} attacks · data-loss stage on`,
        "tone-green",
      ) : ""}
      ${metric("Attacks fixed", fixed, "baseline failures now blocked", "tone-green")}
      ${metric(
        "Still succeeding",
        summary.attacks_still_succeeding ?? still.length,
        "with evidence in Compare",
        "tone-red",
      )}
      ${metric("Regressions", regressions, "new failures after enforcement", regressions ? "tone-amber" : "")}
      ${metric(
        "Control false positives",
        `${controlAfter.false_positives ?? 0}/${controlAfter.controls ?? 0}`,
        `before ${controlBefore.false_positives ?? 0}/${controlBefore.controls ?? 0} · blocked benign calls after ${controlAfter.blocked_calls ?? 0}`,
        (controlAfter.false_positives ?? 0) ? "tone-red" : "tone-green",
      )}
    </section>

    ${stillCallout}

    ${v2 ? v2Progression(comparison, v2) : ""}

    <section class="card">
      <div class="card-title">
        <div>
          <h2>Attack success rate</h2>
          <p>Overall, original and held-out cohorts · lower is better</p>
        </div>
      </div>
      ${groupedBarChart(overallGroups)}
      <div class="chart-legend">
        <span class="legend-item"><span class="legend-swatch swatch-before"></span>Before enforcement</span>
        <span class="legend-item"><span class="legend-swatch swatch-after"></span>After enforcement</span>
      </div>
    </section>

    <section class="card">
      <div class="card-title">
        <div>
          <h2>By category</h2>
          <p>Attack success rate before vs after, per OWASP-mapped category</p>
        </div>
      </div>
      ${groupedBarChart(categoryGroups)}
      <div class="chart-legend">
        <span class="legend-item"><span class="legend-swatch swatch-before"></span>Before</span>
        <span class="legend-item"><span class="legend-swatch swatch-after"></span>After</span>
      </div>
    </section>

    <section class="grid grid-two">
      <article class="card">
        <div class="card-title"><h2>Original vs held-out</h2></div>
        <table>
          <thead><tr><th>Cohort</th><th>Before</th><th>After</th></tr></thead>
          <tbody>
            <tr>
              <td>Original attacks<br /><span class="faint">used to generate the policy</span></td>
              <td class="tone-red">${esc(rate(original.before))}</td>
              <td class="tone-green">${esc(rate(original.after))}</td>
            </tr>
            <tr>
              <td>Held-out attacks<br /><span class="faint">never seen by the generator</span></td>
              <td class="tone-red">${esc(rate(held.before))}</td>
              <td class="tone-green">${esc(rate(held.after))}</td>
            </tr>
            ${heldV2.before ? `<tr>
              <td>Held-out v2 attacks<br /><span class="faint">new channels, never used to tune v2</span></td>
              <td class="tone-red">${esc(rate(heldV2.before))}</td>
              <td class="tone-green">${esc(rate(heldV2.after))}</td>
            </tr>` : ""}
          </tbody>
        </table>
        <p class="metric-detail" style="margin-top: 14px">
          A gap between these rows measures generalisation, not training fit.
        </p>
      </article>

      <article class="card">
        <div class="card-title"><h2>Controls</h2></div>
        <table>
          <thead><tr><th>Benign run</th><th>Before</th><th>After</th></tr></thead>
          <tbody>
            <tr>
              <td>False positives</td>
              <td>${esc(`${controlBefore.false_positives ?? 0}/${controlBefore.controls ?? 0}`)}</td>
              <td>${esc(`${controlAfter.false_positives ?? 0}/${controlAfter.controls ?? 0}`)}</td>
            </tr>
            <tr>
              <td>Benign calls blocked by policy</td>
              <td>${esc(controlBefore.blocked_calls ?? 0)}</td>
              <td>${esc(controlAfter.blocked_calls ?? 0)}</td>
            </tr>
          </tbody>
        </table>
        <p class="metric-detail" style="margin-top: 14px">
          A control counts as a false positive only when a detector fires.
        </p>
      </article>
    </section>
  </div>`;
}

export function mount() {}
