/**
 * A small, dependency-free grouped bar chart.
 *
 * Each group has a before and an after rate cell ({succeeded, attacks, asr}).
 * The chart is plain SVG, so it works offline with no chart library or CDN.
 */

import { esc, pct } from "../utils/format.js";

const COLORS = {
  before: "#f87171",
  after: "#34d399",
  grid: "#24324b",
  axis: "#6f809b",
  text: "#93a3bc",
};

export function groupedBarChart(groups) {
  const width = 760;
  const height = 300;
  const margin = { top: 30, right: 14, bottom: 58, left: 48 };
  const plotWidth = width - margin.left - margin.right;
  const plotHeight = height - margin.top - margin.bottom;
  const baseline = margin.top + plotHeight;

  if (!groups.length) {
    return '<p class="muted">No data to chart.</p>';
  }

  const groupWidth = plotWidth / groups.length;
  const barWidth = Math.max(14, Math.min(38, groupWidth * 0.24));
  const gap = Math.max(6, groupWidth * 0.06);
  const y = (value) => margin.top + (1 - value) * plotHeight;

  const grid = [0, 0.25, 0.5, 0.75, 1]
    .map((tick) => {
      const yPos = y(tick);
      return `<line x1="${margin.left}" y1="${yPos}" x2="${
        width - margin.right
      }" y2="${yPos}" stroke="${COLORS.grid}" stroke-width="1" />
        <text x="${margin.left - 9}" y="${yPos + 4}" fill="${
          COLORS.axis
        }" font-size="10" text-anchor="end">${Math.round(tick * 100)}%</text>`;
    })
    .join("");

  const bars = groups
    .map((group, index) => {
      const center = margin.left + groupWidth * (index + 0.5);
      const beforeX = center - barWidth - gap / 2;
      const afterX = center + gap / 2;
      const beforeValue = Number(group.before?.asr || 0);
      const afterValue = Number(group.after?.asr || 0);

      const bar = (xPos, value, color, label) => {
        const barHeight = Math.max(0, plotHeight * value);
        const top = baseline - barHeight;
        const title = `${label}: ${pct(value)}`;
        return `<g>
          <rect x="${xPos}" y="${top}" width="${barWidth}" height="${barHeight}"
            rx="3" fill="${color}" opacity="0.9">
            <title>${esc(title)}</title>
          </rect>
          <text x="${xPos + barWidth / 2}" y="${Math.max(
            top - 6,
            margin.top + 10,
          )}" fill="${color}" font-size="10" font-weight="600"
            text-anchor="middle">${pct(value)}</text>
        </g>`;
      };

      return `<g>
        ${bar(beforeX, beforeValue, COLORS.before, `${group.label} before`)}
        ${bar(afterX, afterValue, COLORS.after, `${group.label} after`)}
        <text x="${center}" y="${baseline + 21}" fill="${
          COLORS.text
        }" font-size="11" font-weight="500" text-anchor="middle">${esc(
          group.label,
        )}</text>
        <text x="${center}" y="${baseline + 36}" fill="${
          COLORS.axis
        }" font-size="10" text-anchor="middle">${group.attacks} attacks</text>
      </g>`;
    })
    .join("");

  return `<div class="chart-wrap">
    <svg viewBox="0 0 ${width} ${height}" role="img"
      aria-label="Attack success rate before and after enforcement">
      <title>Attack success rate before and after enforcement</title>
      ${grid}
      <line x1="${margin.left}" y1="${baseline}" x2="${
        width - margin.right
      }" y2="${baseline}" stroke="${COLORS.axis}" stroke-width="1" />
      ${bars}
    </svg>
  </div>`;
}
