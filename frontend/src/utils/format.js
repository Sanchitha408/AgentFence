/** Formatting and escaping helpers shared by the dashboard pages. */

const ESCAPES = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

/** Escape untrusted report text before inserting it into HTML. */
export function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ESCAPES[char]);
}

export function pct(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return "—";
  return `${(number * 100).toFixed(1)}%`;
}

/** A rate cell from the report, e.g. "12/12 (100.0%)". */
export function rate(cell) {
  if (!cell) return "—";
  return `${cell.succeeded}/${cell.attacks} (${pct(cell.asr)})`;
}

export function count(value) {
  return Number.isFinite(Number(value)) ? String(Number(value)) : "—";
}

export function decisionPill(decision) {
  const value = String(decision || "").toLowerCase();
  const className =
    value === "allow" ? "pill-ok" : value === "block" ? "pill-danger" : "pill-warn";
  return `<span class="pill ${className}">${esc(value || "unknown")}</span>`;
}

export function attackOutcome(row) {
  if (!row) return '<span class="faint">—</span>';
  if (row.control) {
    return row.succeeded
      ? '<span class="pill pill-danger">False positive</span>'
      : '<span class="pill pill-ok">Clean</span>';
  }
  return row.succeeded
    ? '<span class="pill pill-danger">Vulnerable</span>'
    : '<span class="pill pill-ok">Blocked</span>';
}

/**
 * A stage outcome that separates "blocked" from "the detector saw nothing".
 * Baseline rows have no policy, and an encoded or split leak can be allowed
 * through without tripping a detector; calling that "Blocked" would be a lie.
 */
export function stageOutcome({ succeeded, control, blockedBy, replyBlocked }) {
  if (control) {
    return succeeded
      ? '<span class="pill pill-danger">False positive</span>'
      : '<span class="pill pill-ok">Clean</span>';
  }
  if (succeeded) return '<span class="pill pill-danger">Vulnerable</span>';
  if ((blockedBy && blockedBy.length) || replyBlocked) {
    return '<span class="pill pill-ok">Blocked</span>';
  }
  return '<span class="pill pill-warn">Not detected</span>';
}

const CATEGORY_LABELS = {
  direct_injection: "Direct injection",
  indirect_injection: "Indirect injection",
  tool_misuse: "Tool misuse",
  exfiltration: "Exfiltration",
  control: "Control",
};

export function categoryLabel(category) {
  return CATEGORY_LABELS[category] || category || "—";
}

export function cohortPill(cohort) {
  if (cohort === "held_out_v2") {
    return '<span class="pill pill-warn">Held-out v2</span>';
  }
  return cohort === "held_out"
    ? '<span class="pill pill-warn">Held-out</span>'
    : '<span class="pill pill-neutral">Original</span>';
}

export function chips(items, empty = "—") {
  const list = Array.isArray(items) ? items : [];
  if (!list.length) return `<span class="faint">${esc(empty)}</span>`;
  return `<div class="chips">${list
    .map((item) => `<span class="chip">${esc(item)}</span>`)
    .join("")}</div>`;
}

export function emptyPanel(title, body, options = {}) {
  const command = options.command
    ? `<pre class="command-block">${esc(options.command)}</pre>`
    : "";
  const action = options.action
    ? `<button class="button button-primary" type="button" data-action="${esc(
        options.action,
      )}">${esc(options.actionLabel || "Run again")}</button>`
    : "";
  return `<section class="empty-panel">
    <div class="empty-icon" aria-hidden="true">◇</div>
    <h2>${esc(title)}</h2>
    <p>${esc(body)}</p>
    ${command}
    ${action}
  </section>`;
}

export function formatTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString([], {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

/** Build a map keyed by attack id. */
export function byId(rows) {
  const map = new Map();
  for (const row of rows || []) {
    if (row && row.id) map.set(row.id, row);
  }
  return map;
}
