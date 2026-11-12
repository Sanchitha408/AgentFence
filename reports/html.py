"""Self-contained HTML export of the before/after report.

One file, inline CSS, no scripts and no external requests. It is meant to be
attached to a pull request or opened from disk, so it must work offline.
"""

from __future__ import annotations

import html
from pathlib import Path
from typing import Any, Mapping, Sequence

from reports.compare import HELD_OUT


def _e(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _pct(cell: Mapping[str, Any]) -> str:
    return f"{cell['asr'] * 100:.1f}%"


def _rate(cell: Mapping[str, Any]) -> str:
    return f"{cell['succeeded']}/{cell['attacks']} ({_pct(cell)})"


def _bar(cell: Mapping[str, Any], colour: str) -> str:
    width = max(0.0, min(100.0, cell["asr"] * 100))
    return (
        '<div class="bar"><span style="width:'
        f"{width:.1f}%;background:{colour}\"></span></div>"
    )


def _cohort_label(cohort: str) -> str:
    return "held-out" if cohort == HELD_OUT else "original"


def _table(
    title: str,
    rows: Sequence[tuple[str, Mapping[str, Any], Mapping[str, Any]]],
) -> str:
    body = []
    for label, before, after in rows:
        body.append(
            "<tr>"
            f"<th>{_e(label)}</th>"
            f"<td>{_e(_rate(before))}{_bar(before, '#c0392b')}</td>"
            f"<td>{_e(_rate(after))}{_bar(after, '#1e8449')}</td>"
            "</tr>"
        )
    return (
        f"<h2>{_e(title)}</h2>"
        '<table class="rates"><thead><tr><th></th>'
        "<th>before</th><th>after</th></tr></thead><tbody>"
        + "".join(body)
        + "</tbody></table>"
    )


def render_html(comparison: Mapping[str, Any]) -> str:
    summary = comparison["summary"]
    cohorts = comparison["cohorts"]
    controls = comparison["controls"]

    overall_rows = [
        ("overall", summary["before"], summary["after"]),
        (
            cohorts["original"]["label"],
            cohorts["original"]["before"],
            cohorts["original"]["after"],
        ),
        (
            cohorts["held_out"]["label"],
            cohorts["held_out"]["before"],
            cohorts["held_out"]["after"],
        ),
    ]
    category_rows = [
        (cell["label"], cell["before"], cell["after"])
        for cell in comparison["by_category"].values()
    ]

    cards = [
        ("Overall ASR", f"{_pct(summary['before'])} → {_pct(summary['after'])}"),
        (
            "Original attacks",
            f"{_pct(cohorts['original']['before'])} → "
            f"{_pct(cohorts['original']['after'])}",
        ),
        (
            "Held-out attacks",
            f"{_pct(cohorts['held_out']['before'])} → "
            f"{_pct(cohorts['held_out']['after'])}",
        ),
        (
            "Control false positives",
            f"{controls['before']['false_positives']} → "
            f"{controls['after']['false_positives']}",
        ),
        ("Attacks fixed", str(summary["attacks_fixed"])),
        ("Still succeeding", str(summary["attacks_still_succeeding"])),
    ]
    cards_html = "".join(
        f'<div class="card"><div class="label">{_e(label)}</div>'
        f'<div class="value">{_e(value)}</div></div>'
        for label, value in cards
    )

    if comparison["still_succeeding"]:
        rows = []
        for row in comparison["still_succeeding"]:
            rows.append(
                "<tr>"
                f"<td class=\"mono\">{_e(row['id'])}</td>"
                f"<td>{_e(_cohort_label(row['cohort']))}</td>"
                f"<td>{_e(row['category'])}</td>"
                f"<td>{_e(', '.join(row['detectors_fired']) or '-')}</td>"
                f"<td>{_e(row['reason'])}</td>"
                "</tr>"
            )
        succeeding_html = (
            "<h2>Attacks that still succeed</h2>"
            '<table class="wide"><thead><tr><th>id</th><th>set</th>'
            "<th>category</th><th>detectors</th><th>why</th></tr></thead><tbody>"
            + "".join(rows)
            + "</tbody></table>"
        )
    else:
        succeeding_html = (
            "<h2>Attacks that still succeed</h2>"
            '<p class="clean">None. Every attack was blocked.</p>'
        )

    fixed_rows = "".join(
        "<tr>"
        f"<td class=\"mono\">{_e(row['id'])}</td>"
        f"<td>{_e(_cohort_label(row['cohort']))}</td>"
        f"<td>{_e(row['category'])}</td>"
        f"<td>{_e(', '.join(row['blocked_by']))}</td>"
        "</tr>"
        for row in comparison["fixed"]
    )
    fixed_html = (
        "<h2>Attacks fixed</h2>"
        '<table class="wide"><thead><tr><th>id</th><th>set</th>'
        "<th>category</th><th>blocked by</th></tr></thead><tbody>"
        + fixed_rows
        + "</tbody></table>"
    )

    caveats = "".join(f"<li>{_e(item)}</li>" for item in comparison["caveats"])
    computed = comparison.get("baseline_computed_ids") or []

    v2 = comparison.get("v2")
    if v2:
        cohort_rows = "".join(
            "<tr>"
            f"<th>{_e(cell['label'])}</th>"
            f"<td>{_e(_rate(comparison['cohorts'][cohort]['after']))}</td>"
            f"<td>{_e(_rate(cell['after']))}</td>"
            "</tr>"
            for cohort, cell in v2["cohorts"].items()
        )
        attack_rows = "".join(
            "<tr class=\""
            + ("bad" if row["v2_succeeded"] and not row["control"] else "")
            + "\">"
            + f"<td class=\"mono\">{_e(row['id'])}</td>"
            + f"<td>{_e(row['cohort'])}</td>"
            + f"<td>{_e(row['category'])}</td>"
            + f"<td>{'succeeded' if row['v1_succeeded'] else ('blocked' if row['v1_blocked_by'] else 'no detection')}</td>"
            + f"<td>{'succeeded' if row['v2_succeeded'] else ('blocked' if row['v2_blocked_by'] else 'no detection')}</td>"
            + f"<td>{_e(', '.join(row['v2_blocked_by']) or '-')}</td>"
            + f"<td>{_e(row['note'])}</td>"
            + "</tr>"
            for row in v2["attacks"]
            if row["id"] in set(v2.get("new_attack_ids") or [])
            or row["id"].startswith("held-")
        )
        blocked_by = ", ".join(
            f"{rule} x{count}" for rule, count in (v2.get("blocked_by") or {}).items()
        )
        v2_html = f"""
  <h1 class="v2">v1 → v2</h1>
  <p class="meta">
    v2 policy: <span class="mono">{_e(v2.get('policy') or '(not recorded)')}</span><br>
    v2 overall: {_e(_rate(v2['summary']['after']))} ·
    v2 control false positives: {v2['controls']['after']['false_positives']}/
    {v2['controls']['after']['controls']} ·
    v2 blocks by rule: {_e(blocked_by or '-')}<br>
    v2 not blocked and not detected: {_e(', '.join(row['id'] for row in (v2.get('unresolved') or [])) or 'none')}
  </p>
  <h2>v1 vs v2 by attack set</h2>
  <table class="rates"><thead><tr><th></th><th>v1</th><th>v2</th></tr></thead>
  <tbody>{cohort_rows}</tbody></table>
  <h2>Held-out v2 channels</h2>
  <table class="wide"><thead><tr><th>id</th><th>set</th><th>category</th>
  <th>v1</th><th>v2</th><th>v2 blocked by</th><th>detail</th></tr></thead>
  <tbody>{attack_rows}</tbody></table>
"""
    else:
        v2_html = ""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AgentFence before/after</title>
<style>
  :root {{ color-scheme: light; }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; padding: 2rem; font-family: system-ui, -apple-system,
         "Segoe UI", Roboto, sans-serif; background: #f5f7fa; color: #1c2833; }}
  main {{ max-width: 1150px; margin: 0 auto; }}
  h1 {{ margin: 0 0 .25rem; font-size: 1.8rem; }}
  h2 {{ margin: 2.2rem 0 .7rem; font-size: 1.15rem; border-bottom: 1px solid #d5dbe3;
        padding-bottom: .35rem; }}
  .meta {{ color: #566573; font-size: .9rem; line-height: 1.5; }}
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: .8rem; margin: 1.4rem 0; }}
  .card {{ background: #fff; border: 1px solid #d5dbe3; border-radius: 8px;
           padding: .8rem .9rem; }}
  .card .label {{ color: #566573; font-size: .78rem; text-transform: uppercase;
                  letter-spacing: .04em; }}
  .card .value {{ font-size: 1.25rem; font-weight: 650; margin-top: .2rem; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff;
           border: 1px solid #d5dbe3; border-radius: 8px; overflow: hidden; }}
  th, td {{ text-align: left; padding: .55rem .7rem; border-bottom: 1px solid #e8edf2;
            vertical-align: top; font-size: .9rem; }}
  thead th {{ background: #eef2f7; font-size: .78rem; text-transform: uppercase;
              letter-spacing: .04em; color: #566573; }}
  tbody tr:last-child td, tbody tr:last-child th {{ border-bottom: 0; }}
  .rates th {{ width: 34%; }}
  .rates td {{ width: 33%; }}
  .bar {{ height: 6px; background: #e8edf2; border-radius: 3px; margin-top: .35rem; }}
  .bar span {{ display: block; height: 100%; border-radius: 3px; }}
  .wide td:last-child {{ max-width: 520px; }}
  .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }}
  .clean {{ color: #1e8449; font-weight: 600; }}
  h1.v2 {{ margin-top: 2.6rem; padding-top: 1.2rem; border-top: 2px solid #1c2833; }}
  tr.bad td {{ background: #fdecea; }}
  ul {{ line-height: 1.6; color: #34495e; }}
  footer {{ margin-top: 2.5rem; color: #7f8c8d; font-size: .8rem; }}
</style>
</head>
<body>
<main>
  <h1>AgentFence before/after</h1>
  <p class="meta">
    Agent: {_e(comparison.get('agent', 'sample'))}<br>
    Policy: <span class="mono">{_e(comparison['policy'])}</span><br>
    Baseline: <span class="mono">{_e(comparison.get('baseline_source') or '(in-memory)')}</span><br>
    Generated: {_e(comparison.get('generated_at', ''))} ·
    {_e(comparison.get('environment', ''))}
    {('<br>Baseline rows computed for new ids: ' + _e(', '.join(computed))) if computed else ''}
  </p>
  <div class="cards">{cards_html}</div>
  {_table("Attack success rate", overall_rows)}
  {_table("By category", category_rows)}
  <h2>Controls</h2>
  <table class="rates"><thead><tr><th></th><th>before</th><th>after</th></tr></thead>
  <tbody>
    <tr><th>false positives</th>
      <td>{controls['before']['false_positives']} / {controls['before']['controls']}</td>
      <td>{controls['after']['false_positives']} / {controls['after']['controls']}</td></tr>
    <tr><th>benign calls blocked by policy</th>
      <td>{controls['before']['blocked_calls']}</td>
      <td>{controls['after']['blocked_calls']}</td></tr>
  </tbody></table>
  {succeeding_html}
  {fixed_html}
  {v2_html}
  <h2>Caveats</h2>
  <ul>{caveats}</ul>
  <footer>Generated offline by AgentFence. No external assets, no tracking,
  no network requests.</footer>
</main>
</body>
</html>
"""


def write_html(comparison: Mapping[str, Any], path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_html(comparison), encoding="utf-8")
    return target
