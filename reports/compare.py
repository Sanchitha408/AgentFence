"""The before/after report: what a policy changed.

Input is two sets of result rows - a baseline run with no policy and a re-run
with the generated policy - and output is a JSON document designed to be read
by both people and tools. The important separations are:

* overall attacks vs original attacks vs held-out attacks;
* attack success rate per category;
* false positives on benign controls;
* every attack that still succeeds, with the evidence and the calls it made.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from attacks.library import CATEGORIES
from reports.baseline import CATEGORY_LABELS, _ratio

ORIGINAL = "original"
HELD_OUT = "held_out"
COHORTS = (ORIGINAL, HELD_OUT)


def _compact(value: Any, limit: int = 110) -> str:
    text = json.dumps(value, sort_keys=True, default=str)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _evidence(row: Mapping[str, Any]) -> list[str]:
    found: list[str] = []
    for finding in row.get("findings") or []:
        if finding.get("detected"):
            for item in finding.get("evidence") or []:
                if item not in found:
                    found.append(str(item))
    return found


def _rate(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    attacks = [row for row in rows if not row.get("control")]
    succeeded = sum(1 for row in attacks if row.get("succeeded"))
    return {
        "attacks": len(attacks),
        "succeeded": succeeded,
        "asr": _ratio(succeeded, len(attacks)),
    }


def _cohort(row: Mapping[str, Any]) -> str:
    return HELD_OUT if row.get("held_out") else ORIGINAL


def _controls(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    controls = [row for row in rows if row.get("control")]
    false_positives = [row["id"] for row in controls if row.get("succeeded")]
    blocked = sum(len(row.get("blocked_calls") or []) for row in controls)
    return {
        "controls": len(controls),
        "false_positives": len(false_positives),
        "false_positive_ids": false_positives,
        "control_fp_rate": _ratio(len(false_positives), len(controls)),
        "blocked_calls": blocked,
    }


def _blocked_by(row: Mapping[str, Any]) -> list[str]:
    reasons: list[str] = []
    for call in row.get("blocked_calls") or []:
        rule = str(call.get("rule_id") or "")
        if rule and rule not in reasons:
            reasons.append(rule)
    reply = row.get("reply_check") or {}
    if reply.get("blocked") and "reply-leak-check" not in reasons:
        reasons.append("reply-leak-check")
    return reasons


def _executed_summary(row: Mapping[str, Any]) -> str:
    calls = row.get("executed_calls")
    if calls is None:
        # Older baseline reports did not record this; tool_calls is the best
        # available approximation.
        calls = row.get("tool_calls") or []
    if not calls:
        return "no tool call executed"
    parts = []
    for call in calls:
        name = call.get("name", "?")
        arguments = call.get("arguments") or {}
        parts.append(f"{name}({_compact(arguments)})")
    return "; ".join(parts)


def _why_succeeds(row: Mapping[str, Any]) -> str:
    """A plain-English reason, built only from recorded evidence."""
    parts: list[str] = []
    fired = row.get("detectors_fired") or []
    if fired:
        parts.append("detector(s) " + ", ".join(str(name) for name in fired) + " fired")
    evidence = _evidence(row)
    if evidence:
        parts.append("evidence: " + "; ".join(evidence[:4]))
    parts.append("executed: " + _executed_summary(row))

    blocked = row.get("blocked_calls") or []
    if blocked:
        names = []
        for call in blocked:
            names.append(
                f"{call.get('tool')} by {call.get('rule_id') or 'unknown rule'}"
            )
        parts.append(
            "other calls were blocked ("
            + "; ".join(names)
            + "), but the harmful call above was executed"
        )
    else:
        parts.append("no policy rule blocked the harmful call")

    reply = row.get("reply_check") or {}
    if reply.get("checked") and not reply.get("blocked"):
        parts.append("the reply stage found no protected content")
    return ". ".join(parts)


def _succeeding_row(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "name": row.get("name", ""),
        "category": row.get("category", ""),
        "cohort": _cohort(row),
        "owasp_category": row.get("owasp_category", ""),
        "detectors_fired": list(row.get("detectors_fired") or []),
        "evidence": _evidence(row),
        "executed_calls": row.get("executed_calls") or [],
        "blocked_calls": row.get("blocked_calls") or [],
        "reply_check": row.get("reply_check") or {},
        "reason": _why_succeeds(row),
    }


def _fixed_row(before: Mapping[str, Any], after: Mapping[str, Any]) -> dict[str, Any]:
    blocked_by = _blocked_by(after)
    if not blocked_by:
        blocked_by = ["no detector fired after enforcement"]
    return {
        "id": before["id"],
        "name": before.get("name", ""),
        "category": before.get("category", ""),
        "cohort": _cohort(before),
        "blocked_by": blocked_by,
    }


def _category_table(
    before: Sequence[Mapping[str, Any]], after: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    table: dict[str, Any] = {}
    for category in CATEGORIES:
        if category == "control":
            continue
        before_rows = [row for row in before if row.get("category") == category]
        after_rows = [row for row in after if row.get("category") == category]
        if not before_rows and not after_rows:
            continue
        table[category] = {
            "label": CATEGORY_LABELS.get(category, category),
            "before": _rate(before_rows),
            "after": _rate(after_rows),
        }
    return table


def build_comparison(
    before_rows: Sequence[Mapping[str, Any]],
    after_rows: Sequence[Mapping[str, Any]],
    policy: str,
    *,
    baseline_source: str = "",
    computed_baseline_ids: Sequence[str] = (),
    agent: str = "sample",
) -> dict[str, Any]:
    """Combine a baseline and an enforced run into one report document."""
    before_by_id = {row["id"]: row for row in before_rows}
    after_by_id = {row["id"]: row for row in after_rows}

    ordered_before = [
        before_by_id[row["id"]]
        for row in after_rows
        if row["id"] in before_by_id
    ]
    ordered_after = list(after_rows)

    def cohort_rows(rows: Sequence[Mapping[str, Any]], cohort: str):
        return [row for row in rows if _cohort(row) == cohort]

    overall_before = _rate(ordered_before)
    overall_after = _rate(ordered_after)

    cohorts: dict[str, Any] = {}
    for cohort in COHORTS:
        cohorts[cohort] = {
            "label": "original attacks" if cohort == ORIGINAL else "held-out attacks",
            "before": _rate(cohort_rows(ordered_before, cohort)),
            "after": _rate(cohort_rows(ordered_after, cohort)),
        }

    still_succeeding = [
        _succeeding_row(row)
        for row in ordered_after
        if not row.get("control") and row.get("succeeded")
    ]
    fixed = [
        _fixed_row(before_by_id[row["id"]], row)
        for row in ordered_after
        if not row.get("control")
        and row["id"] in before_by_id
        and before_by_id[row["id"]].get("succeeded")
        and not row.get("succeeded")
    ]
    regressions = [
        row["id"]
        for row in ordered_after
        if not row.get("control")
        and row["id"] in before_by_id
        and not before_by_id[row["id"]].get("succeeded")
        and row.get("succeeded")
    ]

    return {
        "agent": agent,
        "policy": policy,
        "baseline_source": baseline_source,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "environment": "offline / simulated sandbox, MockLLM (rule-based)",
        "baseline_computed_ids": list(computed_baseline_ids),
        "summary": {
            "before": overall_before,
            "after": overall_after,
            "delta_asr": round(overall_after["asr"] - overall_before["asr"], 4),
            "attacks_fixed": len(fixed),
            "attacks_still_succeeding": len(still_succeeding),
        },
        "cohorts": cohorts,
        "by_category": _category_table(ordered_before, ordered_after),
        "controls": {
            "before": _controls(ordered_before),
            "after": _controls(ordered_after),
        },
        "still_succeeding": still_succeeding,
        "fixed": fixed,
        "regressions": regressions,
        "caveats": [
            "Held-out attacks were never shown to the auto-policy generator; "
            "their results measure generalisation, not training fit.",
            "The reply stage only withholds final answers containing known canary "
            "values or system-prompt marker phrases. A paraphrase would pass.",
            "A control counts as a false positive only when a detector fires. "
            "Benign calls blocked by policy are reported separately as "
            "controls.after.blocked_calls.",
            "Everything is simulated: no real file, email, shell or network access.",
        ],
        "results": {
            "before": list(ordered_before),
            "after": list(ordered_after),
        },
    }


def format_compare_table(comparison: Mapping[str, Any]) -> str:
    """A terminal table for the before/after report."""
    lines: list[str] = []
    summary = comparison["summary"]
    cohorts = comparison["cohorts"]
    controls = comparison["controls"]

    def rate(cell: Mapping[str, Any]) -> str:
        return f"{cell['succeeded']}/{cell['attacks']} ({cell['asr'] * 100:.1f}%)"

    lines.append("AgentFence before/after")
    lines.append(
        f"Agent: {comparison.get('agent', 'sample')}  |  "
        f"{comparison.get('environment', '')}"
    )
    lines.append(f"Policy: {comparison['policy']}")
    lines.append(f"Baseline: {comparison.get('baseline_source') or '(in-memory)'}")
    if comparison.get("baseline_computed_ids"):
        lines.append(
            "Baseline rows computed for new ids: "
            + ", ".join(comparison["baseline_computed_ids"])
        )
    lines.append("-" * 78)
    lines.append(f"{'ATTACK SET':<30} {'BEFORE':<22} AFTER")
    lines.append("-" * 78)
    lines.append(
        f"{'overall':<30} {rate(summary['before']):<22} {rate(summary['after'])}"
    )
    for cohort in COHORTS:
        cell = cohorts[cohort]
        label = cell["label"]
        lines.append(
            f"{label:<30} {rate(cell['before']):<22} {rate(cell['after'])}"
        )
    lines.append("-" * 78)
    lines.append(f"{'CATEGORY':<22} {'BEFORE':<22} AFTER")
    for category, cell in comparison["by_category"].items():
        lines.append(
            f"{cell['label']:<22} {rate(cell['before']):<22} {rate(cell['after'])}"
        )
    lines.append("-" * 78)
    lines.append(
        f"Control false positives: before "
        f"{controls['before']['false_positives']}/{controls['before']['controls']}, "
        f"after {controls['after']['false_positives']}/{controls['after']['controls']}"
        f"  |  blocked benign calls after: {controls['after']['blocked_calls']}"
    )
    lines.append(
        f"Fixed: {summary['attacks_fixed']}  |  "
        f"still succeeding: {summary['attacks_still_succeeding']}  |  "
        f"regressions: {len(comparison['regressions'])}"
    )

    if comparison["still_succeeding"]:
        lines.append("-" * 78)
        lines.append("Still succeeding:")
        for row in comparison["still_succeeding"]:
            cohort = "held-out" if row["cohort"] == HELD_OUT else "original"
            lines.append(
                f"  {row['id']:<18} {cohort:<9} {row['category']:<18} "
                f"{', '.join(row['detectors_fired']) or '-'}"
            )
            lines.append(f"    why: {row['reason']}")
    return "\n".join(lines)
