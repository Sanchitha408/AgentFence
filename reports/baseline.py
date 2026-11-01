"""The baseline report: how much gets through before any enforcement exists.

Two outputs from the same data: a JSON document for tooling, and a table for
people. Everything is derived from ``AttackResult`` objects, so the numbers can
never drift from the runs.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from attacks.library import CATEGORIES
from runner.run import AttackResult

CATEGORY_LABELS = {
    "direct_injection": "direct injection",
    "indirect_injection": "indirect injection",
    "tool_misuse": "tool misuse",
    "exfiltration": "exfiltration",
    "control": "control",
}

ROW_WIDTHS = {"id": 12, "category": 18, "owasp": 6, "steps": 3}


def _ratio(part: int, total: int) -> float:
    return round(part / total, 4) if total else 0.0


def _owasp_short(owasp: str) -> str:
    return owasp.split(":", 1)[0] if owasp.startswith("LLM") else "-"


def build_report(
    results: Sequence[AttackResult], agent: str = "sample"
) -> dict[str, Any]:
    """Turn a list of results into the baseline report document."""
    attacks = [result for result in results if not result.attack.control]
    controls = [result for result in results if result.attack.control]

    by_category: dict[str, dict[str, Any]] = {}
    for category in CATEGORIES:
        rows = [result for result in attacks if result.attack.category == category]
        if not rows:
            continue
        succeeded = sum(1 for row in rows if row.succeeded)
        by_category[category] = {
            "label": CATEGORY_LABELS.get(category, category),
            "attacks": len(rows),
            "succeeded": succeeded,
            "asr": _ratio(succeeded, len(rows)),
        }

    owasp: dict[str, dict[str, Any]] = {}
    for result in attacks:
        entry = owasp.setdefault(
            result.attack.owasp_category,
            {"attacks": 0, "succeeded": 0, "attack_ids": []},
        )
        entry["attacks"] += 1
        entry["attack_ids"].append(result.attack.id)
        if result.succeeded:
            entry["succeeded"] += 1

    succeeded_total = sum(1 for result in attacks if result.succeeded)
    false_positives = sum(1 for result in controls if result.succeeded)

    return {
        "agent": agent,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "environment": "offline / simulated sandbox, MockLLM (rule-based)",
        "summary": {
            "attacks": len(attacks),
            "succeeded": succeeded_total,
            "asr": _ratio(succeeded_total, len(attacks)),
            "controls": len(controls),
            "false_positives": false_positives,
            "control_fp_rate": _ratio(false_positives, len(controls)),
        },
        "by_category": by_category,
        "owasp": owasp,
        "results": [result.to_dict() for result in results],
    }


def write_json(report: dict[str, Any], path: str | Path) -> Path:
    """Write the report to ``path``, creating parent directories if needed."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return target


def _verdict(row: dict[str, Any]) -> str:
    if row["control"]:
        return "FALSE POSITIVE" if row["succeeded"] else "clean"
    return "VULNERABLE" if row["succeeded"] else "held"


def format_table(report: dict[str, Any]) -> str:
    """A readable terminal table for the report."""
    summary = report["summary"]
    lines: list[str] = []
    header = (
        f"{'ID':<{ROW_WIDTHS['id']}} {'CATEGORY':<{ROW_WIDTHS['category']}} "
        f"{'OWASP':<{ROW_WIDTHS['owasp']}} {'STEPS':>{ROW_WIDTHS['steps']}} "
        f"{'RESULT':<15} DETECTORS"
    )
    rule = "-" * max(len(header), 78)

    lines.append(f"Agent: {report['agent']}  |  {report['environment']}")
    lines.append(rule)
    lines.append(header)
    lines.append(rule)

    for row in report["results"]:
        category = CATEGORY_LABELS.get(row["category"], row["category"])
        detectors = ", ".join(row["detectors_fired"]) or "-"
        lines.append(
            f"{row['id']:<{ROW_WIDTHS['id']}} {category:<{ROW_WIDTHS['category']}} "
            f"{_owasp_short(row['owasp_category']):<{ROW_WIDTHS['owasp']}} "
            f"{row['steps']:>{ROW_WIDTHS['steps']}} "
            f"{_verdict(row):<15} {detectors}"
        )

    lines.append(rule)
    lines.append(
        f"Attack success rate: {summary['succeeded']}/{summary['attacks']} "
        f"({summary['asr'] * 100:.1f}%)"
    )
    for category, stats in report["by_category"].items():
        lines.append(
            f"  {stats['label']:<20} {stats['succeeded']}/{stats['attacks']} "
            f"({stats['asr'] * 100:.1f}%)"
        )
    lines.append(
        f"Controls: {summary['false_positives']} false positive(s) "
        f"out of {summary['controls']}"
    )
    if report["owasp"]:
        lines.append("OWASP mapping:")
        for name, stats in report["owasp"].items():
            lines.append(
                f"  {name:<45} {stats['succeeded']}/{stats['attacks']} attacks"
            )
    return "\n".join(lines)
