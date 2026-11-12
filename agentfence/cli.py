"""The AgentFence CLI: attack, enforce, generate a policy, compare runs."""

from __future__ import annotations

import argparse
import json
import sys
from functools import partial
from pathlib import Path
from typing import Any, Sequence

from attacks import ALL_ATTACKS, by_id
from autopolicy import generate_from_report
from enforcer import AuditLog, OutputGuard, load_policy
from reports import (
    build_comparison,
    build_report,
    format_compare_table,
    format_table,
    write_html,
    write_json,
)
from runner import build_sample_agent, run_all, run_attack

# Agents that can be tested today. Milestone 5 adds HTTP-accessible agents.
AGENTS = ("sample",)
DEFAULT_OUT = "reports/baseline.json"
DEFAULT_AUDIT = "reports/audit.jsonl"
DEFAULT_POLICY = "policies/generated.yaml"
DEFAULT_COMPARE = "reports/compare.json"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentfence",
        description=(
            "Attack an AI agent, detect what gets through, and report on it. "
            "Everything runs offline against a simulated sandbox."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    attack = subparsers.add_parser(
        "attack", help="run the attack library against an agent"
    )
    attack.add_argument(
        "--agent",
        default="sample",
        choices=AGENTS,
        help="agent to test (default: %(default)s)",
    )
    attack.add_argument(
        "--out",
        default=DEFAULT_OUT,
        help="where to write the JSON report (default: %(default)s)",
    )
    attack.add_argument(
        "--enforce",
        metavar="POLICY",
        default=None,
        help="check every tool call against this YAML policy before it runs",
    )
    attack.add_argument(
        "--audit",
        metavar="PATH",
        default=None,
        help=f"JSONL audit log (default when enforcing: {DEFAULT_AUDIT})",
    )
    attack.add_argument(
        "--id",
        action="append",
        metavar="ATTACK_ID",
        help="run only this attack id (repeatable)",
    )
    attack.add_argument(
        "--no-write",
        action="store_true",
        help="print the report without writing a JSON file",
    )

    autopolicy = subparsers.add_parser(
        "autopolicy",
        help="generate a suggested YAML policy from a baseline report",
    )
    autopolicy.add_argument(
        "--baseline",
        default=DEFAULT_OUT,
        help="baseline JSON to learn from (default: %(default)s)",
    )
    autopolicy.add_argument(
        "--out",
        default=DEFAULT_POLICY,
        help="where to write the generated policy (default: %(default)s)",
    )

    compare = subparsers.add_parser(
        "compare",
        help="re-run attacks under a policy and report before/after",
    )
    compare.add_argument(
        "--baseline",
        default=DEFAULT_OUT,
        help="baseline JSON captured without a policy (default: %(default)s)",
    )
    compare.add_argument(
        "--policy",
        default=DEFAULT_POLICY,
        help="policy to enforce for the after run (default: %(default)s)",
    )
    compare.add_argument(
        "--out",
        default=DEFAULT_COMPARE,
        help="where to write the JSON comparison (default: %(default)s)",
    )
    compare.add_argument(
        "--html",
        default=None,
        help="where to write the self-contained HTML report "
        "(default: alongside --out with .html)",
    )
    compare.add_argument(
        "--audit",
        default=None,
        metavar="PATH",
        help="optional JSONL audit log for the enforced run",
    )
    compare.add_argument(
        "--agent",
        default="sample",
        choices=AGENTS,
        help="agent to test (default: %(default)s)",
    )
    return parser


def _select(args: argparse.Namespace) -> tuple:
    if not args.id:
        return ALL_ATTACKS
    selected = []
    for attack_id in args.id:
        try:
            selected.append(by_id(attack_id))
        except KeyError:
            print(f"agentfence: unknown attack id '{attack_id}'", file=sys.stderr)
            print(
                "known ids: " + ", ".join(attack.id for attack in ALL_ATTACKS),
                file=sys.stderr,
            )
            raise SystemExit(2) from None
    return tuple(selected)


def _run_attack_command(args: argparse.Namespace) -> int:
    attacks = _select(args)

    policy = None
    audit = None
    if args.enforce:
        try:
            policy = load_policy(args.enforce)
        except ValueError as exc:
            print(f"agentfence: {exc}", file=sys.stderr)
            return 2
        audit = AuditLog(args.audit or DEFAULT_AUDIT)

    agent_factory = build_sample_agent
    output_guard = None
    if policy is not None:
        agent_factory = partial(build_sample_agent, policy=policy, audit=audit)
        # The reply stage is separate from tool rules: it runs after the agent
        # answers and withholds a reply that contains prompt/secret material.
        output_guard = OutputGuard(audit=audit)

    results = run_all(
        attacks, agent_factory=agent_factory, output_guard=output_guard
    )
    report = build_report(results, agent=args.agent, policy=args.enforce or None)

    print(format_table(report))

    if not args.no_write:
        path = write_json(report, args.out)
        print(f"\nJSON report written to {path}")
    if audit is not None:
        print(f"Audit log appended to {audit.path}")

    return 0


def _load_json(path: str) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"{path}: cannot read report: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: not valid JSON: {exc}") from exc


def _run_autopolicy_command(args: argparse.Namespace) -> int:
    try:
        report = _load_json(args.baseline)
    except ValueError as exc:
        print(f"agentfence: {exc}", file=sys.stderr)
        return 2

    try:
        policy = generate_from_report(
            report, source=f"{args.baseline} (policy-free baseline)"
        )
    except ValueError as exc:
        print(f"agentfence: cannot generate policy: {exc}", file=sys.stderr)
        return 2

    try:
        policy.load()  # round-trip through the real loader before writing
    except ValueError as exc:
        print(f"agentfence: generated policy is invalid: {exc}", file=sys.stderr)
        return 2

    path = policy.write(args.out)
    print(
        f"Analysed {policy.analysed} failed original attack(s); "
        f"generated {len(policy.rules)} rule(s)."
    )
    for rule in policy.rules:
        print(
            f"  {rule.id:<36} {rule.decision:<6} {rule.type:<20} "
            f"from {', '.join(rule.derived_from)}"
        )
    print(f"\nSuggested policy written to {path}")
    return 0


def _run_compare_command(args: argparse.Namespace) -> int:
    try:
        baseline = _load_json(args.baseline)
    except ValueError as exc:
        print(f"agentfence: {exc}", file=sys.stderr)
        return 2
    if not isinstance(baseline, dict) or not isinstance(
        baseline.get("results"), list
    ):
        print(
            f"agentfence: {args.baseline}: expected a report with a results list",
            file=sys.stderr,
        )
        return 2

    try:
        policy = load_policy(args.policy)
    except ValueError as exc:
        print(f"agentfence: {exc}", file=sys.stderr)
        return 2

    audit = AuditLog(args.audit) if args.audit else None
    after_results = run_all(
        ALL_ATTACKS,
        agent_factory=partial(build_sample_agent, policy=policy, audit=audit),
        output_guard=OutputGuard(audit=audit),
    )

    saved = {row.get("id"): row for row in baseline.get("results") or []}
    before_rows: list[dict[str, Any]] = []
    computed: list[str] = []
    for attack in ALL_ATTACKS:
        row = saved.get(attack.id)
        if row is None:
            # The library gained an attack since the baseline was captured.
            # Measure it now rather than silently dropping it from the split.
            row = run_attack(attack).to_dict()
            computed.append(attack.id)
        else:
            row = dict(row)
        # Trust the library for the cohort, even if the saved report is older.
        row["held_out"] = attack.held_out
        row["control"] = attack.control
        row.setdefault("category", attack.category)
        row.setdefault("detectors_fired", [])
        before_rows.append(row)

    after_rows = [result.to_dict() for result in after_results]
    comparison = build_comparison(
        before_rows,
        after_rows,
        policy=args.policy,
        baseline_source=args.baseline,
        computed_baseline_ids=computed,
        agent=args.agent,
    )

    json_path = write_json(comparison, args.out)
    html_path = write_html(
        comparison,
        args.html or str(Path(args.out).with_suffix(".html")),
    )
    print(format_compare_table(comparison))
    print(f"\nJSON comparison written to {json_path}")
    print(f"HTML comparison written to {html_path}")
    if audit is not None:
        print(f"Audit log appended to {audit.path}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "attack":
        return _run_attack_command(args)
    if args.command == "autopolicy":
        return _run_autopolicy_command(args)
    if args.command == "compare":
        return _run_compare_command(args)

    parser.error(f"unknown command: {args.command}")
    return 2
