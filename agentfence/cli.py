"""The AgentFence CLI: attack, enforce, generate a policy, compare runs."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime
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
from runner import run_all, run_attack
from targets import TARGETS, build_target, model_label
from targets.openai_compat import TargetError

# Agents that can be tested today. Milestone 5 adds HTTP-accessible agents.
AGENTS = ("sample",)
DEFAULT_OUT = "reports/baseline.json"
DEFAULT_AUDIT = "reports/audit.jsonl"
DEFAULT_POLICY = "policies/generated.yaml"
DEFAULT_COMPARE = "reports/compare.json"


def _add_target_options(parser: argparse.ArgumentParser) -> None:
    """Options shared by ``attack`` and ``compare`` for choosing a target."""
    parser.add_argument(
        "--target",
        choices=TARGETS,
        default=None,
        help="target to test: 'sample' (deterministic mock) or 'openai' "
        "(any OpenAI-compatible endpoint); overrides --agent",
    )
    parser.add_argument(
        "--base-url",
        default=None,
        metavar="URL",
        help="OpenAI-compatible base URL, for example "
        "http://localhost:11434/v1 for Ollama",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="model name sent to the endpoint (saved in the report)",
    )
    parser.add_argument(
        "--api-key-env",
        default="OPENAI_API_KEY",
        metavar="ENV_VAR",
        help="environment variable holding the API key; unset means no auth "
        "header, which is what local Ollama needs (default: %(default)s)",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=1,
        metavar="N",
        help="repeat each attack N times and report a success rate instead of "
        "one pass/fail (default: %(default)s)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=180.0,
        metavar="SECONDS",
        help="seconds allowed per model request; a timed-out request is "
        "retried once (default: %(default)s)",
    )
    parser.add_argument(
        "--keep-going",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="record a timed-out or failed attack as an error and continue "
        "with the rest of the scan (default: on; use --no-keep-going to stop "
        "at the first failure)",
    )


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
        default=None,
        help="where to write the JSON report (default: reports/baseline.json "
        "for the sample target; a target-and-model-named file for real "
        "targets)",
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
    _add_target_options(attack)

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
        "--policy-v2",
        default=None,
        metavar="POLICY",
        help="optional second-stage policy (for example policies/v2.yaml); "
        "when given, the report also shows v1 vs v2 side by side",
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
    _add_target_options(compare)
    return parser


def _target_settings(args: argparse.Namespace) -> tuple[str, int]:
    """Resolve --target/--agent and validate the options it needs."""
    target = getattr(args, "target", None) or getattr(args, "agent", "sample")
    runs = getattr(args, "runs", 1)
    if runs < 1:
        raise ValueError("--runs must be at least 1")
    timeout = getattr(args, "timeout", 180.0)
    if timeout <= 0:
        raise ValueError("--timeout must be greater than 0")
    if target == "openai":
        if not getattr(args, "base_url", None):
            raise ValueError("--base-url is required for --target openai")
        if not getattr(args, "model", None):
            raise ValueError("--model is required for --target openai")
    return target, runs


def _target_factory(
    args: argparse.Namespace,
    policy: Any | None = None,
    audit: AuditLog | None = None,
) -> Any:
    """A callable that builds a fresh target with the requested settings."""
    target, _ = _target_settings(args)
    return partial(
        build_target,
        target,
        policy=policy,
        audit=audit,
        base_url=getattr(args, "base_url", None),
        model=getattr(args, "model", None),
        api_key_env=getattr(args, "api_key_env", None),
        timeout=getattr(args, "timeout", 180.0),
    )


def _default_out_path(target: str, model: str | None) -> str:
    """A report path that cannot overwrite the mock baseline.

    Real-model runs are non-deterministic and model-specific, so naming the
    file after the target, model and time keeps them apart from
    ``reports/baseline.json``.
    """
    if target == "sample":
        return DEFAULT_OUT
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", model or "unknown").strip("-.")
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"reports/{target}-{slug or 'unknown'}-{stamp}.json"


def _progress_printer() -> Any:
    """Print one line per attempt, finishing the line once the run ends."""

    def report(event: dict[str, Any]) -> None:
        if event["event"] == "start":
            suffix = (
                f" run {event['run']}/{event['runs']}"
                if event["runs"] > 1
                else ""
            )
            print(
                f"[{event['index']}/{event['total']}] {event['id']}{suffix} ... ",
                end="",
                flush=True,
            )
            return
        status = event["status"].replace("_", "-")
        line = f"{status} ({event['seconds']:.0f}s)"
        if event["status"] == "error" and event.get("error"):
            line += f": {event['error']}"
        print(line, flush=True)

    return report


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

    try:
        target, runs = _target_settings(args)
    except ValueError as exc:
        print(f"agentfence: {exc}", file=sys.stderr)
        return 2

    policy = None
    audit = None
    if args.enforce:
        try:
            policy = load_policy(args.enforce)
        except ValueError as exc:
            print(f"agentfence: {exc}", file=sys.stderr)
            return 2
        audit = AuditLog(args.audit or DEFAULT_AUDIT)

    agent_factory = _target_factory(args, policy=policy, audit=audit)
    output_guard = None
    if policy is not None:
        # The reply stage is separate from tool rules: it runs after the agent
        # answers and withholds a reply that contains prompt/secret material.
        output_guard = OutputGuard(audit=audit)

    try:
        results = run_all(
            attacks,
            agent_factory=agent_factory,
            output_guard=output_guard,
            runs=runs,
            keep_going=args.keep_going,
            progress=_progress_printer(),
        )
    except TargetError as exc:
        print()  # finish a progress line left open by --no-keep-going
        print(f"agentfence: {exc}", file=sys.stderr)
        return 1
    model = model_label(target, args.model)
    report = build_report(
        results,
        agent=target,
        policy=args.enforce or None,
        target=target,
        model=model,
        runs=runs,
    )

    print(format_table(report))

    if not args.no_write:
        out = args.out or _default_out_path(target, model)
        if target != "sample" and Path(out).resolve() == Path(DEFAULT_OUT).resolve():
            # A real-model run must never replace the reproducible baseline.
            out = _default_out_path(target, model)
            print(
                f"agentfence: refusing to write a real-target run to "
                f"{DEFAULT_OUT}; writing {out} instead",
                file=sys.stderr,
            )
        path = write_json(report, out)
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
        target, runs = _target_settings(args)
    except ValueError as exc:
        print(f"agentfence: {exc}", file=sys.stderr)
        return 2

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
    after_factory = _target_factory(args, policy=policy, audit=audit)
    try:
        after_results = run_all(
            ALL_ATTACKS,
            agent_factory=after_factory,
            output_guard=OutputGuard(audit=audit),
            runs=runs,
            keep_going=args.keep_going,
            progress=_progress_printer(),
        )

        v2_results = None
        if args.policy_v2:
            try:
                v2_policy = load_policy(args.policy_v2)
            except ValueError as exc:
                print(f"agentfence: {exc}", file=sys.stderr)
                return 2
            v2_results = run_all(
                ALL_ATTACKS,
                agent_factory=_target_factory(args, policy=v2_policy, audit=audit),
                output_guard=OutputGuard(audit=audit),
                runs=runs,
                keep_going=args.keep_going,
                progress=_progress_printer(),
            )
    except TargetError as exc:
        print()  # finish a progress line left open by --no-keep-going
        print(f"agentfence: {exc}", file=sys.stderr)
        return 1

    saved = {row.get("id"): row for row in baseline.get("results") or []}
    before_rows: list[dict[str, Any]] = []
    computed: list[str] = []
    for attack in ALL_ATTACKS:
        row = saved.get(attack.id)
        if row is None:
            # The library gained an attack since the baseline was captured.
            # Measure it now rather than silently dropping it from the split.
            row = run_attack(
                attack,
                agent_factory=after_factory,
                runs=runs,
                keep_going=args.keep_going,
            ).to_dict()
            computed.append(attack.id)
        else:
            row = dict(row)
        # Trust the library for the cohort, even if the saved report is older.
        row["held_out"] = attack.held_out
        row["held_out_v2"] = attack.held_out_v2
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
        agent=target,
        target=target,
        model=model_label(target, args.model),
        runs=runs,
        v2_rows=[result.to_dict() for result in v2_results]
        if v2_results is not None
        else None,
        v2_policy=args.policy_v2 or "",
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
