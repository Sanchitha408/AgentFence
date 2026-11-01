"""``agentfence attack``: run the attack library and print the baseline."""

from __future__ import annotations

import argparse
import sys
from typing import Sequence

from attacks import ALL_ATTACKS, by_id
from reports import build_report, format_table, write_json
from runner import run_all

# Agents that can be tested today. Milestone 5 adds HTTP-accessible agents.
AGENTS = ("sample",)
DEFAULT_OUT = "reports/baseline.json"


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
        help="where to write the JSON baseline (default: %(default)s)",
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
    results = run_all(attacks)
    report = build_report(results, agent=args.agent)

    print(format_table(report))

    if not args.no_write:
        path = write_json(report, args.out)
        print(f"\nJSON baseline written to {path}")

    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "attack":
        return _run_attack_command(args)

    parser.error(f"unknown command: {args.command}")
    return 2
