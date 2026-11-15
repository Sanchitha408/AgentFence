"""Run attacks against a target and record exactly what happened.

Each attack gets a fresh target and a fresh fake world: the sandbox state is
snapshotted, the attack may plant its bait, the target runs once, all detectors
look at the run, and then the sandbox is put back. ``runs`` repeats that whole
sequence, which is how a non-deterministic real model gets a per-attack success
rate instead of a single pass/fail.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Sequence

from attacks.models import Attack
from detectors import Finding, run_detectors
from detectors.base import executed_tool_calls
from enforcer.audit import AuditLog
from enforcer.guard import BLOCKED_PREFIX, GuardedTools
from enforcer.output_guard import OutputGuard, ReplyCheck
from enforcer.policy import Policy
from sample_agent import sandbox
from sample_agent.agent import AgentRun, VulnerableAgent
from sample_agent.mock_llm import MockLLM
from sample_agent.tools import FakeTools

AgentFactory = Callable[[], VulnerableAgent]


def build_sample_agent(
    policy: Policy | None = None,
    audit: AuditLog | None = None,
) -> VulnerableAgent:
    """A brand-new agent with fresh tools and a fresh MockLLM.

    Without ``policy`` the agent gets the raw ``FakeTools`` - that is the
    baseline. With a policy, every call goes through ``GuardedTools`` and the
    audit log first.
    """
    tools: Any = FakeTools()
    if policy is not None:
        tools = GuardedTools(tools, policy, audit)
    return VulnerableAgent(tools=tools, llm=MockLLM())


@dataclass
class AttackResult:
    """The verdict and the evidence for one attack."""

    attack: Attack
    succeeded: bool
    findings: list[Finding] = field(default_factory=list)
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    executed_calls: list[dict[str, Any]] = field(default_factory=list)
    blocked_calls: list[dict[str, Any]] = field(default_factory=list)
    reply_check: ReplyCheck | None = None
    final_answer: str = ""
    steps: int = 0
    stopped: str = "final_answer"
    # Set when the target could not produce a run at all (timeout, HTTP error).
    error: str = ""
    # How many times this attack was repeated, and how often it worked. With
    # runs=1 these stay at one attempt and 0%/100%, so old reports are
    # unchanged in meaning.
    runs: int = 1
    successes: int = 0
    success_rate: float = 0.0
    attempts: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.attempts:
            self.attempts = [
                {
                    "succeeded": self.succeeded,
                    "detectors_fired": self.fired,
                    "steps": self.steps,
                    "stopped": self.stopped,
                    "status": self.status,
                    "error": self.error,
                    "blocked_by": _blocked_rule_ids(self),
                }
            ]
        self.runs = max(len(self.attempts), 1)
        self.successes = sum(
            1 for attempt in self.attempts if attempt.get("succeeded")
        )
        self.success_rate = round(self.successes / self.runs, 4)

    @property
    def fired(self) -> list[str]:
        """Detectors that reported a problem on this run."""
        return [finding.detector for finding in self.findings if finding.detected]

    @property
    def status(self) -> str:
        """What happened, in one word.

        ``succeeded`` is the success condition firing. ``attempted`` means the
        agent went after the goal (another detector fired) but the success
        condition did not, so it must not be called a win or a clean hold.
        ``held`` is no detector at all; ``error`` is a run that never happened.
        """
        if self.attack.control:
            if self.error:
                return "error"
            return "false_positive" if self.succeeded else "clean"
        if self.succeeded:
            return "succeeded"
        if self.fired:
            return "attempted"
        if self.error:
            return "error"
        return "held"

    @property
    def false_positive(self) -> bool:
        """A control that triggered a detector is a false alarm, not a win."""
        return bool(self.attack.control and self.succeeded)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.attack.id,
            "name": self.attack.name,
            "category": self.attack.category,
            "control": self.attack.control,
            "held_out": self.attack.held_out,
            "held_out_v2": self.attack.held_out_v2,
            "owasp_category": self.attack.owasp_category,
            "payload": self.attack.payload,
            "success_condition": self.attack.success_condition,
            "succeeded": self.succeeded,
            "false_positive": self.false_positive,
            "status": self.status,
            "error": self.error,
            "runs": self.runs,
            "successes": self.successes,
            "success_rate": self.success_rate,
            "detectors_fired": self.fired,
            "steps": self.steps,
            "stopped": self.stopped,
            "tool_calls": self.tool_calls,
            "executed_calls": self.executed_calls,
            "blocked_calls": self.blocked_calls,
            "reply_check": (
                self.reply_check.to_dict()
                if self.reply_check is not None
                else {"checked": False, "blocked": False, "markers": [], "reason": ""}
            ),
            "final_answer": self.final_answer,
            "findings": [finding.to_dict() for finding in self.findings],
            **({"attempts": list(self.attempts)} if self.runs > 1 else {}),
        }


def _blocked_calls(run: AgentRun) -> list[dict[str, Any]]:
    """Tool calls the guard refused, with the rule id and reason it gave."""
    pending: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    for message in run.transcript:
        call = message.get("tool_call")
        if call:
            pending.append(call)
            continue
        if message.get("role") != "tool" or not pending:
            continue
        call = pending.pop(0)
        content = str(message.get("content", ""))
        if message.get("ok") is not False or not content.startswith(BLOCKED_PREFIX):
            continue
        rest = content[len(BLOCKED_PREFIX) :].strip()
        rule_id, _, reason = rest.partition(" - ")
        rule_id = rule_id.replace("(awaiting human approval)", "").strip()
        blocked.append(
            {
                "tool": call.get("name", ""),
                "arguments": call.get("arguments") or {},
                "rule_id": rule_id,
                "reason": reason.strip(),
                "message": content,
            }
        )
    return blocked


def _run_once(
    attack: Attack,
    agent_factory: Callable[[], Any],
    output_guard: OutputGuard | None,
) -> AttackResult:
    """One attack execution in a throwaway sandbox, judged by the detectors."""
    state = sandbox.snapshot_state()
    try:
        if attack.setup is not None:
            attack.setup()
        run: AgentRun = agent_factory().run(attack.payload)
        reply_check = output_guard.inspect(run) if output_guard is not None else None
        findings = run_detectors(run)
    finally:
        sandbox.restore_state(state)

    fired = {finding.detector for finding in findings if finding.detected}
    if attack.control:
        # A control "succeeds" only if it somehow trips a detector: that is the
        # false positive the platform must not produce.
        succeeded = bool(fired)
    else:
        succeeded = attack.success_condition in fired

    return AttackResult(
        attack=attack,
        succeeded=succeeded,
        findings=findings,
        tool_calls=run.tool_calls(),
        executed_calls=executed_tool_calls(run),
        blocked_calls=_blocked_calls(run),
        reply_check=reply_check,
        final_answer=run.final_answer,
        steps=run.steps,
        stopped=run.stopped,
    )


def _merge_findings(attempts: Sequence[AttackResult]) -> list[Finding]:
    """One finding per detector, keeping evidence from a run that fired."""
    merged: dict[str, Finding] = {}
    order: list[str] = []
    for attempt in attempts:
        for finding in attempt.findings:
            if finding.detector not in merged:
                merged[finding.detector] = finding
                order.append(finding.detector)
            elif finding.detected and not merged[finding.detector].detected:
                merged[finding.detector] = finding
    return [merged[name] for name in order]


def _merge_attempts(
    attack: Attack, attempts: Sequence[AttackResult]
) -> AttackResult:
    """Collapse repeated runs into one result with a success rate."""
    if len(attempts) == 1:
        return attempts[0]

    successes = sum(1 for attempt in attempts if attempt.succeeded)
    # The representative attempt is the first one that worked; otherwise the
    # last one, whose evidence is the most recent failure to hold.
    representative = next(
        (attempt for attempt in attempts if attempt.succeeded), attempts[-1]
    )
    findings = _merge_findings(attempts)
    merged_error = (
        next((attempt.error for attempt in attempts if attempt.error), "")
        if successes == 0 and not any(finding.detected for finding in findings)
        else ""
    )
    attempt_rows = [
        {
            "succeeded": attempt.succeeded,
            "detectors_fired": attempt.fired,
            "steps": attempt.steps,
            "stopped": attempt.stopped,
            "status": attempt.status,
            "error": attempt.error,
            "blocked_by": _blocked_rule_ids(attempt),
        }
        for attempt in attempts
    ]
    return AttackResult(
        attack=attack,
        succeeded=successes > 0,
        findings=findings,
        tool_calls=representative.tool_calls,
        executed_calls=representative.executed_calls,
        blocked_calls=representative.blocked_calls,
        reply_check=representative.reply_check,
        final_answer=representative.final_answer,
        steps=representative.steps,
        stopped=representative.stopped,
        error=merged_error,
        runs=len(attempts),
        successes=successes,
        success_rate=round(successes / len(attempts), 4),
        attempts=attempt_rows,
    )


def _blocked_rule_ids(result: AttackResult) -> list[str]:
    """Rules that stopped a call in one run, for per-run outcome counts."""
    rules: list[str] = []
    for call in result.blocked_calls:
        rule = str(call.get("rule_id") or "")
        if rule and rule not in rules:
            rules.append(rule)
    reply = result.reply_check
    if reply is not None and reply.blocked and "reply-leak-check" not in rules:
        rules.append("reply-leak-check")
    return rules


def _error_result(attack: Attack, exc: BaseException) -> AttackResult:
    """An attack that could not run, recorded as evidence instead of a crash."""
    message = str(exc).strip() or type(exc).__name__
    return AttackResult(
        attack=attack,
        succeeded=False,
        steps=0,
        stopped="error",
        error=message,
    )


ProgressCallback = Callable[[dict[str, Any]], None]


def run_attack(
    attack: Attack,
    agent_factory: Callable[[], Any] = build_sample_agent,
    output_guard: OutputGuard | None = None,
    runs: int = 1,
    *,
    keep_going: bool = False,
    progress: ProgressCallback | None = None,
) -> AttackResult:
    """Run one attack in a throwaway sandbox and judge it.

    ``output_guard`` is the separate reply stage. It is optional so tool-policy
    experiments can be run on their own; the CLI and ``compare`` pass one.
    ``runs`` repeats the run in a fresh sandbox each time and reports the
    success rate; with ``runs=1`` the result is exactly the old pass/fail.
    ``keep_going`` turns an exception into an ``error`` result and moves on;
    the default re-raises, which is what library callers expect.
    """
    if runs < 1:
        raise ValueError("runs must be at least 1")

    attempts: list[AttackResult] = []
    for run_index in range(1, runs + 1):
        if progress is not None:
            progress(
                {
                    "event": "start",
                    "id": attack.id,
                    "run": run_index,
                    "runs": runs,
                }
            )
        started = time.monotonic()
        try:
            attempt = _run_once(attack, agent_factory, output_guard)
        except Exception as exc:
            if not keep_going:
                raise
            attempt = _error_result(attack, exc)
        elapsed = time.monotonic() - started
        if progress is not None:
            progress(
                {
                    "event": "finish",
                    "id": attack.id,
                    "run": run_index,
                    "runs": runs,
                    "status": attempt.status,
                    "error": attempt.error,
                    "seconds": elapsed,
                }
            )
        attempts.append(attempt)

    return _merge_attempts(attack, attempts)


def run_all(
    attacks: Sequence[Attack] | None = None,
    agent_factory: Callable[[], Any] = build_sample_agent,
    output_guard: OutputGuard | None = None,
    runs: int = 1,
    *,
    keep_going: bool = False,
    progress: ProgressCallback | None = None,
) -> list[AttackResult]:
    """Run a list of attacks in order. Defaults to the whole library."""
    if attacks is None:
        from attacks import ALL_ATTACKS

        attacks = ALL_ATTACKS

    total = len(attacks)
    results: list[AttackResult] = []
    for index, attack in enumerate(attacks, 1):
        def scoped(
            event: dict[str, Any],
            index: int = index,
            attack: Attack = attack,
        ) -> None:
            if progress is not None:
                progress({**event, "index": index, "total": total})

        results.append(
            run_attack(
                attack,
                agent_factory=agent_factory,
                output_guard=output_guard,
                runs=runs,
                keep_going=keep_going,
                progress=scoped if progress is not None else None,
            )
        )
    return results
