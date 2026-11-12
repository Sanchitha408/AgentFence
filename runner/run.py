"""Run attacks against an agent and record exactly what happened.

Each attack gets a fresh agent and a fresh fake world: the sandbox state is
snapshotted, the attack may plant its bait, the agent runs once, all detectors
look at the run, and then the sandbox is put back.
"""

from __future__ import annotations

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

    @property
    def fired(self) -> list[str]:
        """Detectors that reported a problem on this run."""
        return [finding.detector for finding in self.findings if finding.detected]

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
            "owasp_category": self.attack.owasp_category,
            "payload": self.attack.payload,
            "success_condition": self.attack.success_condition,
            "succeeded": self.succeeded,
            "false_positive": self.false_positive,
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


def run_attack(
    attack: Attack,
    agent_factory: AgentFactory = build_sample_agent,
    output_guard: OutputGuard | None = None,
) -> AttackResult:
    """Run one attack in a throwaway sandbox and judge it.

    ``output_guard`` is the separate reply stage. It is optional so tool-policy
    experiments can be run on their own; the CLI and ``compare`` pass one.
    """
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


def run_all(
    attacks: Sequence[Attack] | None = None,
    agent_factory: AgentFactory = build_sample_agent,
    output_guard: OutputGuard | None = None,
) -> list[AttackResult]:
    """Run a list of attacks in order. Defaults to the whole library."""
    if attacks is None:
        from attacks import ALL_ATTACKS

        attacks = ALL_ATTACKS
    return [
        run_attack(attack, agent_factory=agent_factory, output_guard=output_guard)
        for attack in attacks
    ]
