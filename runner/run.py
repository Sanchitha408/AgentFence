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
from sample_agent import sandbox
from sample_agent.agent import AgentRun, VulnerableAgent
from sample_agent.mock_llm import MockLLM
from sample_agent.tools import FakeTools

AgentFactory = Callable[[], VulnerableAgent]


def build_sample_agent() -> VulnerableAgent:
    """A brand-new agent with fresh tools and a fresh MockLLM."""
    return VulnerableAgent(tools=FakeTools(), llm=MockLLM())


@dataclass
class AttackResult:
    """The verdict and the evidence for one attack."""

    attack: Attack
    succeeded: bool
    findings: list[Finding] = field(default_factory=list)
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
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
            "owasp_category": self.attack.owasp_category,
            "payload": self.attack.payload,
            "success_condition": self.attack.success_condition,
            "succeeded": self.succeeded,
            "false_positive": self.false_positive,
            "detectors_fired": self.fired,
            "steps": self.steps,
            "stopped": self.stopped,
            "tool_calls": self.tool_calls,
            "final_answer": self.final_answer,
            "findings": [finding.to_dict() for finding in self.findings],
        }


def run_attack(
    attack: Attack,
    agent_factory: AgentFactory = build_sample_agent,
) -> AttackResult:
    """Run one attack in a throwaway sandbox and judge it."""
    state = sandbox.snapshot_state()
    try:
        if attack.setup is not None:
            attack.setup()
        run: AgentRun = agent_factory().run(attack.payload)
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
        final_answer=run.final_answer,
        steps=run.steps,
        stopped=run.stopped,
    )


def run_all(
    attacks: Sequence[Attack] | None = None,
    agent_factory: AgentFactory = build_sample_agent,
) -> list[AttackResult]:
    """Run a list of attacks in order. Defaults to the whole library."""
    if attacks is None:
        from attacks import ALL_ATTACKS

        attacks = ALL_ATTACKS
    return [run_attack(attack, agent_factory=agent_factory) for attack in attacks]
