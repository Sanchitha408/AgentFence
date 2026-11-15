"""The original deterministic target: the MockLLM-based sample agent."""

from __future__ import annotations

from typing import Any

from sample_agent.agent import DEFAULT_SYSTEM_PROMPT, MAX_STEPS, AgentRun, VulnerableAgent
from sample_agent.mock_llm import MockLLM
from targets.base import Target


class SampleTarget(Target):
    """A thin Target wrapper around :class:`VulnerableAgent`.

    The agent's planning is still the offline, rule-based ``MockLLM``; only the
    interface is new. Keeping this target as the default is what lets the whole
    existing test suite and the reproducible benchmark numbers stay unchanged.
    """

    kind = "sample"
    model = "MockLLM (rule-based)"

    def __init__(
        self,
        tools: Any | None = None,
        system_prompt: str = DEFAULT_SYSTEM_PROMPT,
        max_steps: int = MAX_STEPS,
    ) -> None:
        super().__init__(tools=tools, max_steps=max_steps)
        self.agent = VulnerableAgent(
            tools=self.tools, llm=MockLLM(), system_prompt=system_prompt
        )

    def run(self, task: str, max_steps: int | None = None) -> AgentRun:
        return self.agent.run(task, max_steps=max_steps or self.max_steps)
