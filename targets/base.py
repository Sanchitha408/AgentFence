"""The target interface: the thing AgentFence attacks.

A target takes a user task and returns an :class:`AgentRun` - the same
structure the detectors, enforcer and reports already consume. Everything a
target does with its tools stays simulated: the tools always come from
``sample_agent.tools.FakeTools`` (optionally wrapped by the enforce
``GuardedTools``), so no target can touch a real file, email, shell or network.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from sample_agent.agent import MAX_STEPS, AgentRun
from sample_agent.tools import FakeTools


class Target(ABC):
    """One agent under test.

    Subclasses decide *how* the agent chooses its actions (a rule-based mock, a
    real model over HTTP, ...) but they share the same tool bundle and the same
    ``run(task) -> AgentRun`` contract.
    """

    #: Short identifier used in reports and on the command line.
    kind = "target"
    #: Human-readable model label saved with every report.
    model = "unknown"

    def __init__(
        self,
        tools: Any | None = None,
        max_steps: int = MAX_STEPS,
    ) -> None:
        self.tools = tools if tools is not None else FakeTools()
        self.max_steps = max_steps

    @abstractmethod
    def run(self, task: str, max_steps: int | None = None) -> AgentRun:
        """Run one user task to completion or until the step budget is spent."""

    def info(self) -> dict[str, Any]:
        """Metadata recorded alongside a run."""
        return {"target": self.kind, "model": self.model}
