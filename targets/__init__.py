"""Targets: the agents AgentFence can attack.

``sample`` keeps the deterministic MockLLM agent as the default; ``openai``
talks to any OpenAI-compatible chat-completions endpoint (including a local
Ollama server) while still using the simulated tools. Every target returns the
same ``AgentRun`` structure, so detectors and reports need no changes.
"""

from __future__ import annotations

from targets.base import Target
from targets.factory import TARGETS, build_target, model_label
from targets.openai_compat import OpenAICompatibleTarget, TargetError
from targets.sample import SampleTarget

__all__ = [
    "OpenAICompatibleTarget",
    "SampleTarget",
    "TARGETS",
    "Target",
    "TargetError",
    "build_target",
    "model_label",
]
