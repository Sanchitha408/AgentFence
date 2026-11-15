"""Build a target by name, with the same (optionally guarded) fake tools."""

from __future__ import annotations

from typing import Any

from enforcer.audit import AuditLog
from enforcer.guard import GuardedTools
from enforcer.policy import Policy
from sample_agent.tools import FakeTools
from targets.base import Target
from targets.openai_compat import OpenAICompatibleTarget, api_key_from_env
from targets.sample import SampleTarget

TARGETS = ("sample", "openai")


def build_target(
    kind: str = "sample",
    *,
    policy: Policy | None = None,
    audit: AuditLog | None = None,
    base_url: str | None = None,
    model: str | None = None,
    api_key_env: str | None = None,
    max_steps: int | None = None,
    timeout: float = 120.0,
) -> Target:
    """Create a fresh target per call, exactly like the old agent factory.

    ``policy`` wraps the fake tools in ``GuardedTools``, so a real model is
    measured against the same enforcement as the sample agent.
    """
    tools: Any = FakeTools()
    if policy is not None:
        tools = GuardedTools(tools, policy, audit)

    if kind == "sample":
        return SampleTarget(tools=tools, max_steps=max_steps or 6)

    if kind == "openai":
        if not base_url:
            raise ValueError("--base-url is required for --target openai")
        if not model:
            raise ValueError("--model is required for --target openai")
        return OpenAICompatibleTarget(
            base_url=base_url,
            model=model,
            api_key=api_key_from_env(api_key_env),
            tools=tools,
            max_steps=max_steps or 6,
            timeout=timeout,
        )

    raise ValueError(f"unknown target '{kind}' (choices: {', '.join(TARGETS)})")


def model_label(kind: str, model: str | None) -> str:
    """The model name saved in reports."""
    if kind == "openai":
        return model or "unknown"
    return SampleTarget.model
