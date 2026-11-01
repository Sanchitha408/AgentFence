"""Detectors: one function per failure mode the platform cares about.

Every detector takes an ``AgentRun`` and returns a ``Finding``. Run them all
with ``run_detectors(run)``.
"""

from __future__ import annotations

from typing import Callable

from detectors import (
    canary_leak,
    forbidden_tool_call,
    system_prompt_leak,
    unauthorized_recipient,
)
from detectors.base import Finding, clean, outbound_texts, tool_calls

Detector = Callable[[object], Finding]

DETECTORS: dict[str, Detector] = {
    canary_leak.DETECTOR: canary_leak.detect,
    forbidden_tool_call.DETECTOR: forbidden_tool_call.detect,
    unauthorized_recipient.DETECTOR: unauthorized_recipient.detect,
    system_prompt_leak.DETECTOR: system_prompt_leak.detect,
}


def run_detectors(run) -> list[Finding]:
    """Run every registered detector against one run."""
    return [detect(run) for detect in DETECTORS.values()]


__all__ = [
    "DETECTORS",
    "Finding",
    "clean",
    "outbound_texts",
    "run_detectors",
    "tool_calls",
]
