"""Shared pieces for detectors: the Finding type and transcript helpers.

A detector is a plain function ``detect(run: AgentRun) -> Finding``. It never
raises and it never decides the score - it just reports what it saw, so several
detectors can fire on the same run.

Detectors judge what the agent **executed**. Once a policy is in place, a call
that was blocked appears in the transcript as a failed tool result, and counting
it as a violation would make enforcement look ineffective. Blocked attempts are
still visible: the runner keeps every tool call and the audit log records them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sample_agent.agent import AgentRun


@dataclass
class Finding:
    """One detector's verdict on one agent run."""

    detector: str
    detected: bool
    severity: str
    evidence: list[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "detector": self.detector,
            "detected": self.detected,
            "severity": self.severity,
            "evidence": list(self.evidence),
            "summary": self.summary,
        }


def clean(detector: str, severity: str, summary: str) -> Finding:
    """A finding for a detector that saw nothing wrong."""
    return Finding(
        detector=detector, detected=False, severity=severity, evidence=[], summary=summary
    )


def _call_pairs(run: AgentRun) -> list[tuple[dict[str, Any], dict[str, Any] | None]]:
    """Pair every tool call with the tool message that followed it."""
    pairs: list[tuple[dict[str, Any], dict[str, Any] | None]] = []
    pending: list[int] = []
    for message in run.transcript:
        call = message.get("tool_call")
        if call:
            pairs.append((call, None))
            pending.append(len(pairs) - 1)
        elif message.get("role") == "tool" and pending:
            index = pending.pop(0)
            pairs[index] = (pairs[index][0], message)
    return pairs


def executed_tool_calls(
    run: AgentRun, name: str | None = None
) -> list[dict[str, Any]]:
    """Tool calls that actually ran (not blocked by policy, not missing a result)."""
    executed: list[dict[str, Any]] = []
    for call, result in _call_pairs(run):
        if result is not None and result.get("ok") is False:
            continue
        if name is not None and call.get("name") != name:
            continue
        executed.append(call)
    return executed


def tool_calls(run: AgentRun, name: str | None = None) -> list[dict[str, Any]]:
    """Every tool call the agent attempted, including blocked ones."""
    calls = run.tool_calls()
    if name is None:
        return calls
    return [call for call in calls if call.get("name") == name]


def outbound_texts(run: AgentRun) -> list[tuple[str, str]]:
    """Every channel that can carry data out of the agent.

    Returns ``(channel, text)`` pairs for email that was actually sent, HTTP
    requests that actually ran, and the reply shown to the user.
    """
    channels: list[tuple[str, str]] = []
    for call in executed_tool_calls(run):
        name = call.get("name")
        arguments = call.get("arguments") or {}
        if name == "send_email":
            text = " ".join(
                str(arguments.get(key, "")) for key in ("to", "subject", "body")
            )
            channels.append(("email", text))
        elif name == "http_get":
            channels.append(("http", str(arguments.get("url", ""))))
    if run.final_answer:
        channels.append(("reply", run.final_answer))
    return channels


def dedupe(items: list[str]) -> list[str]:
    """Drop duplicates while keeping the first-seen order."""
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result
