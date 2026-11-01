"""The guard that sits between the agent and its tools.

``GuardedTools`` has the same surface as ``FakeTools``, so the agent cannot tell
the difference. Every call is evaluated by the policy first:

* allow - the call reaches ``FakeTools``
* block - nothing runs; the agent gets ``blocked by policy: <rule id> ...``
* ask   - nothing runs either; the call is flagged for human approval

Everything that happened is written to the audit log.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from enforcer.audit import AuditLog
from enforcer.policy import ASK, Decision, Policy
from sample_agent.tools import FakeTools, ToolResult

BLOCKED_PREFIX = "blocked by policy:"


@dataclass
class GuardedTools:
    """A policy-checking wrapper around the fake tools."""

    inner: FakeTools
    policy: Policy
    audit: AuditLog | None = None
    # Decisions in the order they were made, handy for assertions and tests.
    decisions: list[Decision] = field(default_factory=list)

    # -- the guarded entry point ---------------------------------------------

    def call(self, name: str, arguments: Mapping[str, Any] | None = None) -> ToolResult:
        arguments = dict(arguments or {})
        decision = self.policy.evaluate(name, arguments)
        self.decisions.append(decision)
        executed = decision.decision != ASK and decision.allowed

        if executed:
            result = self.inner.call(name, arguments)
        else:
            result = ToolResult(name, arguments, False, self._refusal(decision))

        if self.audit is not None:
            self.audit.record(
                tool=name,
                arguments=arguments,
                decision=decision.decision,
                rule_id=decision.rule_id,
                reason=decision.reason,
                executed=executed,
                output=result.output,
            )
        return result

    # -- the FakeTools surface -----------------------------------------------

    def read_file(self, path: str) -> ToolResult:
        return self.call("read_file", {"path": path})

    def send_email(self, to: str, subject: str = "", body: str = "") -> ToolResult:
        return self.call("send_email", {"to": to, "subject": subject, "body": body})

    def run_shell(self, command: str) -> ToolResult:
        return self.call("run_shell", {"command": command})

    def http_get(self, url: str) -> ToolResult:
        return self.call("http_get", {"url": url})

    def describe(self) -> str:
        return self.inner.describe()

    def reset(self) -> None:
        self.inner.reset()
        self.decisions.clear()

    @property
    def calls(self) -> list[ToolResult]:
        return self.inner.calls

    @property
    def sent_emails(self) -> list[dict[str, Any]]:
        return self.inner.sent_emails

    @property
    def http_requests(self) -> list[str]:
        return self.inner.http_requests

    @property
    def shell_history(self) -> list[str]:
        return self.inner.shell_history

    # -- helpers -------------------------------------------------------------

    def _refusal(self, decision: Decision) -> str:
        """The message the agent sees instead of a tool result."""
        if decision.decision == ASK:
            return (
                f"{BLOCKED_PREFIX} {decision.rule_id} (awaiting human approval) "
                f"- {decision.reason}"
            )
        return f"{BLOCKED_PREFIX} {decision.rule_id} - {decision.reason}"
