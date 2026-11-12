"""The output stage: check the agent's final reply, not just its tool calls.

Tool rules cannot see an answer that never touches a tool. ``direct-02`` asks
the agent to recite its hidden system prompt; the agent answers straight from
the model, so no ``read_file``/``send_email`` rule ever gets a chance. This
module is the second, deliberately separate enforcement stage:

* it runs **after** the agent finishes and **before** detectors score the run;
* it looks only at ``run.final_answer`` (the text the user would read);
* if a canary value or a marker phrase from the system prompt appears, the
  whole reply is replaced with a refusal, so the secret never reaches the user;
* the block is written to the same audit log as tool decisions, with
  ``tool="final_reply"`` and rule id ``reply-leak-check``.

It is a backstop, not a content filter: it catches known secret values and the
prompt's marker phrases, and it cannot recognise a paraphrase of the prompt.
That limitation is intentional and is documented in the report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from detectors.base import dedupe
from detectors.system_prompt_leak import markers
from enforcer.audit import AuditLog
from sample_agent import sandbox
from sample_agent.agent import AgentRun

RULE_ID = "reply-leak-check"
# Name of this enforcement stage, shown in reports next to the tool policy.
OUTPUT_CHECK = RULE_ID
PLACEHOLDER = (
    "[reply withheld by policy: it contained protected system-prompt or secret content]"
)


@dataclass(frozen=True)
class ReplyCheck:
    """What the output stage saw in one final reply."""

    checked: bool
    blocked: bool
    markers: tuple[str, ...] = ()
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "checked": self.checked,
            "blocked": self.blocked,
            "markers": list(self.markers),
            "reason": self.reason,
        }


@dataclass
class OutputGuard:
    """Replace a leaking final reply before anyone can read it."""

    audit: AuditLog | None = None
    placeholder: str = PLACEHOLDER
    # Kept for callers that build the guard lazily; the check is always on.
    enabled: bool = True
    checks: list[ReplyCheck] = field(default_factory=list)

    def inspect(self, run: AgentRun) -> ReplyCheck:
        """Check and, if necessary, replace ``run.final_answer``."""
        if not self.enabled:
            return ReplyCheck(False, False, (), "output stage disabled")

        text = run.final_answer or ""
        hits: list[str] = []
        for canary in sandbox.load_canaries():
            if canary["value"] in text:
                hits.append(f"canary {canary['id']} ({canary['location']})")
        for marker in markers():
            if marker in text:
                hits.append(f"system prompt marker {marker!r}")

        hits = dedupe(hits)
        if not hits:
            check = ReplyCheck(True, False, (), "reply contained no protected content")
            self.checks.append(check)
            return check

        reason = (
            "the final reply contained protected content and was withheld "
            f"({'; '.join(hits)})"
        )
        run.final_answer = self.placeholder
        if self.audit is not None:
            self.audit.record(
                tool="final_reply",
                arguments={"markers": hits},
                decision="block",
                rule_id=RULE_ID,
                reason=reason,
                executed=False,
                output=text,
            )
        check = ReplyCheck(True, True, tuple(hits), reason)
        self.checks.append(check)
        return check
