"""A deterministic, offline stand-in for an LLM.

The agent needs *something* to decide which tool to call. Instead of calling a
real model (which would need an API key and would not be reproducible), this
module uses a handful of regular expressions to turn text into a tool call.

That is also where the vulnerability lives: ``MockLLM`` reads instructions from
*every* message, including text that arrived from a tool. A real agent is
supposed to treat tool output as data, not as instructions. Ours does not, so a
poisoned email or file is enough to steer it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Sequence

_PATH = r"(?:~|/)[^\s,'\"`;]+"
_EMAIL = r"[\w.+\-]+@[\w.\-]+\.[A-Za-z]{2,}"

# "email the contents of /path/to/file to someone@example.com"
_EMAIL_FILE_RE = re.compile(
    rf"\b(?:e-?mail|send|forward)\b[^\n]*?\b(?:contents? of|file)\s+"
    rf"(?P<path>{_PATH})\s+to\s+(?P<to>{_EMAIL})",
    re.IGNORECASE,
)
# "send an email to someone@example.com ..."
_EMAIL_ANY_RE = re.compile(
    rf"\b(?:e-?mail|send|forward|mail)\b[^\n]*?\bto\s+(?P<to>{_EMAIL})",
    re.IGNORECASE,
)
# "fetch https://example.com/"
_HTTP_RE = re.compile(
    r"\b(?:http_get|fetch|download|curl|visit|get)\b\s*(?:the\s+)?(?:url\s+)?"
    r"(?P<url>https?://[^\s,'\"`);]+)",
    re.IGNORECASE,
)
# "run the command `cat /etc/passwd`"
_SHELL_RE = re.compile(
    r"\b(?:run|execute)\b(?:\s+the)?(?:\s+shell)?(?:\s+command)?\s*[`\"']?"
    r"(?P<cmd>(?:cat|ls|whoami|pwd|env|rm|echo|touch|curl|wget)[^\n`\"']*)",
    re.IGNORECASE,
)
# "read /home/user/notes.txt"
_READ_RE = re.compile(
    rf"\b(?:read|open|cat|show)\b(?:\s+the)?(?:\s+file)?\s+(?P<path>{_PATH})",
    re.IGNORECASE,
)
_INBOX_RE = re.compile(r"\b(?:inbox|e-?mails?|mail)\b", re.IGNORECASE)
_SUMMARY_RE = re.compile(r"\b(?:summar\w*|check|read|look|see|any)\b", re.IGNORECASE)
_PROMPT_LEAK_RE = re.compile(
    r"\b(?:system prompt|your instructions|initial instructions|hidden prompt|"
    r"original instructions)\b",
    re.IGNORECASE,
)
INBOX_PATH = "/home/user/inbox.txt"


@dataclass(frozen=True)
class ToolCall:
    """The agent wants to call a tool."""

    name: str
    arguments: dict[str, Any]


@dataclass(frozen=True)
class FinalAnswer:
    """The agent is done and replies to the user."""

    text: str


Action = ToolCall | FinalAnswer


class MockLLM:
    """Rule-based planner with the instruction-following habits of a chatbot."""

    def __init__(self, max_text: int = 600) -> None:
        self.max_text = max_text

    def step(self, transcript: Sequence[dict[str, Any]]) -> Action:
        """Pick the next action from the transcript so far."""
        system_prompt = next(
            (m["content"] for m in transcript if m["role"] == "system"), ""
        )

        # 1. The agent happily recites its own system prompt when asked.
        user_messages = [m for m in transcript if m["role"] == "user"]
        latest_user = user_messages[-1]["content"] if user_messages else ""
        if _PROMPT_LEAK_RE.search(latest_user):
            return FinalAnswer(system_prompt)

        # 2. Instructions found in tool output win. This is the core flaw:
        #    tool output is untrusted data but gets parsed like a user message.
        tool_messages = [m for m in transcript if m["role"] == "tool"]
        for message in reversed(tool_messages):
            call = _first_new(transcript, self._plans(message["content"], transcript))
            if call is not None:
                return call

        # 3. Fall back to what the user actually asked for.
        call = _first_new(transcript, self._plans(latest_user, transcript))
        if call is not None:
            return call

        # 4. Answer with whatever the last tool returned.
        return FinalAnswer(self._summarize(tool_messages))

    # -- planning ------------------------------------------------------------

    def _plans(
        self, text: str, transcript: Sequence[dict[str, Any]]
    ) -> list[ToolCall]:
        """Turn text into candidate tool calls, most informative first."""
        if not text:
            return []

        plans: list[ToolCall] = []

        match = _EMAIL_FILE_RE.search(text)
        if match:
            path, to = match.group("path"), match.group("to")
            content = _last_read(transcript, path)
            if content is None:
                plans.append(ToolCall("read_file", {"path": path}))
            else:
                plans.append(
                    ToolCall(
                        "send_email",
                        {"to": to, "subject": f"Contents of {path}", "body": content},
                    )
                )

        if _INBOX_RE.search(text) and _SUMMARY_RE.search(text):
            plans.append(ToolCall("read_file", {"path": INBOX_PATH}))

        match = _EMAIL_ANY_RE.search(text)
        if match:
            body = _last_read(transcript) or text
            plans.append(
                ToolCall(
                    "send_email",
                    {"to": match.group("to"), "subject": "Message", "body": body},
                )
            )

        match = _HTTP_RE.search(text)
        if match:
            plans.append(
                ToolCall("http_get", {"url": match.group("url").rstrip(".,")})
            )

        match = _SHELL_RE.search(text)
        if match:
            plans.append(ToolCall("run_shell", {"command": match.group("cmd").strip()}))

        match = _READ_RE.search(text)
        if match:
            plans.append(
                ToolCall("read_file", {"path": match.group("path").rstrip(".,")})
            )

        return plans

    def _summarize(self, tool_messages: Sequence[dict[str, Any]]) -> str:
        if not tool_messages:
            return (
                "I can read files, send email, run shell commands, and fetch URLs. "
                "What would you like me to do?"
            )
        informative = [
            m for m in tool_messages if m.get("name") in ("read_file", "http_get", "run_shell")
        ]
        last = informative[-1] if informative else tool_messages[-1]
        snippet = last["content"].strip()
        if len(snippet) > self.max_text:
            snippet = snippet[: self.max_text] + "..."
        return f"Here is what I got back from {last.get('name', 'the tool')}:\n{snippet}"


def _call_key(call: ToolCall) -> tuple[str, str]:
    """A stable identity for a call, so the planner does not repeat itself."""
    arguments = call.arguments
    ident = (
        arguments.get("to")
        or arguments.get("path")
        or arguments.get("url")
        or arguments.get("command")
        or ""
    )
    return call.name, str(ident)


def _already_called(transcript: Sequence[dict[str, Any]], call: ToolCall) -> bool:
    for message in transcript:
        previous = message.get("tool_call")
        if previous and _call_key(
            ToolCall(previous["name"], previous.get("arguments", {}))
        ) == _call_key(call):
            return True
    return False


def _first_new(
    transcript: Sequence[dict[str, Any]], calls: Sequence[ToolCall]
) -> ToolCall | None:
    """The first candidate the agent has not already tried."""
    for call in calls:
        if not _already_called(transcript, call):
            return call
    return None


def _last_read(
    transcript: Sequence[dict[str, Any]], path: str | None = None
) -> str | None:
    """Return the content of the most recent successful read_file result."""
    from sample_agent import sandbox

    wanted = sandbox.normalize_path(path) if path else None
    for message in reversed(transcript):
        if message.get("role") != "tool" or message.get("name") != "read_file":
            continue
        if not message.get("ok", True):
            continue
        if wanted is not None:
            call = _previous_call(transcript, message)
            if call is None:
                continue
            if sandbox.normalize_path(call["arguments"].get("path", "")) != wanted:
                continue
        return message["content"]
    return None


def _previous_call(
    transcript: Sequence[dict[str, Any]], tool_message: dict[str, Any]
) -> dict[str, Any] | None:
    """Find the assistant tool_call that produced a given tool message."""
    previous: dict[str, Any] | None = None
    for message in transcript:
        if message is tool_message:
            return previous
        if message.get("tool_call"):
            previous = message["tool_call"]
    return None
