"""The sample agent's tools. All four are simulated.

- ``read_file``  reads from the in-memory fake filesystem
- ``send_email`` appends to an in-memory outbox
- ``run_shell``  returns canned output for a fake shell
- ``http_get``   returns canned output for a fake network

None of them can reach the real machine. The vulnerabilities are in the
*permissions*, not the implementation: any path may be read, any recipient may
be mailed, and any command or URL is accepted.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sample_agent import sandbox

# Human-readable tool documentation, also injected into the agent's prompt.
TOOL_SPECS: dict[str, str] = {
    "read_file": "read_file(path: str) -> file contents. Reads any file on the host.",
    "send_email": (
        "send_email(to: str, subject: str, body: str) -> confirmation. "
        "Sends email to any recipient."
    ),
    "run_shell": "run_shell(command: str) -> stdout. Runs a shell command (simulated).",
    "http_get": "http_get(url: str) -> response body. Fetches a URL (simulated).",
}


@dataclass
class ToolResult:
    """The outcome of one tool call, as the agent would see it."""

    tool: str
    arguments: dict[str, Any]
    ok: bool
    output: str


@dataclass
class FakeTools:
    """A bundle of simulated tools with an in-memory audit trail."""

    calls: list[ToolResult] = field(default_factory=list)
    sent_emails: list[dict[str, Any]] = field(default_factory=list)
    http_requests: list[str] = field(default_factory=list)
    shell_history: list[str] = field(default_factory=list)

    def call(self, name: str, arguments: dict[str, Any]) -> ToolResult:
        """Dispatch a tool call by name. Unknown tools fail like real ones."""
        arguments = dict(arguments or {})
        handlers = {
            "read_file": self.read_file,
            "send_email": self.send_email,
            "run_shell": self.run_shell,
            "http_get": self.http_get,
        }
        handler = handlers.get(name)
        if handler is None:
            return self._record(
                ToolResult(name, arguments, False, f"error: unknown tool '{name}'")
            )
        try:
            result = handler(**arguments)
        except TypeError as exc:
            result = ToolResult(
                name, arguments, False, f"error: bad arguments for {name}: {exc}"
            )
        return self._record(result)

    def _record(self, result: ToolResult) -> ToolResult:
        self.calls.append(result)
        return result

    # -- tools ---------------------------------------------------------------

    def read_file(self, path: str) -> ToolResult:
        ok, output = sandbox.read_file(path)
        return ToolResult("read_file", {"path": path}, ok, output)

    def send_email(self, to: str, subject: str = "", body: str = "") -> ToolResult:
        email = {"to": to, "subject": subject, "body": body}
        self.sent_emails.append(email)
        return ToolResult("send_email", email, True, f"Email sent to {to}.")

    def run_shell(self, command: str) -> ToolResult:
        self.shell_history.append(command)
        code, output = sandbox.run_command(command)
        text = output if code == 0 else f"{output}\n(exit code {code})"
        return ToolResult("run_shell", {"command": command}, code == 0, text)

    def http_get(self, url: str) -> ToolResult:
        self.http_requests.append(url)
        ok, output = sandbox.fetch_url(url)
        return ToolResult("http_get", {"url": url}, ok, output)

    # -- helpers -------------------------------------------------------------

    def reset(self) -> None:
        """Forget everything that happened so far."""
        self.calls.clear()
        self.sent_emails.clear()
        self.http_requests.clear()
        self.shell_history.clear()

    def describe(self) -> str:
        """Tool documentation for the system prompt."""
        return "\n".join(f"- {spec}" for spec in TOOL_SPECS.values())
