"""A target that drives any OpenAI-compatible chat-completions endpoint.

Works with a local Ollama server (``http://localhost:11434/v1``) and with
hosted APIs that speak the same protocol, including free tiers. The model is
given the same four *fake* tools as the sample agent and its tool calls are
executed against the in-memory sandbox, never the real machine.

Only the standard library is used for HTTP, so a real-model run adds no
dependency; tests point the target at a fake local server instead.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

from sample_agent.agent import DEFAULT_SYSTEM_PROMPT, MAX_STEPS, AgentRun
from sample_agent.tools import TOOL_SPECS
from targets.base import Target

# The four fake tools, described in the chat-completions function-calling
# format. Descriptions mirror ``sample_agent.tools.TOOL_SPECS``.
TOOL_SCHEMAS: tuple[dict[str, Any], ...] = (
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": TOOL_SPECS["read_file"],
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "send_email",
            "description": TOOL_SPECS["send_email"],
            "parameters": {
                "type": "object",
                "properties": {
                    "to": {"type": "string"},
                    "subject": {"type": "string"},
                    "body": {"type": "string"},
                },
                "required": ["to", "subject", "body"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_shell",
            "description": TOOL_SPECS["run_shell"],
            "parameters": {
                "type": "object",
                "properties": {"command": {"type": "string"}},
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "http_get",
            "description": TOOL_SPECS["http_get"],
            "parameters": {
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"],
            },
        },
    },
)


class TargetError(RuntimeError):
    """The endpoint could not be reached or returned something unusable."""


class _RequestTimeout(Exception):
    """Internal: one request exceeded the per-request timeout."""


def _parse_arguments(raw: Any) -> dict[str, Any]:
    """Turn a function-call argument payload into a dict, leniently."""
    if isinstance(raw, dict):
        return dict(raw)
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return {}
    return dict(parsed) if isinstance(parsed, dict) else {}


class OpenAICompatibleTarget(Target):
    """A tool-using agent whose planner is a chat-completions model."""

    kind = "openai"

    def __init__(
        self,
        base_url: str,
        model: str,
        api_key: str | None = None,
        tools: Any | None = None,
        system_prompt: str = DEFAULT_SYSTEM_PROMPT,
        max_steps: int = MAX_STEPS,
        timeout: float = 180.0,
    ) -> None:
        super().__init__(tools=tools, max_steps=max_steps)
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.system_prompt = system_prompt
        self.timeout = timeout

    # -- interface -----------------------------------------------------------

    def run(self, task: str, max_steps: int | None = None) -> AgentRun:
        """Run one task, looping through tool calls until the model answers."""
        budget = max_steps or self.max_steps
        self.tools.reset()

        transcript: list[dict[str, Any]] = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": task},
        ]
        messages: list[dict[str, Any]] = list(transcript)

        for step in range(1, budget + 1):
            message = self._chat(messages)
            tool_calls = message.get("tool_calls") or []
            content = message.get("content") or ""

            if not tool_calls:
                messages.append({"role": "assistant", "content": content})
                transcript.append({"role": "assistant", "content": content})
                return AgentRun(task, transcript, content, step, "final_answer")

            messages.append(
                {
                    "role": "assistant",
                    "content": content,
                    "tool_calls": tool_calls,
                }
            )
            for raw_call in tool_calls:
                function = (raw_call or {}).get("function") or {}
                name = str(function.get("name") or "")
                arguments = _parse_arguments(function.get("arguments"))
                call_id = str((raw_call or {}).get("id") or "")

                transcript.append(
                    {
                        "role": "assistant",
                        "content": f"calls {name}({json.dumps(arguments)})",
                        "tool_call": {"name": name, "arguments": arguments},
                    }
                )
                result = self.tools.call(name, arguments)
                transcript.append(
                    {
                        "role": "tool",
                        "name": name,
                        "content": result.output,
                        "ok": result.ok,
                    }
                )
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": call_id,
                        "name": name,
                        "content": result.output,
                    }
                )

        return AgentRun(
            task,
            transcript,
            "(stopped: step limit reached)",
            budget,
            "max_steps",
        )

    # -- HTTP ----------------------------------------------------------------

    def _chat(self, messages: list[dict[str, Any]]) -> dict[str, Any]:
        """POST one request, retrying a timeout once before giving up."""
        for attempt in range(2):
            try:
                return self._post(messages)
            except _RequestTimeout as exc:
                if attempt == 1:
                    raise TargetError(
                        f"request timed out after {self.timeout:g}s "
                        "(retried once)"
                    ) from exc
        raise AssertionError("unreachable")

    def _post(self, messages: list[dict[str, Any]]) -> dict[str, Any]:
        """One chat-completions request and its assistant message."""
        body = json.dumps(
            {
                "model": self.model,
                "messages": messages,
                "tools": list(TOOL_SCHEMAS),
            }
        ).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        request = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=body,
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:500]
            raise TargetError(
                f"{self.base_url}/chat/completions returned HTTP {exc.code}: {detail}"
            ) from exc
        except TimeoutError as exc:
            raise _RequestTimeout from exc
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, TimeoutError):
                raise _RequestTimeout from exc
            raise TargetError(
                f"cannot reach {self.base_url}/chat/completions: {exc}"
            ) from exc
        except OSError as exc:
            raise TargetError(
                f"cannot reach {self.base_url}/chat/completions: {exc}"
            ) from exc
        except json.JSONDecodeError as exc:
            raise TargetError("response was not valid JSON") from exc

        try:
            message = payload["choices"][0]["message"]
        except (KeyError, IndexError, TypeError) as exc:
            raise TargetError(
                "response is missing choices[0].message: "
                + json.dumps(payload)[:300]
            ) from exc
        if not isinstance(message, dict):
            raise TargetError("choices[0].message was not an object")
        return message


def api_key_from_env(variable: str | None) -> str | None:
    """Read an API key from an environment variable, if one was named."""
    if not variable:
        return None
    value = os.environ.get(variable)
    return value or None
