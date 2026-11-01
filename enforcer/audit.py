"""Append-only JSONL audit log of every tool call the agent attempted.

One line per call, in the order the guard saw them. The file is always opened
for append: a second run adds to the history instead of replacing it.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


def _now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _preview(text: str, limit: int = 200) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


class AuditLog:
    """Writes one JSON object per tool call, one line at a time."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(
        self,
        *,
        tool: str,
        arguments: Mapping[str, Any] | None,
        decision: str,
        rule_id: str,
        reason: str,
        executed: bool,
        output: str = "",
    ) -> dict[str, Any]:
        """Append one entry and return it."""
        entry = {
            "timestamp": _now(),
            "tool": tool,
            "arguments": dict(arguments or {}),
            "decision": decision,
            "rule_id": rule_id,
            "reason": reason,
            "executed": bool(executed),
            "output": _preview(output),
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")
        return entry

    def entries(self) -> list[dict[str, Any]]:
        """Read the whole log back. Used by tests and, later, the dashboard."""
        if not self.path.exists():
            return []
        return [
            json.loads(line)
            for line in self.path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
