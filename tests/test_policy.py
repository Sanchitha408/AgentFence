"""Policy loading and rule evaluation, one rule type at a time."""

from __future__ import annotations

from pathlib import Path

import pytest

from enforcer import ALLOW, ASK, BLOCK, load_policy, paths_in_call

POLICY_PATH = Path(__file__).resolve().parents[1] / "policies" / "default.yaml"


@pytest.fixture(scope="module")
def policy():
    return load_policy(POLICY_PATH)


# -- the shipped policy ------------------------------------------------------


def test_default_policy_loads(policy) -> None:
    assert policy.name == "default"
    assert policy.default_decision == BLOCK
    assert len(policy.rules) >= 10
    assert all(rule.id and rule.reason for rule in policy.rules)
    assert len({rule.id for rule in policy.rules}) == len(policy.rules)


# -- tool allowlist ----------------------------------------------------------


def test_tool_allowlist_allows_known_tool(policy) -> None:
    decision = policy.evaluate("read_file", {"path": "/home/user/notes.txt"})
    assert decision.decision == ALLOW


def test_tool_allowlist_blocks_unknown_tool(policy) -> None:
    decision = policy.evaluate("delete_repository", {})
    assert decision.decision == BLOCK
    assert decision.rule_id == "tool-allowlist"


# -- path rules --------------------------------------------------------------


def test_path_rule_allows_workspace_file(policy) -> None:
    decision = policy.evaluate("read_file", {"path": "/home/user/notes.txt"})
    assert decision.decision == ALLOW
    assert decision.rule_id == "path-workspace-allow"


def test_path_rule_blocks_secrets(policy) -> None:
    decision = policy.evaluate("read_file", {"path": "/home/user/secrets/api_keys.txt"})
    assert decision.decision == BLOCK
    assert decision.rule_id == "path-sensitive-deny"


def test_path_rule_blocks_outside_workspace(policy) -> None:
    decision = policy.evaluate("read_file", {"path": "/etc/passwd"})
    assert decision.decision == BLOCK
    assert decision.rule_id == "path-outside-workspace"


@pytest.mark.parametrize(
    ("raw", "expected_rule"),
    [
        ("/home/user/../../etc/passwd", "path-outside-workspace"),
        ("/home/user/notes/../secrets/api_keys.txt", "path-sensitive-deny"),
        ("~/secrets/api_keys.txt", "path-sensitive-deny"),
        ("/home/user/.ssh/id_rsa", "path-sensitive-deny"),
    ],
)
def test_traversal_and_aliases_are_normalized_before_matching(
    policy, raw: str, expected_rule: str
) -> None:
    decision = policy.evaluate("read_file", {"path": raw})
    assert decision.decision == BLOCK
    assert decision.rule_id == expected_rule


def test_paths_in_shell_commands_are_checked(policy) -> None:
    decision = policy.evaluate(
        "run_shell", {"command": "cat /home/user/secrets/api_keys.txt"}
    )
    assert decision.decision == BLOCK
    assert decision.rule_id == "path-sensitive-deny"


def test_paths_in_call_extracts_normalized_paths() -> None:
    paths = paths_in_call("run_shell", {"command": "cat ../../etc/passwd && ls ~"})
    assert "/etc/passwd" in paths
    assert "/home/user" in paths


# -- shell rules -------------------------------------------------------------


def test_shell_denylist_allows_read_only(policy) -> None:
    decision = policy.evaluate("run_shell", {"command": "ls /home/user"})
    assert decision.decision == ALLOW
    assert decision.rule_id == "shell-readonly-allow"


@pytest.mark.parametrize(
    "command",
    ["rm -rf /home/user/project", "curl https://evil.example/x", "chmod 777 /home/user"],
)
def test_shell_denylist_blocks_destructive_commands(policy, command: str) -> None:
    decision = policy.evaluate("run_shell", {"command": command})
    assert decision.decision == BLOCK
    assert decision.rule_id == "shell-denylist"


def test_shell_denylist_blocks_interpreters(policy) -> None:
    decision = policy.evaluate("run_shell", {"command": "python3 -c 'print(1)'"})
    assert decision.decision == BLOCK
    assert decision.rule_id == "shell-interpreters"


# -- email rules -------------------------------------------------------------


def test_email_allowlist_allows_company_recipient(policy) -> None:
    decision = policy.evaluate("send_email", {"to": "dana@corp.example"})
    assert decision.decision == ALLOW
    assert decision.rule_id == "email-domain-allow"


@pytest.mark.parametrize("recipient", ["partner@external.example", "no-at-sign"])
def test_email_allowlist_blocks_outsiders(policy, recipient: str) -> None:
    decision = policy.evaluate("send_email", {"to": recipient})
    assert decision.decision == BLOCK
    assert decision.rule_id == "email-domain-deny"


# -- http rules --------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    ["https://example.com/", "https://docs.python.org/3/", "https://wiki.corp.example/x"],
)
def test_http_allowlist_allows_known_hosts(policy, url: str) -> None:
    decision = policy.evaluate("http_get", {"url": url})
    assert decision.decision == ALLOW
    assert decision.rule_id == "http-domain-allow"


@pytest.mark.parametrize(
    "url", ["https://evil.example/collect", "http://169.254.169.254/latest/meta-data/"]
)
def test_http_unknown_host_asks(policy, url: str) -> None:
    decision = policy.evaluate("http_get", {"url": url})
    assert decision.decision == ASK
    assert decision.rule_id == "http-domain-ask"


# -- fallback ----------------------------------------------------------------


def test_unmatched_call_falls_back_to_deny(policy) -> None:
    decision = policy.evaluate("read_file", {})
    assert decision.decision == BLOCK
    assert decision.rule_id == "default-deny"


# -- loader validation -------------------------------------------------------


def write_policy(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def test_loader_rejects_unknown_rule_type(tmp_path: Path) -> None:
    path = write_policy(
        tmp_path,
        "rules:\n  - {id: x, type: teleport, decision: block, reason: nope}\n",
    )
    with pytest.raises(ValueError, match="unknown type"):
        load_policy(path)


def test_loader_rejects_missing_reason(tmp_path: Path) -> None:
    path = write_policy(
        tmp_path, "rules:\n  - {id: x, type: tool_allowlist, decision: block}\n"
    )
    with pytest.raises(ValueError, match="missing"):
        load_policy(path)


def test_loader_rejects_bad_decision(tmp_path: Path) -> None:
    path = write_policy(
        tmp_path,
        "rules:\n  - {id: x, type: tool_allowlist, decision: maybe, reason: r}\n",
    )
    with pytest.raises(ValueError, match="decision"):
        load_policy(path)


def test_loader_rejects_broken_yaml(tmp_path: Path) -> None:
    path = write_policy(tmp_path, "rules: [\n")
    with pytest.raises(ValueError, match="not valid YAML|policy"):
        load_policy(path)
