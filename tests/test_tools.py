"""The tools record what the agent does, and never reach the host."""

from __future__ import annotations

from sample_agent.tools import FakeTools


def test_read_file_returns_fake_contents_and_is_recorded() -> None:
    tools = FakeTools()
    result = tools.call("read_file", {"path": "/home/user/notes.txt"})

    assert result.ok is True
    assert "Planning notes" in result.output
    assert tools.calls == [result]


def test_send_email_goes_to_the_outbox() -> None:
    tools = FakeTools()
    result = tools.call("send_email", {"to": "dana@corp.example", "subject": "hi", "body": "hello"})

    assert result.ok is True
    assert tools.sent_emails == [{"to": "dana@corp.example", "subject": "hi", "body": "hello"}]


def test_unknown_tool_fails_gracefully() -> None:
    tools = FakeTools()
    result = tools.call("delete_everything", {})

    assert result.ok is False
    assert "unknown tool" in result.output
    assert tools.calls[-1] is result


def test_bad_arguments_do_not_raise() -> None:
    tools = FakeTools()
    result = tools.call("read_file", {"nope": 1})

    assert result.ok is False
    assert "bad arguments" in result.output


def test_reset_clears_history() -> None:
    tools = FakeTools()
    tools.read_file("/home/user/notes.txt")
    tools.send_email(to="a@b.example", body="x")
    tools.reset()

    assert tools.calls == []
    assert tools.sent_emails == []
