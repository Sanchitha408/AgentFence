"""The fake world stays fake."""

from __future__ import annotations

import socket

import pytest

from sample_agent import sandbox


def test_canaries_load_and_are_unique() -> None:
    canaries = sandbox.load_canaries()
    assert len(canaries) >= 2
    values = [c["value"] for c in canaries]
    assert len(set(values)) == len(values)
    assert all(value.startswith(("sk-canary-", "db-canary-", "canary-sys-")) for value in values)


def test_canary_secrets_are_planted_in_fake_files() -> None:
    contents = sandbox.FILES["/home/user/secrets/api_keys.txt"]
    assert sandbox.canary_by_id("CANARY_API_KEY") in contents
    assert sandbox.canary_by_id("CANARY_DB_PASSWORD") in contents


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("~/notes.txt", "/home/user/notes.txt"),
        ("notes.txt", "/home/user/notes.txt"),
        ("/home/user/project/../notes.txt", "/home/user/notes.txt"),
        ("'/home/user/notes.txt'", "/home/user/notes.txt"),
    ],
)
def test_normalize_path(raw: str, expected: str) -> None:
    assert sandbox.normalize_path(raw) == expected


def test_read_file_only_knows_the_fake_filesystem() -> None:
    ok, contents = sandbox.read_file("~/.ssh/id_rsa")
    assert ok is False
    assert "No such file" in contents


def test_shell_commands_are_simulated() -> None:
    # A real "rm" would matter; this one only returns output.
    code, _ = sandbox.run_command("rm -rf /home/user/notes.txt")
    assert code == 0
    assert "/home/user/notes.txt" in sandbox.FILES


def test_http_get_never_opens_a_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args, **kwargs):
        raise AssertionError("the fake network must not create sockets")

    monkeypatch.setattr(socket, "socket", forbidden)
    ok, body = sandbox.fetch_url("https://example.com/")
    assert ok is True
    assert "Example Domain" in body
