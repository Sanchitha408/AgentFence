"""The documented CLI invocation works end to end."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT)
    return subprocess.run(
        [sys.executable, "-m", "agentfence", *args],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_attack_command_writes_a_baseline(tmp_path) -> None:
    out = tmp_path / "baseline.json"
    completed = run_cli("attack", "--agent", "sample", "--out", str(out))

    assert completed.returncode == 0, completed.stderr
    assert "Attack success rate" in completed.stdout

    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["agent"] == "sample"
    assert report["summary"]["attacks"] == 12
    assert len(report["results"]) == 15


def test_single_attack_selection(tmp_path) -> None:
    out = tmp_path / "one.json"
    completed = run_cli("attack", "--id", "direct-01", "--out", str(out))

    assert completed.returncode == 0, completed.stderr
    report = json.loads(out.read_text(encoding="utf-8"))
    assert [row["id"] for row in report["results"]] == ["direct-01"]


def test_unknown_attack_id_is_rejected() -> None:
    completed = run_cli("attack", "--id", "nope", "--no-write")

    assert completed.returncode == 2
    assert "unknown attack id" in completed.stderr
