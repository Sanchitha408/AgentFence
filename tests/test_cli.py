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
    assert report["summary"]["attacks"] == 22
    assert len(report["results"]) == 28
    held_out = [row for row in report["results"] if row["held_out"]]
    assert len(held_out) == 8  # 6 held-out attacks + 2 held-out controls
    held_v2 = [row for row in report["results"] if row["held_out_v2"]]
    assert len(held_v2) == 5  # 4 held-out v2 attacks + 1 benign v2 control


def test_single_attack_selection(tmp_path) -> None:
    out = tmp_path / "one.json"
    completed = run_cli("attack", "--id", "direct-01", "--out", str(out))

    assert completed.returncode == 0, completed.stderr
    report = json.loads(out.read_text(encoding="utf-8"))
    assert [row["id"] for row in report["results"]] == ["direct-01"]


def test_enforced_run_writes_report_and_audit(tmp_path) -> None:
    out = tmp_path / "enforced.json"
    audit = tmp_path / "audit.jsonl"
    completed = run_cli(
        "attack",
        "--agent",
        "sample",
        "--enforce",
        "policies/default.yaml",
        "--out",
        str(out),
        "--audit",
        str(audit),
    )

    assert completed.returncode == 0, completed.stderr
    assert "Policy: policies/default.yaml" in completed.stdout

    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["enforced"] is True
    assert report["summary"]["succeeded"] < report["summary"]["attacks"]
    assert audit.exists() and audit.read_text(encoding="utf-8").strip()


def test_missing_policy_is_reported(tmp_path) -> None:
    completed = run_cli(
        "attack", "--enforce", str(tmp_path / "nope.yaml"), "--no-write"
    )

    assert completed.returncode == 2
    assert "cannot read policy" in completed.stderr


def test_unknown_attack_id_is_rejected() -> None:
    completed = run_cli("attack", "--id", "nope", "--no-write")

    assert completed.returncode == 2
    assert "unknown attack id" in completed.stderr
