"""The compare command produces the before/after report and an offline HTML file."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentfence.cli import main
from attacks import ALL_ATTACKS, ORIGINAL_ATTACKS, ORIGINAL_CONTROLS
from autopolicy import generate_policy
from reports import build_report, write_json
from runner import run_all


@pytest.fixture(scope="module")
def baseline_path(tmp_path_factory: pytest.TempPathFactory) -> Path:
    path = tmp_path_factory.mktemp("compare") / "baseline.json"
    write_json(build_report(run_all()), path)
    return path


@pytest.fixture(scope="module")
def policy_path(tmp_path_factory: pytest.TempPathFactory, baseline_path: Path) -> Path:
    report = json.loads(baseline_path.read_text(encoding="utf-8"))
    policy = generate_policy(report["results"], source=str(baseline_path))
    return policy.write(tmp_path_factory.mktemp("policy") / "generated.yaml")


def test_compare_command_writes_json_and_html(
    baseline_path: Path, policy_path: Path, tmp_path: Path, capsys
) -> None:
    out = tmp_path / "compare.json"
    html = tmp_path / "compare.html"

    code = main(
        [
            "compare",
            "--baseline",
            str(baseline_path),
            "--policy",
            str(policy_path),
            "--out",
            str(out),
            "--html",
            str(html),
        ]
    )
    printed = capsys.readouterr().out

    assert code == 0
    assert out.exists()
    assert html.exists()
    assert "before/after" in printed.lower()
    assert "still succeeding" in printed.lower()

    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["summary"]["before"]["attacks"] == 18
    assert report["summary"]["after"]["attacks"] == 18
    assert report["cohorts"]["original"]["before"]["attacks"] == 12
    assert report["cohorts"]["held_out"]["before"]["attacks"] == 6
    assert report["controls"]["after"]["false_positives"] == 0

    # direct-02 never touches a tool; the separate reply stage is why it is fixed.
    fixed = {row["id"]: row for row in report["fixed"]}
    assert "direct-02" in fixed
    assert "reply-leak-check" in fixed["direct-02"]["blocked_by"]

    succeeding = {row["id"]: row for row in report["still_succeeding"]}
    assert "held-indirect-02" in succeeding
    assert succeeding["held-indirect-02"]["cohort"] == "held_out"
    assert succeeding["held-indirect-02"]["reason"]
    assert "example.com" in succeeding["held-indirect-02"]["reason"]

    # The original 12 are all held by the generated policy.
    after = {row["id"]: row for row in report["results"]["after"]}
    original_ids = {attack.id for attack in ORIGINAL_ATTACKS}
    assert not [row_id for row_id in original_ids if after[row_id]["succeeded"]]


def test_html_is_self_contained(baseline_path: Path, policy_path: Path, tmp_path: Path, capsys) -> None:
    out = tmp_path / "compare.json"
    html_path = tmp_path / "compare.html"
    assert (
        main(
            [
                "compare",
                "--baseline",
                str(baseline_path),
                "--policy",
                str(policy_path),
                "--out",
                str(out),
                "--html",
                str(html_path),
            ]
        )
        == 0
    )
    capsys.readouterr()

    document = html_path.read_text(encoding="utf-8")
    assert "AgentFence before/after" in document
    assert "held-out attacks" in document
    assert "<script" not in document
    assert "<link" not in document
    assert 'src="http' not in document
    assert 'href="http' not in document
    assert "cdn." not in document


def test_compare_fills_in_attacks_missing_from_an_old_baseline(
    tmp_path: Path, capsys
) -> None:
    old_results = run_all(ORIGINAL_ATTACKS + ORIGINAL_CONTROLS)
    old_baseline = tmp_path / "old-baseline.json"
    write_json(build_report(old_results), old_baseline)

    policy = generate_policy(old_results, source=str(old_baseline))
    policy_file = policy.write(tmp_path / "generated.yaml")

    out = tmp_path / "compare.json"
    assert (
        main(
            [
                "compare",
                "--baseline",
                str(old_baseline),
                "--policy",
                str(policy_file),
                "--out",
                str(out),
            ]
        )
        == 0
    )
    capsys.readouterr()

    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["baseline_computed_ids"]
    assert report["cohorts"]["held_out"]["before"]["attacks"] == 6
    assert report["summary"]["before"]["attacks"] == 18


def test_compare_rejects_a_bad_baseline(tmp_path: Path, policy_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{\"nope\": true}", encoding="utf-8")

    assert (
        main(
            [
                "compare",
                "--baseline",
                str(bad),
                "--policy",
                str(policy_path),
                "--out",
                str(tmp_path / "out.json"),
            ]
        )
        == 2
    )
