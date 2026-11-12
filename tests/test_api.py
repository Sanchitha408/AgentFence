"""Tests for the local dashboard API.

The app is built with temporary report/policy directories, so these tests read
fixtures they create and never depend on the repository's current reports or
mutate them.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend import create_app

POLICY_YAML = """\
name: test-policy
default_decision: block
default_reason: deny by default
rules:
  - id: gen-protect-secret-dirs
    type: path_deny
    decision: block
    reason: reads under secrets/ leaked canaries
    patterns: ["/home/user/secrets/**"]
    derived_from: ["direct-01", "exfil-01"]
  - id: gen-allow-workspace-reads
    type: path_inside
    decision: allow
    reason: ordinary workspace reads were benign
    roots: ["/home/user/**"]
    derived_from: ["control-01"]
  - id: gen-email-approved-domains-only
    type: email_domain_deny
    decision: block
    reason: unknown recipient domains
    domains: ["corp.example"]
    derived_from: ["exfil-02"]
"""


def _report(name: str, *, with_results: bool = True) -> dict:
    data = {
        "agent": "sample",
        "policy": f"policies/{name}.yaml" if name == "enforced" else None,
        "generated_at": "2026-11-12T00:00:00+00:00",
        "summary": {"attacks": 2, "succeeded": 1, "asr": 0.5},
    }
    if with_results:
        data["results"] = [
            {
                "id": "direct-01",
                "name": "first",
                "category": "direct_injection",
                "control": False,
                "held_out": False,
                "owasp_category": "LLM01",
                "succeeded": False,
                "detectors_fired": [],
            },
            {
                "id": "held-direct-01",
                "name": "second",
                "category": "direct_injection",
                "control": False,
                "held_out": True,
                "owasp_category": "LLM01",
                "succeeded": True,
                "detectors_fired": ["canary_leak"],
            },
        ]
    return data


@pytest.fixture()
def client(tmp_path: Path) -> TestClient:
    reports = tmp_path / "reports"
    policies = tmp_path / "policies"
    reports.mkdir()
    policies.mkdir()

    for name in ("baseline", "enforced", "compare"):
        (reports / f"{name}.json").write_text(
            json.dumps(_report(name)), encoding="utf-8"
        )
    (policies / "generated.yaml").write_text(POLICY_YAML, encoding="utf-8")
    (policies / "broken.yaml").write_text("rules: nope\n", encoding="utf-8")

    audit_entries = [
        {
            "timestamp": f"2026-11-12T00:00:0{index}+00:00",
            "tool": "read_file",
            "arguments": {"path": f"/home/user/file{index}.txt"},
            "decision": "block" if index % 2 else "allow",
            "rule_id": f"rule-{index}",
            "reason": f"reason {index}",
            "executed": index % 2 == 0,
            "output": "",
        }
        for index in range(3)
    ]
    (reports / "audit.jsonl").write_text(
        "\n".join(json.dumps(entry) for entry in audit_entries) + "\n",
        encoding="utf-8",
    )

    app = create_app(
        reports_dir=reports,
        policies_dir=policies,
        frontend_dir=tmp_path / "no-frontend",
    )
    return TestClient(app)


# -- reports -----------------------------------------------------------------


def test_list_runs_reports_availability(client: TestClient) -> None:
    response = client.get("/api/runs")
    assert response.status_code == 200
    body = response.json()
    assert [entry["name"] for entry in body["reports"]] == [
        "baseline",
        "enforced",
        "compare",
    ]
    assert all(entry["available"] for entry in body["reports"])
    assert body["reports"][0]["summary"]["attacks"] == 2


def test_get_each_report_returns_the_saved_document(client: TestClient) -> None:
    for name in ("baseline", "enforced", "compare"):
        response = client.get(f"/api/runs/{name}")
        assert response.status_code == 200, name
        body = response.json()
        assert body["agent"] == "sample"
        assert body["generated_at"] == "2026-11-12T00:00:00+00:00"
        assert body["results"][1]["held_out"] is True

    assert client.get("/api/compare").json()["results"][0]["id"] == "direct-01"


def test_unknown_report_is_404(client: TestClient) -> None:
    assert client.get("/api/runs/secrets").status_code == 404


def test_missing_report_file_reports_404(tmp_path: Path) -> None:
    reports = tmp_path / "reports"
    policies = tmp_path / "policies"
    reports.mkdir()
    policies.mkdir()
    (policies / "generated.yaml").write_text(POLICY_YAML, encoding="utf-8")
    app = create_app(
        reports_dir=reports,
        policies_dir=policies,
        frontend_dir=tmp_path / "no-frontend",
    )
    with TestClient(app) as client:
        response = client.get("/api/runs/baseline")
    assert response.status_code == 404
    assert "trigger a run" in response.json()["detail"]


# -- policies ----------------------------------------------------------------


def test_policies_are_parsed_with_derived_from(client: TestClient) -> None:
    body = client.get("/api/policies").json()
    files = {entry["file"]: entry for entry in body["policies"]}
    assert set(files) == {"generated.yaml", "broken.yaml"}

    generated = files["generated.yaml"]
    assert generated["name"] == "test-policy"
    assert generated["default_decision"] == "block"
    assert [rule["id"] for rule in generated["rules"]] == [
        "gen-protect-secret-dirs",
        "gen-allow-workspace-reads",
        "gen-email-approved-domains-only",
    ]
    assert generated["rules"][0]["derived_from"] == ["direct-01", "exfil-01"]
    assert "derived_from" not in generated["rules"][0]["params"]
    assert generated["rules"][0]["params"]["patterns"] == ["/home/user/secrets/**"]

    # A malformed policy is reported per-entry instead of breaking the endpoint.
    assert "error" in files["broken.yaml"]


def test_single_policy_includes_raw_yaml(client: TestClient) -> None:
    body = client.get("/api/policies/generated.yaml").json()
    assert body["file"] == "generated.yaml"
    assert body["raw"].startswith("name: test-policy")
    assert body["rules"][2]["derived_from"] == ["exfil-02"]


def test_policy_endpoint_rejects_bad_names(client: TestClient) -> None:
    assert client.get("/api/policies/notes.txt").status_code == 400
    assert client.get("/api/policies/missing.yaml").status_code == 404


# -- audit -------------------------------------------------------------------


def test_audit_returns_the_last_n_entries(client: TestClient) -> None:
    body = client.get("/api/audit", params={"limit": 2}).json()
    assert body["count"] == 2
    assert [entry["rule_id"] for entry in body["entries"]] == ["rule-1", "rule-2"]
    assert body["entries"][1]["decision"] == "allow"


def test_audit_default_and_validation(client: TestClient) -> None:
    body = client.get("/api/audit").json()
    assert body["count"] == 3
    assert client.get("/api/audit", params={"limit": 0}).status_code == 422


def test_audit_is_empty_when_no_log_exists(tmp_path: Path) -> None:
    reports = tmp_path / "reports"
    policies = tmp_path / "policies"
    reports.mkdir()
    policies.mkdir()
    (policies / "generated.yaml").write_text(POLICY_YAML, encoding="utf-8")
    app = create_app(
        reports_dir=reports,
        policies_dir=policies,
        frontend_dir=tmp_path / "no-frontend",
    )
    with TestClient(app) as client:
        body = client.get("/api/audit").json()
    assert body["count"] == 0
    assert body["entries"] == []


# -- triggering runs ---------------------------------------------------------


def test_trigger_baseline_writes_a_full_report(client: TestClient) -> None:
    response = client.post("/api/run", json={"kind": "baseline"})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["ok"] is True
    assert body["report"].endswith("baseline.json")
    assert body["html"] is None

    report = client.get("/api/runs/baseline").json()
    assert report["enforced"] is False
    assert report["summary"]["attacks"] == 22
    assert report["summary"]["controls"] == 6


def test_trigger_enforced_uses_the_policy_and_writes_an_audit_log(
    client: TestClient,
) -> None:
    response = client.post(
        "/api/run", json={"kind": "enforced", "policy": "generated.yaml"}
    )
    assert response.status_code == 200, response.text

    report = client.get("/api/runs/enforced").json()
    assert report["enforced"] is True
    assert report["policy"].endswith("generated.yaml")
    assert len(report["results"]) == 28
    # The temp policy has no reply configuration, but the runner still applies
    # the separate output stage; direct-02 should no longer succeed.
    rows = {row["id"]: row for row in report["results"]}
    assert rows["direct-02"]["succeeded"] is False

    audit = client.get("/api/audit", params={"limit": 1000}).json()
    assert audit["count"] > 0
    assert {entry["decision"] for entry in audit["entries"]} <= {
        "allow",
        "block",
        "ask",
    }


def test_trigger_compare_writes_json_and_html(client: TestClient) -> None:
    response = client.post("/api/run", json={"kind": "compare"})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["report"].endswith("compare.json")
    assert body["html"].endswith("compare.html")

    compare = client.get("/api/compare").json()
    assert compare["summary"]["before"]["attacks"] == 22
    assert compare["summary"]["after"]["attacks"] == 22
    assert compare["cohorts"]["held_out"]["before"]["attacks"] == 6
    assert isinstance(compare["still_succeeding"], list)


def test_trigger_compare_adds_v2_when_the_policy_exists(tmp_path: Path) -> None:
    reports = tmp_path / "reports"
    policies = tmp_path / "policies"
    reports.mkdir()
    policies.mkdir()
    (policies / "generated.yaml").write_text(POLICY_YAML, encoding="utf-8")
    root = Path(__file__).resolve().parents[1]
    (policies / "v2.yaml").write_text(
        (root / "policies" / "v2.yaml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    app = create_app(
        reports_dir=reports,
        policies_dir=policies,
        frontend_dir=tmp_path / "no-frontend",
    )
    with TestClient(app) as client:
        response = client.post("/api/run", json={"kind": "compare"})
        assert response.status_code == 200, response.text
        compare = client.get("/api/compare").json()

    assert compare["v2"]["policy"].endswith("v2.yaml")
    assert len(compare["v2"]["new_attack_ids"]) == 4
    assert compare["v2"]["controls"]["after"]["false_positives"] == 0


def test_trigger_rejects_bad_requests(client: TestClient) -> None:
    assert client.post("/api/run", json={"kind": "nope"}).status_code == 422
    assert (
        client.post(
            "/api/run", json={"kind": "enforced", "policy": "missing.yaml"}
        ).status_code
        == 404
    )
    assert (
        client.post(
            "/api/run",
            json={"kind": "enforced", "policy": "../policies/default.yaml"},
        ).status_code
        == 400
    )
