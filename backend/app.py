"""AgentFence dashboard API.

This is a thin local server around the existing project pieces:

* reports are read from ``reports/*.json`` and never recalculated on a GET;
* policies are parsed by the same loader the enforcer uses, read-only;
* audit entries are the tail of the existing JSONL log;
* ``POST /api/run`` calls the existing runner and report builders to produce a
  fresh baseline, enforced, or comparison run.

Everything is local. No request handler opens a socket to the internet, and the
runner only uses the in-memory sandbox described in ``sample_agent/``.
"""

from __future__ import annotations

import json
import threading
import time
from functools import partial
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from attacks import ALL_ATTACKS
from enforcer import AuditLog, OutputGuard, load_policy
from reports import build_comparison, build_report, write_html, write_json
from runner import build_sample_agent, run_all

ROOT = Path(__file__).resolve().parents[1]
REPORT_NAMES = ("baseline", "enforced", "compare")
POLICY_SUFFIXES = (".yaml", ".yml")

# Runs mutate the fake sandbox globals via the runner, so keep them serial.
_RUN_LOCK = threading.Lock()


class RunRequest(BaseModel):
    """A request to produce one fresh report."""

    kind: Literal["baseline", "enforced", "compare"]
    policy: str | None = Field(
        default=None,
        description="Policy filename from /api/policies; defaults to generated.yaml",
    )


def _display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def create_app(
    reports_dir: str | Path | None = None,
    policies_dir: str | Path | None = None,
    frontend_dir: str | Path | None = None,
) -> FastAPI:
    """Build the app. Directories are injectable so tests never touch the repo."""
    reports = Path(reports_dir) if reports_dir else ROOT / "reports"
    policies = Path(policies_dir) if policies_dir else ROOT / "policies"
    frontend = Path(frontend_dir) if frontend_dir else ROOT / "frontend"
    reports.mkdir(parents=True, exist_ok=True)
    policies.mkdir(parents=True, exist_ok=True)

    app = FastAPI(
        title="AgentFence dashboard API",
        version="1.0.0",
        description=(
            "Local read-only API over AgentFence reports, policies and audit log, "
            "plus an endpoint that triggers a fresh sandboxed run."
        ),
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["null"],
        allow_origin_regex=r"http://(localhost|127\.0\.0\.1)(:\d+)?",
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    # -- reading reports -----------------------------------------------------

    def read_report(name: str) -> dict[str, Any]:
        if name not in REPORT_NAMES:
            raise HTTPException(
                status_code=404,
                detail=f"unknown report '{name}'; expected one of {REPORT_NAMES}",
            )
        path = reports / f"{name}.json"
        if not path.is_file():
            raise HTTPException(
                status_code=404,
                detail=f"{_display_path(path)} does not exist yet; trigger a run first",
            )
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise HTTPException(
                status_code=500, detail=f"{_display_path(path)} is not valid JSON: {exc}"
            ) from exc

    def report_entry(name: str) -> dict[str, Any]:
        path = reports / f"{name}.json"
        entry: dict[str, Any] = {
            "name": name,
            "file": _display_path(path),
            "available": path.is_file(),
        }
        if not path.is_file():
            return entry
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            entry["error"] = str(exc)
            return entry
        entry["generated_at"] = data.get("generated_at")
        entry["policy"] = data.get("policy")
        entry["summary"] = data.get("summary")
        return entry

    @app.get("/", tags=["meta"])
    def index() -> dict[str, Any]:
        return {
            "name": "AgentFence dashboard API",
            "ui": "/ui/",
            "docs": "/docs",
            "reports": [f"/api/runs/{name}" for name in REPORT_NAMES],
        }

    @app.get("/api/health", tags=["meta"])
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/runs", tags=["reports"])
    def list_runs() -> dict[str, Any]:
        """List the report files the dashboard can show."""
        return {"reports": [report_entry(name) for name in REPORT_NAMES]}

    @app.get("/api/runs/{name}", tags=["reports"])
    def get_run(name: str) -> dict[str, Any]:
        """Return one complete report document (baseline, enforced or compare)."""
        return read_report(name)

    @app.get("/api/compare", tags=["reports"])
    def get_compare() -> dict[str, Any]:
        """Shortcut for the before/after document."""
        return read_report("compare")

    # -- policies ------------------------------------------------------------

    def policy_files() -> list[Path]:
        return sorted(
            path
            for path in policies.iterdir()
            if path.is_file() and path.suffix.lower() in POLICY_SUFFIXES
        )

    @app.get("/api/policies", tags=["policies"])
    def list_policies() -> dict[str, Any]:
        """Parse every YAML policy with the same loader the enforcer uses."""
        entries: list[dict[str, Any]] = []
        for path in policy_files():
            entry: dict[str, Any] = {
                "file": path.name,
                "path": _display_path(path),
            }
            try:
                policy = load_policy(path)
            except ValueError as exc:
                entry["error"] = str(exc)
                entries.append(entry)
                continue

            entry.update(
                {
                    "name": policy.name,
                    "default_decision": policy.default_decision,
                    "default_reason": policy.default_reason,
                    "rules": [
                        {
                            "id": rule.id,
                            "type": rule.type,
                            "decision": rule.decision,
                            "reason": rule.reason,
                            "derived_from": list(rule.params.get("derived_from", [])),
                            "params": {
                                key: value
                                for key, value in rule.params.items()
                                if key != "derived_from"
                            },
                        }
                        for rule in policy.rules
                    ],
                }
            )
            entries.append(entry)
        return {"policies": entries}

    @app.get("/api/policies/{filename}", tags=["policies"])
    def get_policy(filename: str) -> dict[str, Any]:
        """Return one parsed policy plus its raw YAML for review."""
        if Path(filename).name != filename or not filename.lower().endswith(
            POLICY_SUFFIXES
        ):
            raise HTTPException(status_code=400, detail="not a policy filename")
        path = (policies / filename).resolve()
        try:
            path.relative_to(policies.resolve())
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="path escapes policies/") from exc
        if not path.is_file():
            raise HTTPException(status_code=404, detail=f"policy '{filename}' not found")
        try:
            policy = load_policy(path)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {
            "file": path.name,
            "raw": path.read_text(encoding="utf-8"),
            "name": policy.name,
            "default_decision": policy.default_decision,
            "rules": [
                {
                    "id": rule.id,
                    "type": rule.type,
                    "decision": rule.decision,
                    "reason": rule.reason,
                    "derived_from": list(rule.params.get("derived_from", [])),
                    "params": {
                        key: value
                        for key, value in rule.params.items()
                        if key != "derived_from"
                    },
                }
                for rule in policy.rules
            ],
        }

    # -- audit ---------------------------------------------------------------

    @app.get("/api/audit", tags=["audit"])
    def get_audit(
        limit: int = Query(default=50, ge=1, le=1000),
    ) -> dict[str, Any]:
        """Return the last ``limit`` decisions from the JSONL audit log."""
        path = reports / "audit.jsonl"
        entries: list[dict[str, Any]] = []
        if path.is_file():
            lines = [
                line
                for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            for line in lines[-limit:]:
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(entry, dict):
                    entries.append(entry)
        return {
            "file": _display_path(path),
            "limit": limit,
            "count": len(entries),
            "entries": entries,
        }

    # -- triggering runs -----------------------------------------------------

    def resolve_policy(selector: str | None) -> Path:
        if selector:
            if Path(selector).name != selector:
                raise HTTPException(
                    status_code=400,
                    detail="policy must be a filename returned by /api/policies",
                )
            candidate = (policies / selector).resolve()
            try:
                candidate.relative_to(policies.resolve())
            except ValueError as exc:
                raise HTTPException(
                    status_code=400, detail="policy path escapes policies/"
                ) from exc
        else:
            preferred = policies / "generated.yaml"
            candidate = preferred if preferred.is_file() else policies / "default.yaml"
        if candidate.suffix.lower() not in POLICY_SUFFIXES:
            raise HTTPException(status_code=400, detail="policy must be YAML")
        if not candidate.is_file():
            raise HTTPException(
                status_code=404, detail=f"policy '{candidate.name}' not found"
            )
        return candidate

    def run_baseline() -> dict[str, Any]:
        results = run_all(ALL_ATTACKS)
        return build_report(results, agent="sample", policy=None)

    def run_enforced(policy_path: Path) -> dict[str, Any]:
        policy = load_policy(policy_path)
        audit = AuditLog(reports / "audit.jsonl")
        results = run_all(
            ALL_ATTACKS,
            agent_factory=partial(build_sample_agent, policy=policy, audit=audit),
            output_guard=OutputGuard(audit=audit),
        )
        return build_report(
            results, agent="sample", policy=_display_path(policy_path)
        )

    @app.post("/api/run", tags=["runs"])
    def trigger_run(request: RunRequest) -> dict[str, Any]:
        """Run the existing attack runner and write the requested report."""
        policy_path = (
            resolve_policy(request.policy)
            if request.kind in ("enforced", "compare")
            else None
        )
        started = time.perf_counter()
        with _RUN_LOCK:
            if request.kind == "baseline":
                report = run_baseline()
                json_path = write_json(report, reports / "baseline.json")
                html_path = None
            elif request.kind == "enforced":
                assert policy_path is not None
                report = run_enforced(policy_path)
                json_path = write_json(report, reports / "enforced.json")
                html_path = None
            else:
                assert policy_path is not None
                before = run_baseline()
                after = run_enforced(policy_path)

                # When a v2 policy ships alongside v1, run it too so the
                # dashboard can show the v1 -> v2 progression.
                v2_path = policies / "v2.yaml"
                v2_rows = None
                v2_label = ""
                if v2_path.is_file() and v2_path.resolve() != policy_path.resolve():
                    v2_policy = load_policy(v2_path)
                    v2_audit = AuditLog(reports / "audit.jsonl")
                    v2_results = run_all(
                        ALL_ATTACKS,
                        agent_factory=partial(
                            build_sample_agent, policy=v2_policy, audit=v2_audit
                        ),
                        output_guard=OutputGuard(audit=v2_audit),
                    )
                    v2_rows = [result.to_dict() for result in v2_results]
                    v2_label = _display_path(v2_path)

                report = build_comparison(
                    before["results"],
                    after["results"],
                    policy=_display_path(policy_path),
                    baseline_source="fresh in-process baseline",
                    agent="sample",
                    v2_rows=v2_rows,
                    v2_policy=v2_label,
                )
                json_path = write_json(report, reports / "compare.json")
                html_path = write_html(report, reports / "compare.html")

        return {
            "ok": True,
            "kind": request.kind,
            "report": _display_path(json_path),
            "html": _display_path(html_path) if html_path else None,
            "policy": report.get("policy"),
            "summary": report.get("summary"),
            "generated_at": report.get("generated_at"),
            "duration_seconds": round(time.perf_counter() - started, 3),
        }

    # -- the dashboard itself ------------------------------------------------
    if frontend.is_dir():
        app.mount(
            "/ui",
            StaticFiles(directory=str(frontend), html=True),
            name="ui",
        )

    return app


app = create_app()
