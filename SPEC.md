# AgentFence — AI Agent Security Validation & Enforcement Research Platform

## One-line pitch
AgentFence attacks an AI agent in a sandbox, records what got through, auto-generates enforcement policies from the failures, then re-runs the same attacks to prove the policies work (before/after report).

## Goals
- Test tool-using AI agents against prompt injection, tool misuse, and data exfiltration.
- Enforce per-tool-call policy between the agent and its tools.
- Close the loop: failures -> suggested policy -> re-test -> measurable improvement.
- Show everything in a simple web dashboard and exportable report.

## Non-goals
- Not an agent framework. Not a real-world exploitation tool.
- Never touches real email, real files, or real networks. Everything is sandboxed and fake (canary data only).
- No claim of full protection against a determined attacker; limitations are documented.

## Stack (suggested)
- Python 3.11+, FastAPI backend, SQLite storage
- React (or plain HTML + JS) dashboard
- YAML policy files
- pytest for tests, GitHub Actions for CI

## Architecture
1. `sample_agent/`  deliberately vulnerable tool-calling agent (fake inbox, fake files, fake secrets/canary tokens)
2. `attacks/`       attack library (each attack = id, category, payload, success condition)
3. `runner/`        executes attacks against an agent, logs every tool call
4. `detectors/`     canary-secret leak, forbidden-tool call, unauthorized-recipient, system-prompt leak
5. `enforcer/`      proxy between agent and tools; evaluates YAML policy before each call (allow / block / ask)
6. `autopolicy/`    turns failed attacks into suggested policy rules
7. `reports/`       before/after scoring, JSON + HTML export, OWASP category mapping
8. `dashboard/`     web UI: runs, results, policies, comparison view
9. `tests/`

## Features
### Core (MVP)
- Vulnerable sample agent with 3-4 tools (read_file, send_email, run_shell(simulated), http_get(simulated))
- 10-15 attacks: direct injection, indirect injection (poisoned email/file), tool misuse, exfiltration of canary secrets
- Detectors with pass/fail per attack
- Per-tool-call YAML policy enforcement (allow/deny lists, argument rules, recipient allowlist)
- Audit log of every tool call (JSONL)
- CLI: `agentfence attack`, `agentfence enforce`, `agentfence report`

### Differentiators
- Auto-policy generation from failed attacks
- Before/after re-test with attack success rate and false-positive count
- OWASP LLM Top 10 / agentic risk category mapping on each finding
- HTML/JSON report export

### Stretch
- Web dashboard with run history and side-by-side comparison
- Test any HTTP-accessible agent, not just the sample one
- MCP-proxy mode
- GitHub Action to run attacks in CI
- Human-approval mode for risky calls
- Multi-turn attacks and encoding-obfuscation attacks

## Milestones
1. Repo setup, README skeleton, sample agent
2. Attack runner + 10 attacks + detectors + baseline report
3. Enforcer + YAML policy + audit log
4. Auto-policy + before/after report
5. Dashboard
6. Tests, CI, docs, demo GIF, blog post

## Definition of done (per milestone)
Runs from a clean clone, has tests, README updated, committed to GitHub.
