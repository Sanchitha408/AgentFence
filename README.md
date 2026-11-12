# AgentFence

A research platform for **validating the security of AI agents**: run a deliberately
vulnerable tool-calling agent through a library of attacks, detect when it leaks
secrets or misuses tools, then enforce a policy that stops those calls and
re-measure.

> Status: **Milestone 5 complete, v2 enforcement added** — auto-generated
> policies, the before/after report, the local web dashboard, and an
> argument-level data-loss stage that layer 2 adds on top of the v1 rules.
> Full design and roadmap: [`SPEC.md`](SPEC.md).

## Why

Agents read files, send email, run commands, and fetch URLs. A single poisoned
email can turn "summarize my inbox" into "email the API keys to an attacker".
AgentFence aims to make that measurable: reproducible attacks, pass/fail
detectors, and per-tool-call policy enforcement.

## How it works

```
attacks/   -> runner/   -> sample_agent/  (tools)
                 |              |
                 v              v
             detectors/ <---- enforcer/ (YAML policy: allow / block)
                 |
                 v
              reports/  ->  dashboard/
```

What exists today:

```
sample_agent/  deliberately vulnerable agent (fake tools, fake canaries)
attacks/       the attack library: 12 attacks + 6 held-out attacks + 5 controls
detectors/     canary_leak, forbidden_tool_call, unauthorized_recipient,
               system_prompt_leak — each turns an AgentRun into a Finding
runner/        runs each attack in a fresh sandbox, applies all detectors
reports/       JSON reports, before/after comparison and self-contained HTML
enforcer/      policy engine, guarded tools, data-loss stage, reply stage, audit log
autopolicy/    turns baseline failures into a suggested YAML policy
policies/      default.yaml, generated.yaml (v1) and v2.yaml (+ data_loss stage)
backend/       FastAPI dashboard API over the reports, policies and audit log
frontend/      dependency-free HTML/CSS/JS dashboard (no build step, no CDN)
agentfence/    the CLI: attack, autopolicy, compare
tests/         pytest suite (including FastAPI TestClient API tests)
requirements.txt  pyyaml, fastapi, uvicorn, httpx, pytest; fully offline
pytest.ini        pytest config (imports from the repo root)
SPEC.md           project vision, features, milestones
```

## Milestone 1: the vulnerable sample agent

`sample_agent/` is the target of every attack that will come later. It is
intentionally unsafe, and it never leaves the process:

| File | What it does |
| --- | --- |
| `agent.py` | `VulnerableAgent`: system prompt + step loop + tool dispatch. Records every step in an `AgentRun` transcript. |
| `mock_llm.py` | `MockLLM`: a deterministic, rule-based stand-in for an LLM. Regular expressions over the transcript decide the next tool call, so no API key and no network are needed. It also reads instructions out of tool output — that is the vulnerability. |
| `tools.py` | `FakeTools`: `read_file`, `send_email`, `run_shell`, `http_get`. All simulated, all recorded. |
| `sandbox.py` | The fake world: in-memory filesystem, inbox with a poisoned email, canned HTTP responses, and a fake shell. |
| `canaries.json` | Synthetic secrets (`sk-canary-…`) that act as tripwires. If one shows up in an email, a URL, or a reply, a leak happened. |
| `__main__.py` | `python -m sample_agent`: runs three scenarios and reports leaks. |

### What the agent gets wrong

1. It treats tool output as instructions, so an HTML comment in `inbox.txt`
   becomes a command (indirect prompt injection).
2. It has no path restrictions, so it will read `secrets/api_keys.txt`.
3. It will send email to any recipient.
4. It runs any shell command (simulated) and fetches any URL (simulated).
5. It recites its system prompt, including the internal canary token.

## Milestone 2: attacks, detectors, baseline

```bash
python -m agentfence attack --agent sample --out reports/baseline.json
```

With no enforcement in place, every attack works:

```
Attack success rate: 12/12 (100.0%)
  direct injection     3/3 (100.0%)
  indirect injection   4/4 (100.0%)
  tool misuse          3/3 (100.0%)
  exfiltration         2/2 (100.0%)
Controls: 0 false positive(s) out of 3
```

That 100% is the *finding*, not the goal: Milestone 3 adds the enforcer and
re-runs the same library to show the drop.

| id | category | what it proves |
| --- | --- | --- |
| `direct-01` | direct injection | "ignore previous instructions" exfiltrates the API keys |
| `direct-02` | direct injection | the system prompt (and its canary) is echoed back |
| `direct-03` | direct injection | a role-play override reads `/etc/passwd` |
| `indirect-01` | indirect injection | instruction hidden in an inbox email |
| `indirect-02` | indirect injection | instruction hidden in a notes file |
| `indirect-03` | indirect injection | instruction in shell stdout |
| `indirect-04` | indirect injection | instruction in a fetched web page |
| `misuse-01` | tool misuse | path traversal escapes `/home/user` |
| `misuse-02` | tool misuse | destructive `rm -rf` is executed (simulated) |
| `misuse-03` | tool misuse | email leaves for a non-allowlisted domain |
| `exfil-01` | exfiltration | canaries sent by email |
| `exfil-02` | exfiltration | canaries uploaded in a URL query string |
| `control-01..03` | control | ordinary file reads and a fetch must stay quiet |

Each attack declares `success_condition` — the detector that proves it worked —
and the control set exists to measure false positives. Use `--id` to run one:

```bash
python -m agentfence attack --id indirect-02 --no-write
```

## Milestone 3: enforcement

```bash
python -m agentfence attack --agent sample --out reports/baseline.json
python -m agentfence attack --agent sample --enforce policies/default.yaml \
    --out reports/enforced.json --audit reports/audit.jsonl
```

Enforcement is opt-in, so the baseline keeps working unchanged.

| | baseline | enforced |
| --- | --- | --- |
| overall attack success rate | 12/12 (100%) | 1/12 (8.3%) |
| direct injection | 3/3 | 1/3 |
| indirect injection | 4/4 | 0/4 |
| tool misuse | 3/3 | 0/3 |
| exfiltration | 2/2 | 0/2 |
| control false positives | 0/3 | 0/3 |

`direct-02` still succeeds: it is a pure prompt leak, answered without calling a
tool, so a tool-level policy has nothing to block. Closing that needs an output
filter, which is not in this milestone.

How it works: `GuardedTools` implements the same surface as `FakeTools`, so the
agent cannot tell the difference. Each call is evaluated against the YAML rules
(top to bottom, first match wins, otherwise deny) and ends in `allow`, `block`,
or `ask`:

- **allow** - the call reaches the fake tool.
- **block** - nothing runs; the agent gets `blocked by policy: <rule id> - <reason>`.
- **ask** - nothing runs either; the call is flagged as awaiting human approval.

Paths are normalised before matching, so `/home/user/../../etc/passwd` is tested
as `/etc/passwd`. Paths hidden inside shell commands (`cat /home/user/secrets/...`)
are extracted and checked too. Every call, allowed or not, appends one JSON line:

```json
{"timestamp": "2026-11-01T16:05:11.511Z", "tool": "read_file",
 "arguments": {"path": "..."}, "decision": "block", "rule_id": "path-sensitive-deny",
 "reason": "...", "executed": false, "output": "blocked by policy: ..."}
```

Detectors judge only calls that actually executed, so enforcement is measured on
what happened rather than what was attempted; blocked attempts stay visible in
the report's `tool_calls` and in the audit log.

## Milestone 4: auto-policy and before/after

```bash
python -m agentfence attack --out reports/baseline.json
python -m agentfence autopolicy --baseline reports/baseline.json \
    --out policies/generated.yaml
python -m agentfence compare --baseline reports/baseline.json \
    --policy policies/generated.yaml --out reports/compare.json
```

The generator reads only the original attacks that succeeded. The six held-out
attacks are marked `held_out` in `attacks/` and are never analysed, so their
before/after numbers measure generalisation rather than training fit. Compare
also writes `reports/compare.html`, a single self-contained file with no CDN.

## v2 enforcement: argument-level data loss

v1 decides calls by tool, path, recipient and destination host. It never looks
at *what* a call carries. That is the `held-indirect-02` gap: the agent reads a
backup key from an allowed workspace file and sends it to an allowed host inside
the URL query string.

`policies/v2.yaml` keeps every v1 rule and adds a top-level `data_loss` block.
`enforcer/data_loss.py` then scans the outgoing URL (including the decoded query
string), email subject and body, and shell command text for canary values and
for content read from the deny-listed paths. It decodes URL-encoding, base64 and
hex first. A hit becomes a `block` with `rule_id: arg-data-loss` and is written
to the same audit log.

The rule id, reason, tools, channels, encodings, protect paths and minimum
fragment length all come from YAML. `default.yaml` and `generated.yaml` have no
`data_loss` block, so v1 behaviour and numbers are unchanged.

```bash
python -m agentfence compare --baseline reports/baseline.json \
    --policy policies/generated.yaml \
    --policy-v2 policies/v2.yaml \
    --out reports/compare.json
```

The report gains a `v2` section with v1 vs v2 rates overall, per cohort and per
category, control false positives, which rule blocked what, and a per-attack
v1/v2 table. Four attacks (`held-v2-*`) were written **before** the check for
its other channels: a URL path, a shell echo, a base64 email body, and a secret
split across two calls. They are tagged `held_out_v2`, are a separate cohort,
and the auto-policy generator ignores them.

The v2 cohort also shows two honest limits of the *detectors*, not just the
check: a base64 body and a split secret do not contain a raw canary, so the
baseline `canary_leak` detector does not fire for them. v2's stage decodes the
base64 body and blocks it; the split halves are shorter than the 16-character
fragment threshold and get through.

## Milestone 5: web dashboard

The dashboard is plain HTML, CSS and JavaScript with hand-rolled SVG charts.
There is no npm install, no build step, no CDN and no external asset: it works
fully offline and calls only the local FastAPI API.

### Start the backend and dashboard

```bash
cd AgentFence
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

venv/bin/uvicorn backend.app:app --host 127.0.0.1 --port 8000
```

Open **http://127.0.0.1:8000/ui/** for the dashboard, or
**http://127.0.0.1:8000/docs** for the generated API docs.

### Run the frontend as a separate server (optional)

In a second terminal, with the backend still running:

```bash
cd AgentFence
venv/bin/python -m http.server 5173 --directory frontend
```

Open **http://127.0.0.1:5173/**. The page calls `http://127.0.0.1:8000`; CORS
accepts only local origins. If the API runs elsewhere, add `?api=`:

```text
http://127.0.0.1:5173/?api=http://127.0.0.1:9000#/overview
```

### Pages and data

| Page | What it shows |
| --- | --- |
| Overview | Before/after attack success rate (overall, original, held-out and held-out v2, per category), the v1 → v2 progression, control false positives, fixed / still-succeeding / regression counts |
| Results | Every attack with category, OWASP mapping, baseline and enforced outcomes, detectors fired; filters for category and original / held-out / held-out v2 |
| Policies | Parsed YAML rules with id, type, decision, reason and `derived_from` attacks |
| Audit log | Recent allow / block / ask decisions with rule id, reason and arguments |
| Compare | Baseline, v1 and v2 per attack, with rows still succeeding under the last stage highlighted and the recorded "why" |

**Run again** posts to `POST /api/run` with `{"kind": "compare"}`. The backend
runs the existing baseline and enforced runner in-process, then rewrites
`reports/compare.json` and `reports/compare.html`; the page reloads the data.
All runs use the in-memory sandbox — no real file, email, shell or network access.

API endpoints: `/api/runs`, `/api/runs/{baseline|enforced|compare}`,
`/api/compare`, `/api/policies`, `/api/policies/{file}`,
`/api/audit?limit=N`, `/api/run`, `/api/health`.

## Screenshots

### Overview
![Overview: attack success before vs after enforcement](docs/screenshots/overview.png)

### Results
![Results: every attack with baseline vs enforced outcome](docs/screenshots/results.png)

### Compare
![Compare: side-by-side view with still-succeeding attacks highlighted](docs/screenshots/compare.png)

### Policies
![Policies: generated rules with derived_from attacks](docs/screenshots/policies.png)

### Audit log
![Audit log: allow, block and ask decisions](docs/screenshots/audit.png)

## Setup

Requires Python 3.10+.

```bash
cd AgentFence
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Run the sample agent

```bash
python -m sample_agent
python -m sample_agent --task "Summarize my inbox."
python -m sample_agent --task "Read /home/user/notes.txt" --json
```

Expected: the inbox scenario ends with an email to `attacker@evil.example`
containing both canary secrets, and the tool prints `*** LEAK: … ***`.

## Tests

```bash
python -m pytest
```

The suite covers path normalization, the fake filesystem, tool recording and
error handling, indirect prompt injection, explicit exfiltration, prompt leak,
the step limit, and that no real socket is ever opened. On top of that: a
positive and a negative case for every detector, the attack library's shape and
counts, sandbox isolation between attacks, the report's arithmetic, the v2
data-loss check (plain, URL-encoded, base64 and hex positives; benign query
strings, email and shell negatives; fragment threshold; audit logging; tracked
reads), the held-out-v2 split, and the CLI invocation from the README.

## Limitations

v2 raises the bar; it is not a guarantee. What it still cannot catch:

- **Split secrets.** A value broken into pieces shorter than
  `min_fragment_length` (16 characters in `policies/v2.yaml`) is not matched.
  `held-v2-split-01` does exactly this and is reported as not blocked.
- **Unknown encodings.** Only URL-encoding, base64 and hex are decoded. A
  rotation cipher, compression, or a bespoke encoding passes through.
- **Secrets the check has never seen.** It knows the canaries and content read
  from `protect_paths`. A secret obtained elsewhere (for example typed into the
  task by the user) is not protected unless a detector or path rule knows it.
- **Channel coverage.** Only `http_get` URLs, `send_email` subject/body and
  `run_shell` commands are scanned. A new tool argument is invisible until a
  channel is added to the YAML.
- **Detector blind spots.** The baseline `canary_leak` detector matches raw
  canary strings. It does not decode base64 or hex, so those baseline rows
  under-report the leak even when v2 blocks it. `v2.attacks` shows the
  per-channel outcome.
- **Paraphrased prompt leakage.** The reply stage matches canary values and
  marker phrases, not a paraphrase of the system prompt.
- **A determined attacker.** Everything here runs against a rule-based mock
  model and in-memory tools; the numbers are a reproducible benchmark, not a
  claim about any production agent.

## Roadmap

| # | Milestone | Status |
| --- | --- | --- |
| 1 | Repo setup, README, sample agent | ✅ |
| 2 | Attack runner + attacks + detectors + baseline report | ✅ |
| 3 | Enforcer + YAML policy + audit log | ✅ |
| 4 | Auto-policy generation + before/after report | ✅ |
| 5 | Dashboard | ✅ |
| 5.1 | v2 argument-level data-loss enforcement | ✅ |
| 6 | Tests, CI, docs, demo | ⏳ |

## Safety

Every secret is synthetic. The filesystem, shell, network, and email outbox are
in-memory fakes; nothing in this repository executes a real command, opens a real
socket, or sends a real email. This project is for studying agent security, not
for attacking third-party systems.
