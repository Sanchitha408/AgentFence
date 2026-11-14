# AgentFence

[![CI](https://github.com/Sanchitha408/AgentFence/actions/workflows/ci.yml/badge.svg)](https://github.com/Sanchitha408/AgentFence/actions/workflows/ci.yml)

AgentFence is an offline research platform for measuring and enforcing the
security of tool-using AI agents: it runs a deliberately vulnerable agent
through a reproducible library of prompt-injection, tool-misuse and
data-exfiltration attacks, records every tool call, uses canary secrets and
call-level detectors to prove which attacks worked, auto-generates a YAML
policy from the baseline failures, then re-runs the same library through a
policy-enforcing proxy and a reply check to produce a before/after comparison,
JSON/HTML reports and a local dashboard.

## The problem

Agents read files, send email, run commands and fetch URLs. A single poisoned
email can turn "summarize my inbox" into "email the API keys to an attacker",
and a tool call that looks reasonable in isolation can still carry a secret
out. Teams deploying agents usually have no repeatable way to answer basic
questions: which attacks get through, which policy rules actually stop them,
how much the fix generalises beyond the attacks used to design it, and how
often benign work gets blocked. AgentFence turns those questions into a
measured benchmark with explicit blind spots, rather than an assurance claim.

## Architecture

```mermaid
flowchart LR
    A["Baseline run<br/>attacks/ → runner/ → sample_agent/"] --> B["Detectors<br/>canary leak · forbidden tool<br/>unauthorized recipient · prompt leak"]
    B --> C["Auto-policy<br/>autopolicy/ → policies/generated.yaml"]
    C --> D["Enforcer<br/>per-tool-call YAML policy<br/>allow / block / ask"]
    D --> E["Reply check<br/>withhold canaries and<br/>system-prompt markers"]
    E --> F["Compare report<br/>reports/compare.json + HTML"]
    F --> G["Dashboard<br/>backend/ + frontend/"]
```

The vulnerable agent and all of its tools are simulated. The baseline run is
policy-free; the same attack library is then re-run behind the enforcer, so the
comparison isolates the effect of the policy. `policies/v2.yaml` adds an
argument-level data-loss stage on top of the generated v1 rules.

### Repository layout

```text
sample_agent/   deliberately vulnerable agent, fake tools, in-memory sandbox
attacks/        12 original attacks, 6 held-out, 4 held-out-v2, 6 controls
detectors/      canary_leak, forbidden_tool_call, unauthorized_recipient,
                system_prompt_leak
runner/         runs each attack in a fresh sandbox and applies the detectors
enforcer/       policy engine, guarded tools, data-loss stage, reply stage, audit log
autopolicy/     turns baseline failures into a suggested YAML policy
policies/       default.yaml, generated.yaml (v1), v2.yaml (+ data-loss stage)
reports/        JSON reports, before/after comparison and self-contained HTML
backend/        FastAPI API over reports, policies and the audit log
frontend/       dependency-free HTML/CSS/JS dashboard (no build step, no CDN)
agentfence/     CLI: attack, autopolicy, compare
tests/          pytest suite, including FastAPI TestClient API tests
scripts/        demo.sh: clean-clone walkthrough from venv to dashboard
docs/           methodology and dashboard screenshots
```

## Quick start

Requires Python 3.11 or newer. Every command below is run from the repository
root; nothing needs a network connection after installation.

```bash
git clone https://github.com/Sanchitha408/AgentFence.git
cd AgentFence

python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Run the test suite
python -m pytest

# 1. Baseline: no policy, attacks against the vulnerable agent
python -m agentfence attack --agent sample --out reports/baseline.json

# 2. Relearn a policy from the baseline, then compare v1 and v2
python -m agentfence autopolicy --baseline reports/baseline.json \
    --out policies/generated.yaml
python -m agentfence compare --baseline reports/baseline.json \
    --policy policies/generated.yaml \
    --policy-v2 policies/v2.yaml \
    --out reports/compare.json

# 3. Start the dashboard
venv/bin/uvicorn backend.app:app --host 127.0.0.1 --port 8000
```

Open **http://127.0.0.1:8000/ui/** for the dashboard (or
**http://127.0.0.1:8000/docs** for the generated API docs). The comparison is
written to `reports/compare.json` and `reports/compare.html`.

The short version of all of that is:

```bash
bash scripts/demo.sh
```

`scripts/demo.sh` creates the virtual environment if needed, installs the
requirements, runs the tests, runs the baseline, runs the v1/v2 comparison, and
prints the dashboard URL.

## Results

The library has 22 attacks (12 original, 6 held-out, 4 held-out-v2) and 6
controls. "Detected ASR" is attack success rate as proved by the detectors: an
attack counts as successful only when its declared success detector fires on
what actually executed. v0 is the policy-free baseline, v1 is the
auto-generated `policies/generated.yaml`, and v2 adds argument-level data loss.

| Stage | Detected ASR (22) | Original (12) | Held-out (6) | Held-out v2 (4) | Control false positives (6) |
| --- | --- | --- | --- | --- | --- |
| v0 — baseline, no policy | 20/22 (90.9%) | 12/12 (100%) | 6/6 (100%) | 2/4 (50%) | 0/6 |
| v1 — generated policy | 2/22 (9.1%) | 0/12 (0%) | 1/6 (16.7%) | 0/4 (0%) | 0/6 |
| v2 — generated + data loss | 0/22 (0%) | 0/12 (0%) | 0/6 (0%) | 0/4 (0%) | 0/6 |

How to read this table honestly:

- **The baseline is understated.** The baseline `canary_leak` detector matches
  raw canary strings without decoding. `held-v2-base64-01` and
  `held-v2-split-01` never fire at baseline, which is why baseline detection is
  2/4 for the v2 cohort rather than 4/4. Those attacks still leak.
- **Detected ASR is not the same as blocked.** v1 leaves two known leaks
  unblocked (`held-indirect-02`, `held-v2-url-01`); v2 blocks those and the
  base64 case, so v2 blocks 21 of the 22 harmful executions. The remaining one,
  `held-v2-split-01`, is not blocked *and not detected*, so it is reported as
  "unresolved" rather than counted in the 0/22 above. See
  [Limitations and known gaps](#limitations-and-known-gaps).
- **Generalisation:** v1 was learned from the 12 original attacks only. It
  fixed all 12 original attacks and 5 of the 6 held-out attacks; the sixth is
  the argument-level leak that motivated v2.
- **Controls** are benign tasks. None of the 6 controls fired a detector or was
  blocked at any stage, so the measured control false-positive rate is 0/6
  throughout. A control only counts as a false positive when a detector fires.

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

## Limitations and known gaps

This is a research benchmark, not a guarantee. The important gaps:

- **Cross-call exfiltration via split payloads is not detected.** A secret
  broken into pieces shorter than `min_fragment_length` (16 characters in
  `policies/v2.yaml`), sent over two calls, matches no canary and no fragment.
  `held-v2-split-01` demonstrates this and is reported as unresolved.
- **The baseline detectors do not decode encodings, so the baseline is
  understated.** Base64 and hex leaks are invisible to the raw canary detector
  even when v2's decoding stage blocks them. Read `v2.attacks` for per-channel
  detail rather than relying on baseline ASR alone.
- **The model is a rule-based mock.** `sample_agent/mock_llm.py` is a
  deterministic regular-expression stand-in for an LLM. The numbers are
  reproducible, but they say nothing about how a particular production model
  would behave.
- **The attack set is small and author-written.** 22 attacks and 6 controls,
  all written by the same author, cannot cover the space of agentic failures.
  The held-out split reduces training-fit bias but is not an external benchmark.
- **The held-out split is only partly unseen.** The first 6 held-out attacks
  informed the design of v2, so they are no longer a clean generalisation test
  for it. Only the 4 `held_out_v2` attacks were written before v2 and never used
  to tune it; `held-v2-split-01` still escapes.

Additional known gaps:

- **Unknown encodings.** Only URL-encoding, base64 and hex are decoded; a
  rotation cipher, compression or bespoke encoding passes through.
- **Secrets the check has never seen.** v2 protects canary values and content
  read from `protect_paths`, not arbitrary secrets typed into a task.
- **Channel coverage.** Only `http_get` URLs, `send_email` subject/body and
  `run_shell` commands are scanned. A new tool argument is invisible until its
  channel is added to the YAML.
- **Paraphrased prompt leakage.** The reply stage matches canary values and
  marker phrases, not a paraphrase of the system prompt.
- **No defence against a determined attacker.** Policy evasion, tool
  chaining and novel side channels are out of scope.

## Future work

- Decode-aware baseline detectors so the baseline measures encoded and
  cross-call leaks instead of understating them.
- Cross-call taint tracking and per-conversation accumulation, to close the
  split-payload gap.
- More encodings, compression and bespoke-encoding detection.
- A larger, independently authored attack corpus; report confidence intervals.
- An adapter for a real model behind the same agent interface, with the mock
  kept as the deterministic default.
- Additional tools and channels, an MCP proxy mode, and a GitHub Action for
  continuous attack runs.
- Human-approval (`ask`) workflows with an approval queue in the dashboard.

## Documentation

- [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md) — attack categories, OWASP
  mapping, held-out split, success measurement and blind spots.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — add an attack, detector or policy
  rule; run the tests.
- [`SECURITY.md`](SECURITY.md) — responsible use and how to report issues.
- [`LICENSE`](LICENSE) — MIT.
- [`SPEC.md`](SPEC.md) — project vision and roadmap.

## Responsible use

AgentFence is for **offline, simulated, authorized security testing and
research only**. Every canary is synthetic; the filesystem, shell, network and
email outbox are in-memory fakes, and nothing here opens a real socket, reads a
real file or sends a real email. Do not point these attacks at systems you do
not own or have explicit written permission to test. See
[`SECURITY.md`](SECURITY.md) and [`DISCLAIMER.md`](DISCLAIMER.md).
