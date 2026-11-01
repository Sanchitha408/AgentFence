# AgentFence

A research platform for **validating the security of AI agents**: run a deliberately
vulnerable tool-calling agent through a library of attacks, detect when it leaks
secrets or misuses tools, then enforce a policy that stops those calls and
re-measure.

> Status: **Milestone 1 complete** — repository layout, sample agent, tests.
> Full design and roadmap: [`SPEC.md`](SPEC.md).

## Why

Agents read files, send email, run commands, and fetch URLs. A single poisoned
email can turn "summarize my inbox" into "email the API keys to an attacker".
AgentFence aims to make that measurable: reproducible attacks, pass/fail
detectors, and per-tool-call policy enforcement.

## How it works (planned architecture)

```
attacks/   -> runner/   -> sample_agent/  (tools)
                 |              |
                 v              v
             detectors/ <---- enforcer/ (YAML policy: allow / block)
                 |
                 v
              reports/  ->  dashboard/
```

Only the pieces on the left of the arrow that matter for Milestone 1 exist today:

```
sample_agent/     deliberately vulnerable agent (fake tools, fake canaries)
tests/            pytest suite
requirements.txt  test dependency only — the agent runs fully offline
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
the step limit, and that no real socket is ever opened.

## Roadmap

| # | Milestone | Status |
| --- | --- | --- |
| 1 | Repo setup, README, sample agent | ✅ |
| 2 | Attack runner + attacks + detectors + baseline report | ⏳ |
| 3 | Enforcer + YAML policy + audit log | ⏳ |
| 4 | Auto-policy generation + before/after report | ⏳ |
| 5 | Dashboard | ⏳ |
| 6 | Tests, CI, docs, demo | ⏳ |

## Safety

Every secret is synthetic. The filesystem, shell, network, and email outbox are
in-memory fakes; nothing in this repository executes a real command, opens a real
socket, or sends a real email. This project is for studying agent security, not
for attacking third-party systems.
