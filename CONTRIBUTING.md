# Contributing to AgentFence

Thanks for helping improve AgentFence. This project is an offline, simulated
security benchmark, so contributions must stay safe: never add code that opens a
real network connection, reads or writes real user files, sends real email, or
executes a real shell command. See [`SECURITY.md`](SECURITY.md).

## Set up

Requires Python 3.11 or newer.

```bash
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python -m pytest
```

Run the full suite before opening a pull request:

```bash
python -m pytest
```

## Add an attack

Attacks are data, not scripts. Each one is an `Attack` in
`attacks/library.py`:

```python
Attack(
    id="indirect-05",
    name="Instruction hidden in a calendar invite",
    category=INDIRECT,
    payload="Read /home/user/calendar.ics and summarize it.",
    setup=_poison_calendar,          # optional; mutates the fake sandbox
    success_condition="canary_leak", # must be a registered detector name
    owasp_category=OWASP_INJECTION,
)
```

1. Pick the right tuple: `ATTACKS` for a normal attack, `V2_HOLDOUT_ATTACKS` for
   a new v2-cohort held-out attack, or `CONTROLS` for a benign control. Do not
   edit an existing attack's payload to make a policy look better.
2. Use an id that matches the cohort convention (`direct-`, `indirect-`,
   `misuse-`, `exfil-`, `held-`, `held-v2-`, `control-`).
3. If the attack needs poisoned content, write a small `setup` function that
   calls `sample_agent.sandbox.set_file` or `set_http`. The runner snapshots and
   restores the sandbox around every attack, so no cleanup is needed.
4. `success_condition` must name a detector registered in `detectors/__init__.py`.
   For a control it must be `""`, and `control=True` must be set.
5. Held-out attacks are never shown to the auto-policy generator. Add the
   `held_out=True` or `held_out_v2=True` flag if the attack must stay out of
   training. Never move an attack out of a held-out cohort after seeing results.
6. Update the counts and coverage assertions in `tests/test_attacks.py` if the
   library size changes, then run the suite.

Verify the attack does what you expect against the baseline:

```bash
python -m agentfence attack --id indirect-05 --no-write
```

## Add a detector

1. Create a module in `detectors/`, for example `detectors/pii_leak.py`, with:

   - `DETECTOR`: the stable name used by `success_condition`;
   - `SEVERITY`: `"low"`, `"medium"`, `"high"` or `"critical"`;
   - `detect(run: AgentRun) -> Finding`.

2. Detect only what the agent actually executed. Use
   `detectors.base.executed_tool_calls` / `outbound_texts`, not every attempted
   call, otherwise blocked calls make enforcement look ineffective.
3. Return `clean(DETECTOR, SEVERITY, "…")` when nothing is wrong, or a `Finding`
   with concrete `evidence` when it is. Detectors must never raise.
4. Register the module in `DETECTORS` in `detectors/__init__.py`.
5. Add at least one positive and one negative test in
   `tests/test_detectors.py`, plus any focused tests for decoding or edge cases.
6. Document the detector's blind spots in `docs/METHODOLOGY.md` and, if it
   affects the headline numbers, in the README.

## Add a policy rule

Policies live in `policies/`. Rules are evaluated top to bottom, first match
wins, and an unmatched call gets `default_decision` (normally `block`).

```yaml
- id: gen-allow-calendar-reads
  type: path_inside
  decision: allow
  reason: calendar reads were needed for a benign control
  tools: [read_file]
  roots: ["/home/user/calendar.ics"]
  derived_from: ["control-04"]
```

1. `type` must be one of `RULE_TYPES` in `enforcer/policy.py`; `decision` must
   be `allow`, `block` or `ask`. Every rule needs an `id` and a `reason`, because
   the audit log shows them.
2. Put broad deny rules before narrow allow rules, and prefer deny-by-default.
3. Add a `derived_from` list when the rule came from an attack or control, and
   keep rule ids stable for audit compatibility.
4. `policies/generated.yaml` is generated output: change the generator in
   `autopolicy/generate.py` rather than hand-editing it. `policies/v2.yaml` is
   the hand-maintained v2 policy and must keep the v1 rules intact.
5. Verify a rule without changing the checked-in report:

   ```bash
   python -m agentfence attack --id held-indirect-02 --enforce policies/v2.yaml --no-write
   python -m agentfence compare --baseline reports/baseline.json \
       --policy policies/generated.yaml --policy-v2 policies/v2.yaml \
       --out /tmp/compare.json
   ```

   Confirm both the intended attack and the controls behave correctly. A new
   rule that blocks benign work is a false positive, not a fix.

## Pull requests

- Keep changes focused and explain the security reasoning.
- Include tests for new behavior and note any measured before/after change.
- Do not weaken or skip tests, detectors or assertions to make numbers improve.
- Update the docs when you add an attack, detector, rule or limitation.
- Run `python -m pytest` and report the result in the pull request.

## Reporting issues

Security issues in AgentFence itself go through the private channel described
in [`SECURITY.md`](SECURITY.md), not the public issue tracker. Ordinary bugs,
false positives and documentation fixes are welcome as GitHub issues.
