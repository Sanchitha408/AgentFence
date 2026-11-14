# Security policy

## Responsible use

AgentFence is a research benchmark for **offline, simulated, authorized**
security testing. It ships with deliberately vulnerable sample code and a
library of prompt-injection, tool-misuse and exfiltration attacks.

- Every canary is synthetic. The filesystem, shell, network and email outbox are
  in-memory fakes; nothing in this repository opens a real socket, reads a real
  file or sends a real email.
- Do not use these attacks against systems, agents or accounts you do not own or
  do not have explicit written permission to test. Testing third-party systems
  without authorization may be illegal and is not an intended use of this
  project.
- The sample agent is intentionally insecure. Do not deploy it, or a policy
  derived from it, as a production security control without independent review.
- AgentFence measures a narrow set of failure modes. Its results are not a
  guarantee that any agent is secure or compliant.

See [`DISCLAIMER.md`](DISCLAIMER.md) and
[`docs/METHODOLOGY.md`](docs/METHODOLOGY.md) for the full scope and known
limitations.

## Reporting a vulnerability

If you find a security issue **in AgentFence itself** — for example a real
network or filesystem escape in the simulated tools, a canary being written to
disk, unsafe template handling in the dashboard, or a way the enforcer can be
bypassed in the shipped sample — please report it privately rather than opening
a public issue.

Use GitHub's private vulnerability reporting for this repository:

<https://github.com/Sanchitha408/AgentFence/security/advisories/new>

Please include:

- a description of the issue and its impact,
- the affected file or component,
- minimal reproduction steps or a proof of concept,
- the Python version and operating system you used.

Do not include real credentials, personal data or data from systems you do not
own. Use the synthetic canaries from `sample_agent/canaries.json` in examples.

## What is not a vulnerability

The following are documented, intentional design choices rather than security
bugs:

- the sample agent follows instructions found in tool output;
- the baseline has no enforcement and therefore leaks;
- known detector blind spots such as split payloads, undecoded encodings,
  paraphrased prompt leakage and out-of-scope tool channels
  ([`README.md`](README.md#limitations-and-known-gaps));
- the fact that the mock model is rule-based.

## Scope and disclosure

This is a small research project maintained on a best-effort basis. Reports are
acknowledged when possible, and a fix or documented limitation will be published
in the repository. Please allow reasonable time for a response before public
disclosure.
