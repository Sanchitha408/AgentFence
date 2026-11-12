"""Turn a baseline run's successful attacks into a suggested YAML policy.

The generator is intentionally boring: it reads the **original** attacks that
got through a policy-free run, looks at the tool calls they executed and the
detectors they tripped, and emits a rule for each kind of dangerous action it
can name. It never invents a rule for an attack it did not see, and it never
emits an ``allow`` rule without a concrete constraint.

Held-out attacks are marked ``held_out`` in the library and filtered out here.
That is the whole defence for the held-out measurement: the generator cannot
learn a rule from an attack whose result it refuses to look at.

Rules are generalised one level:

* a canary file becomes its parent directory glob (``/home/user/secrets/**``);
* a recipient address becomes a domain decision (``email_domain_deny``);
* an exact shell command becomes its command family (``rm *``);
* a destination host becomes part of an approved-destination allowlist.

Every emitted rule carries ``id``, ``type``, ``decision``, ``reason`` and
``derived_from`` (the attack ids that motivated it).
"""

from __future__ import annotations

import copy
import fnmatch
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urlparse

import yaml

from detectors.forbidden_tool_call import FORBIDDEN_SHELL_COMMANDS
from detectors.unauthorized_recipient import ALLOWED_DOMAINS
from enforcer.policy import ALLOW, BLOCK, DECISIONS, RULE_TYPES, paths_in_call
from sample_agent import sandbox

HOME = sandbox.HOME
DEFAULT_OUTPUT = "policies/generated.yaml"


@dataclass(frozen=True)
class GeneratedRule:
    """One suggested rule, with the evidence that asked for it."""

    id: str
    type: str
    decision: str
    reason: str
    derived_from: tuple[str, ...]
    params: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "id": self.id,
            "type": self.type,
            "decision": self.decision,
            "reason": self.reason,
            "derived_from": list(self.derived_from),
        }
        data.update(copy.deepcopy(dict(self.params)))
        return data


@dataclass(frozen=True)
class GeneratedPolicy:
    """A complete, loadable policy document plus its provenance."""

    rules: tuple[GeneratedRule, ...]
    source: str = "baseline"
    analysed: int = 0
    name: str = "generated"
    default_decision: str = BLOCK
    default_reason: str = (
        "deny by default: the baseline did not show this call to be safe"
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": 1,
            "generated_from": self.source,
            "analysed_failed_attacks": self.analysed,
            "default_decision": self.default_decision,
            "default_reason": self.default_reason,
            "output_check": {
                "stage": "reply",
                "enabled": True,
                "reason": (
                    "the reply stage (enforcer/output_guard.py) withholds final "
                    "answers that contain canaries or system-prompt markers, so "
                    "attacks that never call a tool can still be blocked"
                ),
            },
            "rules": [rule.to_dict() for rule in self.rules],
        }

    def to_yaml(self) -> str:
        header = (
            "# AgentFence suggested policy - auto-generated from a baseline run.\n"
            "#\n"
            "# Source: "
            f"{self.source}\n"
            f"# Failed original attacks analysed: {self.analysed}\n"
            "#\n"
            "# Rules are evaluated top to bottom, first match wins. `default_decision`\n"
            "# is block, so a call no rule allows is refused. Every rule names the\n"
            "# attack ids that motivated it in `derived_from`. Held-out attacks are\n"
            "# deliberately absent: the generator never saw them.\n"
            "#\n"
            "# `output_check` is a separate stage (enforcer/output_guard.py) applied to\n"
            "# the agent's final reply, because a tool policy cannot see an answer.\n"
            "\n"
        )
        return header + yaml.safe_dump(
            self.to_dict(), sort_keys=False, default_flow_style=False
        )

    def write(self, path: str | Path = DEFAULT_OUTPUT) -> Path:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(self.to_yaml(), encoding="utf-8")
        return target

    def load(self) -> Any:
        """Round-trip validation through the real policy loader."""
        from enforcer.policy import load_policy
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as handle:
            handle.write(self.to_yaml())
            temporary = handle.name
        try:
            return load_policy(temporary)
        finally:
            Path(temporary).unlink(missing_ok=True)


# -- reading either an AttackResult or a report row --------------------------


def _row(result: Any) -> dict[str, Any]:
    if isinstance(result, Mapping):
        return {
            "id": str(result.get("id", "")),
            "name": str(result.get("name", "")),
            "category": str(result.get("category", "")),
            "control": bool(result.get("control", False)),
            "held_out": bool(result.get("held_out", False)),
            "succeeded": bool(result.get("succeeded", False)),
            "detectors_fired": list(result.get("detectors_fired", [])),
            "tool_calls": list(result.get("tool_calls", [])),
        }

    attack = result.attack
    return {
        "id": attack.id,
        "name": attack.name,
        "category": attack.category,
        "control": bool(attack.control),
        "held_out": bool(getattr(attack, "held_out", False)),
        "succeeded": bool(result.succeeded),
        "detectors_fired": list(result.fired),
        "tool_calls": list(result.tool_calls),
    }


def _recipient_domain(address: str) -> str:
    address = (address or "").strip().lower()
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[1]


def _request_host(url: str) -> str:
    try:
        return (urlparse(str(url)).hostname or "").lower()
    except ValueError:  # pragma: no cover - urlparse is very forgiving
        return ""


def _inside_home(path: str) -> bool:
    return path == HOME or path.startswith(HOME + "/")


def _protected_patterns() -> dict[str, tuple[str, ...]]:
    """Map a canary's parent directory to a deny glob for that directory."""
    patterns: dict[str, tuple[str, ...]] = {}
    for canary in sandbox.load_canaries():
        location = str(canary.get("location", ""))
        if not location.startswith("/"):
            continue  # the system prompt has no filesystem path
        parent = location.rsplit("/", 1)[0]
        patterns.setdefault(parent, (parent + "/**",))
    return patterns


def _append(mapping: dict[str, set[str]], key: str, attack_id: str) -> None:
    mapping.setdefault(key, set()).add(attack_id)


def generate_policy(
    results: Sequence[Any],
    source: str = "baseline run",
) -> GeneratedPolicy:
    """Build a policy from baseline results.

    ``results`` may be ``AttackResult`` objects or JSON report rows. Rows that
    are controls, held-out, or did not succeed are never used to derive a
    block rule.
    """
    rows = [_row(result) for result in results]
    original_attacks = [
        row for row in rows if not row["control"] and not row["held_out"]
    ]
    original_controls = [
        row for row in rows if row["control"] and not row["held_out"]
    ]
    failures = [row for row in original_attacks if row["succeeded"]]

    protected = _protected_patterns()
    sensitive: dict[str, set[str]] = {}
    outside: set[str] = set()
    destructive: dict[str, set[str]] = {}
    unauthorized_email: set[str] = set()
    untrusted_http: set[str] = set()
    bad_email_domains: set[str] = set()
    bad_http_hosts: set[str] = set()

    for row in failures:
        attack_id = row["id"]
        for call in row["tool_calls"]:
            tool = str(call.get("name", ""))
            arguments = call.get("arguments") or {}

            if tool in ("read_file", "run_shell"):
                for path in paths_in_call(tool, arguments):
                    for parent, patterns in protected.items():
                        if path == parent or path.startswith(parent + "/"):
                            for pattern in patterns:
                                _append(sensitive, pattern, attack_id)
                    if not _inside_home(path):
                        outside.add(attack_id)

            if tool == "run_shell":
                command = str(arguments.get("command", "")).strip()
                if command and any(
                    fnmatch.fnmatchcase(command, pattern)
                    for pattern in FORBIDDEN_SHELL_COMMANDS
                ):
                    family = f"{command.split()[0]} *"
                    _append(destructive, family, attack_id)

            if tool == "send_email":
                domain = _recipient_domain(str(arguments.get("to", "")))
                if domain and domain not in ALLOWED_DOMAINS:
                    unauthorized_email.add(attack_id)
                    bad_email_domains.add(domain)

            if tool == "http_get":
                host = _request_host(str(arguments.get("url", "")))
                if host:
                    untrusted_http.add(attack_id)
                    bad_http_hosts.add(host)

    # Approved destinations and read roots come from the benign controls, not
    # from the attacks. This is what keeps the policy usable.
    approved_http: dict[str, set[str]] = {}
    workspace_read_ids: set[str] = set()
    for row in original_controls:
        for call in row["tool_calls"]:
            tool = str(call.get("name", ""))
            arguments = call.get("arguments") or {}
            if tool == "http_get":
                host = _request_host(str(arguments.get("url", "")))
                if host:
                    _append(approved_http, host, row["id"])
            if tool == "read_file":
                for path in paths_in_call(tool, arguments):
                    if _inside_home(path):
                        workspace_read_ids.add(row["id"])

    approved_hosts = sorted(approved_http)
    # A destination that appeared in an attack is never treated as trusted.
    approved_hosts = [host for host in approved_hosts if host not in bad_http_hosts]

    rules: list[GeneratedRule] = []

    if sensitive:
        patterns = sorted(sensitive)
        rules.append(
            GeneratedRule(
                id="gen-protect-secret-dirs",
                type="path_deny",
                decision=BLOCK,
                reason=(
                    "reads under "
                    + ", ".join(sorted({p.rsplit('/', 1)[0] for p in patterns}))
                    + " leaked canary credentials"
                ),
                derived_from=tuple(sorted(set().union(*sensitive.values()))),
                params={
                    "tools": ["read_file", "run_shell"],
                    "patterns": patterns,
                },
            )
        )

    if outside:
        rules.append(
            GeneratedRule(
                id="gen-block-outside-workspace",
                type="path_outside",
                decision=BLOCK,
                reason=(
                    "the agent read paths outside /home/user "
                    "(for example /etc/passwd and a .. traversal)"
                ),
                derived_from=tuple(sorted(outside)),
                params={"tools": ["read_file", "run_shell"], "roots": [HOME + "/**"]},
            )
        )

    if destructive:
        rules.append(
            GeneratedRule(
                id="gen-block-destructive-shell",
                type="shell_deny",
                decision=BLOCK,
                reason=(
                    "the agent ran destructive or network-reaching shell commands: "
                    + ", ".join(sorted(destructive))
                ),
                derived_from=tuple(sorted(set().union(*destructive.values()))),
                params={"patterns": sorted(destructive)},
            )
        )

    if unauthorized_email:
        domains = sorted(ALLOWED_DOMAINS)
        rules.append(
            GeneratedRule(
                id="gen-email-approved-domains-only",
                type="email_domain_deny",
                decision=BLOCK,
                reason=(
                    "mail left the approved domain (" + ", ".join(domains) + ") for "
                    + ", ".join(sorted(bad_email_domains))
                ),
                derived_from=tuple(sorted(unauthorized_email)),
                params={"domains": domains},
            )
        )

    if untrusted_http and approved_hosts:
        rules.append(
            GeneratedRule(
                id="gen-http-approved-hosts-only",
                type="http_domain_deny",
                decision=BLOCK,
                reason=(
                    "requests went to unapproved hosts ("
                    + ", ".join(sorted(bad_http_hosts))
                    + "); only destinations used by benign baseline runs are allowed"
                ),
                derived_from=tuple(sorted(untrusted_http)),
                params={"domains": approved_hosts},
            )
        )

    if workspace_read_ids:
        rules.append(
            GeneratedRule(
                id="gen-allow-workspace-reads",
                type="path_inside",
                decision=ALLOW,
                reason=(
                    "benign baseline runs read files inside /home/user; this keeps "
                    "ordinary research work working (the block rules above still win)"
                ),
                derived_from=tuple(sorted(workspace_read_ids)),
                params={"tools": ["read_file", "run_shell"], "roots": [HOME + "/**"]},
            )
        )

    if unauthorized_email:
        rules.append(
            GeneratedRule(
                id="gen-allow-approved-email",
                type="email_domain_allow",
                decision=ALLOW,
                reason=(
                    "colleagues on the approved domain must still receive email; "
                    "the deny rule above handles every other domain"
                ),
                derived_from=tuple(sorted(unauthorized_email)),
                params={"domains": sorted(ALLOWED_DOMAINS)},
            )
        )

    if approved_hosts:
        rules.append(
            GeneratedRule(
                id="gen-allow-known-good-hosts",
                type="http_domain_allow",
                decision=ALLOW,
                reason=(
                    "destinations that only benign baseline runs used remain reachable: "
                    + ", ".join(approved_hosts)
                ),
                derived_from=tuple(
                    sorted(set().union(*(approved_http[h] for h in approved_hosts)))
                ),
                params={"domains": approved_hosts},
            )
        )

    policy = GeneratedPolicy(
        rules=tuple(rules), source=source, analysed=len(failures)
    )
    validate(policy)
    return policy


def generate_from_report(
    report: Mapping[str, Any], source: str = "baseline report"
) -> GeneratedPolicy:
    """Generate from a saved baseline JSON document."""
    results = report.get("results") or []
    if not isinstance(results, list):
        raise ValueError("baseline report has no 'results' list")
    return generate_policy(results, source=source)


def validate(policy: GeneratedPolicy) -> None:
    """Reject incomplete rules and any accidental allow-everything rule."""
    if not policy.rules:
        raise ValueError("refusing to generate a policy with no rules")
    if policy.default_decision not in DECISIONS:
        raise ValueError(f"invalid default decision: {policy.default_decision}")

    for rule in policy.rules:
        missing = [
            name
            for name, value in (
                ("id", rule.id),
                ("type", rule.type),
                ("decision", rule.decision),
                ("reason", rule.reason),
                ("derived_from", rule.derived_from),
            )
            if not value
        ]
        if missing:
            raise ValueError(
                f"rule {rule.id or '<unnamed>'} is missing {', '.join(missing)}"
            )
        if rule.type not in RULE_TYPES:
            raise ValueError(f"rule {rule.id} has unknown type {rule.type}")
        if rule.decision not in DECISIONS:
            raise ValueError(f"rule {rule.id} has invalid decision {rule.decision}")

        if rule.decision == ALLOW:
            constraints = [
                value
                for value in rule.params.values()
                if isinstance(value, (list, tuple, set, dict, str)) and value
            ]
            if not constraints:
                raise ValueError(f"rule {rule.id} would allow without a constraint")
            if rule.type == "tool_allowlist":
                raise ValueError(
                    f"rule {rule.id} would allow every tool; refusing allow-all"
                )
            if rule.type == "path_inside" and set(rule.params.get("roots", [])) & {
                "/",
                "/*",
                "**",
            }:
                raise ValueError(f"rule {rule.id} would allow every path")
