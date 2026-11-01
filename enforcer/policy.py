"""The policy engine: decide allow / block / ask before a tool call runs.

Policy is YAML so a human can read and review it. Rules are evaluated **in
order**, first match wins; if nothing matches, ``default_decision`` applies
(which is ``block`` in the shipped policy, so the safe case is the default).

Every rule needs an ``id`` and a ``reason`` so the audit log can explain itself.
Each ``type`` is a condition, not a verdict - the rule's ``decision`` decides:

=====================  ======================================================
type                   matches when...
=====================  ======================================================
tool_allowlist         the tool is not one of ``tools``
path_deny              a path in the call matches one of ``patterns``
path_outside           a path in the call is outside every glob in ``roots``
path_inside            every path in the call is inside one of ``roots``
shell_deny             the command matches one of ``patterns``
shell_allow            the command matches one of ``patterns``
email_domain_allow     a recipient's domain matches ``domains``
email_domain_deny      a recipient's domain does not match ``domains``
http_domain_allow      the request host matches one of ``domains``
http_domain_deny       the request host does not match ``domains``
=====================  ======================================================

Paths are normalised with ``sandbox.normalize_path`` before matching, so
``/home/user/../../etc/passwd`` is compared as ``/etc/passwd``.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse

import yaml

from sample_agent import sandbox

ALLOW = "allow"
BLOCK = "block"
ASK = "ask"
DECISIONS = (ALLOW, BLOCK, ASK)

RULE_TYPES = (
    "tool_allowlist",
    "path_deny",
    "path_outside",
    "path_inside",
    "shell_deny",
    "shell_allow",
    "email_domain_allow",
    "email_domain_deny",
    "http_domain_allow",
    "http_domain_deny",
)


@dataclass(frozen=True)
class Decision:
    """The verdict on one tool call, with the rule that produced it."""

    decision: str
    rule_id: str
    reason: str

    @property
    def allowed(self) -> bool:
        return self.decision == ALLOW


@dataclass(frozen=True)
class Rule:
    """One ordered policy rule."""

    id: str
    type: str
    decision: str
    reason: str
    params: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Policy:
    """A parsed policy file, ready to evaluate calls."""

    name: str
    default_decision: str
    default_reason: str
    rules: tuple[Rule, ...]

    def evaluate(
        self, tool: str, arguments: Mapping[str, Any] | None = None
    ) -> Decision:
        """Return the first matching rule's decision, else the default."""
        arguments = dict(arguments or {})
        for rule in self.rules:
            if _MATCHERS[rule.type](rule, tool, arguments):
                return Decision(rule.decision, rule.id, rule.reason)
        return Decision(self.default_decision, "default-deny", self.default_reason)


# -- reading the call --------------------------------------------------------


def paths_in_call(tool: str, arguments: Mapping[str, Any]) -> list[str]:
    """Every path a call would touch, normalised.

    ``read_file`` has an explicit path. For ``run_shell`` we look at tokens that
    look like paths, because ``cat /etc/passwd`` would otherwise bypass the
    file-rule checks.
    """
    raw: list[str] = []
    if tool == "read_file":
        raw = [str(arguments.get("path", ""))]
    elif tool == "run_shell":
        command = str(arguments.get("command", ""))
        raw = re.findall(r"(?:^|\s)([~./][^\s;|&<>'\"]*)", command)

    normalized = [sandbox.normalize_path(item) for item in raw if item]
    return [path for path in normalized if path]


def _tools_of(rule: Rule) -> list[str]:
    return [str(tool) for tool in rule.params.get("tools", [])]


def _applies(rule: Rule, tool: str) -> bool:
    tools = _tools_of(rule)
    return not tools or tool in tools


def _patterns(rule: Rule, key: str = "patterns") -> list[str]:
    return [str(pattern) for pattern in rule.params.get(key, [])]


def _glob_any(value: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(value, pattern) for pattern in patterns)


def _domain_any(domain: str, patterns: list[str]) -> bool:
    return bool(domain) and _glob_any(domain, [p.lower() for p in patterns])


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


# -- matchers ----------------------------------------------------------------


def _match_tool_allowlist(rule: Rule, tool: str, arguments: Mapping[str, Any]) -> bool:
    return tool not in _tools_of(rule)


def _match_path_deny(rule: Rule, tool: str, arguments: Mapping[str, Any]) -> bool:
    if not _applies(rule, tool):
        return False
    patterns = [pattern.lower() for pattern in _patterns(rule)]
    return any(
        _glob_any(path.lower(), patterns) for path in paths_in_call(tool, arguments)
    )


def _under_any(path: str, roots: list[str]) -> bool:
    """True if ``path`` is one of ``roots`` or inside it.

    A root of ``/home/user/**`` covers ``/home/user`` itself as well as every
    file below it, which is what a reader expects from that glob.
    """
    for root in roots:
        if _glob_any(path, [root]):
            return True
        if root.endswith("/**") and path == root[:-3]:
            return True
    return False


def _match_path_outside(rule: Rule, tool: str, arguments: Mapping[str, Any]) -> bool:
    if not _applies(rule, tool):
        return False
    roots = _patterns(rule, "roots")
    paths = paths_in_call(tool, arguments)
    if not paths:
        return False
    return any(not _under_any(path, roots) for path in paths)


def _match_path_inside(rule: Rule, tool: str, arguments: Mapping[str, Any]) -> bool:
    if not _applies(rule, tool):
        return False
    roots = _patterns(rule, "roots")
    paths = paths_in_call(tool, arguments)
    if not paths:
        return False
    return all(_under_any(path, roots) for path in paths)


def _match_shell(rule: Rule, tool: str, arguments: Mapping[str, Any]) -> bool:
    if tool != "run_shell":
        return False
    command = str(arguments.get("command", "")).strip()
    return _glob_any(command, _patterns(rule))


def _match_email_allow(rule: Rule, tool: str, arguments: Mapping[str, Any]) -> bool:
    if tool != "send_email":
        return False
    domains = _patterns(rule, "domains")
    return _domain_any(_recipient_domain(str(arguments.get("to", ""))), domains)


def _match_email_deny(rule: Rule, tool: str, arguments: Mapping[str, Any]) -> bool:
    if tool != "send_email":
        return False
    domains = _patterns(rule, "domains")
    return not _domain_any(_recipient_domain(str(arguments.get("to", ""))), domains)


def _match_http_allow(rule: Rule, tool: str, arguments: Mapping[str, Any]) -> bool:
    if tool != "http_get":
        return False
    domains = _patterns(rule, "domains")
    return _domain_any(_request_host(str(arguments.get("url", ""))), domains)


def _match_http_deny(rule: Rule, tool: str, arguments: Mapping[str, Any]) -> bool:
    if tool != "http_get":
        return False
    domains = _patterns(rule, "domains")
    return not _domain_any(_request_host(str(arguments.get("url", ""))), domains)


_MATCHERS = {
    "tool_allowlist": _match_tool_allowlist,
    "path_deny": _match_path_deny,
    "path_outside": _match_path_outside,
    "path_inside": _match_path_inside,
    "shell_deny": _match_shell,
    "shell_allow": _match_shell,
    "email_domain_allow": _match_email_allow,
    "email_domain_deny": _match_email_deny,
    "http_domain_allow": _match_http_allow,
    "http_domain_deny": _match_http_deny,
}


# -- loading -----------------------------------------------------------------


def load_policy(path: str | Path) -> Policy:
    """Read and validate a YAML policy file."""
    source = Path(path)
    try:
        data = yaml.safe_load(source.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ValueError(f"{source}: not valid YAML: {exc}") from exc
    except OSError as exc:
        raise ValueError(f"{source}: cannot read policy: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError(f"{source}: policy must be a mapping")

    raw_rules = data.get("rules") or []
    if not isinstance(raw_rules, list) or not raw_rules:
        raise ValueError(f"{source}: policy needs a non-empty 'rules' list")

    default_decision = str(data.get("default_decision", BLOCK)).lower()
    if default_decision not in DECISIONS:
        raise ValueError(
            f"{source}: default_decision must be one of {', '.join(DECISIONS)}"
        )

    rules: list[Rule] = []
    for index, raw in enumerate(raw_rules, start=1):
        if not isinstance(raw, dict):
            raise ValueError(f"{source}: rule #{index} must be a mapping")
        missing = [
            key for key in ("id", "type", "decision", "reason") if not raw.get(key)
        ]
        if missing:
            raise ValueError(f"{source}: rule #{index} is missing {', '.join(missing)}")

        rule_type = str(raw["type"])
        if rule_type not in RULE_TYPES:
            raise ValueError(
                f"{source}: rule '{raw['id']}' has unknown type '{rule_type}'"
            )

        decision = str(raw["decision"]).lower()
        if decision not in DECISIONS:
            raise ValueError(
                f"{source}: rule '{raw['id']}' decision must be one of "
                f"{', '.join(DECISIONS)}"
            )

        params = {
            key: value
            for key, value in raw.items()
            if key not in ("id", "type", "decision", "reason")
        }
        rules.append(
            Rule(
                id=str(raw["id"]),
                type=rule_type,
                decision=decision,
                reason=str(raw["reason"]),
                params=params,
            )
        )

    return Policy(
        name=str(data.get("name", source.stem)),
        default_decision=default_decision,
        default_reason=str(
            data.get("default_reason", "deny by default: no rule allowed this call")
        ),
        rules=tuple(rules),
    )
