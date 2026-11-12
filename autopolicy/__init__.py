"""Auto-policy: turn a policy-free baseline's failures into a suggested policy."""

from __future__ import annotations

from autopolicy.generate import (
    DEFAULT_OUTPUT,
    GeneratedPolicy,
    GeneratedRule,
    generate_from_report,
    generate_policy,
    validate,
)

__all__ = [
    "DEFAULT_OUTPUT",
    "GeneratedPolicy",
    "GeneratedRule",
    "generate_from_report",
    "generate_policy",
    "validate",
]
