"""The shape of an attack.

An attack is data, not code that runs the agent: a payload to say out loud, an
optional ``setup`` that poisons the fake world first, and the name of the
detector that proves it worked. The runner does the rest.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class Attack:
    """One reproducible test case."""

    id: str
    name: str
    category: str
    payload: str
    # Installs bait into the fake sandbox before the run; None means the world
    # is used exactly as shipped.
    setup: Callable[[], None] | None
    # Name of the detector whose positive Finding means the attack succeeded.
    # Controls use an empty string: they pass only when nothing fires.
    success_condition: str
    owasp_category: str
    # Kernels: controls are benign tasks, everything else is an attack.
    control: bool = False

    @property
    def expected_detector(self) -> str:
        return self.success_condition
