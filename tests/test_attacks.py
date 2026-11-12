"""The attack library is complete, consistent, and wired to real detectors."""

from __future__ import annotations

from attacks import (
    ALL_ATTACKS,
    ATTACKS,
    CONTROLS,
    HELD_OUT_ATTACKS,
    ORIGINAL_ATTACKS,
    by_id,
)
from detectors import DETECTORS


def test_library_size() -> None:
    assert len(ORIGINAL_ATTACKS) == 12
    assert len(HELD_OUT_ATTACKS) == 6
    assert len(ATTACKS) == 18
    assert len(CONTROLS) == 5


def test_categories_have_the_expected_counts() -> None:
    counts: dict[str, int] = {}
    for attack in ATTACKS:
        counts[attack.category] = counts.get(attack.category, 0) + 1

    assert counts == {
        "direct_injection": 4,
        "indirect_injection": 6,
        "tool_misuse": 4,
        "exfiltration": 4,
    }


def test_ids_are_unique() -> None:
    ids = [attack.id for attack in ALL_ATTACKS]
    assert len(set(ids)) == len(ids)


def test_success_conditions_point_at_real_detectors() -> None:
    for attack in ATTACKS:
        assert attack.success_condition in DETECTORS, attack.id
    for control in CONTROLS:
        assert control.success_condition == ""
        assert control.control is True


def test_every_attack_is_fully_described() -> None:
    for attack in ALL_ATTACKS:
        assert attack.id and attack.name and attack.payload
        assert attack.owasp_category


def test_indirect_attacks_all_plant_their_own_bait() -> None:
    for attack in ATTACKS:
        if attack.category == "indirect_injection":
            # indirect-01 relies on the inbox that ships poisoned.
            if attack.id != "indirect-01":
                assert attack.setup is not None, attack.id


def test_by_id_and_unknown_id() -> None:
    assert by_id("direct-01").category == "direct_injection"

    try:
        by_id("does-not-exist")
    except KeyError:
        pass
    else:  # pragma: no cover - the assertion below is the real check
        raise AssertionError("by_id should raise KeyError for unknown ids")
