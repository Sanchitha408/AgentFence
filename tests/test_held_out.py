"""The held-out split is real, complete, and invisible to the generator."""

from __future__ import annotations

from collections import Counter

from attacks import (
    ALL_ATTACKS,
    HELD_OUT_ATTACKS,
    HELD_OUT_CONTROLS,
    ORIGINAL_ATTACKS,
    ORIGINAL_CONTROLS,
)
from attacks.library import DIRECT, EXFIL, INDIRECT, MISUSE


def test_held_out_counts_and_categories() -> None:
    assert len(HELD_OUT_ATTACKS) == 6
    assert len(HELD_OUT_CONTROLS) == 2

    counts = Counter(attack.category for attack in HELD_OUT_ATTACKS)
    assert counts[DIRECT] >= 1
    assert counts[INDIRECT] >= 1
    assert counts[MISUSE] >= 1
    assert counts[EXFIL] >= 1


def test_held_out_records_are_marked_and_original_records_are_not() -> None:
    for attack in HELD_OUT_ATTACKS + HELD_OUT_CONTROLS:
        assert attack.held_out is True, attack.id
    for attack in ORIGINAL_ATTACKS + ORIGINAL_CONTROLS:
        assert attack.held_out is False, attack.id


def test_held_out_ids_and_payloads_are_new() -> None:
    original_ids = {attack.id for attack in ORIGINAL_ATTACKS}
    original_payloads = {attack.payload for attack in ORIGINAL_ATTACKS}
    held_out = HELD_OUT_ATTACKS

    assert not (original_ids & {attack.id for attack in held_out})
    assert not (original_payloads & {attack.payload for attack in held_out})

    # The new set uses destinations the original attacks did not.
    from attacks.library import HELD_POISONED_BRIEF

    destinations = " ".join(attack.payload for attack in held_out) + HELD_POISONED_BRIEF
    assert "leak.example" in destinations
    assert "build.example" in destinations
    assert "drop.example" in destinations
    assert "transfer.example" in destinations


def test_held_out_controls_are_benign_and_separate() -> None:
    non_control_ids = {attack.id for attack in ALL_ATTACKS if not attack.control}
    for control in HELD_OUT_CONTROLS:
        assert control.control is True
        assert control.success_condition == ""
        assert control.id not in non_control_ids


def test_held_out_attacks_use_different_paths() -> None:
    held_out_setups = [attack.id for attack in HELD_OUT_ATTACKS if attack.setup]
    assert "held-indirect-01" in held_out_setups
    assert "held-indirect-02" in held_out_setups

    # The two indirect held-out attacks plant files the original set never uses.
    from attacks.library import HELD_POISONED_MEETING

    by_id = {attack.id: attack for attack in HELD_OUT_ATTACKS}
    assert "vendor-brief.txt" in by_id["held-indirect-01"].payload
    assert "meeting-notes.md" in by_id["held-indirect-02"].payload
    assert ".config/backup.txt" in HELD_POISONED_MEETING
