"""Datamarking tests (step 10)."""

from __future__ import annotations

import pytest

from containment.datamark import DatamarkedText, generate_marker, mark, unwrap


def test_round_trip_integrity() -> None:
    original = "The quarterly revenue was $1.2M. Schedule a review for Friday."
    wrapped = mark(original, every_n_chars=8)
    assert isinstance(wrapped, DatamarkedText)
    assert wrapped.marker in wrapped.text
    assert original not in wrapped.text or len(original) < 8
    restored = unwrap(wrapped.text, wrapped.marker)
    assert restored == original
    assert wrapped.original_length == len(original)


def test_marker_uniqueness_per_call() -> None:
    markers = {mark("same text").marker for _ in range(30)}
    assert len(markers) == 30


def test_generate_marker_prefix_and_length() -> None:
    m = generate_marker(length=16)
    assert m.startswith("DM_")
    assert len(m) == 3 + 16


def test_empty_text_round_trip() -> None:
    wrapped = mark("")
    assert unwrap(wrapped.text, wrapped.marker) == ""


def test_custom_marker() -> None:
    wrapped = mark("abcdef", marker="DM_CUSTOM01", every_n_chars=2)
    assert wrapped.marker == "DM_CUSTOM01"
    assert unwrap(wrapped.text, "DM_CUSTOM01") == "abcdef"


def test_unwrap_wrong_marker_fails() -> None:
    wrapped = mark("hello world")
    with pytest.raises(ValueError, match="sentinels"):
        unwrap(wrapped.text, "DM_WRONGMARKER")


def test_collision_refused() -> None:
    with pytest.raises(ValueError, match="collides"):
        mark("keep DM_COLLIDE01 inside", marker="DM_COLLIDE01")


def test_long_text_many_insertions() -> None:
    original = "x" * 200
    wrapped = mark(original, every_n_chars=10)
    assert wrapped.text.count(f"|{wrapped.marker}|") == 19
    assert unwrap(wrapped.text, wrapped.marker) == original
