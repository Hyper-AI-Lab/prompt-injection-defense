"""Locate data that ships with containment (default policies, eval fixtures).

A built wheel carries them under ``containment/_data/``; a source checkout
(editable install) keeps them at the repository root. Packaged data wins.
"""

from __future__ import annotations

from pathlib import Path

_PKG = Path(__file__).resolve().parent
_PACKAGED = _PKG / "_data"
_CHECKOUT = _PKG.parents[1]


def data_path(*parts: str) -> Path:
    """Path to ``policies/...`` or ``fixtures/...`` for this install.

    Returns the packaged path when it exists, else the checkout path (which may
    not exist either; callers raise their own ``FileNotFoundError``).
    """
    packaged = _PACKAGED.joinpath(*parts)
    if packaged.exists():
        return packaged
    return _CHECKOUT.joinpath(*parts)


def default_policy_path() -> Path:
    """``policies/default_deny.yaml`` for this install."""
    return data_path("policies", "default_deny.yaml")


def default_fixtures_root() -> Path:
    """``fixtures/`` (attacks + benign eval corpus) for this install."""
    return data_path("fixtures")


__all__ = ["data_path", "default_fixtures_root", "default_policy_path"]
