"""Security labels for integrity, confidentiality, and provenance."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Integrity = Literal["trusted", "untrusted"]
Confidentiality = Literal["public", "private", "identity"]

_VALID_INTEGRITY = frozenset({"trusted", "untrusted"})
_VALID_CONFIDENTIALITY = frozenset({"public", "private", "identity"})


@dataclass(frozen=True, slots=True)
class SecurityLabel:
    """Immutable taint / provenance label attached to data.

    Illegal states are rejected in ``__post_init__`` so callers cannot
    construct a label with an unknown integrity or empty provenance fields.
    """

    integrity: Integrity
    confidentiality: Confidentiality
    source: str
    task_id: str
    transformations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.integrity not in _VALID_INTEGRITY:
            raise ValueError(
                f"integrity must be one of {sorted(_VALID_INTEGRITY)}, "
                f"got {self.integrity!r}"
            )
        if self.confidentiality not in _VALID_CONFIDENTIALITY:
            raise ValueError(
                f"confidentiality must be one of "
                f"{sorted(_VALID_CONFIDENTIALITY)}, "
                f"got {self.confidentiality!r}"
            )
        if not self.source or not str(self.source).strip():
            raise ValueError("source must be a non-empty string")
        if not self.task_id or not str(self.task_id).strip():
            raise ValueError("task_id must be a non-empty string")
        if not isinstance(self.transformations, tuple):
            raise TypeError("transformations must be a tuple[str, ...]")
        for item in self.transformations:
            if not isinstance(item, str):
                raise TypeError(
                    f"transformations items must be str, got {type(item).__name__}"
                )
