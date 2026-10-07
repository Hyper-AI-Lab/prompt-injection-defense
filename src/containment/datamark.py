"""Datamarking / spotlighting helpers for untrusted text.

Inserts a per-call random marker throughout the text so a privileged model
can distinguish data from instructions. ``unwrap`` restores the original
when given the matching marker.
"""

from __future__ import annotations

import secrets
import string
from dataclasses import dataclass

_MARKER_ALPHABET = string.ascii_letters + string.digits


@dataclass(frozen=True, slots=True)
class DatamarkedText:
    """Marked payload plus the unique marker used for this call."""

    text: str
    marker: str
    original_length: int

    def __post_init__(self) -> None:
        if not self.marker or not str(self.marker).strip():
            raise ValueError("marker must be a non-empty string")
        if self.original_length < 0:
            raise ValueError("original_length must be >= 0")


def generate_marker(*, length: int = 12) -> str:
    """Return a cryptographically strong random marker unique per call."""
    if length < 8:
        raise ValueError("marker length must be >= 8")
    return "DM_" + "".join(secrets.choice(_MARKER_ALPHABET) for _ in range(length))


def mark(
    text: str,
    *,
    marker: str | None = None,
    every_n_chars: int = 32,
) -> DatamarkedText:
    """Insert ``marker`` throughout ``text`` (between chunks).

    Markers are placed at chunk boundaries and as begin/end sentinels so the
    wrapper is unambiguous for ``unwrap``.
    """
    if not isinstance(text, str):
        raise TypeError("text must be str")
    if every_n_chars < 1:
        raise ValueError("every_n_chars must be >= 1")
    token = marker if marker is not None else generate_marker()
    if not token or not str(token).strip():
        raise ValueError("marker must be a non-empty string")
    if token in text:
        # Extremely unlikely with random markers; refuse rather than corrupt.
        raise ValueError("marker collides with content; generate a new marker")

    begin = f"<{token}>"
    end = f"</{token}>"
    if not text:
        marked = f"{begin}{end}"
        return DatamarkedText(text=marked, marker=token, original_length=0)

    parts: list[str] = [begin]
    for i in range(0, len(text), every_n_chars):
        chunk = text[i : i + every_n_chars]
        parts.append(chunk)
        if i + every_n_chars < len(text):
            parts.append(f"|{token}|")
    parts.append(end)
    return DatamarkedText(
        text="".join(parts),
        marker=token,
        original_length=len(text),
    )


def unwrap(marked_text: str, marker: str) -> str:
    """Remove datamark sentinels/separators for ``marker``; restore original."""
    if not isinstance(marked_text, str):
        raise TypeError("marked_text must be str")
    if not marker or not str(marker).strip():
        raise ValueError("marker must be a non-empty string")

    begin = f"<{marker}>"
    end = f"</{marker}>"
    sep = f"|{marker}|"

    if not (marked_text.startswith(begin) and marked_text.endswith(end)):
        raise ValueError("marked_text missing begin/end sentinels for marker")

    body = marked_text[len(begin) : -len(end)]
    if sep in body:
        return "".join(body.split(sep))
    return body
