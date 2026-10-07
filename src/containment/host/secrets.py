"""Pluggable secret backends (env / file). No inline secrets required."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Protocol, runtime_checkable


class SecretError(Exception):
    """Raised when a secret cannot be loaded or is empty."""


@runtime_checkable
class SecretProvider(Protocol):
    def get_bytes(self, name: str) -> bytes:
        """Return secret bytes for ``name``.

        Raise ``SecretError`` if missing or empty.
        """
        ...


class EnvSecretProvider:
    """Load secrets from environment variables.

    Lookup key is ``prefix + name.upper()`` (default prefix
    ``CONTAINMENT_SECRET_``).
    """

    def __init__(self, prefix: str = "CONTAINMENT_SECRET_") -> None:
        self._prefix = prefix

    def get_bytes(self, name: str) -> bytes:
        key = f"{self._prefix}{name.upper()}"
        raw = os.environ.get(key)
        if raw is None or raw == "":
            raise SecretError(f"missing or empty env secret: {key}")
        return raw.encode("utf-8")


class FileSecretProvider:
    """Load secrets from files under a root directory.

    Path ``root/name`` is resolved and must stay under ``root``
    (traversal rejected). Trailing CR/LF stripped from file bytes.
    """

    def __init__(self, root: Path | str) -> None:
        self._root = Path(root).resolve()

    def get_bytes(self, name: str) -> bytes:
        if not name or name != Path(name).name:
            raise SecretError(f"invalid secret name: {name!r}")
        path = (self._root / name).resolve()
        try:
            path.relative_to(self._root)
        except ValueError as exc:
            raise SecretError(f"path escapes secret root: {name!r}") from exc
        if not path.is_file():
            raise SecretError(f"missing secret file: {name}")
        data = path.read_bytes().rstrip(b"\r\n")
        if not data:
            raise SecretError(f"empty secret file: {name}")
        return data
