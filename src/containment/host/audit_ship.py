"""Audit export shipper (tamper-evidence export, not WORM)."""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Protocol, runtime_checkable


@runtime_checkable
class AuditShipper(Protocol):
    def ship_file(self, path: Path) -> None:
        """Copy/append JSONL audit lines from ``path`` to the ship destination.

        Destinations may preserve or re-hash chains; this interface is export
        only (tamper evidence), not WORM storage.
        """
        ...


class FileAuditShipper:
    """Append JSONL lines from a source audit file to a destination path.

    Creates parent directories as needed. Empty source lines are skipped.
    Thread-safe for concurrent ship_file calls against the same destination.
    """

    def __init__(self, destination: Path | str) -> None:
        self._destination = Path(destination)
        self._lock = threading.Lock()

    def ship_file(self, path: Path) -> None:
        source = Path(path)
        text = source.read_text(encoding="utf-8")
        lines = [ln for ln in text.splitlines() if ln.strip()]
        if not lines:
            return
        with self._lock:
            self._destination.parent.mkdir(parents=True, exist_ok=True)
            with self._destination.open("a", encoding="utf-8") as fh:
                for ln in lines:
                    fh.write(ln + "\n")
