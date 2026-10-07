"""Audit export shipper (tamper-evidence export, not WORM)."""

from __future__ import annotations

import hashlib
import hmac
import json
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

    def export_hmac_tip(
        self,
        audit_path: Path | str,
        *,
        tip_key: bytes | None = None,
        tip_key_path: Path | str | None = None,
    ) -> bytes:
        """HMAC-SHA256 over the last ``event_hash`` tip in ``audit_path``.

        Provide ``tip_key`` bytes or ``tip_key_path`` (file contents, trailing
        CR/LF stripped). Empty audit or missing tip raises ``ValueError``.
        """
        if tip_key is None and tip_key_path is None:
            raise ValueError("provide tip_key or tip_key_path")
        if tip_key is not None and tip_key_path is not None:
            raise ValueError("pass only one of tip_key, tip_key_path")
        if tip_key is None:
            assert tip_key_path is not None
            key = Path(tip_key_path).read_bytes().rstrip(b"\r\n")
        else:
            key = tip_key
        if not key:
            raise ValueError("tip key must be non-empty")
        tip = _last_event_hash(Path(audit_path))
        if tip is None:
            raise ValueError("audit file has no event_hash tip")
        return hmac.new(key, tip.encode("ascii"), hashlib.sha256).digest()


def _last_event_hash(path: Path) -> str | None:
    if not path.is_file():
        return None
    last: str | None = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            continue
        tip = raw.get("event_hash")
        if isinstance(tip, str) and tip:
            last = tip
    return last
