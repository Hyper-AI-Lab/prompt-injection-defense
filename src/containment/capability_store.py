"""Pluggable one-use capability consume ledger (process-local or shared)."""

from __future__ import annotations

import sqlite3
import threading
import time
from typing import Protocol, runtime_checkable


@runtime_checkable
class CapabilityConsumeStore(Protocol):
    def try_consume(self, token_id: str, *, expiry_unix: float) -> bool:
        """Atomically mark token_id consumed.

        Return True if this call won (first consume), False if already used.
        Implementations may use expiry_unix for TTL/GC.
        """
        ...


class MemoryConsumeStore:
    """Process-local default; thread-safe."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._consumed: dict[str, float] = {}

    def try_consume(self, token_id: str, *, expiry_unix: float) -> bool:
        with self._lock:
            if token_id in self._consumed:
                return False
            self._consumed[token_id] = expiry_unix
            return True

    def purge_expired(self, now: float | None = None) -> int:
        stamp = time.time() if now is None else now
        with self._lock:
            dead = [k for k, exp in self._consumed.items() if stamp > exp]
            for k in dead:
                del self._consumed[k]
            return len(dead)


class SqliteConsumeStore:
    """Shared-file consume ledger; UNIQUE insert = first consume wins."""

    def __init__(self, path: str) -> None:
        self._path = path
        with sqlite3.connect(path) as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS consumed ("
                "token_id TEXT PRIMARY KEY, expiry_unix REAL NOT NULL)"
            )

    def try_consume(self, token_id: str, *, expiry_unix: float) -> bool:
        try:
            with sqlite3.connect(self._path) as db:
                db.execute(
                    "INSERT INTO consumed(token_id, expiry_unix) VALUES (?, ?)",
                    (token_id, expiry_unix),
                )
            return True
        except sqlite3.IntegrityError:
            return False
