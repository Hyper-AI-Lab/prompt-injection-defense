"""Rate / spend gate hook for privileged tool calls."""

from __future__ import annotations

import threading
import time
from typing import Protocol, runtime_checkable


@runtime_checkable
class RateLimitGate(Protocol):
    def allow(self, tool: str, *, cost: float = 1.0) -> bool:
        """Return True if ``cost`` tokens may be spent for ``tool``.

        False means deny (insufficient budget).
        """
        ...


class TokenBucketRateLimit:
    """Thread-safe token bucket shared across tools.

    ``rate`` is tokens replenished per second; ``capacity`` is the max
    burst size. Starts full. ``tool`` is accepted for Protocol compatibility
    but does not partition buckets in this implementation.
    """

    def __init__(self, rate: float, capacity: float) -> None:
        if rate < 0 or capacity < 0:
            raise ValueError("rate and capacity must be non-negative")
        self._rate = float(rate)
        self._capacity = float(capacity)
        self._tokens = float(capacity)
        self._updated = time.monotonic()
        self._lock = threading.Lock()

    def allow(self, tool: str, *, cost: float = 1.0) -> bool:
        del tool  # shared bucket; tool reserved for future per-tool caps
        if cost < 0:
            raise ValueError("cost must be non-negative")
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._updated
            self._updated = now
            self._tokens = min(
                self._capacity, self._tokens + elapsed * self._rate
            )
            if self._tokens < cost:
                return False
            self._tokens -= cost
            return True
