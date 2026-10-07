"""Optional Redis backend for CapabilityConsumeStore (``[redis]`` extra).

Import is safe without the redis package. Constructing from ``url=`` lazy-imports
redis; inject ``client=`` for tests or custom clients.
"""

from __future__ import annotations

import math
import time
from typing import Any


class CapabilityStoreError(RuntimeError):
    """Consume-store outage or misconfiguration; callers must fail closed."""


class RedisConsumeStore:
    """Shared Redis consume ledger; ``SET key NX EX ttl`` = first consume wins.

    On Redis connection/operation errors, raises ``CapabilityStoreError`` so the
    broker denies execute (fail closed). Already-consumed keys return False.
    Memory/Sqlite backends never raise on the happy path; Redis outage must not
    be confused with already-used (which would also deny, but with the wrong
    error class and no signal to operators).
    """

    def __init__(
        self,
        url: str | None = None,
        *,
        client: Any | None = None,
        key_prefix: str = "containment:cap:",
        now: float | None = None,
    ) -> None:
        if client is None and url is None:
            raise CapabilityStoreError(
                "RedisConsumeStore requires url= or client="
            )
        if client is not None:
            self._client = client
        else:
            self._client = self._client_from_url(url)  # type: ignore[arg-type]
        self._key_prefix = key_prefix
        self._now = now

    @staticmethod
    def _client_from_url(url: str) -> Any:
        try:
            import redis
        except ImportError as exc:
            raise CapabilityStoreError(
                "RedisConsumeStore requires the redis package; "
                'install with: pip install "containment[redis]"'
            ) from exc
        try:
            return redis.Redis.from_url(url, decode_responses=True)
        except Exception as exc:
            raise CapabilityStoreError(
                f"Redis client init failed: {exc}"
            ) from exc

    def _clock(self) -> float:
        return time.time() if self._now is None else self._now

    def try_consume(self, token_id: str, *, expiry_unix: float) -> bool:
        key = f"{self._key_prefix}{token_id}"
        ttl = max(1, int(math.ceil(expiry_unix - self._clock())))
        try:
            # redis-py: True if set, None/False if NX lost the race
            result = self._client.set(key, "1", nx=True, ex=ttl)
        except CapabilityStoreError:
            raise
        except Exception as exc:
            raise CapabilityStoreError(
                f"Redis consume failed (fail closed): {exc}"
            ) from exc
        return bool(result)
