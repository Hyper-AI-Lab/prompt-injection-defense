"""RedisConsumeStore tests (leftovers step 8).

Unit path uses an injectable fake client; no redis package required.
Live Redis tests skip unless CONTAINMENT_LIVE_REDIS=1 (or REDIS_URL set with
that flag).
"""

from __future__ import annotations

import os
import time
from typing import Any

import pytest

from containment.capability import CapabilityError, CapabilityMinter
from containment.capability_store_redis import (
    CapabilityStoreError,
    RedisConsumeStore,
)


class _FakeRedis:
    """Minimal SET NX EX surface for hermetic unit tests."""

    def __init__(self) -> None:
        self.data: dict[str, str] = {}
        self.last_ex: int | None = None
        self.fail_next: Exception | None = None

    def set(
        self,
        name: str,
        value: str,
        nx: bool = False,
        ex: int | None = None,
    ) -> bool | None:
        if self.fail_next is not None:
            exc = self.fail_next
            self.fail_next = None
            raise exc
        self.last_ex = ex
        if nx and name in self.data:
            return None
        self.data[name] = value
        return True


def test_requires_url_or_client() -> None:
    with pytest.raises(CapabilityStoreError, match="url= or client="):
        RedisConsumeStore()


def test_fake_first_wins() -> None:
    client = _FakeRedis()
    store = RedisConsumeStore(client=client, key_prefix="t:")
    assert store.try_consume("a", expiry_unix=1_000_100.0) is True
    assert store.try_consume("a", expiry_unix=1_000_100.0) is False
    assert "t:a" in client.data


def test_ttl_ceil_min_one() -> None:
    client = _FakeRedis()
    store = RedisConsumeStore(client=client, now=1_000_000.0)
    assert store.try_consume("x", expiry_unix=1_000_000.4) is True
    assert client.last_ex == 1  # ceil(0.4) -> 1, min 1
    client2 = _FakeRedis()
    store2 = RedisConsumeStore(client=client2, now=1_000_000.0)
    assert store2.try_consume("y", expiry_unix=1_000_010.1) is True
    assert client2.last_ex == 11  # ceil(10.1)


def test_ttl_past_expiry_still_min_one() -> None:
    client = _FakeRedis()
    store = RedisConsumeStore(client=client, now=2_000_000.0)
    assert store.try_consume("z", expiry_unix=1_000_000.0) is True
    assert client.last_ex == 1


def test_outage_raises_fail_closed() -> None:
    client = _FakeRedis()
    client.fail_next = ConnectionError("boom")
    store = RedisConsumeStore(client=client)
    with pytest.raises(CapabilityStoreError, match="fail closed"):
        store.try_consume("a", expiry_unix=time.time() + 60)


def test_url_without_redis_package(monkeypatch: pytest.MonkeyPatch) -> None:
    import builtins

    real_import = builtins.__import__

    def blocker(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "redis" or name.startswith("redis."):
            raise ImportError("simulated missing redis")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", blocker)
    with pytest.raises(CapabilityStoreError, match="redis package"):
        RedisConsumeStore(url="redis://127.0.0.1:6379/0")


def test_minter_with_redis_store() -> None:
    client = _FakeRedis()
    store = RedisConsumeStore(client=client)
    minter = CapabilityMinter(
        secret=b"test-secret-key-32bytes-padded!!",
        store=store,
    )
    token = minter.one_use(tool="web.fetch", now=1_000_000.0)
    minter.verify(token, tool="web.fetch", now=1_000_001.0)
    with pytest.raises(CapabilityError, match="already used"):
        minter.verify(token, tool="web.fetch", now=1_000_002.0)


def test_minter_store_outage_propagates() -> None:
    client = _FakeRedis()
    store = RedisConsumeStore(client=client)
    minter = CapabilityMinter(
        secret=b"test-secret-key-32bytes-padded!!",
        store=store,
    )
    token = minter.one_use(tool="web.fetch", now=1_000_000.0)
    client.fail_next = OSError("redis down")
    with pytest.raises(CapabilityStoreError, match="fail closed"):
        minter.verify(token, tool="web.fetch", now=1_000_001.0)


@pytest.mark.skipif(
    os.environ.get("CONTAINMENT_LIVE_REDIS") != "1",
    reason="set CONTAINMENT_LIVE_REDIS=1 to run against a live Redis",
)
def test_live_redis_try_consume_unique() -> None:
    redis = pytest.importorskip("redis")
    url = os.environ.get("REDIS_URL") or os.environ.get(
        "CONTAINMENT_REDIS_URL", "redis://127.0.0.1:6379/15"
    )
    try:
        probe = redis.Redis.from_url(url, socket_connect_timeout=0.25)
        probe.ping()
    except Exception as exc:
        pytest.skip(f"redis unavailable: {exc}")
    prefix = f"containment:test:{int(time.time())}:"
    store = RedisConsumeStore(url=url, key_prefix=prefix)
    tid = f"tok-{time.time()}"
    assert store.try_consume(tid, expiry_unix=time.time() + 60) is True
    assert store.try_consume(tid, expiry_unix=time.time() + 60) is False
