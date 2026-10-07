"""CapabilityConsumeStore backends (enterprise step 2)."""

from __future__ import annotations

from pathlib import Path

import pytest

from containment.capability import CapabilityError, CapabilityMinter
from containment.capability_store import MemoryConsumeStore, SqliteConsumeStore


def test_memory_second_try_consume_fails() -> None:
    store = MemoryConsumeStore()
    assert store.try_consume("a", expiry_unix=100.0) is True
    assert store.try_consume("a", expiry_unix=100.0) is False


def test_memory_minter_second_verify_fails() -> None:
    minter = CapabilityMinter(secret=b"test-secret-key-32bytes-padded!!")
    token = minter.one_use(tool="web.fetch", now=1_000_000.0)
    minter.verify(token, tool="web.fetch", now=1_000_001.0)
    with pytest.raises(CapabilityError, match="already used"):
        minter.verify(token, tool="web.fetch", now=1_000_002.0)


def test_sqlite_cross_instance_consume(tmp_path: Path) -> None:
    path = str(tmp_path / "consumed.sqlite")
    secret = b"shared-secret-key-32bytes-pad!!!!"
    store_a = SqliteConsumeStore(path)
    store_b = SqliteConsumeStore(path)
    minter_a = CapabilityMinter(secret=secret, store=store_a)
    minter_b = CapabilityMinter(secret=secret, store=store_b)
    token = minter_a.one_use(tool="email.send", now=1_000_000.0)
    minter_a.verify(token, tool="email.send", now=1_000_001.0)
    with pytest.raises(CapabilityError, match="already used"):
        minter_b.verify(token, tool="email.send", now=1_000_002.0)


def test_sqlite_try_consume_unique(tmp_path: Path) -> None:
    store = SqliteConsumeStore(str(tmp_path / "c.sqlite"))
    assert store.try_consume("tok", expiry_unix=50.0) is True
    assert store.try_consume("tok", expiry_unix=50.0) is False


def test_invalid_mac_does_not_consume() -> None:
    store = MemoryConsumeStore()
    minter = CapabilityMinter(secret=b"test-secret-key-32bytes-padded!!", store=store)
    token = minter.one_use(tool="web.fetch", now=1_000_000.0)
    from dataclasses import replace

    bad = replace(token, mac="0" * 64)
    with pytest.raises(CapabilityError, match="MAC"):
        minter.verify(bad, tool="web.fetch", now=1_000_001.0)
    # Valid token still consumable (garbage did not pollute store).
    minter.verify(token, tool="web.fetch", now=1_000_001.0)
