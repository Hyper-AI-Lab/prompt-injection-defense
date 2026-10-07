"""Host foundation: secrets, checklist, audit ship, rate limit (step 2)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from containment.host import (
    EnvSecretProvider,
    FileAuditShipper,
    FileSecretProvider,
    HostChecklist,
    SecretError,
    TokenBucketRateLimit,
)


def test_env_secret_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CONTAINMENT_SECRET_HMAC", "s3cret-value")
    provider = EnvSecretProvider()
    assert provider.get_bytes("hmac") == b"s3cret-value"


def test_env_secret_custom_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MYAPP_KEY_FOO", "bar")
    provider = EnvSecretProvider(prefix="MYAPP_KEY_")
    assert provider.get_bytes("foo") == b"bar"


def test_env_secret_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CONTAINMENT_SECRET_MISSING", raising=False)
    provider = EnvSecretProvider()
    with pytest.raises(SecretError, match="missing or empty"):
        provider.get_bytes("missing")


def test_env_secret_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CONTAINMENT_SECRET_EMPTY", "")
    provider = EnvSecretProvider()
    with pytest.raises(SecretError, match="missing or empty"):
        provider.get_bytes("empty")


def test_file_secret_success(tmp_path: Path) -> None:
    (tmp_path / "hmac").write_bytes(b"file-secret\n")
    provider = FileSecretProvider(tmp_path)
    assert provider.get_bytes("hmac") == b"file-secret"


def test_file_secret_missing(tmp_path: Path) -> None:
    provider = FileSecretProvider(tmp_path)
    with pytest.raises(SecretError, match="missing secret file"):
        provider.get_bytes("nope")


def test_file_secret_empty(tmp_path: Path) -> None:
    (tmp_path / "blank").write_bytes(b"\n\n")
    provider = FileSecretProvider(tmp_path)
    with pytest.raises(SecretError, match="empty secret file"):
        provider.get_bytes("blank")


def test_file_secret_path_traversal_rejected(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-secret"
    outside.write_bytes(b"leak")
    provider = FileSecretProvider(tmp_path)
    with pytest.raises(SecretError):
        provider.get_bytes("../outside-secret")
    with pytest.raises(SecretError):
        provider.get_bytes("..")


def test_checklist_ok() -> None:
    provider = EnvSecretProvider()
    shipper = FileAuditShipper("/tmp/unused-audit-ship.jsonl")
    checklist = HostChecklist(
        isolation_declared=True,
        secret_provider=provider,
        egress_configured=True,
        audit_shipper=shipper,
    )
    assert checklist.ok() is True
    assert checklist.failures() == ()


def test_checklist_failures_stable_codes() -> None:
    checklist = HostChecklist(
        isolation_declared=False,
        secret_provider=None,
        egress_configured=False,
        audit_shipper=None,
    )
    assert checklist.ok() is False
    assert checklist.failures() == (
        "isolation_not_declared",
        "secret_provider_missing",
        "egress_not_configured",
        "audit_shipper_missing",
    )


def test_file_audit_shipper_roundtrip(tmp_path: Path) -> None:
    source = tmp_path / "audit.jsonl"
    dest = tmp_path / "shipped" / "out.jsonl"
    events = [
        {"event_id": "1", "kind": "policy_decision"},
        {"event_id": "2", "kind": "broker"},
    ]
    source.write_text(
        "\n".join(json.dumps(e, sort_keys=True) for e in events) + "\n",
        encoding="utf-8",
    )
    shipper = FileAuditShipper(dest)
    shipper.ship_file(source)
    lines = [
        ln for ln in dest.read_text(encoding="utf-8").splitlines() if ln.strip()
    ]
    assert len(lines) == 2
    assert json.loads(lines[0])["event_id"] == "1"
    assert json.loads(lines[1])["event_id"] == "2"
    # Second ship appends again.
    shipper.ship_file(source)
    lines2 = [
        ln for ln in dest.read_text(encoding="utf-8").splitlines() if ln.strip()
    ]
    assert len(lines2) == 4


def test_token_bucket_allow_then_deny() -> None:
    gate = TokenBucketRateLimit(rate=0.0, capacity=2.0)
    assert gate.allow("web.fetch", cost=1.0) is True
    assert gate.allow("email.send", cost=1.0) is True
    assert gate.allow("web.fetch", cost=1.0) is False


def test_token_bucket_refill() -> None:
    gate = TokenBucketRateLimit(rate=1000.0, capacity=1.0)
    assert gate.allow("t", cost=1.0) is True
    assert gate.allow("t", cost=1.0) is False
    # Force refill by advancing internal clock via allow after sleep-free
    # injection: call with zero rate already tested; here large rate +
    # tiny sleep via updating by calling allow after setting tokens via
    # a second instance is unnecessary — just verify capacity=1 refill
    # path with rate high enough that any positive elapsed refills.
    import time

    time.sleep(0.01)
    assert gate.allow("t", cost=1.0) is True
