"""Capability one-use + append-only audit tests (step 4)."""

from __future__ import annotations

from pathlib import Path

import pytest

from containment.actions import PolicyDecision, ProposedAction
from containment.audit import AuditLog
from containment.capability import CapabilityError, CapabilityMinter
from containment.labels import SecurityLabel


def test_one_use_second_verify_fails() -> None:
    minter = CapabilityMinter(secret=b"test-secret-key-32bytes-padded!!")
    token = minter.one_use(
        tool="email.send",
        resources=("alice@acme.test",),
        expiry_seconds=60,
        now=1_000_000.0,
    )
    minter.verify(
        token,
        tool="email.send",
        resources=("alice@acme.test",),
        now=1_000_001.0,
    )
    with pytest.raises(CapabilityError, match="already used"):
        minter.verify(
            token,
            tool="email.send",
            resources=("alice@acme.test",),
            now=1_000_002.0,
        )


def test_verify_rejects_tool_mismatch() -> None:
    minter = CapabilityMinter(secret=b"test-secret-key-32bytes-padded!!")
    token = minter.one_use(tool="email.send", now=1_000_000.0)
    with pytest.raises(CapabilityError, match="tool mismatch"):
        minter.verify(token, tool="http.post", now=1_000_001.0)


def test_verify_rejects_expired() -> None:
    minter = CapabilityMinter(secret=b"test-secret-key-32bytes-padded!!")
    token = minter.one_use(tool="web.fetch", expiry_seconds=10, now=1_000_000.0)
    with pytest.raises(CapabilityError, match="expired"):
        minter.verify(token, tool="web.fetch", now=1_000_020.0)


def test_verify_rejects_tampered_mac() -> None:
    minter = CapabilityMinter(secret=b"test-secret-key-32bytes-padded!!")
    token = minter.one_use(tool="web.fetch", now=1_000_000.0)
    from dataclasses import replace

    bad = replace(token, mac="0" * 64)
    with pytest.raises(CapabilityError, match="MAC"):
        minter.verify(bad, tool="web.fetch", now=1_000_001.0)


def test_audit_round_trip(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    action = ProposedAction(
        tool="email.send",
        arguments={"recipient": "alice@acme.test"},
        principal="alice",
        task_id="t1",
        reason_code="test",
        input_labels=(
            SecurityLabel(
                integrity="trusted",
                confidentiality="private",
                source="user",
                task_id="t1",
            ),
        ),
        plan_step="s1",
    )
    decision = PolicyDecision(
        effect="require_human", rule_id="approved-email", reason="matched"
    )
    event = log.append_decision(
        action, decision, timestamp="2026-10-07T01:00:00+00:00"
    )
    assert event.kind == "policy_decision"
    loaded = log.read_all()
    assert len(loaded) == 1
    assert loaded[0].event_id == event.event_id
    assert loaded[0].task_id == "t1"
    assert loaded[0].detail["decision"]["rule_id"] == "approved-email"
    assert loaded[0].detail["tool"] == "email.send"

    # Append-only: second write grows the file; first record unchanged.
    log.append_decision(
        action,
        PolicyDecision(effect="deny", rule_id="default_deny"),
        timestamp="2026-10-07T01:01:00+00:00",
    )
    loaded2 = log.read_all()
    assert len(loaded2) == 2
    assert loaded2[0].event_id == event.event_id
    assert loaded2[1].detail["decision"]["effect"] == "deny"


def test_audit_creates_parent_dirs(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "dir" / "audit.jsonl"
    log = AuditLog(path)
    assert path.exists()
    assert log.read_all() == []
