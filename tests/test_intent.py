"""Signed IntentEnvelope HMAC tests (enterprise step 3)."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from containment.actions import ProposedAction
from containment.audit import AuditLog
from containment.broker import SecurityViolation, ToolBroker
from containment.capability import CapabilityMinter
from containment.intent import IntentError, IntentSigner, SignedIntent, plan_hash
from containment.labels import SecurityLabel
from containment.plan import IntentEnvelope, Plan, PlanStep
from containment.policy import PolicyEngine

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "policies" / "default_deny.yaml"
SECRET = b"intent-test-secret-key-32bytes!!!"


def _plan(**kwargs) -> Plan:
    base = dict(
        task_id="t1",
        steps=(PlanStep(step_id="s_fetch", tool="web.fetch"),),
        capabilities=frozenset({"web.fetch"}),
        approved_public_hosts=frozenset({"example.com"}),
    )
    base.update(kwargs)
    return Plan(**base)


def _envelope(**kwargs) -> IntentEnvelope:
    base = dict(
        task_id="t1",
        tenant="acme",
        user="alice",
        scope=frozenset({"web.fetch"}),
        risk_budget="low",
        principal_authenticated=True,
    )
    base.update(kwargs)
    return IntentEnvelope(**base)


def _label() -> SecurityLabel:
    return SecurityLabel(
        integrity="trusted",
        confidentiality="public",
        source="user",
        task_id="t1",
    )


def test_sign_verify_round_trip() -> None:
    signer = IntentSigner(SECRET)
    plan = _plan()
    signed = signer.sign(_envelope(), plan=plan, now=1_000_000.0, ttl_seconds=60.0)
    env = signer.verify(signed, plan=plan, now=1_000_001.0)
    assert env.user == "alice"
    assert signed.plan_hash == plan_hash(plan)


def test_tamper_task_id_fails() -> None:
    signer = IntentSigner(SECRET)
    plan = _plan()
    signed = signer.sign(_envelope(), plan=plan, now=1_000_000.0)
    bad_env = replace(signed.envelope, task_id="t2")
    bad = replace(signed, envelope=bad_env)
    with pytest.raises(IntentError, match="MAC"):
        signer.verify(bad, plan=plan, now=1_000_001.0)


def test_expired_intent_fails() -> None:
    signer = IntentSigner(SECRET)
    plan = _plan()
    signed = signer.sign(_envelope(), plan=plan, now=1_000_000.0, ttl_seconds=10.0)
    with pytest.raises(IntentError, match="expired"):
        signer.verify(signed, plan=plan, now=1_000_020.0)


def test_plan_hash_mismatch_fails() -> None:
    signer = IntentSigner(SECRET)
    plan = _plan()
    signed = signer.sign(_envelope(), plan=plan, now=1_000_000.0)
    other = _plan(approved_public_hosts=frozenset({"evil.com"}))
    with pytest.raises(IntentError, match="plan_hash"):
        signer.verify(signed, plan=other, now=1_000_001.0)


def test_scope_subset_fails() -> None:
    signer = IntentSigner(SECRET)
    plan = _plan(capabilities=frozenset({"web.fetch", "email.send"}),
                steps=(
                    PlanStep(step_id="s_fetch", tool="web.fetch"),
                    PlanStep(step_id="s_email", tool="email.send"),
                ))
    # Envelope scope missing email.send
    signed = signer.sign(_envelope(scope=frozenset({"web.fetch"})), plan=plan, now=1.0)
    # sign() does not enforce scope⊇capabilities; verify does
    with pytest.raises(IntentError, match="scope"):
        signer.verify(signed, plan=plan, now=2.0)


def test_broker_require_signed_intent_denies_unsigned(tmp_path: Path) -> None:
    broker = ToolBroker(
        policy=PolicyEngine.from_yaml_path(POLICY_PATH),
        audit=AuditLog(tmp_path / "a.jsonl"),
        minter=CapabilityMinter(secret=b"x" * 32),
        require_signed_intent=True,
        intent_signer=IntentSigner(SECRET),
        known_tools=frozenset({"web.fetch"}),
    )
    action = ProposedAction(
        tool="web.fetch",
        arguments={"url": "https://example.com/"},
        principal="alice",
        task_id="t1",
        reason_code="test",
        input_labels=(_label(),),
        plan_step="s_fetch",
    )
    with pytest.raises(SecurityViolation) as ei:
        broker.secure_execute(action, plan=_plan())
    assert ei.value.decision.rule_id == "signed_intent_required"


def test_broker_enterprise_profile_accepts_valid_intent(tmp_path: Path) -> None:
    signer = IntentSigner(SECRET)
    plan = _plan()
    signed = signer.sign(_envelope(), plan=plan, ttl_seconds=3600.0)
    broker = ToolBroker(
        policy=PolicyEngine.from_yaml_path(POLICY_PATH),
        audit=AuditLog(tmp_path / "a.jsonl"),
        minter=CapabilityMinter(secret=b"x" * 32),
        enterprise_profile=True,
        intent_signer=signer,
        known_tools=frozenset({"web.fetch"}),
    )
    action = ProposedAction(
        tool="web.fetch",
        arguments={"url": "https://example.com/"},
        principal="alice",
        task_id="t1",
        reason_code="test",
        input_labels=(_label(),),
        plan_step="s_fetch",
    )
    result = broker.secure_execute(
        action, plan=plan, intent=signed, principal_authenticated=False
    )
    # Verified envelope overrides caller principal_authenticated=False
    assert result.decision.effect == "allow"
    assert result.capability is not None


def test_broker_rejects_tampered_intent(tmp_path: Path) -> None:
    signer = IntentSigner(SECRET)
    plan = _plan()
    signed = signer.sign(_envelope(), plan=plan, now=1_000_000.0)
    bad = SignedIntent(
        envelope=signed.envelope,
        issued_at_unix=signed.issued_at_unix,
        expiry_unix=signed.expiry_unix,
        nonce=signed.nonce,
        plan_hash=signed.plan_hash,
        mac="0" * 64,
    )
    broker = ToolBroker(
        policy=PolicyEngine.from_yaml_path(POLICY_PATH),
        audit=AuditLog(tmp_path / "a.jsonl"),
        minter=CapabilityMinter(secret=b"x" * 32),
        require_signed_intent=True,
        intent_signer=signer,
        known_tools=frozenset({"web.fetch"}),
    )
    action = ProposedAction(
        tool="web.fetch",
        arguments={"url": "https://example.com/"},
        principal="alice",
        task_id="t1",
        reason_code="test",
        input_labels=(_label(),),
        plan_step="s_fetch",
    )
    with pytest.raises(SecurityViolation) as ei:
        broker.secure_execute(action, plan=plan, intent=bad)
    assert ei.value.decision.rule_id == "signed_intent_invalid"
