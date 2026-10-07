"""Ed25519 IntentEnvelope tests (optional cryptography extra)."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from containment.actions import ProposedAction
from containment.audit import AuditLog
from containment.broker import SecurityViolation, ToolBroker
from containment.capability import CapabilityMinter
from containment.host import FileAuditShipper, FileSecretProvider, HostChecklist
from containment.intent import (
    Ed25519IntentSigner,
    IntentError,
    IntentSigner,
    SignedIntent,
    intent_payload_bytes,
    plan_hash,
)
from containment.labels import SecurityLabel
from containment.plan import IntentEnvelope, Plan, PlanStep
from containment.policy import PolicyEngine

pytest.importorskip("cryptography")

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "policies" / "default_deny.yaml"
HMAC_SECRET = b"intent-test-secret-key-32bytes!!!"


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


def test_ed25519_sign_verify_round_trip() -> None:
    signer = Ed25519IntentSigner.generate(key_id="k1")
    plan = _plan()
    signed = signer.sign(_envelope(), plan=plan, now=1_000_000.0, ttl_seconds=60.0)
    assert signed.alg == "ed25519"
    assert signed.key_id == "k1"
    env = signer.verify(signed, plan=plan, now=1_000_001.0)
    assert env.user == "alice"
    assert signed.plan_hash == plan_hash(plan)
    # public-only verifier
    verifier = Ed25519IntentSigner(public_key=signer.public_bytes(), key_id="k1")
    assert verifier.verify(signed, plan=plan, now=1_000_001.0).user == "alice"


def test_ed25519_tamper_fails() -> None:
    signer = Ed25519IntentSigner.generate()
    plan = _plan()
    signed = signer.sign(_envelope(), plan=plan, now=1_000_000.0)
    bad_env = replace(signed.envelope, task_id="t2")
    bad = replace(signed, envelope=bad_env)
    with pytest.raises(IntentError, match="MAC"):
        signer.verify(bad, plan=plan, now=1_000_001.0)


def test_ed25519_tampered_mac_fails() -> None:
    signer = Ed25519IntentSigner.generate()
    plan = _plan()
    signed = signer.sign(_envelope(), plan=plan, now=1_000_000.0)
    bad = replace(signed, mac="00" * 64)
    with pytest.raises(IntentError, match="MAC"):
        signer.verify(bad, plan=plan, now=1_000_001.0)


def test_cross_alg_hmac_rejects_ed25519() -> None:
    ed = Ed25519IntentSigner.generate()
    plan = _plan()
    signed = ed.sign(_envelope(), plan=plan, now=1_000_000.0)
    hmac_signer = IntentSigner(HMAC_SECRET)
    with pytest.raises(IntentError, match="unsupported alg"):
        hmac_signer.verify(signed, plan=plan, now=1_000_001.0)


def test_cross_alg_ed25519_rejects_hmac() -> None:
    hmac_signer = IntentSigner(HMAC_SECRET)
    plan = _plan()
    signed = hmac_signer.sign(_envelope(), plan=plan, now=1_000_000.0)
    ed = Ed25519IntentSigner.generate()
    with pytest.raises(IntentError, match="unsupported alg"):
        ed.verify(signed, plan=plan, now=1_000_001.0)


def test_intent_payload_bytes_stable() -> None:
    signed = SignedIntent(
        envelope=_envelope(),
        issued_at_unix=1.0,
        expiry_unix=2.0,
        nonce="n",
        plan_hash="abc",
        mac="",
        alg="ed25519",
        key_id="k",
    )
    a = intent_payload_bytes(signed)
    b = intent_payload_bytes(signed)
    assert a == b
    assert b"ed25519" in a


def test_ed25519_missing_crypto_message(monkeypatch: pytest.MonkeyPatch) -> None:
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name.startswith("cryptography"):
            raise ImportError("blocked for test")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(IntentError, match="cryptography"):
        Ed25519IntentSigner.generate()


def test_broker_ed25519_allow(tmp_path: Path) -> None:
    signer = Ed25519IntentSigner.generate()
    plan = _plan()
    signed = signer.sign(_envelope(), plan=plan, ttl_seconds=3600.0)
    secrets_root = tmp_path / "secrets"
    secrets_root.mkdir()
    (secrets_root / "hmac").write_bytes(b"host-gate-secret-bytes")
    checklist = HostChecklist(
        isolation_declared=True,
        secret_provider=FileSecretProvider(secrets_root),
        egress_configured=True,
        audit_shipper=FileAuditShipper(tmp_path / "shipped-audit.jsonl"),
    )
    # Verify-only public key on the broker
    verifier = Ed25519IntentSigner(public_key=signer.public_bytes())
    broker = ToolBroker(
        policy=PolicyEngine.from_yaml_path(POLICY_PATH),
        audit=AuditLog(tmp_path / "a.jsonl"),
        minter=CapabilityMinter(secret=b"x" * 32),
        enterprise_profile=True,
        intent_signer=verifier,
        host_checklist=checklist,
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
    assert result.decision.effect == "allow"
    assert result.capability is not None


def test_broker_ed25519_deny_tampered(tmp_path: Path) -> None:
    signer = Ed25519IntentSigner.generate()
    plan = _plan()
    signed = signer.sign(_envelope(), plan=plan, now=1_000_000.0)
    bad = replace(signed, mac="11" * 64)
    broker = ToolBroker(
        policy=PolicyEngine.from_yaml_path(POLICY_PATH),
        audit=AuditLog(tmp_path / "a.jsonl"),
        minter=CapabilityMinter(secret=b"x" * 32),
        require_signed_intent=True,
        intent_signer=Ed25519IntentSigner(public_key=signer.public_bytes()),
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


def test_public_only_cannot_sign() -> None:
    full = Ed25519IntentSigner.generate()
    verifier = Ed25519IntentSigner(public_key=full.public_bytes())
    with pytest.raises(IntentError, match="private key"):
        verifier.sign(_envelope(), plan=_plan())
