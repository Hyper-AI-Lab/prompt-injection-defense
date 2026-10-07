"""Broker HostGate: require_host_gate / enterprise fail-closed (step 3)."""

from __future__ import annotations

from pathlib import Path

import pytest

from containment.actions import ProposedAction
from containment.audit import AuditLog
from containment.broker import SecurityViolation, ToolBroker
from containment.capability import CapabilityMinter
from containment.host import (
    EnvSecretProvider,
    FileAuditShipper,
    FileSecretProvider,
    HostChecklist,
)
from containment.intent import IntentSigner
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


def _action() -> ProposedAction:
    return ProposedAction(
        tool="web.fetch",
        arguments={"url": "https://example.com/"},
        principal="alice",
        task_id="t1",
        reason_code="test",
        input_labels=(_label(),),
        plan_step="s_fetch",
    )


def _complete_checklist(tmp_path: Path) -> HostChecklist:
    secrets_root = tmp_path / "secrets"
    secrets_root.mkdir()
    (secrets_root / "hmac").write_bytes(b"host-gate-secret-bytes")
    return HostChecklist(
        isolation_declared=True,
        secret_provider=FileSecretProvider(secrets_root),
        egress_configured=True,
        audit_shipper=FileAuditShipper(tmp_path / "shipped-audit.jsonl"),
    )


def _broker(tmp_path: Path, **kwargs) -> ToolBroker:
    defaults = dict(
        policy=PolicyEngine.from_yaml_path(POLICY_PATH),
        audit=AuditLog(tmp_path / "a.jsonl"),
        minter=CapabilityMinter(secret=b"x" * 32),
        known_tools=frozenset({"web.fetch"}),
    )
    defaults.update(kwargs)
    return ToolBroker(**defaults)


def test_enterprise_without_checklist_denies(tmp_path: Path) -> None:
    broker = _broker(tmp_path, enterprise_profile=True, intent_signer=IntentSigner(SECRET))
    with pytest.raises(SecurityViolation) as ei:
        broker.secure_execute(_action(), plan=_plan())
    assert ei.value.decision.rule_id == "host_gate_required"
    assert broker.require_host_gate is True


def test_require_host_gate_incomplete_checklist_denies(tmp_path: Path) -> None:
    incomplete = HostChecklist(
        isolation_declared=False,
        secret_provider=EnvSecretProvider(),
        egress_configured=True,
        audit_shipper=FileAuditShipper(tmp_path / "ship.jsonl"),
    )
    broker = _broker(
        tmp_path,
        require_host_gate=True,
        host_checklist=incomplete,
    )
    with pytest.raises(SecurityViolation) as ei:
        broker.secure_execute(_action(), plan=_plan())
    assert ei.value.decision.rule_id == "host_checklist_failed"
    assert "isolation_not_declared" in ei.value.decision.reason


def test_complete_checklist_enterprise_allows(tmp_path: Path) -> None:
    signer = IntentSigner(SECRET)
    plan = _plan()
    signed = signer.sign(_envelope(), plan=plan, ttl_seconds=3600.0)
    broker = _broker(
        tmp_path,
        enterprise_profile=True,
        intent_signer=signer,
        host_checklist=_complete_checklist(tmp_path),
    )
    result = broker.secure_execute(
        _action(), plan=plan, intent=signed, principal_authenticated=False
    )
    assert result.decision.effect == "allow"
    assert result.capability is not None


def test_require_host_gate_false_skips_host_check(tmp_path: Path) -> None:
    broker = _broker(tmp_path, require_host_gate=False, host_checklist=None)
    result = broker.secure_execute(_action(), plan=_plan())
    assert result.decision.effect == "allow"
    assert result.capability is not None
