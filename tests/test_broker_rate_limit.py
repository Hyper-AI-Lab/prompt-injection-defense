"""Broker rate/spend gate for privileged sinks (step 9)."""

from __future__ import annotations

from pathlib import Path

import pytest

from containment.actions import PolicyDecision, ProposedAction
from containment.audit import AuditLog
from containment.broker import SecurityViolation, ToolBroker
from containment.capability import CapabilityMinter
from containment.host import TokenBucketRateLimit
from containment.labels import SecurityLabel
from containment.plan import Plan, PlanStep
from containment.policy import PolicyEngine

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "policies" / "default_deny.yaml"


def _label() -> SecurityLabel:
    return SecurityLabel(
        integrity="trusted",
        confidentiality="private",
        source="user",
        task_id="t1",
    )


def _plan() -> Plan:
    return Plan(
        task_id="t1",
        steps=(
            PlanStep(step_id="s_fetch", tool="web.fetch"),
            PlanStep(step_id="s_email", tool="email.send"),
        ),
        capabilities=frozenset({"web.fetch", "email.send"}),
        approved_public_hosts=frozenset({"example.com"}),
        approved_recipients=frozenset({"alice@acme.test"}),
    )


def _email_action() -> ProposedAction:
    return ProposedAction(
        tool="email.send",
        arguments={"recipient": "alice@acme.test", "body": "hi"},
        principal="alice",
        task_id="t1",
        reason_code="test",
        input_labels=(_label(),),
        plan_step="s_email",
    )


def _fetch_action() -> ProposedAction:
    return ProposedAction(
        tool="web.fetch",
        arguments={"url": "https://example.com/"},
        principal="alice",
        task_id="t1",
        reason_code="test",
        input_labels=(_label(),),
        plan_step="s_fetch",
    )


def _approve(action: ProposedAction, decision: PolicyDecision) -> None:
    del action, decision


def _broker(tmp_path: Path, **kwargs) -> ToolBroker:
    defaults = dict(
        policy=PolicyEngine.from_yaml_path(POLICY_PATH),
        audit=AuditLog(tmp_path / "audit.jsonl"),
        minter=CapabilityMinter(secret=b"broker-rate-test-secret-key-32b"),
        known_tools=frozenset({"web.fetch", "email.send"}),
        approval=_approve,
    )
    defaults.update(kwargs)
    return ToolBroker(**defaults)


def test_privileged_first_allow_second_deny(tmp_path: Path) -> None:
    gate = TokenBucketRateLimit(rate=0.0, capacity=1.0)
    broker = _broker(tmp_path, rate_limit=gate)
    plan = _plan()

    first = broker.secure_execute(_email_action(), plan=plan)
    assert first.capability is not None

    with pytest.raises(SecurityViolation) as ei:
        broker.secure_execute(_email_action(), plan=plan)
    assert ei.value.decision.rule_id == "rate_limit_exceeded"
    assert ei.value.decision.effect == "deny"

    events = broker.audit.read_all()
    assert any(e.detail["decision"]["rule_id"] == "rate_limit_exceeded" for e in events)


def test_without_rate_limit_unchanged(tmp_path: Path) -> None:
    broker = _broker(tmp_path)
    plan = _plan()
    assert broker.rate_limit is None
    r1 = broker.secure_execute(_email_action(), plan=plan)
    r2 = broker.secure_execute(_email_action(), plan=plan)
    assert r1.capability is not None
    assert r2.capability is not None


def test_non_privileged_not_rate_limited(tmp_path: Path) -> None:
    gate = TokenBucketRateLimit(rate=0.0, capacity=1.0)
    broker = _broker(tmp_path, rate_limit=gate)
    plan = _plan()

    # Exhaust budget on privileged sink.
    broker.secure_execute(_email_action(), plan=plan)
    with pytest.raises(SecurityViolation) as ei:
        broker.secure_execute(_email_action(), plan=plan)
    assert ei.value.decision.rule_id == "rate_limit_exceeded"

    # web.fetch is not in PRIVILEGED_SINKS; still allowed.
    result = broker.secure_execute(_fetch_action(), plan=plan)
    assert result.capability is not None
