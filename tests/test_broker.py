"""Tool broker secure_execute tests (step 5)."""

from __future__ import annotations

from pathlib import Path

import pytest

from containment.actions import PolicyDecision, ProposedAction
from containment.audit import AuditLog
from containment.broker import SecurityViolation, ToolBroker
from containment.capability import CapabilityMinter
from containment.labels import SecurityLabel
from containment.plan import Plan, PlanStep
from containment.policy import PolicyEngine

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "policies" / "default_deny.yaml"


def _label(*, integrity: str = "trusted", confidentiality: str = "private") -> SecurityLabel:
    return SecurityLabel(
        integrity=integrity,  # type: ignore[arg-type]
        confidentiality=confidentiality,  # type: ignore[arg-type]
        source="user" if integrity == "trusted" else "web",
        task_id="t1",
    )


def _plan() -> Plan:
    return Plan(
        task_id="t1",
        steps=(
            PlanStep(step_id="s_fetch", tool="web.fetch"),
            PlanStep(step_id="s_email", tool="email.send"),
            PlanStep(step_id="s_post", tool="http.post"),
        ),
        capabilities=frozenset({"web.fetch", "email.send", "http.post"}),
        approved_public_hosts=frozenset({"example.com"}),
        approved_recipients=frozenset({"alice@acme.test"}),
    )


def _broker(tmp_path: Path, **kwargs) -> ToolBroker:
    return ToolBroker(
        policy=PolicyEngine.from_yaml_path(POLICY_PATH),
        audit=AuditLog(tmp_path / "audit.jsonl"),
        minter=CapabilityMinter(secret=b"broker-test-secret-key-32b!!!!"),
        known_tools=frozenset(
            {"web.fetch", "email.send", "http.post", "wallet.transfer"}
        ),
        **kwargs,
    )


def test_unknown_tool_denied(tmp_path: Path) -> None:
    broker = _broker(tmp_path)
    action = ProposedAction(
        tool="shell.exec",
        arguments={"cmd": "id"},
        principal="alice",
        task_id="t1",
        reason_code="test",
        input_labels=(_label(),),
        plan_step="s_fetch",
    )
    with pytest.raises(SecurityViolation) as excinfo:
        broker.secure_execute(action, plan=_plan())
    assert excinfo.value.decision.rule_id == "unknown_tool"
    assert excinfo.value.decision.effect == "deny"
    events = broker.audit.read_all()
    assert len(events) == 1
    assert events[0].detail["decision"]["rule_id"] == "unknown_tool"


def test_tainted_egress_denied(tmp_path: Path) -> None:
    broker = _broker(tmp_path)
    action = ProposedAction(
        tool="email.send",
        arguments={"recipient": "alice@acme.test", "body": "hi"},
        principal="alice",
        task_id="t1",
        reason_code="test",
        input_labels=(_label(integrity="untrusted"),),
        plan_step="s_email",
    )
    with pytest.raises(SecurityViolation) as excinfo:
        broker.secure_execute(action, plan=_plan())
    assert excinfo.value.decision.rule_id == "no-tainted-egress"
    assert excinfo.value.decision.effect == "deny"


def test_require_human_calls_approval(tmp_path: Path) -> None:
    calls: list[tuple[ProposedAction, PolicyDecision]] = []

    def approval(action: ProposedAction, decision: PolicyDecision) -> None:
        calls.append((action, decision))

    broker = _broker(tmp_path, approval=approval)
    action = ProposedAction(
        tool="email.send",
        arguments={"recipient": "alice@acme.test", "body": "hi"},
        principal="alice",
        task_id="t1",
        reason_code="test",
        input_labels=(_label(confidentiality="private"),),
        plan_step="s_email",
    )
    result = broker.secure_execute(action, plan=_plan())
    assert len(calls) == 1
    assert calls[0][0].tool == "email.send"
    assert calls[0][1].effect == "require_human"
    assert calls[0][1].rule_id == "approved-email"
    assert result.decision.effect == "require_human"
    assert result.capability is not None
    assert result.capability.tool == "email.send"


def test_require_human_without_approval_fails_closed(tmp_path: Path) -> None:
    broker = _broker(tmp_path)  # default approval raises
    action = ProposedAction(
        tool="email.send",
        arguments={"recipient": "alice@acme.test", "body": "hi"},
        principal="alice",
        task_id="t1",
        reason_code="test",
        input_labels=(_label(),),
        plan_step="s_email",
    )
    with pytest.raises(SecurityViolation, match="human approval"):
        broker.secure_execute(action, plan=_plan())


def test_allow_fetch_mints_capability(tmp_path: Path) -> None:
    broker = _broker(tmp_path)
    action = ProposedAction(
        tool="web.fetch",
        arguments={"url": "https://example.com/x"},
        principal="alice",
        task_id="t1",
        reason_code="test",
        input_labels=(_label(),),
        plan_step="s_fetch",
    )
    result = broker.secure_execute(action, plan=_plan())
    assert result.decision.effect == "allow"
    assert result.decision.rule_id == "read-public-web"
    assert result.capability is not None
    # Token not yet consumed when no executor is wired.
    broker.minter.verify(
        result.capability,
        tool="web.fetch",
        resources=("https://example.com/x",),
    )
