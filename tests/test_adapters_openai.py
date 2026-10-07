"""brokered_tool decorator: allow + SecurityViolation on deny."""

from __future__ import annotations

from pathlib import Path

import pytest

from containment.adapters import BrokeredRegistry, brokered_tool
from containment.audit import AuditLog
from containment.broker import SecurityViolation, ToolBroker
from containment.capability import CapabilityMinter
from containment.labels import SecurityLabel
from containment.plan import Plan, PlanStep
from containment.policy import PolicyEngine

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "policies" / "default_deny.yaml"


def _label(*, integrity: str = "trusted") -> SecurityLabel:
    return SecurityLabel(
        integrity=integrity,  # type: ignore[arg-type]
        confidentiality="private",
        source="user" if integrity == "trusted" else "web",
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


def _registry(tmp_path: Path) -> BrokeredRegistry:
    broker = ToolBroker(
        policy=PolicyEngine.from_yaml_path(POLICY_PATH),
        audit=AuditLog(tmp_path / "audit.jsonl"),
        minter=CapabilityMinter(secret=b"adapter-openai-test-secret-32b!!"),
        known_tools=frozenset({"web.fetch", "email.send"}),
    )
    return BrokeredRegistry(
        broker,
        _plan(),
        principal="alice",
        task_id="t1",
        reason_code="test",
        plan_step="s_fetch",
    )


def test_brokered_tool_allow(tmp_path: Path) -> None:
    reg = _registry(tmp_path)

    @brokered_tool(reg, tool="web.fetch")
    def fetch_url(url: str) -> str:
        return f"got:{url}"

    out = fetch_url(url="https://example.com/a", _input_labels=(_label(),))
    assert out == "got:https://example.com/a"


def test_brokered_tool_deny_raises(tmp_path: Path) -> None:
    reg = _registry(tmp_path)
    fired = {"n": 0}

    @brokered_tool(reg, name="email.send")
    def send_email(recipient: str, body: str = "") -> str:
        fired["n"] += 1
        return "sent"

    with pytest.raises(SecurityViolation) as excinfo:
        send_email(
            recipient="alice@acme.test",
            body="hi",
            _input_labels=(_label(integrity="untrusted"),),
            _plan_step="s_email",
        )
    assert excinfo.value.decision.effect == "deny"
    assert excinfo.value.decision.rule_id == "no-tainted-egress"
    assert fired["n"] == 0


def test_brokered_tool_rejects_positional(tmp_path: Path) -> None:
    reg = _registry(tmp_path)

    @brokered_tool(reg)
    def web_fetch(url: str) -> str:
        return url

    with pytest.raises(TypeError, match="keyword arguments only"):
        web_fetch("https://example.com")  # type: ignore[misc]
