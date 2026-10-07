"""url_guard SSRF helpers (enterprise step 4)."""

from __future__ import annotations

from pathlib import Path

import pytest

from containment.actions import ProposedAction
from containment.audit import AuditLog
from containment.broker import SecurityViolation, ToolBroker
from containment.capability import CapabilityMinter
from containment.labels import SecurityLabel
from containment.plan import Plan, PlanStep
from containment.policy import PolicyEngine
from containment.url_guard import (
    UrlGuardError,
    check_public_only,
    check_url_for_tool,
    is_blocked_ip_literal,
    parse_egress_url,
)

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "policies" / "default_deny.yaml"


def test_parse_rejects_userinfo() -> None:
    with pytest.raises(UrlGuardError, match="userinfo") as ei:
        parse_egress_url("https://user:pass@example.com/x")
    assert ei.value.code == "userinfo"


def test_parse_rejects_http_by_default() -> None:
    with pytest.raises(UrlGuardError, match="scheme") as ei:
        parse_egress_url("http://example.com/")
    assert ei.value.code == "bad_scheme"


def test_decimal_loopback_blocked() -> None:
    assert is_blocked_ip_literal("2130706433") is True  # 127.0.0.1
    with pytest.raises(UrlGuardError, match="public") as ei:
        check_public_only("https://2130706433/")
    assert ei.value.code == "not_public"


def test_ipv6_loopback_blocked() -> None:
    assert is_blocked_ip_literal("::1") is True


def test_metadata_ip_blocked() -> None:
    assert is_blocked_ip_literal("169.254.169.254") is True
    with pytest.raises(UrlGuardError):
        check_public_only("https://169.254.169.254/latest")


def test_cgnat_literal_blocked() -> None:
    assert is_blocked_ip_literal("100.64.1.1") is True
    with pytest.raises(UrlGuardError) as ei:
        check_public_only("https://100.64.1.1/")
    assert ei.value.code == "not_public"


def test_public_hostname_ok() -> None:
    parsed = check_url_for_tool(
        "https://example.com/a",
        host_allowlist={"example.com"},
        network="public_only",
    )
    assert parsed.host == "example.com"


def test_broker_rejects_decimal_ip(tmp_path: Path) -> None:
    broker = ToolBroker(
        policy=PolicyEngine.from_yaml_path(POLICY_PATH),
        audit=AuditLog(tmp_path / "a.jsonl"),
        minter=CapabilityMinter(secret=b"x" * 32),
        known_tools=frozenset({"web.fetch"}),
    )
    plan = Plan(
        task_id="t1",
        steps=(PlanStep(step_id="s_fetch", tool="web.fetch"),),
        capabilities=frozenset({"web.fetch"}),
        approved_public_hosts=frozenset({"2130706433"}),
    )
    action = ProposedAction(
        tool="web.fetch",
        arguments={"url": "https://2130706433/"},
        principal="alice",
        task_id="t1",
        reason_code="test",
        input_labels=(
            SecurityLabel(
                integrity="trusted",
                confidentiality="public",
                source="user",
                task_id="t1",
            ),
        ),
        plan_step="s_fetch",
    )
    with pytest.raises(SecurityViolation) as ei:
        broker.secure_execute(action, plan=plan)
    # Either host allowlist miss path won't apply (host is allowlisted) → limits
    assert ei.value.decision.rule_id in {"limits_violation", "default_deny"}
    if ei.value.decision.rule_id == "limits_violation":
        assert "public_only" in ei.value.decision.reason


def test_policy_rejects_userinfo_host_predicate() -> None:
    engine = PolicyEngine.from_yaml_path(POLICY_PATH)
    plan = Plan(
        task_id="t1",
        steps=(PlanStep(step_id="s_fetch", tool="web.fetch"),),
        capabilities=frozenset({"web.fetch"}),
        approved_public_hosts=frozenset({"example.com"}),
    )
    action = ProposedAction(
        tool="web.fetch",
        arguments={"url": "https://user:pass@example.com/"},
        principal="alice",
        task_id="t1",
        reason_code="test",
        input_labels=(
            SecurityLabel(
                integrity="trusted",
                confidentiality="public",
                source="user",
                task_id="t1",
            ),
        ),
        plan_step="s_fetch",
    )
    decision = engine.evaluate(action, plan=plan, principal_authenticated=True)
    assert decision.effect == "deny"
