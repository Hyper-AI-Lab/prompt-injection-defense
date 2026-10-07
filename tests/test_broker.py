"""Tool broker secure_execute tests (step 5)."""

from __future__ import annotations

from pathlib import Path

import pytest

from containment.actions import PolicyDecision, ProposedAction
from containment.audit import AuditLog
from containment.broker import ApprovalOutcome, SecurityViolation, ToolBroker
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


def test_empty_input_labels_privileged_email_denied(tmp_path: Path) -> None:
    """H1: empty labels on privileged sink must deny (not require_human/mint)."""
    calls: list[object] = []

    def approval(action: ProposedAction, decision: PolicyDecision) -> None:
        calls.append((action, decision))

    broker = _broker(tmp_path, approval=approval)
    action = ProposedAction(
        tool="email.send",
        arguments={"recipient": "alice@acme.test", "body": "hi"},
        principal="alice",
        task_id="t1",
        reason_code="test",
        input_labels=(),
        plan_step="s_email",
    )
    with pytest.raises(SecurityViolation) as excinfo:
        broker.secure_execute(action, plan=_plan())
    assert excinfo.value.decision.effect == "deny"
    assert excinfo.value.decision.rule_id == "empty_input_labels"
    assert calls == []
    events = broker.audit.read_all()
    assert len(events) == 1
    assert events[0].detail["decision"]["rule_id"] == "empty_input_labels"


def test_empty_input_labels_http_post_denied(tmp_path: Path) -> None:
    broker = _broker(tmp_path)
    action = ProposedAction(
        tool="http.post",
        arguments={"url": "https://example.com/hook"},
        principal="alice",
        task_id="t1",
        reason_code="test",
        input_labels=(),
        plan_step="s_post",
    )
    with pytest.raises(SecurityViolation) as excinfo:
        broker.secure_execute(action, plan=_plan())
    assert excinfo.value.decision.rule_id == "empty_input_labels"


def test_detector_fail_closed_cascade_blocks_privileged(tmp_path: Path) -> None:
    """H2: cascade risk on privileged sink denies even if policy would require_human."""
    from containment.detectors.base import CascadeResult, RiskSignal

    def approval(action: ProposedAction, decision: PolicyDecision) -> None:
        return None

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
    cascade = CascadeResult(
        signals=(
            RiskSignal(
                stage="stage1",
                score=0.95,
                label="malicious",
                detector="test",
            ),
        ),
        max_score=0.95,
        aggregate_label="malicious",
        normalized_text="x",
        original_sha256="a" * 64,
    )
    with pytest.raises(SecurityViolation) as excinfo:
        broker.secure_execute(action, plan=_plan(), cascade=cascade)
    assert excinfo.value.decision.rule_id == "detector_fail_closed"
    assert excinfo.value.decision.effect == "deny"


def test_fail_closed_privileged_flag_blocks_email(tmp_path: Path) -> None:
    """H2: fail_closed_privileged=True blocks privileged sinks without cascade."""

    def approval(action: ProposedAction, decision: PolicyDecision) -> None:
        return None

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
    with pytest.raises(SecurityViolation) as excinfo:
        broker.secure_execute(
            action, plan=_plan(), fail_closed_privileged=True
        )
    assert excinfo.value.decision.rule_id == "detector_fail_closed"


def test_fail_closed_does_not_block_web_fetch(tmp_path: Path) -> None:
    """Non-privileged tools still allow under fail_closed_privileged."""
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
    result = broker.secure_execute(
        action, plan=_plan(), fail_closed_privileged=True
    )
    assert result.decision.effect == "allow"
    assert result.capability is not None


def test_plan_step_unknown_denied(tmp_path: Path) -> None:
    """M1: bogus plan_step id is denied."""
    broker = _broker(tmp_path)
    action = ProposedAction(
        tool="email.send",
        arguments={"recipient": "alice@acme.test", "body": "hi"},
        principal="alice",
        task_id="t1",
        reason_code="test",
        input_labels=(_label(confidentiality="private"),),
        plan_step="not_in_plan",
    )
    with pytest.raises(SecurityViolation) as excinfo:
        broker.secure_execute(action, plan=_plan())
    assert excinfo.value.decision.rule_id == "plan_step_unknown"


def test_plan_step_tool_mismatch_denied(tmp_path: Path) -> None:
    """M1: plan_step exists but bound to a different tool."""
    def approval(action: ProposedAction, decision: PolicyDecision) -> None:
        return None

    broker = _broker(tmp_path, approval=approval)
    action = ProposedAction(
        tool="email.send",
        arguments={"recipient": "alice@acme.test", "body": "hi"},
        principal="alice",
        task_id="t1",
        reason_code="test",
        input_labels=(_label(confidentiality="private"),),
        plan_step="s_fetch",  # bound to web.fetch
    )
    with pytest.raises(SecurityViolation) as excinfo:
        broker.secure_execute(action, plan=_plan())
    assert excinfo.value.decision.rule_id == "plan_step_tool_mismatch"


def test_plan_expired_denied(tmp_path: Path) -> None:
    """M4: expired plan.expiry_unix is denied."""
    import time

    def approval(action: ProposedAction, decision: PolicyDecision) -> None:
        return None

    broker = _broker(tmp_path, approval=approval)
    plan = Plan(
        task_id="t1",
        steps=(
            PlanStep(step_id="s_fetch", tool="web.fetch"),
            PlanStep(step_id="s_email", tool="email.send"),
            PlanStep(step_id="s_post", tool="http.post"),
        ),
        capabilities=frozenset({"web.fetch", "email.send", "http.post"}),
        approved_public_hosts=frozenset({"example.com"}),
        approved_recipients=frozenset({"alice@acme.test"}),
        expiry_unix=time.time() - 10,
    )
    action = ProposedAction(
        tool="email.send",
        arguments={"recipient": "alice@acme.test", "body": "hi"},
        principal="alice",
        task_id="t1",
        reason_code="test",
        input_labels=(_label(confidentiality="private"),),
        plan_step="s_email",
    )
    with pytest.raises(SecurityViolation) as excinfo:
        broker.secure_execute(action, plan=plan)
    assert excinfo.value.decision.rule_id == "plan_expired"


def test_approved_email_passes_display_to_approval(tmp_path: Path) -> None:
    """H4/M2: rule display is on PolicyDecision for the approval hook."""
    seen: list[PolicyDecision] = []

    def approval(action: ProposedAction, decision: PolicyDecision) -> None:
        seen.append(decision)

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
    broker.secure_execute(action, plan=_plan())
    assert len(seen) == 1
    assert seen[0].display == (
        "resolved_recipient",
        "resolved_subject",
        "resolved_body",
        "data_sources",
    )


def test_requires_mfa_without_verification_denied(tmp_path: Path) -> None:
    """M2: requires_mfa fails closed when approval does not verify MFA."""

    def approval_no_mfa(action: ProposedAction, decision: PolicyDecision) -> None:
        return None

    plan = Plan(
        task_id="t1",
        steps=(
            PlanStep(step_id="s_fetch", tool="web.fetch"),
            PlanStep(step_id="s_email", tool="email.send"),
            PlanStep(step_id="s_post", tool="http.post"),
            PlanStep(step_id="s_wallet", tool="wallet.transfer"),
        ),
        capabilities=frozenset(
            {"web.fetch", "email.send", "http.post", "wallet.transfer"}
        ),
        approved_public_hosts=frozenset({"example.com"}),
        approved_recipients=frozenset({"alice@acme.test"}),
        approved_wallets=frozenset({"0xabc"}),
        transaction_limit=100.0,
    )
    broker = _broker(tmp_path, approval=approval_no_mfa)
    action = ProposedAction(
        tool="wallet.transfer",
        arguments={"amount": 50.0, "destination": "0xabc"},
        principal="alice",
        task_id="t1",
        reason_code="test",
        input_labels=(_label(integrity="trusted"),),
        plan_step="s_wallet",
    )
    with pytest.raises(SecurityViolation) as excinfo:
        broker.secure_execute(action, plan=plan)
    assert excinfo.value.decision.rule_id == "mfa_required"
    assert excinfo.value.decision.effect == "deny"


def test_requires_mfa_with_verification_mints(tmp_path: Path) -> None:
    """M2: MFA-verified approval allows mint for wallet.transfer."""

    def approval_mfa(
        action: ProposedAction, decision: PolicyDecision
    ) -> ApprovalOutcome:
        assert decision.requires_mfa is True
        return ApprovalOutcome(mfa_verified=True)

    plan = Plan(
        task_id="t1",
        steps=(
            PlanStep(step_id="s_fetch", tool="web.fetch"),
            PlanStep(step_id="s_email", tool="email.send"),
            PlanStep(step_id="s_post", tool="http.post"),
            PlanStep(step_id="s_wallet", tool="wallet.transfer"),
        ),
        capabilities=frozenset(
            {"web.fetch", "email.send", "http.post", "wallet.transfer"}
        ),
        approved_public_hosts=frozenset({"example.com"}),
        approved_recipients=frozenset({"alice@acme.test"}),
        approved_wallets=frozenset({"0xabc"}),
        transaction_limit=100.0,
    )
    broker = _broker(tmp_path, approval=approval_mfa)
    action = ProposedAction(
        tool="wallet.transfer",
        arguments={"amount": 50.0, "destination": "0xabc"},
        principal="alice",
        task_id="t1",
        reason_code="test",
        input_labels=(_label(integrity="trusted"),),
        plan_step="s_wallet",
    )
    result = broker.secure_execute(action, plan=plan)
    assert result.capability is not None
    assert result.decision.requires_mfa is True


def test_allow_fetch_exposes_limits_on_decision(tmp_path: Path) -> None:
    """H4: matched rule limits are attached to the decision (not silent)."""
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
    assert result.decision.limits is not None
    assert result.decision.limits["max_bytes"] == 2000000
    assert result.decision.limits["redirects"] == 0
    assert result.decision.limits["network"] == "public_only"


def test_limits_max_bytes_denies_oversized_payload(tmp_path: Path) -> None:
    broker = _broker(tmp_path)
    action = ProposedAction(
        tool="web.fetch",
        arguments={"url": "https://example.com/x", "body": "x" * 2_000_001},
        principal="alice",
        task_id="t1",
        reason_code="test",
        input_labels=(_label(),),
        plan_step="s_fetch",
    )
    with pytest.raises(SecurityViolation) as excinfo:
        broker.secure_execute(action, plan=_plan())
    assert excinfo.value.decision.rule_id == "limits_violation"
    assert "max_bytes" in excinfo.value.decision.reason


def test_limits_redirects_zero_denies_allow_redirects(tmp_path: Path) -> None:
    broker = _broker(tmp_path)
    action = ProposedAction(
        tool="web.fetch",
        arguments={"url": "https://example.com/x", "allow_redirects": True},
        principal="alice",
        task_id="t1",
        reason_code="test",
        input_labels=(_label(),),
        plan_step="s_fetch",
    )
    with pytest.raises(SecurityViolation) as excinfo:
        broker.secure_execute(action, plan=_plan())
    assert excinfo.value.decision.rule_id == "limits_violation"
    assert "allow_redirects" in excinfo.value.decision.reason


def test_limits_network_public_only_denies_private_ip(tmp_path: Path) -> None:
    broker = _broker(tmp_path)
    plan = Plan(
        task_id="t1",
        steps=(
            PlanStep(step_id="s_fetch", tool="web.fetch"),
            PlanStep(step_id="s_email", tool="email.send"),
            PlanStep(step_id="s_post", tool="http.post"),
        ),
        capabilities=frozenset({"web.fetch", "email.send", "http.post"}),
        approved_public_hosts=frozenset({"example.com", "10.0.0.1"}),
        approved_recipients=frozenset({"alice@acme.test"}),
    )
    action = ProposedAction(
        tool="web.fetch",
        arguments={"url": "https://10.0.0.1/secret"},
        principal="alice",
        task_id="t1",
        reason_code="test",
        input_labels=(_label(),),
        plan_step="s_fetch",
    )
    with pytest.raises(SecurityViolation) as excinfo:
        broker.secure_execute(action, plan=plan)
    assert excinfo.value.decision.rule_id == "limits_violation"
    assert "public_only" in excinfo.value.decision.reason
