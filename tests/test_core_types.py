"""Unit tests for frozen core types (step 2)."""

from __future__ import annotations

import pytest

from containment import (
    IntentEnvelope,
    Plan,
    PlanStep,
    PolicyDecision,
    ProposedAction,
    SecurityLabel,
    TraceEvent,
)


def _label(**kwargs) -> SecurityLabel:
    base = dict(
        integrity="trusted",
        confidentiality="private",
        source="user",
        task_id="t1",
        transformations=(),
    )
    base.update(kwargs)
    return SecurityLabel(**base)


class TestSecurityLabel:
    def test_frozen(self) -> None:
        label = _label()
        with pytest.raises(AttributeError):
            label.integrity = "untrusted"  # type: ignore[misc]

    def test_rejects_bad_integrity(self) -> None:
        with pytest.raises(ValueError, match="integrity"):
            _label(integrity="maybe")  # type: ignore[arg-type]

    def test_rejects_bad_confidentiality(self) -> None:
        with pytest.raises(ValueError, match="confidentiality"):
            _label(confidentiality="secret")  # type: ignore[arg-type]

    def test_rejects_empty_source(self) -> None:
        with pytest.raises(ValueError, match="source"):
            _label(source="")

    def test_rejects_empty_task_id(self) -> None:
        with pytest.raises(ValueError, match="task_id"):
            _label(task_id="  ")

    def test_rejects_non_tuple_transformations(self) -> None:
        with pytest.raises(TypeError, match="transformations"):
            SecurityLabel(
                integrity="trusted",
                confidentiality="public",
                source="web",
                task_id="t1",
                transformations=["ocr"],  # type: ignore[arg-type]
            )


class TestIntentEnvelope:
    def test_frozen_and_valid(self) -> None:
        env = IntentEnvelope(
            task_id="t1",
            tenant="acme",
            user="alice",
            scope=frozenset({"web.fetch"}),
            risk_budget="low",
        )
        assert env.principal_authenticated is True
        with pytest.raises(AttributeError):
            env.user = "bob"  # type: ignore[misc]

    def test_rejects_non_frozenset_scope(self) -> None:
        with pytest.raises(TypeError, match="scope"):
            IntentEnvelope(
                task_id="t1",
                tenant="acme",
                user="alice",
                scope={"web.fetch"},  # type: ignore[arg-type]
                risk_budget="low",
            )

    def test_rejects_empty_user(self) -> None:
        with pytest.raises(ValueError, match="user"):
            IntentEnvelope(
                task_id="t1",
                tenant="acme",
                user="",
                scope=frozenset(),
                risk_budget="low",
            )


class TestPlan:
    def test_valid_plan(self) -> None:
        plan = Plan(
            task_id="t1",
            steps=(PlanStep(step_id="s1", tool="web.fetch"),),
            capabilities=frozenset({"web.fetch"}),
        )
        assert plan.step_by_id("s1").tool == "web.fetch"
        assert plan.has_capability("web.fetch")

    def test_rejects_empty_steps(self) -> None:
        with pytest.raises(ValueError, match="steps"):
            Plan(task_id="t1", steps=(), capabilities=frozenset({"web.fetch"}))

    def test_rejects_duplicate_step_ids(self) -> None:
        with pytest.raises(ValueError, match="duplicate"):
            Plan(
                task_id="t1",
                steps=(
                    PlanStep(step_id="s1", tool="web.fetch"),
                    PlanStep(step_id="s1", tool="email.send"),
                ),
                capabilities=frozenset({"web.fetch", "email.send"}),
            )

    def test_rejects_step_tool_outside_capabilities(self) -> None:
        with pytest.raises(ValueError, match="capabilities"):
            Plan(
                task_id="t1",
                steps=(PlanStep(step_id="s1", tool="email.send"),),
                capabilities=frozenset({"web.fetch"}),
            )

    def test_rejects_negative_transaction_limit(self) -> None:
        with pytest.raises(ValueError, match="transaction_limit"):
            Plan(
                task_id="t1",
                steps=(PlanStep(step_id="s1", tool="wallet.transfer"),),
                capabilities=frozenset({"wallet.transfer"}),
                transaction_limit=-1.0,
            )

    def test_unknown_step_raises(self) -> None:
        plan = Plan(
            task_id="t1",
            steps=(PlanStep(step_id="s1", tool="web.fetch"),),
            capabilities=frozenset({"web.fetch"}),
        )
        with pytest.raises(KeyError):
            plan.step_by_id("missing")


class TestProposedAction:
    def test_arguments_are_immutable(self) -> None:
        action = ProposedAction(
            tool="web.fetch",
            arguments={"url": "https://example.com"},
            principal="alice",
            task_id="t1",
            reason_code="user_request",
            input_labels=(_label(),),
            plan_step="s1",
        )
        with pytest.raises(TypeError):
            action.arguments["url"] = "https://evil.example"  # type: ignore[index]

    def test_rejects_non_label_inputs(self) -> None:
        with pytest.raises(TypeError, match="SecurityLabel"):
            ProposedAction(
                tool="web.fetch",
                arguments={},
                principal="alice",
                task_id="t1",
                reason_code="x",
                input_labels=("not-a-label",),  # type: ignore[arg-type]
                plan_step="s1",
            )

    def test_any_untrusted(self) -> None:
        action = ProposedAction(
            tool="email.send",
            arguments={},
            principal="alice",
            task_id="t1",
            reason_code="x",
            input_labels=(_label(integrity="untrusted", source="web"),),
            plan_step="s1",
        )
        assert action.any_untrusted() is True
        assert action.all_trusted() is False


class TestPolicyDecision:
    def test_valid_effects(self) -> None:
        for effect in ("allow", "deny", "require_human"):
            d = PolicyDecision(effect=effect, rule_id="r1")  # type: ignore[arg-type]
            assert d.effect == effect

    def test_rejects_unknown_effect(self) -> None:
        with pytest.raises(ValueError, match="effect"):
            PolicyDecision(effect="permit", rule_id="r1")  # type: ignore[arg-type]

    def test_mfa_only_with_require_human(self) -> None:
        with pytest.raises(ValueError, match="requires_mfa"):
            PolicyDecision(effect="allow", rule_id="r1", requires_mfa=True)
        ok = PolicyDecision(
            effect="require_human", rule_id="r1", requires_mfa=True
        )
        assert ok.requires_mfa is True


class TestTraceEvent:
    def test_detail_immutable(self) -> None:
        ev = TraceEvent(
            event_id="e1",
            timestamp="2026-10-07T10:00:00+09:00",
            kind="policy",
            task_id="t1",
            detail={"effect": "deny"},
        )
        with pytest.raises(TypeError):
            ev.detail["effect"] = "allow"  # type: ignore[index]

    def test_rejects_empty_kind(self) -> None:
        with pytest.raises(ValueError, match="kind"):
            TraceEvent(
                event_id="e1",
                timestamp="2026-10-07T10:00:00+09:00",
                kind="",
                task_id="t1",
            )
