"""Derived content (summaries, compaction) keeps the lowest trust of its inputs."""

from __future__ import annotations

import pytest

from containment import resources
from containment.actions import ProposedAction
from containment.ingest import ingest
from containment.labels import SecurityLabel, derive_label
from containment.plan import Plan, PlanStep
from containment.policy import PolicyEngine


def _label(integrity: str, confidentiality: str = "public", *steps: str) -> SecurityLabel:
    return SecurityLabel(
        integrity=integrity,  # type: ignore[arg-type]
        confidentiality=confidentiality,  # type: ignore[arg-type]
        source=f"src-{integrity}",
        task_id="t1",
        transformations=steps,
    )


def test_one_untrusted_input_makes_derived_untrusted() -> None:
    out = derive_label(
        [_label("trusted"), _label("untrusted")], source="summary", task_id="t1",
        transformation="summarize",
    )
    assert out.integrity == "untrusted"


def test_all_trusted_inputs_stay_trusted() -> None:
    out = derive_label(
        [_label("trusted"), _label("trusted")], source="summary", task_id="t1",
        transformation="summarize",
    )
    assert out.integrity == "trusted"


def test_highest_confidentiality_and_merged_transformations() -> None:
    out = derive_label(
        [
            _label("trusted", "private", "normalize", "cascade"),
            _label("trusted", "identity", "cascade", "quarantine_extract"),
            _label("trusted", "public"),
        ],
        source="summary",
        task_id="t1",
        transformation="summarize",
    )
    assert out.confidentiality == "identity"
    assert out.transformations == ("normalize", "cascade", "quarantine_extract", "summarize")
    assert (out.source, out.task_id) == ("summary", "t1")


def test_derive_rejects_empty_and_non_labels() -> None:
    with pytest.raises(ValueError):
        derive_label([], source="s", task_id="t1", transformation="summarize")
    with pytest.raises(TypeError):
        derive_label(["trusted"], source="s", task_id="t1", transformation="x")  # type: ignore[list-item]
    with pytest.raises(ValueError):
        derive_label([_label("trusted")], source="s", task_id="t1", transformation=" ")


def test_summary_of_untrusted_ingest_cannot_be_ingested_as_trusted() -> None:
    page = ingest("Quarterly numbers look fine.", source="web:example.com", task_id="t1")
    assert page.label.integrity == "untrusted"
    summary = ingest(
        "Summary: numbers look fine.",
        source="agent:summary",
        task_id="t1",
        integrity="trusted",
        confidentiality="private",
        derived_from=(page.label,),
    )
    assert summary.label.integrity == "untrusted"
    assert summary.label.confidentiality == "private"
    assert summary.label.transformations[-1] == "derived"


def test_ingest_without_parents_keeps_given_integrity() -> None:
    note = ingest("Owner note.", source="owner", task_id="t1", integrity="trusted")
    assert note.label.integrity == "trusted"
    assert "derived" not in note.label.transformations


def _email_effect(label: SecurityLabel) -> str:
    engine = PolicyEngine.from_yaml_path(resources.default_policy_path())
    action = ProposedAction(
        tool="email.send",
        arguments={"recipient": "owner@example.com", "subject": "s", "body": "b"},
        principal="agent",
        task_id="t1",
        reason_code="send-summary",
        input_labels=(label,),
        plan_step="s1",
    )
    plan = Plan(
        task_id="t1",
        steps=(PlanStep(step_id="s1", tool="email.send"),),
        capabilities=frozenset({"email.send"}),
        approved_recipients=frozenset({"owner@example.com"}),
    )
    return engine.evaluate(action, plan=plan, principal_authenticated=True).effect


def test_policy_denies_egress_of_summary_derived_from_untrusted() -> None:
    trusted = _label("trusted")
    assert _email_effect(trusted) != "deny"
    derived = derive_label(
        [trusted, _label("untrusted")], source="summary", task_id="t1",
        transformation="summarize",
    )
    assert _email_effect(derived) == "deny"
