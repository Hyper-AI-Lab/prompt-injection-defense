"""Table-driven policy engine tests (step 3; Kirill example rules)."""

from __future__ import annotations

from pathlib import Path

import pytest

from containment.actions import ProposedAction
from containment.labels import SecurityLabel
from containment.plan import Plan, PlanStep
from containment.policy import PolicyEngine

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "policies" / "default_deny.yaml"


def _trusted(**kwargs) -> SecurityLabel:
    base = dict(
        integrity="trusted",
        confidentiality="private",
        source="user",
        task_id="t1",
        transformations=(),
    )
    base.update(kwargs)
    return SecurityLabel(**base)


def _untrusted(**kwargs) -> SecurityLabel:
    return _trusted(integrity="untrusted", source="web", **kwargs)


def _plan(**kwargs) -> Plan:
    base = dict(
        task_id="t1",
        steps=(
            PlanStep(step_id="s_fetch", tool="web.fetch"),
            PlanStep(step_id="s_email", tool="email.send"),
            PlanStep(step_id="s_wallet", tool="wallet.transfer"),
            PlanStep(step_id="s_post", tool="http.post"),
        ),
        capabilities=frozenset(
            {"web.fetch", "email.send", "wallet.transfer", "http.post"}
        ),
        approved_public_hosts=frozenset({"example.com", "docs.python.org"}),
        approved_recipients=frozenset({"alice@acme.test", "bob@acme.test"}),
        approved_wallets=frozenset({"0xabc"}),
        transaction_limit=100.0,
    )
    base.update(kwargs)
    return Plan(**base)


def _action(tool: str, arguments: dict, labels: tuple, plan_step: str) -> ProposedAction:
    return ProposedAction(
        tool=tool,
        arguments=arguments,
        principal="alice",
        task_id="t1",
        reason_code="test",
        input_labels=labels,
        plan_step=plan_step,
    )


@pytest.fixture(scope="module")
def engine() -> PolicyEngine:
    return PolicyEngine.from_yaml_path(POLICY_PATH)


# Columns: id, tool, arguments, labels, plan_step, auth, expected_effect, expected_rule, mfa
CASES = [
    (
        "allow_https_approved_host",
        "web.fetch",
        {"url": "https://example.com/page"},
        (_trusted(),),
        "s_fetch",
        True,
        "allow",
        "read-public-web",
        False,
    ),
    (
        "deny_http_scheme",
        "web.fetch",
        {"url": "http://example.com/page"},
        (_trusted(),),
        "s_fetch",
        True,
        "deny",
        "default_deny",
        False,
    ),
    (
        "deny_unapproved_host",
        "web.fetch",
        {"url": "https://evil.example/x"},
        (_trusted(),),
        "s_fetch",
        True,
        "deny",
        "default_deny",
        False,
    ),
    (
        "deny_unauthenticated_fetch",
        "web.fetch",
        {"url": "https://example.com/page"},
        (_trusted(),),
        "s_fetch",
        False,
        "deny",
        "default_deny",
        False,
    ),
    (
        "deny_tainted_email",
        "email.send",
        {"recipient": "alice@acme.test", "subject": "hi", "body": "x"},
        (_untrusted(),),
        "s_email",
        True,
        "deny",
        "no-tainted-egress",
        False,
    ),
    (
        "deny_tainted_http_post",
        "http.post",
        {"url": "https://example.com/api"},
        (_untrusted(),),
        "s_post",
        True,
        "deny",
        "no-tainted-egress",
        False,
    ),
    (
        "deny_tainted_wallet",
        "wallet.transfer",
        {"amount": 10, "destination": "0xabc"},
        (_untrusted(),),
        "s_wallet",
        True,
        "deny",
        "no-tainted-egress",
        False,
    ),
    (
        "require_human_trusted_email",
        "email.send",
        {"recipient": "alice@acme.test", "subject": "hi", "body": "hello"},
        (_trusted(confidentiality="private"),),
        "s_email",
        True,
        "require_human",
        "approved-email",
        False,
    ),
    (
        "deny_email_bad_recipient",
        "email.send",
        {"recipient": "eve@evil.test", "subject": "hi", "body": "hello"},
        (_trusted(),),
        "s_email",
        True,
        "deny",
        "default_deny",
        False,
    ),
    (
        "deny_email_identity_body",
        "email.send",
        {"recipient": "alice@acme.test", "subject": "hi", "body": "ssn"},
        (_trusted(confidentiality="identity"),),
        "s_email",
        True,
        "deny",
        "default_deny",
        False,
    ),
    (
        "require_human_mfa_transfer",
        "wallet.transfer",
        {"amount": 50, "destination": "0xabc"},
        (_trusted(),),
        "s_wallet",
        True,
        "require_human",
        "transfer-limit",
        True,
    ),
    (
        "deny_transfer_over_limit",
        "wallet.transfer",
        {"amount": 500, "destination": "0xabc"},
        (_trusted(),),
        "s_wallet",
        True,
        "deny",
        "default_deny",
        False,
    ),
    (
        "deny_unknown_tool",
        "shell.exec",
        {"cmd": "id"},
        (_trusted(),),
        "s_fetch",
        True,
        "deny",
        "default_deny",
        False,
    ),
]


@pytest.mark.parametrize(
    "case_id,tool,arguments,labels,plan_step,auth,effect,rule_id,mfa",
    CASES,
    ids=[c[0] for c in CASES],
)
def test_policy_table(
    engine: PolicyEngine,
    case_id: str,
    tool: str,
    arguments: dict,
    labels: tuple,
    plan_step: str,
    auth: bool,
    effect: str,
    rule_id: str,
    mfa: bool,
) -> None:
    plan = _plan()
    action = _action(tool, arguments, labels, plan_step)
    decision = engine.evaluate(
        action, plan=plan, principal_authenticated=auth
    )
    assert decision.effect == effect, case_id
    assert decision.rule_id == rule_id, case_id
    assert decision.requires_mfa is mfa, case_id


def test_task_mismatch_denied(engine: PolicyEngine) -> None:
    plan = _plan()
    action = ProposedAction(
        tool="web.fetch",
        arguments={"url": "https://example.com/"},
        principal="alice",
        task_id="other",
        reason_code="test",
        input_labels=(_trusted(),),
        plan_step="s_fetch",
    )
    decision = engine.evaluate(action, plan=plan)
    assert decision.effect == "deny"
    assert decision.rule_id == "task_mismatch"


def test_load_rejects_non_deny_default(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("version: 1\ndefault: allow\nrules: []\n", encoding="utf-8")
    with pytest.raises(ValueError, match="default"):
        PolicyEngine.from_yaml_path(path)


def test_capability_missing_blocks_fetch(engine: PolicyEngine) -> None:
    plan = _plan(
        steps=(PlanStep(step_id="s_email", tool="email.send"),),
        capabilities=frozenset({"email.send"}),
        approved_recipients=frozenset({"alice@acme.test"}),
    )
    action = _action(
        "web.fetch",
        {"url": "https://example.com/"},
        (_trusted(),),
        "s_email",
    )
    decision = engine.evaluate(action, plan=plan)
    assert decision.effect == "deny"
    assert decision.rule_id == "default_deny"


def test_input_max_confidentiality_lte_labels_and_args(engine: PolicyEngine) -> None:
    """input.max_confidentiality_lte uses max(labels, optional args fields)."""
    plan = _plan()
    # Labels private + args identity → exceeds private threshold → deny (no match).
    action = _action(
        "email.send",
        {
            "recipient": "alice@acme.test",
            "subject": "hi",
            "body": "x",
            "body_confidentiality": "identity",
        },
        (_trusted(confidentiality="private"),),
        "s_email",
    )
    decision = engine.evaluate(action, plan=plan)
    assert decision.effect == "deny"
    assert decision.rule_id == "default_deny"

    # Alias args.body_confidentiality_lte still works on a custom engine.
    alias_yaml = """
version: 1
default: deny
rules:
  - id: email-alias
    effect: require_human
    tool: email.send
    when:
      args.body_confidentiality_lte: private
      args.recipient_in: task.approved_recipients
"""
    alias_engine = PolicyEngine.from_yaml_text(alias_yaml)
    ok = _action(
        "email.send",
        {"recipient": "alice@acme.test", "body": "x"},
        (_trusted(confidentiality="public"),),
        "s_email",
    )
    d_ok = alias_engine.evaluate(ok, plan=plan)
    assert d_ok.effect == "require_human"
    assert d_ok.rule_id == "email-alias"
