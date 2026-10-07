"""Fixture corpus size and offline eval (step 14)."""

from __future__ import annotations

from pathlib import Path

from containment.eval_runner import iter_fixtures, run_eval

ROOT = Path(__file__).resolve().parents[1] / "fixtures"


def test_corpus_has_at_least_30_each() -> None:
    attacks = list(iter_fixtures(ROOT))
    n_a = sum(1 for c in attacks if c.kind == "attack")
    n_b = sum(1 for c in attacks if c.kind == "benign")
    assert n_a >= 30, n_a
    assert n_b >= 30, n_b


def test_corpus_covers_categories() -> None:
    names = {c.path.name for c in iter_fixtures(ROOT)}
    assert any(n.startswith("direct_") for n in names)
    assert any(n.startswith("indirect_") for n in names)
    assert any(n.startswith("invisible_") or "hidden_" in n for n in names)
    assert any(n.startswith("encoded_") or "base64" in n for n in names)
    # Benign trigger-word cases
    assert "benign_system_prompt_docs.txt" in names
    assert "benign_act_as_roleplay.txt" in names


def test_offline_eval_runs_and_control() -> None:
    on, on_out = run_eval(fixtures_root=ROOT, policy_enabled=True)
    off, _ = run_eval(fixtures_root=ROOT, policy_enabled=False)
    assert on.n_attack >= 30 and on.n_benign >= 30
    assert off.asr > on.asr
    assert off.asr == 1.0
    assert 0.0 <= on.asr <= 1.0
    assert 0.0 <= on.fpr <= 1.0
    assert 0.0 <= on.utility <= 1.0
    assert 0.0 <= on.detector_block_rate <= 1.0
    assert 0.0 <= on.policy_block_rate <= 1.0
    # Honesty: detector rate is not a silent constant identical deny for every attack.
    det = [o.detector_blocked for o in on_out if o.case.kind == "attack"]
    assert any(det) and not all(det), "detector_blocked must vary across attacks"
    assert off.policy_block_rate == 0.0
