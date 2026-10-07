"""Detector cascade tests (step 7)."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from containment.detectors.base import (
    CascadeResult,
    NoOpContextualDetector,
    RiskSignal,
)
from containment.detectors.cascade import (
    PRIVILEGED_SINKS,
    DetectorCascade,
    PassthroughStage1,
    privileged_sink_fail_closed,
)
from containment.detectors.rules import Finding

ROOT = Path(__file__).resolve().parents[1]
ATTACKS = ROOT / "fixtures" / "attacks"


class FakeStage1:
    def __init__(self, score: float = 0.9, label: str = "malicious") -> None:
        self.name = "fake_stage1"
        self._score = score
        self._label = label

    def scan(self, text: str) -> RiskSignal:
        return RiskSignal(
            stage="stage1",
            score=self._score,
            label=self._label,  # type: ignore[arg-type]
            detector=self.name,
            detail={"text_len": len(text)},
        )


class RecordingStage2:
    def __init__(self) -> None:
        self.calls: list[tuple[str, Mapping[str, Any]]] = []

    def scan_context(
        self, text: str, *, context: Mapping[str, Any]
    ) -> RiskSignal:
        self.calls.append((text, context))
        return RiskSignal(
            stage="stage2",
            score=0.2,
            label="inconclusive",
            detector="recording_stage2",
        )


def test_cascade_returns_risk_not_authorization() -> None:
    cascade = DetectorCascade(stage1=FakeStage1())
    result = cascade.scan("hello")
    assert isinstance(result, CascadeResult)
    assert result.max_score >= 0.0
    # CascadeResult has no allow/deny/authorize fields.
    assert not hasattr(result, "effect")
    assert not hasattr(result, "authorize")
    assert not hasattr(result, "decision")
    assert {s.stage for s in result.signals} == {"stage0", "stage1"}


def test_cascade_never_imports_or_calls_policy() -> None:
    import containment.detectors.cascade as cascade_mod

    # No policy/broker modules imported — docstring may mention them.
    assert not hasattr(cascade_mod, "PolicyEngine")
    assert not hasattr(cascade_mod, "ToolBroker")
    mod_file = Path(cascade_mod.__file__).read_text(encoding="utf-8")
    for banned in (
        "from containment.policy",
        "import containment.policy",
        "from containment.broker",
        "import containment.broker",
        "policy.evaluate",
        "secure_execute(",
    ):
        assert banned not in mod_file, banned


def test_noop_contextual_returns_inconclusive() -> None:
    noop = NoOpContextualDetector()
    signal = noop.scan_context("x", context={"tool": "web.fetch"})
    assert signal.label == "inconclusive"
    assert signal.stage == "stage2"
    assert signal.score == 0.0


def test_stage2_optional_hook_runs_when_enabled() -> None:
    stage2 = RecordingStage2()
    cascade = DetectorCascade(
        stage1=FakeStage1(score=0.1, label="benign"),
        stage2=stage2,
        run_stage2=True,
    )
    result = cascade.scan("hi", context={"k": 1})
    assert len(stage2.calls) == 1
    assert any(s.stage == "stage2" for s in result.signals)


def test_stage2_skipped_by_default() -> None:
    stage2 = RecordingStage2()
    cascade = DetectorCascade(stage1=FakeStage1(), stage2=stage2)
    result = cascade.scan("hi")
    assert stage2.calls == []
    assert all(s.stage != "stage2" for s in result.signals)


def test_attack_fixture_elevates_risk() -> None:
    text = (ATTACKS / "hidden_zwsp.txt").read_text(encoding="utf-8")
    cascade = DetectorCascade(stage1=PassthroughStage1())
    result = cascade.scan(text)
    assert result.max_score > 0.0
    assert result.aggregate_label in ("suspicious", "malicious")


def test_stage1_error_becomes_error_signal() -> None:
    class Boom:
        name = "boom"

        def scan(self, text: str) -> RiskSignal:
            raise RuntimeError("weights missing")

    cascade = DetectorCascade(stage1=Boom())  # type: ignore[arg-type]
    result = cascade.scan("x")
    assert any(s.label == "error" and s.stage == "stage1" for s in result.signals)
    assert result.aggregate_label == "error"


def test_privileged_sink_fail_closed_advisory() -> None:
    cascade = DetectorCascade(stage1=FakeStage1(score=0.0, label="benign"))
    benign = cascade.scan("hello world")
    # Force inconclusive aggregate via stage1 error path semantics:
    bad = DetectorCascade(stage1=FakeStage1(score=1.0, label="error")).scan("x")
    assert "email.send" in PRIVILEGED_SINKS
    assert privileged_sink_fail_closed("email.send", bad) is True
    assert privileged_sink_fail_closed("web.fetch", bad) is False
    # Benign low score: do not fail-closed solely from cascade helper.
    assert privileged_sink_fail_closed("email.send", benign) is False


def test_risk_signal_findings_round_trip() -> None:
    finding = Finding(kind="invisible_char", message="zwsp", offset=1)
    signal = RiskSignal(
        stage="stage0",
        score=0.5,
        label="suspicious",
        detector="rules",
        findings=(finding,),
    )
    assert signal.findings[0].kind == "invisible_char"
