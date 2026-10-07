"""Detector cascade: Stage0 → Stage1 → optional Stage2.

The cascade never authorizes. It only returns risk signals.
Stage3 is policy and lives outside this module — the cascade must not
call ``PolicyEngine`` or ``ToolBroker``.

Fail-closed integration note (privileged sinks)
-----------------------------------------------
When Stage-1 weights are unavailable and a RulesOnly / inconclusive path
is selected, the *broker* must fail closed for privileged tools
(``email.send``, ``http.post``, wallet, etc.): detector uncertainty is
not an allow. See ``privileged_sink_fail_closed`` and broker docs.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from containment.detectors.base import (
    CascadeResult,
    ContextualDetector,
    NoOpContextualDetector,
    RiskLabel,
    RiskSignal,
    Stage1Detector,
    label_from_score,
)
from containment.detectors.rules import RulesDetector, scan_stage0

# Tools that must not proceed on detector error / missing Stage-1 weights
# without an explicit policy allow + independent approval path.
PRIVILEGED_SINKS: frozenset[str] = frozenset(
    {
        "email.send",
        "http.post",
        "wallet.transfer",
        "shell.exec",
        "file.write",
    }
)


def privileged_sink_fail_closed(tool: str, cascade: CascadeResult) -> bool:
    """Return True when a privileged sink should be blocked on cascade risk.

    Used by broker/ingest integration: if Stage-1 is missing/errored or the
    aggregate looks malicious/suspicious/error, privileged tools fail closed.
    This helper does **not** authorize; it only advises the reference monitor.
    """
    if tool not in PRIVILEGED_SINKS:
        return False
    if cascade.aggregate_label in ("malicious", "suspicious", "error", "inconclusive"):
        return True
    if cascade.max_score >= 0.4:
        return True
    return False


class PassthroughStage1:
    """Stage-1 adapter that mirrors Stage-0 risk when no ML model is loaded."""

    def __init__(self, *, name: str = "rules_only_stage1") -> None:
        self.name = name

    def scan(self, text: str) -> RiskSignal:
        stage0 = scan_stage0(text)
        return RiskSignal(
            stage="stage1",
            score=stage0.risk_score,
            label=label_from_score(stage0.risk_score),
            detector=self.name,
            findings=stage0.findings,
            detail={"source": "stage0_mirror"},
        )


def _aggregate_label(signals: list[RiskSignal]) -> RiskLabel:
    priority = {
        "error": 5,
        "malicious": 4,
        "suspicious": 3,
        "inconclusive": 2,
        "benign": 1,
    }
    best = "benign"
    best_p = 0
    for signal in signals:
        p = priority[signal.label]
        if p > best_p:
            best = signal.label
            best_p = p
    return best  # type: ignore[return-value]


class DetectorCascade:
    """Stage0 → Stage1 → optional Stage2. Never calls policy."""

    def __init__(
        self,
        *,
        stage0: RulesDetector | None = None,
        stage1: Stage1Detector | None = None,
        stage2: ContextualDetector | None = None,
        run_stage2: bool = False,
    ) -> None:
        self.stage0 = stage0 or RulesDetector()
        self.stage1 = stage1 or PassthroughStage1()
        self.stage2 = stage2 if stage2 is not None else NoOpContextualDetector()
        self.run_stage2 = run_stage2

    def scan(
        self,
        text: str,
        *,
        context: Mapping[str, Any] | None = None,
    ) -> CascadeResult:
        if not isinstance(text, str):
            raise TypeError("text must be str")

        s0 = self.stage0.scan(text)
        signal0 = RiskSignal(
            stage="stage0",
            score=s0.risk_score,
            label=label_from_score(s0.risk_score),
            detector="rules",
            findings=s0.findings,
            detail={
                "exceeded_size_limit": s0.exceeded_size_limit,
                "finding_count": len(s0.findings),
            },
        )

        # Stage-1 sees normalized text to reduce homoglyph / fullwidth tricks.
        try:
            signal1 = self.stage1.scan(s0.normalized_text)
        except Exception as exc:
            signal1 = RiskSignal(
                stage="stage1",
                score=1.0,
                label="error",
                detector=getattr(self.stage1, "name", type(self.stage1).__name__),
                detail={"error": str(exc)},
            )
        if signal1.stage != "stage1":
            signal1 = RiskSignal(
                stage="stage1",
                score=signal1.score,
                label=signal1.label,
                detector=signal1.detector,
                findings=signal1.findings,
                detail=dict(signal1.detail),
            )

        signals: list[RiskSignal] = [signal0, signal1]

        if self.run_stage2:
            ctx = context if context is not None else {}
            signal2 = self.stage2.scan_context(s0.normalized_text, context=ctx)
            if signal2.stage != "stage2":
                signal2 = RiskSignal(
                    stage="stage2",
                    score=signal2.score,
                    label=signal2.label,
                    detector=signal2.detector,
                    findings=signal2.findings,
                    detail=dict(signal2.detail),
                )
            signals.append(signal2)

        return CascadeResult(
            signals=tuple(signals),
            max_score=max(s.score for s in signals),
            aggregate_label=_aggregate_label(signals),
            normalized_text=s0.normalized_text,
            original_sha256=s0.original_sha256,
        )


# Re-export for discoverability at cascade/broker integration points.
__all__ = [
    "DetectorCascade",
    "PRIVILEGED_SINKS",
    "PassthroughStage1",
    "privileged_sink_fail_closed",
]
