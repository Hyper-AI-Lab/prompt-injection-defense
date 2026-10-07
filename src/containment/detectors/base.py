"""Detector protocols and risk-signal types.

Detectors emit risk signals only. They never authorize tool calls;
authorization is exclusively the policy engine / broker's job.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Literal, Protocol, runtime_checkable

from containment.detectors.rules import Finding

RiskLabel = Literal["benign", "suspicious", "malicious", "inconclusive", "error"]
_VALID_LABELS = frozenset(
    {"benign", "suspicious", "malicious", "inconclusive", "error"}
)


@dataclass(frozen=True, slots=True)
class RiskSignal:
    """Non-authorizing detector output.

    A ``RiskSignal`` is advisory. Callers must not treat any label as an
    allow/deny decision; only ``PolicyEngine`` / ``ToolBroker`` authorizes.
    """

    stage: str
    score: float
    label: RiskLabel
    detector: str
    findings: tuple[Finding, ...] = ()
    detail: Mapping[str, Any] = MappingProxyType({})

    def __post_init__(self) -> None:
        if not self.stage or not str(self.stage).strip():
            raise ValueError("stage must be a non-empty string")
        if not self.detector or not str(self.detector).strip():
            raise ValueError("detector must be a non-empty string")
        if not 0.0 <= self.score <= 1.0:
            raise ValueError("score must be in [0.0, 1.0]")
        if self.label not in _VALID_LABELS:
            raise ValueError(
                f"label must be one of {sorted(_VALID_LABELS)}, got {self.label!r}"
            )
        if not isinstance(self.findings, tuple):
            raise TypeError("findings must be a tuple")
        if not isinstance(self.detail, Mapping):
            raise TypeError("detail must be a mapping")
        object.__setattr__(self, "detail", MappingProxyType(dict(self.detail)))


@dataclass(frozen=True, slots=True)
class CascadeResult:
    """Aggregated cascade output — still never an authorization."""

    signals: tuple[RiskSignal, ...]
    max_score: float
    aggregate_label: RiskLabel
    normalized_text: str
    original_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.signals, tuple) or not self.signals:
            raise ValueError("signals must be a non-empty tuple")
        if not 0.0 <= self.max_score <= 1.0:
            raise ValueError("max_score must be in [0.0, 1.0]")
        if self.aggregate_label not in _VALID_LABELS:
            raise ValueError(f"invalid aggregate_label {self.aggregate_label!r}")


@runtime_checkable
class Stage1Detector(Protocol):
    """Fast local classifier adapter (Stage 1)."""

    def scan(self, text: str) -> RiskSignal: ...


@runtime_checkable
class ContextualDetector(Protocol):
    """Optional Stage-2 contextual hook (history, tool topology, etc.)."""

    def scan_context(
        self, text: str, *, context: Mapping[str, Any]
    ) -> RiskSignal: ...


class NoOpContextualDetector:
    """Real Stage-2 implementation that always returns inconclusive.

    Not a raise stub: safe to wire when no contextual model is configured.
    Cascade aggregation omits this detector so enabling ``run_stage2`` with
    the default NoOp does not force aggregate ``inconclusive`` / fail-closed.
    """

    def scan_context(
        self, text: str, *, context: Mapping[str, Any]
    ) -> RiskSignal:
        if not isinstance(text, str):
            raise TypeError("text must be str")
        if not isinstance(context, Mapping):
            raise TypeError("context must be a mapping")
        return RiskSignal(
            stage="stage2",
            score=0.0,
            label="inconclusive",
            detector="noop_contextual",
            detail={"context_keys": sorted(str(k) for k in context.keys())},
        )


def label_from_score(score: float) -> RiskLabel:
    if score >= 0.85:
        return "malicious"
    if score >= 0.4:
        return "suspicious"
    return "benign"
