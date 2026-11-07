"""Layered Stage-1: a local classifier fused with wording-independent structural signals.

The classifier reads the normalized text plus Stage-0 *views* (decoded payloads,
de-obfuscated and CSS-hidden text), so an instruction is scored in the form a model would
read it. Fusion (thresholds tuned on the mutation-eval **train** split only):

* ``p >= t_hi``                                  → suspicious/malicious
* ``t_lo <= p < t_hi`` and a structural action cue → suspicious
* otherwise                                       → benign / inconclusive

Stage-0 rules still score independently in the cascade; this layer only adds recall.
"""

from __future__ import annotations

import os
import time
from collections.abc import Sequence
from typing import Protocol

from containment.detectors.base import RiskSignal, label_from_score
from containment.detectors.structural import ACTION_CATEGORIES, weak_signal

# Tuned on the train split (see DECISIONS.md, 1.8.0 / scripts in EVAL_CARD.md).
DEFAULT_T_HI = 0.9
DEFAULT_T_LO = 0.5
# Cap only for the structural-cue regex pass (a secondary booster); the classifier always
# reads the whole document via its own sliding-window + budget path.
_MAX_CUE_CHARS = 256_000
_DEFAULT_BUDGET_S = 45.0
# Fail-closed floor when the budget is exhausted: at least "suspicious".
_BUDGET_FAIL_FLOOR = 0.4


def _budget_from_env() -> float:
    raw = os.environ.get("CONTAINMENT_STAGE1_BUDGET_S")
    if not raw:
        return _DEFAULT_BUDGET_S
    try:
        val = float(raw)
    except ValueError:
        return _DEFAULT_BUDGET_S
    return val if val > 0 else _DEFAULT_BUDGET_S


class ProbabilityModel(Protocol):
    name: str

    def probability(self, text: str) -> float: ...


class LayeredDetector:
    """Stage-1 detector: classifier probability + structural cues, fused."""

    accepts_views = True
    # ~0.1 s/KB on 4 CPU threads; a 256 KB document plus views fits; beyond → error.
    default_timeout_s = 60.0

    def __init__(
        self,
        model: ProbabilityModel,
        *,
        t_hi: float = DEFAULT_T_HI,
        t_lo: float = DEFAULT_T_LO,
    ) -> None:
        if not 0.0 < t_lo <= t_hi < 1.0:
            raise ValueError("need 0 < t_lo <= t_hi < 1")
        self.model = model
        self.t_hi = float(t_hi)
        self.t_lo = float(t_lo)
        self.budget_s = _budget_from_env()
        self.name = f"layered:{getattr(model, 'name', type(model).__name__)}"

    def _score(self, p: float, cues: frozenset[str]) -> float:
        if p >= self.t_hi:
            # Map [t_hi, 1] onto [0.4, 1.0]: the suspicious threshold is exactly t_hi.
            return 0.4 + 0.6 * (p - self.t_hi) / (1.0 - self.t_hi)
        if p >= self.t_lo and cues & ACTION_CATEGORIES:
            return 0.4
        return 0.39 * p / self.t_hi

    def _model_prob(self, reading: str, budget_s: float) -> tuple[float, bool]:
        budgeted = getattr(self.model, "probability_budgeted", None)
        if callable(budgeted):
            return budgeted(reading, budget_s)
        return self.model.probability(reading), False

    def scan(self, text: str, views: Sequence[str] = ()) -> RiskSignal:
        if not isinstance(text, str):
            raise TypeError("text must be str")
        readings = [r for r in (text, *views) if r.strip()]
        if not readings:
            return RiskSignal(stage="stage1", score=0.0, label="benign", detector=self.name)
        # Scan the whole document (every reading, in full) under one shared wall-clock budget;
        # never silently drop a tail. Exhausting the budget fails closed (elevated risk).
        deadline = time.monotonic() + self.budget_s
        p = 0.0
        exhausted = False
        for reading in readings:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                exhausted = True
                break
            rp, rex = self._model_prob(reading, remaining)
            p = max(p, rp)
            exhausted = exhausted or rex
            if exhausted:
                break
        cues = weak_signal("\n\n".join(readings)[:_MAX_CUE_CHARS])
        if exhausted:
            score = round(min(1.0, max(self._score(p, cues), _BUDGET_FAIL_FLOOR)), 4)
            return RiskSignal(
                stage="stage1",
                score=score,
                label="error",
                detector=self.name,
                detail={
                    "error": "budget_exceeded",
                    "budget_s": self.budget_s,
                    "probability": round(p, 4),
                    "t_hi": self.t_hi,
                    "t_lo": self.t_lo,
                    "cues": sorted(cues),
                },
            )
        score = round(min(1.0, self._score(p, cues)), 4)
        return RiskSignal(
            stage="stage1",
            score=score,
            label=label_from_score(score),
            detector=self.name,
            detail={
                "probability": round(p, 4),
                "t_hi": self.t_hi,
                "t_lo": self.t_lo,
                "cues": sorted(cues),
            },
        )


__all__ = ["DEFAULT_T_HI", "DEFAULT_T_LO", "LayeredDetector", "ProbabilityModel"]
