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

from collections.abc import Sequence
from typing import Protocol

from containment.detectors.base import RiskSignal, label_from_score
from containment.detectors.structural import ACTION_CATEGORIES, weak_signal

# Tuned on the train split (see DECISIONS.md, 1.8.0 / scripts in EVAL_CARD.md).
DEFAULT_T_HI = 0.9
DEFAULT_T_LO = 0.5
_MAX_VIEW_CHARS = 64_000


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
        self.name = f"layered:{getattr(model, 'name', type(model).__name__)}"

    def _score(self, p: float, cues: frozenset[str]) -> float:
        if p >= self.t_hi:
            # Map [t_hi, 1] onto [0.4, 1.0]: the suspicious threshold is exactly t_hi.
            return 0.4 + 0.6 * (p - self.t_hi) / (1.0 - self.t_hi)
        if p >= self.t_lo and cues & ACTION_CATEGORIES:
            return 0.4
        return 0.39 * p / self.t_hi

    def scan(self, text: str, views: Sequence[str] = ()) -> RiskSignal:
        if not isinstance(text, str):
            raise TypeError("text must be str")
        readings = [text, *views]
        joined = "\n\n".join(r for r in readings if r.strip())[: _MAX_VIEW_CHARS * 4]
        if not joined.strip():
            return RiskSignal(stage="stage1", score=0.0, label="benign", detector=self.name)
        p = max(self.model.probability(r[:_MAX_VIEW_CHARS]) for r in readings if r.strip())
        cues = weak_signal(joined)
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
