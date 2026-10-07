"""Optional StackOne Defender adapter (Apache-2.0, tool-result / Tier-1 analyze).

When ``stackone-defender`` is installed, ``StackOneDetector.try_load`` wraps
``create_prompt_defense(...).analyze`` as a Stage-1 ``RiskSignal`` source.
Default offline CI keeps RulesOnly/PIGuard selection; this adapter is opt-in.
See DECISIONS.md for adopt/skip due diligence.
"""

from __future__ import annotations

from typing import Any

from containment.detectors.base import RiskSignal, label_from_score

_RISK_TO_SCORE: dict[str, float] = {
    "low": 0.15,
    "medium": 0.55,
    "high": 0.9,
    "critical": 0.99,
}


class StackOneDetector:
    """Stage-1 adapter over StackOne ``PromptDefense.analyze`` (Tier-1 patterns)."""

    name = "stackone"

    def __init__(self, defense: Any) -> None:
        if defense is None:
            raise ValueError("defense is required")
        if not hasattr(defense, "analyze"):
            raise TypeError("defense must provide analyze(text)")
        self._defense = defense

    @classmethod
    def try_load(cls, *, enable_tier2: bool = False) -> StackOneDetector | None:
        """Return adapter if ``stackone-defender`` imports; else None (no raise)."""
        try:
            from stackone_defender import (  # type: ignore[import-not-found]
                create_prompt_defense,
            )
        except ImportError:
            return None
        try:
            defense = create_prompt_defense(enable_tier2=enable_tier2)
        except Exception:
            return None
        return cls(defense)

    def scan(self, text: str) -> RiskSignal:
        if not isinstance(text, str):
            raise TypeError("text must be str")
        try:
            result = self._defense.analyze(text)
        except Exception as exc:
            return RiskSignal(
                stage="stage1",
                score=1.0,
                label="error",
                detector=self.name,
                detail={"error": str(exc)},
            )
        has = bool(getattr(result, "has_detections", False))
        suggested = str(getattr(result, "suggested_risk", "low") or "low").lower()
        score = _RISK_TO_SCORE.get(suggested, 0.4 if has else 0.0)
        if not has:
            score = min(score, 0.2)
            label = "benign"
        else:
            label = label_from_score(score)
            if score >= 0.85:
                label = "malicious"
        match_count = len(getattr(result, "matches", []) or [])
        return RiskSignal(
            stage="stage1",
            score=round(min(1.0, max(0.0, score)), 4),
            label=label,  # type: ignore[arg-type]
            detector=self.name,
            detail={
                "suggested_risk": suggested,
                "has_detections": has,
                "match_count": match_count,
                "tier2": False,
            },
        )


def stackone_status() -> dict[str, Any]:
    """Availability probe without forcing model warmup."""
    try:
        import stackone_defender  # type: ignore[import-not-found]  # noqa: F401
    except ImportError:
        return {
            "available": False,
            "reason": "stackone-defender not installed (optional extra [stackone])",
            "package": "stackone-defender",
        }
    return {
        "available": True,
        "reason": "stackone-defender importable; use StackOneDetector.try_load",
        "package": "stackone-defender",
    }
