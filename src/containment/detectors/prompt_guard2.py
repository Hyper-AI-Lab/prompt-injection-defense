"""Optional Meta Prompt Guard 2 adapter (gated HF weights).

Prompt Guard 2 is **not** bundled and is not downloaded by default.
When transformers + granted gated access + local/cache weights are present,
``PromptGuard2Detector.try_load`` returns a live classifier adapter.
Otherwise it returns ``None`` and callers must use ``RulesOnlyDetector``
via ``select_stage1`` / config (fail-closed for privileged sinks).

Absence of weights is expressed as ``None`` plus a documented skip path.
See DECISIONS.md for adopt/skip rationale.
"""

from __future__ import annotations

from typing import Any

from containment.detectors.base import RiskSignal, label_from_score

PROMPT_GUARD2_MODEL_IDS: tuple[str, ...] = (
    "meta-llama/Prompt-Guard-86M",
    "meta-llama/Llama-Prompt-Guard-2-86M",
    "meta-llama/Llama-Prompt-Guard-2-22M",
)


class PromptGuard2Detector:
    """HF text-classification adapter for Prompt Guard 2 when available."""

    name = "prompt_guard2"

    def __init__(self, classifier: Any, *, model_id: str) -> None:
        if classifier is None:
            raise ValueError("classifier is required")
        if not model_id:
            raise ValueError("model_id is required")
        self._classifier = classifier
        self.model_id = model_id

    @classmethod
    def try_load(
        cls,
        *,
        model_id: str | None = None,
        device: int = -1,
    ) -> PromptGuard2Detector | None:
        """Attempt load; return None if gated/unavailable (never raises for skip)."""
        try:
            from transformers import (  # type: ignore[import-not-found]
                AutoModelForSequenceClassification,
                AutoTokenizer,
                pipeline,
            )
        except ImportError:
            return None
        candidates = (model_id,) if model_id else PROMPT_GUARD2_MODEL_IDS
        for mid in candidates:
            if not mid:
                continue
            try:
                tokenizer = AutoTokenizer.from_pretrained(mid)
                model = AutoModelForSequenceClassification.from_pretrained(mid)
                classifier = pipeline(
                    "text-classification",
                    model=model,
                    tokenizer=tokenizer,
                    truncation=True,
                    device=device,
                )
                return cls(classifier, model_id=mid)
            except Exception:
                continue
        return None

    def scan(self, text: str) -> RiskSignal:
        if not isinstance(text, str):
            raise TypeError("text must be str")
        try:
            raw = self._classifier(text)
        except Exception as exc:
            return RiskSignal(
                stage="stage1",
                score=1.0,
                label="error",
                detector=self.name,
                detail={"error": str(exc), "model_id": self.model_id},
            )
        item = raw[0] if isinstance(raw, list) else raw
        label_raw = str(item.get("label", "")).lower()
        conf = float(item.get("score", 0.0))
        if any(tok in label_raw for tok in ("inject", "jailbreak", "malicious")):
            score = conf
            label = "malicious" if score >= 0.85 else label_from_score(score)
        elif "benign" in label_raw or "safe" in label_raw:
            score = 1.0 - conf
            label = label_from_score(score)
        else:
            score = conf
            label = "inconclusive"
        return RiskSignal(
            stage="stage1",
            score=round(min(1.0, max(0.0, score)), 4),
            label=label,  # type: ignore[arg-type]
            detector=self.name,
            detail={
                "model_id": self.model_id,
                "raw_label": item.get("label"),
                "raw_score": item.get("score"),
            },
        )


def prompt_guard2_status() -> dict[str, Any]:
    """Lightweight availability probe without downloading gated weights."""
    try:
        import transformers  # type: ignore[import-not-found]  # noqa: F401
    except ImportError:
        return {
            "available": False,
            "reason": "transformers not installed (optional extra [ml])",
            "model_ids": list(PROMPT_GUARD2_MODEL_IDS),
        }
    return {
        "available": False,
        "reason": (
            "Prompt Guard 2 is gated on Hugging Face; skipped unless the "
            "operator grants access and calls PromptGuard2Detector.try_load "
            "with cached weights"
        ),
        "model_ids": list(PROMPT_GUARD2_MODEL_IDS),
        "transformers_installed": True,
    }
