"""PIGuard Stage-1 adapter (optional transformers/HF weights).

Prefer loading ``leolee99/PIGuard`` when transformers + weights are available.
If deps/weights are missing, callers must select ``RulesOnlyDetector`` via
``select_stage1`` (fail-closed for privileged sinks — see cascade module).

This module ships only real adapters or explicit None/skip selection.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from containment.detectors.base import RiskSignal, Stage1Detector, label_from_score
from containment.detectors.rules import scan_stage0

PIGUARD_MODEL_ID = "leolee99/PIGuard"
Stage1Backend = Literal["piguard", "rules_only", "fake"]


@dataclass(frozen=True, slots=True)
class Stage1Selection:
    """Result of backend selection for Stage-1."""

    backend: Stage1Backend
    detector: Stage1Detector
    reason: str
    fail_closed_privileged: bool


class RulesOnlyDetector:
    """Stage-1 path used when ML weights/deps are unavailable.

    Mirrors Stage-0 risk. Integration points must treat this as
    ``fail_closed_privileged=True`` for email/http/wallet sinks.
    """

    name = "rules_only"

    def scan(self, text: str) -> RiskSignal:
        stage0 = scan_stage0(text)
        return RiskSignal(
            stage="stage1",
            score=stage0.risk_score,
            label=label_from_score(stage0.risk_score),
            detector=self.name,
            findings=stage0.findings,
            detail={"backend": "rules_only", "source": "stage0_mirror"},
        )


class FakeStage1Detector:
    """Deterministic Stage-1 double for offline CI (no model download)."""

    name = "fake_stage1"

    def __init__(self, *, score: float = 0.0, label: str = "benign") -> None:
        if not 0.0 <= score <= 1.0:
            raise ValueError("score must be in [0.0, 1.0]")
        self._score = score
        self._label = label

    def scan(self, text: str) -> RiskSignal:
        if not isinstance(text, str):
            raise TypeError("text must be str")
        # Elevate on obvious injection keywords for fixture utility tests.
        lowered = text.lower()
        score = self._score
        label = self._label
        if any(
            needle in lowered
            for needle in ("ignore previous", "ignore all", "system prompt")
        ):
            score = max(score, 0.95)
            label = "malicious"
        return RiskSignal(
            stage="stage1",
            score=score,
            label=label,  # type: ignore[arg-type]
            detector=self.name,
            detail={"backend": "fake", "text_len": len(text)},
        )


class PIGuardDetector:
    """Load PIGuard via Hugging Face transformers when available."""

    name = "piguard"
    model_id = PIGUARD_MODEL_ID

    def __init__(self, classifier: Any, *, model_id: str = PIGUARD_MODEL_ID) -> None:
        if classifier is None:
            raise ValueError("classifier is required")
        self._classifier = classifier
        self.model_id = model_id

    @classmethod
    def try_load(
        cls,
        *,
        model_id: str = PIGUARD_MODEL_ID,
        device: int = -1,
    ) -> PIGuardDetector | None:
        """Return a loaded detector, or None if deps/weights are unavailable.

        Does not raise on missing optional deps — callers fall back to rules-only.
        """
        try:
            from transformers import (  # type: ignore[import-not-found]
                AutoModelForSequenceClassification,
                AutoTokenizer,
                pipeline,
            )
        except ImportError:
            return None
        try:
            tokenizer = AutoTokenizer.from_pretrained(model_id)
            model = AutoModelForSequenceClassification.from_pretrained(
                model_id, trust_remote_code=True
            )
            classifier = pipeline(
                "text-classification",
                model=model,
                tokenizer=tokenizer,
                truncation=True,
                device=device,
            )
        except Exception:
            return None
        return cls(classifier, model_id=model_id)

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
        # pipeline may return list[dict] or dict
        item = raw[0] if isinstance(raw, list) else raw
        label_raw = str(item.get("label", "")).lower()
        conf = float(item.get("score", 0.0))
        if "inject" in label_raw or label_raw in {"1", "malicious", "label_1"}:
            score = conf
            label = label_from_score(score) if score < 0.85 else "malicious"
            if score >= 0.4 and label == "benign":
                label = "suspicious"
        elif "benign" in label_raw or label_raw in {"0", "label_0"}:
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


def select_stage1(
    *,
    prefer: Stage1Backend = "piguard",
    allow_download: bool = False,
    fake: FakeStage1Detector | None = None,
) -> Stage1Selection:
    """Select Stage-1 backend with fail-closed metadata for privileged sinks.

    Offline CI: pass ``prefer="fake"`` or ``prefer="rules_only"`` (no HF download).
    ``prefer="piguard"`` attempts load only when ``allow_download`` is True or
    the model is already cached; on failure, falls back to rules-only with
    ``fail_closed_privileged=True``.
    """
    if prefer == "fake":
        detector: Stage1Detector = fake or FakeStage1Detector()
        return Stage1Selection(
            backend="fake",
            detector=detector,
            reason="explicit fake backend for tests/CI",
            fail_closed_privileged=False,
        )
    if prefer == "rules_only":
        return Stage1Selection(
            backend="rules_only",
            detector=RulesOnlyDetector(),
            reason="explicit rules-only configuration",
            fail_closed_privileged=True,
        )
    # prefer piguard
    if not allow_download:
        # Avoid surprising multi-hundred-MB downloads in default CI.
        return Stage1Selection(
            backend="rules_only",
            detector=RulesOnlyDetector(),
            reason="piguard skipped (allow_download=False); rules-only fail-closed",
            fail_closed_privileged=True,
        )
    loaded = PIGuardDetector.try_load()
    if loaded is None:
        return Stage1Selection(
            backend="rules_only",
            detector=RulesOnlyDetector(),
            reason="piguard unavailable (deps/weights); rules-only fail-closed",
            fail_closed_privileged=True,
        )
    return Stage1Selection(
        backend="piguard",
        detector=loaded,
        reason=f"loaded {PIGUARD_MODEL_ID}",
        fail_closed_privileged=False,
    )


# Alias used in cascade docs / older names.
RulesOnlyStage1 = RulesOnlyDetector
