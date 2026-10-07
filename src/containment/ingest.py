"""Ingestion pipeline: label → normalize → cascade → quarantine typed extract.

External content enters here. The pipeline never authorizes tool calls; it
produces a labeled typed result (or a failed extract) plus cascade risk
signals for the broker/policy layer.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from containment.detectors.base import CascadeResult
from containment.detectors.cascade import DetectorCascade
from containment.detectors.piguard import FakeStage1Detector, RulesOnlyDetector
from containment.labels import Confidentiality, Integrity, SecurityLabel
from containment.quarantine import (
    ALLOWLIST_SUMMARY_SCHEMA,
    ExtractResult,
    QuarantineError,
    extract,
)


@dataclass(frozen=True, slots=True)
class IngestResult:
    """Labeled typed ingest outcome (success or quarantined failure)."""

    label: SecurityLabel
    cascade: CascadeResult
    extract: ExtractResult | None
    extract_error: str | None
    raw_sha256: str
    normalized_text: str

    @property
    def ok(self) -> bool:
        """True when typed extract succeeded."""
        return self.extract is not None and self.extract_error is None

    @property
    def high_risk(self) -> bool:
        """True when cascade aggregate is malicious/suspicious/error."""
        return self.cascade.aggregate_label in (
            "malicious",
            "suspicious",
            "error",
        ) or self.cascade.max_score >= 0.4


def default_ingest_cascade() -> DetectorCascade:
    """Offline-safe cascade: Stage0 rules + FakeStage1 (keyword elevation)."""
    return DetectorCascade(stage1=FakeStage1Detector())


def ingest(
    raw_text: str,
    *,
    source: str,
    task_id: str,
    schema: Mapping[str, Any] | None = None,
    candidate: str | Mapping[str, Any] | None = None,
    integrity: Integrity = "untrusted",
    confidentiality: Confidentiality = "public",
    cascade: DetectorCascade | None = None,
    schema_id: str | None = None,
    reject_instruction_text: bool | None = None,
) -> IngestResult:
    """Run label → normalize/cascade → quarantine typed extract.

    Parameters
    ----------
    raw_text:
        Untrusted (or labeled) input text scanned by the detector cascade.
    source / task_id:
        Provenance fields for ``SecurityLabel``.
    schema:
        Closed JSON Schema for typed extract (defaults to allowlist summary).
    candidate:
        Structured data (or JSON text) to validate. When omitted, ``raw_text``
        is parsed as JSON for the extract step.
    integrity:
        Defaults to ``untrusted`` for external feeds.
    """
    if not isinstance(raw_text, str):
        raise TypeError("raw_text must be str")
    if not source or not str(source).strip():
        raise ValueError("source must be a non-empty string")
    if not task_id or not str(task_id).strip():
        raise ValueError("task_id must be a non-empty string")

    engine = cascade or default_ingest_cascade()
    cascade_result = engine.scan(raw_text)

    transformations: list[str] = ["normalize", "cascade"]
    extract_result: ExtractResult | None = None
    extract_error: str | None = None

    schema_map: Mapping[str, Any] = schema if schema is not None else ALLOWLIST_SUMMARY_SCHEMA
    extract_input: str | Mapping[str, Any]
    if candidate is not None:
        extract_input = candidate
    else:
        extract_input = cascade_result.normalized_text

    try:
        extract_result = extract(
            extract_input,
            schema_map,
            schema_id=schema_id,
            reject_instruction_text=reject_instruction_text,
        )
        transformations.append("quarantine_extract")
    except QuarantineError as exc:
        extract_error = str(exc)
        transformations.append("quarantine_reject")

    label = SecurityLabel(
        integrity=integrity,
        confidentiality=confidentiality,
        source=source,
        task_id=task_id,
        transformations=tuple(transformations),
    )
    return IngestResult(
        label=label,
        cascade=cascade_result,
        extract=extract_result,
        extract_error=extract_error,
        raw_sha256=cascade_result.original_sha256,
        normalized_text=cascade_result.normalized_text,
    )


__all__ = [
    "IngestResult",
    "default_ingest_cascade",
    "ingest",
    "ALLOWLIST_SUMMARY_SCHEMA",
    "RulesOnlyDetector",
]
