"""Detector adapters (rules, PIGuard, cascade)."""

from containment.detectors.base import (
    CascadeResult,
    ContextualDetector,
    NoOpContextualDetector,
    RiskSignal,
    Stage1Detector,
)
from containment.detectors.cascade import (
    PRIVILEGED_SINKS,
    DetectorCascade,
    PassthroughStage1,
    privileged_sink_fail_closed,
)
from containment.detectors.piguard import (
    FakeStage1Detector,
    PIGuardDetector,
    RulesOnlyDetector,
    Stage1Selection,
    select_stage1,
)
from containment.detectors.rules import Finding, RulesDetector, Stage0Result, scan_stage0

__all__ = [
    "CascadeResult",
    "ContextualDetector",
    "DetectorCascade",
    "FakeStage1Detector",
    "Finding",
    "NoOpContextualDetector",
    "PIGuardDetector",
    "PRIVILEGED_SINKS",
    "PassthroughStage1",
    "RiskSignal",
    "RulesDetector",
    "RulesOnlyDetector",
    "Stage0Result",
    "Stage1Detector",
    "Stage1Selection",
    "privileged_sink_fail_closed",
    "scan_stage0",
    "select_stage1",
]
