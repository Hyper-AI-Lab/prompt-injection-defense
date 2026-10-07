"""containment — production prompt-injection defense kit."""

from containment.actions import PolicyDecision, ProposedAction, TraceEvent
from containment.audit import AuditLog
from containment.broker import BrokerResult, SecurityViolation, ToolBroker
from containment.capability import CapabilityError, CapabilityMinter, CapabilityToken
from containment.datamark import DatamarkedText, mark, unwrap
from containment.detectors.cascade import DetectorCascade
from containment.detectors.piguard import select_stage1
from containment.ingest import IngestResult, ingest
from containment.labels import SecurityLabel
from containment.moltbook import MOLTBOOK_SUMMARY_SCHEMA, MoltbookError, read_posts
from containment.plan import IntentEnvelope, Plan, PlanStep
from containment.policy import PolicyEngine, PolicyRule
from containment.quarantine import (
    ALLOWLIST_SUMMARY_SCHEMA,
    ExtractResult,
    QuarantineError,
    closed_object_schema,
    extract,
)

__version__ = "1.0.0"

__all__ = [
    "ALLOWLIST_SUMMARY_SCHEMA",
    "AuditLog",
    "BrokerResult",
    "CapabilityError",
    "CapabilityMinter",
    "CapabilityToken",
    "DatamarkedText",
    "DetectorCascade",
    "ExtractResult",
    "IngestResult",
    "IntentEnvelope",
    "MOLTBOOK_SUMMARY_SCHEMA",
    "MoltbookError",
    "Plan",
    "PlanStep",
    "PolicyDecision",
    "PolicyEngine",
    "PolicyRule",
    "ProposedAction",
    "QuarantineError",
    "SecurityLabel",
    "SecurityViolation",
    "ToolBroker",
    "TraceEvent",
    "__version__",
    "closed_object_schema",
    "extract",
    "ingest",
    "mark",
    "read_posts",
    "select_stage1",
    "unwrap",
]
