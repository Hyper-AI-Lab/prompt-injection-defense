"""containment — production prompt-injection defense kit."""

from containment.actions import PolicyDecision, ProposedAction, TraceEvent
from containment.audit import AuditLog
from containment.broker import BrokerResult, SecurityViolation, ToolBroker
from containment.capability import CapabilityError, CapabilityMinter, CapabilityToken
from containment.datamark import DatamarkedText, mark, unwrap
from containment.ingest import IngestResult, ingest
from containment.labels import SecurityLabel
from containment.moltbook import MOLTBOOK_SUMMARY_SCHEMA, read_posts
from containment.plan import IntentEnvelope, Plan, PlanStep
from containment.policy import PolicyEngine, PolicyRule
from containment.quarantine import ExtractResult, QuarantineError, extract

__version__ = "1.0.0"

__all__ = [
    "AuditLog",
    "BrokerResult",
    "CapabilityError",
    "CapabilityMinter",
    "CapabilityToken",
    "DatamarkedText",
    "ExtractResult",
    "IngestResult",
    "MOLTBOOK_SUMMARY_SCHEMA",
    "IntentEnvelope",
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
    "extract",
    "ingest",
    "read_posts",
    "mark",
    "unwrap",
]
