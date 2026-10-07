"""containment — production prompt-injection defense kit."""

from containment.actions import PolicyDecision, ProposedAction, TraceEvent
from containment.audit import AuditLog
from containment.broker import BrokerResult, SecurityViolation, ToolBroker
from containment.capability import CapabilityError, CapabilityMinter, CapabilityToken
from containment.capability_store import (
    CapabilityConsumeStore,
    MemoryConsumeStore,
    SqliteConsumeStore,
)
from containment.datamark import DatamarkedText, mark, unwrap
from containment.detectors.cascade import DetectorCascade
from containment.detectors.piguard import make_stage1_cascade, select_stage1, stage1_from_env
from containment.ingest import IngestResult, ingest
from containment.intent import IntentError, IntentSigner, SignedIntent, plan_hash
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
from containment.url_guard import (
    ParsedEgressUrl,
    UrlGuardError,
    check_url_for_tool,
    parse_egress_url,
)

__version__ = "1.2.0"

__all__ = [
    "ALLOWLIST_SUMMARY_SCHEMA",
    "AuditLog",
    "BrokerResult",
    "CapabilityError",
    "CapabilityMinter",
    "CapabilityToken",
    "CapabilityConsumeStore",
    "MemoryConsumeStore",
    "SqliteConsumeStore",
    "DatamarkedText",
    "DetectorCascade",
    "ExtractResult",
    "IngestResult",
    "IntentEnvelope",
    "IntentError",
    "IntentSigner",
    "SignedIntent",
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
    "ParsedEgressUrl",
    "UrlGuardError",
    "__version__",
    "closed_object_schema",
    "extract",
    "ingest",
    "mark",
    "check_url_for_tool",
    "parse_egress_url",
    "plan_hash",
    "read_posts",
    "select_stage1",
    "make_stage1_cascade",
    "stage1_from_env",
    "unwrap",
]
