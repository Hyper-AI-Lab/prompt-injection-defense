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
from containment.capability_store_redis import (
    CapabilityStoreError,
    RedisConsumeStore,
)
from containment.datamark import DatamarkedText, mark, unwrap
from containment.detectors.cascade import DetectorCascade
from containment.detectors.piguard import make_stage1_cascade, select_stage1, stage1_from_env
from containment.egress_proxy import EgressProxyServer, ProxyConfig
from containment.egress_resolve import (
    DenyNetworkError,
    ResolvedPin,
    open_pinned_urllib,
    resolve_and_pin,
)
from containment.enterprise import EnterpriseHost, build_enterprise_host
from containment.host import (
    AuditShipper,
    EgressProvider,
    EnvSecretProvider,
    FileAuditShipper,
    FileSecretProvider,
    HostChecklist,
    PinnedEgressProvider,
    ProxyEgressProvider,
    RateLimitGate,
    SecretError,
    SecretProvider,
    TokenBucketRateLimit,
)
from containment.http_egress import HttpEgressError, fetch_url
from containment.ingest import IngestResult, ingest
from containment.intent import (
    Ed25519IntentSigner,
    IntentError,
    IntentSigner,
    IntentVerifier,
    SignedIntent,
    intent_payload_bytes,
    plan_hash,
)
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

__version__ = "1.3.1"

__all__ = [
    "ALLOWLIST_SUMMARY_SCHEMA",
    "AuditLog",
    "AuditShipper",
    "BrokerResult",
    "CapabilityError",
    "CapabilityMinter",
    "CapabilityToken",
    "CapabilityConsumeStore",
    "MemoryConsumeStore",
    "SqliteConsumeStore",
    "CapabilityStoreError",
    "RedisConsumeStore",
    "DatamarkedText",
    "DenyNetworkError",
    "DetectorCascade",
    "EgressProxyServer",
    "EnterpriseHost",
    "EgressProvider",
    "PinnedEgressProvider",
    "ProxyEgressProvider",
    "EnvSecretProvider",
    "ExtractResult",
    "FileAuditShipper",
    "FileSecretProvider",
    "HostChecklist",
    "HttpEgressError",
    "IngestResult",
    "IntentEnvelope",
    "IntentError",
    "IntentSigner",
    "IntentVerifier",
    "Ed25519IntentSigner",
    "SignedIntent",
    "intent_payload_bytes",
    "MOLTBOOK_SUMMARY_SCHEMA",
    "MoltbookError",
    "Plan",
    "PlanStep",
    "PolicyDecision",
    "PolicyEngine",
    "PolicyRule",
    "ProposedAction",
    "ProxyConfig",
    "QuarantineError",
    "RateLimitGate",
    "ResolvedPin",
    "SecretError",
    "SecretProvider",
    "SecurityLabel",
    "SecurityViolation",
    "TokenBucketRateLimit",
    "ToolBroker",
    "TraceEvent",
    "ParsedEgressUrl",
    "UrlGuardError",
    "__version__",
    "build_enterprise_host",
    "check_url_for_tool",
    "closed_object_schema",
    "extract",
    "fetch_url",
    "ingest",
    "mark",
    "open_pinned_urllib",
    "parse_egress_url",
    "plan_hash",
    "read_posts",
    "resolve_and_pin",
    "select_stage1",
    "make_stage1_cascade",
    "stage1_from_env",
    "unwrap",
]
