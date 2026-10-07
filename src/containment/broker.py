"""Tool broker reference monitor: schema → policy → audit → capability."""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from containment.actions import PolicyDecision, ProposedAction
from containment.audit import AuditLog
from containment.capability import CapabilityMinter, CapabilityToken
from containment.detectors.base import CascadeResult
from containment.detectors.cascade import PRIVILEGED_SINKS, privileged_sink_fail_closed
from containment.host.checklist import HostChecklist
from containment.host.rate_limit import RateLimitGate
from containment.host.secrets import SecretError
from containment.intent import IntentError, IntentVerifier, SignedIntent
from containment.plan import Plan
from containment.policy import PolicyEngine
from containment.tool_schemas import registry_schema_validator
from containment.url_guard import UrlGuardError, check_public_only, check_redirect_args

# Privileged / no-tainted-egress tools must carry non-empty input_labels (H1).
# Shared with BrokeredRegistry early gate (C5) — keep a single source of truth.
LABEL_REQUIRED_SINKS: frozenset[str] = PRIVILEGED_SINKS | frozenset({"social.publish"})

# Sentinel: omit per-call executor= to use ToolBroker.executor (C2).
_EXECUTOR_UNSET: object = object()


class SecurityViolation(Exception):
    """Raised when the broker denies an action."""

    def __init__(self, message: str, *, decision: PolicyDecision) -> None:
        super().__init__(message)
        self.decision = decision


@dataclass(frozen=True, slots=True)
class ApprovalOutcome:
    """Result of a human approval hook.

    For ``requires_mfa`` decisions, ``mfa_verified`` must be True or the
    broker fails closed before mint.
    """

    mfa_verified: bool = False


ApprovalHook = Callable[[ProposedAction, PolicyDecision], ApprovalOutcome | None]
SchemaValidator = Callable[[str, Mapping[str, Any]], None]
Executor = Callable[[ProposedAction, CapabilityToken], Any]


def default_schema_validator(tool: str, arguments: Mapping[str, Any]) -> None:
    """Minimal structural check: arguments must be a mapping; tool non-empty.

    Deeper JSON Schema validation can replace this hook later without changing
    the broker contract.
    """
    if not tool or not str(tool).strip():
        raise SecurityViolation(
            "tool name required",
            decision=PolicyDecision(
                effect="deny", rule_id="schema", reason="empty tool"
            ),
        )
    if not isinstance(arguments, Mapping):
        raise SecurityViolation(
            "arguments must be a mapping",
            decision=PolicyDecision(
                effect="deny", rule_id="schema", reason="arguments type"
            ),
        )


def default_approval_hook(
    action: ProposedAction, decision: PolicyDecision
) -> None:
    """Fail closed when human approval is required but no hook was provided."""
    raise SecurityViolation(
        f"human approval required for {action.tool} (rule {decision.rule_id})",
        decision=decision,
    )


@dataclass(slots=True)
class BrokerResult:
    decision: PolicyDecision
    capability: CapabilityToken | None
    result: Any = None


class ToolBroker:
    """Synchronous secure_execute reference monitor."""

    def __init__(
        self,
        policy: PolicyEngine,
        audit: AuditLog,
        minter: CapabilityMinter,
        *,
        schema_validate: SchemaValidator = registry_schema_validator,
        approval: ApprovalHook = default_approval_hook,
        executor: Executor | None = None,
        known_tools: frozenset[str] | None = None,
        require_signed_intent: bool = False,
        intent_signer: IntentVerifier | None = None,
        enterprise_profile: bool = False,
        require_host_gate: bool = False,
        host_checklist: HostChecklist | None = None,
        rate_limit: RateLimitGate | None = None,
        ship_audit: bool | None = None,
    ) -> None:
        self.policy = policy
        self.audit = audit
        self.minter = minter
        self.schema_validate = schema_validate
        self.approval = approval
        self.executor = executor
        self.known_tools = known_tools
        self.enterprise_profile = bool(enterprise_profile)
        self.require_signed_intent = bool(require_signed_intent or self.enterprise_profile)
        self.intent_signer = intent_signer
        self.require_host_gate = bool(require_host_gate or self.enterprise_profile)
        self.host_checklist = host_checklist
        self.rate_limit = rate_limit
        self.ship_audit = (
            bool(ship_audit) if ship_audit is not None else self.require_host_gate
        )


    def _record_decision(
        self, action: ProposedAction, decision: PolicyDecision
    ) -> None:
        """Append audit decision; optionally ship under HostGate (fail-closed)."""
        self.audit.append_decision(action, decision)
        if not self.ship_audit:
            return
        checklist = self.host_checklist
        if checklist is None or checklist.audit_shipper is None:
            return
        try:
            checklist.audit_shipper.ship_file(self.audit.path)
        except Exception as exc:
            if self.require_host_gate:
                raise SecurityViolation(
                    f"audit ship failed: {exc}",
                    decision=PolicyDecision(
                        effect="deny",
                        rule_id="host_audit_ship_failed",
                        reason=f"audit ship failed: {exc}",
                    ),
                ) from exc

    def secure_execute(
        self,
        action: ProposedAction,
        *,
        plan: Plan,
        principal_authenticated: bool = True,
        expiry_seconds: float = 60.0,
        cascade: CascadeResult | None = None,
        fail_closed_privileged: bool = False,
        intent: SignedIntent | None = None,
        executor: Executor | None | object = _EXECUTOR_UNSET,
        dry_run: bool = False,
    ) -> BrokerResult:
        # 0a) Host gate (enterprise / require_host_gate): fail closed before mint.
        if self.require_host_gate:
            if self.host_checklist is None:
                decision = PolicyDecision(
                    effect="deny",
                    rule_id="host_gate_required",
                    reason="host checklist required but not provided",
                )
                self._record_decision(action, decision)
                raise SecurityViolation(decision.reason, decision=decision)
            if not self.host_checklist.ok():
                codes = ",".join(self.host_checklist.failures())
                decision = PolicyDecision(
                    effect="deny",
                    rule_id="host_checklist_failed",
                    reason=f"host checklist failed: {codes}",
                )
                self._record_decision(action, decision)
                raise SecurityViolation(decision.reason, decision=decision)
            # Bind SecretProvider capability secret to the minter (H2).
            provider = self.host_checklist.secret_provider
            if provider is not None:
                name = self.host_checklist.capability_secret_name
                try:
                    provided = provider.get_bytes(name)
                except SecretError as exc:
                    decision = PolicyDecision(
                        effect="deny",
                        rule_id="host_secret_mismatch",
                        reason=f"capability secret unavailable: {exc}",
                    )
                    self._record_decision(action, decision)
                    raise SecurityViolation(decision.reason, decision=decision) from exc
                if not self.minter.matches_secret(provided):
                    decision = PolicyDecision(
                        effect="deny",
                        rule_id="host_secret_mismatch",
                        reason="capability secret does not match minter",
                    )
                    self._record_decision(action, decision)
                    raise SecurityViolation(decision.reason, decision=decision)

        # 0) Signed intent gate (enterprise / require_signed_intent).
        if self.require_signed_intent:
            if intent is None:
                decision = PolicyDecision(
                    effect="deny",
                    rule_id="signed_intent_required",
                    reason="signed intent required but not provided",
                )
                self._record_decision(action, decision)
                raise SecurityViolation(decision.reason, decision=decision)
            if self.intent_signer is None:
                decision = PolicyDecision(
                    effect="deny",
                    rule_id="signed_intent_required",
                    reason="intent_signer not configured",
                )
                self._record_decision(action, decision)
                raise SecurityViolation(decision.reason, decision=decision)
            try:
                env = self.intent_signer.verify(intent, plan=plan)
            except IntentError as exc:
                decision = PolicyDecision(
                    effect="deny",
                    rule_id="signed_intent_invalid",
                    reason=str(exc),
                )
                self._record_decision(action, decision)
                raise SecurityViolation(decision.reason, decision=decision) from exc
            principal_authenticated = env.principal_authenticated

        # 1) Optional known-tool gate (deny unknown before policy noise).
        if self.known_tools is not None and action.tool not in self.known_tools:
            decision = PolicyDecision(
                effect="deny",
                rule_id="unknown_tool",
                reason=f"unknown tool {action.tool!r}",
            )
            self._record_decision(action, decision)
            raise SecurityViolation(decision.reason, decision=decision)

        # 2) Schema validation hook.
        try:
            self.schema_validate(action.tool, action.arguments)
        except SecurityViolation as exc:
            self._record_decision(action, exc.decision)
            raise
        except Exception as exc:
            decision = PolicyDecision(
                effect="deny",
                rule_id="schema",
                reason=str(exc),
            )
            self._record_decision(action, decision)
            raise SecurityViolation(str(exc), decision=decision) from exc

        # 3) Empty-label fail-closed on privileged / egress sinks (H1).
        if action.tool in LABEL_REQUIRED_SINKS and not action.input_labels:
            decision = PolicyDecision(
                effect="deny",
                rule_id="empty_input_labels",
                reason=(
                    f"privileged sink {action.tool!r} requires non-empty "
                    "input_labels (fail closed)"
                ),
            )
            self._record_decision(action, decision)
            raise SecurityViolation(decision.reason, decision=decision)

        # 3b) Plan expiry (M4).
        if plan.expiry_unix is not None and time.time() > float(plan.expiry_unix):
            decision = PolicyDecision(
                effect="deny",
                rule_id="plan_expired",
                reason=f"plan expired at unix {plan.expiry_unix}",
            )
            self._record_decision(action, decision)
            raise SecurityViolation(decision.reason, decision=decision)

        # 3c) Plan step binding (M1): step id must exist and tool must match.
        try:
            step = plan.step_by_id(action.plan_step)
        except KeyError:
            decision = PolicyDecision(
                effect="deny",
                rule_id="plan_step_unknown",
                reason=f"unknown plan_step {action.plan_step!r}",
            )
            self._record_decision(action, decision)
            raise SecurityViolation(decision.reason, decision=decision) from None
        if step.tool != action.tool:
            decision = PolicyDecision(
                effect="deny",
                rule_id="plan_step_tool_mismatch",
                reason=(
                    f"plan step {action.plan_step!r} tool {step.tool!r} "
                    f"!= action tool {action.tool!r}"
                ),
            )
            self._record_decision(action, decision)
            raise SecurityViolation(decision.reason, decision=decision)

        # 4) Policy evaluate.
        decision = self.policy.evaluate(
            action,
            plan=plan,
            principal_authenticated=principal_authenticated,
        )

        # 4b) Detector fail-closed for privileged sinks (H2).
        # Overrides allow/require_human before mint when cascade or selection says so.
        if decision.effect != "deny":
            cascade_blocks = cascade is not None and privileged_sink_fail_closed(
                action.tool, cascade
            )
            selection_blocks = fail_closed_privileged and action.tool in PRIVILEGED_SINKS
            if cascade_blocks or selection_blocks:
                decision = PolicyDecision(
                    effect="deny",
                    rule_id="detector_fail_closed",
                    reason=(
                        f"privileged sink {action.tool!r} denied: detector "
                        "fail-closed (cascade risk or rules-only selection)"
                    ),
                )

        # 4c) Enforce matched-rule limits (H4) — no silent pass-through keys.
        if decision.effect != "deny" and decision.limits:
            limit_reason = _limits_violation(action, decision.limits)
            if limit_reason is not None:
                decision = PolicyDecision(
                    effect="deny",
                    rule_id="limits_violation",
                    reason=limit_reason,
                    display=decision.display,
                    limits=dict(decision.limits),
                )

        # 5) Audit append (every decision).
        self._record_decision(action, decision)

        # 6) Deny path.
        if decision.effect == "deny":
            raise SecurityViolation(
                f"denied by {decision.rule_id}: {decision.reason}",
                decision=decision,
            )

        # 6b) dry_run (C3): evaluate-only — no approval, mint, or execute.
        # PreToolUse / ask paths must not side-effect via approving hooks.
        if dry_run:
            if decision.effect == "require_human":
                raise SecurityViolation(
                    f"human approval required for {action.tool} "
                    f"(rule {decision.rule_id})",
                    decision=decision,
                )
            return BrokerResult(decision=decision, capability=None, result=None)

        # 7) Human approval hook for require_human (+ MFA / display).
        if decision.effect == "require_human":
            outcome = self.approval(action, decision)
            if decision.requires_mfa:
                verified = (
                    isinstance(outcome, ApprovalOutcome) and outcome.mfa_verified
                )
                if not verified:
                    decision = PolicyDecision(
                        effect="deny",
                        rule_id="mfa_required",
                        reason=(
                            f"MFA verification required for {action.tool} "
                            f"(rule {decision.rule_id})"
                        ),
                        display=decision.display,
                    )
                    self._record_decision(action, decision)
                    raise SecurityViolation(decision.reason, decision=decision)

        # 7b) Rate / spend gate for privileged sinks (optional when configured).
        if self.rate_limit is not None and action.tool in PRIVILEGED_SINKS:
            if not self.rate_limit.allow(action.tool, cost=1.0):
                decision = PolicyDecision(
                    effect="deny",
                    rule_id="rate_limit_exceeded",
                    reason=(
                        f"rate/spend budget exhausted for privileged sink "
                        f"{action.tool!r}"
                    ),
                    display=decision.display,
                )
                self._record_decision(action, decision)
                raise SecurityViolation(decision.reason, decision=decision)

        # 8) Mint one-use capability.
        resources = _resource_hints(action)
        token = self.minter.one_use(
            tool=action.tool,
            resources=resources,
            expiry_seconds=expiry_seconds,
        )

        # Per-call executor overrides instance default without shared mutation (C2).
        active_executor: Executor | None
        if executor is _EXECUTOR_UNSET:
            active_executor = self.executor
        else:
            active_executor = executor  # type: ignore[assignment]

        result: Any = None
        if active_executor is not None:
            self.minter.verify(token, tool=action.tool, resources=resources)
            result = active_executor(action, token)

        return BrokerResult(decision=decision, capability=token, result=result)



_ENFORCED_LIMIT_KEYS = frozenset({"max_bytes", "redirects", "network"})
_PAYLOAD_ARG_KEYS = ("body", "content", "data", "payload", "text")


def _limits_violation(action: ProposedAction, limits: Mapping[str, Any]) -> str | None:
    """Return a deny reason if action violates enforced policy limits, else None.

    Unknown limit keys fail closed (must not remain silently unenforced).
    """
    unknown = set(limits) - _ENFORCED_LIMIT_KEYS
    if unknown:
        return f"unenforced limit keys present: {sorted(unknown)}"

    if "max_bytes" in limits:
        max_b = int(limits["max_bytes"])
        if max_b < 0:
            return "max_bytes must be >= 0"
        for key in _PAYLOAD_ARG_KEYS:
            value = action.arguments.get(key)
            if isinstance(value, (str, bytes)) and len(value) > max_b:
                return f"argument {key!r} exceeds max_bytes {max_b}"

    if "redirects" in limits:
        try:
            check_redirect_args(action.arguments, max_redirects=int(limits["redirects"]))
        except UrlGuardError as exc:
            return str(exc)

    if "network" in limits:
        network = limits["network"]
        if network != "public_only":
            return f"unsupported network limit {network!r}"
        url = action.arguments.get("url")
        if isinstance(url, str) and url.strip():
            try:
                check_public_only(url)
            except UrlGuardError as exc:
                return str(exc)

    return None


def _resource_hints(action: ProposedAction) -> tuple[str, ...]:
    hints: list[str] = []
    args: Mapping[str, Any] = action.arguments
    for key in ("url", "recipient", "destination", "path"):
        value = args.get(key)
        if isinstance(value, str) and value:
            hints.append(value)
    return tuple(hints)


# Convenience alias matching the research sketch.
def secure_execute(
    action: ProposedAction,
    *,
    broker: ToolBroker,
    plan: Plan,
    principal_authenticated: bool = True,
) -> BrokerResult:
    return broker.secure_execute(
        action,
        plan=plan,
        principal_authenticated=principal_authenticated,
    )
