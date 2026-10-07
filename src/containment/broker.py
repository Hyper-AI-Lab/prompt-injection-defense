"""Tool broker reference monitor: schema → policy → audit → capability."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from containment.actions import PolicyDecision, ProposedAction
from containment.audit import AuditLog
from containment.capability import CapabilityMinter, CapabilityToken
from containment.plan import Plan
from containment.policy import PolicyEngine


class SecurityViolation(Exception):
    """Raised when the broker denies an action."""

    def __init__(self, message: str, *, decision: PolicyDecision) -> None:
        super().__init__(message)
        self.decision = decision


ApprovalHook = Callable[[ProposedAction, PolicyDecision], None]
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
        schema_validate: SchemaValidator = default_schema_validator,
        approval: ApprovalHook = default_approval_hook,
        executor: Executor | None = None,
        known_tools: frozenset[str] | None = None,
    ) -> None:
        self.policy = policy
        self.audit = audit
        self.minter = minter
        self.schema_validate = schema_validate
        self.approval = approval
        self.executor = executor
        self.known_tools = known_tools

    def secure_execute(
        self,
        action: ProposedAction,
        *,
        plan: Plan,
        principal_authenticated: bool = True,
        expiry_seconds: float = 60.0,
    ) -> BrokerResult:
        # 1) Optional known-tool gate (deny unknown before policy noise).
        if self.known_tools is not None and action.tool not in self.known_tools:
            decision = PolicyDecision(
                effect="deny",
                rule_id="unknown_tool",
                reason=f"unknown tool {action.tool!r}",
            )
            self.audit.append_decision(action, decision)
            raise SecurityViolation(decision.reason, decision=decision)

        # 2) Schema validation hook.
        try:
            self.schema_validate(action.tool, action.arguments)
        except SecurityViolation as exc:
            self.audit.append_decision(action, exc.decision)
            raise
        except Exception as exc:
            decision = PolicyDecision(
                effect="deny",
                rule_id="schema",
                reason=str(exc),
            )
            self.audit.append_decision(action, decision)
            raise SecurityViolation(str(exc), decision=decision) from exc

        # 3) Policy evaluate.
        decision = self.policy.evaluate(
            action,
            plan=plan,
            principal_authenticated=principal_authenticated,
        )

        # 4) Audit append (every decision).
        self.audit.append_decision(action, decision)

        # 5) Deny path.
        if decision.effect == "deny":
            raise SecurityViolation(
                f"denied by {decision.rule_id}: {decision.reason}",
                decision=decision,
            )

        # 6) Human approval hook for require_human.
        if decision.effect == "require_human":
            self.approval(action, decision)

        # 7) Mint one-use capability.
        resources = _resource_hints(action)
        token = self.minter.one_use(
            tool=action.tool,
            resources=resources,
            expiry_seconds=expiry_seconds,
        )

        result: Any = None
        if self.executor is not None:
            self.minter.verify(token, tool=action.tool, resources=resources)
            result = self.executor(action, token)

        return BrokerResult(decision=decision, capability=token, result=result)


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
